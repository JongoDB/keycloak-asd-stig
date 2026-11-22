#!/usr/bin/env python3
"""Live test of the allowlist's GRANT-LEVEL entries (review 2026-11-11 HIGH 1), in a throwaway realm, with the real
gate (stig-extensions) and the real guard (idp-admin.py, pointed at the throwaway realm and at temporary state files).
Runs ON the VM as root; joins the Keycloak container's network namespace.

  sudo python3 grant_extent_test.py --skill /srv/idp/src/keycloak-asd-stig-<sha>/keycloak-asd-stig

  A, granted /roles/idp-admin (realm-admin), and B, granted /roles/idp-user-manager, both by the tooling's grant code:
  1. both sign in (password; the realm's browser flow ends with the allowlist gate) and reach the admin API
  2. the grant's expansion grows after the grant (as an upgrade adding a role to a composite would; Keycloak refuses
     changes to realm-management roles themselves, even to the master realm, so the composite route is exercised
     through the granted group): a realm role composite of view-events mapped to /roles/idp-user-manager. B now holds a role its grant snapshot lacks but its granted group
     carries: NEEDS-REGRANT - the gate refuses its sign-in and its token (logged STIG-ADMIN-NEEDS-REGRANT); the guard
     alerts and changes NOTHING (B keeps its group, stays enabled, factors and card binding kept); A is unaffected
  3. the operator re-grants B (the tooling's grant code): B signs in again and reaches the admin API
  4. an unrelated realm-management role mapped DIRECTLY to B: OVER-ENTRY - sign-in and token refused; the guard
     demotes B, resets its factors (card binding kept), disables and holds it - and touches no one else (A untouched)
"""
import argparse, importlib.machinery, importlib.util, json, os, socket, sys, tempfile, time, urllib.error, urllib.parse, urllib.request, uuid

ap = argparse.ArgumentParser(); ap.add_argument("--skill", required=True)
a = ap.parse_args()
ld = importlib.machinery.SourceFileLoader("idp_admin", "/usr/local/sbin/idp-admin.py")
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
kc = M.KC()                                    # joins the Keycloak container's network namespace
HOST, PORT = M.ADMIN_HOST, M.ADMIN_PORT
_gai = socket.getaddrinfo
socket.getaddrinfo = lambda h, p, *r, **k: _gai("127.0.0.1", PORT, *r, **k) if h == HOST else _gai(h, p, *r, **k)
sys.path.insert(0, os.path.join(a.skill, "scripts")); import e2e_check as E   # noqa: E402
BASE = "https://%s" % HOST
TR = "t-grant-%s" % uuid.uuid4().hex[:6]
res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s  %-84s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

TMP = tempfile.mkdtemp(prefix="grant-extent-")
ORIG = {k: getattr(M, k) for k in ("REALM", "ALLOWLIST", "STATE", "ALLOWLIST_ATTR", "ALLOWLIST_ROLES_ATTR")}
def master_attrs(pop=False):
    st, d = kc.req("GET", "/admin/realms/master"); at = json.loads(d).get("attributes") or {}
    if pop:
        for k in (M.ALLOWLIST_ATTR, M.ALLOWLIST_ROLES_ATTR): at.pop(k, None)
        kc.req("PUT", "/admin/realms/master", json.dumps({"attributes": at}).encode(), {"Content-Type": "application/json"})
    return at

def sign_in(username, password):
    """(code or None, pages): a password sign-in to the throwaway realm's admin console."""
    fl = E.Flow(argparse.Namespace(url=BASE, realm=TR, client="security-admin-console", redirect="%s/admin/%s/console/" % (BASE, TR),
                                   admin_url=None, client_secret=None, cacert=None))
    b = E.Browser(); url, ver = fl.auth_url(); k, u, p = b.go(url, None, fl.a.redirect)
    act, f = E.form(p, "kc-form-login"); f.update({"username": username, "password": password}); k, u, p = b.go(act, f, fl.a.redirect)
    final, seen = fl.finish(b, k, u, p, {})
    code = urllib.parse.parse_qs(urllib.parse.urlparse(final).query)["code"][0] if final and "code=" in final else None
    return (fl.token(code, ver) if code else None), ([E.page_id(p)] if k == "page" else []) + seen

def admin_api(tok):
    req = urllib.request.Request("%s/admin/realms/%s/users?max=1" % (BASE, TR), headers={"Authorization": "Bearer " + tok})
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status
    except urllib.error.HTTPError as e:
        return "403 allowlist" if e.code == 403 and "not allowed" in e.read().decode() else e.code

def kc_logs(since):
    import subprocess
    p = subprocess.run(["docker", "logs", "--since", str(since), M.KC_CONTAINER], capture_output=True, text=True)
    return p.stdout + p.stderr

made = False
try:
    st_, _ = kc.req("POST", "/admin/realms", json.dumps({"realm": TR, "enabled": True, "sslRequired": "none",
                                                          "adminEventsEnabled": True, "adminEventsDetailsEnabled": True}).encode(),
                    {"Content-Type": "application/json"})
    made = st_ == 201
    M.REALM, M.ALLOWLIST, M.STATE = TR, os.path.join(TMP, "admins.json"), os.path.join(TMP, "state.json")
    M.ALLOWLIST_ATTR, M.ALLOWLIST_ROLES_ATTR = "stig.admin-allowlist.%s" % TR, "stig.admin-allowlist-roles.%s" % TR
    M._write_json(M.ALLOWLIST, {}); M.save_state(M.new_state())
    rmc = M.client_uuid(kc, "realm-management")
    up = kc.api("GET", "/users/profile"); up["unmanagedAttributePolicy"] = "ENABLED"; kc.api("PUT", "/users/profile", up)   # keep cac_edipi
    for name, roles in M.ROLE_GROUPS.items():
        M.set_group_client_roles(kc, M.ensure_group(kc, "/roles/" + name), "realm-management", roles)
    # the realm's browser flow: password, then the allowlist gate (as the production STIG Browser flow ends)
    M.flow(kc, "t-gate-browser", [("stig-admin-allowlist-gate", "REQUIRED", None)])
    M.subflow(kc, "t-gate-browser", "t-gate-forms", "REQUIRED", [("auth-username-password-form", "REQUIRED", None)], first_position=True)
    r0 = kc.api("GET", ""); r0["browserFlow"] = "t-gate-browser"; kc.api("PUT", "", r0)
    pw = {k: "Tg1!" + uuid.uuid4().hex[:16] for k in "AB"}
    users = {}
    for k, edipi in (("A", "1000000001"), ("B", "1000000002")):
        kc.api("POST", "/users", {"username": "t.grant.%s" % k.lower(), "enabled": True, "firstName": "T", "lastName": k,
                                  "email": "t.grant.%s@test.invalid" % k.lower(), "attributes": {"cac_edipi": [edipi]},
                                  "credentials": [{"type": "password", "value": pw[k], "temporary": False}]})
        users[k] = M.user(kc, "t.grant.%s" % k.lower())
    st = M.load_state() or M.new_state()
    M.apply_roles(kc, users["A"], ["idp-admin"], st)
    M.apply_roles(kc, users["B"], ["idp-user-manager"], st)
    al = M.load_allowlist()
    check("setup: A (idp-admin) and B (idp-user-manager) granted by the tooling: entries hold the groups BY ID with snapshots",
          all(al.get(users[k]["id"], {}).get("grants") and all(M.UUID.match(g["id"]) for g in al[users[k]["id"]]["grants"]) for k in "AB")
          and M.gate_version(kc) >= 2, "gate marker %s" % M.gate_version(kc))
    pub = master_attrs().get(M.ALLOWLIST_ROLES_ATTR, "")
    check("setup: the published entries are group:<id>@<snapshot>", all("%s=group:" % users[k]["id"] in pub for k in "AB") and "/roles/" not in pub, pub[:60])
    tA, sA = sign_in("t.grant.a", pw["A"]); tB, sB = sign_in("t.grant.b", pw["B"])
    check("1. both sign in through the gate and reach the admin API", tA and tB and admin_api(tA["access_token"]) == 200
          and admin_api(tB["access_token"]) == 200, "%s %s" % (sA, sB))

    # 2. the grant's expansion grows after the grant. Keycloak refuses changes to realm-management roles themselves
    # (creating one, or editing a composite: 403 even to the master realm), so the composite route an upgrade takes is
    # exercised through the granted group: a realm role made a composite of view-events and mapped to /roles/idp-user-manager
    comp = "t-grown-%s" % uuid.uuid4().hex[:6]
    kc.api("POST", "/roles", {"name": comp, "composite": True})
    kc.api("POST", "/roles/%s/composites" % comp, [kc.api("GET", "/clients/%s/roles/view-events" % rmc)])
    kc.api("POST", "/groups/%s/role-mappings/realm" % M.group_by_path(kc, "/roles/idp-user-manager")["id"], [kc.api("GET", "/roles/%s" % comp)])
    since = int(time.time())
    check("2. setup: B now holds view-events through a composite its granted group carries, beyond its grant snapshot",
          "view-events" in M.rm_roles(kc, users["B"]["id"]) and "view-events" not in al[users["B"]["id"]]["rm_roles"])
    t2, s2 = sign_in("t.grant.b", pw["B"])
    check("2. B: NEEDS-REGRANT -> its sign-in is refused (no code)", t2 is None, "%s" % s2)
    check("2. B: its existing token -> 403 by the filter", admin_api(tB["access_token"]) == "403 allowlist")
    time.sleep(2)
    check("2. ... logged STIG-ADMIN-NEEDS-REGRANT", "STIG-ADMIN-NEEDS-REGRANT realm=%s user=t.grant.b" % TR in kc_logs(since))
    import io, contextlib
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        g = M.guard(kc, True)
    out = err.getvalue()
    ub = kc.api("GET", "/users/%s" % users["B"]["id"])
    check("2. the guard alerts NEEDS-REGRANT and changes NOTHING on B (still holds its group, enabled, factors and card kept)",
          "STIG-ADMIN-NEEDS-REGRANT user=t.grant.b" in out and "STIG-ADMIN-UNVETTED user=t.grant.b" not in out
          and "view-events" in M.rm_roles(kc, users["B"]["id"]) and ub["enabled"] is True
          and kc.api("GET", "/users/%s/credentials" % users["B"]["id"]) and (ub.get("attributes") or {}).get("cac_edipi") == ["1000000002"],
          "guard %s; %s" % (g, [l[:160] for l in out.splitlines() if "t.grant.b" in l]))
    tA2, _ = sign_in("t.grant.a", pw["A"])
    check("2. A (realm-admin: its snapshot already holds every role) is unaffected: signs in, admin API 200",
          tA2 and admin_api(tA2["access_token"]) == 200 and "t.grant.a" not in out)

    # 3. the operator accepts the change: re-grant B
    with contextlib.redirect_stdout(io.StringIO()):
        M.apply_roles(kc, users["B"], ["idp-user-manager"], M.load_state() or M.new_state())
    t3, s3 = sign_in("t.grant.b", pw["B"])
    check("3. after the operator re-grants B: it signs in and reaches the admin API", t3 and admin_api(t3["access_token"]) == 200, "%s" % s3)
    tB2 = t3

    # 4. an unrelated realm-management role mapped DIRECTLY to B: over-entry
    kc.api("POST", "/users/%s/role-mappings/clients/%s" % (users["B"]["id"], rmc), [kc.api("GET", "/clients/%s/roles/manage-realm" % rmc)])
    t4, s4 = sign_in("t.grant.b", pw["B"])
    check("4. B, given manage-realm directly (outside its grant): sign-in refused, its token 403", t4 is None
          and admin_api(tB2["access_token"]) == "403 allowlist", "%s" % s4)
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        g = M.guard(kc, True)
    out = err.getvalue()
    ub = kc.api("GET", "/users/%s" % users["B"]["id"]); ua = kc.api("GET", "/users/%s" % users["A"]["id"])
    stB = M.load_state() or {}
    check("4. the guard: B over-entry -> demoted, factors reset, disabled and held; its card binding KEPT",
          "STIG-ADMIN-UNVETTED user=t.grant.b holds more than its entry" in out and not M.is_admin(kc, users["B"]["id"]) and ub["enabled"] is False
          and not kc.api("GET", "/users/%s/credentials" % users["B"]["id"]) and (ub.get("attributes") or {}).get("cac_edipi") == ["1000000002"]
          and users["B"]["id"] in (stB.get("guard_disabled") or {}), "guard %s; %s" % (g, [l[:160] for l in out.splitlines() if "t.grant.b" in l]))
    check("4. ... and no one else is touched: A still an administrator, enabled, signs in", M.is_admin(kc, users["A"]["id"]) and ua["enabled"] is True
          and sign_in("t.grant.a", pw["A"])[0] is not None and "user=t.grant.a" not in out)
finally:
    try:
        M.REALM = ORIG["REALM"]
        M.ALLOWLIST_ATTR, M.ALLOWLIST_ROLES_ATTR = "stig.admin-allowlist.%s" % TR, "stig.admin-allowlist-roles.%s" % TR
        master_attrs(pop=True)          # the throwaway realm's published allowlist goes with it
    finally:
        for k, v in ORIG.items():
            setattr(M, k, v)
    if made:
        kc.req("DELETE", "/admin/realms/%s" % TR)
    import shutil; shutil.rmtree(TMP, ignore_errors=True)
print("\n%d/%d passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)

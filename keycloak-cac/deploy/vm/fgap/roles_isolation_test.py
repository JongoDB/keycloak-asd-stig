#!/usr/bin/env python3
"""Live isolation test of the IdP role catalogue (option B). Each role is exercised through a
throwaway service account placed in its group (FGAP v2 and realm-management roles judge a service account exactly as
they judge a person in the group). Creates and deletes its own fgap.* / t-role-* objects; prints PASS/FAIL.

  roles_isolation_test.py --url https://idp.example.mil --realm example \
      --admin-client-id stig-automation --admin-secret-file /s/automation_secret --admin-user-name op.admin

Checks, per role:
  idp-user-manager  creates users only into application role groups (stig-accounts) and never with a card identity; reads
                    and moves members; cannot see, edit, reset or sign out an administrator (one holding /roles/*),
                    cannot touch a user outside the application groups, cannot join anyone to /roles/*, cannot map
                    any role, cannot write cac_edipi or entra_amr
  idp-auditor       reads users and events; changes nothing
  idp-admin         full realm admin, the only one besides a master admin that may write cac_edipi
"""
import argparse, json, os, re, socket, ssl, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--url", required=True); ap.add_argument("--realm", required=True)
ap.add_argument("--admin-client-id", required=True); ap.add_argument("--admin-secret-file", required=True)
ap.add_argument("--admin-user-name", required=True, help="an existing account in /roles/idp-admin (read-only target)")
ap.add_argument("--app-a-secret-file", help="app-a-admin's secret: also test that delegate against a misplaced admin")
ap.add_argument("--skill", default=None, help="keycloak-asd-stig skill dir (e2e_check); default: the newest under /srv/idp/src")
ap.add_argument("--resolve-to", help="connect to this address for the --url host (e.g. 127.0.0.1 on the VM, so the master realm answers)")
a = ap.parse_args()
if not a.skill:
    import glob, os
    a.skill = sorted(glob.glob("/srv/idp/src/keycloak-asd-stig-*/keycloak-asd-stig"), key=os.path.getmtime)[-1]
CTX = ssl.create_default_context()
if a.resolve_to:
    _host, _orig = urllib.parse.urlparse(a.url).hostname, socket.getaddrinfo
    socket.getaddrinfo = lambda h, *r, **k: _orig(a.resolve_to if h == _host else h, *r, **k)
B = a.url.rstrip("/")

def q(s): return urllib.parse.quote(s, safe="")

class KC:
    def __init__(self, realm, client_id, secret):
        st, body = self.raw("POST", "/realms/%s/protocol/openid-connect/token" % realm,
                            urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret}).encode(),
                            {"Content-Type": "application/x-www-form-urlencoded"}, None)
        if st != 200:
            sys.exit("token for %s failed: HTTP %s" % (client_id, st))
        self.t = json.loads(body)["access_token"]
    def raw(self, m, p, body, h, t):
        h = dict(h or {})
        if t: h["Authorization"] = "Bearer " + t
        try:
            with urllib.request.urlopen(urllib.request.Request(B + p, data=body, method=m, headers=h), context=CTX, timeout=60) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
    def api(self, m, p, o=None, expect=(200, 201, 204)):
        st, body = self.raw(m, "/admin/realms/%s%s" % (a.realm, p), json.dumps(o).encode() if o is not None else None,
                            {"Content-Type": "application/json"} if o is not None else {}, self.t)
        if expect and st not in expect:
            sys.exit("%s %s -> %s %s" % (m, p, st, body[:200]))
        return st, (json.loads(body) if body.strip().startswith(("{", "[")) else body)

adm = KC("master", a.admin_client_id, open(a.admin_secret_file).read().strip())
# The operator tooling is run as a FIXED program with validated arguments and a minimal environment: nothing from this
# script's command line or environment reaches a child process unchecked.
ADM = "/usr/local/sbin/idp-admin.py"
BASE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
PASS_ENV = ("SUDO_USER", "USER", "IDP_KC_CONTAINER")    # who the operator is (audit attribution); the container name
ADM_COMMANDS = {"guard": {"--fix"}, "grant": {"--reset-credentials", "--clear-bindings"}, "promote": {"--clear-bindings"},
                "revoke": set(), "user-delete": set()}
ADM_ARG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}")      # always used with fullmatch: no trailing newline

def child_env():
    """The minimal environment, plus the operator's identity and the Keycloak container name when they are set - each
    only if it is a plain name; anything else is dropped."""
    env = dict(BASE_ENV)
    for k in PASS_ENV:
        v = os.environ.get(k)
        if v is not None and ADM_ARG.fullmatch(v):
            env[k] = v
    return env

def adm_argv(command, *args):
    """[python, idp-admin.py, command, args...] - command and flags from fixed allowlists, every other argument a plain
    name (username, role); anything else is refused before a process starts."""
    if command not in ADM_COMMANDS:
        raise ValueError("idp-admin.py %r is not a command this test runs" % command)
    for x in args:
        if x.startswith("-") and x not in ADM_COMMANDS[command]:
            raise ValueError("idp-admin.py %s: flag %r not allowed" % (command, x))
        if not x.startswith("-") and not ADM_ARG.fullmatch(x):
            raise ValueError("idp-admin.py %s: argument %r is not a plain name" % (command, x))
    return [sys.executable, ADM, command] + list(args)

def run_adm(command, *args):
    r = subprocess.run(adm_argv(command, *args), capture_output=True, text=True, timeout=600, env=child_env())
    return r.returncode, (r.stdout + r.stderr).strip()

def run_guard(*extra):
    """The real guard (idp-admin.py guard [--fix]): returns (exit status, combined output)."""
    return run_adm("guard", *extra)

res = []
def check(name, ok, detail=""):
    res.append(bool(ok)); print("%s  %-66s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)
def gpath(p): return adm.api("GET", "/group-by-path/%s" % urllib.parse.quote(p.strip("/")))[1]
def find_user(n):
    us = adm.api("GET", "/users?exact=true&username=%s" % q(n))[1]
    return us[0] if us else None

def grant(username, *roles):
    rc, out = run_adm("grant", username, *roles)
    if rc != 0:
        sys.exit("grant %s %s failed: %s" % (username, roles, out[-400:]))
    return out

def role_person(name, role):
    """A PERSON holding `role` (service accounts are never administrators or user managers): password + TOTP, granted
    by the tooling (allowlisted), signed in on the realm's admin console client. Returns (user id, caller)."""
    import importlib.machinery, importlib.util
    ld = importlib.machinery.SourceFileLoader("idp_admin", "/usr/local/sbin/idp-admin.py")
    spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
    sys.path.insert(0, "/root/idp-deploy/tests"); import persona       # noqa: E402
    sys.path.insert(0, a.skill + "/scripts"); import e2e_check as E    # noqa: E402
    p = persona.Person(M, M.KC(), E, run_adm, B, a.realm, "t.role-%s%s" % (name, time.strftime("%H%M%S")), role)
    made_users.append(p.username)
    class Caller:
        def api(self, m, path, o=None, expect=(200, 201, 204)):
            st, b = p.api(m, path, o)
            if expect and st not in expect:
                sys.exit("%s %s -> %s %s" % (m, path, st, str(b)[:200]))
            return st, b
    return p.user["id"], Caller()

def role_client(name):
    """A throwaway confidential client (its service account holds no role: an ordinary caller)."""
    cid = "t-role-" + name
    adm.api("POST", "/clients", {"clientId": cid, "publicClient": False, "serviceAccountsEnabled": True, "standardFlowEnabled": False,
                                  "directAccessGrantsEnabled": False, "fullScopeAllowed": False}, expect=(201, 409))
    c = adm.api("GET", "/clients?clientId=%s" % q(cid))[1][0]
    scopes = [s for s in adm.api("GET", "/client-scopes")[1] if s["name"] == "kc-admin-api"]
    if scopes:
        adm.api("PUT", "/clients/%s/default-client-scopes/%s" % (c["id"], scopes[0]["id"]))
    # like the realm's admin console (roles-setup): realm-management roles may ride in this client's tokens
    rmc = adm.api("GET", "/clients?clientId=realm-management")[1][0]["id"]
    adm.api("POST", "/clients/%s/scope-mappings/clients/%s" % (c["id"], rmc), adm.api("GET", "/clients/%s/roles" % rmc)[1])
    sec = adm.api("GET", "/clients/%s/client-secret" % c["id"])[1]["value"]
    return c["id"], KC(a.realm, cid, sec)

made_clients, made_users = [], []
old_dom = None
try:
    boss = find_user(a.admin_user_name) or sys.exit("no %s" % a.admin_user_name)
    # fixtures: an application member and an outsider, created by the realm (master) admin
    for n, grp in (("fgap.member", "/app-b/member"), ("fgap.outsider", None)):
        adm.api("POST", "/users", dict({"username": n, "email": n + "@test.invalid", "firstName": "Fgap", "lastName": n.split(".")[1].title(),
                                        "enabled": True}, **({"groups": [grp]} if grp else {})), expect=(201, 409))
        made_users.append(n)
    mem, out = find_user("fgap.member"), find_user("fgap.outsider")

    # ---------------------------------------------------------------- idp-user-manager
    um_id, um = role_person("um", "idp-user-manager")
    ra_ = dict(adm.api("GET", "")[1].get("attributes") or {}); old_dom = ra_.get("stig.accounts.email-domains")
    ra_["stig.accounts.email-domains"] = ".mil,example.mil,notify.example.mil"; adm.api("PUT", "", {"attributes": ra_})   # restored below
    # accounts are created only through stig-accounts (no manage-members: see accounts_endpoint_test.py for the rest)
    st, _ = um.api("POST", "/users", {"username": "fgap.invitee", "email": "fgap.invitee@test.invalid", "firstName": "F", "lastName": "Invitee",
                                       "enabled": True, "groups": ["/app-b/maintainer"]}, expect=None)
    made_users.append("fgap.invitee")
    check("user-manager cannot create a user through the plain admin API", st == 403, "HTTP %s" % st)
    st, _ = um.api("POST", "/stig-accounts/users", {"username": "fgap.invitee2", "email": "fgap.invitee2@notify.example.mil", "firstName": "F",
                                                    "lastName": "Invitee", "group": "/app-b/maintainer"}, expect=None)
    made_users.append("fgap.invitee2")
    check("user-manager CAN create a user into an application role group (stig-accounts)", st == 201, "HTTP %s" % st)
    st, _ = um.api("POST", "/users", {"username": "fgap.loose", "email": "fgap.loose@test.invalid", "firstName": "F", "lastName": "Loose", "enabled": True}, expect=None)
    made_users.append("fgap.loose")
    check("user-manager cannot create a user outside the application groups", st == 403, "HTTP %s" % st)
    st, _ = um.api("POST", "/users", {"username": "fgap.carded", "email": "fgap.carded@test.invalid", "firstName": "F", "lastName": "Carded",
                                       "enabled": True, "groups": ["/app-b/member"], "attributes": {"cac_edipi": ["5555555555"]}}, expect=None)
    made_users.append("fgap.carded")
    check("user-manager cannot create a user with a card identity", st in (400, 403), "HTTP %s" % st)
    st, _ = um.api("POST", "/users", {"username": "fgap.boss2", "email": "fgap.boss2@test.invalid", "firstName": "F", "lastName": "Boss",
                                       "enabled": True, "groups": ["/roles/idp-admin"]}, expect=None)
    made_users.append("fgap.boss2")
    check("user-manager cannot create a user into /roles/idp-admin", st == 403, "HTTP %s" % st)
    st, m = um.api("GET", "/users/%s" % mem["id"], expect=None)
    check("user-manager CAN read an application member", st == 200, "HTTP %s" % st)
    st, _ = um.api("PUT", "/users/%s" % mem["id"], dict(m, firstName="Renamed"), expect=None)
    check("user-manager cannot edit an application member (no manage-members)", st == 403, "HTTP %s" % st)
    st1, _ = um.api("PUT", "/users/%s/groups/%s" % (mem["id"], gpath("/app-b/reviewer")["id"]), expect=None)
    st2, _ = um.api("DELETE", "/users/%s/groups/%s" % (mem["id"], gpath("/app-b/member")["id"]), expect=None)
    check("user-manager CAN move a member between application role groups", (st1, st2) == (204, 204), "HTTP %s/%s" % (st1, st2))
    st, _ = um.api("PUT", "/users/%s" % mem["id"], dict(m, attributes=dict(m.get("attributes") or {}, cac_edipi=["4444444444"])), expect=None)
    check("user-manager cannot set a member's cac_edipi", st in (400, 403), "HTTP %s" % st)
    st, _ = um.api("PUT", "/users/%s" % mem["id"], dict(m, attributes=dict(m.get("attributes") or {}, entra_amr=["pwd", "mfa"])), expect=None)
    check("user-manager cannot write a member's entra_amr", st in (400, 403), "HTTP %s" % st)
    st, _ = um.api("PUT", "/users/%s/groups/%s" % (mem["id"], gpath("/roles/idp-admin")["id"]), expect=None)
    check("user-manager cannot join a member to /roles/idp-admin", st == 403, "HTTP %s" % st)
    st, _ = um.api("PUT", "/users/%s/groups/%s" % (um_id, gpath("/roles/idp-admin")["id"]), expect=None)
    check("user-manager cannot join itself to /roles/idp-admin", st in (403, 404), "HTTP %s" % st)
    rm = adm.api("GET", "/clients?clientId=realm-management")[1][0]
    ra = adm.api("GET", "/clients/%s/roles/realm-admin" % rm["id"])[1]
    st, _ = um.api("POST", "/users/%s/role-mappings/clients/%s" % (mem["id"], rm["id"]), [ra], expect=None)
    check("user-manager cannot map realm-admin", st == 403, "HTTP %s" % st)
    app = adm.api("GET", "/clients?clientId=app-b")[1][0]
    st, _ = um.api("POST", "/users/%s/role-mappings/clients/%s" % (mem["id"], app["id"]),
                   [adm.api("GET", "/clients/%s/roles/admin" % app["id"])[1]], expect=None)
    check("user-manager cannot map application roles directly", st == 403, "HTTP %s" % st)
    for what, method, path, body in (
            ("read", "GET", "/users/%s" % boss["id"], None),
            ("edit", "PUT", "/users/%s" % boss["id"], {"firstName": "Hijacked"}),
            ("reset the password of", "PUT", "/users/%s/reset-password" % boss["id"], {"type": "password", "value": "Hijack-1234567890!", "temporary": False}),
            ("list the credentials of", "GET", "/users/%s/credentials" % boss["id"], None),
            ("sign out", "POST", "/users/%s/logout" % boss["id"], None)):
        st, _ = um.api(method, path, body, expect=None)
        check("user-manager cannot %s an administrator (%s)" % (what, a.admin_user_name), st in (403, 404), "HTTP %s" % st)
    st, _ = um.api("GET", "/users/%s" % out["id"], expect=None)
    check("user-manager cannot read a user outside the application groups", st in (403, 404), "HTTP %s" % st)
    st, us = um.api("GET", "/users?max=500", expect=None)
    ids = [u["id"] for u in us] if st == 200 and isinstance(us, list) else []
    check("user-manager's user search shows no administrator and no outsider", boss["id"] not in ids and out["id"] not in ids,
          "HTTP %s, %d visible" % (st, len(ids)))

    # ---------------------------------------------------------------- nobody but an administrator reaches an administrator
    # 2026-11-10 incident: a Users permission whose only policy was a NEGATIVE aggregate PERMITTED every non-delegate.
    # Now: the guard keeps a Users permission on every administrator whose only policy is POSITIVE (/roles/idp-admin),
    # and takes administrators out of every application-tree group at any depth. Fixtures: one administrator by
    # /roles/idp-admin membership placed in a depth-2 AND a NESTED application group, and one administrator only by an
    # effective realm-management role (realm-admin mapped directly, no /roles group) placed in a nested group.
    ad_id, ad = role_person("adm", "idp-admin")
    cid, ordinary = role_client("ordinary"); made_clients.append(cid)
    nested = adm.api("POST", "/groups/%s/children" % gpath("/app-b/member")["id"], {"name": "fgap-nested"}, expect=(201, 409))
    nested = gpath("/app-b/member/fgap-nested")
    stu = adm.api("GET", "/clients/%s/roles/student" % app["id"])[1]
    adm.api("POST", "/groups/%s/role-mappings/clients/%s" % (nested["id"], app["id"]), [stu])
    try:
        pw = "Mis-" + "placed-123456789!"
        # an ALLOWLISTED administrator (granted by the tooling: card mapping), later put into application groups by hand
        adm.api("POST", "/users", {"username": "fgap.misplaced-admin", "email": "fgap.misplaced-admin@test.invalid", "firstName": "Fgap",
                                   "lastName": "Misplaced", "enabled": True, "credentials": [{"type": "password", "value": pw, "temporary": False}],
                                   "attributes": {"cac_edipi": [str(int(time.time() * 1000))[-10:]]}}, expect=(201, 409))
        made_users.append("fgap.misplaced-admin")
        grant("fgap.misplaced-admin", "idp-admin")
        mis = find_user("fgap.misplaced-admin")
        for gp in ("/app-b/member", "/app-b/member/fgap-nested", "/app-a/viewer"):
            adm.api("PUT", "/users/%s/groups/%s" % (mis["id"], gpath(gp)["id"]))
        adm.api("POST", "/users", {"username": "fgap.role-admin", "email": "fgap.role-admin@test.invalid", "firstName": "Fgap", "lastName": "Roleadmin",
                                   "enabled": True, "groups": ["/app-b/member/fgap-nested"]}, expect=(201, 409))
        made_users.append("fgap.role-admin")
        adm.api("POST", "/users", {"username": "fgap.control", "email": "fgap.control@test.invalid", "firstName": "Fgap", "lastName": "Control",
                                   "enabled": True, "groups": ["/app-b/member", "/app-b/member/fgap-nested", "/app-a/viewer"]},
                expect=(201, 409))
        made_users.append("fgap.control")
        adm.api("POST", "/users", {"username": "fgap.control-other", "email": "fgap.control-other@test.invalid", "firstName": "Fgap", "lastName": "ControlOther",
                                   "enabled": True, "groups": ["/app-a/viewer"]}, expect=(201, 409))
        made_users.append("fgap.control-other")
        control, control_other = find_user("fgap.control"), find_user("fgap.control-other")
        victim, roleadm = find_user("fgap.misplaced-admin"), find_user("fgap.role-admin")
        adm.api("POST", "/users/%s/role-mappings/clients/%s" % (roleadm["id"], rm["id"]), [ra])
        callers = [("an ordinary realm account", ordinary), ("user-manager", um)]
        if a.app-a_secret_file:
            callers.append(("app-a-admin", KC(a.realm, "app-a-admin", open(a.app-a_secret_file).read().strip())))
        targets = ((a.admin_user_name, boss), ("misplaced admin (depth-2 + nested)", victim), ("realm-admin-by-role admin (nested)", roleadm))

        def denied_all(when):
            for target_name, target in targets:
                for name, d in callers:
                    st1, _ = d.api("GET", "/users/%s" % target["id"], expect=None)
                    st2, _ = d.api("PUT", "/users/%s/reset-password" % target["id"], {"type": "password", "value": "Hijack-1234567890!", "temporary": False}, expect=None)
                    st3, _ = d.api("POST", "/users/%s/impersonation" % target["id"], expect=None)
                    check("%s: %s cannot view/reset/impersonate %s" % (when, name, target_name), all(x in (403, 404) for x in (st1, st2, st3)),
                          "view %s, reset %s, impersonate %s" % (st1, st2, st3))

        # 1. report only: the guard finds both (one by an effective role only) and syncs the server-side permission
        rc, out_ = run_guard()
        check("guard (no --fix) reports the misplaced administrator and the unvetted one, exit 2", rc == 2 and
              "STIG-ADMIN-IN-DELEGATED-GROUP user=fgap.misplaced-admin" in out_ and "STIG-ADMIN-UNVETTED user=fgap.role-admin" in out_, "exit %s" % rc)
        # 2. server-side deny while they are STILL in the application groups (does not wait for --fix or the timer)
        still = [g["path"] for g in adm.api("GET", "/users/%s/groups" % victim["id"])[1] if not g["path"].startswith("/roles/")]
        check("precondition: the misplaced administrator is still in its application groups", len(still) == 3, "%s" % still)
        # control: the same callers DO reach a non-administrator in the same groups, so each 403 above is the
        # administrators' permission at work, not a delegation that never covered those groups
        denied_all("before --fix")
        st, _ = um.api("GET", "/users/%s" % control["id"], expect=None)
        check("control: user-manager CAN view a non-administrator in the same (depth-2 + nested) groups", st == 200, "HTTP %s" % st)
        if a.app-a_secret_file:
            # (a person in two application trees needs a delegate of both: Keycloak combines permissions unanimously)
            st, _ = callers[-1][1].api("GET", "/users/%s" % control_other["id"], expect=None)
            check("control: app-a-admin CAN view a non-administrator in /app-a/viewer", st == 200, "HTTP %s" % st)
        st, _ = ad.api("GET", "/users/%s" % victim["id"], expect=None)
        check("before --fix: idp-admin CAN still view the misplaced administrator", st == 200, "HTTP %s" % st)
        # 3. --fix takes them out of every application group at any depth and verifies it; roles kept as direct mappings
        rc, out_ = run_guard("--fix")
        check("guard --fix exits 2 (found and fixed) and says verified", rc == 2 and out_.count("fixed (verified") == 1, "exit %s" % rc)
        left = [g["path"] for g in adm.api("GET", "/users/%s/groups" % victim["id"])[1] if g["path"].split("/")[1] in ("app-b", "app-a", "app-c")]
        check("after --fix: the allowlisted administrator is in no application group at any depth (still an administrator)", not left
              and "STIG-ADMIN-UNVETTED user=fgap.misplaced-admin" not in out_, "left in %s" % left)
        ra_now = adm.api("GET", "/users/%s" % roleadm["id"])[1]
        rmn = adm.api("GET", "/users/%s/role-mappings/clients/%s/composite" % (roleadm["id"], rm["id"]))[1]
        check("after --fix: the unvetted realm-admin-by-role account is demoted and DISABLED", "STIG-ADMIN-UNVETTED user=fgap.role-admin" in out_
              and not rmn and ra_now["enabled"] is False, "roles %d, enabled %s" % (len(rmn), ra_now["enabled"]))
        targets = ((a.admin_user_name, boss), ("misplaced admin (depth-2 + nested)", victim))
        direct = [r["name"] for r in adm.api("GET", "/users/%s/role-mappings/clients/%s" % (victim["id"], app["id"]))[1]]
        check("after --fix: the misplaced administrator keeps app-b member by direct mapping", "member" in direct, "%s" % direct)
        denied_all("after --fix")
        rc, out_ = run_guard("--fix")
        check("guard --fix again: nothing left to fix, exit 0", rc == 0, "exit %s: %s" % (rc, out_.strip()[-120:]))
        st, _ = ad.api("GET", "/users/%s" % victim["id"], expect=None)
        check("after --fix: idp-admin CAN still view the administrator", st == 200, "HTTP %s" % st)
        st, _ = ordinary.api("GET", "/users?max=5", expect=None)
        check("an ordinary realm account cannot list users", st == 403, "HTTP %s" % st)
    finally:
        adm.api("DELETE", "/groups/%s" % nested["id"], expect=None)

    # ---------------------------------------------------------------- idp-auditor
    au_id, au = role_person("aud", "idp-auditor")
    st, us = au.api("GET", "/users?max=5", expect=None)
    check("auditor CAN list users", st == 200, "HTTP %s" % st)
    st, _ = au.api("GET", "/events?max=5", expect=None)
    check("auditor CAN read sign-in events", st == 200, "HTTP %s" % st)
    st, _ = au.api("PUT", "/users/%s" % mem["id"], dict(m, firstName="AuditorWasHere"), expect=None)
    check("auditor cannot edit a user", st == 403, "HTTP %s" % st)
    st, _ = au.api("POST", "/users", {"username": "fgap.byauditor", "enabled": True}, expect=None)
    made_users.append("fgap.byauditor")
    check("auditor cannot create a user", st == 403, "HTTP %s" % st)

    # ---------------------------------------------------------------- idp-admin
    m = adm.api("GET", "/users/%s" % mem["id"])[1]
    st, _ = ad.api("PUT", "/users/%s" % mem["id"], dict(m, attributes=dict(m.get("attributes") or {}, cac_edipi=["3333333333"])), expect=None)
    check("idp-admin CAN set a member's cac_edipi (realm-admin)", st == 204, "HTTP %s" % st)
    st, _ = ad.api("PUT", "/users/%s" % out["id"], dict(adm.api("GET", "/users/%s" % out["id"])[1], attributes={"cac_edipi": ["3333333333"]}), expect=None)
    check("... and a duplicate cac_edipi is refused even for idp-admin", st == 400, "HTTP %s" % st)
finally:
    for n in made_users:
        u = find_user(n)
        if u: adm.api("DELETE", "/users/%s" % u["id"])
    ra_ = dict(adm.api("GET", "")[1].get("attributes") or {})
    if old_dom is None: ra_.pop("stig.accounts.email-domains", None)
    else: ra_["stig.accounts.email-domains"] = old_dom
    adm.api("PUT", "", {"attributes": ra_})
    for c in made_clients:
        adm.api("DELETE", "/clients/%s" % c)
    rc, out_ = run_guard()       # re-sync the administrators' permission now the fixtures are gone
    check("guard after cleanup: exit 0", rc == 0, "exit %s" % rc)
print("\n%d/%d passed" % (sum(res), len(res))); sys.exit(0 if all(res) else 1)

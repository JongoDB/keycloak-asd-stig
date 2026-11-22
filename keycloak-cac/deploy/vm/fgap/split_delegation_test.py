#!/usr/bin/env python3
"""The split delegation of /app-a, proved against a real Keycloak.

`idp-admin.py roles-setup` gives every group of an application tree its OWN membership-write permission, and
`APP_DELEGATIONS` decides who may write each group (docs/passkey-public-realm.md, Appendix E):

  app-a-admin            the 6 app-a role groups + partner-reader
  app-a-reader-delegate  partner-reader only
  /roles/idp-user-manager         every group of the tree (unchanged)

Every delegate still SEES the whole tree (`delegated: /<app>`: view, view-members, manage-membership-of-members), and
a move needs manage-group-membership on the ACCOUNT too, which a delegate holds only for accounts already in the tree.

  split_delegation_test.py --url http://127.0.0.1:18080 --admin-user admin --admin-password-file F lab [--keep]
      THROWAWAY realms only: creates `split-lab-a` and `split-lab-b` (refuses any realm that is not its own, marked
      with the realm attribute split-delegation-lab=true), then deletes them unless --keep. It drives idp-admin.py's
      own sync_delegations / ensure_delegate_client through an HTTP adapter, so what is tested is the code that runs
      on the IdP. Realm A follows the live order (earlier single permission -> roles-setup -> reader-delegate-setup ->
      partner roles added -> roles-setup) and probes app-a's administrator after EVERY permission write of the
      migration; realm B starts from the dangerous state (partner roles added under the earlier permission) and shows
      the escalation before the split and the refusal after it.
  split_delegation_test.py --url https://idp... --realm example --admin-client-id ... --admin-secret-file F test
      --admin-secret-file F --reader-secret-file F [--app app-a]
      (a delegate on client-jwt: --sa-jwt-key / --reader-jwt-key <PEM private key> instead of its secret file)
      the permission matrix on an already-converged realm: the operating guide's apply step 5 (before the partner roles: the matrix
      over the app-a groups, stig-accounts and impersonation refused) and step 6 (after them: also the reader
      delegate's reach). Creates and deletes its own t.split.* users; never puts anyone into a /roles/* group.

Prints no secrets. Exit 0 only if every check passed.
"""
import argparse, importlib.machinery, importlib.util, json, os, secrets, ssl, sys, time, urllib.error, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REVIEW = ("partner-lead", "partner-auditor", "partner-reader", "contractor")
LAB_MARK = "split-delegation-lab"

def q(s): return urllib.parse.quote(s, safe="")

def load_idp_admin(path):
    os.environ.setdefault("IDP_ADMIN_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures", "idp-admin.test.json"))   # the lab/unit config; on a host the real one is used
    ld = importlib.machinery.SourceFileLoader("idp_admin", path)
    spec = importlib.util.spec_from_loader("idp_admin", ld); m = importlib.util.module_from_spec(spec); ld.exec_module(m)
    return m

class Http:
    def __init__(self, url, cafile=None):
        self.url = url.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=cafile) if self.url.startswith("https") else None
    def raw(self, method, path, body=None, headers=None):
        req = urllib.request.Request(self.url + path, data=body, method=method, headers=dict(headers or {}))
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=60) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

class Caller:
    """A token holder (admin, service account or person) calling one realm's admin API; re-logs in when stale."""
    def __init__(self, http, realm, form, label):
        self.http, self.realm, self.form, self.label, self.token, self.at = http, realm, dict(form), label, None, 0
    def login(self):
        f = dict(self.form); tr = f.pop("_realm")
        jwt_ = f.pop("_jwt", None)
        if jwt_:                                   # client-jwt: a fresh assertion per sign-in (a jti is never replayed)
            sys.path.insert(0, HERE); import client_jwt  # noqa: E402
            f.update(client_jwt.form_fields(jwt_, f["client_id"], self.http.url + "/realms/%s" % tr))
        st, body = self.http.raw("POST", "/realms/%s/protocol/openid-connect/token" % tr, urllib.parse.urlencode(f).encode(),
                                 {"Content-Type": "application/x-www-form-urlencoded"})
        if st != 200:
            sys.exit("%s: login failed: HTTP %s %s" % (self.label, st, body[:200]))
        self.token, self.at = json.loads(body)["access_token"], time.time()
    def call(self, method, path, obj=None, realm=None):
        if not self.token or time.time() - self.at > 45:
            self.login()
        h = {"Authorization": "Bearer " + self.token}
        if obj is not None:
            h["Content-Type"] = "application/json"
        st, body = self.http.raw(method, "/admin/realms/%s%s" % (realm or self.realm, path),
                                 json.dumps(obj).encode() if obj is not None else None, h)
        return st, (json.loads(body) if body.strip().startswith(("{", "[")) else body)

class Adapter:
    """idp-admin.py's KC.api over plain HTTP, for one realm: the same call contract (exit on an unexpected status), plus
    a count of writes and an optional probe after every write to the admin-permissions resource server."""
    def __init__(self, caller, on_authz_write=None):
        self.c, self.writes, self.on_authz_write = caller, [], on_authz_write
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        st, body = self.c.call(method, path, obj)
        if st == 404 and ok404:
            return None
        if st not in ok:
            sys.exit("%s %s -> HTTP %s %s" % (method, path, st, str(body)[:300]))
        if method != "GET":
            self.writes.append((method, path))
            if self.on_authz_write and "/authz/" in path:
                self.on_authz_write(method, path)
        return body if body != "" else None

results = []
def check(name, ok, detail=""):
    results.append(bool(ok)); print("%s  %-92s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)

# ------------------------------------------------------------------------------------------------ fixtures
def admin_caller(a, http, realm):
    if a.admin_client_id:
        form = {"_realm": "master", "grant_type": "client_credentials", "client_id": a.admin_client_id,
                "client_secret": open(a.admin_secret_file).read().strip()}
    else:
        form = {"_realm": "master", "grant_type": "password", "client_id": "admin-cli", "username": a.admin_user,
                "password": open(a.admin_password_file).read().strip()}
    return Caller(http, realm, form, "admin")

def sa_caller(http, adm, realm, cid, secret=None, jwt_key=None):
    if jwt_key:
        return Caller(http, realm, {"_realm": realm, "grant_type": "client_credentials", "client_id": cid, "_jwt": jwt_key}, cid)
    if secret is None:
        c = [x for x in adm.call("GET", "/clients?clientId=%s" % q(cid))[1] if x["clientId"] == cid][0]
        secret = adm.call("GET", "/clients/%s/client-secret" % c["id"])[1]["value"]
    return Caller(http, realm, {"_realm": realm, "grant_type": "client_credentials", "client_id": cid, "client_secret": secret}, cid)

def gid(adm, path):
    st, g = adm.call("GET", "/group-by-path/%s" % "/".join(q(x) for x in path.strip("/").split("/")))
    return g["id"] if st == 200 else None

def ensure_user(adm, username, groups=()):
    adm.call("POST", "/users", {"username": username, "email": "%s@test.invalid" % username, "firstName": "T",
                                "lastName": "Split", "enabled": True})
    u = [x for x in adm.call("GET", "/users?exact=true&username=%s" % q(username))[1] if x["username"] == username][0]
    set_groups(adm, u["id"], groups)
    return u["id"]

def set_groups(adm, uid, paths):
    """The account's groups become exactly `paths` (set by the realm admin, never by a delegate)."""
    want = {gid(adm, p) for p in paths}
    have = {g["id"] for g in adm.call("GET", "/users/%s/groups?max=1000" % uid)[1]}
    for g in have - want:
        adm.call("DELETE", "/users/%s/groups/%s" % (uid, g))
    for g in want - have:
        st, _ = adm.call("PUT", "/users/%s/groups/%s" % (uid, g))
        if st != 204:
            sys.exit("admin could not put %s into %s: HTTP %s" % (uid, g, st))

def groups_of(adm, uid):
    return sorted(g["path"] for g in adm.call("GET", "/users/%s/groups?max=1000" % uid)[1])

# ------------------------------------------------------------------------------------------------ the matrix
def allowed_writes(M, app, cid, tree):
    if cid == "idp-user-manager":           # every application tree's groups (theirs is the whole delegation)
        return set(tree) | {p for p in ALL_PATHS if p.strip("/").split("/")[0] in M.APP_CLIENTS}
    return {"/%s/%s" % (app, g) for g in M.APP_DELEGATIONS.get(app, {}).get(cid, ())} & set(tree)

def matrix(M, adm, app, callers, tree, outside, live, um=None):
    """For each delegate and each group: may it ADD a tree member to the group, and REMOVE one from it? Expected
    exactly when APP_DELEGATIONS lists the group for it. Outside groups (/roles/*, other apps' trees, a loose group):
    always refused. Returns nothing; records PASS/FAIL lines."""
    rows = []
    ALL_PATHS[:] = tree + outside
    who = list(callers.items()) + ([("idp-user-manager", um)] if um else [])
    for cid, c in who:
        mem = ensure_user(adm, "t.split.m.%s" % cid.replace("-", "")[:20])
        allow = allowed_writes(M, app, cid, tree)
        for path in tree + outside:
            base = "/%s/viewer" % app if path != "/%s/viewer" % app else "/%s/editor" % app
            g = gid(adm, path)
            set_groups(adm, mem, [base])
            st_add, _ = c.call("PUT", "/users/%s/groups/%s" % (mem, g))
            added = path in groups_of(adm, mem)
            exp = path in allow
            check("%-31s ADD a tree member to %s" % (cid, path), (st_add == 204 and added) if exp else (st_add in (403, 404) and not added),
                  "HTTP %s (expected %s)" % (st_add, "204" if exp else "403"))
            st_del = None
            if not (live and path.startswith("/roles/")):           # live: never place anyone in /roles/*
                set_groups(adm, mem, [base, path])
                st_del, _ = c.call("DELETE", "/users/%s/groups/%s" % (mem, g))
                gone = path not in groups_of(adm, mem)
                check("%-31s REMOVE a tree member from %s" % (cid, path), (st_del == 204 and gone) if exp else (st_del in (403, 404) and not gone),
                      "HTTP %s (expected %s)" % (st_del, "204" if exp else "403"))
            rows.append((cid, path, exp, st_add, st_del))
            set_groups(adm, mem, [])
    return rows

def account_powers(adm, app, callers, live):
    """No account powers beyond membership, checkable before any partner role exists (the operating guide's apply step 5 as well as
    step 6): every stig-accounts call and impersonation of a tree member are refused. Live, stig-accounts is served,
    so only 403 passes; the lab start does not serve it, so 404 passes there too."""
    mem = ensure_user(adm, "t.split.powers", ["/%s/viewer" % app])
    sa_ok = (403,) if live else (403, 404)
    for cid, c in callers.items():
        st, _ = c.call("POST", "/stig-accounts/users", {"username": "t.split.loose", "email": "t.split.loose@example.mil",
                                                        "firstName": "T", "lastName": "Loose", "group": "/%s/viewer" % app})
        check("%-31s stig-accounts: cannot create" % cid, st in sa_ok, "HTTP %s%s" % (st, " (endpoint absent in this lab)" if st == 404 else ""))
        st1, _ = c.call("POST", "/stig-accounts/users/%s/setup-email" % mem)
        st2, _ = c.call("POST", "/stig-accounts/users/%s/disable" % mem)
        en = adm.call("GET", "/users/%s" % mem)[1].get("enabled")
        check("%-31s stig-accounts: cannot re-send set-up mail or disable a member" % cid, st1 in sa_ok and st2 in sa_ok and en is True,
              "HTTP %s/%s, enabled=%s" % (st1, st2, en))
        st, _ = c.call("POST", "/users/%s/impersonation" % mem)
        check("%-31s cannot IMPERSONATE a tree member" % cid, st == 403, "HTTP %s" % st)
    adm.call("DELETE", "/users/%s" % mem)

def reach(adm, app, callers, live):
    """J1: a delegate sees and moves only accounts already in the tree; it can edit nothing and create nobody."""
    reader = "/%s/partner-reader" % app
    rg = gid(adm, reader)
    by = ensure_user(adm, "t.split.bystander")                              # in no group at all
    other_app = [p for p in ("/app-b/member", "/app-c/reader") if gid(adm, p)]
    oa = ensure_user(adm, "t.split.otherapp", other_app[:1])                # another application's member
    mem = ensure_user(adm, "t.split.member", ["/%s/viewer" % app])
    ronly = ensure_user(adm, "t.split.readeronly", [reader])
    for cid, c in callers.items():
        for label, uid in (("a non-member", by), ("another app's member (%s)" % (other_app[:1] or ["none"])[0], oa)):
            st, _ = c.call("GET", "/users/%s" % uid); check("%-31s cannot READ %s" % (cid, label), st in (403, 404), "HTTP %s" % st)
            st, _ = c.call("GET", "/users/%s/groups" % uid); check("%-31s cannot read %s's groups" % (cid, label), st in (403, 404), "HTTP %s" % st)
            st, _ = c.call("PUT", "/users/%s/groups/%s" % (uid, rg))
            check("%-31s cannot ADD %s to partner-reader" % (cid, label), st in (403, 404) and reader not in groups_of(adm, uid), "HTTP %s" % st)
        st, us = c.call("GET", "/users?max=1000")
        ids = [u["id"] for u in us] if st == 200 and isinstance(us, list) else []
        check("%-31s user listing shows no non-member" % cid, st in (200, 403) and by not in ids and oa not in ids, "HTTP %s, %d listed" % (st, len(ids)))
        st, us = c.call("GET", "/users?search=t.split&max=1000")
        ids = [u["id"] for u in us] if st == 200 and isinstance(us, list) else []
        check("%-31s user search finds no non-member" % cid, st in (200, 403) and by not in ids and oa not in ids, "HTTP %s, %d found" % (st, len(ids)))
        st, us = c.call("GET", "/users?q=cac_edipi:1111111111")
        check("%-31s attribute search refused or empty" % cid, st in (400, 403) or (st == 200 and not us), "HTTP %s" % st)
        if other_app:
            st, _ = c.call("GET", "/groups/%s/members" % gid(adm, other_app[0]))
            check("%-31s cannot list another app's members (%s)" % (cid, other_app[0]), st in (403, 404), "HTTP %s" % st)
        st, _ = c.call("GET", "/users/%s" % mem); check("%-31s CAN read a tree member" % cid, st == 200, "HTTP %s" % st)
        st1, g = c.call("GET", "/group-by-path/%s/partner-reader" % app)
        st2, ms = c.call("GET", "/groups/%s/members" % rg)
        st3, ug = c.call("GET", "/users/%s/groups" % mem)
        check("%-31s CAN GET group-by-path, partner-reader's members, a member's groups" % cid,
              (st1, st2, st3) == (200, 200, 200) and g.get("id") == rg and ronly in [x["id"] for x in ms], "HTTP %s/%s/%s" % (st1, st2, st3))
        # the lead's flow: a tree member becomes a reader, and stops being one
        set_groups(adm, mem, ["/%s/viewer" % app])
        st1, _ = c.call("PUT", "/users/%s/groups/%s" % (mem, rg)); in1 = reader in groups_of(adm, mem)
        st2, _ = c.call("DELETE", "/users/%s/groups/%s" % (mem, rg)); in2 = reader in groups_of(adm, mem)
        check("%-31s CAN make a tree member a reader, and undo it" % cid, (st1, st2) == (204, 204) and in1 and not in2,
              "HTTP %s/%s" % (st1, st2))
        set_groups(adm, ronly, [reader])
        st, _ = c.call("DELETE", "/users/%s/groups/%s" % (ronly, rg))
        check("%-31s CAN remove a reader-only member from partner-reader" % cid, st == 204 and reader not in groups_of(adm, ronly), "HTTP %s" % st)
        set_groups(adm, ronly, [reader])
        # nothing beyond membership
        full = c.call("GET", "/users/%s" % mem)[1]
        st, _ = c.call("PUT", "/users/%s" % mem, dict(full, firstName="Hijacked")); check("%-31s cannot EDIT a member" % cid, st == 403, "HTTP %s" % st)
        st, _ = c.call("PUT", "/users/%s/reset-password" % mem, {"type": "password", "value": secrets.token_urlsafe(24), "temporary": False})
        check("%-31s cannot reset a member's password" % cid, st == 403, "HTTP %s" % st)
        st, _ = c.call("PUT", "/users/%s/execute-actions-email" % mem, ["UPDATE_PASSWORD"])
        check("%-31s cannot send execute-actions mail" % cid, st == 403, "HTTP %s" % st)
        st, _ = c.call("DELETE", "/users/%s" % mem); check("%-31s cannot DELETE a member" % cid, st == 403, "HTTP %s" % st)
        st, _ = c.call("POST", "/users", {"username": "t.split.loose", "enabled": True, "groups": [reader]})
        check("%-31s cannot CREATE a user (plain admin API)" % cid, st == 403, "HTTP %s" % st)
        st, _ = c.call("POST", "/stig-accounts/users", {"username": "t.split.loose", "email": "t.split.loose@example.mil",
                                                        "firstName": "T", "lastName": "Loose", "group": reader})
        check("%-31s cannot create a READER through stig-accounts" % cid, st in ((403,) if live else (403, 404)),
              "HTTP %s%s" % (st, " (endpoint absent)" if st == 404 else ""))
        st, _ = c.call("POST", "/users/%s/impersonation" % ronly)
        check("%-31s cannot IMPERSONATE a reader" % cid, st == 403, "HTTP %s" % st)
        appc = [x for x in adm.call("GET", "/clients?clientId=%s" % q(app))[1] if x["clientId"] == app][0]
        lead = adm.call("GET", "/clients/%s/roles/partner-lead" % appc["id"])
        if lead[0] == 200:
            st, _ = c.call("POST", "/users/%s/role-mappings/clients/%s" % (mem, appc["id"]), [lead[1]])
            check("%-31s cannot MAP partner-lead directly" % cid, st == 403, "HTTP %s" % st)
            st, _ = c.call("POST", "/groups/%s/role-mappings/clients/%s" % (rg, appc["id"]), [lead[1]])
            check("%-31s cannot make partner-reader's group carry partner-lead" % cid, st == 403, "HTTP %s" % st)
        st, _ = c.call("PUT", "/groups/%s" % rg, {"name": "partner-reader", "path": reader, "attributes": {"x": ["y"]}})
        check("%-31s cannot change the partner-reader group" % cid, st == 403, "HTTP %s" % st)
        st, _ = c.call("POST", "/groups/%s/children" % rg, {"name": "t-split-child"})
        check("%-31s cannot create a subgroup" % cid, st == 403, "HTTP %s" % st)
    eff = adm.call("GET", "/users/%s/role-mappings/clients/%s/composite" % (mem, [x for x in adm.call("GET", "/clients?clientId=%s" % q(app))[1]
                   if x["clientId"] == app][0]["id"]))[1]
    check("the member holds no partner role after all of that", not [r for r in eff if r["name"] in REVIEW], str([r["name"] for r in eff]))

def cleanup_users(adm):
    for u in adm.call("GET", "/users?search=t.split&max=1000")[1]:
        if u["username"].startswith("t.split."):
            adm.call("DELETE", "/users/%s" % u["id"])

def print_matrix(rows, tree):
    callers = sorted({r[0] for r in rows})
    print("\nPermission matrix (manage-membership: add and remove a tree member; Y = allowed, - = refused 403):")
    print("%-40s %s" % ("group", "  ".join("%-30s" % c for c in callers)))
    for path in dict.fromkeys(r[1] for r in rows):
        line = []
        for c in callers:
            r = [x for x in rows if x[0] == c and x[1] == path][0]
            line.append("%-30s" % ("%s  (add %s, remove %s)" % ("Y" if r[2] else "-", r[3], r[4] if r[4] is not None else "n/a")))
        print("%-40s %s" % (path, "  ".join(line)))

# ------------------------------------------------------------------------------------------------ lab
def lab_realm(adm, realm):
    st, r = adm.call("GET", "", realm=realm)
    if st == 200:
        if (r.get("attributes") or {}).get(LAB_MARK) != "true":
            sys.exit("REFUSED: realm %s exists and is not this test's throwaway realm" % realm)
        adm.call("DELETE", "", realm=realm)
    if True:
        adm.call("GET", "")                                   # a fresh token
        st, body = adm.http.raw("POST", "/admin/realms", json.dumps({"realm": realm, "enabled": True, "attributes": {LAB_MARK: "true"}}).encode(),
                                {"Authorization": "Bearer " + adm.token, "Content-Type": "application/json"})
        if st != 201:
            sys.exit("could not create %s: HTTP %s %s" % (realm, st, body[:200]))
    adm.call("PUT", "", {"adminPermissionsEnabled": True}, realm=realm)

def lab_clients(adm, app, review):
    def client(cid, roles):
        adm.call("POST", "/clients", {"clientId": cid, "publicClient": False, "standardFlowEnabled": True,
                                      "redirectUris": ["https://%s.test.invalid/cb" % cid]})
        c = [x for x in adm.call("GET", "/clients?clientId=%s" % q(cid))[1] if x["clientId"] == cid][0]
        for r in roles:
            adm.call("POST", "/clients/%s/roles" % c["id"], {"name": r})
    client(app, list(APP_A_ROLES) + (list(REVIEW) if review else []))
    client("app-b", ["owner", "maintainer", "reviewer", "member"])
    adm.call("POST", "/groups", {"name": "t-split-elsewhere"})                 # a group nobody is delegated

def add_review_roles(adm, app):
    c = [x for x in adm.call("GET", "/clients?clientId=%s" % q(app))[1] if x["clientId"] == app][0]
    for r in REVIEW:
        adm.call("POST", "/clients/%s/roles" % c["id"], {"name": r})

def lab_roles(M, kc):
    """The /roles/* groups and what they carry, as roles-setup makes them (the rest of roles-setup is realm hardening
    and the allowlist guard, which this test does not need)."""
    for name, roles in M.ROLE_GROUPS.items():
        M.set_group_client_roles(kc, M.ensure_group(kc, "/roles/" + name), "realm-management", roles)

def legacy_delegation(M, kc, app, tree_ids):
    """The state live today (before the per-group split): ONE permission over the whole tree, manage-membership included,
    for the AFFIRMATIVE aggregate of the user managers and app-a's administrator - exactly what the earlier
    roles-setup and fgap/app_admin_fgap.py setup wrote."""
    ap = kc.api("GET", "/clients?clientId=admin-permissions")[0]; base = "/clients/%s/authz/resource-server" % ap["id"]
    um = M.ensure_um_policy(kc, base)
    fa = M.ensure_delegate_policy(kc, base, "app-a-admin")
    agg = M.ensure_aggregate(kc, base, "delegates of /%s" % app, [um, fa])
    M.ensure_group_permission(kc, base, "delegated: /%s" % app, tree_ids, M.TREE_SCOPES + ["manage-membership"], agg)
    cagg = M.ensure_aggregate(kc, base, "delegates of /app-b", [um])
    M.ensure_group_permission(kc, base, "delegated: /app-b",
                              [g["id"] for g in M.app_groups(kc) if g["path"].startswith("/app-b")], M.SCOPES_MEMBERS, cagg)

def um_person(http, adm, realm):
    uid = ensure_user(adm, "t.split.usermanager", ["/roles/idp-user-manager"])
    pw = "Lab-" + secrets.token_urlsafe(24)            # throwaway realm only; never printed
    adm.call("PUT", "/users/%s/reset-password" % uid, {"type": "password", "value": pw, "temporary": False})
    return Caller(http, realm, {"_realm": realm, "grant_type": "password", "client_id": "admin-cli",
                                "username": "t.split.usermanager", "password": pw}, "idp-user-manager")

def tree_paths(adm, app):
    root = gid(adm, "/" + app)
    kids = adm.call("GET", "/groups/%s/children?max=1000" % root)[1]
    return ["/" + app] + sorted(k["path"] for k in kids)

def outside_paths(adm):
    return [p for p in ("/roles/idp-admin", "/roles/idp-user-manager", "/roles/idp-auditor", "/app-b",
                        "/app-b/owner", "/app-b/member", "/t-split-elsewhere") if gid(adm, p)]

def run_fgap_setup(a, realm):
    """fgap/app_admin_fgap.py setup against the lab realm, as the operator runs it. -> (exit code, output)."""
    import subprocess
    cmd = [sys.executable, os.path.join(HERE, "app_admin_fgap.py"), "--url", a.url, "--realm", realm,
           "--admin-script", a.admin_script, "--app", "app-a"]
    cmd += (["--admin-client-id", a.admin_client_id, "--admin-secret-file", a.admin_secret_file] if a.admin_client_id
            else ["--admin-user", a.admin_user, "--admin-password-file", a.admin_password_file])
    r = subprocess.run(cmd + ["setup"], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr

def authz_state(adm, app):
    """(tree permission scopes, sorted names of every membership:/writers of/delegates of object, and their members)."""
    ap = adm.call("GET", "/clients?clientId=admin-permissions")[1][0]; base = "/clients/%s/authz/resource-server" % ap["id"]
    tp = [p for p in adm.call("GET", base + "/permission?name=%s" % q("delegated: /" + app))[1] if p["name"] == "delegated: /" + app]
    scopes = sorted(x["name"] for x in adm.call("GET", base + "/permission/%s/scopes" % tp[0]["id"])[1]) if tp else None
    objs = {}
    for p in adm.call("GET", base + "/policy?first=0&max=1000")[1]:
        if p["name"].startswith(("membership: /" + app, "writers of /" + app, "delegates of /" + app)):
            objs[p["name"]] = sorted(x["name"] for x in adm.call("GET", base + "/policy/%s/associatedPolicies" % p["id"])[1])
    return scopes, objs

def fgap_setup_checks(a, adm, M, app, realm, fa, mem):
    """The fgap setup never grants a write and fails closed on a partial or inconsistent split (review HIGH)."""
    ap = adm.call("GET", "/clients?clientId=admin-permissions")[1][0]; base = "/clients/%s/authz/resource-server" % ap["id"]
    def fa_can(path):
        set_groups(adm, mem, ["/%s/viewer" % app])
        st, _ = fa.call("PUT", "/users/%s/groups/%s" % (mem, gid(adm, path))); set_groups(adm, mem, ["/%s/viewer" % app])
        return st
    # converged realm: setup succeeds and changes no grant
    before = authz_state(adm, app)
    rc, out = run_fgap_setup(a, realm)
    check("[fgap setup] on a fully split realm: succeeds, the tree permission stays sight-only, no grant changes",
          rc == 0 and authz_state(adm, app) == before and "manage-membership" not in before[0], "rc %s; %s" % (rc, out.strip().splitlines()[-1:]))
    # partial split: one group's write permission is missing
    name = "membership: /%s/administrator" % app
    pid = [p for p in adm.call("GET", base + "/permission?name=%s" % q(name))[1] if p["name"] == name][0]["id"]
    adm.call("DELETE", base + "/permission/%s" % pid)
    before = authz_state(adm, app)
    rc, out = run_fgap_setup(a, realm)
    after = authz_state(adm, app)
    check("[fgap setup] PARTIAL split (one group's write permission missing): REFUSED, names roles-setup",
          rc != 0 and "REFUSED" in out and "roles-setup" in out and "administrator" in out, "rc %s" % rc)
    check("[fgap setup] ... and it granted nothing: the tree permission and every aggregate unchanged, no tree-wide write",
          after == before and "manage-membership" not in (after[0] or []), str(after[0]))
    check("[fgap setup] ... so app-a's administrator cannot write the uncovered group (administrator)", fa_can("/%s/administrator" % app) in (403, 404))
    kc = Adapter(adm); M.sync_delegations(kc, M.app_groups(kc))
    check("[roles-setup] repairs the partial split (administrator writable by app-a's administrator again)", fa_can("/%s/administrator" % app) == 204)
    # drift: someone added app-a's administrator to partner-lead's writers
    fa_pol = [p for p in adm.call("GET", base + "/policy?name=%s" % q(M.delegate_policy_name("app-a-admin")))[1]
              if p["name"] == M.delegate_policy_name("app-a-admin")][0]["id"]
    w = "writers of /%s/partner-lead" % app
    agg = [p for p in adm.call("GET", base + "/policy?name=%s" % q(w))[1] if p["name"] == w][0]
    mem_ids = [x["id"] for x in adm.call("GET", base + "/policy/%s/associatedPolicies" % agg["id"])[1]]
    adm.call("PUT", base + "/policy/aggregate/%s" % agg["id"], {"id": agg["id"], "name": w, "type": "aggregate", "logic": "POSITIVE",
                                                                 "decisionStrategy": "AFFIRMATIVE", "policies": mem_ids + [fa_pol]})
    rc, out = run_fgap_setup(a, realm)
    check("[fgap setup] DRIFT (app-a's administrator among partner-lead's writers): REFUSED", rc != 0 and "partner-lead" in out, "rc %s" % rc)
    kc = Adapter(adm); M.sync_delegations(kc, M.app_groups(kc))
    check("[roles-setup] removes the drift (partner-lead closed to app-a's administrator again)", fa_can("/%s/partner-lead" % app) in (403, 404))
    # a new role nobody lists: fgap setup creates its subgroup but grants no write, and refuses until roles-setup
    c = [x for x in adm.call("GET", "/clients?clientId=%s" % q(app))[1] if x["clientId"] == app][0]
    adm.call("POST", "/clients/%s/roles" % c["id"], {"name": "partner-superlead"})
    rc, out = run_fgap_setup(a, realm)
    check("[fgap setup] a NEW unlisted role: REFUSED until roles-setup covers its group", rc != 0 and "partner-superlead" in out, "rc %s" % rc)
    check("[fgap setup] ... and its group is closed to app-a's administrator meanwhile", fa_can("/%s/partner-superlead" % app) in (403, 404))
    kc = Adapter(adm); M.sync_delegations(kc, M.app_groups(kc))
    rc, out = run_fgap_setup(a, realm)
    check("[roles-setup] covers the new role for the user managers only; fgap setup then succeeds",
          rc == 0 and fa_can("/%s/partner-superlead" % app) in (403, 404), "rc %s" % rc)

def lab(a):
    M = load_idp_admin(a.admin_script)
    http = Http(a.url, a.cacert); app = "app-a"
    global APP_A_ROLES; APP_A_ROLES = tuple(g for g in M.APP_DELEGATIONS["app-a"]["app-a-admin"] if g != "partner-reader")
    for realm in ("split-lab-a", "split-lab-b"):
        if realm == "split-lab-b" and a.only_a:
            continue
        adm = admin_caller(a, http, realm); adm.login(); lab_realm(adm, realm)
        kc = Adapter(adm)
        print("\n================ %s: %s" % (realm, "the live order" if realm.endswith("a") else "partner roles added BEFORE the split"))
        lab_clients(adm, app, review=realm.endswith("b"))
        lab_roles(M, kc)
        M.ensure_delegate_client(kc, "app-a-admin", "app-a account administrator")
        apps = M.app_groups(kc)
        legacy_delegation(M, kc, app, [g["id"] for g in apps if g["path"].startswith("/" + app)])
        before = authz_state(adm, app)
        rc, out = run_fgap_setup(a, realm)
        check("[fgap setup] on the earlier (unsplit) realm: REFUSED, names roles-setup, changes nothing",
              rc != 0 and "roles-setup" in out and authz_state(adm, app) == before, "rc %s" % rc)
        fa = sa_caller(http, adm, realm, "app-a-admin")
        mem = ensure_user(adm, "t.split.probe", ["/%s/viewer" % app])
        adm_g, ou = gid(adm, "/%s/administrator" % app), gid(adm, "/%s/viewer" % app)
        def fa_moves():
            set_groups(adm, mem, ["/%s/viewer" % app])
            s1, _ = fa.call("PUT", "/users/%s/groups/%s" % (mem, adm_g)); s2, _ = fa.call("DELETE", "/users/%s/groups/%s" % (mem, ou))
            s3, _ = fa.call("PUT", "/users/%s/groups/%s" % (mem, ou)); s4, _ = fa.call("DELETE", "/users/%s/groups/%s" % (mem, adm_g))
            return (s1, s2, s3, s4)
        check("[legacy] app-a's administrator moves a member between app-a roles", fa_moves() == (204,) * 4)
        if realm.endswith("b"):
            set_groups(adm, mem, ["/%s/viewer" % app])
            st, _ = fa.call("PUT", "/users/%s/groups/%s" % (mem, gid(adm, "/%s/partner-lead" % app)))
            check("[legacy] THE DEFECT: app-a's administrator can move a member INTO partner-lead", st == 204,
                  "HTTP %s (reproduces the escalation the split closes)" % st)
            set_groups(adm, mem, ["/%s/viewer" % app])
        # the migration, probing after every permission write
        window = []
        def probe(method, path):
            r = fa_moves()
            lead = gid(adm, "/%s/partner-lead" % app)
            st_lead = None
            if lead:
                set_groups(adm, mem, ["/%s/viewer" % app])
                st_lead, _ = fa.call("PUT", "/users/%s/groups/%s" % (mem, lead))
                set_groups(adm, mem, ["/%s/viewer" % app])
            st_um, _ = fa.call("PUT", "/users/%s/groups/%s" % (mem, gid(adm, "/roles/idp-user-manager")))
            set_groups(adm, mem, ["/%s/viewer" % app])
            window.append((method, path.split("/authz/resource-server")[-1], r, st_lead, st_um))
        kc_m = Adapter(adm, on_authz_write=probe)
        M.sync_delegations(kc_m, M.app_groups(kc_m))
        lost = [w for w in window if w[2] != (204,) * 4]
        check("[migration] app-a's administrator kept its app-a moves after each of %d permission writes" % len(window), not lost,
              str(lost[:3]))
        gained = [w for w in window if w[4] not in (403, 404)]
        check("[migration] ... and never reached /roles/idp-user-manager during it", not gained, str(gained[:3]))
        if realm.endswith("b"):
            # the very first write may still precede the LEAD group's own permission; from that write on, it is closed
            first_lead = [i for i, w in enumerate(window) if "permission" in w[1] and w[3] in (403, 404)]
            check("[migration] partner-lead closed to app-a's administrator once its own permission exists, and stays closed",
                  first_lead and all(w[3] in (403, 404) for w in window[first_lead[0]:]), "first refused at write %s of %d" %
                  (first_lead[0] + 1 if first_lead else None, len(window)))
        # reader-delegate-setup
        rd_window = []
        def probe_rd(method, path):
            if not [x for x in adm.call("GET", "/clients?clientId=app-a-reader-delegate")[1]]:
                return
            rd = sa_caller(http, adm, realm, "app-a-reader-delegate")
            set_groups(adm, mem, ["/%s/viewer" % app])
            bad = []
            for p in tree_paths(adm, app) + outside_paths(adm):
                if p.endswith("/partner-reader") or p == "/%s/viewer" % app:
                    continue
                st, _ = rd.call("PUT", "/users/%s/groups/%s" % (mem, gid(adm, p)))
                if st not in (403, 404):
                    bad.append((p, st))
                set_groups(adm, mem, ["/%s/viewer" % app])
            rd_window.append(bad)
        kc_r = Adapter(adm, on_authz_write=probe_rd)
        M.ensure_delegate_client(kc_r, "app-a-reader-delegate", "app-a partner reader delegate")
        M.sync_delegations(kc_r, M.app_groups(kc_r))
        check("[reader-delegate-setup] the reader delegate wrote no group but partner-reader at any of %d writes" % len(rd_window),
              not any(rd_window), str([b for b in rd_window if b][:2]))
        if realm.endswith("a"):
            # the rollback of the live apply (before any partner role exists), probed after every write, then re-applied
            rb_window = []
            rd = sa_caller(http, adm, realm, "app-a-reader-delegate")
            def probe_rb(method, path):
                rd_bad = []
                if [c for c in adm.call("GET", "/clients?clientId=app-a-reader-delegate")[1] if c.get("enabled", True)]:
                    set_groups(adm, mem, ["/%s/viewer" % app])
                    for p in ("/%s/administrator" % app, "/" + app, "/roles/idp-user-manager"):
                        st, _ = rd.call("PUT", "/users/%s/groups/%s" % (mem, gid(adm, p)))
                        if st not in (403, 404, 401):
                            rd_bad.append((p, st))
                        set_groups(adm, mem, ["/%s/viewer" % app])
                rb_window.append((fa_moves(), rd_bad))
            kc_rb = Adapter(adm, on_authz_write=probe_rb)
            M.rollback_delegations(kc_rb, M.app_groups(kc_rb))
            check("[rollback] app-a's administrator kept its app-a moves after each of %d writes" % len(rb_window),
                  all(w[0] == (204,) * 4 for w in rb_window), str([w for w in rb_window if w[0] != (204,) * 4][:2]))
            check("[rollback] the reader delegate never wrote anything during it", not any(w[1] for w in rb_window),
                  str([w[1] for w in rb_window if w[1]][:2]))
            ap_ = adm.call("GET", "/clients?clientId=admin-permissions")[1][0]; base_ = "/clients/%s/authz/resource-server" % ap_["id"]
            left = [p["name"] for p in adm.call("GET", base_ + "/permission?name=membership")[1]]
            rdc = [c for c in adm.call("GET", "/clients?clientId=app-a-reader-delegate")[1]][0]
            set_groups(adm, mem, ["/%s/viewer" % app])
            st_root, _ = fa.call("PUT", "/users/%s/groups/%s" % (mem, gid(adm, "/" + app)))
            set_groups(adm, mem, ["/%s/viewer" % app])
            check("[rollback] the earlier shape is back: no per-group permission, the tree root writable again, the reader delegate disabled",
                  not left and st_root == 204 and rdc.get("enabled") is False, "left %s, root HTTP %s, enabled %s" % (left, st_root, rdc.get("enabled")))
            # re-apply: roles-setup, then reader-delegate-setup (which re-enables nothing by itself: the operator does)
            full = adm.call("GET", "/clients/%s" % rdc["id"])[1]; full["enabled"] = True; adm.call("PUT", "/clients/%s" % rdc["id"], full)
            M.sync_delegations(Adapter(adm), M.app_groups(Adapter(adm)))
            kc_again = Adapter(adm); M.sync_delegations(kc_again, M.app_groups(kc_again))
            check("[re-apply after rollback] converges again (a second run makes no write)", not kc_again.writes, str(kc_again.writes[:3]))
            # the client-file change that waits for the operator: partner roles added, then roles-setup
            add_review_roles(adm, app)
            win3 = []
            def probe3(method, path):
                set_groups(adm, mem, ["/%s/viewer" % app])
                out = []
                for g in ("partner-lead", "partner-auditor", "contractor"):
                    if gid(adm, "/%s/%s" % (app, g)):
                        st, _ = fa.call("PUT", "/users/%s/groups/%s" % (mem, gid(adm, "/%s/%s" % (app, g))))
                        out.append((g, st)); set_groups(adm, mem, ["/%s/viewer" % app])
                win3.append(out)
            kc3 = Adapter(adm, on_authz_write=probe3)
            apps3 = M.app_groups(kc3)       # creates the partner groups (no permission covers them yet)
            probe3("-", "/authz/after-groups-created")
            M.sync_delegations(kc3, apps3)
            leaks = [o for w in win3 for o in w if o[1] not in (403, 404)]
            check("[partner roles added] LEAD/ASSESSOR/contractor closed to app-a's administrator at every step (%d probes)" % len(win3),
                  not leaks, str(leaks[:3]))
        if realm.endswith("b"):
            try:
                M.rollback_delegations(Adapter(adm), M.app_groups(Adapter(adm))); refused = None
            except SystemExit as e:
                refused = str(e)
            check("[rollback] REFUSED once partner roles exist (it would re-open the escalation)", refused and "REFUSED" in refused, str(refused)[:120])
        if realm.endswith("a"):
            fgap_setup_checks(a, adm, M, app, realm, fa, mem)
        # idempotence
        kc_i = Adapter(adm)
        M.sync_delegations(kc_i, M.app_groups(kc_i))
        check("re-running roles-setup's delegation sync makes no write (converged)", not kc_i.writes, str(kc_i.writes[:4]))
        kc_c = Adapter(adm)
        M.ensure_delegate_client(kc_c, "app-a-reader-delegate", "app-a partner reader delegate")
        check("re-running reader-delegate-setup's client step makes no write", not kc_c.writes, str(kc_c.writes[:4]))
        adm.call("DELETE", "/users/%s" % mem)
        # the matrix
        callers = {"app-a-admin": sa_caller(http, adm, realm, "app-a-admin"),
                   "app-a-reader-delegate": sa_caller(http, adm, realm, "app-a-reader-delegate")}
        um = um_person(http, adm, realm)
        tree, outside = tree_paths(adm, app), outside_paths(adm)
        rows = matrix(M, adm, app, callers, tree, outside, live=False, um=um)
        reach(adm, app, callers, live=False)
        account_powers(adm, app, callers, live=False)
        if realm.endswith("a"):
            # a group leaves the tree: its write permission must go, and must never be left covering ALL groups
            ap = adm.call("GET", "/clients?clientId=admin-permissions")[1][0]; base = "/clients/%s/authz/resource-server" % ap["id"]
            name = "membership: /%s/partner-auditor" % app
            pid = [p for p in adm.call("GET", base + "/permission?name=%s" % q(name))[1] if p["name"] == name][0]["id"]
            adm.call("DELETE", "/groups/%s" % gid(adm, "/%s/partner-auditor" % app))
            st, perm = adm.call("GET", base + "/permission/%s" % pid)
            res = adm.call("GET", base + "/permission/%s/resources" % pid)[1] if st == 200 else []
            print("      (Keycloak, after the group was deleted: permission HTTP %s, resources %s)" % (st, res))
            probe_u = ensure_user(adm, "t.split.afterdelete", ["/%s/viewer" % app])
            stx, _ = callers["app-a-reader-delegate"].call("PUT", "/users/%s/groups/%s" % (probe_u, gid(adm, "/roles/idp-admin")))
            check("deleting a group never widens a delegate (reader delegate -> /roles/idp-admin)", stx in (403, 404), "HTTP %s" % stx)
            set_groups(adm, probe_u, [])
            kc_d = Adapter(adm)
            M.sync_delegations(kc_d, [g for g in M.app_groups(kc_d) if not g["path"].endswith("/partner-auditor")])
            left = [p for p in adm.call("GET", base + "/permission?name=%s" % q(name))[1] if p["name"] == name]
            check("roles-setup removes the write permission of a group that left the tree", not left, str(left))
            # roles-setup would re-create the group from the client role; do that and converge again
            kc_e = Adapter(adm); M.sync_delegations(kc_e, M.app_groups(kc_e))
        print_matrix(rows, tree)
        cleanup_users(adm)
        if not a.keep:
            adm.call("DELETE", "", realm=realm); print("realm %s deleted" % realm)
    print("\n%d/%d passed" % (sum(results), len(results))); sys.exit(0 if all(results) else 1)

def test(a):
    """The matrix on a converged realm (live after the apply). No /roles/* membership is ever created."""
    M = load_idp_admin(a.admin_script)
    http = Http(a.url, a.cacert); app = a.app
    adm = admin_caller(a, http, a.realm); adm.login()
    def cred(secret_file, key_file):
        if bool(secret_file) == bool(key_file):
            sys.exit("give exactly one of --sa-secret-file/--sa-jwt-key (and of --reader-secret-file/--reader-jwt-key)")
        return (open(secret_file).read().strip() if secret_file else None), key_file
    s1, k1 = cred(a.sa_secret_file, a.sa_jwt_key); s2, k2 = cred(a.reader_secret_file, a.reader_jwt_key)
    # --sa-client-id / --reader-client-id: sign in as each delegate's TEST TWIN (same delegation; idp-admin.py
    # delegate-test-twin) when the delegate itself is on client-jwt; the matrix is still the delegate's
    callers = {"app-a-admin": sa_caller(http, adm, a.realm, a.sa_client_id or "app-a-admin", s1, k1),
               "app-a-reader-delegate": sa_caller(http, adm, a.realm, a.reader_client_id or "app-a-reader-delegate", s2, k2)}
    try:
        tree, outside = tree_paths(adm, app), outside_paths(adm)
        rows = matrix(M, adm, app, callers, tree, outside, live=True)
        account_powers(adm, app, callers, live=True)
        if gid(adm, "/%s/partner-reader" % app):
            reach(adm, app, callers, live=True)
        else:
            print("(no /%s/partner-reader yet: the reader delegate's reach checks wait for the partner roles)" % app)
        print_matrix(rows, tree)
    finally:
        cleanup_users(adm)
    print("\n%d/%d passed" % (sum(results), len(results))); sys.exit(0 if all(results) else 1)

APP_A_ROLES = ()
ALL_PATHS = []
ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--url", required=True); ap.add_argument("--cacert")
ap.add_argument("--admin-script", default=os.path.join(HERE, "..", "host", "idp-admin.py"))
ap.add_argument("--admin-user"); ap.add_argument("--admin-password-file"); ap.add_argument("--admin-client-id"); ap.add_argument("--admin-secret-file")
sp = ap.add_subparsers(dest="cmd", required=True)
l = sp.add_parser("lab"); l.add_argument("--keep", action="store_true"); l.add_argument("--only-a", action="store_true"); l.set_defaults(fn=lab)
t = sp.add_parser("test"); t.add_argument("--realm", required=True); t.add_argument("--app", default="app-a")
t.add_argument("--sa-secret-file"); t.add_argument("--reader-secret-file")
t.add_argument("--sa-client-id"); t.add_argument("--reader-client-id")
t.add_argument("--sa-jwt-key", help="client-jwt: the delegate's PEM private key (ES256/RS256), instead of --sa-secret-file")
t.add_argument("--reader-jwt-key", help="client-jwt: the reader delegate's PEM private key, instead of --reader-secret-file")
t.set_defaults(fn=test)
a = ap.parse_args(); a.fn(a)

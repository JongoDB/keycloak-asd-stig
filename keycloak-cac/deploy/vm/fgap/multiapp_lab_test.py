#!/usr/bin/env python3
"""app-a's access-request form fulfils app-b and app-c roles too: one onboarding client
serves several application trees, and each caller reaches only the trees their own manager roles cover. Proved
against a throwaway keycloak-cac container in lab mode (strict FIPS), driving idp-admin.py's own code.

  fgap/onboarding_lab.sh <image> <kas checkout> [report] multiapp_lab_test.py

  setup     roles-setup makes /roles/<client>-user-manager for app-a, app-b and app-c;
            grant refuses a app-b manager without that client's admin role (held directly)
  app-a-only manager   cannot create into or move anyone into /app-b-*; works in /app-a
  app-b manager       creates into /app-b/owner (an APP admin group) and /app-c, adds the second
                       tree's role by membership; cannot touch /app-a, any /roles/* group, or a tree root
  all-apps user manager both trees; an IdP admin both trees when it also holds the user-manager role (an IdP admin
                       alone gets nothing through the capped portal client, by design)
  profile   step-up (a write older than max-auth-age: 401 + challenge) and the operations list (disable not listed:
            403) still apply
  guard / check-clients  the multi-app record; retiring an app: an orphaned manager role and an unconfigured app reported
"""
import argparse, contextlib, http.client, importlib.machinery, importlib.util, io, json, os, secrets, socket
import ssl, sys, tempfile, time, urllib.parse, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser()
ap.add_argument("--cacert", required=True)
ap.add_argument("--skill-scripts", required=True)
ap.add_argument("--admin", default=os.path.join(HERE, "..", "host", "idp-admin.py"))
ap.add_argument("--realm", default="dod-cac")
ap.add_argument("--origin", default="https://portal.lab.example")
a = ap.parse_args()

os.environ.setdefault("IDP_ADMIN_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures", "idp-admin.test.json"))   # the lab/unit config; on a host the real one is used
ld = importlib.machinery.SourceFileLoader("idp_admin", a.admin)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
# the lab config's application shape (tests/fixtures/idp-admin.test.json)
APP_A_ROLES = tuple(g for g in M.APP_DELEGATIONS["app-a"]["app-a-admin"] if g != "partner-reader")
APP_BC_CLIENTS = tuple(c for c in M.APP_CLIENTS if c != "app-a" and c in M.APP_USER_MANAGERS)
sys.path.insert(0, a.skill_scripts); import e2e_check as E   # noqa: E402

REALM, ORIGIN, PORT, HOST = a.realm, a.origin, 8443, "localhost"
BASE = "https://%s:%d" % (HOST, PORT)
REDIRECT = ORIGIN + "/admin/accounts/callback"
OB = M.ONBOARDING_CLIENT_IDS[0]
CTX = ssl.create_default_context(cafile=a.cacert)
_u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); _u.connect(("192.0.2.1", 9)); NET_IP = _u.getsockname()[0]; _u.close()
TAG = "".join(secrets.choice("abcdefghjkmnpqrstuvwxyz") for _ in range(6))   # letters only: a random digit run would trip the audit-log checks
res = []
def check(n, ok, d=""):
    res.append(bool(ok)); print("%s  %-100s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

def raw(method, path, body=None, headers=None, net=False):
    """(status, lower-case headers, text). net=True: from the container's own address (an ordinary network client)."""
    sock = socket.create_connection((NET_IP if net else "127.0.0.1", PORT), timeout=30)
    con = http.client.HTTPSConnection(HOST, PORT, context=CTX, timeout=60)
    con.sock = CTX.wrap_socket(sock, server_hostname=HOST)
    h = {"Host": "%s:%d" % (HOST, PORT)}; h.update(headers or {})
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    con.request(method, path, body=body, headers=h)
    r = con.getresponse(); text = r.read().decode("utf-8", "replace"); hd = {k.lower(): v for k, v in r.getheaders()}
    con.close()
    return r.status, hd, text

def js(text):
    try:
        return json.loads(text)
    except ValueError:
        return text

class Adapter:
    """idp-admin.py's KC over the trusted source, as the master realm's stig-automation (as on the host)."""
    def __init__(self):
        self.login()
    def login(self):
        st, _, t = raw("POST", "/realms/master/protocol/openid-connect/token", urllib.parse.urlencode({
            "grant_type": "client_credentials", "client_id": "stig-automation", "client_secret": os.environ["AUTOMATION_SECRET"]}).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"})
        if st != 200:
            sys.exit("master login failed: HTTP %s" % st)
        self.token, self.at = json.loads(t)["access_token"], time.time()
    def req(self, method, path, body=None, headers=None, auth=True, _retry=True):
        if auth and time.time() - self.at > 40:
            self.login()
        h = dict(headers or {})
        if auth:
            h["Authorization"] = "Bearer " + self.token
        st, _, t = raw(method, path, body, h)
        return st, t
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        st, data = self.req(method, "/admin/realms/%s%s" % (M.REALM, path), json.dumps(obj).encode() if obj is not None else None,
                            {"Content-Type": "application/json"} if obj is not None else {})
        if st == 404 and ok404:
            return None
        if st not in ok:
            sys.exit("%s %s -> HTTP %s %s" % (method, path, st, data[:300]))
        return json.loads(data) if data.strip() else None

TMP = tempfile.mkdtemp(prefix="onb-lab-")
M.REALM = REALM
M.ALLOWLIST, M.STATE, M.ONBOARDING_STATE = (os.path.join(TMP, x) for x in ("admins.json", "state.json", "onboarding.json"))
M.ALLOWLIST_ATTR, M.ALLOWLIST_ROLES_ATTR = "stig.admin-allowlist.%s" % REALM, "stig.admin-allowlist-roles.%s" % REALM
kc = Adapter()
M.KC = lambda: kc
M._write_json(M.ALLOWLIST, {}); M.save_state(M.new_state())

def quiet(fn, *args):
    """(result or the exception, stdout+stderr)."""
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            return fn(*args), out.getvalue()
    except (SystemExit, RuntimeError) as e:
        return e, out.getvalue()

# ---- sign-in, OTP and tokens
_last = {}
_totp = E.totp
def totp_once(secret, *x, **k):
    """A fresh TOTP code per 30 s period per secret (the realm refuses a reused code)."""
    while int(time.time()) // 30 == _last.get(secret):
        time.sleep(1)
    _last[secret] = int(time.time()) // 30
    return _totp(secret, *x, **k)
E.totp = totp_once

class Person:
    def __init__(self, username):
        self.username, self.pw, self.ctx, self.b = username, "Lab!9%sQz" % secrets.token_hex(10), {}, None
        kc.api("POST", "/users", {"username": username, "enabled": True, "firstName": "Lab", "lastName": username.split(".")[-1].title(),
                                  "email": "%s@lab.test.mil" % username, "emailVerified": True,
                                  "credentials": [{"type": "password", "value": self.pw, "temporary": False}]})
        self.id = M.user(kc, username)["id"]
    def sign_in(self, client=OB, redirect=REDIRECT, extra=None, fresh=False, dpop=False):
        """A token for `client` (PKCE), through the realm's own browser flow (password, OTP, terms, allowlist gate)."""
        fl = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client=client, redirect=redirect, admin_url=None, client_secret=None, cacert=a.cacert))
        if fresh or self.b is None:
            self.b = E.Browser(a.cacert)
        url, ver = fl.auth_url(extra=extra)
        k, u, p = self.b.go(url, None, redirect)
        if k == "page" and 'id="kc-form-login"' in p:
            act, f = E.form(p, "kc-form-login"); f.update({"username": self.username, "password": self.pw})
            k, u, p = self.b.go(act, f, redirect)
        final, seen = fl.finish(self.b, k, u, p, self.ctx)
        if not final or "code=" not in final:
            return None, seen
        code = urllib.parse.parse_qs(urllib.parse.urlparse(final).query)["code"][0]
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect, "client_id": client, "code_verifier": ver}
        st, _, t = raw("POST", "/realms/%s/protocol/openid-connect/token" % REALM, urllib.parse.urlencode(form).encode(),
                       {"Content-Type": "application/x-www-form-urlencoded"})
        return (json.loads(t) if st == 200 else None), seen

def claims(tok):
    return E.claims(tok["access_token"])

def call(tok, method, path, body=None, origin=ORIGIN, net=True, query=""):
    """An admin-API call from the network, as a browser on ORIGIN makes it: (status, headers, body)."""
    h = {"Authorization": "Bearer " + tok["access_token"]}
    if origin:
        h["Origin"] = origin
    st, hd, t = raw(method, "/admin/realms/%s/%s%s" % (REALM, path.lstrip("/"), query), body, h, net=net)
    return st, hd, js(t)

def acao(hd):
    return hd.get("access-control-allow-origin")

# ===================================================================== setup
APP_A = list(APP_A_ROLES)
APP_BC_ROLES = {"app-b": ("owner", "maintainer", "reviewer", "member"), "app-c": ("lead", "analyst", "auditor", "reader")}
for cid, roles in [("app-a", APP_A)] + [(c, list(APP_BC_ROLES[c])) for c in APP_BC_CLIENTS]:
    if not M.find_client(kc, cid):
        kc.api("POST", "/clients", {"clientId": cid, "protocol": "openid-connect", "publicClient": False, "standardFlowEnabled": True,
                                    "redirectUris": ["https://%s.lab.example/cb" % cid], "fullScopeAllowed": False})
    cu = M.client_uuid(kc, cid)
    for r in roles:
        kc.req("POST", "/admin/realms/%s/clients/%s/roles" % (REALM, cu), json.dumps({"name": r}).encode(), {"Content-Type": "application/json"})
r_, out = quiet(M.cmd_roles_setup, argparse.Namespace())
check("setup: roles-setup ran", not isinstance(r_, BaseException), out[-300:] if isinstance(r_, BaseException) else "")
for c in APP_BC_CLIENTS:
    line = [l for l in out.splitlines() if l.startswith("membership of /%s/%s " % (c, M.APP_USER_MANAGERS[c]))]
    check("setup: /roles/%s-user-manager exists and writes /%s/%s (an APP admin group)" % (c, c, M.APP_USER_MANAGERS[c]),
          M.group_by_path(kc, "/roles/%s-user-manager" % c) and line and "%s-user-manager" % c in line[0], line)
    root = [l for l in out.splitlines() if l.startswith("membership of /%s " % c)]
    check("setup: ... but never the bare /%s root" % c, root and "%s-user-manager" % c not in root[0], root)
check("setup: an app admin role group carries no realm-management role (so stig-accounts does not treat it as an IdP admin)",
      not any(kc.api("GET", "/groups/%s/role-mappings/clients/%s" % (M.group_by_path(kc, "/%s/%s" % (c, M.APP_USER_MANAGERS[c]))["id"], M.client_uuid(kc, "realm-management")))
              for c in APP_BC_CLIENTS))

lmgr = Person("lab.lmgr.%s" % TAG)        # app-a manager only
cmgr = Person("lab.cmgr.%s" % TAG)        # app-b and app-c manager (both clients)
um = Person("lab.um.%s" % TAG)            # all-applications user manager
adm = Person("lab.adm.%s" % TAG)          # IdP admin only
admu = Person("lab.admu.%s" % TAG)        # IdP admin + all-applications user manager (as the operator holds the top roles)
nomgr = Person("lab.nomgr.%s" % TAG)        # wants the app-b manager role without app-b admin
dmgr = Person("lab.dmgr.%s" % TAG)        # app-b manager only (retiring app-b removes it)
ACCT = ("account-console", "%s/realms/%s/account/" % (BASE, REALM))
for p in (lmgr, cmgr, um, adm, admu, dmgr):
    tok, seen = p.sign_in(client=ACCT[0], redirect=ACCT[1])
    check("setup: %s enrols TOTP as an ordinary account" % p.username.split(".")[1], tok is not None, seen)
st0 = M.load_state() or M.new_state()
for p, roles in ((lmgr, ["app-a-user-manager", "app-a:administrator"]),
                 (cmgr, ["app-b-user-manager", "app-c-user-manager", "app-b:owner", "app-c:lead"]),
                 (um, ["idp-user-manager"]), (adm, ["idp-admin"]), (admu, ["idp-admin", "idp-user-manager"]),
                 (dmgr, ["app-b-user-manager", "app-b:owner"])):
    r_, out = quiet(M.apply_roles, kc, M.user(kc, p.username), roles, st0)
    check("setup: the tooling grants %s %s" % (p.username.split(".")[1], roles), not isinstance(r_, BaseException), out[-200:])
r_, out = quiet(M.cmd_grant, argparse.Namespace(username=nomgr.username, roles=["app-b-user-manager"], reset_credentials=False,
                                                email=None, clear_bindings=False))
check("[grant] refuses app-b-user-manager for an account without app-b:owner (changing nothing)",
      isinstance(r_, SystemExit) and "REFUSED" in str(r_) and not M.admin_paths(kc, nomgr.id), str(r_)[:120])
lines = M.app_manager_alignment(kc)
check("[guard] the aligned managers are not reported", not any(x in l for l in lines for x in (lmgr.username, cmgr.username)), lines)

r_, out = quiet(M.cmd_onboarding_client_setup, argparse.Namespace(
    redirect_uri=REDIRECT, origin=None, client_id=OB, app=list(M.APP_USER_MANAGERS), max_auth_age=300, require_dpop=False,
    operations="create,setup-email,membership"))
check("[setup] onboarding-client-setup --app app-a --app app-b --app app-c", not isinstance(r_, BaseException)
      and json.load(open(M.ONBOARDING_STATE))[OB]["apps"] == sorted(M.APP_USER_MANAGERS), (str(r_) + out)[-200:])
r_, out = quiet(M.cmd_onboarding_client_setup, argparse.Namespace(
    redirect_uri=REDIRECT, origin=None, client_id=OB, app=["app-a", "nonesuch"], max_auth_age=300, require_dpop=False,
    operations="create,setup-email,membership"))
check("[setup] ... an app without a per-application manager is refused", isinstance(r_, SystemExit) and "REFUSED" in str(r_), str(r_)[:100])

G = {x: M.group_by_path(kc, x)["id"] for x in
     ["/app-a", "/app-a/viewer", "/roles/idp-user-manager", "/roles/idp-admin", "/roles/app-b-user-manager"]
     + ["/%s" % c for c in APP_BC_CLIENTS] + ["/%s/%s" % (c, r) for c in APP_BC_CLIENTS for r in APP_BC_ROLES[c]]}
n_ = [0]
def create(tok, group, who):
    n_[0] += 1; u = "lab.n%02d.%s" % (n_[0], TAG)
    st, _, body = call(tok, "POST", "stig-accounts/users", {"username": u, "email": "%s@lab.test.mil" % u, "firstName": "New",
                                                            "lastName": "Person", "group": group})
    return st, (body.get("id") if isinstance(body, dict) else None), body
def add(tok, uid, group):
    return call(tok, "PUT", "users/%s/groups/%s" % (uid, G[group]))[0]

# ===================================================================== app-a-only manager
tl, seen = lmgr.sign_in(extra={"max_age": "0"})
check("[lmgr] signs in through the portal client", tl is not None, seen)
st, lid, b = create(tl, "/app-a/viewer", "lmgr")
check("[lmgr] creates into /app-a/viewer: 201", st == 201, (st, b))
for grp in ("/app-b/member", "/app-c/lead"):
    st, _, b = create(tl, grp, "lmgr")
    check("[lmgr] creates into %s: 403" % grp, st == 403, (st, b))
for grp in ("/app-b/member", "/app-c/auditor", "/roles/idp-user-manager"):
    check("[lmgr] adds its own app-a member to %s: 403" % grp, add(tl, lid, grp) == 403)

# ===================================================================== app-b and app-c manager
tc, seen = cmgr.sign_in(extra={"max_age": "0"})
st, cid1, b = create(tc, "/app-b/owner", "cmgr")
check("[cmgr] creates into /app-b/owner (an APP admin group, not an IdP admin): 201", st == 201, (st, b))
check("[cmgr] ... that account is no IdP administrator", cid1 and not M.admin_paths(kc, cid1)
      and not kc.api("GET", "/users/%s/role-mappings/clients/%s/composite" % (cid1, M.client_uuid(kc, "realm-management"))))
check("[cmgr] adds the same person's second tree by membership (/app-c/auditor): 204", add(tc, cid1, "/app-c/auditor") == 204)
st, cid2, b = create(tc, "/app-c/reader", "cmgr")
check("[cmgr] creates into /app-c/reader: 201", st == 201, (st, b))
st, _, b = create(tc, "/app-a/viewer", "cmgr")
check("[cmgr] creates into /app-a/viewer: 403", st == 403, (st, b))
check("[cmgr] adds its own app-b member to /app-a/viewer: 403", add(tc, cid1, "/app-a/viewer") == 403)
check("[cmgr] adds a app-a member (not its own) to /app-b/member: 403", add(tc, lid, "/app-b/member") == 403)
for grp in ("/roles/idp-user-manager", "/roles/idp-admin", "/roles/app-b-user-manager", "/app-b"):
    check("[cmgr] adds its member to %s: 403" % grp, add(tc, cid1, grp) == 403)
    st, _, b = create(tc, grp, "cmgr")
    check("[cmgr] creates into %s: 403" % grp, st == 403, (st, b))

# ===================================================================== all-applications user manager, IdP admin
tu, _ = um.sign_in(extra={"max_age": "0"})
st1, uid1, _ = create(tu, "/app-c/analyst", "um"); st2, uid2, _ = create(tu, "/app-a/viewer", "um")
check("[um] the all-applications user manager creates in both trees", (st1, st2) == (201, 201), (st1, st2))
check("[um] ... and adds across them", add(tu, uid1, "/app-a/viewer") == 204)
check("[um] ... but never into /roles/*", add(tu, uid1, "/roles/idp-user-manager") == 403)
ta, _ = adm.sign_in(extra={"max_age": "0"})
st1, _, _ = create(ta, "/app-b/member", "adm")
check("[adm] an IdP admin ALONE gets nothing through the capped portal client (403; it administers in the console)", st1 == 403, st1)
tau, _ = admu.sign_in(extra={"max_age": "0"})
st1, _, _ = create(tau, "/app-b/member", "admu"); st2, _, _ = create(tau, "/app-a/viewer", "admu")
check("[admu] an IdP admin who also holds idp-user-manager (as the operator does) creates in both trees", (st1, st2) == (201, 201), (st1, st2))

# ===================================================================== the profile still applies
st, _, b = call(tc, "POST", "stig-accounts/users/%s/disable" % cid2)
check("[profile] disable is not in the operations list: 403", st == 403, (st, b))
quiet(M.cmd_onboarding_client_setup, argparse.Namespace(redirect_uri=REDIRECT, origin=None, client_id=OB, app=list(M.APP_USER_MANAGERS),
                                                        max_auth_age=30, require_dpop=False, operations="create,setup-email,membership"))
t_old, _ = cmgr.sign_in(extra={"max_age": "600"})
time.sleep(max(0, 32 - (int(time.time()) - claims(t_old)["auth_time"])))
st, _, b = create(t_old, "/app-c/reader", "cmgr")
check("[profile] a app-b manager's write older than max-auth-age (30 s): 401 step-up", st == 401, (st, b))
st = add(t_old, cid2, "/app-c/analyst")
check("[profile] ... a membership change too: 401", st == 401, st)
t_new, _ = cmgr.sign_in(extra={"max_age": "30"})
check("[profile] after a fresh sign-in it goes through", add(t_new, cid2, "/app-c/analyst") == 204)

# ===================================================================== guard / check-clients know the shape
d0, o0 = None, None
sv = (M.load_kcstig, M.host_client_files)
M.load_kcstig, M.host_client_files = (lambda *x, **k: (None, None, None, None)), (lambda d=None: {})
buf = io.StringIO()
try:
    d0 = M.check_clients(kc, None, buf, {})
finally:
    M.load_kcstig, M.host_client_files = sv
o0 = buf.getvalue()
check("[check-clients] lists every tree the onboarding client serves, with its writers",
      all("serves /%s (writers: /roles/idp-user-manager, /roles/%s-user-manager)" % (x, x) in o0 for x in M.APP_USER_MANAGERS), o0[-300:])
# retiring an application: app-b leaves the config, then is RETIRED
td, _ = dmgr.sign_in(extra={"max_age": "0"})
st, _, b = create(td, "/app-b/member", "dmgr")
check("[retire] before: the app-b-only manager creates into /app-b (201)", st == 201, (st, b))
M.APP_CLIENTS = ("app-a", "app-c")      # as if app-b were taken out of the config
M.APP_USER_MANAGERS = {k: v for k, v in M.APP_USER_MANAGERS.items() if k != "app-b"}
M.ROLE_GROUPS.pop("app-b-user-manager", None)
lines = M.app_manager_alignment(kc)
check("[retire] guard reports the orphaned /roles/app-b-user-manager (members remain)",
      any("STIG-APP-MANAGER-ORPHANED /roles/app-b-user-manager" in l for l in lines), lines)
check("[retire] ... and the onboarding record still naming app-b", any("STIG-ONBOARDING-APP-UNKNOWN client=%s" % OB in l
                                                                                  and "app-b" in l for l in lines), lines)
r_, out = quiet(M.cmd_roles_setup, argparse.Namespace(retire_app=[]))
check("[retire] a plain roles-setup REFUSES while the removed app's delegation is live", isinstance(r_, SystemExit)
      and "REFUSED" in str(r_) and "app-b" in str(r_), str(r_)[:200])
r_, out = quiet(M.cmd_roles_setup, argparse.Namespace(retire_app=["app-c"]))
check("[retire] --retire-app of a still-configured client is refused", isinstance(r_, SystemExit) and "still configured" in str(r_), str(r_)[:120])
r_, out = quiet(M.cmd_roles_setup, argparse.Namespace(retire_app=["app-b"]))
check("[retire] roles-setup --retire-app app-b tears it down (verified)", not isinstance(r_, BaseException)
      and "retire app-b" in out, (str(r_) + out)[-300:])
base_ = "/clients/%s/authz/resource-server" % kc.api("GET", "/clients?clientId=admin-permissions")[0]["id"]
names = [x["name"] for k_ in ("permission", "policy") for x in M.paged(kc, base_ + "/" + k_)]
check("[retire] no permission, aggregate or policy of app-b remains",
      not [n_ for n_ in names if "/app-b" in n_ or n_.startswith("app-b-user-manager")], [n_ for n_ in names if "app-b" in n_])
gd = M.group_by_path(kc, "/roles/app-b-user-manager")
check("[retire] /roles/app-b-user-manager: no realm-management role, no member",
      not (kc.api("GET", "/groups/%s/role-mappings" % gd["id"]) or {}).get("clientMappings") and not M.paged(kc, "/groups/%s/members" % gd["id"]))
al_ = M.load_allowlist()
check("[retire] the allowlist: the app-b-only manager's entry is gone; the app-b manager's keeps only its app-c grant",
      dmgr.id not in al_ and cmgr.id in al_ and [g["path"] for g in al_[cmgr.id].get("grants") or []] == ["/roles/app-c-user-manager"],
      {k: [g["path"] for g in v.get("grants") or []] for k, v in al_.items() if k in (dmgr.id, cmgr.id)})
check("[retire] ... and the app-c delegation is intact", any(n_ == "membership: /app-c/lead" for n_ in names)
      and any(n_ == "app-c-user-manager group" for n_ in names))
td2, seen = dmgr.sign_in(extra={"max_age": "0"}, fresh=True)
for grp in ("/app-b/member", "/app-c/reader", "/app-a/viewer"):
    st, _, b = create(td2, grp, "dmgr") if td2 else (0, None, seen)
    check("[retire] the former app-b-only manager: create into %s -> 403" % grp, st == 403, (st, b))
check("[retire] ... and a membership change -> 403", td2 is not None and add(td2, cid1, "/app-b/member") == 403)
tc2, _ = cmgr.sign_in(extra={"max_age": "0"}, fresh=True)
st1, _, _ = create(tc2, "/app-c/reader", "cmgr"); st2, _, _ = create(tc2, "/app-b/member", "cmgr")
check("[retire] the app-b manager: app-c unaffected (201), app-b gone (403)", (st1, st2) == (201, 403), (st1, st2))
r_, out = quiet(M.cmd_roles_setup, argparse.Namespace(retire_app=[]))
check("[retire] afterwards a plain roles-setup runs clean", not isinstance(r_, BaseException), str(r_)[:200])
lines = M.app_manager_alignment(kc)
check("[retire] ... and the guard no longer reports an orphaned manager group", not any("ORPHANED" in l for l in lines), lines)

n = sum(res); print("\n%d/%d passed" % (n, len(res))); sys.exit(0 if n == len(res) else 1)

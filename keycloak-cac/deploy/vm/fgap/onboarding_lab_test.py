#!/usr/bin/env python3
"""Portal account administration (option D, 2026-11-18): the IdP side proved against a real, throwaway Keycloak.

Runs INSIDE the network namespace of a throwaway keycloak-cac container in lab mode (fgap/onboarding_lab.sh starts it
and this script), so that two sources exist, exactly as on the IdP host:
  - 127.0.0.1                 trusted by the path filter: the master realm and the operator's tooling (idp-admin.py);
  - the container's own IP    an ordinary network client: what a browser on an application's page is.

What is driven is idp-admin.py's own code (roles-setup, grant's apply_roles, onboarding-client-setup, guard,
app_manager_alignment) through an adapter for its KC class, and stig-extensions as built into the image under test.

  I1  onboarding-client-setup: refused unless the deployed extension enforces the admin-API profile; the client's exact
      shape (public, PKCE, one redirect and origin, no refresh token, scope mappings query-users+query-groups only, no
      optional scopes or mappers, the profile attributes); the guard reports drift and DISABLES the client with --fix;
      re-running setup restores it.
  I2  per-application user managers: /roles/app-a-user-manager writes every app-a role group (never the root,
      never another app's tree); grant refuses one without app-a:administrator; the guard reports a misaligned
      holder (STIG-APP-MANAGER-MISALIGNED) and changes nothing; an unvetted holder is refused by the gate.
  I3  stig-extensions: a token from the onboarding client reaches only the profile's calls (403 elsewhere, whoever
      holds it); a write older than max-auth-age gets 401 + an RFC 9470 challenge, and a fresh sign-in (max_age)
      clears it; 20 disables per caller per hour; the optional reference lands in the admin event.
  I4  the three open lab items: (1) CORS on real responses for this client's origin only (preflight through the path
      filter, 2xx, 401 and 403 answers); (2) an idp-admin signing in through the capped client gets no more than a
      user manager; (3) whether the admin API checks DPoP proofs.
  plus: EDIPI uniqueness and admin-only binding still hold; the IdP's admin events name the person, the client and
  the person's own address.

  onboarding_lab_test.py --cacert root.crt --skill-scripts <keycloak-asd-stig/scripts> [--realm dod-cac]
  (AUTOMATION_SECRET in the environment: the lab container's stig-automation secret)

Prints no secrets. Exit 0 only if every check passed.
"""
import argparse, base64, contextlib, hashlib, http.client, importlib.machinery, importlib.util, io, json, os, secrets, socket
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

# ===================================================================== setup: the realm as production shapes it
cap = M.gate_capability(kc, M.GATE_ADMIN_API_PROFILE_KEY)
check("setup: the image under test states the admin-API profile capability 2 (operations lists enforced)", cap == 2, "marker %s" % cap)
APP_A, REVIEW = list(APP_A_ROLES), ["partner-reader", "partner-auditor", "partner-lead", "contractor"]
for cid, roles in (("app-a", APP_A + REVIEW), ("app-b", ["owner", "maintainer", "reviewer", "member"])):
    if not M.find_client(kc, cid):
        kc.api("POST", "/clients", {"clientId": cid, "protocol": "openid-connect", "publicClient": False, "standardFlowEnabled": True,
                                    "redirectUris": ["https://%s.lab.example/cb" % cid], "fullScopeAllowed": False})
    cu = M.client_uuid(kc, cid)
    for r in roles:
        kc.req("POST", "/admin/realms/%s/clients/%s/roles" % (REALM, cu), json.dumps({"name": r}).encode(), {"Content-Type": "application/json"})
quiet(M.ensure_delegate_client, kc, "app-a-admin", "app-a account administrator (lab)")   # the server path
r_, out = quiet(M.cmd_roles_setup, argparse.Namespace())
check("setup: roles-setup (idp-admin.py) ran on the lab realm", not isinstance(r_, BaseException), out[-300:] if isinstance(r_, BaseException) else "")
check("setup: roles-setup prints the per-application manager as a writer of each app-a role group (never the root)",
      "membership of /app-a/administrator" in out and "app-a-user-manager" in out.split("membership of /app-a/administrator")[1].splitlines()[0]
      and "app-a-user-manager" not in [l for l in out.splitlines() if l.startswith("membership of /app-a ")][0],
      [l for l in out.splitlines() if l.startswith("membership of /app-a ") or "administrator " in l][:2])

def into(username, path):
    u = Person(username)
    kc.api("PUT", "/users/%s/groups/%s" % (u.id, M.group_by_path(kc, path)["id"]))
    return u

# the people: each enrols TOTP while still an ordinary account (an administrator is never offered enrolment)
mgr = Person("lab.mgr.%s" % TAG)          # app-a user manager (per-application role) + app-a administrator
um = Person("lab.um.%s" % TAG)            # all-applications user manager
adm = Person("lab.adm.%s" % TAG)          # realm administrator (idp-admin)
mis = Person("lab.mis.%s" % TAG)          # holds the app-a manager role WITHOUT administrator (misaligned)
ACCT = ("account-console", "%s/realms/%s/account/" % (BASE, REALM))
for p in (mgr, um, adm, mis):
    tok, seen = p.sign_in(client=ACCT[0], redirect=ACCT[1])
    check("setup: %s signs in once as an ordinary account and enrols TOTP" % p.username.split(".")[1],
          tok is not None and "login-login-config-totp" in seen, seen)
st0 = M.load_state() or M.new_state()
for p, roles in ((mgr, ["app-a-user-manager", "app-a:administrator"]), (um, ["idp-user-manager"]), (adm, ["idp-admin"]),
                 (mis, ["app-a-user-manager"])):
    r_, out = quiet(M.apply_roles, kc, M.user(kc, p.username), roles, st0)
    check("setup: the tooling grants %s %s" % (p.username.split(".")[1], roles), not isinstance(r_, BaseException), out[-200:])

# I2: grant's refusal and the guard's alignment report
nob = Person("lab.norole.%s" % TAG)
r_, out = quiet(M.cmd_grant, argparse.Namespace(username=nob.username, roles=["app-a-user-manager"], reset_credentials=False,
                                                email=None, clear_bindings=False))
check("[I2] grant refuses app-a-user-manager for an account without app-a:administrator, changing nothing",
      isinstance(r_, SystemExit) and "REFUSED" in str(r_) and not M.admin_paths(kc, nob.id), str(r_)[:120])
kc.api("PUT", "/users/%s/groups/%s" % (nob.id, M.group_by_path(kc, "/app-a/administrator")["id"]))
r_, out = quiet(M.cmd_grant, argparse.Namespace(username=nob.username, roles=["app-a-user-manager"], reset_credentials=False,
                                                email=None, clear_bindings=False))
check("[I2] grant refuses it too when administrator is held only through /app-a/administrator (a group the app's delegate writes)",
      isinstance(r_, SystemExit) and "REFUSED" in str(r_) and not M.admin_paths(kc, nob.id), str(r_)[:120])
lines = M.app_manager_alignment(kc)
check("[I2] the guard reports the misaligned holder (STIG-APP-MANAGER-MISALIGNED) ...",
      any("STIG-APP-MANAGER-MISALIGNED user=%s" % mis.username in l for l in lines), lines)
check("[I2] ... and only them (the aligned app-a manager holds administrator by direct mapping, as administrators do)",
      not any(mgr.username in l for l in lines) and "administrator" in M.effective_client_roles(kc, mgr.id, "app-a"))
r_, out = quiet(M.guard, kc, True)
check("[I2] guard --fix leaves the misaligned holder untouched (report only: still a manager, enabled)",
      "/roles/app-a-user-manager" in M.admin_paths(kc, mis.id) and kc.api("GET", "/users/%s" % mis.id)["enabled"], r_)

# targets (made by the tooling): app-a members, a app-b member
members = [into("lab.m%02d.%s" % (i, TAG), "/app-a/viewer") for i in range(23)]
buser = into("lab.bmember.%s" % TAG, "/app-b/member")
G = {x: M.group_by_path(kc, x)["id"] for x in ("/app-a", "/app-a/viewer", "/app-a/editor",
                                              "/app-a/partner-lead", "/app-b/member", "/app-b/owner",
                                              "/roles/idp-user-manager")}

# ===================================================================== I1: onboarding-client-setup
ns = lambda **k: argparse.Namespace(**dict({"redirect_uri": REDIRECT, "origin": None, "client_id": OB, "app": ["app-a"], "max_auth_age": 300,
                                            "require_dpop": False, "operations": ",".join(M.ONBOARDING_OPERATIONS)}, **k))
# (all four operations first, so the disable checks below can run; the default, without disable, is checked after them)
real_cap = M.gate_capability
M.gate_capability = lambda kc_, key: 0
r_, out = quiet(M.cmd_onboarding_client_setup, ns())
M.gate_capability = real_cap
check("[I1] setup is REFUSED while the deployed extension does not enforce the profile, and creates nothing",
      isinstance(r_, SystemExit) and "REFUSED" in str(r_) and M.find_client(kc, OB) is None, str(r_)[:100])
for bad_uri in ("http://portal.lab.example/cb", "https://portal.lab.example/*", "https://10.1.2.3/cb", "https://localhost/cb",
                "https://portal.lab.example/cb?x=1"):
    r_, out = quiet(M.cmd_onboarding_client_setup, ns(redirect_uri=bad_uri))
    check("[I1] setup refuses redirect %s" % bad_uri, isinstance(r_, SystemExit) and "REFUSED" in str(r_), str(r_)[:90])
r_, out = quiet(M.cmd_onboarding_client_setup, ns(origin="https://other.lab.example"))
check("[I1] setup refuses an --origin that is not the redirect's", isinstance(r_, SystemExit) and "REFUSED" in str(r_))
r_, out = quiet(M.cmd_onboarding_client_setup, ns())
check("[I1] setup creates the client and verifies it against its record", not isinstance(r_, BaseException), (str(r_) + out)[-300:])
c = kc.api("GET", "/clients/%s" % M.find_client(kc, OB)["id"])
sm = kc.api("GET", "/clients/%s/scope-mappings" % c["id"])
check("[I1] public, standard flow only, PKCE S256, no refresh token, 300 s tokens, 600 s client idle",
      c["publicClient"] and c["standardFlowEnabled"] and not c["implicitFlowEnabled"] and not c["directAccessGrantsEnabled"]
      and not c["serviceAccountsEnabled"] and not c["fullScopeAllowed"] and c["attributes"].get("pkce.code.challenge.method") == "S256"
      and c["attributes"].get("use.refresh.tokens") == "false" and c["attributes"].get("access.token.lifespan") == "300"
      and c["attributes"].get("client.session.idle.timeout") == "600")
check("[I1] exactly one redirect URI and one web origin", c["redirectUris"] == [REDIRECT] and c["webOrigins"] == [ORIGIN])
check("[I1] scope mappings: realm-management query-users + query-groups only, no realm role",
      not sm.get("realmMappings") and {k: sorted(r["name"] for r in v["mappings"]) for k, v in (sm.get("clientMappings") or {}).items()}
      == {"realm-management": ["query-groups", "query-users"]}, sm)
check("[I1] the profile attributes (account-onboarding, 300 s)", c["attributes"].get(M.ONBOARDING_PROFILE_ATTR) == "account-onboarding"
      and c["attributes"].get(M.ONBOARDING_MAX_AGE_ATTR) == "300")
check("[I1] no optional scopes; default scopes exactly the console's",
      not kc.api("GET", "/clients/%s/optional-client-scopes" % c["id"])
      and sorted(x["name"] for x in kc.api("GET", "/clients/%s/default-client-scopes" % c["id"])) == sorted(M.ONBOARDING_DEFAULT_SCOPES))
check("[I1] the record is written (root-only state)", json.load(open(M.ONBOARDING_STATE)).get(OB, {}).get("redirect") == REDIRECT)
r_, out = quiet(M.cmd_onboarding_client_setup, ns())
check("[I1] a re-run converges with no change", not isinstance(r_, BaseException) and "updated" not in out and "created" not in out, out[-120:])
r_, out = quiet(M.guard, kc, False)
check("[I1] guard: no onboarding-client violation on the recorded shape", "0 onboarding-client violations" in out, out[-160:])

def cc_report():
    """check-clients' onboarding lines (the client-file part stubbed out: no host files in the lab)."""
    sv = (M.load_kcstig, M.host_client_files)
    M.load_kcstig, M.host_client_files = (lambda *x, **k: (None, None, None, None)), (lambda d=None: {})
    out = io.StringIO()
    try:
        drift_ = M.check_clients(kc, None, out, {})
    finally:
        M.load_kcstig, M.host_client_files = sv
    return drift_, out.getvalue()
d0, o0 = cc_report()
check("[I1] check-clients: the onboarding client matches its record (no drift)", not d0 and "ok    %s: onboarding client matches" % OB in o0, o0[-160:])

def drift(name, mutate, undo=None):
    mutate()
    if name.startswith("redirect"):
        d1, o1_ = cc_report()
        check("[I1 drift] %s: check-clients reports DRIFT for it" % name, any(OB in x for x in d1), d1[:1])
    r1, o1 = quiet(M.guard, kc, False)
    check("[I1 drift] %s: guard reports STIG-ONBOARDING-CLIENT-DRIFT (exit 2 path)" % name,
          r1 == M.GUARD_VIOLATION and "STIG-ONBOARDING-CLIENT-DRIFT client=%s" % OB in o1, [l for l in o1.splitlines() if "DRIFT" in l][:1])
    r2, o2 = quiet(M.guard, kc, True)
    cc = kc.api("GET", "/clients/%s" % M.find_client(kc, OB)["id"])
    check("[I1 drift] %s: guard --fix DISABLES the client (verified)" % name, r2 == M.GUARD_FIXED and cc["enabled"] is False, r2)
    if undo:
        undo()
    r3, o3 = quiet(M.cmd_onboarding_client_setup, ns())
    cc = kc.api("GET", "/clients/%s" % M.find_client(kc, OB)["id"])
    r4, o4 = quiet(M.guard, kc, False)
    check("[I1 drift] %s: setup restores and re-enables it; guard clean" % name, not isinstance(r3, BaseException) and cc["enabled"]
          and "0 onboarding-client violations" in o4, (str(r3) + o3)[-160:])

cid_ = lambda: M.find_client(kc, OB)["id"]
def put_attr(k, v):
    cc = kc.api("GET", "/clients/%s" % cid_()); cc["redirectUris"] = cc["redirectUris"]; cc.setdefault("attributes", {})[k] = v
    kc.api("PUT", "/clients/%s" % cc["id"], cc)
def set_field(k, v):
    cc = kc.api("GET", "/clients/%s" % cid_()); cc[k] = v; kc.api("PUT", "/clients/%s" % cc["id"], cc)
rmc = M.client_uuid(kc, "realm-management")
drift("redirect URI moved to another origin", lambda: set_field("redirectUris", ["https://evil.lab.example/cb"]))
drift("realm-admin added to its scope mappings", lambda: kc.api("POST", "/clients/%s/scope-mappings/clients/%s" % (cid_(), rmc),
                                                               [kc.api("GET", "/clients/%s/roles/realm-admin" % rmc)]))
drift("profile attribute removed", lambda: put_attr(M.ONBOARDING_PROFILE_ATTR, ""))
drift("refresh tokens switched on", lambda: put_attr("use.refresh.tokens", "true"))
drift("a hardcoded-claim mapper added", lambda: kc.api("POST", "/clients/%s/protocol-mappers/models" % cid_(), {
    "name": "fake auth_time", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
    "config": {"claim.name": "auth_time", "claim.value": str(41024448 * 100), "jsonType.label": "long", "access.token.claim": "true"}}),
    lambda: [kc.api("DELETE", "/clients/%s/protocol-mappers/models/%s" % (cid_(), m["id"])) for m in
             kc.api("GET", "/clients/%s/protocol-mappers/models" % cid_()) or []])
flows = {f["alias"]: f["id"] for f in kc.api("GET", "/authentication/flows")}
drift("a browser-flow binding override (another flow than the realm's)", lambda: set_field(
    "authenticationFlowBindingOverrides", {"browser": flows.get("browser") or list(flows.values())[0]}))
bscope = [x for x in kc.api("GET", "/client-scopes") if x["name"] == "basic"][0]
def add_scope_mapper():
    kc.api("POST", "/client-scopes/%s/protocol-mappers/models" % bscope["id"], {
        "name": "lab forged auth_time", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": {"claim.name": "auth_time", "claim.value": str(41024448 * 100), "jsonType.label": "long", "access.token.claim": "true"}})
def del_scope_mapper():
    for m in kc.api("GET", "/client-scopes/%s/protocol-mappers/models" % bscope["id"]) or []:
        if m["name"] == "lab forged auth_time":
            kc.api("DELETE", "/client-scopes/%s/protocol-mappers/models/%s" % (bscope["id"], m["id"]))
drift("a claim-writing mapper on the shared 'basic' scope", add_scope_mapper, del_scope_mapper)
M.gate_capability = lambda kc_, key: 0 if key == M.GATE_ADMIN_API_PROFILE_KEY else real_cap(kc_, key)
r_, out = quiet(M.guard, kc, True)
M.gate_capability = real_cap
cc = kc.api("GET", "/clients/%s" % cid_())
check("[I1] an image without the profile (e.g. a rollback): guard --fix disables the enabled onboarding client",
      cc["enabled"] is False and "does not enforce what this client relies on" in out, [l for l in out.splitlines() if "ONBOARDING" in l][:1])
d9, o9 = cc_report()
check("[I1] check-clients: a guard-disabled client that otherwise matches its record is not drift (reported as info)",
      not any(OB in x for x in d9) and "DISABLED" in o9, d9[:1])
M.gate_capability = lambda kc_, key: None if key == M.GATE_ADMIN_API_PROFILE_KEY else real_cap(kc_, key)
quiet(M.cmd_onboarding_client_setup, ns())
set_field("redirectUris", ["https://evil.lab.example/cb"])
r_, out = quiet(M.guard, kc, True)
M.gate_capability = real_cap
cc = kc.api("GET", "/clients/%s" % cid_())
check("[I1] capability marker unreadable: a drifted client is STILL disabled by guard --fix", cc["enabled"] is False,
      [l for l in out.splitlines() if "ONBOARDING" in l][:2])
quiet(M.cmd_onboarding_client_setup, ns())

# ===================================================================== tokens through the onboarding client
tm, seen = mgr.sign_in(extra={"max_age": "0"})        # a fresh authentication: its writes come within max-auth-age
check("[I3] the app-a manager signs in through %s (password + OTP, allowlist gate)" % OB, tm is not None and "login-login-otp" in seen, seen)
cl = claims(tm)
check("[I3] its token: azp=%s, auth_time present, allowed-origins = the portal only, no refresh token" % OB,
      cl.get("azp") == OB and isinstance(cl.get("auth_time"), int) and cl.get("allowed-origins") == [ORIGIN] and not tm.get("refresh_token"),
      {k: cl.get(k) for k in ("azp", "auth_time", "allowed-origins")})
check("[I3] ... carrying no realm-management role beyond query-users/query-groups",
      set((cl.get("resource_access") or {}).get("realm-management", {}).get("roles", [])) <= {"query-users", "query-groups"},
      (cl.get("resource_access") or {}).get("realm-management"))

# ---- I4(1) CORS
st, hd, _ = raw("OPTIONS", "/admin/realms/%s/stig-accounts/users" % REALM, None,
                {"Origin": ORIGIN, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type"}, net=True)
check("[I4.1] preflight from the network passes the path filter: 200 + the origin", st == 200 and acao(hd) == ORIGIN, (st, acao(hd)))
st, hd, body = call(tm, "GET", "groups/%s/members" % G["/app-a/viewer"])
check("[I4.1] GET members with the onboarding token: 200 and Access-Control-Allow-Origin = the portal", st == 200 and acao(hd) == ORIGIN,
      (st, acao(hd)))
st, hd, body = call(tm, "GET", "groups/%s/members" % G["/app-a/viewer"], origin="https://evil.lab.example")
check("[I4.1] the same call from another origin: no CORS grant for it", acao(hd) in (None, "") or acao(hd) != "https://evil.lab.example",
      (st, acao(hd)))
cons, _ = mgr.sign_in(client="security-admin-console", redirect="%s/admin/%s/console/" % (BASE, REALM))
st, hd, _ = call(cons, "GET", "groups/%s/members" % G["/app-a/viewer"]) if cons else (None, {}, None)
check("[I4.1] a console token used from the portal's origin: no CORS grant (only this client's tokens are readable there)",
      cons is not None and acao(hd) != ORIGIN, (st, acao(hd)))

# ---- I3: what the app-a manager can do through the portal client
email = lambda n: "lab.new%s.%s@lab.test.mil" % (n, TAG)
st, hd, body = call(tm, "POST", "stig-accounts/users", {"username": "lab.new1.%s" % TAG, "email": email(1), "firstName": "New",
                                                        "lastName": "One", "group": "/app-a/viewer", "reference": "AR-1234"})
check("[I3] create into a app-a role group: 201 (+ CORS)", st == 201 and acao(hd) == ORIGIN, (st, body if st != 201 else body.get("setupEmail")))
new1 = body.get("id") if isinstance(body, dict) else None
st, hd, body = call(tm, "POST", "stig-accounts/users", {"username": "lab.new2.%s" % TAG, "email": email(2), "firstName": "New",
                                                        "lastName": "Two", "group": "/app-a/partner-lead"})
check("[I3] create into partner-lead (the user managers' alone; never the app's delegates): 201", st == 201, (st, body))
st, hd, body = call(tm, "POST", "stig-accounts/users", {"username": "lab.new3.%s" % TAG, "email": email(3), "firstName": "New",
                                                        "lastName": "Three", "group": "/app-b/member"})
check("[I3/I2] create into another application's tree: 403", st == 403, (st, body))
st, hd, body = call(tm, "POST", "stig-accounts/users", {"username": "lab.new4.%s" % TAG, "email": email(4), "firstName": "New",
                                                        "lastName": "Four", "group": "/app-a"})
check("[I3/I2] create into the bare /app-a root: 403", st == 403, (st, body))
st, hd, body = call(tm, "POST", "stig-accounts/users", {"username": "lab.new5.%s" % TAG, "email": email(5), "firstName": "New",
                                                        "lastName": "Five", "group": "/app-a/viewer", "reference": "a b"})
check("[I3] an invalid reference: 400", st == 400, (st, body))
st, hd, body = call(tm, "POST", "stig-accounts/users", {"username": "lab.new6.%s" % TAG, "email": "x.%s@mail.example.com" % TAG, "firstName": "New",
                                                        "lastName": "Six", "group": "/app-a/viewer"})
check("[I3] an e-mail domain outside the realm's list: 403 (+ CORS, so the page can say why)", st == 403 and acao(hd) == ORIGIN, (st, body))
m0 = members[0]
st, hd, body = call(tm, "PUT", "users/%s/groups/%s" % (m0.id, G["/app-a/editor"]))
st2, _, _ = call(tm, "DELETE", "users/%s/groups/%s" % (m0.id, G["/app-a/viewer"]))
check("[I3] role change within the tree (add the new group, then remove the old): 204, 204", (st, st2) == (204, 204), (st, st2))

# ---- offboarding by removing the LAST app-a group (offboarding = removing the app's roles): what the IdP does
dual = into("lab.dual.%s" % TAG, "/app-a/viewer")
kc.api("PUT", "/users/%s/groups/%s" % (dual.id, G["/app-b/member"]))
solo = into("lab.solo.%s" % TAG, "/app-a/viewer")
st, hd, body = call(tm, "GET", "users/%s/groups" % dual.id)
seen_groups = sorted(g_.get("path") for g_ in body) if st == 200 and isinstance(body, list) else body
print("INFO  [offboard] a app-a manager reading users/{id}/groups of a member of app-a AND app-b -> %s %s" % (st, seen_groups))
check("[offboard] users/{id}/groups of someone ALSO in another application's group: 403 (FGAP: no sight of that member at all)",
      st == 403, st)
st, hd, body = call(tm, "GET", "users/%s/groups" % solo.id)
check("[offboard] users/{id}/groups of a app-a-only member: 200, listing only app-a groups (so 200 = nothing outside app-a remains)",
      st == 200 and [g_.get("path") for g_ in body] == ["/app-a/viewer"], (st, body))
st, hd, body = call(tm, "DELETE", "users/%s/groups/%s" % (solo.id, G["/app-a/viewer"]))
check("[offboard] removing an account's LAST /app-a group: allowed (204) - nothing refuses it", st == 204, st)
st2, _, _ = call(tm, "GET", "users/%s" % solo.id)
st3, _, _ = call(tm, "PUT", "users/%s/groups/%s" % (solo.id, G["/app-a/viewer"]))
check("[offboard] ... after which the manager can neither see the account (403) nor put it back (403): only IdP admins can",
      (st2, st3) == (403, 403), (st2, st3))
su = kc.api("GET", "/users/%s" % solo.id)
check("[offboard] ... and the account stays ENABLED, with no group", su["enabled"] is True and not kc.api("GET", "/users/%s/groups" % solo.id))

# ---- the SERVER path (app-a-admin, client credentials), as app-a uses it for role moves and offboarding
dcl = M.find_client(kc, "app-a-admin")
dsec = kc.api("GET", "/clients/%s/client-secret" % dcl["id"])["value"]
st, _, t = raw("POST", "/realms/%s/protocol/openid-connect/token" % REALM, urllib.parse.urlencode({
    "grant_type": "client_credentials", "client_id": "app-a-admin", "client_secret": dsec}).encode(),
    {"Content-Type": "application/x-www-form-urlencoded"})
dtok = {"access_token": json.loads(t)["access_token"]}
solo2 = into("lab.solo2.%s" % TAG, "/app-a/viewer")
st, _, _ = call(dtok, "PUT", "users/%s/groups/%s" % (solo2.id, G["/app-a"]), origin=None)
check("[server path] app-a-admin cannot ADD anyone to the bare /app-a root (403)", st == 403, st)
kc.api("PUT", "/users/%s/groups/%s" % (solo2.id, G["/app-a"]))           # a direct root member made by the tooling
st, _, _ = call(dtok, "DELETE", "users/%s/groups/%s" % (solo2.id, G["/app-a"]), origin=None)
check("[server path] ... nor remove someone from it (403): only someone ALREADY in the root stays there", st == 403, st)
kc.api("DELETE", "/users/%s/groups/%s" % (solo2.id, G["/app-a"]))
st, _, _ = call(dtok, "DELETE", "users/%s/groups/%s" % (solo2.id, G["/app-a/viewer"]), origin=None)
check("[server path] removing a member's LAST app-a group: allowed (204); the account is left with no group, enabled",
      st == 204 and not kc.api("GET", "/users/%s/groups" % solo2.id) and kc.api("GET", "/users/%s" % solo2.id)["enabled"], st)
lead = M.user(kc, "lab.new2.%s" % TAG)
st, _, _ = call(dtok, "DELETE", "users/%s/groups/%s" % (lead["id"], G["/app-a/partner-lead"]), origin=None)
check("[server path] removing someone from partner-lead: refused (403) - a server-path offboarding leaves LEAD/ASSESSOR/contractor",
      st == 403, st)
tmr, _ = mgr.sign_in()                 # a fresh token through the session (reads need no step-up)
for who, tok_ in (("app-a-admin", dtok), ("the manager via idp-onboarding", tmr)):
    st, _, body = call(tok_, "GET", "groups/%s/members" % G["/app-a/viewer"], origin=None, query="?briefRepresentation=false")
    n1 = [m_ for m_ in body if m_.get("username") == "lab.new1.%s" % TAG] if st == 200 and isinstance(body, list) else []
    print("INFO  [members read] %s, briefRepresentation=false -> %s; lab.new1 (in set-up): requiredActions=%s" % (
        who, st, n1[0].get("requiredActions") if n1 else "(not listed)"))
    check("[members read] %s: members with briefRepresentation=false carry requiredActions" % who,
          st == 200 and n1 and "requiredActions" in n1[0] and "UPDATE_PASSWORD" in n1[0]["requiredActions"], (st, n1[0].keys() if n1 else None))
st, hd, body = call(tm, "PUT", "users/%s/groups/%s" % (buser.id, G["/app-a/viewer"]))
check("[I2] pulling another application's member into app-a: 403", st == 403, st)
st, hd, body = call(tm, "PUT", "users/%s/groups/%s" % (m0.id, G["/app-b/owner"]))
check("[I2] putting a app-a member into another application's group: 403", st == 403, st)
st, hd, body = call(tm, "GET", "groups/%s/members" % G["/app-b/member"])
check("[I2] another application's members: not visible (403 or an empty list)", st == 403 or body == [], (st, body))
st, hd, body = call(tm, "POST", "stig-accounts/users/%s/disable" % buser.id)
check("[I2] disabling another application's member: 403", st == 403, (st, body))
st, hd, body = call(tm, "POST", "stig-accounts/users/%s/disable" % members[1].id, query="?reference=AR-77")
check("[I3] disable a app-a member (with ?reference=): 204", st == 204, (st, body))
st, hd, body = call(tm, "POST", "stig-accounts/users/%s/setup-email" % new1) if new1 else (None, {}, None)
check("[I3] re-send the set-up mail: authorised (204, or 502 here: the lab has no mail relay)", st in (204, 502), (st, body))
for nm, (m, path, body_) in {
        "PUT users/{id} (edit; e.g. an EDIPI)": ("PUT", "users/%s" % m0.id, {"attributes": {"cac_edipi": ["1234567890"]}}),
        "DELETE users/{id}": ("DELETE", "users/%s" % m0.id, None),
        "PUT users/{id}/reset-password": ("PUT", "users/%s/reset-password" % m0.id, {"type": "password", "value": "Zz!9" + "a" * 20, "temporary": True}),
        "PUT users/{id}/execute-actions-email": ("PUT", "users/%s/execute-actions-email" % m0.id, ["UPDATE_PASSWORD"]),
        "POST users (admin-API create)": ("POST", "users", {"username": "lab.x.%s" % TAG}),
        "POST users/{id}/impersonation": ("POST", "users/%s/impersonation" % m0.id, None),
        "GET users/{id}/credentials": ("GET", "users/%s/credentials" % m0.id, None),
        "GET admin-events": ("GET", "admin-events", None),
        "GET clients": ("GET", "clients", None)}.items():
    st, hd, body = call(tm, m, path, body_)
    check("[I3] outside the profile, %s: 403 (+ CORS)" % nm, st == 403 and acao(hd) == ORIGIN, (st, acao(hd)))
st, hd, body = call(tm, "GET", "users", query="?q=cac_edipi:1234567890")
check("[EDIPI] probing by the card mapping through the portal client: 403", st == 403, st)

# ---- I4(2): an idp-admin through the capped client
ta, seen = adm.sign_in(extra={"max_age": "0"})
check("[I4.2] the realm administrator signs in through %s" % OB, ta is not None, seen)
cla = claims(ta) if ta else {}
check("[I4.2] its token carries no realm-admin (the client's scope mappings cap it)",
      "realm-admin" not in (cla.get("resource_access") or {}).get("realm-management", {}).get("roles", []),
      (cla.get("resource_access") or {}).get("realm-management"))
st, hd, body = call(ta, "POST", "stig-accounts/users", {"username": "lab.byadm.%s" % TAG, "email": email(9), "firstName": "By",
                                                        "lastName": "Admin", "group": "/app-a/viewer"})
ADM_CREATE = st
check("[I4.2] the realm administrator creating through stig-accounts with the capped token: refused (it is not a user manager)",
      st == 403, (st, body))
st, hd, body = call(ta, "PUT", "users/%s/groups/%s" % (members[2].id, G["/app-a/editor"]))
check("[I4.2] ... and a membership move with the capped token: refused", st == 403, (st, body))
st, hd, body = call(ta, "GET", "users/%s" % members[2].id)
check("[I4.2] ... a read with the capped token gets only what Keycloak's own permissions give query-users (403 here)", st == 403, st)
tc, _ = adm.sign_in(client="security-admin-console", redirect="%s/admin/%s/console/" % (BASE, REALM))
st, hd, body = call(tc, "GET", "users/%s" % members[2].id, origin=None)
check("[I4.2] control: the same administrator through the console (full realm-admin) reads it: 200", st == 200, st)

# ---- all-applications user manager
tu, _ = um.sign_in(extra={"max_age": "0"})
st, hd, body = call(tu, "POST", "stig-accounts/users", {"username": "lab.bmember2.%s" % TAG, "email": email(7), "firstName": "Bea",
                                                        "lastName": "Two", "group": "/app-b/member"})
check("[I2] the all-applications user manager still creates in another application's tree: 201", st == 201, (st, body))

# ---- I3: the creation rate slot (um has made 1 creation): a caller's own mistakes spend none; every 409 spends one
tu, _ = um.sign_in(extra={"max_age": "0"})
free_ = []
for i in range(12):
    body_ = {"username": "lab.rf%02d.%s" % (i, TAG), "email": "lab.rf%02d.%s@lab.test.mil" % (i, TAG), "firstName": "Ref", "lastName": "Used",
             "group": "/roles/idp-user-manager" if i % 2 else "/app-b/member"}
    if not i % 2:
        body_["lifespan"] = 10
    free_.append(call(tu, "POST", "stig-accounts/users", body_)[0])
check("[I3] 12 requests the caller got wrong (400 bad lifespan, 403 a group it cannot manage)", sorted(set(free_)) == [400, 403], sorted(set(free_)))
probe = lambda n: call(tu, "POST", "stig-accounts/users", {"username": mgr.username if n % 2 else "lab.pr%02d.%s" % (n, TAG),
        "email": "lab.pr%02d.%s@lab.test.mil" % (n, TAG) if n % 2 else "%s@lab.test.mil" % adm.username,
        "firstName": "Pro", "lastName": "Be", "group": "/app-b/member"})
p1 = [probe(n) for n in range(19)]
check("[I3] ... spent no slot: 19 existence probes (an existing username, or an existing e-mail) all get 409 (20 - the 1 before)",
      [x[0] for x in p1] == [409] * 19, [x[0] for x in p1])
check("[I3] ... and the 409 is generic: it does not say which one is taken, nor echo it",
      all(x[2] == {"error": "username or e-mail address already in use"} for x in p1), p1[0][2])
p21 = probe(19)
check("[I3] the 21st creation attempt within the hour (a probe): 429 - each 409 spent a slot, so probing is capped", p21[0] == 429, p21[0])
st, hd, body = call(tu, "POST", "stig-accounts/users", {"username": "lab.ok.%s" % TAG, "email": "lab.ok.%s@lab.test.mil" % TAG,
                                                        "firstName": "Ok", "lastName": "Late", "group": "/app-b/member"})
check("[I3] ... and a valid creation by that caller is now refused too (429)", st == 429, st)

# ---- unvetted holder of the per-application role: refused by the gate
rogue = Person("lab.rogue.%s" % TAG)
rogue.sign_in(client=ACCT[0], redirect=ACCT[1])        # TOTP enrolled while ordinary
tr0, _ = rogue.sign_in(fresh=True)
kc.api("PUT", "/users/%s/groups/%s" % (rogue.id, M.group_by_path(kc, "/roles/app-a-user-manager")["id"]))
st, hd, body = call(tr0, "GET", "groups/%s/members" % G["/app-a/viewer"])
check("[I2] someone put into /roles/app-a-user-manager without the tooling: their token gets 403 (allowlist gate)", st == 403, st)
tr1, seen = rogue.sign_in(fresh=True)
check("[I2] ... and a new sign-in is refused (no code)", tr1 is None, seen[-2:])
r_, out = quiet(M.guard, kc, True)
check("[I2] ... the guard finds it unvetted and contains it (demoted, disabled)", "STIG-ADMIN-UNVETTED user=%s" % rogue.username in out
      and not M.admin_paths(kc, rogue.id) and kc.api("GET", "/users/%s" % rogue.id)["enabled"] is False, r_)

# ---- I3: a master-realm client carrying the profile attribute is refused outright
def master_client(cid, attrs):
    sec = secrets.token_hex(20)
    kc.req("POST", "/admin/realms/master/clients", json.dumps({"clientId": cid, "publicClient": False, "serviceAccountsEnabled": True,
           "standardFlowEnabled": False, "secret": sec, "attributes": attrs}).encode(), {"Content-Type": "application/json"})
    st_, d_ = kc.req("GET", "/admin/realms/master/clients?clientId=%s" % cid); c_ = json.loads(d_)[0]
    st_, d_ = kc.req("GET", "/admin/realms/master/clients?clientId=stig-automation"); auto_ = json.loads(d_)[0]
    st_, d_ = kc.req("GET", "/admin/realms/master/clients/%s/default-client-scopes" % auto_["id"])
    for sc_ in json.loads(d_):                         # the same token shape as the operator's own tooling
        kc.req("PUT", "/admin/realms/master/clients/%s/default-client-scopes/%s" % (c_["id"], sc_["id"]))
    st_, d_ = kc.req("GET", "/admin/realms/master/clients/%s/service-account-user" % c_["id"]); sa_ = json.loads(d_)
    st_, d_ = kc.req("GET", "/admin/realms/master/roles/admin"); role_ = json.loads(d_)
    kc.req("POST", "/admin/realms/master/users/%s/role-mappings/realm" % sa_["id"], json.dumps([role_]).encode(), {"Content-Type": "application/json"})
    kc.req("POST", "/admin/realms/master/clients/%s/scope-mappings/realm" % c_["id"], json.dumps([role_]).encode(), {"Content-Type": "application/json"})
    st_, _, t_ = raw("POST", "/realms/master/protocol/openid-connect/token", urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": cid, "client_secret": sec}).encode(), {"Content-Type": "application/x-www-form-urlencoded"})
    return c_["id"], {"access_token": json.loads(t_)["access_token"]}
mc1, mt1 = master_client("lab-master-profiled-%s" % TAG, {"stig.admin-api.profile": "account-onboarding"})
mc2, mt2 = master_client("lab-master-plain-%s" % TAG, {})
st1, _, _ = call(mt1, "GET", "users", origin=None, net=False)
st2, _, _ = call(mt2, "GET", "users", origin=None, net=False)
check("[I3] a master-realm client carrying stig.admin-api.profile: refused (403); the same without it: 200", (st1, st2) == (403, 200), (st1, st2))
for x in (mc1, mc2):
    kc.req("DELETE", "/admin/realms/master/clients/%s" % x)

# ---- I3: step-up
quiet(M.cmd_onboarding_client_setup, ns(max_auth_age=30))
t_old, _ = mgr.sign_in(extra={"max_age": "600"})          # SSO: no new authentication
age = int(time.time()) - claims(t_old)["auth_time"]
wait = max(0, 32 - age)
time.sleep(wait)
st, hd, body = call(t_old, "POST", "stig-accounts/users", {"username": "lab.new8.%s" % TAG, "email": email(8), "firstName": "New",
                                                           "lastName": "Eight", "group": "/app-a/viewer"})
wa = hd.get("www-authenticate", "")
check("[I3] a write whose authentication is older than max-auth-age (30 s here): 401", st == 401, (st, body))
check("[I3] ... with the RFC 9470 challenge (insufficient_user_authentication, max_age=30) and CORS, so the page can react",
      "insufficient_user_authentication" in wa and 'max_age="30"' in wa and acao(hd) == ORIGIN, (wa, acao(hd)))
exposed = [x.strip().lower() for x in hd.get("access-control-expose-headers", "").split(",")]
check("[I3] ... and WWW-Authenticate is EXPOSED to the page (Access-Control-Expose-Headers), or a browser cannot read the challenge",
      "www-authenticate" in exposed, hd.get("access-control-expose-headers"))
st, hd, body = call(t_old, "GET", "groups/%s/members" % G["/app-a/viewer"])
check("[I3] ... while reads with the same token still work (200)", st == 200, st)
t_new, seen = mgr.sign_in(extra={"max_age": "30"})
check("[I3] the page re-authenticates with max_age: the IdP asks again (password + OTP) and the new token is fresh",
      bool(t_new) and "login-login-otp" in seen and int(time.time()) - claims(t_new)["auth_time"] < 30,
      (seen, int(time.time()) - claims(t_new)["auth_time"] if t_new else None))
st, hd, body = call(t_new, "POST", "stig-accounts/users", {"username": "lab.new8.%s" % TAG, "email": email(8), "firstName": "New",
                                                           "lastName": "Eight", "group": "/app-a/viewer"})
check("[I3] ... and the write then succeeds: 201", st == 201, (st, body))
st, hd, body = call(t_old, "POST", "stig-accounts/users/%s/disable" % members[3].id)
check("[I3] the old token stays stale for every write (disable: 401)", st == 401, st)
quiet(M.cmd_onboarding_client_setup, ns(max_auth_age=300))

# ---- I3: the disable rate limit (20 per caller in any 60 minutes; members[1] was the first)
tm2, _ = mgr.sign_in(extra={"max_age": "0"})
codes = [call(tm2, "POST", "stig-accounts/users/%s/disable" % m.id)[0] for m in members[2:22]]
check("[I3] disables 2..20 within the hour: 204", codes[:-1] == [204] * 19, codes[:-1])
check("[I3] the 21st disable within 60 minutes (a sliding window): 429", codes[-1] == 429, codes[-1:])
check("[I3] ... and the refused account is still enabled", kc.api("GET", "/users/%s" % members[21].id)["enabled"] is True)

# ---- the default operations list (the portal never disables)
r_, out = quiet(M.cmd_onboarding_client_setup, ns(operations=",".join(M.ONBOARDING_DEFAULT_OPS)))
cc = kc.api("GET", "/clients/%s" % cid_())
check("[ops] setup with the default operations: create,setup-email,membership recorded and set; guard clean",
      not isinstance(r_, BaseException) and cc["attributes"].get(M.ONBOARDING_OPS_ATTR) == "create,setup-email,membership"
      and json.load(open(M.ONBOARDING_STATE))[OB].get("operations") == ["create", "setup-email", "membership"]
      and "0 onboarding-client violations" in quiet(M.guard, kc, False)[1], (str(r_) + out)[-200:])
tm4, _ = mgr.sign_in(extra={"max_age": "0"})
st, hd, body = call(tm4, "POST", "stig-accounts/users/%s/disable" % members[22].id)
check("[ops] disable through idp-onboarding: refused by the profile (403), the account untouched",
      st == 403 and kc.api("GET", "/users/%s" % members[22].id)["enabled"], (st, body))
st1, _, _ = call(tm4, "PUT", "users/%s/groups/%s" % (members[0].id, G["/app-a/partner-lead"]))
st2, _, _ = call(tm4, "DELETE", "users/%s/groups/%s" % (members[0].id, G["/app-a/partner-lead"]))
check("[ops] membership still allowed (the human path to partner-lead/ASSESSOR/contractor): PUT and DELETE 204", (st1, st2) == (204, 204), (st1, st2))
M.gate_capability = lambda kc_, key: 1 if key == M.GATE_ADMIN_API_PROFILE_KEY else real_cap(kc_, key)
r1, o1 = quiet(M.cmd_onboarding_client_setup, ns(operations=",".join(M.ONBOARDING_DEFAULT_OPS)))
r2, o2 = quiet(M.guard, kc, True)
M.gate_capability = real_cap
check("[ops] an image stating capability 1 (operations not enforced): setup refuses an operations list, and guard --fix "
      "disables a client that records one", isinstance(r1, SystemExit) and "REFUSED" in str(r1)
      and kc.api("GET", "/clients/%s" % cid_())["enabled"] is False, (str(r1)[:90], [l for l in o2.splitlines() if "ONBOARDING" in l][:1]))
quiet(M.cmd_onboarding_client_setup, ns(operations=",".join(M.ONBOARDING_DEFAULT_OPS)))
infos = M.accounts_without_app_role(kc)
check("[offboard] the guard's information list names the accounts left with no application role (solo, solo2), and not the others",
      any("user=lab.solo.%s " % TAG in l for l in infos) and any("user=lab.solo2.%s " % TAG in l for l in infos)
      and not any(mgr.username in l or "lab.dual." in l for l in infos), [l[:80] for l in infos][:4])

# ---- I3: concurrent creations never exceed the limit (mgr has made 3: new1, new2, new8)
import concurrent.futures
tm3, _ = mgr.sign_in(extra={"max_age": "0"})
def one(i):
    return call(tm3, "POST", "stig-accounts/users", {"username": "lab.cc%02d.%s" % (i, TAG), "email": "lab.cc%02d.%s@lab.test.mil" % (i, TAG),
                                                    "firstName": "Con", "lastName": "Current", "group": "/app-a/viewer"})[0]
with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex_:
    cc_codes = list(ex_.map(one, range(25)))
check("[I3] 25 CONCURRENT creations by one caller -> exactly 17 created (20 - 3 before) and 8 refused (429)",
      cc_codes.count(201) == 17 and cc_codes.count(429) == 8, "201 x%d, 429 x%d, other %s" % (cc_codes.count(201), cc_codes.count(429),
      sorted(set(c_ for c_ in cc_codes if c_ not in (201, 429)))))

# ---- audit: the IdP's admin events name the person, the client, their address, and the reference
evs = kc.api("GET", "/admin-events?max=500") or []
def ev(op, rt, path_part):
    return [e for e in evs if e.get("operationType") == op and e.get("resourceType") == rt and path_part in (e.get("resourcePath") or "")]
cr = [e for e in ev("CREATE", "USER", "users/") if new1 and new1 in e.get("resourcePath", "")]
check("[audit] the create's admin event: the manager's user id, client %s, the browser's (network) address" % OB,
      cr and cr[0]["authDetails"].get("userId") == mgr.id and cr[0]["authDetails"].get("clientId") == c["id"]
      and cr[0]["authDetails"].get("ipAddress") == NET_IP, cr[0]["authDetails"] if cr else "none")
check("[audit] ... and its representation records reference AR-1234", cr and json.loads(cr[0].get("representation") or "{}").get("reference") == "AR-1234")
dis = ev("UPDATE", "USER", members[1].id)
check("[audit] the disable's admin event records reference AR-77", dis and json.loads(dis[0].get("representation") or "{}").get("reference") == "AR-77",
      dis[0].get("representation") if dis else "none")
mv = ev("CREATE", "GROUP_MEMBERSHIP", m0.id)
check("[audit] the role change's admin event names the manager and the client", mv and mv[0]["authDetails"].get("userId") == mgr.id
      and mv[0]["authDetails"].get("clientId") == c["id"])

# ---- EDIPI: uniqueness and admin-only binding hold
created = M.user(kc, "lab.new1.%s" % TAG)
full = kc.api("GET", "/users/%s" % created["id"])
check("[EDIPI] the portal-created account carries no card mapping and is marked stig_created_by",
      "cac_edipi" not in (full.get("attributes") or {}) and (full.get("attributes") or {}).get("stig_created_by", [""])[0].startswith(mgr.username))
x = kc.api("GET", "/users/%s" % members[4].id); x.setdefault("attributes", {})["cac_edipi"] = ["5555555555"]
kc.api("PUT", "/users/%s" % x["id"], x)
y = kc.api("GET", "/users/%s" % members[5].id); y.setdefault("attributes", {})["cac_edipi"] = ["5555555555"]
st_, t_ = kc.req("PUT", "/admin/realms/%s/users/%s" % (REALM, y["id"]), json.dumps(y).encode(), {"Content-Type": "application/json"})
check("[EDIPI] a second account with the same EDIPI is refused even to the master realm (cac-identity-guard unique)", st_ == 400, (st_, t_[:80]))

# ---- I4(3): DPoP
key = None
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    key = ec.generate_private_key(ec.SECP256R1())
except Exception:      # noqa: BLE001
    pass
if key is None:
    check("[I4.3] DPoP: not measured (no 'cryptography' module in the test container)", True, "skipped")
else:
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    pub = key.public_key().public_numbers()
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    jwk = {"kty": "EC", "crv": "P-256", "x": b64(pub.x.to_bytes(32, "big")), "y": b64(pub.y.to_bytes(32, "big"))}
    def proof(htm, htu, ath=None):
        h = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
        pl = {"jti": uuid.uuid4().hex, "htm": htm, "htu": htu, "iat": int(time.time())}
        if ath:
            pl["ath"] = b64(hashlib.sha256(ath.encode()).digest())
        si = b64(json.dumps(h).encode()) + "." + b64(json.dumps(pl).encode())
        r, s = decode_dss_signature(key.sign(si.encode(), ec.ECDSA(hashes.SHA256())))
        return si + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    fl = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client=OB, redirect=REDIRECT, admin_url=None, client_secret=None, cacert=a.cacert))
    url, ver = fl.auth_url(extra={"max_age": "300"})
    k, u, p = mgr.b.go(url, None, REDIRECT)
    final, seen = fl.finish(mgr.b, k, u, p, mgr.ctx)
    code = urllib.parse.parse_qs(urllib.parse.urlparse(final).query)["code"][0] if final and "code=" in final else None
    tu_ = "%s/realms/%s/protocol/openid-connect/token" % (BASE, REALM)
    st, _, t = raw("POST", "/realms/%s/protocol/openid-connect/token" % REALM, urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "client_id": OB, "code_verifier": ver}).encode(),
        {"Content-Type": "application/x-www-form-urlencoded", "DPoP": proof("POST", tu_)})
    dt = json.loads(t) if st == 200 else {}
    bound = bool((E.claims(dt["access_token"]).get("cnf") or {}).get("jkt")) if dt else False
    check("[I4.3] DPoP: the token endpoint binds the onboarding token to a key (cnf.jkt) when a proof is sent", bound, (st, dt.get("token_type")))
    path = "/admin/realms/%s/groups/%s/members" % (REALM, G["/app-a/viewer"])
    s_plain, _, _ = raw("GET", path, None, {"Authorization": "Bearer " + dt.get("access_token", "")}, net=True)
    s_dpop, _, _ = raw("GET", path, None, {"Authorization": "DPoP " + dt.get("access_token", ""),
                                           "DPoP": proof("GET", BASE + path, dt.get("access_token", ""))}, net=True)
    s_noproof, _, _ = raw("GET", path, None, {"Authorization": "DPoP " + dt.get("access_token", "")}, net=True)
    print("INFO  [I4.3] DPoP-bound token on the admin API: as a plain Bearer -> %s; DPoP with a proof -> %s; DPoP without a proof -> %s"
          % (s_plain, s_dpop, s_noproof))
    check("[I4.3] DPoP: measured on the admin API (recorded; see INFO line)", True,
          "admin API %s DPoP proofs" % ("CHECKS" if s_plain != 200 and s_noproof != 200 else "does NOT check"))

    # --require-dpop: the client only issues key-bound tokens
    r_, out = quiet(M.cmd_onboarding_client_setup, ns(require_dpop=True))
    cc_ = kc.api("GET", "/clients/%s" % cid_())
    check("[I4.3] onboarding-client-setup --require-dpop: dpop.bound.access.tokens=true, recorded, guard clean",
          not isinstance(r_, BaseException) and cc_["attributes"].get("dpop.bound.access.tokens") == "true"
          and json.load(open(M.ONBOARDING_STATE))[OB].get("dpop") is True and "0 onboarding-client violations" in quiet(M.guard, kc, False)[1])
    def code_for(p_):
        fl_ = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client=OB, redirect=REDIRECT, admin_url=None, client_secret=None, cacert=a.cacert))
        url_, ver_ = fl_.auth_url(extra={"max_age": "300"})
        k_, u_, pg_ = p_.b.go(url_, None, REDIRECT)
        fin_, _ = fl_.finish(p_.b, k_, u_, pg_, p_.ctx)
        return urllib.parse.parse_qs(urllib.parse.urlparse(fin_).query)["code"][0], ver_
    code, ver = code_for(mgr)
    st, _, t = raw("POST", "/realms/%s/protocol/openid-connect/token" % REALM, urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "client_id": OB, "code_verifier": ver}).encode(),
        {"Content-Type": "application/x-www-form-urlencoded"})
    check("[I4.3] with --require-dpop, a token request without a DPoP proof is refused", st == 400, (st, t[:100]))
    code, ver = code_for(mgr)
    st, _, t = raw("POST", "/realms/%s/protocol/openid-connect/token" % REALM, urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "client_id": OB, "code_verifier": ver}).encode(),
        {"Content-Type": "application/x-www-form-urlencoded", "DPoP": proof("POST", tu_)})
    dt2 = json.loads(t) if st == 200 else {}
    s2, h2, _ = raw("GET", path, None, {"Authorization": "DPoP " + dt2.get("access_token", ""), "Origin": ORIGIN,
                                        "DPoP": proof("GET", BASE + path, dt2.get("access_token", ""))}, net=True)
    s3, _, _ = raw("GET", path, None, {"Authorization": "Bearer " + dt2.get("access_token", "")}, net=True)
    check("[I4.3] ... with a proof the page gets a bound token that works with a proof (200 + CORS) and not without (401)",
          s2 == 200 and acao(h2) == ORIGIN and s3 == 401, (st, s2, acao(h2), s3))
    quiet(M.cmd_onboarding_client_setup, ns())

n = sum(res)
print("\n%d/%d passed" % (n, len(res)))
sys.exit(0 if n == len(res) else 1)

#!/usr/bin/env python3
"""tests/create_shapes_live_check.py's run() against a throwaway keycloak-cac container in lab mode (strict FIPS), before it
runs on production. Lab wiring only: idp-admin.py's KC over the trusted source, `grant` and `guard` in process, the lab
CA trusted; the realm shaped as on the host (roles-setup, card-accounts on, the Entra domain attribute).

  fgap/onboarding_lab.sh <image> <kas checkout> [report] create_shapes_lab_test.py

Also proves "safe to run twice": a planted leftover of an earlier run (holding a test card) is swept; a second run
passes; an account NOT made by the check that holds a test card stops the run (NOT RUN) and is left alone.
"""
import argparse, contextlib, importlib.machinery, importlib.util, io, json, os, socket, ssl, sys, tempfile, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser()
ap.add_argument("--cacert", required=True); ap.add_argument("--skill-scripts", required=True)
ap.add_argument("--admin", default=os.path.join(HERE, "..", "host", "idp-admin.py")); ap.add_argument("--realm", default="dod-cac")
a = ap.parse_args()
os.environ.setdefault("IDP_ADMIN_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures", "idp-admin.test.json"))   # the lab/unit config; on a host the real one is used
ld = importlib.machinery.SourceFileLoader("idp_admin", a.admin)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
# the lab config's application shape (tests/fixtures/idp-admin.test.json)
APP_A_ROLES = tuple(g for g in M.APP_DELEGATIONS["app-a"]["app-a-admin"] if g != "partner-reader")
APP_BC_CLIENTS = tuple(c for c in M.APP_CLIENTS if c != "app-a" and c in M.APP_USER_MANAGERS)
sys.path.insert(0, a.skill_scripts); import e2e_check as E                                   # noqa: E402
sys.path.insert(0, os.path.join(HERE, "..", "tests")); import persona, create_shapes_live_check as CS   # noqa: E402
REALM, PORT, HOST = a.realm, 8443, "localhost"
BASE = "https://%s:%d" % (HOST, PORT)
CTX = ssl.create_default_context(cafile=a.cacert)
_cdc = ssl.create_default_context                       # persona and e2e_check build their own contexts: trust the lab CA
ssl.create_default_context = lambda purpose=ssl.Purpose.SERVER_AUTH, cafile=None, **k: _cdc(purpose, cafile=cafile or a.cacert, **k)
ssl._create_default_https_context = lambda: ssl.create_default_context()
_gai = socket.getaddrinfo                                                                      # the trusted source, IPv4
socket.getaddrinfo = lambda h, p, *r, **k: _gai("127.0.0.1", p, *r, **k) if h == HOST else _gai(h, p, *r, **k)
res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s  %-96s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

def raw(method, path, body=None, headers=None):
    import http.client
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=30)
    con = http.client.HTTPSConnection(HOST, PORT, context=CTX, timeout=60); con.sock = CTX.wrap_socket(sock, server_hostname=HOST)
    h = {"Host": "%s:%d" % (HOST, PORT)}; h.update(headers or {})
    con.request(method, path, body=body, headers=h); r = con.getresponse(); t = r.read().decode("utf-8", "replace"); con.close()
    return r.status, t

class Adapter:
    def __init__(self): self.login()
    def login(self):
        st, t = raw("POST", "/realms/master/protocol/openid-connect/token", urllib.parse.urlencode({
            "grant_type": "client_credentials", "client_id": "stig-automation", "client_secret": os.environ["AUTOMATION_SECRET"]}).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"})
        self.token = json.loads(t)["access_token"]
    def req(self, method, path, body=None, headers=None, _retry=True):
        h = dict(headers or {}); h["Authorization"] = "Bearer " + self.token
        st, t = raw(method, path, body, h)
        if st == 401 and _retry:
            self.login(); return self.req(method, path, body, headers, False)
        return st, t
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        st, d = self.req(method, "/admin/realms/%s%s" % (M.REALM, path), json.dumps(obj).encode() if obj is not None else None,
                         {"Content-Type": "application/json"} if obj is not None else {})
        if st == 404 and ok404:
            return None
        if st not in ok:
            sys.exit("%s %s -> HTTP %s %s" % (method, path, st, d[:300]))
        return json.loads(d) if d.strip() else None

TMP = tempfile.mkdtemp(prefix="shapes-")
M.REALM = REALM; M.CFG = dict(M.CFG, CAC_PUBLIC_URL=BASE); M.ADMIN_HOST, M.ADMIN_PORT = HOST, PORT
M.ALLOWLIST, M.STATE, M.ONBOARDING_STATE, M.DELEGATE_STATE = (os.path.join(TMP, x) for x in ("a.json", "s.json", "o.json", "d.json"))
M.ALLOWLIST_ATTR, M.ALLOWLIST_ROLES_ATTR = "stig.admin-allowlist.%s" % REALM, "stig.admin-allowlist-roles.%s" % REALM
kc = Adapter(); M.KC = lambda: kc
M._write_json(M.ALLOWLIST, {}); M.save_state(M.new_state())

def quiet(fn, *args):
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            return fn(*args), out.getvalue()
    except (SystemExit, RuntimeError) as e:
        return e, out.getvalue()

def run_adm(*args):
    """The two idp-admin.py commands the check uses, in process (the lab has no host tooling)."""
    if args[0] == "grant":
        r_, out = quiet(M.apply_roles, kc, M.user(kc, args[1]), list(args[2:]), M.load_state() or M.new_state())
        return (1 if isinstance(r_, BaseException) else 0), out
    if args[0] == "guard":
        r_, out = quiet(M.guard, kc, False)
        return r_, out
    raise AssertionError(args)

# the realm as on the host
if not M.find_client(kc, "app-a"):
    kc.api("POST", "/clients", {"clientId": "app-a", "protocol": "openid-connect", "publicClient": False,
                                "redirectUris": ["https://app-a.lab.example/cb"], "fullScopeAllowed": False})
cu = M.client_uuid(kc, "app-a")
for r in APP_A_ROLES:
    kc.req("POST", "/admin/realms/%s/clients/%s/roles" % (REALM, cu), json.dumps({"name": r}).encode(), {"Content-Type": "application/json"})
r_, out = quiet(M.cmd_roles_setup, argparse.Namespace(retire_app=[]))
check("setup: roles-setup", not isinstance(r_, BaseException), out[-200:] if isinstance(r_, BaseException) else "")
r_, out = quiet(M.cmd_card_accounts, argparse.Namespace(state="on", attribute="cac_edipi"))
check("setup: card-accounts on", "ON" in out, out[-160:])
at = dict(kc.api("GET", "").get("attributes") or {}); at.update({"stig.accounts.entra-domain": "example.mil",
                                                             "stig.accounts.email-domains": ".mil,example.mil"})
kc.api("PUT", "", {"attributes": at})                       # as `entra --auto-link-domain example.mil` sets it

# not run while an account the check did not make holds a test card
kc.api("POST", "/users", {"username": "someone.else", "enabled": False, "firstName": "Some", "lastName": "One",
                          "attributes": {"cac_edipi": [CS.TEST_CARDS[1]]}})
r_, out = quiet(CS.run, M, kc, E, persona, run_adm, BASE, REALM, "000001")
check("[twice] an account outside the check holding a test card: NOT RUN, and it is left alone",
      isinstance(r_, SystemExit) and "NOT RUN" in str(r_) and M.user(kc, "someone.else"), str(r_)[:160])
kc.api("DELETE", "/users/%s" % M.user(kc, "someone.else")["id"])

# a leftover of an earlier run, holding a test card: swept by the next run
kc.api("POST", "/users", {"username": "tshp-000000.cac", "enabled": True, "firstName": "Left", "lastName": "Over",
                          "attributes": {"cac_edipi": [CS.TEST_CARDS[0]]}})
kc.api("POST", "/users", {"username": "tshp-000000.extra", "enabled": True, "firstName": "Not", "lastName": "Ours"})
print("\n== run 1")
n1, t1 = CS.run(M, kc, E, persona, run_adm, BASE, REALM, "000002")
check("[run 1] %d/%d" % (n1, t1), t1 and n1 == t1)
check("[twice] the planted leftover (an exact name) was swept; a near name (tshp-000000.extra) was NOT",
      not kc.api("GET", "/users?exact=true&username=tshp-000000.cac") and kc.api("GET", "/users?exact=true&username=tshp-000000.extra"))
print("\n== run 2 (the same check again)")
n2, t2 = CS.run(M, kc, E, persona, run_adm, BASE, REALM, "000003")
check("[run 2] %d/%d - safe to run twice" % (n2, t2), t2 and n2 == t2)
kc.api("DELETE", "/users/%s" % M.user(kc, "tshp-000000.extra")["id"])

n = sum(res); print("\n%d/%d passed" % (n, len(res))); sys.exit(0 if n == len(res) else 1)

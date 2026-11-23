#!/usr/bin/env python3
"""tests/onboarding_live_check.py, run in the lab against a throwaway keycloak-cac container with STIG_CARD_PORT set.

The live check signs a throwaway user manager in through the realm's browser flow. With the card port set (as on a
production host), a browser that presented no card first meets the X.509 step's card sign-in choice, not the password
form; the check used to look for the password form on the first page and crashed before testing anything. This runs
the live check's own code (`onboarding_live_check.run`, and tests/persona.py) here, so a change to the sign-in pages
is caught in the lab first:

  - the first page of a browser sign-in is the card sign-in choice (the condition the live check must handle);
  - the live check's checks all pass for an onboarding client (max-auth-age 30 s here, so the stale-write wait is short);
  - its throwaway user manager is gone afterwards (no t.onb.* account left).

  live_check_lab_test.py --cacert root.crt --skill-scripts <keycloak-asd-stig/scripts> [--realm dod-cac]
  (fgap/onboarding_lab.sh starts the container, with STIG_CARD_PORT=8444, and this script; AUTOMATION_SECRET in the
  environment)

Prints no secrets. Exit 0 only if every check passed.
"""
import argparse, contextlib, http.client, importlib.machinery, importlib.util, io, json, os, socket, ssl, sys, tempfile
import time, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser()
ap.add_argument("--cacert", required=True)
ap.add_argument("--skill-scripts", required=True)
ap.add_argument("--admin", default=os.path.join(HERE, "..", "host", "idp-admin.py"))
ap.add_argument("--realm", default="dod-cac")
a = ap.parse_args()

# the live check's HTTP (persona, its admin-API calls) uses Python's default trust store: here, the lab's CA
os.environ["SSL_CERT_FILE"] = a.cacert
os.environ.setdefault("IDP_ADMIN_CONFIG", os.path.join(HERE, "..", "tests", "fixtures", "idp-admin.test.json"))
ld = importlib.machinery.SourceFileLoader("idp_admin", a.admin)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
sys.path.insert(0, a.skill_scripts); import e2e_check as E                                    # noqa: E402
sys.path.insert(0, os.path.join(HERE, "..", "tests")); import onboarding_live_check as L, persona   # noqa: E402

REALM, PORT, HOST = a.realm, 8443, "localhost"
BASE = "https://%s:%d" % (HOST, PORT)
ORIGIN = "https://portal.lab.example"
CTX = ssl.create_default_context(cafile=a.cacert)
res = []
def check(n, ok, d=""):
    res.append(bool(ok)); print("%s  %-100s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

def raw(method, path, body=None, headers=None):
    """From 127.0.0.1, the source the path filter trusts (the operator's tooling); never ::1."""
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=30)
    con = http.client.HTTPSConnection(HOST, PORT, context=CTX, timeout=60)
    con.sock = CTX.wrap_socket(sock, server_hostname=HOST)
    h = {"Host": "%s:%d" % (HOST, PORT)}; h.update(headers or {})
    con.request(method, path, body=body, headers=h)
    r = con.getresponse(); text = r.read().decode("utf-8", "replace")
    con.close()
    return r.status, text

class Adapter:
    """idp-admin.py's KC over the trusted source, as the master realm's stig-automation (as on the host)."""
    def __init__(self):
        self.login()
    def login(self):
        st, t = raw("POST", "/realms/master/protocol/openid-connect/token", urllib.parse.urlencode({
            "grant_type": "client_credentials", "client_id": "stig-automation", "client_secret": os.environ["AUTOMATION_SECRET"]}).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"})
        if st != 200:
            sys.exit("master login failed: HTTP %s" % st)
        self.token, self.at = json.loads(t)["access_token"], time.time()
    def req(self, method, path, body=None, headers=None):
        if time.time() - self.at > 40:
            self.login()
        h = dict(headers or {}); h["Authorization"] = "Bearer " + self.token
        return raw(method, path, body, h)
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        st, data = self.req(method, "/admin/realms/%s%s" % (M.REALM, path), json.dumps(obj).encode() if obj is not None else None,
                            {"Content-Type": "application/json"} if obj is not None else {})
        if st == 404 and ok404:
            return None
        if st not in ok:
            sys.exit("%s %s -> HTTP %s %s" % (method, path, st, data[:300]))
        return json.loads(data) if data.strip() else None

TMP = tempfile.mkdtemp(prefix="live-check-lab-")
M.REALM = REALM
M.ALLOWLIST, M.STATE, M.ONBOARDING_STATE = (os.path.join(TMP, x) for x in ("admins.json", "state.json", "onboarding.json"))
M.ALLOWLIST_ATTR, M.ALLOWLIST_ROLES_ATTR = "stig.admin-allowlist.%s" % REALM, "stig.admin-allowlist-roles.%s" % REALM
kc = Adapter()
M.KC = lambda: kc
M._write_json(M.ALLOWLIST, {}); M.save_state(M.new_state())

def quiet(fn, *args):
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            return fn(*args), out.getvalue()
    except (SystemExit, RuntimeError) as e:
        return e, out.getvalue()

def run_adm(*args):
    """The live check's `idp-admin.py <command>`, in process: grant and guard are all it runs."""
    if args[0] == "grant":
        r_, out = quiet(M.cmd_grant, argparse.Namespace(username=args[1], roles=list(args[2:]), reset_credentials=False,
                                                        email=None, clear_bindings=False))
    elif args[0] == "guard":
        r_, out = quiet(M.guard, kc, True)
    else:
        raise AssertionError("the live check ran idp-admin.py %s" % " ".join(args))
    return (1 if isinstance(r_, BaseException) and not (isinstance(r_, SystemExit) and r_.code in (0, None)) else 0), out

# ---- the realm as a host shapes it: application clients and their role groups, the user-manager roles
for cid, roles in (("app-a", list(M.APP_DELEGATIONS["app-a"]["app-a-admin"])), ("app-b", ["owner", "member"]), ("app-c", ["lead"])):
    if not M.find_client(kc, cid):
        kc.api("POST", "/clients", {"clientId": cid, "protocol": "openid-connect", "publicClient": False, "standardFlowEnabled": True,
                                    "redirectUris": ["https://%s.lab.example/cb" % cid], "fullScopeAllowed": False})
    cu = M.client_uuid(kc, cid)
    for r in roles:
        kc.req("POST", "/admin/realms/%s/clients/%s/roles" % (REALM, cu), json.dumps({"name": r}).encode(), {"Content-Type": "application/json"})
r_, out = quiet(M.cmd_roles_setup, argparse.Namespace())
check("setup: roles-setup", not isinstance(r_, BaseException), out[-300:] if isinstance(r_, BaseException) else "")
OB = M.ONBOARDING_CLIENT_IDS[0]
r_, out = quiet(M.cmd_onboarding_client_setup, argparse.Namespace(
    redirect_uri=ORIGIN + "/admin/accounts/callback", origin=None, client_id=OB, app=["app-a"], max_auth_age=30,
    require_dpop=False, operations=",".join(M.ONBOARDING_DEFAULT_OPS)))
check("setup: onboarding-client-setup %s (max-auth-age 30 s)" % OB, not isinstance(r_, BaseException), (str(r_) + out)[-300:])

# V-222447: the harness's log gate wants one request with a Referer (a query, a fragment, an EDIPI-like run in its path)
st_r, _ = raw("GET", "/realms/%s/.well-known/openid-configuration" % REALM, None,
              {"Referer": "https://portal.lab.example/admin/accounts/1234567890?q=cac_edipi:1234567890#frag"})
check("[log] a request with a Referer (query, fragment, an EDIPI in its path) is served", st_r == 200, st_r)

# ---- the condition: a browser sign-in starts at the card sign-in choice
fl = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client="security-admin-console", redirect="%s/admin/%s/console/" % (BASE, REALM),
                               admin_url=None, client_secret=None, cacert=a.cacert))
url, _ = fl.auth_url()
k, u, p = E.Browser(a.cacert).go(url, None, "%s/admin/%s/console/" % (BASE, REALM))
check("the first page of a browser sign-in is the card sign-in choice (STIG_CARD_PORT), with no password form",
      k == "page" and E.page_id(p) == persona.CARD_CHOICE and 'id="kc-form-login"' not in p, (k, E.page_id(p or "")))

# ---- the live check itself, unchanged
name = "t.onb.lab%s" % time.strftime("%H%M%S")
try:
    lres = L.run(M, kc, E, run_adm, BASE, REALM, OB, name=name)
except Exception as e:      # noqa: BLE001 - a crash is the failure this test exists for
    lres = []
    check("the live check ran to the end (no crash)", False, repr(e)[:200])
check("the live check ran to the end and every one of its checks passed (%d)" % len(lres), lres and all(lres), lres)
left = kc.api("GET", "/users?search=t.onb") or []
check("no t.onb.* account is left", not left, [x.get("username") for x in left])

n = sum(res)
print("\n%d/%d passed" % (n, len(res)))
sys.exit(0 if n == len(res) else 1)

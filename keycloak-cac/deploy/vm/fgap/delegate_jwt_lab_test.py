#!/usr/bin/env python3
"""The delegates on client-jwt (private_key_jwt, ES256), proved against a throwaway keycloak-cac container in lab mode.

Runs INSIDE that container's network namespace (fgap/onboarding_lab.sh <image> <kas> [report] fgap/delegate_jwt_lab_test.py),
so 127.0.0.1 is the operator's tooling, as on the IdP host. Drives idp-admin.py's own ensure_delegate_client,
roles-setup, converge_delegate_auth (what delegate-client-setup runs), check_jwks_url and the drift report, and the
existing delegation tests fgap/app_admin_fgap.py test ($L) and fgap/split_delegation_test.py test ($T):

  1. baseline, both delegates on client-secret: $L and $T pass;
  2. delegate-client-setup refuses a JWKS URL that is http, an IP literal or a local name;
  3. each delegate switched to client-jwt ES256 with its OWN key and JWKS (served on 127.0.0.1 here, because the lab
     has no public name; the URL rule itself is (2) and the unit test):
     - an ES256 client assertion mints a token, and that token works on the admin API;
     - the OLD secret and the regenerated one both fail (invalid_client);
     - the expected authentication is recorded and reports no drift; a re-run of reader-delegate-setup keeps client-jwt;
     - a flip back to client-secret behind the tooling's back is reported as drift (STIG-DELEGATE-CLIENT-DRIFT);
     - the service account still holds no role, the delegation is unchanged;
  4. $L and $T pass again, signing in with the delegates' keys instead of secrets.

  (AUTOMATION_SECRET in the environment) delegate_jwt_lab_test.py --cacert root.crt --skill-scripts <kas scripts>
"""
import time
import argparse, http.server, importlib.machinery, importlib.util, io, json, os, re, socket, ssl, subprocess, sys, tempfile, threading
import contextlib, urllib.parse

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
sys.path.insert(0, HERE); import client_jwt  # noqa: E402
REALM, PORT, HOST = a.realm, 8443, "localhost"
BASE = "https://%s:%d" % (HOST, PORT)
CTX = ssl.create_default_context(cafile=a.cacert)
DELEGATES = ("app-a-admin", "app-a-reader-delegate")
res = []
def check(n, ok, d=""):
    res.append(bool(ok)); print("%s  %-100s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

def raw(method, path, body=None, headers=None):
    import http.client
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=30)
    con = http.client.HTTPSConnection(HOST, PORT, context=CTX, timeout=60); con.sock = CTX.wrap_socket(sock, server_hostname=HOST)
    h = {"Host": "%s:%d" % (HOST, PORT)}; h.update(headers or {})
    con.request(method, path, body=body, headers=h); r = con.getresponse(); t = r.read().decode("utf-8", "replace"); con.close()
    return r.status, t

class Adapter:
    def __init__(self):
        self.login()
    def login(self):
        st, t = raw("POST", "/realms/master/protocol/openid-connect/token", urllib.parse.urlencode({
            "grant_type": "client_credentials", "client_id": "stig-automation", "client_secret": os.environ["AUTOMATION_SECRET"]}).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"})
        self.token = json.loads(t)["access_token"]
    def req(self, method, path, body=None, headers=None, auth=True, _retry=True):
        h = dict(headers or {})
        if auth:
            h["Authorization"] = "Bearer " + self.token
        st, t = raw(method, path, body, h)
        if st == 401 and auth and _retry:
            self.login(); return self.req(method, path, body, headers, auth, False)
        return st, t
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        st, d = self.req(method, "/admin/realms/%s%s" % (M.REALM, path), json.dumps(obj).encode() if obj is not None else None,
                         {"Content-Type": "application/json"} if obj is not None else {})
        if st == 404 and ok404:
            return None
        if st not in ok:
            sys.exit("%s %s -> HTTP %s %s" % (method, path, st, d[:300]))
        return json.loads(d) if d.strip() else None

TMP = tempfile.mkdtemp(prefix="djwt-")
M.REALM = REALM
M.ALLOWLIST, M.STATE, M.ONBOARDING_STATE, M.DELEGATE_STATE = (os.path.join(TMP, x) for x in
                                                              ("admins.json", "state.json", "onb.json", "delegates.json"))
M.ALLOWLIST_ATTR, M.ALLOWLIST_ROLES_ATTR = "stig.admin-allowlist.%s" % REALM, "stig.admin-allowlist-roles.%s" % REALM
kc = Adapter(); M.KC = lambda: kc
M._write_json(M.ALLOWLIST, {}); M.save_state(M.new_state())
SECRET_FILE = os.path.join(TMP, "automation_secret"); open(SECRET_FILE, "w").write(os.environ["AUTOMATION_SECRET"])
# the tests run as subprocesses: make "localhost" mean 127.0.0.1 for them too (the path filter trusts only that source;
# ::1 would be an ordinary network client, and the master realm answers 404 there)
SITE = os.path.join(TMP, "site"); os.makedirs(SITE)
open(os.path.join(SITE, "sitecustomize.py"), "w").write(
    "import socket\n_g = socket.getaddrinfo\n"
    "socket.getaddrinfo = lambda h, *a, **k: _g('127.0.0.1' if h == 'localhost' else h, *a, **k)\n")
SUB_ENV = dict(os.environ, PYTHONPATH=SITE)

def quiet(fn, *args):
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            return fn(*args), out.getvalue()
    except (SystemExit, RuntimeError) as e:
        return e, out.getvalue()

def token(cid, **cred):
    st, t = raw("POST", "/realms/%s/protocol/openid-connect/token" % REALM, urllib.parse.urlencode(dict(
        {"grant_type": "client_credentials", "client_id": cid}, **cred)).encode(), {"Content-Type": "application/x-www-form-urlencoded"})
    return st, (json.loads(t) if t.strip().startswith("{") else t)

def run_tests(label, sa_cred, reader_cred):
    """$L and $T against the lab realm; returns ((passed, total) of $L, of $T)."""
    common = ["--url", BASE, "--cacert", a.cacert, "--admin-client-id", "stig-automation", "--admin-secret-file", SECRET_FILE]
    out = {}
    for name, cmd in (("$L", [sys.executable, os.path.join(HERE, "app_admin_fgap.py")] + common + ["--app", "app-a", "--realm", REALM, "test"] + sa_cred),
                      ("$T", [sys.executable, os.path.join(HERE, "split_delegation_test.py")] + common
                       + ["--admin-script", a.admin, "test", "--realm", REALM] + sa_cred + reader_cred)):
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, env=SUB_ENV)
        txt = p.stdout + p.stderr
        m = re.findall(r"(\d+)/(\d+) passed", txt)
        pt = tuple(int(x) for x in m[-1]) if m else (0, -1)
        fails = [l for l in txt.splitlines() if l.startswith("FAIL")]
        check("[%s] %s: %d/%d passed" % (label, name, pt[0], pt[1]), p.returncode == 0 and pt[0] == pt[1] and pt[1] > 0,
              fails[:3] or ("" if p.returncode == 0 else txt[-300:]))
        out[name] = pt
    return out

# ------------------------------------------------------------------ setup: the realm and the two delegates (secrets)
cap = M.gate_capability(kc, M.GATE_ADMIN_API_PROFILE_KEY)
APP_A, REVIEW = list(APP_A_ROLES), ["partner-reader", "partner-auditor", "partner-lead", "contractor"]
for cid, roles in (("app-a", APP_A + REVIEW), ("app-b", ["owner", "maintainer", "reviewer", "member"]),
                   ("app-c", ["lead", "analyst", "auditor", "reader"])):
    if not M.find_client(kc, cid):
        kc.api("POST", "/clients", {"clientId": cid, "protocol": "openid-connect", "publicClient": False, "standardFlowEnabled": True,
                                    "redirectUris": ["https://%s.lab.example/cb" % cid], "fullScopeAllowed": False})
    cu = M.client_uuid(kc, cid)
    for r in roles:
        kc.req("POST", "/admin/realms/%s/clients/%s/roles" % (REALM, cu), json.dumps({"name": r}).encode(), {"Content-Type": "application/json"})
for cid in DELEGATES:
    quiet(M.ensure_delegate_client, kc, cid, "lab delegate %s" % cid)
r_, out = quiet(M.cmd_roles_setup, argparse.Namespace())
check("setup: roles-setup with both delegates", not isinstance(r_, BaseException), out[-200:] if isinstance(r_, BaseException) else "")
p = subprocess.run([sys.executable, os.path.join(HERE, "app_admin_fgap.py"), "--url", BASE, "--cacert", a.cacert, "--realm", REALM, "--app", "app-a",
                    "--admin-client-id", "stig-automation", "--admin-secret-file", SECRET_FILE, "--admin-script", a.admin, "setup"],
                   capture_output=True, text=True, timeout=600, env=SUB_ENV)
check("setup: fgap/app_admin_fgap.py setup (as the operator runs it)", p.returncode == 0, (p.stdout + p.stderr)[-200:])
secrets_ = {}
for cid in DELEGATES:
    c = M.find_client(kc, cid)
    secrets_[cid] = kc.api("GET", "/clients/%s/client-secret" % c["id"])["value"]
    open(os.path.join(TMP, cid + ".secret"), "w").write(secrets_[cid])
check("setup: both delegates on client-secret", all(kc.api("GET", "/clients/%s" % M.find_client(kc, cid)["id"])["clientAuthenticatorType"]
                                                   == "client-secret" for cid in DELEGATES))

# ------------------------------------------------------------------ 1. baseline with secrets
base = run_tests("baseline, client-secret", ["--sa-secret-file", os.path.join(TMP, "app-a-admin.secret")],
                 ["--reader-secret-file", os.path.join(TMP, "app-a-reader-delegate.secret")])

# ------------------------------------------------------------------ 2. the JWKS URL rule (delegate-client-setup)
for bad in ("http://app-a.lab.example/jwks", "https://10.1.2.3/jwks", "https://localhost/jwks", "https://127.0.0.1:18081/jwks",
            "https://app-a.lab.example/jwks?x=1"):
    r_, out = quiet(M.cmd_delegate_client_setup, argparse.Namespace(client_id="app-a-admin", jwks_url=bad, alg="ES256",
                                                                     client_secret=False))
    check("[url] delegate-client-setup refuses %s" % bad, isinstance(r_, SystemExit) and "REFUSED" in str(r_), str(r_)[:90])
r_, out = quiet(M.cmd_delegate_client_setup, argparse.Namespace(client_id="app-a-admin", jwks_url=None, alg="ES256",
                                                                 client_secret=False))
check("[url] ... and needs either --jwks-url or --client-secret", isinstance(r_, SystemExit) and "REFUSED" in str(r_))
check("[url] nothing changed by the refusals", all(kc.api("GET", "/clients/%s" % M.find_client(kc, cid)["id"])["clientAuthenticatorType"]
                                                   == "client-secret" for cid in DELEGATES) and not M.load_delegate_records())

# ------------------------------------------------------------------ 3. the switch, with each delegate's own ES256 key
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
keys, jwks = {}, {}
for cid in DELEGATES:
    k = ec.generate_private_key(ec.SECP256R1())
    keys[cid] = os.path.join(TMP, cid + ".pem")
    open(keys[cid], "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    jwks[cid] = {"keys": [client_jwt.jwk(keys[cid])]}

class JWKS(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        cid = self.path.strip("/").split("/")[0]
        body = json.dumps(jwks.get(cid, {"keys": []})).encode()
        self.send_response(200 if cid in jwks else 404); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *x):
        pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 18081), JWKS)
threading.Thread(target=srv.serve_forever, daemon=True).start()
ISS = BASE + "/realms/%s" % REALM

for cid in DELEGATES:
    old = secrets_[cid]
    url = "http://127.0.0.1:18081/%s/jwks" % cid            # the lab's stand-in for the app's https JWKS
    r_, out = quiet(M.converge_delegate_auth, kc, cid, "client-jwt", url, "ES256")
    c = kc.api("GET", "/clients/%s" % M.find_client(kc, cid)["id"])
    check("[%s] switched to client-jwt ES256 with its own JWKS" % cid, not isinstance(r_, BaseException)
          and c["clientAuthenticatorType"] == "client-jwt" and c["attributes"].get("token.endpoint.auth.signing.alg") == "ES256"
          and c["attributes"].get("jwks.url") == url, (str(r_) + out)[-160:])
    st, t = token(cid, **client_jwt.form_fields(keys[cid], cid, ISS))
    check("[%s] an ES256 client assertion mints a token" % cid, st == 200 and "access_token" in t, (st, t if st != 200 else ""))
    if st == 200:
        g = M.group_by_path(kc, "/app-a/partner-reader")
        st2, _ = raw("GET", "/admin/realms/%s/groups/%s/members" % (REALM, g["id"]), None, {"Authorization": "Bearer " + t["access_token"]})
        check("[%s] ... and that token works on the admin API (200)" % cid, st2 == 200, st2)
    st, t = token(cid, client_secret=old)
    new = kc.api("GET", "/clients/%s/client-secret" % c["id"]).get("value")
    st2, t2 = token(cid, client_secret=new)
    check("[%s] a client-jwt client accepts no secret at all (the old one and the regenerated one both refused)" % cid,
          new != old and st in (400, 401) and st2 in (400, 401), (st, st2))
    check("[%s] no rotated (previous) secret is kept" % cid,
          (kc.api("GET", "/clients/%s" % c["id"]).get("attributes") or {}).get("client.secret.rotated") in (None, ""))
    other = [x for x in DELEGATES if x != cid][0]
    st, t = token(cid, **client_jwt.form_fields(keys[other], cid, ISS))
    check("[%s] an assertion signed with the OTHER delegate's key is refused" % cid, st in (400, 401), st)
    sa = kc.api("GET", "/clients/%s/service-account-user" % c["id"])
    rm = kc.api("GET", "/users/%s/role-mappings" % sa["id"]) or {}
    check("[%s] its service account still holds no role" % cid, not (rm.get("clientMappings") or {})
          and all(r["name"].startswith("default-roles-") for r in rm.get("realmMappings") or []))

check("[record] both delegates recorded as client-jwt ES256", {k: (v["auth"], v.get("alg")) for k, v in M.load_delegate_records().items()}
      == {cid: ("client-jwt", "ES256") for cid in DELEGATES})
check("[record] no drift reported", not M.delegate_auth_report(kc), M.delegate_auth_report(kc))
sv = (M.load_kcstig, M.host_client_files)
M.load_kcstig, M.host_client_files = (lambda *x, **k: (None, None, None, None)), (lambda d=None: {})
o_ = io.StringIO(); d_ = M.check_clients(kc, None, o_, {})
M.load_kcstig, M.host_client_files = sv
check("[record] check-clients: ok for both delegates, no drift", not d_ and all("ok    %s: delegate authentication matches" % cid in o_.getvalue()
                                                                              for cid in DELEGATES), d_[:2])
r_, out = quiet(M.guard, kc, False)
check("[record] guard: clean (the recorded switch is not drift)", r_ == M.GUARD_OK, out[-160:])
quiet(M.ensure_delegate_client, kc, "app-a-reader-delegate", "lab delegate")
check("[record] a re-run of the reader delegate's setup leaves it on client-jwt",
      kc.api("GET", "/clients/%s" % M.find_client(kc, "app-a-reader-delegate")["id"])["clientAuthenticatorType"] == "client-jwt")
c = kc.api("GET", "/clients/%s" % M.find_client(kc, "app-a-admin")["id"]); c["clientAuthenticatorType"] = "client-secret"
kc.api("PUT", "/clients/%s" % c["id"], c)
rep_ = M.delegate_auth_report(kc)
check("[record] a flip back to client-secret behind the tooling's back: STIG-DELEGATE-CLIENT-DRIFT",
      any("STIG-DELEGATE-CLIENT-DRIFT client=app-a-admin authenticates with client-secret" in l for l in rep_), rep_)
o_ = io.StringIO(); M.load_kcstig, M.host_client_files = (lambda *x, **k: (None, None, None, None)), (lambda d=None: {})
d_ = M.check_clients(kc, None, o_, {}); M.load_kcstig, M.host_client_files = sv
check("[record] ... and check-clients reports it as drift", any("app-a-admin" in x for x in d_), d_[:1])
quiet(M.converge_delegate_auth, kc, "app-a-admin", "client-jwt", "http://127.0.0.1:18081/app-a-admin/jwks", "ES256")
check("[record] restored by re-running the switch: no drift", not M.delegate_auth_report(kc))

# ---- ROLLBACK (delegate-client-setup --client-secret): the key is gone, the secret from BEFORE the switch stays dead
old0 = secrets_["app-a-admin"]
r_, out = quiet(M.cmd_delegate_client_setup, argparse.Namespace(client_id="app-a-admin", jwks_url=None, alg="ES256",
                                                                 expect_thumbprint=None, client_secret=True))
c = kc.api("GET", "/clients/%s" % M.find_client(kc, "app-a-admin")["id"]); at_ = c.get("attributes") or {}
check("[rollback] --client-secret: back on client-secret, recorded, no drift", r_ is None
      and c["clientAuthenticatorType"] == "client-secret" and M.load_delegate_records()["app-a-admin"]["auth"] == "client-secret"
      and not M.delegate_auth_report(kc), (str(r_) + out)[-160:])
check("[rollback] ... and every JWKS attribute really gone from the live client (sent empty, re-read)",
      all(at_.get(k) in (None, "", "false") for k in M.JWKS_ATTRS + ("token.endpoint.auth.signing.alg",)),
      {k: at_.get(k) for k in M.JWKS_ATTRS + ("token.endpoint.auth.signing.alg",)})
st, t = token("app-a-admin", client_secret=old0)
check("[rollback] the secret from BEFORE the switch is refused after the rollback (a client-secret client now)",
      st in (400, 401) and "access_token" not in str(t), (st, str(t)[:80]))
st, t = token("app-a-admin", client_secret=kc.api("GET", "/clients/%s/client-secret" % c["id"])["value"])
check("[rollback] ... while the NEW secret works (200)", st == 200, st)
st, t = token("app-a-admin", **client_jwt.form_fields(keys["app-a-admin"], "app-a-admin", ISS))
check("[rollback] ... and the app's key no longer does", st in (400, 401), st)
check("[rollback] no rotated secret kept", at_.get("client.secret.rotated") in (None, ""))
quiet(M.converge_delegate_auth, kc, "app-a-admin", "client-jwt", "http://127.0.0.1:18081/app-a-admin/jwks", "ES256")
check("[rollback] switched forward again for the rest: no drift", not M.delegate_auth_report(kc))

# ------------------------------------------------------------------ 4. the delegation tests, signing in with the keys
after = run_tests("client-jwt ES256", ["--sa-jwt-key", keys["app-a-admin"]], ["--reader-jwt-key", keys["app-a-reader-delegate"]])
check("the delegation tests give the same counts with keys as with secrets", after == base, (base, after))

# ------------------------------------------------------------------ 5. the LIVE way to run $L/$T after the switch: test twins
before_auth = {cid: kc.api("GET", "/clients/%s" % M.find_client(kc, cid)["id"])["clientAuthenticatorType"] for cid in DELEGATES}
tsec = {}
for cid in DELEGATES:
    tsec[cid] = os.path.join(TMP, "twin-%s.secret" % cid)
    r_, out = quiet(M.create_test_twin, kc, cid, tsec[cid])
    check("[twin] delegate-test-twin %s create: %s, a secret in a 0400 file" % (cid, M.twin_id(cid)),
          not isinstance(r_, BaseException) and M.find_client(kc, M.twin_id(cid)) and oct(os.stat(tsec[cid]).st_mode & 0o777) == "0o400",
          (str(r_) + out)[-160:])
tw_rep = M.test_twins_present(kc)
check("[twin] while they exist, the guard reports them (STIG-DELEGATE-TEST-TWIN)", len(tw_rep) == 2, tw_rep)
twin = run_tests("test twins, client-secret", ["--sa-client-id", M.twin_id("app-a-admin"), "--sa-secret-file", tsec["app-a-admin"]],
                 ["--reader-client-id", M.twin_id("app-a-reader-delegate"), "--reader-secret-file", tsec["app-a-reader-delegate"]])
check("[twin] $L and $T as the twins give the same counts as the delegates themselves (same delegation, nothing more)", twin == base, (base, twin))
for cid in DELEGATES:
    quiet(M.remove_test_twin, kc, cid)
# a disabled delegate gets no twin; a stale twin is removed by guard --fix; `run` always cleans up
rd_ = kc.api("GET", "/clients/%s" % M.find_client(kc, "app-a-reader-delegate")["id"]); rd_["enabled"] = False
kc.api("PUT", "/clients/%s" % rd_["id"], rd_)
r_, out = quiet(M.create_test_twin, kc, "app-a-reader-delegate", os.path.join(TMP, "never"))
check("[twin] refused for a DISABLED delegate, nothing created", isinstance(r_, SystemExit) and "disabled" in str(r_)
      and not M.find_client(kc, M.twin_id("app-a-reader-delegate")), str(r_)[:90])
rd_["enabled"] = True; kc.api("PUT", "/clients/%s" % rd_["id"], rd_)
quiet(M.create_test_twin, kc, "app-a-admin", os.path.join(TMP, "stale"))
tc = kc.api("GET", "/clients/%s" % M.find_client(kc, M.twin_id("app-a-admin"))["id"])
tc["attributes"][M.TWIN_CREATED_ATTR] = str(int(time.time()) - M.TWIN_MAX_AGE - 60); kc.api("PUT", "/clients/%s" % tc["id"], tc)
lines_ = M.test_twins_present(kc, fix=False)
check("[twin] an old twin is reported with its age", any("older than" in l for l in lines_), lines_)
lines_ = M.test_twins_present(kc, fix=True)
check("[twin] guard --fix removes a twin older than 2 h", any("REMOVED" in l for l in lines_)
      and not M.find_client(kc, M.twin_id("app-a-admin")), lines_)
quiet(M.create_test_twin, kc, "app-a-admin", os.path.join(TMP, "future"))
tc = kc.api("GET", "/clients/%s" % M.find_client(kc, M.twin_id("app-a-admin"))["id"])
tc["attributes"][M.TWIN_CREATED_ATTR] = str(int(time.time()) + 3600); kc.api("PUT", "/clients/%s" % tc["id"], tc)
lines_ = M.test_twins_present(kc, fix=True)
check("[twin] a creation time in the FUTURE is not trusted: guard --fix removes the twin", any("REMOVED" in l for l in lines_)
      and not M.find_client(kc, M.twin_id("app-a-admin")), lines_)
quiet(M.create_test_twin, kc, "app-a-admin", os.path.join(TMP, "orph"))
dl_ = kc.api("GET", "/clients/%s" % M.find_client(kc, "app-a-admin")["id"]); dl_["enabled"] = False
kc.api("PUT", "/clients/%s" % dl_["id"], dl_)
lines_ = M.test_twins_present(kc, fix=True)
check("[twin] guard --fix removes a twin whose delegate was disabled", any("REMOVED" in l and "disabled" in l for l in lines_)
      and not M.find_client(kc, M.twin_id("app-a-admin")), lines_)
dl_["enabled"] = True; kc.api("PUT", "/clients/%s" % dl_["id"], dl_)
RD = os.path.join(TMP, "twins")
probe = ("import os,stat,sys; d=%r; ok=all(stat.S_IMODE(os.stat(os.path.join(d,c)).st_mode)==0o400 for c in %r); "
         "sys.exit(0 if ok else 3)") % (RD, list(DELEGATES))
r_, out = quiet(M.cmd_delegate_test_twin, argparse.Namespace(client_id="all", action="run", secret_dir=RD, secret_file=None,
                                                             run_cmd=[sys.executable, "-c", probe]))
check("[twin run] runs the command with both twins and their 0400 secrets in place (exit 0)",
      isinstance(r_, SystemExit) and r_.code == 0, (str(r_), out[-200:]))
check("[twin run] ... and afterwards no twin and no secret file is left", not any(M.find_client(kc, M.twin_id(c)) for c in DELEGATES)
      and not os.listdir(RD), os.listdir(RD))
r_, out = quiet(M.cmd_delegate_test_twin, argparse.Namespace(client_id="all", action="run", secret_dir=RD, secret_file=None,
                                                             run_cmd=[sys.executable, "-c", "import sys; sys.exit(7)"]))
check("[twin run] a failing command: its exit code is passed on, and the twins are still removed",
      isinstance(r_, SystemExit) and r_.code == 7 and not any(M.find_client(kc, M.twin_id(c)) for c in DELEGATES) and not os.listdir(RD))
base_ = M._authz_base(kc)
left = [p_["name"] for p_ in M.paged(kc, base_ + "/policy") if "--test" in p_["name"]]
check("[twin] removed: no twin client, no twin policy, guard silent", not any(M.find_client(kc, M.twin_id(c)) for c in DELEGATES)
      and not left and not M.test_twins_present(kc), left)
check("[twin] the live delegates were never touched: still client-jwt, no drift",
      all(kc.api("GET", "/clients/%s" % M.find_client(kc, cid)["id"])["clientAuthenticatorType"] == before_auth[cid] == "client-jwt"
          for cid in DELEGATES) and not M.delegate_auth_report(kc))
srv.shutdown()
n = sum(res); print("\n%d/%d passed" % (n, len(res))); sys.exit(0 if n == len(res) else 1)

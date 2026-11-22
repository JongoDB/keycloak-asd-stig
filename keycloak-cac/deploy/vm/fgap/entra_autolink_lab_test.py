#!/usr/bin/env python3
"""First Entra sign-in binds a pending invite, proved against a throwaway keycloak-cac container in
lab mode with a MOCK Entra: an OIDC issuer this script runs (RS256 ID tokens with oid, tid, preferred_username, email,
amr), so every claim is under the test's control.

  fgap/onboarding_lab.sh <image> <kas checkout> [report] entra_autolink_lab_test.py

Set-up as on the host: idp-admin.py roles-setup and `entra --auto-link-domain example.mil` (its flows, mappers and
the realm attribute), then the provider pointed at the mock. A user manager creates an Entra-type account through
stig-accounts (signIn entra: no password/OTP set-up, no mail, entra_pending). Then:
  happy path   the first Entra sign-in whose UPN is the invite's address binds entra_oid (admin event + STIG log line)
               and signs in; a later sign-in with the same identity works; the marker is gone
  refused      wrong tid; a UPN outside the domain; an e-mail-only match; an invite older than 7 days; an account with a
               credential; one with a card binding; one already bound; one not made by a delegate; a disabled one;
               two matching accounts; a DIFFERENT oid for a bound account (new link, and same link)
  unchanged    the manual binding (link-entra / invite --entra-oid) still signs in
  guard        expired and pending Entra invites reported
  stig-accounts  signIn entra only for the realm's Entra domain; no set-up mail; re-send refused
Each refusal: no token, and no entra_oid written.

  (AUTOMATION_SECRET in the environment) entra_autolink_lab_test.py --cacert root.crt --skill-scripts <kas scripts>
"""
import html, re, urllib.request
import argparse, base64, contextlib, http.server, importlib.machinery, importlib.util, io, json, os, secrets, socket
import ssl, sys, tempfile, threading, time, urllib.parse, uuid

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
sys.path.insert(0, a.skill_scripts); import e2e_check as E  # noqa: E402
REALM, PORT, HOST = a.realm, 8443, "localhost"
BASE = "https://%s:%d" % (HOST, PORT)
CTX = ssl.create_default_context(cafile=a.cacert)
TENANT = str(uuid.uuid4()); OTHER_TENANT = str(uuid.uuid4())
DOMAIN = "example.mil"
MOCK = "http://127.0.0.1:18090"; ISS = MOCK + "/v2.0"
# the card port: 8444 -> 8443 at the TCP level (TLS passes through untouched, as the host's port mapping 8444:8443)
CARD_PORT = 8444
PRESENT = "login-stig-present-card"           # the present-card page (stig-extensions' own template)
FORWARD = {"on": True}                        # off: the card port is unreachable (a network that only lets 443 out)
def _pipe(src, dst):
    try:
        while True:
            d = src.recv(65536)
            if not d:
                break
            dst.sendall(d)
    except OSError:
        pass
    finally:
        for x in (src, dst):
            try:
                x.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
def _forward():
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", CARD_PORT)); ls.listen(32)
    while True:
        c, _ = ls.accept()
        if not FORWARD["on"]:
            c.close(); continue
        up = socket.create_connection(("127.0.0.1", PORT))
        threading.Thread(target=_pipe, args=(c, up), daemon=True).start(); threading.Thread(target=_pipe, args=(up, c), daemon=True).start()
threading.Thread(target=_forward, daemon=True).start()
res = []
def check(n, ok, d=""):
    res.append(bool(ok)); print("%s  %-100s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

def raw(method, path, body=None, headers=None):
    import http.client
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=30)
    con = http.client.HTTPSConnection(HOST, PORT, context=CTX, timeout=60); con.sock = CTX.wrap_socket(sock, server_hostname=HOST)
    h = {"Host": "%s:%d" % (HOST, PORT)}; h.update(headers or {})
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode(); h["Content-Type"] = "application/json"
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

TMP = tempfile.mkdtemp(prefix="entra-")
M.REALM = REALM; M.CFG = dict(M.CFG, CAC_PUBLIC_URL=BASE)
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

# ------------------------------------------------------------------ the mock Entra (an OIDC issuer under our control)
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
pn = KEY.public_key().public_numbers()
JWK = {"kty": "RSA", "kid": "mock-1", "use": "sig", "alg": "RS256", "e": b64(pn.e.to_bytes(3, "big")), "n": b64(pn.n.to_bytes(256, "big"))}
NEXT = {}          # the identity the next authorization returns
CODES = {}

def id_token(ident, nonce, aud):
    now = int(time.time())
    claims = {"iss": ISS, "aud": aud, "sub": ident["sub"], "oid": ident["oid"], "tid": ident["tid"], "preferred_username": ident["upn"],
              "email": ident.get("email", ident["upn"]), "name": "Lab Person", "amr": ["pwd", "mfa"], "iat": now, "nbf": now, "exp": now + 600}
    if nonce:
        claims["nonce"] = nonce
    for k in ("idp", "acct"):                   # a guest's marks (absent for a member)
        if ident.get(k) is not None:
            claims[k] = ident[k]
    si = (b64(json.dumps({"alg": "RS256", "kid": "mock-1", "typ": "JWT"}).encode()) + "." + b64(json.dumps(claims).encode())).encode()
    return si.decode() + "." + b64(KEY.sign(si, padding.PKCS1v15(), hashes.SHA256()))

class Mock(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="application/json", loc=None):
        self.send_response(code)
        if loc:
            self.send_header("Location", loc)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q_ = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/v1.0/domains" and (self.headers.get("Authorization") or "").startswith("Bearer graph-"):
            return self._send(200, json.dumps({"value": [{"id": DOMAIN, "isVerified": True},
                                                         {"id": "unverified.example", "isVerified": False}]}).encode())
        if u.path == "/v2.0/keys":
            return self._send(200, json.dumps({"keys": [JWK]}).encode())
        if u.path == "/v2.0/authorize":
            code = secrets.token_urlsafe(16); CODES[code] = (dict(NEXT), q_.get("nonce"), q_.get("client_id"))
            return self._send(302, loc="%s?%s" % (q_["redirect_uri"], urllib.parse.urlencode({"code": code, "state": q_.get("state", "")})))
        return self._send(404)
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0); f = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))
        if self.path == "/%s/oauth2/v2.0/token" % TENANT and f.get("grant_type") == "client_credentials":    # Graph's token
            return self._send(200, json.dumps({"access_token": "graph-" + secrets.token_urlsafe(12), "token_type": "Bearer"}).encode())
        if urllib.parse.urlparse(self.path).path == "/v2.0/token" and f.get("code") in CODES:
            ident, nonce, aud = CODES.pop(f["code"])
            return self._send(200, json.dumps({"access_token": secrets.token_urlsafe(24), "token_type": "Bearer", "expires_in": 300,
                                               "id_token": id_token(ident, nonce, aud)}).encode())
        return self._send(400, b'{"error":"invalid_grant"}')
    def log_message(self, *x):
        pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 18090), Mock); threading.Thread(target=srv.serve_forever, daemon=True).start()

def point_at_mock():
    """The provider's endpoints -> the mock (Keycloak wants the client secret re-entered when they change)."""
    idp_ = kc.api("GET", "/identity-provider/instances/entra")
    idp_["config"].update({"issuer": ISS, "authorizationUrl": MOCK + "/v2.0/authorize", "tokenUrl": MOCK + "/v2.0/token",
                           "jwksUrl": MOCK + "/v2.0/keys", "logoutUrl": MOCK + "/v2.0/logout", "clientSecret": "mock-secret"})
    kc.api("PUT", "/identity-provider/instances/entra", idp_)

# ------------------------------------------------------------------ set-up: the realm as the tooling shapes it
r0 = kc.api("GET", "")
if not r0.get("eventsEnabled"):                 # login events stored, so the EDIPI check below reads real ones
    kc.api("PUT", "", {"eventsEnabled": True, "adminEventsEnabled": True, "adminEventsDetailsEnabled": True})
if r0.get("sslRequired") == "all":         # the mock speaks http on 127.0.0.1; "external" still requires TLS off-host
    kc.api("PUT", "", {"sslRequired": "external"})
at0 = dict(r0.get("attributes") or {}); at0["stig.accounts.email-domains"] = ".mil,%s" % DOMAIN; kc.api("PUT", "", {"attributes": at0})
for cid, roles in (("app-a", list(APP_A_ROLES) + ["partner-reader", "partner-auditor", "partner-lead", "contractor"]),):
    if not M.find_client(kc, cid):
        kc.api("POST", "/clients", {"clientId": cid, "protocol": "openid-connect", "publicClient": False, "standardFlowEnabled": True,
                                    "redirectUris": ["https://%s.lab.example/cb" % cid], "fullScopeAllowed": False})
    cu = M.client_uuid(kc, cid)
    for r in roles:
        kc.req("POST", "/admin/realms/%s/clients/%s/roles" % (REALM, cu), json.dumps({"name": r}).encode(), {"Content-Type": "application/json"})
r_, out = quiet(M.cmd_roles_setup, argparse.Namespace())
check("setup: roles-setup (declares entra_pending admin-only)", not isinstance(r_, BaseException)
      and any(x["name"] == M.ENTRA_PENDING for x in kc.api("GET", "/users/profile")["attributes"]), out[-160:] if isinstance(r_, BaseException) else "")
sec = os.path.join(TMP, "entra_secret"); open(sec, "w").write("mock-secret")
def entra_cmd(**kw):
    ns = dict(tenant=TENANT, client_id="mock-entra-client", secret_file=sec, enable=True, auto_link_domain=None, no_auto_link=False,
              domain_verified_by_operator=False); ns.update(kw)
    return quiet(M.cmd_entra, argparse.Namespace(**ns))
M.GRAPH_LOGIN, M.GRAPH_API = MOCK, "http://127.0.0.1:1"          # Graph unreachable
r_, out = entra_cmd(auto_link_domain=DOMAIN)
check("[domain] Graph unreachable, no acknowledgement: --auto-link-domain refused, nothing changed",
      isinstance(r_, SystemExit) and "domain-verified-by-operator" in str(r_) and M.current_autolink_domain(kc) is None, str(r_)[:120])
r_, out = entra_cmd(auto_link_domain=DOMAIN, domain_verified_by_operator=True)
check("[domain] ... with --domain-verified-by-operator: accepted (the operator's word)", not isinstance(r_, BaseException)
      and "the operator's word" in out and M.current_autolink_domain(kc) == DOMAIN, out[-160:])
M.GRAPH_API = MOCK                                                 # Graph answers
r_, out = entra_cmd(auto_link_domain="unverified.example", domain_verified_by_operator=True)
check("[domain] Graph says the domain is NOT verified: refused even with the acknowledgement, binding unchanged",
      isinstance(r_, SystemExit) and "not a verified domain" in str(r_) and M.current_autolink_domain(kc) == DOMAIN, str(r_)[:120])
r_, out = entra_cmd(auto_link_domain=DOMAIN)
check("setup: idp-admin.py entra --auto-link-domain: flows, mappers (UPN included), realm attribute", not isinstance(r_, BaseException)
      and "ON for @%s" % DOMAIN in out and "(Graph)" in out and kc.api("GET", "").get("attributes", {}).get("stig.accounts.entra-domain") == DOMAIN
      and any(m["name"] == "entra vouched upn" for m in kc.api("GET", "/identity-provider/instances/entra/mappers")), out[-200:])
check("setup: the first-broker step carries the tenant (from the command line, i.e. config) and the pending-invite domain",
      M.current_autolink_domain(kc) == DOMAIN)
point_at_mock()
r_, out = entra_cmd()
check("setup: a re-run WITHOUT the flag keeps the binding on (never switched off silently)", M.current_autolink_domain(kc) == DOMAIN, out[-120:])
point_at_mock()                # (the re-run reset the URLs to Entra's)

# ------------------------------------------------------------------ sign-in through the (mock) Entra
ACCT = "%s/realms/%s/account/" % (BASE, REALM)
def entra_sign_in(ident):
    """(token or None, pages) of a sign-in to the account console through the provider, as the identity `ident`."""
    NEXT.clear(); NEXT.update(ident)
    fl = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client="account-console", redirect=ACCT, admin_url=None, client_secret=None, cacert=a.cacert))
    b = E.Browser(a.cacert); url, ver = fl.auth_url()
    try:
        k, u, p = b.go(url, None, ACCT)
        # the sign-in page's "Microsoft Entra ID" button, as a person clicks it
        m_ = re.search(r'href="([^"]*/broker/entra/login[^"]*)"', p or "")
        if k != "page" or not m_:
            return None, ["no Entra button on the sign-in page (%s)" % E.page_id(p or "")]
        k, u, p = b.go(urllib.parse.urljoin(u, html.unescape(m_.group(1))), None, ACCT)
        final, seen = fl.finish(b, k, u, p, {})
    except Exception as e:      # noqa: BLE001
        return None, ["exception: %s" % e]
    if not final or "code=" not in final:
        return None, seen
    return fl.token(urllib.parse.parse_qs(urllib.parse.urlparse(final).query)["code"][0], ver), seen

def entra_then_card(ident_, cert=None, skip=False):
    """An Entra sign-in that may meet "present your card" (the x509 confirmation page of the required action): the person
    then presents `cert` (a mock card, /t/<name>.crt|.key) on the same session, or skips. (token or None, pages)."""
    NEXT.clear(); NEXT.update(ident_)
    fl = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client="account-console", redirect=ACCT, admin_url=None, client_secret=None, cacert=a.cacert))
    b = E.Browser(a.cacert); url, ver = fl.auth_url(); seen = []
    try:
        k, u, p = b.go(url, None, ACCT)
        m_ = re.search(r'href="([^"]*/broker/entra/login[^"]*)"', p or "")
        if k != "page" or not m_:
            return None, ["no Entra button"]
        k, u, p = b.go(urllib.parse.urljoin(u, html.unescape(m_.group(1))), None, ACCT)
        for _ in range(8):
            if k == "redirect":
                break
            if k == "error":
                seen.append("error:" + E.error_text(p)); return None, seen
            pid = E.page_id(p); seen.append(pid)
            if pid == "login-terms":
                act, f = E.form(p); f["accept"] = "OK"; k, u, p = b.go(act, f, ACCT)
            elif pid == PRESENT:
                if skip or not cert:                        # "Continue without the card": this page's own origin
                    act, f = E.form(p, "stig-card-ignore"); f["cancel"] = "Continue without the card"     # the clicked button
                    k, u, p = b.go(act, f, ACCT)
                else:                                       # the same session, now with the card in the reader
                    act, f = E.form(p, "stig-card-form"); f["login"] = "Sign in with my CAC"
                    bc = E.Browser(a.cacert, "/t/%s.crt" % cert, "/t/%s.key" % cert)
                    bc.op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=bc.ctx),
                                                        urllib.request.HTTPCookieProcessor(b.jar), E.Stop())
                    k, u, p = bc.go(act, f, ACCT); b = bc
            else:
                seen.append("stuck:" + E.error_text(p)); return None, seen
    except Exception as e:      # noqa: BLE001
        return None, seen + ["exception: %s" % e]
    if k != "redirect" or "code=" not in u:
        return None, seen
    return fl.token(urllib.parse.parse_qs(urllib.parse.urlparse(u).query)["code"][0], ver), seen

def ident(upn, oid=None, tid=None, email=None, sub=None, idp=None, acct=None):
    oid = oid or str(uuid.uuid4())
    return {"upn": upn, "oid": oid, "tid": tid or TENANT, "email": email or upn, "sub": sub or ("sub-" + oid), "idp": idp, "acct": acct}

def acct(username, email, *, created_by=True, marker_days_ago=1, pending=True, enabled=True, oid=None, card=None, password=False):
    at = {}
    if created_by:
        at[M.CREATED_BY] = ["lab.um %d" % int((time.time() - marker_days_ago * 86400) * 1000)]
    if pending:
        at[M.ENTRA_PENDING] = [M.ENTRA_PENDING_VALUE]
    if oid:
        at["entra_oid"] = [oid]
    if card:
        at["cac_edipi"] = [card]
    rep = {"username": username, "email": email, "firstName": "Lab", "lastName": "Entra", "enabled": enabled, "emailVerified": True,
           "attributes": at, "requiredActions": []}
    if password:
        rep["credentials"] = [{"type": "password", "value": "Lab!9" + secrets.token_hex(10) + "Qz", "temporary": False}]
    kc.api("POST", "/users", rep)
    u = M.user(kc, username)
    kc.api("PUT", "/users/%s/groups/%s" % (u["id"], M.group_by_path(kc, "/app-a/viewer")["id"]))
    return u

def oid_of(username):
    return ((kc.api("GET", "/users/%s" % M.user(kc, username)["id"]).get("attributes") or {}).get("entra_oid") or [None])[0]

def find_user(name):
    return next(iter(x for x in kc.api("GET", "/users?exact=true&username=%s" % urllib.parse.quote(name)) or [] if x["username"] == name), None)

# ------------------------------------------------------------------ stig-accounts: an Entra-type invite by a user manager
um_name = "lab.um.%s" % "".join(secrets.choice("abcdefghjkmnpqrstuvwxyz") for _ in range(6)); um_pw = "Lab!9%sQz" % secrets.token_hex(10); um_ctx = {}
kc.api("POST", "/users", {"username": um_name, "email": "%s@lab.test.mil" % um_name, "firstName": "Lab", "lastName": "Um", "enabled": True,
                          "emailVerified": True, "credentials": [{"type": "password", "value": um_pw, "temporary": False}]})
def pw_sign_in(client, redirect, ctx):
    fl = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client=client, redirect=redirect, admin_url=None, client_secret=None, cacert=a.cacert))
    b = E.Browser(a.cacert); url, ver = fl.auth_url(); k, u, p = b.go(url, None, redirect)
    act, f = E.form(p, "kc-form-login"); f.update({"username": um_name, "password": um_pw}); k, u, p = b.go(act, f, redirect)
    final, seen = fl.finish(b, k, u, p, ctx)
    return fl.token(urllib.parse.parse_qs(urllib.parse.urlparse(final).query)["code"][0], ver) if final and "code=" in final else None
pw_sign_in("account-console", ACCT, um_ctx)                    # TOTP enrolled while an ordinary account
quiet(M.apply_roles, kc, M.user(kc, um_name), ["idp-user-manager"], M.load_state() or M.new_state())
time.sleep(31)
umt = pw_sign_in("security-admin-console", "%s/admin/%s/console/" % (BASE, REALM), um_ctx)
check("setup: a user manager (password + TOTP, allowlisted)", umt is not None)
def um(method, path, body=None):
    """The user manager's own admin-API call (its token refreshed when it expires)."""
    global umt
    for _ in range(2):
        st, t = raw(method, "/admin/realms/%s%s" % (REALM, path), body, {"Authorization": "Bearer " + umt["access_token"]})
        if st != 401:
            break
        st2, t2 = raw("POST", "/realms/%s/protocol/openid-connect/token" % REALM, urllib.parse.urlencode({
            "grant_type": "refresh_token", "client_id": "security-admin-console", "refresh_token": umt["refresh_token"]}).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"})
        if st2 == 200:
            umt = json.loads(t2)
    try:
        return st, json.loads(t) if t.strip()[:1] in "{[" else t
    except ValueError:
        return st, t
def accounts(body):
    return um("POST", "/stig-accounts/users", body)
st, body = accounts({"username": "alice.lab", "email": "alice.lab@%s" % DOMAIN, "firstName": "Alice", "lastName": "Lab",
                     "group": "/app-a/viewer", "signIn": "entra"})
alice = M.user(kc, "alice.lab"); ar = kc.api("GET", "/users/%s" % alice["id"]) if alice else {}
check("[stig-accounts] signIn entra: 201, setupEmail none", st == 201 and body.get("setupEmail") == "none" and body.get("signIn") == "entra", (st, body))
check("[stig-accounts] ... no password or OTP set-up (terms only), entra_pending set, stig_created_by set",
      ar.get("requiredActions") == ["TERMS_AND_CONDITIONS"] and (ar.get("attributes") or {}).get(M.ENTRA_PENDING)
      and (ar.get("attributes") or {}).get(M.CREATED_BY), (ar.get("requiredActions"), sorted((ar.get("attributes") or {}).keys())))
st, body = accounts({"username": "milo.lab", "email": "milo.lab@unit.example.mil", "firstName": "Milo", "lastName": "Lab",
                     "group": "/app-a/viewer", "signIn": "entra"})
check("[stig-accounts] signIn entra for an address outside the realm's Entra domain: 403", st == 403, (st, body))
st, body = accounts({"username": "bad.lab", "email": "bad.lab@%s" % DOMAIN, "firstName": "Bad", "lastName": "Lab",
                     "group": "/app-a/viewer", "signIn": "fido"})
check("[stig-accounts] an unknown signIn: 400", st == 400, (st, body))
# app-a's request shapes (its MR 39): each refusal below is the one its simulation expects
eb = lambda u, **kw: dict({"username": u, "email": "%s@%s" % (u, DOMAIN), "firstName": "Shape", "lastName": "Lab",
                           "group": "/app-a/viewer"}, **kw)
for name_, kw, want in (("an empty list", {"signIn": []}, 400), ("a duplicate method", {"signIn": ["entra", "entra"]}, 400),
                        ("password in the list", {"signIn": ["password", "entra"]}, 400), ("[password] alone", {"signIn": ["password"]}, 400),
                        ("cac without an edipi", {"signIn": "cac"}, 400), ("both without an edipi", {"signIn": ["entra", "cac"]}, 400),
                        ("entra WITH a lifespan (no set-up mail to time)", {"signIn": "entra", "lifespan": 43200}, 400)):
    st, body = accounts(eb("shape.lab", **kw))
    check("[shape] %s: %d" % (name_, want), st == want and find_user("shape.lab") is None, (st, body))
st, t = raw("POST", "/admin/realms/%s/stig-accounts/users/%s/setup-email" % (REALM, alice["id"]), None, {"Authorization": "Bearer " + umt["access_token"]})
check("[stig-accounts] re-send set-up mail to an Entra-type account: 409 (nothing to set up)", st == 409, (st, t[:100]))

# ------------------------------------------------------------------ the happy path
A_OID = str(uuid.uuid4()); since = time.time()
# (the provider's claim filter, unchanged, admits only a lower-case @example.mil domain; the local part's case is free)
tok, seen = entra_sign_in(ident("Alice.Lab@%s" % DOMAIN, oid=A_OID))
check("[happy] the first Entra sign-in whose UPN is the invite's address (local part case-insensitive) signs in", tok is not None, seen)
check("[happy] ... and binds entra_oid to the vouched oid; entra_pending removed", oid_of("alice.lab") == A_OID
      and M.ENTRA_PENDING not in (kc.api("GET", "/users/%s" % alice["id"]).get("attributes") or {}))
evs = kc.api("GET", "/admin-events?resourcePath=users/%s&max=50" % alice["id"]) or []
bound_ev = [e for e in evs if e.get("operationType") == "UPDATE" and "entra_oid" in (e.get("representation") or "")]
check("[happy] ... audited: an admin event (UPDATE USER, attributed to the account, with the binding)", bound_ev
      and bound_ev[0]["authDetails"].get("userId") == alice["id"], [e.get("operationType") for e in evs][:5])
tok2, seen2 = entra_sign_in(ident("alice.lab@%s" % DOMAIN, oid=A_OID))
check("[happy] a later sign-in with the same identity works", tok2 is not None, seen2)
evs2 = kc.api("GET", "/admin-events?resourcePath=users/%s&max=50" % alice["id"]) or []
check("[happy] ... and does NOT re-run the binding (still one binding event; the marker stays gone)",
      len([e for e in evs2 if e.get("operationType") == "UPDATE" and "entra_oid" in (e.get("representation") or "")]) == 1
      and M.ENTRA_PENDING not in (kc.api("GET", "/users/%s" % alice["id"]).get("attributes") or {}))

# ------------------------------------------------------------------ refusals: no token, nothing written
def refused(name, ident_, username=None):
    tok_, seen_ = entra_sign_in(ident_)
    ok_ = tok_ is None and (username is None or oid_of(username) in (None, ident_.get("_keep")))
    check("[refused] %s" % name, ok_, seen_[-2:] if seen_ else "")

refused("a DIFFERENT oid for the bound account (new link): refused, the binding unchanged",
        dict(ident("alice.lab@%s" % DOMAIN), _keep=A_OID), "alice.lab")
refused("a different oid for the bound account on its EXISTING link (same sub): refused by the post-broker match",
        dict(ident("alice.lab@%s" % DOMAIN, oid=str(uuid.uuid4()), sub="sub-" + A_OID), _keep=A_OID), "alice.lab")
st, body = accounts({"username": "paula.lab", "email": "paula.lab@%s" % DOMAIN, "firstName": "Paula", "lastName": "Lab",
                     "group": "/app-a/viewer", "lifespan": 43200})   # a PASSWORD-type invite (app-a's shape)
pr = kc.api("GET", "/users/%s" % M.user(kc, "paula.lab")["id"]) if st == 201 else {}
check("[setup] a password-type invite by the user manager (stig_created_by, no entra_pending, password/TOTP set-up owed)",
      st == 201 and (pr.get("attributes") or {}).get(M.CREATED_BY) and M.ENTRA_PENDING not in (pr.get("attributes") or {}), (st, body))
refused("a PASSWORD-type invite (made by a user manager, unused) with a matching UPN", ident("paula.lab@%s" % DOMAIN), "paula.lab")
acct("pete.lab", "pete.lab@%s" % DOMAIN, pending=False)
refused("a delegate-made account without the pending marker", ident("pete.lab@%s" % DOMAIN), "pete.lab")
acct("gus.lab", "gus.lab@%s" % DOMAIN)
refused("a B2B GUEST (idp = its home tenant) whose home preferred_username is the invite's address",
        ident("gus.lab@%s" % DOMAIN, idp="https://sts.windows.net/%s/" % OTHER_TENANT), "gus.lab")
refused("an e-mail one-time-passcode guest (idp mail)", ident("gus.lab@%s" % DOMAIN, idp="mail"), "gus.lab")
refused("a Microsoft-account guest (idp live.com)", ident("gus.lab@%s" % DOMAIN, idp="live.com"), "gus.lab")
refused("acct = 1 (a guest), no idp claim", ident("gus.lab@%s" % DOMAIN, acct=1), "gus.lab")
xm = {"name": "lab second upn writer", "identityProviderAlias": "entra", "identityProviderMapper": "oidc-user-attribute-idp-mapper",
      "config": {"claim": "email", "user.attribute": "entra_vouched_upn", "syncMode": "IMPORT"}}
kc.api("POST", "/identity-provider/instances/entra/mappers", xm)
refused("a second mapper writing entra_vouched_upn (from the e-mail claim): no binding at all", ident("gus.lab@%s" % DOMAIN), "gus.lab")
for m_ in kc.api("GET", "/identity-provider/instances/entra/mappers"):
    if m_["name"] == xm["name"]:
        kc.api("DELETE", "/identity-provider/instances/entra/mappers/%s" % m_["id"])
im = [m_ for m_ in kc.api("GET", "/identity-provider/instances/entra/mappers") if m_["name"] == "entra vouched idp"][0]
kc.api("DELETE", "/identity-provider/instances/entra/mappers/%s" % im["id"])
refused("no mapper for the idp claim (a guest would pass unseen): no binding at all", ident("gus.lab@%s" % DOMAIN), "gus.lab")
kc.api("POST", "/identity-provider/instances/entra/mappers", {k: v for k, v in im.items() if k != "id"})
acct("bob.lab", "bob.lab@%s" % DOMAIN)
refused("wrong tid (another tenant), UPN otherwise right", ident("bob.lab@%s" % DOMAIN, tid=OTHER_TENANT), "bob.lab")
refused("an e-mail-only match (UPN another person's, the e-mail claim the invite's)",
        ident("robert.other@%s" % DOMAIN, email="bob.lab@%s" % DOMAIN), "bob.lab")
acct("x.lab", "x.lab@other.example")
refused("a UPN outside the domain", ident("x.lab@other.example"), "x.lab")
acct("carol.lab", "carol.lab@%s" % DOMAIN, marker_days_ago=8)
refused("an invite older than 7 days", ident("carol.lab@%s" % DOMAIN), "carol.lab")
acct("dave.lab", "dave.lab@%s" % DOMAIN, password=True)
refused("an account that already has a credential", ident("dave.lab@%s" % DOMAIN), "dave.lab")
acct("erin.lab", "erin.lab@%s" % DOMAIN, card="9%09d" % secrets.randbelow(10 ** 9))
refused("an account with a card binding", ident("erin.lab@%s" % DOMAIN), "erin.lab")
F_OID = str(uuid.uuid4()); acct("frank.lab", "frank.lab@%s" % DOMAIN, oid=F_OID)
refused("an account already bound to another oid", dict(ident("frank.lab@%s" % DOMAIN), _keep=F_OID), "frank.lab")
acct("gina.lab", "gina.lab@%s" % DOMAIN, created_by=False)
refused("an account not created by a delegate (no stig_created_by)", ident("gina.lab@%s" % DOMAIN), "gina.lab")
acct("hank.lab", "hank.lab@%s" % DOMAIN, enabled=False)
refused("a disabled account", ident("hank.lab@%s" % DOMAIN), "hank.lab")
acct("ivy.one", "ivy@%s" % DOMAIN); acct("ivy@%s" % DOMAIN, "ivy.two@lab.test.mil")
refused("two accounts match (one by e-mail, one by username)", ident("ivy@%s" % DOMAIN), "ivy.one")
check("[refused] ... and the other one too", oid_of("ivy@%s" % DOMAIN) is None)
acct("jill.lab", "jill.lab@%s" % DOMAIN)
refused("nobody invited under that UPN", ident("nobody.lab@%s" % DOMAIN))

# ------------------------------------------------------------------ the markers are not the delegate's to write
pu = M.user(kc, "jill.lab")
st, urep = um("GET", "/users/%s" % pu["id"])
# (what app-a's list can read with the same rights: entra_pending and requiredActions, not the concealed bindings)
check("[visibility] a delegate reads entra_pending and requiredActions (to hide Re-send), never stig_created_by / bindings",
      st == 200 and (urep.get("attributes") or {}).get(M.ENTRA_PENDING) == [M.ENTRA_PENDING_VALUE] and "requiredActions" in urep
      and M.CREATED_BY not in (urep.get("attributes") or {}), (st, sorted((urep.get("attributes") or {}).keys()) if isinstance(urep, dict) else urep))
mk = acct("mark.lab", "mark.lab@%s" % DOMAIN, created_by=False)          # nothing concealed on it: each PUT changes ONE thing
st, t = um("PUT", "/users/%s" % mk["id"], {"firstName": "Marked"})
check("[markers] a user manager cannot PUT a user through the plain admin API at all (403: no manage on users)", st == 403, (st, str(t)[:80]))
# give this user manager fine-grained `manage` on this ONE account, so its PUT gets past the permission check and
# meets the user profile: the markers and the card must still be refused there (cac-identity-guard, not realm-admin)
ap_ = kc.api("GET", "/clients?clientId=admin-permissions")[0]["id"]; base_rs = "/clients/%s/authz/resource-server" % ap_
kc.api("POST", base_rs + "/policy/user", {"name": "lab um", "logic": "POSITIVE", "users": [M.user(kc, um_name)["id"]]})
pol_ = [x for x in kc.api("GET", base_rs + "/policy?name=lab%20um") if x["name"] == "lab um"][0]["id"]
kc.api("POST", base_rs + "/permission/scope", {"name": "lab um manages mark", "resourceType": "Users", "resources": [mk["id"]],
                                                "scopes": ["view", "manage"], "policies": [pol_], "decisionStrategy": "UNANIMOUS"})
st, mrep = um("GET", "/users/%s" % mk["id"])
base_ = {k: mrep[k] for k in ("username", "email", "firstName", "lastName", "enabled") if k in mrep}
st, t = um("PUT", "/users/%s" % mk["id"], dict(base_, firstName="Marked", attributes=dict(mrep.get("attributes") or {})))
check("[markers] control: with `manage` on it, the user manager may change the account's first name (204)", st == 204, (st, str(t)[:120]))
for attr, val in ((M.ENTRA_PENDING, "x"), (M.CREATED_BY, "lab.um 1"), ("cac_edipi", "7777777777")):
    st, t = um("PUT", "/users/%s" % mk["id"], dict(base_, firstName="Marked", attributes=dict(mrep.get("attributes") or {}, **{attr: [val]})))
    check("[markers] a user manager's PUT of %s through the plain admin API: 400" % attr, st == 400, (st, str(t)[:120]))
ma = kc.api("GET", "/users/%s" % mk["id"]).get("attributes") or {}
check("[markers] ... nothing was written", ma.get(M.ENTRA_PENDING) == [M.ENTRA_PENDING_VALUE] and not ma.get("cac_edipi")
      and not ma.get(M.CREATED_BY), ma)

# ------------------------------------------------------------------ card accounts: stig-accounts signIn cac

CARD = "8888888888"            # the mock PKI's "unmapped" card: no lab account carries it
cac_body = lambda u, e, **kw: dict({"username": u, "email": e, "firstName": "Card", "lastName": "Lab",
                                    "group": "/app-a/viewer", "signIn": "cac", "edipi": CARD}, **kw)
st, body = accounts(cac_body("cara.lab", "cara.lab@lab.test.mil"))
check("[cac] card accounts OFF (no stig.accounts.card-attribute): 403", st == 403 and find_user("cara.lab") is None, (st, body))
xe = [e for e in kc.api("GET", "/authentication/flows/%s/executions" % urllib.parse.quote(kc.api("GET", "")["browserFlow"]))
      if e.get("providerId") in ("stig-x509-client-username-form", "auth-x509-client-username-form") and e.get("authenticationConfig")][0]
xc = kc.api("GET", "/authentication/config/%s" % xe["authenticationConfig"])
xc2 = json.loads(json.dumps(xc)); xc2["config"]["x509-cert-auth.mapper-selection.user-attribute-name"] = "cac_upn"
kc.api("PUT", "/authentication/config/%s" % xc["id"], xc2)
r_, out = quiet(M.cmd_card_accounts, argparse.Namespace(state="on", attribute="cac_edipi"))
check("[cac] card-accounts on REFUSES when the X.509 step maps cards by another attribute", isinstance(r_, SystemExit) and "REFUSED" in str(r_), str(r_)[:150])
kc.api("PUT", "/authentication/config/%s" % xc["id"], xc)
r_, out = quiet(M.cmd_card_accounts, argparse.Namespace(state="on", attribute="cac_edipi"))
check("[cac] idp-admin.py card-accounts on", "ON" in out, out[-100:])
st, body = accounts(cac_body("cara.lab", "cara.lab@lab.test.mil", edipi="12345"))
check("[cac] a malformed EDIPI (5 digits): 400", st == 400, (st, body))
st, body = accounts(cac_body("cara.lab", "cara.lab@lab.test.mil", edipi="12345678x0"))
check("[cac] a malformed EDIPI (a letter): 400", st == 400, (st, body))
st, body = accounts(cac_body("cara.lab", "cara.lab@lab.test.mil", signIn="password"))
check("[cac] an EDIPI with a password-type create: 400", st == 400, (st, body))
st, body = accounts(cac_body("cara.lab", "cara.lab@lab.test.mil"))
cara = find_user("cara.lab"); cr = kc.api("GET", "/users/%s" % cara["id"]) if cara else {}
check("[cac] create signIn cac: 201, setupEmail none, the card masked in the answer (never the EDIPI)",
      st == 201 and body.get("setupEmail") == "none" and body.get("card") == "******8888" and CARD not in json.dumps(body), (st, body))
check("[cac] ... cac_edipi bound server-side; terms only (no password/OTP set-up); stig_created_by; no entra_pending",
      (cr.get("attributes") or {}).get("cac_edipi") == [CARD] and cr.get("requiredActions") == ["TERMS_AND_CONDITIONS"]
      and (cr.get("attributes") or {}).get(M.CREATED_BY) and M.ENTRA_PENDING not in (cr.get("attributes") or {}),
      (cr.get("requiredActions"), sorted((cr.get("attributes") or {}).keys())))
evs = kc.api("GET", "/admin-events?resourcePath=users/%s&max=20" % cara["id"]) if cara else []
check("[cac] ... the admin event carries the masked card only", evs and all(CARD not in (e.get("representation") or "") for e in evs)
      and any("******8888" in (e.get("representation") or "") for e in evs))
if os.path.exists("/t/unmapped.crt"):
    fl = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client="account-console", redirect=ACCT, admin_url=None, client_secret=None, cacert=a.cacert))
    b_, final, seen, _, ver = E.cac_login(fl, "/t/unmapped.crt", "/t/unmapped.key")
    tk = fl.token(urllib.parse.parse_qs(urllib.parse.urlparse(final).query)["code"][0], ver) if final and "code=" in final else None
    check("[cac] the CAC sign-in with that card reaches the new account", tk is not None
          and E.claims(tk["access_token"]).get("preferred_username") == "cara.lab", seen)
else:
    check("[cac] the CAC sign-in with that card reaches the new account (mock card missing)", False)
st, body = accounts(cac_body("cara.two", "cara.two@lab.test.mil"))
check("[cac] the same EDIPI again (a new account): 409, generic", st == 409 and body == {"error": "username, e-mail address or card already in use"}
      and find_user("cara.two") is None, (st, body))
st, body = accounts(cac_body("john.other", "john.other@lab.test.mil", edipi="1234567890"))
check("[cac] the EDIPI of an existing (operator-made) card account: 409, generic", st == 409 and find_user("john.other") is None, (st, body))
st, body = accounts(cac_body("jill.lab", "jill.lab@%s" % DOMAIN, edipi="7777777777"))
check("[cac] onto an EXISTING account (its username/e-mail): 409 - a card is never bound to an existing account",
      st == 409 and not (kc.api("GET", "/users/%s" % pu["id"]).get("attributes") or {}).get("cac_edipi")
      and not kc.api("GET", "/users?q=cac_edipi:7777777777"), (st, body))
st, t = um("POST", "/stig-accounts/users/%s/setup-email" % cara["id"]) if cara else (0, "")
check("[cac] re-send set-up mail to a card account: 409", st == 409, (st, t))

# ------------------------------------------------------------------ BOTH on one account (the common case)
# An Entra + card invite only NAMES the card (cac_edipi_pending). After the first Entra sign-in the person must present
# THAT card; a delegate naming their own card for someone else's account gets nothing. Cards in the mock PKI:
# "unmapped" 8888888888 (free once cara.lab is gone), "roe.jane" 2345678901 (bound to the lab's roe.jane).
kc.api("DELETE", "/users/%s" % cara["id"])
attrs = lambda u_: (kc.api("GET", "/users/%s" % u_["id"]).get("attributes") or {}) if u_ else {}
def card_sign_in(cert="unmapped"):
    fl_ = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client="account-console", redirect=ACCT, admin_url=None, client_secret=None, cacert=a.cacert))
    _, fin, seen_, _, ver_ = E.cac_login(fl_, "/t/%s.crt" % cert, "/t/%s.key" % cert)
    tk_ = fl_.token(urllib.parse.parse_qs(urllib.parse.urlparse(fin).query)["code"][0], ver_) if fin and "code=" in fin else None
    return (E.claims(tk_["access_token"]).get("preferred_username") if tk_ else None), seen_

# the attack: a user manager names THEIR OWN card (8888888888) in a victim's Entra + card invite
st, body = accounts(cac_body("vic.lab", "vic.lab@%s" % DOMAIN, signIn=["entra", "cac"]))
vic = find_user("vic.lab"); va = attrs(vic)
check("[both] create [entra, cac]: 201; the card is NOT bound, only named (cac_edipi_pending), stig_signin_methods cac,entra",
      st == 201 and body.get("signIn") == ["cac", "entra"] and not va.get("cac_edipi") and va.get("cac_edipi_pending") == [CARD]
      and va.get(M.ENTRA_PENDING) == [M.ENTRA_PENDING_VALUE] and va.get("stig_signin_methods") == ["cac,entra"], (st, body, sorted(va)))
st, vrep = um("GET", "/users/%s" % vic["id"]) if vic else (0, {})
check("[both] a delegate sees stig_signin_methods, never the named card", st == 200 and (vrep.get("attributes") or {}).get("stig_signin_methods") == ["cac,entra"]
      and "cac_edipi_pending" not in (vrep.get("attributes") or {}), sorted((vrep.get("attributes") or {}).keys()))
st, body = accounts(cac_body("res.lab", "res.lab@%s" % DOMAIN, signIn=["entra", "cac"]))
check("[reserve] the named card is RESERVED: another [entra, cac] create naming it -> 409 (generic)", st == 409 and body == {"error": "username, e-mail address or card already in use"}, (st, body))
st, body = accounts(cac_body("res.lab", "res.lab@lab.test.mil"))
check("[reserve] ... and a card-only create with it -> 409", st == 409, (st, body))
who, seen = card_sign_in("unmapped")
check("[both] the named card opens NOTHING before it is presented by the account holder", who is None, seen[-1:])
who, seen = card_sign_in("revoked")
check("[log] a revoked card is refused (validation failure path)", who is None, seen[-1:])
V_OID = str(uuid.uuid4())
tok, seen = entra_then_card(ident("vic.lab@%s" % DOMAIN, oid=V_OID), cert="roe.jane")
va = attrs(vic)
check("[attack] the victim's Entra links; then asked for the card, the victim presents THEIR OWN card: mismatch refused",
      tok is not None and oid_of("vic.lab") == V_OID and PRESENT in seen and not va.get("cac_edipi")
      and not va.get("cac_edipi_pending"), (seen, sorted(va)))
who, seen = card_sign_in("unmapped")
check("[attack] the manager's card CANNOT sign in (to the victim's account or any)", who is None, seen[-1:])
evs = kc.api("GET", "/admin-events?resourcePath=users/%s&max=20" % vic["id"]) or []
check("[attack] the refusal is audited (admin event, masked card)", any("card refused" in (e.get("representation") or "") and "******8888" in (e.get("representation") or "")
                                                                         and CARD not in (e.get("representation") or "") for e in evs))
kc.api("POST", "/users/%s/logout" % vic["id"])
tok, seen = entra_sign_in(ident("vic.lab@%s" % DOMAIN, oid=V_OID))
check("[attack] ... the victim stays Entra-only: signs in with Entra, no card prompt", tok is not None and PRESENT not in seen, seen)

# the honest flow: the card is free again (the refused invite released it)
st, body = accounts(cac_body("dana.lab", "dana.lab@%s" % DOMAIN, signIn=["entra", "cac"]))
dana = find_user("dana.lab")
check("[reserve] a refused invite releases its card: a new [entra, cac] create naming it -> 201", st == 201 and dana is not None, (st, body))
D_OID = str(uuid.uuid4())
tok, seen = entra_then_card(ident("dana.lab@%s" % DOMAIN, oid=D_OID), cert="unmapped")
da = attrs(dana)
check("[honest] Entra links, then the person presents the card the invite named: bound, pending cleared",
      tok is not None and oid_of("dana.lab") == D_OID and da.get("cac_edipi") == [CARD] and not da.get("cac_edipi_pending"), (seen, sorted(da)))
kc.api("POST", "/users/%s/logout" % dana["id"])
who, seen = card_sign_in("unmapped")
check("[honest] afterwards the CAC signs in", who == "dana.lab", seen)
kc.api("POST", "/users/%s/logout" % dana["id"])
tok, seen = entra_sign_in(ident("dana.lab@%s" % DOMAIN, oid=D_OID))
check("[honest] ... and Entra too, with no card prompt", tok is not None and PRESENT not in seen, seen)

st, body = accounts(cac_body("dup.lab", "dup.lab@%s" % DOMAIN, signIn=["entra", "cac"], edipi="1234567890"))
check("[dup] [entra, cac] naming a card already bound (doe.john's): 409 (generic)", st == 409 and find_user("dup.lab") is None, (st, body))

# skip, then expiry
st, body = accounts(cac_body("sam.lab", "sam.lab@%s" % DOMAIN, signIn=["cac", "entra"], edipi="6666666666"))
sam = find_user("sam.lab")
check("[skip] the other order [cac, entra] is accepted too", st == 201 and sam is not None, (st, body))
S_OID = str(uuid.uuid4())
tok, seen = entra_then_card(ident("sam.lab@%s" % DOMAIN, oid=S_OID), skip=True)
check("[skip] no card reader: the person skips and is signed in with Entra; the named card stays pending",
      tok is not None and PRESENT in seen and attrs(sam).get("cac_edipi_pending") == ["6666666666"] and not attrs(sam).get("cac_edipi"), seen)
kc.api("POST", "/users/%s/logout" % sam["id"])
tok, seen = entra_then_card(ident("sam.lab@%s" % DOMAIN, oid=S_OID), skip=True)
check("[skip] ... asked again at the next sign-in while the invite is live", tok is not None and PRESENT in seen, seen)
srep = kc.api("GET", "/users/%s" % sam["id"]); srep["attributes"][M.CREATED_BY] = ["lab.um %d" % int((time.time() - 8 * 86400) * 1000)]
kc.api("PUT", "/users/%s" % sam["id"], srep)                       # the invite is now 8 days old
kc.api("POST", "/users/%s/logout" % sam["id"])
tok, seen = entra_then_card(ident("sam.lab@%s" % DOMAIN, oid=S_OID), cert="unmapped")
check("[expiry] after 7 days: no card prompt, nothing bound", tok is not None and PRESENT not in seen and not attrs(sam).get("cac_edipi"), seen)
ex_, pe_ = M.pending_cards(kc)
check("[expiry] guard reports STIG-CARD-PENDING-EXPIRED for it", any("STIG-CARD-PENDING-EXPIRED user=sam.lab" in l for l in ex_), ex_)
st, body = accounts(cac_body("sam.two", "sam.two@lab.test.mil", edipi="6666666666"))
check("[expiry] an expired named card is free again: a create naming it -> 201", st == 201, (st, body))

# signed into before the Entra link: never linked afterwards
st, body = accounts({"username": "ses.lab", "email": "ses.lab@%s" % DOMAIN, "firstName": "Ses", "lastName": "Lab",
                     "group": "/app-a/viewer", "signIn": "entra"})
ses = find_user("ses.lab")
kc.req("POST", "/admin/realms/%s/users/%s/impersonation" % (REALM, ses["id"]))     # a session on the account (as any sign-in makes)
check("[session] (the account now has a session)", len(kc.api("GET", "/users/%s/sessions" % ses["id"]) or []) > 0)
refused("an Entra invite that has already been signed into (a session exists) before the Entra link", ident("ses.lab@%s" % DOMAIN), "ses.lab")

# ------------------------------------------------------------------ [tls] a REAL client-certificate handshake, and the reuse case
# What failed live (2026-11-22): the browser's connection to host:443 had been made without a certificate (Entra sign-in);
# it was kept (HTTP/2) for the present-card POST, so the request carried none - a TLS server can ask for a certificate
# only in a handshake. Here: the same with a kept-alive connection to the main port, then the fix (the card port).
import http.client
def jar_cookies(b_):
    return "; ".join("%s=%s" % (c.name, c.value) for c in b_.jar)
def to_present_page(ident_):
    """An Entra sign-in in a browser WITHOUT a card, up to the present-card page: (browser, page html, page url)."""
    NEXT.clear(); NEXT.update(ident_)
    fl_ = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client="account-console", redirect=ACCT, admin_url=None, client_secret=None, cacert=a.cacert))
    b_ = E.Browser(a.cacert); url_, ver_ = fl_.auth_url()
    k_, u_, p_ = b_.go(url_, None, ACCT)
    m_ = re.search(r'href="([^"]*/broker/entra/login[^"]*)"', p_ or "")
    k_, u_, p_ = b_.go(urllib.parse.urljoin(u_, html.unescape(m_.group(1))), None, ACCT)
    for _ in range(4):
        if k_ == "page" and E.page_id(p_) == "login-terms":
            act_, f_ = E.form(p_); f_["accept"] = "OK"; k_, u_, p_ = b_.go(act_, f_, ACCT)
    return b_, p_, u_
def post_on(conn, url_, fields, b_):
    pu = urllib.parse.urlparse(url_)
    conn.request("POST", pu.path + ("?" + pu.query if pu.query else ""), body=urllib.parse.urlencode(fields).encode(),
                 headers={"Host": pu.netloc, "Cookie": jar_cookies(b_), "Content-Type": "application/x-www-form-urlencoded"})
    r_ = conn.getresponse(); body_ = r_.read().decode("utf-8", "replace")
    return r_.status, r_.getheader("Location"), body_
def conn_to(port, ctx_):
    sock_ = socket.create_connection(("127.0.0.1", port), timeout=30)
    c_ = http.client.HTTPSConnection(HOST, port, context=ctx_, timeout=60); c_.sock = ctx_.wrap_socket(sock_, server_hostname=HOST)
    return c_
roe = find_user("roe.jane")
if roe:
    kc.api("DELETE", "/users/%s" % roe["id"])                     # frees roe.jane's card (2345678901) for this test
st, body = accounts(cac_body("tls.lab", "tls.lab@%s" % DOMAIN, signIn=["entra", "cac"], edipi="2345678901"))
tlsu = find_user("tls.lab")
check("[tls] an [entra, cac] invite for the card of the mock PKI's roe.jane", st == 201 and tlsu is not None, (st, body))
b_t, page_t, url_t = to_present_page(ident("tls.lab@%s" % DOMAIN))
act_t, f_t = E.form(page_t, "stig-card-form")
ign_t, _ = E.form(page_t, "stig-card-ignore")
check("[tls] ... while \"Continue without the card\" posts to the page's OWN origin (port %d), and the page carries the network fallback" % PORT,
      urllib.parse.urlparse(ign_t).port == PORT and "stig-card-blocked" in page_t and ":%d/realms/%s/.well-known/openid-configuration" % (CARD_PORT, REALM) in page_t,
      ign_t)
check("[tls] after the Entra sign-in the present-card page's form posts to the CARD port (%d), same path and query" % CARD_PORT,
      E.page_id(page_t) == PRESENT and urllib.parse.urlparse(act_t).port == CARD_PORT
      and "execution=stig-present-card" in act_t, act_t)
# the bug: a connection to the MAIN port made without a certificate and kept; the card is in the reader by now
ctx_keep = ssl.create_default_context(cafile=a.cacert)
c_main = conn_to(PORT, ctx_keep)
c_main.request("GET", "/realms/%s/.well-known/openid-configuration" % REALM, headers={"Host": "%s:%d" % (HOST, PORT)}); c_main.getresponse().read()
ctx_keep.load_cert_chain("/t/roe.jane.crt", "/t/roe.jane.key")       # the card inserted AFTER the connection was made
f_t["login"] = "Sign in with my CAC"
main_act = act_t.replace(":%d/" % CARD_PORT, ":%d/" % PORT)
st, loc, body = post_on(c_main, main_act, f_t, b_t)
check("[tls] the bug reproduced: the POST on the kept main-port connection (made without a card) carries NO certificate",
      st == 200 and "No card was presented" in html.unescape(body) and not (kc.api("GET", "/users/%s" % tlsu["id"]).get("attributes") or {}).get("cac_edipi"),
      (st, loc, E.page_id(body), (re.search(r"No card[^<]{0,60}", html.unescape(body)) or [None])[0], re.findall(r'class="[^"]*alert[^"]*"[^>]*>\s*<[^>]+>\s*([^<]{0,80})', body)[:2]))
# a resumed TLS session made without a certificate: the server does not ask again either
ctx_res = ssl.create_default_context(cafile=a.cacert)
s1 = ctx_res.wrap_socket(socket.create_connection(("127.0.0.1", PORT)), server_hostname=HOST)
s1.sendall(("GET /realms/%s/.well-known/openid-configuration HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n" % (REALM, HOST, PORT)).encode())
while s1.recv(65536):
    pass
sess = s1.session; s1.close()
ctx_res.load_cert_chain("/t/roe.jane.crt", "/t/roe.jane.key")
s2 = ctx_res.wrap_socket(socket.create_connection(("127.0.0.1", PORT)), server_hostname=HOST, session=sess)
resumed = s2.session_reused
s2.close()
print("info  [tls] TLS session resumption on the main port: %s" % ("resumed (no certificate request in a resumed handshake)" if resumed
      else "not resumed by this server (each new connection is a full handshake)"))
# the fix: the page's own action, on the card port - a new connection and a full handshake, which asks for the card
page_now = body                                                    # the re-challenged page (the old code is spent)
act_now, f_now = E.form(page_now, "stig-card-form"); f_now["login"] = "Sign in with my CAC"
check("[tls] ... and the re-challenge still points at the card port", urllib.parse.urlparse(act_now).port == CARD_PORT, act_now)
ctx_card = ssl.create_default_context(cafile=a.cacert); ctx_card.load_cert_chain("/t/roe.jane.crt", "/t/roe.jane.key")
c_card = conn_to(CARD_PORT, ctx_card)
st, loc, body = post_on(c_card, act_now, f_now, b_t)

ta = kc.api("GET", "/users/%s" % tlsu["id"]).get("attributes") or {}
check("[tls] the fix: the POST to the card port (a fresh handshake that asks for the certificate) binds the card",
      ta.get("cac_edipi") == ["2345678901"] and not ta.get("cac_edipi_pending") and st in (302, 303) and loc and loc.startswith(ACCT),
      (st, (loc or "")[:80], sorted(ta)))
check("[tls] ... same authentication session: the redirect carries the account console's code (and back on the main port)",
      loc and "code=" in loc and urllib.parse.urlparse(loc).port == PORT, (loc or "")[:100])
kc.api("POST", "/users/%s/logout" % tlsu["id"])
fl_c = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client="account-console", redirect=ACCT, admin_url=None, client_secret=None, cacert=a.cacert))
_, fin_c, seen_c, _, ver_c = E.cac_login(fl_c, "/t/roe.jane.crt", "/t/roe.jane.key")
tk_c = fl_c.token(urllib.parse.parse_qs(urllib.parse.urlparse(fin_c).query)["code"][0], ver_c) if fin_c and "code=" in fin_c else None
check("[tls] afterwards the CAC signs in to that account", tk_c and E.claims(tk_c["access_token"]).get("preferred_username") == "tls.lab", seen_c)

# a network that blocks the card port: "Continue without the card" still completes the sign-in (on the page's own origin)
st, body = accounts(cac_body("blk.lab", "blk.lab@%s" % DOMAIN, signIn=["entra", "cac"], edipi="7777777777"))
FORWARD["on"] = False
try:
    s_ = socket.create_connection(("127.0.0.1", CARD_PORT), timeout=5)
    tls_ok = True
    try:
        ssl.create_default_context(cafile=a.cacert).wrap_socket(s_, server_hostname=HOST).close()
    except (ssl.SSLError, OSError):
        tls_ok = False
except OSError:
    tls_ok = False
check("[blocked] (the card port is unreachable now: no TLS handshake completes there)", not tls_ok)
B_OID = str(uuid.uuid4())
tok, seen = entra_then_card(ident("blk.lab@%s" % DOMAIN, oid=B_OID), skip=True)
ba = attrs(find_user("blk.lab"))
check("[blocked] the Entra sign-in completes with \"Continue without the card\" - nothing on the card port needed",
      tok is not None and PRESENT in seen and oid_of("blk.lab") == B_OID and ba.get("cac_edipi_pending") == ["7777777777"] and not ba.get("cac_edipi"), seen)
FORWARD["on"] = True

# ------------------------------------------------------------------ the manual binding still works
K_OID = str(uuid.uuid4()); acct("kim.lab", "kim.lab@%s" % DOMAIN, created_by=False, pending=False)
r_, out = quiet(M.cmd_link_entra, argparse.Namespace(username="kim.lab", oid=K_OID))
tok, seen = entra_sign_in(ident("kim.lab@%s" % DOMAIN, oid=K_OID))
check("[manual] link-entra (the admin-set binding, as invite --entra-oid sets it) still signs in", tok is not None and oid_of("kim.lab") == K_OID, seen)

# ------------------------------------------------------------------ guard: an EDIPI as a username
kc.api("POST", "/users", {"username": "9999999999", "enabled": False, "firstName": "Edipi", "lastName": "Name"})
kc.api("GET", "/users?q=cac_edipi:123456789")                 # a partial EDIPI search (audited masked: see the log check)
kc.api("GET", "/users?search=9999999&q=cac_upn:x@mil")
kc.api("GET", "/users?q=%22cac_edipi%22:%22123%22")         # quoted (Keycloak strips the quotes)
# V-222447: a request carrying a Referer with a query, a fragment and an EDIPI (the server-log gates check the record)
st_r, _ = raw("GET", "/realms/%s/.well-known/openid-configuration" % REALM, None,
              {"Referer": "https://portal.lab.example/admin/accounts/1234567890?q=cac_edipi:1234567890#frag"})
check("[log] a request with a Referer (query, fragment, an EDIPI in its path) is served", st_r == 200, st_r)
check("[log] the extension publishes referer-audit=sanitised (operationalInfo), and guard reports nothing for it",
      M.gate_marker(kc, "referer-audit") == "sanitised" and M.referer_audit_report(kc) == ([], []), M.gate_marker(kc, "referer-audit"))
eu = M.edipi_usernames(kc)
check("[guard] a username that is a 10-digit run is reported (STIG-USERNAME-IS-EDIPI), masked",
      any("STIG-USERNAME-IS-EDIPI user=******9999 " in l for l in eu) and not any(re.search(r"[0-9]{10}", l) for l in eu), eu)

# ------------------------------------------------------------------ guard: pending and expired Entra invites
expired, pending = M.entra_invites(kc)
check("[guard] the expired invite is reported (STIG-ENTRA-INVITE-EXPIRED)", any("user=carol.lab " in l for l in expired), expired)
check("[guard] a pending one is information", any("user=bob.lab " in l for l in pending) and not any("bob.lab" in l for l in expired), pending[:3])
check("[guard] a bound one is neither", not any("alice.lab" in l for l in expired + pending))
check("[guard] a DISABLED pending invite is neither (it can no longer sign in at all)", not any("user=hank.lab " in l for l in expired + pending))

# ------------------------------------------------------------------ off
r_, out = entra_cmd(no_auto_link=True)
point_at_mock()
refused("with --no-auto-link, a fresh valid invite is NOT bound (today's behaviour)", ident("jill.lab@%s" % DOMAIN), "jill.lab")
check("[off] ... and stig-accounts makes no Entra-type account any more", accounts({"username": "late.lab", "email": "late.lab@%s" % DOMAIN,
      "firstName": "Late", "lastName": "Lab", "group": "/app-a/viewer", "signIn": "entra"})[0] == 403)

# no EDIPI in the stored events: every login event, and the admin events not written by the operator's tooling
TEN = re.compile(r"(?<![0-9A-Za-z])[0-9]{10}(?![0-9A-Za-z])")
lev = kc.api("GET", "/events?max=5000") or []
master_id = json.loads(raw("GET", "/admin/realms/master", None, {"Authorization": "Bearer " + kc.token})[1]).get("id")
aev = [e for e in (kc.api("GET", "/admin-events?max=5000") or []) if (e.get("authDetails") or {}).get("realmId") != master_id]
bad_l = [e for e in lev if TEN.search(json.dumps(e))]
bad_a = [e for e in aev if TEN.search(json.dumps(e))]
check("[log] no ten-digit run in any stored login event (%d events, LOGIN_ERROR included)" % len(lev),
      lev and not bad_l, [TEN.sub("<10>", json.dumps(e))[:200] for e in bad_l[:2]])
check("[log] ... nor in the admin events written in the realm (stig-accounts, the binding steps; %d)" % len(aev),
      not bad_a, [TEN.sub("<10>", json.dumps(e))[:200] for e in bad_a[:2]])
nf = [e for e in lev if e.get("type") == "LOGIN_ERROR" and (e.get("details") or {}).get("username", "").startswith("card:")]
check("[log] a refused card's LOGIN_ERROR names it as card:******NNNN#<keyed hash> (correlatable, never the number)",
      nf and all(re.fullmatch(r"card:\*{6}[0-9]{4}(@mil)?#[0-9a-f]{8}", e["details"]["username"]) for e in nf),
      [e["details"].get("username") for e in nf[:3]])

srv.shutdown()
n = sum(res); print("\n%d/%d passed" % (n, len(res))); sys.exit(0 if n == len(res) else 1)

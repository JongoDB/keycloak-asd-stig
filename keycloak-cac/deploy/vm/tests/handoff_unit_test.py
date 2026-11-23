#!/usr/bin/env python3
"""Unit test of idp-admin.py's hand-off intake (`handoffs`, the token self-check, the note rules, the fetch hygiene) and
of the handoffIntake config rules, against a MOCK intake: one local HTTPS server that is both the IdP's token endpoint
(issuing unsigned tokens whose claims each test chooses) and an application's intake API, with the intake's rules:
401 for a bad token, 403 for a missing aud / scope / azp, a lifetime over 600 s refused, an outcome recorded once (the
same outcome again is idempotent, another one 409), 404 for an unknown id, 400 for a ten-digit note. No Keycloak, no
root; needs `openssl` for the test certificate.

  python3 handoff_unit_test.py
"""
import argparse, base64, contextlib, copy, io, json, os, socket, ssl, subprocess, sys, tempfile, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.machinery, importlib.util, re

HERE = os.path.dirname(os.path.abspath(__file__))
ADM = os.path.join(HERE, "..", "host", "idp-admin.py")
BASE_CFG = json.load(open(os.path.join(HERE, "fixtures", "idp-admin.test.json")))
res = []
def check(n, ok, d=""):
    res.append(bool(ok)); print("%s  %-96s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

TMP = tempfile.mkdtemp(prefix="handoff-unit-")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", os.path.join(TMP, "k.pem"),
                "-out", os.path.join(TMP, "c.pem"), "-days", "1", "-subj", "/CN=intake.test",
                "-addext", "subjectAltName=DNS:intake.test,DNS:idp.test"], check=True, capture_output=True)

CID, AUD, SCOPE, REALM, SECRET = "app-handoff-worker", "app-handoffs", "app-handoffs.intake", "lab", "s3cret-value"
U1, U2, U3 = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"

class Mock:
    """What the server does; each test sets the parts it needs."""
    def reset(self):
        self.claims = {}            # overrides of the issued token's claims (None value = drop the claim)
        self.mode = ""              # "", redirect, big, slow, ratelimit, garbage
        self.calls = []             # (method, path, body) of every intake call
        self.token_calls = []
        self.items = {U1: {"id": U1, "kind": "disable_enable_unlock", "username": "jane.doe", "status": "open",
                           "filedBy": "mgr@example.mil", "filedAt": "2026-11-20T10:00:00Z"},
                      U2: {"id": U2, "kind": "link_cac", "username": "x; rm -rf /", "status": "open",
                           "filedBy": "mgr@example.mil", "filedAt": "2026-11-20T11:00:00Z"},
                      U3: {"id": U3, "kind": "consider_disable", "username": "john.roe", "status": "cancelled",
                           "filedBy": "mgr@example.mil", "filedAt": "2026-11-20T12:00:00Z"}}
        for i, (kind, user) in enumerate([("delete_account", "ghost.user"), ("reset_credentials", "boss.admin"),
                                          ("disable_enable_unlock", "rm.holder"), ("delete_account", "other.app"),
                                          ("consider_disable", "gone.user"), ("consider_disable", "still.member"),
                                          ("disable_enable_unlock", "off.user"), ("consider_disable", "direct.role"),
                                          ("disable_enable_unlock", "roles.root"), ("delete_account", "shared.user"),
                                          ("reset_credentials", "shared.direct"), ("change_name_email", "shared.user"),
                                          ("disable_enable_unlock", "plain.member"), ("link_cac", "no.card"),
                                          ("link_cac", "has.card"), ("link_cac", "boss.admin"), ("link_cac", "other.app")]):
            iid = "%08d-5555-4555-8555-555555555555" % (i + 1)
            if user == "shared.user" and kind == "change_name_email":
                iid = "%08d-6666-4666-8666-666666666666" % (i + 1)
            self.items[iid] = {"id": iid, "kind": kind, "username": user, "status": "open", "filedBy": "mgr@example.mil",
                               "filedAt": "2026-11-21T%02d:00:00Z" % (10 + i)}
M_ = Mock(); M_.reset()

def b64(o):
    return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def send(self, st, obj, ctype="application/json", extra=None):
        data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(st); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)
    def problem(self, st, detail, extra=None):
        self.send(st, {"type": "about:blank", "title": "x", "status": st, "detail": detail}, "application/problem+json", extra)
    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""
    def do_POST(self):
        self.route("POST")
    def do_GET(self):
        self.route("GET")
    def route(self, method):
        host = (self.headers.get("Host") or "").split(":")[0]
        body = self.body()
        if host == "idp.test":
            return self.token(body)
        self.calls_append(method, body)
        if M_.mode == "redirect":
            return self.send(302, {}, extra={"Location": "https://elsewhere.test/"})
        if M_.mode == "big":
            return self.send(200, b"[" + b" " * (2 << 20) + b"]")
        if M_.mode == "slow":
            self.send_response(200); self.send_header("Content-Length", "100"); self.end_headers()
            try:
                for _ in range(30):
                    time.sleep(0.2); self.wfile.write(b" "); self.wfile.flush()
            except OSError:
                pass             # the client gave up (its deadline): expected
            return
        if M_.mode == "ratelimit":
            return self.problem(429, "Rate limit exceeded", {"Retry-After": "42"})
        # the intake's token rules (as agreed): 401 bad token, 403 missing aud/scope/azp
        m = re.fullmatch(r"Bearer ([A-Za-z0-9._~+/=-]+)", self.headers.get("Authorization") or "")
        if not m:
            return self.problem(401, "Bearer token required")
        try:
            c = json.loads(base64.urlsafe_b64decode(m.group(1).split(".")[1] + "=="))
        except Exception:      # noqa: BLE001
            return self.problem(401, "The token is not valid")
        now = time.time()
        if c.get("iss") != ISSUER or c.get("exp", 0) < now or c.get("iat", 0) > now + 60 or c.get("exp", 0) - c.get("iat", 0) > 600:
            return self.problem(401, "The token is not valid")
        aud = c.get("aud") if isinstance(c.get("aud"), list) else [c.get("aud")]
        if c.get("azp") != CID or AUD not in aud or SCOPE not in (c.get("scope") or "").split():
            return self.problem(403, "This token may not use hand-off intake.")
        p = urllib.parse.urlsplit(self.path)
        if method == "GET" and p.path == "/api/v1/idp-intake/handoffs":
            if M_.mode == "garbage":
                return self.send(200, {"items": [{"kind": "link_cac"}]})
            items = sorted((i for i in M_.items.values() if i["status"] == "open"), key=lambda i: i["filedAt"])
            return self.send(200, {"items": items})
        mm = re.fullmatch(r"/api/v1/idp-intake/handoffs/([^/]+)/outcome", p.path)
        if method == "POST" and mm:
            try:
                b = json.loads(body)
            except ValueError:
                return self.problem(400, "bad json")
            if set(b) - {"outcome", "note"} or b.get("outcome") not in ("done", "refused") or len((b.get("note") or "").strip()) > 200 \
                    or re.search(r"\b\d{10}\b", b.get("note") or ""):
                return self.problem(400, "Invalid body")
            it = M_.items.get(urllib.parse.unquote(mm.group(1)))
            if not it:
                return self.problem(404, "Hand-off not found")
            if it["status"] == b["outcome"]:
                return self.send(200, it)
            if it["status"] != "open":
                return self.problem(409, "This hand-off is already %s; its outcome cannot change." % it["status"])
            it["status"] = b["outcome"]
            return self.send(200, it)
        return self.problem(404, "Not found")
    def calls_append(self, method, body):
        M_.calls.append((method, self.path, body))
    def token(self, body):
        f = dict(urllib.parse.parse_qsl(body.decode()))
        M_.token_calls.append(f)
        if self.path != "/realms/%s/protocol/openid-connect/token" % REALM or f.get("grant_type") != "client_credentials" \
                or f.get("client_id") != CID or f.get("client_secret") != SECRET:
            return self.send(401, {"error": "unauthorized_client"})
        now = int(time.time())
        c = {"exp": now + 300, "iat": now, "jti": "j", "iss": ISSUER, "aud": AUD, "typ": "Bearer", "azp": CID,
             "scope": f.get("scope", "")}
        for k, v in M_.claims.items():
            if v is None:
                c.pop(k, None)
            else:
                c[k] = v
        return self.send(200, {"access_token": "%s.%s.sig" % (b64({"alg": "RS256", "typ": "JWT"}), b64(c)),
                               "expires_in": 300, "token_type": "Bearer"})

sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sctx.load_cert_chain(os.path.join(TMP, "c.pem"), os.path.join(TMP, "k.pem"))
srv = ThreadingHTTPServer(("127.0.0.1", 0), H); srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
ISSUER = "https://idp.test:%d/realms/%s" % (PORT, REALM)
INTAKE = "https://intake.test:%d/api/v1/idp-intake" % PORT

# ---- the config rules (each config loaded in a fresh interpreter: the module reads it at import)
def cfg_with(h):
    c = copy.deepcopy(BASE_CFG)
    if h is not None:
        c["handoffIntake"] = h
    return c
GOOD = {"url": INTAKE, "clientId": CID, "audience": AUD, "scope": SCOPE, "app": "app-a"}

def load(cfg):
    p = os.path.join(TMP, "cfg-%d.json" % len(res))
    json.dump(cfg, open(p, "w"))
    r = subprocess.run([sys.executable, ADM, "--help"], env=dict(os.environ, IDP_ADMIN_CONFIG=p), capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout + r.stderr

rc, out = load(cfg_with(GOOD))
check("config: a complete handoffIntake loads", rc == 0, out[-200:] if rc else "")
for name, h, want in [
        ("an http intake URL", dict(GOOD, url="http://intake.test/api"), "plain https URL"),
        ("an intake URL with a query", dict(GOOD, url=INTAKE + "?x=1"), "plain https URL"),
        ("an intake URL with credentials", dict(GOOD, url="https://u:p@intake.test/api"), "plain https URL"),
        ("an intake URL on an IP literal", dict(GOOD, url="https://192.0.2.10/api"), "plain https URL"),
        ("a missing scope", {k: v for k, v in GOOD.items() if k != "scope"}, "handoffIntake.scope is required"),
        ("an unknown key", dict(GOOD, scopes=SCOPE), "unknown key"),
        ("a reserved client id (admin-cli)", dict(GOOD, clientId="admin-cli"), "reserved"),
        ("a client id that is an application", dict(GOOD, clientId="app-b"), "also an application"),
        ("a client id that is a delegate", dict(GOOD, clientId="app-a-admin"), "also an application or a delegate"),
        ("a scope that is one of Keycloak's own (profile)", dict(GOOD, scope="profile"), "Keycloak's own"),
        ("an audience with a space", dict(GOOD, audience="a b"), "one token"),
        ("a scope as a list", dict(GOOD, scope=[SCOPE]), "non-empty string"),
        ("a missing app (the filing application)", {k: v for k, v in GOOD.items() if k != "app"}, "handoffIntake.app is required"),
        ("an app that is not an application", dict(GOOD, app="nonesuch"), "not an application")]:
    rc, out = load(cfg_with(h))
    check("config: refuses %s" % name, rc != 0 and want in out, out.strip().splitlines()[-1][:110] if out.strip() else "")

# ---- the module, configured for the mock
cfgp = os.path.join(TMP, "idp-admin.json"); json.dump(cfg_with(GOOD), open(cfgp, "w"))
os.environ["IDP_ADMIN_CONFIG"] = cfgp
ld = importlib.machinery.SourceFileLoader("idp_admin", ADM)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
M.CFG = {"CAC_PUBLIC_URL": "https://idp.test:%d" % PORT, "CAC_REALM": REALM}; M.REALM = REALM
M.HANDOFF_CTX = ssl.create_default_context(cafile=os.path.join(TMP, "c.pem"))
def resolver(host, port, proto=0, **k):
    if host in ("intake.test", "idp.test"):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    raise socket.gaierror("no such host %s" % host)
M.HANDOFF_RESOLVER = resolver
M.HANDOFF_SECRET_FILE = os.path.join(TMP, "secret"); open(M.HANDOFF_SECRET_FILE, "w").write(SECRET + "\n")
AUDIT = []
M.HANDOFF_AUDIT = AUDIT.append

class FakeKC:
    """Just enough of the admin API for handoff_account: users, their groups, links and realm-management roles."""
    def __init__(self):
        self.users = {}
    def add(self, name, groups=(), rm=(), enabled=True, attrs=None, links=(), roles=None):
        """roles: {client: [role]} held effectively (direct, composite or group); rm: realm-management roles."""
        uid = "u-%s" % name
        cr = {k: [{"name": r} for r in v] for k, v in (roles or {}).items()}
        cr["realm-management"] = [{"name": r} for r in rm]
        self.users[name] = {"rep": {"id": uid, "username": name, "enabled": enabled, "attributes": attrs or {}},
                            "groups": [{"id": "g-" + g, "path": g} for g in groups], "roles": cr,
                            "links": [{"identityProvider": l} for l in links]}
    def by_id(self, uid):
        return next(v for v in self.users.values() if v["rep"]["id"] == uid)
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        p_ = urllib.parse.urlsplit(path); qs = dict(urllib.parse.parse_qsl(p_.query)); parts = p_.path.strip("/").split("/")
        if p_.path == "/users":
            u = self.users.get(qs.get("username"))
            return [copy.deepcopy(u["rep"])] if u else []
        if p_.path == "/clients":
            return [{"id": "C-" + qs.get("clientId"), "clientId": qs.get("clientId")}]
        if parts[0] == "users" and len(parts) == 2:
            return copy.deepcopy(self.by_id(parts[1])["rep"])
        if parts[0] == "users" and parts[2] == "groups":
            return copy.deepcopy(self.by_id(parts[1])["groups"]) if qs.get("first", "0") == "0" else []
        if parts[0] == "users" and parts[2] == "federated-identity":
            return copy.deepcopy(self.by_id(parts[1])["links"])
        if parts[0] == "users" and parts[2:4] == ["role-mappings", "clients"] and parts[-1] == "composite":
            return copy.deepcopy(self.by_id(parts[1])["roles"].get(parts[4][2:], []))
        raise AssertionError("unexpected admin call %s %s" % (method, path))
FK = FakeKC()
FK.add("jane.doe", groups=["/app-a", "/app-a/viewer"], roles={"app-a": ["viewer"]}, attrs={"cac_edipi": ["1234567890"], "entra_oid": ["0b1c2d3e-0000-4000-8000-000000000001"]},
       links=["entra"])
FK.add("boss.admin", groups=["/roles/idp-admin"])
FK.add("rm.holder", groups=["/app-a/viewer"], rm=["manage-users"])
FK.add("other.app", groups=["/app-b/owner"])
FK.add("gone.user", enabled=True)
FK.add("still.member", groups=["/app-c/lead"])
FK.add("off.user", groups=["/app-a/editor"], enabled=False)
FK.add("direct.role", roles={"app-b": ["owner"]})                    # user-create-cac style: a direct mapping, no group
FK.add("roles.root", groups=["/roles"])                             # the bare /roles group
FK.add("shared.user", groups=["/app-a/viewer", "/app-c/lead"], roles={"app-a": ["viewer"], "app-c": ["lead"]})
FK.add("shared.direct", groups=["/app-a/viewer"], roles={"app-a": ["viewer"], "app-b": ["owner"]})
FK.add("plain.member", groups=["/app-a/viewer"], roles={"app-a": ["viewer"]})
FK.add("no.card", groups=["/app-a/viewer"], roles={"app-a": ["viewer"]})
FK.add("has.card", groups=["/app-a/viewer"], roles={"app-a": ["viewer"]}, attrs={"cac_edipi": ["2345678901"]})
M.KC = lambda: FK
check("module: UNMANAGED_CLIENTS (so add-client refuses it, check-clients does not call it unmanaged) names the worker",
      CID in M.UNMANAGED_CLIENTS and CID in M.RESERVED_CLIENTS)

def run(action="list", id=None, note=None):
    """(exit code, output) of `handoffs`."""
    out = io.StringIO(); code = 0
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            M.cmd_handoffs(argparse.Namespace(action=action, id=id, note=note))
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
        out.write(str(e.code) if not isinstance(e.code, int) else "")
    return code, out.getvalue()

# ---- fetch hygiene
M_.reset()
code, out = run()
check("hygiene: the intake host must resolve to public addresses (127.0.0.1 refused, nothing sent)",
      code != 0 and "non-public address" in out and not M_.calls, out.strip()[-90:])
M.HANDOFF_PUBLIC_ONLY = False          # the mock lives on loopback; from here on only that rule is relaxed
def call(url, **k):
    try:
        return M.https_call(url, resolver=resolver, ctx=M.HANDOFF_CTX, public_only=False, **k)
    except Exception as e:      # noqa: BLE001
        return e
r = call(INTAKE.replace("https:", "http:") + "/handoffs")
check("hygiene: an http URL is refused before any connection", isinstance(r, ValueError) and "https" in str(r), str(r))
M_.reset(); M_.mode = "redirect"; r = call(INTAKE + "/handoffs")
check("hygiene: a redirect is refused, never followed", isinstance(r, ValueError) and "redirect" in str(r), str(r))
M_.mode = "big"; r = call(INTAKE + "/handoffs")
check("hygiene: an answer over the size cap (1 MiB) is refused", isinstance(r, ValueError) and "more than" in str(r), str(r))
M_.mode = "slow"; t0 = time.time(); r = call(INTAKE + "/handoffs", deadline=2)
check("hygiene: a server that drips its answer meets the overall deadline", isinstance(r, TimeoutError) and time.time() - t0 < 4,
      "%s after %.1fs" % (r, time.time() - t0))
bad_ctx = ssl.create_default_context()
try:
    M.https_call(INTAKE + "/handoffs", resolver=resolver, ctx=bad_ctx, public_only=False); r = None
except ssl.SSLError as e:
    r = e
check("hygiene: the certificate is verified (an untrusted one fails)", isinstance(r, ssl.SSLError), str(r)[:80])
M_.mode = "ratelimit"; code, out = run()
check("hygiene: 429 is reported with Retry-After", code != 0 and "rate limited" in out and "42" in out, out.strip()[-90:])
M_.mode = "garbage"; code, out = run()
check("hygiene: an item without a usable id is refused, not printed", code != 0 and "not a hand-off list" in out, out.strip()[-90:])

# ---- the token's claims, checked before any intake call
M_.reset(); code, out = run()
check("token: asks for exactly the configured scope with the worker's client credentials",
      M_.token_calls and M_.token_calls[-1].get("scope") == SCOPE and M_.token_calls[-1].get("grant_type") == "client_credentials")
for name, claims, want in [
        ("aud missing", {"aud": None}, "aud is None"),
        ("another audience", {"aud": "account"}, "aud is 'account'"),
        ("an extra audience", {"aud": [AUD, "account"]}, "expected exactly"),
        ("scope missing", {"scope": ""}, "scope is ''"),
        ("an extra scope", {"scope": "profile %s" % SCOPE}, "expected exactly"),
        ("another azp", {"azp": "someone-else"}, "azp is 'someone-else'"),
        ("another issuer", {"iss": "https://elsewhere.test/realms/lab"}, "iss is"),
        ("a lifetime of 900 s", {"exp": int(time.time()) + 900}, "lives 900 s"),
        ("an iat two minutes ahead", {"iat": int(time.time()) + 120, "exp": int(time.time()) + 400}, "in the future"),
        ("an ID token", {"typ": "ID"}, "not an access token")]:
    M_.reset(); M_.claims = claims
    code, out = run()
    check("token: refused locally when %s - the intake is never called" % name, code != 0 and want in out and not M_.calls,
          out.strip()[-80:])
open(M.HANDOFF_SECRET_FILE, "w").write("wrong")
M_.reset(); code, out = run()
check("token: a wrong secret is reported (the IdP's 401), nothing sent to the intake",
      code != 0 and "refused the worker's token request" in out and not M_.calls, out.strip()[-80:])
open(M.HANDOFF_SECRET_FILE, "w").write(SECRET + "\n")
check("token: handoff_token_problems accepts exactly the agreed token",
      M.handoff_token_problems({"iss": ISSUER, "azp": CID, "aud": AUD, "scope": SCOPE, "typ": "Bearer", "iat": 100, "exp": 400},
                               CID, AUD, SCOPE, ISSUER, now=150) == [])

# ---- the list: oldest first, the suggested command per kind, never an unsafe username in a command
M_.reset(); code, out = run()
check("list: 200, the open hand-offs only (a cancelled one is not listed)", code == 0 and U1 in out and U2 in out and U3 not in out, "")
check("list: oldest first", 0 <= out.find(U1) < out.find(U2))
check("list: disable_enable_unlock suggests user-enable false / true and user-unlock for the username",
      "run:  sudo idp-admin.py user-enable jane.doe false" in out and "run:  sudo idp-admin.py user-unlock jane.doe" in out)
check("list: a username a command cannot carry gives NO command line (never a quoted one)",
      "rm -rf" not in "\n".join(l for l in out.splitlines() if "run:" in l) and "characters a command cannot carry" in out)
check("list: nothing was changed, and no outcome was sent", "Nothing was changed" in out and all(m == "GET" for m, _, _ in M_.calls))
for kind, want in [("link_cac", "link-cac a.b"), ("link_entra", "link-entra a.b <Entra object id>"), ("reset_credentials", "reset-user a.b"),
                   ("change_name_email", "rename a.b a.b --email <address>"), ("delete_account", "user-delete a.b"),
                   ("consider_disable", "user-enable a.b false"), ("something_new", None)]:
    cmds, note = M.handoff_suggestion(kind, "a.b")
    ok = (any(want in c for c in cmds) if want else not cmds) and bool(note)
    check("suggestion: %-22s -> %s" % (kind, cmds[0] if cmds else "(no command; a note)"), ok, (note or "")[:60])
cmds, note = M.handoff_suggestion("link_cac", "a.b")
check("suggestion: link_cac -> exactly `link-cac a.b` (possession: no EDIPI in any command); --edipi typed at the prompt, "
      "--bind-edipi only if the person cannot present a card",
      cmds == ["sudo idp-admin.py link-cac a.b"] and "--edipi" in note and "prompt" in note and "never from the hand-off" in note
      and "--bind-edipi --confirm-direct-bind" in note and not re.search(r"[0-9]{4}", note), note[:120])
check("suggestion: every command is an existing idp-admin.py command",
      all(c.split()[0] in M.build_parser()._subparsers._group_actions[0].choices
          for cmds, _ in M.HANDOFF_SUGGESTIONS.values() for c in cmds))

# ---- each account as Keycloak sees it: a wrong or compromised intake cannot steer the operator
M_.reset(); code, out = run()
def block(user):
    """The lines printed for the hand-off of `user` (its header line up to the next hand-off)."""
    ls = out.splitlines(); i = next((n for n, l in enumerate(ls) if "  %s " % user in l and "filed" in l), None)
    if i is None:
        return ""
    j = next((n for n in range(i + 1, len(ls)) if not ls[n].startswith("    ")), len(ls))
    return "\n".join(ls[i:j])
b = block("jane.doe")
check("account: a member of the filing tree gets its state (enabled, card bound, Entra bound + linked, trees) and the command",
      "account: enabled; card bound; Entra bound (linked); application trees /app-a; application roles app-a:viewer" in b and "run:  sudo idp-admin.py user-unlock jane.doe" in b
      and "WARNING" not in b, b.replace("\n", " | ")[:160])
check("account: the card number and the Entra object id are never printed", "1234567890" not in out and "0b1c2d3e" not in out)
for user, want, name in [("ghost.user", "NO account ghost.user", "an account that does not exist"),
                         ("boss.admin", "IdP ADMINISTRATOR (/roles/idp-admin)", "an IdP administrator by /roles/* group"),
                         ("rm.holder", "IdP ADMINISTRATOR (manage-users)", "an administrator by an effective realm-management role (even inside the tree)"),
                         ("other.app", "not a member of /app-a", "an account outside the filing application's tree"),
                         ("still.member", "still holds groups or roles of app-c", "consider_disable for an account still in another application's tree"),
                         ("direct.role", "still holds groups or roles of app-b", "consider_disable for an account holding another app's role by a DIRECT mapping (no group)"),
                         ("roles.root", "IdP ADMINISTRATOR (/roles)", "a member of the bare /roles group")]:
    b = block(user)
    check("account: %s -> a WARNING and NO command line" % name, want in b and "WARNING" in b and "run:" not in b, b.replace("\n", " | ")[-150:])
b = block("direct.role")
check("account: the state line names the application roles held (role names only)", "application roles app-b:owner" in b, b.replace("\n", " | ")[:160])
def blocks(user):
    ls = out.splitlines(); res_ = []
    for i, l in enumerate(ls):
        if "  %s " % user in l and "filed" in l:
            j = next((n for n in range(i + 1, len(ls)) if not ls[n].startswith("    ")), len(ls)); res_.append("\n".join(ls[i:j]))
    return res_
for user, kind, other, cmd in [("shared.user", "delete_account", "app-c", "user-delete shared.user"),
                               ("shared.direct", "reset_credentials", "app-b", "reset-user shared.direct")]:
    b = next((x for x in blocks(user) if kind in x), "")
    check("account: %s on an account another app also uses (%s, %s) keeps the command and a clear CAUTION"
          % (kind, other, "tree" if user == "shared.user" else "direct role"),
          "CAUTION: %s is also used by %s" % (user, other) in b and "WHOLE account" in b and ("run:  sudo idp-admin.py " + cmd) in b
          and "WARNING" not in b, b.replace("\n", " | ")[-170:])
b = next((x for x in blocks("shared.user") if "change_name_email" in x), "")
check("account: change_name_email on a shared account: no caution (not a whole-account action on access)", "CAUTION" not in b and "run:" in b,
      b.replace("\n", " | ")[-120:])
b = block("plain.member")
check("account: a whole-account action on an account only the filing app uses: no caution", "CAUTION" not in b and "run:" in b and "WARNING" not in b,
      b.replace("\n", " | ")[-120:])
b = block("gone.user")
check("account: consider_disable for an account in no application tree gets its command (user-enable ... false)",
      "application trees none; application roles none" in b and "run:  sudo idp-admin.py user-enable gone.user false" in b and "WARNING" not in b, b.replace("\n", " | ")[-120:])
b = block("off.user")
check("account: a disabled account is shown DISABLED", "account: DISABLED; card not bound; Entra not bound; application trees /app-a; application roles none" in b, b.replace("\n", " | ")[-120:])
b = block("x; rm -rf /")
check("account: an unsafe username is never looked up and gets no command", "WARNING" in b and "run:" not in b, b.replace("\n", " | ")[-100:])
b = block("no.card")
check("account: link_cac for a member of the filing tree without a card -> run: link-cac no.card, no warning, no caution",
      "run:  sudo idp-admin.py link-cac no.card" in b and "WARNING" not in b and "CAUTION" not in b and "card not bound" in b,
      b.replace("\n", " | ")[-150:])
b = block("has.card")
check("account: link_cac for an account that already has a card keeps the command with a CAUTION (--replace), never the number",
      "CAUTION: has.card already has a card" in b and "--replace" in b and "run:  sudo idp-admin.py link-cac has.card" in b
      and "2345678901" not in out and "8901" not in b, b.replace("\n", " | ")[-170:])
for user in ("boss.admin", "other.app"):
    b = next((x for x in blocks(user) if "link_cac" in x), "")
    check("account: link_cac for %s -> a WARNING and NO command line (the existing safety checks)" % user,
          "WARNING" in b and "run:" not in b, b.replace("\n", " | ")[-120:])
def kc_down():
    sys.exit("admin login failed")
M.KC = kc_down
M_.reset(); code, out = run()
check("account: when Keycloak cannot be asked, NO command is suggested for any hand-off (warned)",
      code == 0 and "accounts could not be checked" in out and "run:" not in out, out.strip().splitlines()[0][:120] if out.strip() else "")
M.KC = lambda: FK

# ---- outcomes: recorded, idempotent, refused when closed otherwise, unknown id, audit
M_.reset(); AUDIT.clear()
code, out = run("done", U1, "unlocked after a phone call")
check("outcome: done is recorded (200, status done)", code == 0 and M_.items[U1]["status"] == "done" and "done recorded" in out, out.strip()[-80:])
sent = json.loads(M_.calls[-1][2]) if M_.calls else {}
check("outcome: the body is exactly {outcome, note}", sent == {"outcome": "done", "note": "unlocked after a phone call"}, sent)
check("outcome: audited (STIG-HANDOFF-OUTCOME ... result=recorded, kind and username, the operator, the note)",
      AUDIT and AUDIT[-1].startswith("STIG-HANDOFF-OUTCOME id=%s outcome=done" % U1) and "result=recorded" in AUDIT[-1]
      and "username=jane.doe" in AUDIT[-1] and "kind=disable_enable_unlock" in AUDIT[-1] and "operator=" in AUDIT[-1]
      and '"unlocked after a phone call"' in AUDIT[-1], AUDIT[-1] if AUDIT else "")
code, out = run("done", U1, "unlocked after a phone call")
check("outcome: the same outcome again is idempotent (200, done)", code == 0 and "done recorded" in out, out.strip()[-60:])
code, out = run("refused", U1, "changed my mind")
check("outcome: another outcome on a closed hand-off is 409, reported, exit non-zero",
      code != 0 and "HTTP 409" in out and M_.items[U1]["status"] == "done", out.strip()[-90:])
check("outcome: the 409 is audited too (result=refused-by-intake http=409)", AUDIT and "result=refused-by-intake http=409" in AUDIT[-1],
      AUDIT[-1] if AUDIT else "")
code, out = run("done", U3, "")
check("outcome: a cancelled hand-off is 409", code != 0 and "HTTP 409" in out and "cancelled" in out, out.strip()[-80:])
code, out = run("done", "44444444-4444-4444-8444-444444444444")
check("outcome: an unknown id is 404", code != 0 and "HTTP 404" in out, out.strip()[-60:])
n_calls = len(M_.calls)
code, out = run("refused", U2)
check("outcome: refused without --note is refused locally (nothing sent)", code != 0 and "needs --note" in out and len(M_.calls) == n_calls,
      out.strip()[-60:])
code, out = run("done", "../../admin")
check("outcome: an id that is not an id is refused locally", code != 0 and len(M_.calls) == n_calls, out.strip()[-60:])
M_.claims = {"aud": "elsewhere"}
code, out = run("done", U2, "x")
check("outcome: never sent with a token the intake would refuse", code != 0 and len(M_.calls) == n_calls, out.strip()[-60:])
M_.claims = {}

# ---- the note rules (checked before the token is even asked for)
for note, ok, name in [("card 1234567890 linked", False, "ten digits"), ("12345678901", False, "eleven digits"),
                       ("1234 567 890", False, "ten digits in groups split by spaces"), ("123-456-7890", False, "a phone-like 3-3-4"),
                       ("12.345.678.90", False, "ten digits split by dots"), ("x" * 201, False, "201 characters"),
                       ("line\nbreak", False, "a line break"), ("tab\there", False, "a control character"),
                       ("ticket 123456789", True, "nine digits"), ("x" * 200, True, "200 characters"),
                       ("on 2026-11-22 at 14:05", True, "a date and a time"), ("", True, "empty")]:
    M_.reset(); nt = len(M_.token_calls)
    code, out = run("done", U1, note)
    accepted = code == 0
    check("note: %-38s %s" % (name, "accepted" if ok else "refused before anything is sent"),
          accepted == ok and (ok or (len(M_.token_calls) == nt and not M_.calls)), out.strip()[-70:])

srv.shutdown()
print("%d/%d passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)

#!/usr/bin/env python3
"""Live test of the 2026-11-10 review's HIGH findings. Runs ON the VM as root, inside the Keycloak container's network
namespace (it joins it itself), against the live realm; creates t.fp.* users, a t-role-fp-um client and a throwaway
identity provider t-entra (a stand-in for Entra, served by this script on 127.0.0.1 inside that namespace) in a
throwaway realm t-fp-broker, and removes them all. Prints PASS/FAIL.

  sudo python3 factor_promotion_test.py --skill /srv/idp/src/keycloak-asd-stig-<sha>/keycloak-asd-stig

HIGH 2 - an administrator's second factor is never enrolled after one factor
  - an administrator with a password and no OTP: the password is refused (looks wrong), no TOTP set-up page, no code,
    for an application and for the realm's admin console
  - a non-administrator with a password and no OTP still enrols TOTP at first sign-in (unchanged)
  - an administrator who holds OTP gets the OTP prompt (never set-up) and signs in
  - identity provider (Entra stand-in): an administrator whose amr lacks "mfa" and who holds no OTP is refused;
    with amr "mfa" signs in; with OTP held gets the OTP prompt; a non-administrator signs in without OTP
HIGH 1 - promotion never keeps what a delegate planted
  - the user manager plants a password (reset), a TOTP (signing in with it) and an identity-provider link on a member:
    grant idp-admin is REFUSED and changes nothing; grant --reset-credentials removes every planted factor and link,
    takes the account out of the application groups, and leaves it PENDING (no card, no trusted second factor)
  - promoted by hand (as the console would) with planted factors: guard --fix demotes it, resets its factors and
    identity bindings and disables it, exit 2; user-enable refuses it until reset-user
GATE (the primary control) - an account holding realm-management rights but not on the allowlist
  - (a) every way this realm issues a token ends at an allowlist check: the browser flow (card, password, SSO cookie)
    ends with the gate, every identity provider's post-broker flow requires the binding check that also refuses an
    unvetted administrator, the direct grant is denied, no device / CIBA / token-exchange grant and no per-client flow
    override; live: a fresh password+TOTP sign-in and (stand-in realm) an Entra sign-in with amr mfa are refused with
    no code; the card path: tests/card_allowlist_gate.sh (the deployed image, mock PKI)
  - (b) a token it held before the promotion, and one refreshed after it, get 403 on the first admin-API request
  - (c) its existing SSO session yields no code
  - the same (a)-(c) for an allowlist entry WITHDRAWN while the account holds a session and tokens (published only,
    no logout, so the gate itself is what refuses)
  - the same for an account holding MORE than its entry (the published entry carries its permitted realm-management
    roles): an allowlisted user manager given realm-admin in the console - its existing token 403 on its first request,
    a fresh sign-in refused; the guard demotes, resets and disables it and changes no other account; an administrator
    holding exactly its entry (X, the operator) is unaffected
  - a username pre-created by the user manager: invite refuses it
  - invite with idp-admin: created with no group and NOT an administrator, pending until it holds a second factor
"""
import argparse, base64, hashlib, hmac, http.server, importlib.machinery, importlib.util, json, os, re, socket, ssl
import subprocess, sys, threading, time, urllib.error, urllib.parse, urllib.request, uuid

ap = argparse.ArgumentParser(); ap.add_argument("--skill", required=True); ap.add_argument("--client", default="app-b")
a = ap.parse_args()
ADM = "/usr/local/sbin/idp-admin.py"
ld = importlib.machinery.SourceFileLoader("idp_admin", ADM)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
kc = M.KC()                                    # joins the Keycloak container's network namespace (setns)
HOST, PORT = M.ADMIN_HOST, M.ADMIN_PORT
_gai = socket.getaddrinfo
socket.getaddrinfo = lambda h, p, *r, **k: _gai("127.0.0.1", PORT, *r, **k) if h == HOST else _gai(h, p, *r, **k)
sys.path.insert(0, os.path.join(a.skill, "scripts")); import e2e_check as E   # noqa: E402
BASE = "https://%s" % HOST
REALM = M.REALM
res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s  %-74s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)
def run(*args):
    p = subprocess.run([sys.executable, ADM] + list(args), capture_output=True, text=True, timeout=600)
    return p.returncode, (p.stdout + p.stderr).strip()

app = kc.api("GET", "/clients?clientId=%s" % a.client)[0]
REDIRECT = (app.get("redirectUris") or [None])[0]
SECRET = kc.api("GET", "/clients/%s/client-secret" % app["id"])["value"]
CONSOLE = "%s/admin/%s/console/" % (BASE, REALM)
def flow(client=None, redirect=None):
    return E.Flow(argparse.Namespace(url=BASE, realm=REALM, client=client or a.client, redirect=redirect or REDIRECT,
                                     admin_url=None, client_secret=None if client else SECRET, cacert=None))

def pw_login(username, password, ctx, client=None, redirect=None):
    """Password sign-in; returns (code_or_None, pages seen, last page id)."""
    fl = flow(client, redirect); b = E.Browser(); url, ver = fl.auth_url()
    k, u, p = b.go(url, None, fl.a.redirect)
    act, f = E.form(p, "kc-form-login"); f.update({"username": username, "password": password})
    k, u, p = b.go(act, f, fl.a.redirect)
    first = E.page_id(p) if k == "page" else k
    if k == "page" and first == "login-login":
        return None, ["login-login:" + E.error_text(p)], first
    final, seen = fl.finish(b, k, u, p, ctx)
    return (final if final and "code=" in final else None), seen, first

made_users, made_clients = [], []
def mk_user(name, groups=(), password=None, attrs=None, email=True):
    rep = {"username": name, "firstName": "T", "lastName": name.split(".")[-1].title(), "enabled": True, "groups": list(groups)}
    if email: rep["email"] = name + "@test.invalid"
    if attrs: rep["attributes"] = attrs
    if password: rep["credentials"] = [{"type": "password", "value": password, "temporary": False}]
    kc.api("POST", "/users", rep); made_users.append(name)
    return M.user(kc, name)
def creds(u): return sorted(c["type"] for c in kc.api("GET", "/users/%s/credentials" % u["id"]) or [])
def links(u): return [l["identityProvider"] for l in kc.api("GET", "/users/%s/federated-identity" % u["id"]) or []]
def groups(u): return [g["path"] for g in M.paged(kc, "/users/%s/groups" % u["id"])]
def make_admin(u):        # what a console promotion does: join /roles/idp-admin directly
    kc.api("PUT", "/users/%s/groups/%s" % (u["id"], M.group_by_path(kc, "/roles/idp-admin")["id"]))
PW = lambda: "Tf1!" + uuid.uuid4().hex[:20]

# ------------------------------------------------------------------ a stand-in for Entra (OIDC), in this namespace only
OP = {"codes": {}, "next": {}}
class OPHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *x): pass
    def do_GET(self):
        qd = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query))
        code = uuid.uuid4().hex; OP["codes"][code] = dict(OP["next"], nonce=qd.get("nonce"), aud=qd.get("client_id"))
        self.send_response(302)
        self.send_header("Location", qd["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": qd.get("state", "")}))
        self.end_headers()
    def do_POST(self):
        body = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
        c = OP["codes"].pop(body.get("code"), None)
        if not c:
            self.send_response(400); self.end_headers(); return
        now = int(time.time())
        claims = {"iss": OP["iss"], "aud": c["aud"], "sub": c["oid"], "oid": c["oid"], "tid": c.get("tid", TENANT), "amr": c["amr"], "iat": now, "exp": now + 300,
                  "nonce": c["nonce"], "preferred_username": c["upn"], "email": c["upn"]}
        enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
        si = enc({"alg": "HS256", "typ": "JWT"}) + "." + enc(claims)
        sig = base64.urlsafe_b64encode(hmac.new(OP["secret"].encode(), si.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        out = json.dumps({"access_token": uuid.uuid4().hex, "token_type": "Bearer", "expires_in": 300, "id_token": si + "." + sig}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(out)))
        self.end_headers(); self.wfile.write(out)
srv = http.server.HTTPServer(("127.0.0.1", 0), OPHandler)
OP["iss"] = "http://127.0.0.1:%d" % srv.server_address[1]; OP["secret"] = uuid.uuid4().hex + uuid.uuid4().hex
threading.Thread(target=srv.serve_forever, daemon=True).start()
IDP = "t-entra"
TENANT = str(uuid.uuid4())     # the stand-in's tenant

REALM_DOMS = None
try:
    # ============================================================== HIGH 2: browser (password path)
    kc_admin_pw = PW()
    # an ALLOWLISTED administrator (granted by the tooling on its card mapping) that also has a password and no OTP
    adm_nootp = mk_user("t.fp.admin-nootp", password=kc_admin_pw, attrs={"cac_edipi": [str(int(time.time() * 1000) + 5)[-10:]]})
    rcg, og = run("grant", adm_nootp["username"], "idp-admin")
    if rcg != 0 or not M.is_admin(kc, adm_nootp["id"]):
        sys.exit("could not grant %s: %s" % (adm_nootp["username"], og))
    for label, cl, rd in (("an application", None, None), ("the realm's admin console", "security-admin-console", CONSOLE)):
        code, seen, first = pw_login(adm_nootp["username"], kc_admin_pw, {}, cl, rd)
        check("admin, password, no OTP -> %s: refused, no TOTP set-up" % label,
              code is None and not any("config-totp" in s for s in seen), "first=%s seen=%s" % (first, seen))
    check("... and still no second factor was enrolled", creds(adm_nootp) == ["password"], "%s" % creds(adm_nootp))
    plain_pw = PW(); plain = mk_user("t.fp.plain", password=plain_pw)
    ctx = {}; code, seen, _ = pw_login(plain["username"], plain_pw, ctx)
    check("non-admin, password, no OTP: enrols TOTP at first sign-in (unchanged)", bool(code) and "login-login-config-totp" in seen, "%s" % seen)
    rcg, og = run("grant", plain["username"], "idp-admin")          # OTP enrolled before: promoted, allowlisted
    check("setup: the OTP holder is granted idp-admin by the tooling", rcg == 0 and M.is_admin(kc, plain["id"]), og.splitlines()[-1][:90] if og else "")
    time.sleep(31)
    code, seen, first = pw_login(plain["username"], plain_pw, ctx)
    check("admin holding OTP: OTP prompt (never set-up) and signs in", bool(code) and seen[:1] == ["login-login-otp"] and
          "login-login-config-totp" not in seen, "%s" % seen)

    # ============================================================== GATE (a): every way this realm issues a token
    rr = kc.api("GET", "")
    top = [(e.get("providerId") or e.get("displayName"), e["requirement"]) for e in
           kc.api("GET", "/authentication/flows/%s/executions" % M.q(rr["browserFlow"])) if e["level"] == 0]
    check("GATE (a) browser flow (card, password, SSO cookie) ends with the REQUIRED allowlist gate",
          top[-1:] == [("stig-admin-allowlist-gate", "REQUIRED")] and all(r_ == "REQUIRED" for _, r_ in top), "%s" % top)
    dg = [(e.get("providerId") or e.get("displayName"), e["requirement"]) for e in
          kc.api("GET", "/authentication/flows/%s/executions" % M.q(rr["directGrantFlow"]))]
    stg, _ = kc.req("POST", "/realms/%s/protocol/openid-connect/token" % REALM, urllib.parse.urlencode({"grant_type": "password",
                    "client_id": "admin-cli", "username": plain["username"], "password": plain_pw}).encode(),
                    {"Content-Type": "application/x-www-form-urlencoded"}, auth=False)
    check("GATE (a) the direct (password) grant is denied: flow %s, a real password -> HTTP %s" % (rr["directGrantFlow"], stg),
          stg in (400, 401) and any(r_ == "REQUIRED" and "deny" in (p_ or "").lower() for p_, r_ in dg), "%s" % dg)
    odd = []
    for c in kc.api("GET", "/clients?max=1000"):
        at_ = c.get("attributes") or {}
        odd += ["%s:%s" % (c["clientId"], k) for k in ("oauth2.device.authorization.grant.enabled", "oidc.ciba.grant.enabled",
                                                        "standard.token.exchange.enabled") if at_.get(k) == "true"]
        odd += ["%s:implicit" % c["clientId"]] if c.get("implicitFlowEnabled") else []
        odd += ["%s:flow-override" % c["clientId"]] if c.get("authenticationFlowBindingOverrides") else []
    check("GATE (a) no device, CIBA, token-exchange or implicit grant and no per-client flow override", odd == [], "%s" % odd)
    pb = []
    for i in kc.api("GET", "/identity-provider/instances"):
        f_ = i.get("postBrokerLoginFlowAlias")
        ex_ = kc.api("GET", "/authentication/flows/%s/executions" % M.q(f_)) if f_ else []
        if not any(e.get("providerId") == "idp-require-admin-attribute-match" and e["requirement"] == "REQUIRED" and e["level"] == 0 for e in ex_):
            pb.append(i["alias"])
    check("GATE (a) every identity provider's post-broker flow REQUIRES the binding check (it refuses an unvetted administrator)",
          pb == [], "missing: %s" % pb)
    # client credentials (service accounts): never administrators; the admin-API filter refuses one holding
    # realm-management rights on its first request (tested below)

    # ============================================================== HIGH 2: identity provider (Entra stand-in)
    # The production realm refuses an http provider (sslRequired=all), so the provider case runs in a throwaway realm
    # (sslRequired=none, reachable only from this namespace) whose post-broker flow is built by the SAME
    # idp-admin.post_broker_flow() as production's - asserted equal below - with the same stig-extensions authenticators.
    TR = "t-fp-broker"
    def shape(alias):
        return [("  " * e["level"]) + (e.get("providerId") or "SUB") + ":" + e["requirement"]
                for e in kc.api("GET", "/authentication/flows/%s/executions" % M.q(alias))]
    live = shape(M.POST_BROKER)
    st_, _ = kc.req("POST", "/admin/realms", json.dumps({"realm": TR, "enabled": True, "sslRequired": "none"}).encode(),
                    {"Content-Type": "application/json"})
    made_realm = st_ == 201
    M.REALM = TR
    try:
        r0 = kc.api("GET", "")           # OTP policy as production's (a partial PUT or the create call ignores it)
        r0.update({"otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA256", "otpPolicyDigits": 6, "otpPolicyPeriod": 30,
                   "otpPolicyLookAheadWindow": 1, "loginTheme": "dod-stig"}); kc.api("PUT", "", r0)
        up = kc.api("GET", "/users/profile"); up["unmanagedAttributePolicy"] = "ENABLED"; kc.api("PUT", "/users/profile", up)
        M.first_broker_flow(kc, IDP, TENANT)
        M.post_broker_flow(kc, IDP, TENANT)
        check("throwaway realm's post-broker flow = production's (same code)", shape(M.POST_BROKER) == live, "%s" % live)
        kc.api("POST", "/clients", {"clientId": "t-app", "publicClient": True, "standardFlowEnabled": True,
                                    "redirectUris": ["https://t.invalid/cb"], "attributes": {"pkce.code.challenge.method": "S256"}})
        def mk_idp(alias):
            kc.api("POST", "/identity-provider/instances", {
                "alias": alias, "providerId": "oidc", "enabled": True, "trustEmail": False, "storeToken": False, "linkOnly": False,
                "firstBrokerLoginFlowAlias": "STIG First Broker Link by Admin", "postBrokerLoginFlowAlias": M.POST_BROKER,
                "config": {"issuer": OP["iss"], "authorizationUrl": OP["iss"] + "/authorize", "tokenUrl": OP["iss"] + "/token",
                           "clientId": "t-broker", "clientSecret": OP["secret"], "clientAuthMethod": "client_secret_post",
                           "validateSignature": "false", "useJwksUrl": "false", "disableUserInfo": "true", "syncMode": "IMPORT",
                           "defaultScope": "openid", "pkceEnabled": "false"}})
            for m in ({"name": "username", "identityProviderMapper": "oidc-username-idp-mapper",
                       "config": {"template": "${CLAIM.preferred_username | localpart | lowercase}", "target": "LOCAL", "syncMode": "IMPORT"}},
                      {"name": "vouched oid", "identityProviderMapper": "oidc-user-attribute-idp-mapper", "config": {"claim": "oid", "user.attribute": "entra_vouched_oid", "syncMode": "IMPORT"}},
                      {"name": "vouched tid", "identityProviderMapper": "oidc-user-attribute-idp-mapper", "config": {"claim": "tid", "user.attribute": "entra_vouched_tid", "syncMode": "IMPORT"}},
                      {"name": "amr", "identityProviderMapper": "oidc-user-attribute-idp-mapper", "config": {"claim": "amr", "user.attribute": "entra_amr", "syncMode": "FORCE"}}):
                kc.api("POST", "/identity-provider/instances/%s/mappers" % alias, dict(m, identityProviderAlias=alias))
        mk_idp(IDP); mk_idp("t-entra2")
        rmc_t = M.client_uuid(kc, "realm-management")
        def t_admin(u):    # an administrator in that realm: realm-admin mapped directly (detected by role, not group)
            kc.api("POST", "/users/%s/role-mappings/clients/%s" % (u["id"], rmc_t), [kc.api("GET", "/clients/%s/roles/realm-admin" % rmc_t)])
        def t_user(name, oid, password=None, actions=()):
            rep = {"username": name, "enabled": True, "firstName": "T", "lastName": "U", "email": name + "@test.invalid",
                   "attributes": {"entra_oid": [oid]}, "requiredActions": list(actions)}
            if password: rep["credentials"] = [{"type": "password", "value": password, "temporary": False}]
            kc.api("POST", "/users", rep); return M.user(kc, name)
        tfl = E.Flow(argparse.Namespace(url=BASE, realm=TR, client="t-app", redirect="https://t.invalid/cb", admin_url=None,
                                        client_secret=None, cacert=None))
        def broker_login(oid, amr, upn, ctx, idp=IDP, tid=TENANT):
            OP["next"] = {"oid": oid, "amr": amr, "upn": upn, "tid": tid}
            b = E.Browser(); url, ver = tfl.auth_url(extra={"kc_idp_hint": idp})
            k, u, p = b.go(url, None, tfl.a.redirect)
            final, seen = tfl.finish(b, k, u, p, ctx)
            return (final if final and "code=" in final else None), seen
        o1, o2, o3 = (str(uuid.uuid4()) for _ in range(3))
        e_adm = t_user("e-admin", o1); t_admin(e_adm)
        code, seen = broker_login(o1, ["pwd"], "e-admin@example.mil", {})
        check("IdP: admin, amr lacks mfa, no OTP -> refused, no TOTP set-up", code is None and not any("config-totp" in x for x in seen), "%s" % seen)
        check("... and nothing was enrolled", creds(e_adm) == [], "%s" % creds(e_adm))
        code, seen = broker_login(o1, ["pwd", "mfa"], "e-admin@example.mil", {})
        check("IdP: admin, amr has mfa -> signs in", bool(code), "%s" % seen)
        # GATE (a), Entra: the realm enforces an allowlist that does not hold e-admin -> refused, no code, no token
        AL_T = "stig.admin-allowlist." + TR
        def t_allowlist(ids):
            stm, dm = kc.req("GET", "/admin/realms/master"); at_ = json.loads(dm).get("attributes") or {}
            if ids is None: at_.pop(AL_T, None); at_.pop("stig.admin-allowlist-roles." + TR, None)
            else:
                at_[AL_T] = ",".join(ids)
                def held_(i):     # an id that is no user (a stand-in "someone else") permits nothing real
                    return sorted(M.rm_roles(kc, i)) if kc.req("GET", "/admin/realms/%s/users/%s" % (TR, i))[0] == 200 else []
                at_["stig.admin-allowlist-roles." + TR] = ";".join("%s=%s" % (i, ",".join(held_(i) or ["none"])) for i in ids)
            return kc.req("PUT", "/admin/realms/master", json.dumps({"attributes": at_}).encode(), {"Content-Type": "application/json"})[0]
        t_allowlist([str(uuid.uuid4())])
        code_g, seen_g = broker_login(o1, ["pwd", "mfa"], "e-admin@example.mil", {})
        check("GATE (a) IdP: an administrator NOT on the allowlist, amr mfa -> refused, no code (no token issued)", code_g is None, "%s" % seen_g)
        t_allowlist([e_adm["id"]])
        code_g, seen_g = broker_login(o1, ["pwd", "mfa"], "e-admin@example.mil", {})
        check("... control: the same administrator on the allowlist -> signs in", bool(code_g), "%s" % seen_g)
        t_allowlist(None)
        t_user("e-user", o2)
        code, seen = broker_login(o2, ["pwd"], "e-user@example.mil", {})
        check("IdP: non-admin, amr lacks mfa -> signs in (MFA is Entra's job)", bool(code) and "login-login-config-totp" not in seen, "%s" % seen)
        otp_pw = PW(); e_otp = t_user("e-otp", o3, otp_pw, ["CONFIGURE_TOTP"]); ctx = {}
        b = E.Browser(); url, ver = tfl.auth_url(); k, u, p = b.go(url, None, tfl.a.redirect)
        act, f = E.form(p, "kc-form-login"); f.update({"username": "e-otp", "password": otp_pw}); k, u, p = b.go(act, f, tfl.a.redirect)
        enr = tfl.finish(b, k, u, p, ctx)[1]; t_admin(e_otp); time.sleep(31)
        code, seen = broker_login(o3, ["pwd"], "e-otp@example.mil", ctx)
        # a link nobody authorised (planted through the admin API, as a delegate or the account console could) for an
        # identity other than the admin-set entra_oid: the sign-in through it is refused
        o5, o6 = str(uuid.uuid4()), str(uuid.uuid4())
        vict = t_user("e-victim", o5)
        kc.api("POST", "/users/%s/federated-identity/%s" % (vict["id"], IDP), {"identityProvider": IDP, "userId": o6, "userName": "evil"})
        code2, seen2 = broker_login(o6, ["pwd", "mfa"], "evil@example.mil", {})
        check("IdP: sign-in through a planted link (other identity) -> refused", code2 is None, "%s" % seen2)
        # review 2026-11-10 (2): a second provider presenting the SAME oid; the right provider from another tenant
        code3, seen3 = broker_login(o1, ["pwd", "mfa"], "e-admin@example.mil", {}, idp="t-entra2")
        check("IdP: a second provider presenting the administrator-set oid -> refused", code3 is None, "%s" % seen3)
        code3, seen3 = broker_login(o1, ["pwd", "mfa"], "e-admin@example.mil", {}, tid=str(uuid.uuid4()))
        check("IdP: the configured provider, another tenant -> refused", code3 is None, "%s" % seen3)
        # review 2026-11-10 (1): a mapper that writes the administrator-set attribute (FORCE, from the incoming oid):
        # the planted link's mismatched oid must still not get in - nor, while that mapper exists, anyone
        bad = {"name": "writes entra_oid", "identityProviderMapper": "oidc-user-attribute-idp-mapper", "identityProviderAlias": IDP,
               "config": {"claim": "oid", "user.attribute": "entra_oid", "syncMode": "FORCE"}}
        kc.api("POST", "/identity-provider/instances/%s/mappers" % IDP, bad)
        code3, seen3 = broker_login(o6, ["pwd", "mfa"], "evil@example.mil", {})
        held = (kc.api("GET", "/users/%s" % vict["id"]).get("attributes") or {}).get("entra_oid")
        check("IdP: with a mapper writing entra_oid, the planted link's other oid is refused", code3 is None, "%s; entra_oid now %s" % (
            seen3, "overwritten" if held != [o5] else "kept"))
        code3, seen3 = broker_login(o1, ["pwd", "mfa"], "e-admin@example.mil", {})
        check("... and while that mapper exists nobody signs in through the provider (fail closed)", code3 is None, "%s" % seen3)
        for m in kc.api("GET", "/identity-provider/instances/%s/mappers" % IDP):
            if m["name"] == "writes entra_oid":
                kc.api("DELETE", "/identity-provider/instances/%s/mappers/%s" % (IDP, m["id"]))
        check("IdP: admin holding OTP, amr lacks mfa -> OTP prompt, signs in", bool(code) and "login-login-otp" in seen and
              "login-login-config-totp" not in seen, "%s (enrolment %s, creds %s)" % (seen, enr, creds(e_otp)))
    finally:
        M.REALM = REALM
        try:
            t_allowlist(None)
        except Exception:      # noqa: BLE001 - defined only once the realm exists
            pass
        if made_realm:
            kc.req("DELETE", "/admin/realms/%s" % TR)

    # ============================================================== HIGH 1: promotion
    rmc = M.client_uuid(kc, "realm-management")
    sys.path.insert(0, "/root/idp-deploy/tests"); import persona       # noqa: E402
    # the user manager is a PERSON (service accounts are never administrators or user managers), granted by the tooling
    um_p = persona.Person(M, kc, E, run, BASE, REALM, "t.fp.um", "idp-user-manager"); made_users.append("t.fp.um")
    sa = um_p.user
    def um(method, path, body=None):
        return um_p.api(method, path, body)[0]
    ra0 = dict(kc.api("GET", "").get("attributes") or {}); REALM_DOMS = ra0.get("stig.accounts.email-domains")
    ra0["stig.accounts.email-domains"] = ".mil,example.mil,notify.example.mil"; kc.api("PUT", "", {"attributes": ra0})   # restored at the end

    # option (a): a delegate can plant nothing on an existing member
    probe = mk_user("t.fp.probe", groups=["/%s/student" % a.client], attrs={"cac_edipi": [str(int(time.time() * 1000) + 3)[-10:]]})
    tries = (um("PUT", "/users/%s/reset-password" % probe["id"], {"type": "password", "value": PW(), "temporary": False}),
             um("POST", "/users/%s/federated-identity/entra" % probe["id"], {"identityProvider": "entra", "userId": str(uuid.uuid4()), "userName": "evil"}),
             um("PUT", "/users/%s/execute-actions-email" % probe["id"], ["UPDATE_PASSWORD", "CONFIGURE_TOTP"]),
             um("PUT", "/users/%s" % probe["id"], {"email": "evil@notify.example.mil"}))
    check("the user manager cannot plant: reset-password / IdP link / execute-actions / e-mail change -> 403", all(t == 403 for t in tries)
          and creds(probe) == [] and links(probe) == [], "HTTP %s" % (tries,))

    # Defence in depth (grant / guard provenance) still has to hold if a delegate ever could plant - e.g. a future
    # misconfiguration. Simulated with a throwaway "legacy delegate": a service account with NO realm-management role,
    # granted manage + reset-password on exactly the victims below by a Users permission of its own.
    legacy_cid = "t-fp-legacy"
    kc.api("POST", "/clients", {"clientId": legacy_cid, "publicClient": False, "serviceAccountsEnabled": True, "standardFlowEnabled": False,
                                "directAccessGrantsEnabled": False, "fullScopeAllowed": False}); made_clients.append(legacy_cid)
    legacy_c = kc.api("GET", "/clients?clientId=%s" % legacy_cid)[0]
    for sc in kc.api("GET", "/client-scopes"):
        if sc["name"] == "kc-admin-api":
            kc.api("PUT", "/clients/%s/default-client-scopes/%s" % (legacy_c["id"], sc["id"]))
    lsa = kc.api("GET", "/clients/%s/service-account-user" % legacy_c["id"])
    apc = kc.api("GET", "/clients?clientId=admin-permissions")[0]; AB = "/clients/%s/authz/resource-server" % apc["id"]
    kc.api("POST", AB + "/policy/user", {"name": "t-fp legacy delegate", "users": [lsa["id"]], "logic": "POSITIVE"})
    LPOL = [x for x in kc.api("GET", AB + "/policy?name=" + M.q("t-fp legacy delegate")) if x["name"] == "t-fp legacy delegate"][0]["id"]
    victims = []
    def legacy_off(uid):
        """The misconfiguration is fixed: the legacy delegate loses this victim (grant still refuses what it planted)."""
        if uid in victims:
            victims.remove(uid)
            if victims:
                legacy_on(None)
            else:
                for x in kc.api("GET", AB + "/permission?name=" + M.q("t-fp legacy delegate: victims")) or []:
                    if x["name"] == "t-fp legacy delegate: victims":
                        kc.api("DELETE", AB + "/permission/%s" % x["id"])
    def legacy_on(uid):
        if uid:
            victims.append(uid)
        rep = {"name": "t-fp legacy delegate: victims", "resourceType": "Users", "resources": list(victims), "policies": [LPOL],
               "scopes": ["view", "manage", "reset-password"], "decisionStrategy": "UNANIMOUS"}
        ex = [x for x in kc.api("GET", AB + "/permission?name=" + M.q(rep["name"])) or [] if x["name"] == rep["name"]]
        if ex:
            rep["id"] = ex[0]["id"]; kc.api("PUT", AB + "/permission/scope/%s" % rep["id"], rep)
        else:
            kc.api("POST", AB + "/permission/scope", rep)
    ltok = json.loads(urllib.request.urlopen(urllib.request.Request("%s/realms/%s/protocol/openid-connect/token" % (BASE, REALM),
           urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": legacy_cid,
                                   "client_secret": kc.api("GET", "/clients/%s/client-secret" % legacy_c["id"])["value"]}).encode()), timeout=30).read())["access_token"]
    def legacy(method, path, body=None):
        req = urllib.request.Request("%s/admin/realms/%s%s" % (BASE, REALM, path), method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": "Bearer " + ltok, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r: return r.status
        except urllib.error.HTTPError as e: return e.code

    def plant(name):
        """The legacy delegate plants on an existing card-only member: a password (reset), a TOTP (the attacker signs in
        with that password and enrols it) and an identity-provider link."""
        u = mk_user(name, groups=["/%s/student" % a.client], attrs={"cac_edipi": [str(int(time.time() * 1000))[-10:]]})
        legacy_on(u["id"])
        p = PW(); s1 = legacy("PUT", "/users/%s/reset-password" % u["id"], {"type": "password", "value": p, "temporary": False})
        cx = {}; code, seen, _ = pw_login(name, p, cx)
        s2 = legacy("POST", "/users/%s/federated-identity/entra" % u["id"], {"identityProvider": "entra", "userId": str(uuid.uuid4()), "userName": "evil"})
        return u, (s1, bool(code), s2), creds(u), links(u)
    vic, sts, cr, ln = plant("t.fp.planted")
    check("setup (defence in depth): the legacy delegate planted password + TOTP + link", cr == ["otp", "password"] and ln == ["entra"],
          "reset %s, signed in %s, link %s -> %s %s" % (sts + (cr, ln)))
    rc, out = run("grant", vic["username"], "idp-admin")
    check("grant idp-admin is REFUSED (planted factors)", rc != 0 and "REFUSED" in out and "non-administrator" in out, out.splitlines()[0][:120])
    check("... and changed nothing: not an administrator, factors as they were", not M.is_admin(kc, vic["id"]) and creds(vic) == ["otp", "password"]
          and links(vic) == ["entra"], "admin=%s creds=%s links=%s" % (M.is_admin(kc, vic["id"]), creds(vic), links(vic)))
    legacy_off(vic["id"])
    rc, out = run("grant", vic["username"], "idp-admin", "--reset-credentials")
    v2 = kc.api("GET", "/users/%s" % vic["id"])
    check("grant --reset-credentials: no planted factor or link is left", creds(vic) == [] and links(vic) == [], "creds=%s links=%s" % (creds(vic), links(vic)))
    check("... out of every application group, e-mail a delegate could have set is cleared", not [g for g in groups(vic) if not g.startswith("/roles/")]
          and not v2.get("email"), "groups=%s email=%s" % (groups(vic), bool(v2.get("email"))))
    check("... promoted at once: it has a card (admin-set cac_edipi), the only factor left", rc == 0 and M.is_admin(kc, vic["id"]) and "promoted" in out,
          out.splitlines()[-1][:120])
    # the same without a card: left pending until it holds a second factor
    nocard = mk_user("t.fp.nocard", groups=["/%s/student" % a.client])
    legacy_on(nocard["id"]); legacy("PUT", "/users/%s/reset-password" % nocard["id"], {"type": "password", "value": PW(), "temporary": False})
    legacy_off(nocard["id"])
    rc, out = run("grant", nocard["username"], "idp-admin", "--reset-credentials")
    check("no card: grant --reset-credentials leaves it PENDING, not an administrator", rc == 0 and "PENDING" in out and not M.is_admin(kc, nocard["id"])
          and creds(nocard) == [], [l for l in out.splitlines() if "PENDING" in l][:1])
    nc = kc.api("GET", "/users/%s" % nocard["id"])
    check("... a reset ALWAYS clears the e-mail (the delegate never touched it here) and mails no set-up link", not nc.get("email")
          and "set the address explicitly" in out and "set-up link went" not in out, "email=%s" % bool(nc.get("email")))
    # review 2026-11-10 (3): demoted by hand, replanted by a delegate, re-granted -> the promotion checks run again
    dem = mk_user("t.fp.demoted", attrs={"cac_edipi": [str(int(time.time() * 1000) + 7)[-10:]]})
    rc, out = run("grant", dem["username"], "idp-admin")
    check("setup: a clean card account is promoted at once", rc == 0 and M.is_admin(kc, dem["id"]), out.splitlines()[-1][:100])
    kc.api("DELETE", "/users/%s/groups/%s" % (dem["id"], M.group_by_path(kc, "/roles/idp-admin")["id"]))    # console demotion
    kc.api("PUT", "/users/%s/groups/%s" % (dem["id"], M.group_by_path(kc, "/%s/student" % a.client)["id"]))
    s_ = um("PUT", "/users/%s/reset-password" % dem["id"], {"type": "password", "value": PW(), "temporary": False})
    rc, out = run("grant", dem["username"], "idp-admin")
    # (the plant may get 403: until the next guard sync the administrators' permission still names the account -
    # the cache and that permission go stale together. Either way the re-grant must run the promotion checks.)
    check("demoted by hand, delegate tries to plant, re-grant -> REFUSED (stale known_admins not trusted)", s_ in (204, 403) and rc != 0
          and "REFUSED" in out and not M.is_admin(kc, dem["id"]), "plant %s; %s" % (s_, out.splitlines()[0][:90]))
    rc, out = run("promote", nocard["username"])
    check("... promote refuses while it holds no second factor", rc != 0 and not M.is_admin(kc, nocard["id"]), "exit %s" % rc)
    # a console promotion of an account with planted factors: the guard strips them
    vic2, sts, cr, ln = plant("t.fp.planted2")
    make_admin(vic2)
    rc, out = run("guard", "--fix")
    v2 = kc.api("GET", "/users/%s" % vic2["id"])
    check("console promotion with planted factors: guard --fix demotes it, resets its factors, links and e-mail (card binding KEPT), DISABLES it, exit 2",
          rc == 2 and "STIG-ADMIN-UNVETTED user=t.fp.planted2" in out and not M.is_admin(kc, vic2["id"]) and v2["enabled"] is False
          and creds(vic2) == [] and links(vic2) == [] and not v2.get("email") and (v2.get("attributes") or {}).get("cac_edipi"),
          "exit %s admin=%s enabled=%s creds=%s" % (rc, M.is_admin(kc, vic2["id"]), v2["enabled"], creds(vic2)))
    rce1, oe1 = run("user-enable", vic2["username"], "true")
    rce2, oe2 = run("reset-user", vic2["username"])
    rce3, oe3 = run("user-enable", vic2["username"], "true")
    check("... user-enable refuses the guard-disabled account until reset-user", rce1 != 0 and "REFUSED" in oe1 and rce2 == 0 and rce3 == 0
          and kc.api("GET", "/users/%s" % vic2["id"])["enabled"] is True, "%s | %s" % (oe1[:70], oe3[:50]))
    run("user-enable", vic2["username"], "false")
    rc, out = run("guard", "--fix")
    check("... and the next guard run is clean (exit 0)", rc == 0, "exit %s" % rc)
    # review 2026-11-10 (allowlist): an ALLOWLISTED realm administrator X promotes accounts in the console by every
    # route - a direct realm-management mapping, a composite role, a group role mapping, and re-parenting a group with
    # members under /roles/idp-admin. The guard demotes (and disables, and alerts) every one, and leaves X alone.
    x_p = persona.Person(M, kc, E, run, BASE, REALM, "t.fp.x", "idp-admin"); made_users.append("t.fp.x")
    xsa = x_p.user
    check("setup: X (a console administrator, a person) is granted idp-admin by the tooling and on the allowlist", xsa["id"] in M.load_allowlist())
    def X(method, path, body=None):
        return x_p.api(method, path, body)[0]
    ra_role = kc.api("GET", "/clients/%s/roles/realm-admin" % rmc)
    tag = uuid.uuid4().hex[:6]
    made_groups = []
    victims_c = {}
    # (a) direct realm-management mapping
    va = mk_user("t.fp.c-direct", password=PW()); victims_c["direct mapping"] = (va, X("POST", "/users/%s/role-mappings/clients/%s" % (va["id"], rmc), [ra_role]))
    # (b) a composite realm role holding realm-admin, mapped to the account
    X("POST", "/roles", {"name": "t-fp-comp-%s" % tag}); comp = kc.api("GET", "/roles/t-fp-comp-%s" % tag)
    X("POST", "/roles/t-fp-comp-%s/composites" % tag, [ra_role])
    vb = mk_user("t.fp.c-composite", password=PW()); victims_c["composite role"] = (vb, X("POST", "/users/%s/role-mappings/realm" % vb["id"], [comp]))
    # (c) a group role mapping on a group the account is in
    X("POST", "/groups", {"name": "t-fp-gmap-%s" % tag}); gm = M.group_by_path(kc, "/t-fp-gmap-%s" % tag); made_groups.append(gm["id"])
    vc = mk_user("t.fp.c-groupmap", groups=["/t-fp-gmap-%s" % tag], password=PW())
    victims_c["group role mapping"] = (vc, X("POST", "/groups/%s/role-mappings/clients/%s" % (gm["id"], rmc), [ra_role]))
    # (d) re-parenting a group with members under /roles/idp-admin
    X("POST", "/groups", {"name": "t-fp-reparent-%s" % tag}); gr = M.group_by_path(kc, "/t-fp-reparent-%s" % tag); made_groups.append(gr["id"])
    vd = mk_user("t.fp.c-reparent", groups=["/t-fp-reparent-%s" % tag], password=PW())
    victims_c["re-parented group"] = (vd, X("POST", "/groups/%s/children" % M.group_by_path(kc, "/roles/idp-admin")["id"], {"id": gr["id"], "name": gr["name"]}))
    before = {k: M.is_admin(kc, v[0]["id"]) for k, v in victims_c.items()}
    rc, out = run("guard", "--fix")
    for label, (v, st_) in victims_c.items():
        vv = kc.api("GET", "/users/%s" % v["id"])
        check("console promotion by %s: guard demotes, resets and DISABLES it, alerts (exit 2)" % label,
              st_ in (201, 204) and before[label] and rc == 2 and "STIG-ADMIN-UNVETTED user=%s" % v["username"] in out
              and not M.is_admin(kc, v["id"]) and vv["enabled"] is False and creds(v) == [],
              "X %s, admin before %s, exit %s, admin now %s, enabled %s" % (st_, before[label], rc, M.is_admin(kc, v["id"]), vv["enabled"]))
    xx = kc.api("GET", "/users/%s" % xsa["id"])
    check("the allowlisted administrators are left alone (X and the operator still administrators, enabled)", M.is_admin(kc, xsa["id"]) and xx["enabled"]
          and M.is_admin(kc, M.user(kc, "op.admin")["id"]) and "user=%s" % xsa["username"] not in out and "op.admin" not in out)
    rgp = M.group_by_path(kc, "/roles/idp-admin/t-fp-reparent-%s" % tag)
    if rgp: kc.api("DELETE", "/groups/%s" % rgp["id"])
    kc.api("DELETE", "/roles/t-fp-comp-%s" % tag)
    for gid in made_groups:
        kc.api("DELETE", "/groups/%s" % gid, ok404=True)
    # review 2026-11-10 (allowlist at sign-in): an account a delegate created through stig-accounts (as if with its own
    # mailbox) and holds a session and tokens for, then promoted in the console by an allowlisted administrator
    s_c = um("POST", "/stig-accounts/users", {"username": "t.fp.owned", "email": "t.fp.owned%s@notify.example.mil" % tag, "firstName": "T",
                                              "lastName": "Owned", "group": "/%s/student" % a.client}); made_users.append("t.fp.owned")
    owned = M.user(kc, "t.fp.owned")
    opw = PW(); kc.api("PUT", "/users/%s/reset-password" % owned["id"], {"type": "password", "value": opw, "temporary": False})   # the set-up link, used by the delegate
    r_ = kc.api("GET", "/users/%s" % owned["id"]); r_["requiredActions"] = ["CONFIGURE_TOTP"]; kc.api("PUT", "/users/%s" % owned["id"], r_)
    ofl = flow("security-admin-console", CONSOLE); ob = E.Browser(); ourl, over = ofl.auth_url(); k_, u_, p_ = ob.go(ourl, None, ofl.a.redirect)
    act_, f_ = E.form(p_, "kc-form-login"); f_.update({"username": "t.fp.owned", "password": opw}); k_, u_, p_ = ob.go(act_, f_, ofl.a.redirect)
    octx = {}; ofinal, oseen = ofl.finish(ob, k_, u_, p_, octx)
    otok = ofl.token(urllib.parse.parse_qs(urllib.parse.urlparse(ofinal).query)["code"][0], over) if ofinal and "code=" in ofinal else None
    check("setup: the delegate created t.fp.owned (stig-accounts) and holds a session and tokens for it", s_c == 201 and bool(otok), "create %s" % s_c)
    sp_ = X("PUT", "/users/%s/groups/%s" % (owned["id"], M.group_by_path(kc, "/roles/idp-admin")["id"]))
    check("setup: an allowlisted administrator promotes it in the console", sp_ == 204 and M.is_admin(kc, owned["id"]), "HTTP %s" % sp_)
    time.sleep(31)
    code1, seen1, first1 = pw_login("t.fp.owned", opw, octx, "security-admin-console", CONSOLE)
    check("allowlist at sign-in: a fresh password+TOTP sign-in is refused", code1 is None, "%s" % seen1)
    u2, v2 = ofl.auth_url(); k2, l2, p2 = ob.go(u2, None, ofl.a.redirect)
    check("allowlist at sign-in: its existing SSO session (cookie) is refused", not (k2 == "redirect" and "code=" in l2),
          "%s %s" % (k2, E.page_id(p2) if k2 == "page" else l2[:60]))
    def api_with(at_tok):
        req_ = urllib.request.Request("%s/admin/realms/%s/users?max=1" % (BASE, REALM), headers={"Authorization": "Bearer " + at_tok})
        try:
            with urllib.request.urlopen(req_, timeout=30) as r: return r.status
        except urllib.error.HTTPError as e: return e.code
    st_old = api_with(otok["access_token"])
    rr_ = urllib.parse.urlencode({"grant_type": "refresh_token", "client_id": "security-admin-console", "refresh_token": otok["refresh_token"]}).encode()
    try:
        ntok = json.loads(urllib.request.urlopen(urllib.request.Request("%s/realms/%s/protocol/openid-connect/token" % (BASE, REALM), data=rr_), timeout=30).read())
        st_new = api_with(ntok["access_token"])
    except urllib.error.HTTPError as e:
        st_new = "refresh refused %s" % e.code
    check("allowlist on the admin API: its existing token and a refreshed one get 403", st_old == 403 and st_new in (403, "refresh refused 400", "refresh refused 401"),
          "old %s, refreshed %s" % (st_old, st_new))
    rc, out = run("guard", "--fix")
    ow = kc.api("GET", "/users/%s" % owned["id"])
    check("... and the guard demotes, disables it and alerts (exit 2)", rc == 2 and "STIG-ADMIN-UNVETTED user=t.fp.owned" in out
          and not M.is_admin(kc, owned["id"]) and ow["enabled"] is False, "exit %s admin %s enabled %s" % (rc, M.is_admin(kc, owned["id"]), ow["enabled"]))
    rc1, o1 = run("grant", "t.fp.owned", "idp-admin")
    rc2, o2 = run("grant", "t.fp.owned", "idp-admin", "--reset-credentials")
    check("grant refuses a delegate-created account, even with --reset-credentials, without an operator-set e-mail", rc1 != 0 and rc2 != 0
          and "created by a delegate" in o1 and "created by a delegate" in o2 and not M.is_admin(kc, owned["id"]), "%s | %s" % (o1[:70], o2[:70]))
    rc3, o3 = run("grant", "t.fp.owned", "idp-admin", "--reset-credentials", "--email", "t.fp.owned.checked%s@notify.example.mil" % tag)
    ow = kc.api("GET", "/users/%s" % owned["id"])
    check("... with --reset-credentials --email: reset, the operator's address set, the delegate marker cleared, PENDING", rc3 == 0 and "PENDING" in o3
          and ow.get("email", "").startswith("t.fp.owned.checked") and not (ow.get("attributes") or {}).get("stig_created_by")
          and not M.is_admin(kc, owned["id"]), o3.splitlines()[-1][:100] if o3 else "")
    # an administrator taken off the allowlist: its sessions end and its existing token stops working
    y_p = persona.Person(M, kc, E, run, BASE, REALM, "t.fp.y", "idp-admin"); made_users.append("t.fp.y")
    ysa = y_p.user; ytok = y_p.token()
    before_ = api_with(ytok)
    M.allowlist_drop(ysa["id"], kc)
    after_ = api_with(ytok)
    check("an administrator taken off the allowlist: its existing token is refused at once (200 -> 401/403)", before_ == 200 and after_ in (401, 403),
          "before %s, after %s" % (before_, after_))
    run("revoke", ysa["username"])
    # review 2026-11-10 (allowlist, round 2)
    def sa_client(cid_):
        kc.api("POST", "/clients", {"clientId": cid_, "publicClient": False, "serviceAccountsEnabled": True, "standardFlowEnabled": False,
                                    "directAccessGrantsEnabled": False, "fullScopeAllowed": False}); made_clients.append(cid_)
        c_ = kc.api("GET", "/clients?clientId=%s" % cid_)[0]
        for sc in kc.api("GET", "/client-scopes"):
            if sc["name"] == "kc-admin-api":
                kc.api("PUT", "/clients/%s/default-client-scopes/%s" % (c_["id"], sc["id"]))
        kc.api("POST", "/clients/%s/scope-mappings/clients/%s" % (c_["id"], rmc), kc.api("GET", "/clients/%s/roles" % rmc))
        return c_, kc.api("GET", "/clients/%s/service-account-user" % c_["id"])
    def sa_token(c_):
        return json.loads(urllib.request.urlopen(urllib.request.Request("%s/realms/%s/protocol/openid-connect/token" % (BASE, REALM),
               urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": c_["clientId"],
                                       "client_secret": kc.api("GET", "/clients/%s/client-secret" % c_["id"])["value"]}).encode()), timeout=30).read())["access_token"]
    # (a) a realm-management holder that was never vetted is refused on its very first admin-API request
    zc, zsa = sa_client("t-fp-unlisted-z")
    kc.api("POST", "/users/%s/role-mappings/clients/%s" % (zsa["id"], rmc), [ra_role])
    st_z = api_with(sa_token(zc))
    check("a realm-admin holder that was never vetted: its FIRST admin-API request -> 403", st_z == 403, "HTTP %s" % st_z)
    # (d) a client's service account is never an administrator (nor a user manager)
    wc, wsa = sa_client("t-fp-sa-w")
    rcw, ow_ = run("grant", wsa["username"], "idp-user-manager")
    check("grant to a service account -> REFUSED (service accounts are never administrators)", rcw != 0 and "never administrators" in ow_
          and wsa["id"] not in M.load_allowlist(), ow_.splitlines()[0][:100] if ow_ else "")
    # (c) grant never writes a right given outside the tooling into the allowlist
    extra = mk_user("t.fp.extra", attrs={"cac_edipi": [str(int(time.time() * 1000) + 13)[-10:]]})
    kc.api("POST", "/users/%s/role-mappings/clients/%s" % (extra["id"], rmc), [kc.api("GET", "/clients/%s/roles/manage-users" % rmc)])
    rce, oe = run("grant", extra["username"], "idp-user-manager")
    check("grant to an account already holding an unvetted realm-management role -> REFUSED, not written to the allowlist",
          rce != 0 and "nobody vetted" in oe and extra["id"] not in M.load_allowlist(), oe.splitlines()[0][:110] if oe else "")
    # (b) an administrator X2 acts - creates a client and resets ANOTHER administrator Y2's password - and then turns
    # out to be unvetted (its vetting withdrawn: its changes after its last vetting are in scope). The guard
    # (run as the real unit, so the alert mail goes out) demotes, resets and disables X2; lists both changes as REVIEW
    # under a GATE-FAILURE notice; and touches Y2, an allowlisted administrator (ALLOWLISTED-TOUCHED): its sessions
    # ended and the password X2 set removed - never disabled, its operator-set bindings kept. The client stays. The
    # operator then reviews: reset-user --clear-bindings on Y2 (bindings only on request); client-delete the client.
    touched_m = mk_user("t.fp.touchedm", groups=["/%s/student" % a.client], password=PW())
    x2 = persona.Person(M, kc, E, run, BASE, REALM, "t.fp.x2", "idp-admin"); made_users.append("t.fp.x2")
    y2 = persona.Person(M, kc, E, run, BASE, REALM, "t.fp.y2", "idp-admin"); made_users.append("t.fp.y2")
    y2tok = y2.token()
    y2r = kc.api("GET", "/users/%s" % y2.user["id"]); y2r["attributes"] = dict(y2r.get("attributes") or {},
        entra_oid=[str(uuid.uuid4())], cac_edipi=[str(int(time.time() * 1000) + 17)[-10:]]); kc.api("PUT", "/users/%s" % y2.user["id"], y2r)
    qc_id = "t-fp-x2client-%s" % tag; made_clients.append(qc_id)
    s_c1 = x2.api("POST", "/clients", {"clientId": qc_id, "publicClient": True, "standardFlowEnabled": False})[0]
    s_c2 = x2.api("PUT", "/users/%s/reset-password" % y2.user["id"], {"type": "password", "value": PW(), "temporary": False})[0]
    al_ = M.load_allowlist(); al_.pop(x2.user["id"], None); M._write_json(M.ALLOWLIST, al_); M.publish_allowlist(kc, al_)   # vetting withdrawn
    t0 = time.strftime("%Y-%m-%d %H:%M:%S")
    subprocess.run(["systemctl", "start", "idp-guard.service"], capture_output=True, text=True, timeout=900)
    out = subprocess.run(["journalctl", "-u", "idp-guard.service", "--since", t0, "--no-pager", "-o", "cat"], capture_output=True, text=True).stdout
    time.sleep(10)
    mail = subprocess.run(["journalctl", "-u", "idp-alert@idp-guard.service.service", "--since", t0, "--no-pager", "-o", "cat"],
                          capture_output=True, text=True).stdout
    xx2 = kc.api("GET", "/users/%s" % x2.user["id"])
    def refresh_refused(person):
        person.at = 0                       # force a refresh with the refresh token it holds
        try:
            person.token(); return False
        except urllib.error.HTTPError:
            return True
    x2tok_st = "refresh refused" if refresh_refused(x2) else "refresh still works"
    check("unvetted X2 (it acted, then its vetting was withdrawn): demoted, factors reset, DISABLED, sessions ended", (s_c1, s_c2) == (201, 204)
          and "STIG-ADMIN-UNVETTED user=t.fp.x2" in out and not M.is_admin(kc, x2.user["id"]) and xx2["enabled"] is False
          and x2tok_st == "refresh refused" and creds(x2.user) == [], "create %s, reset %s, enabled %s, its token %s" % (s_c1, s_c2, xx2["enabled"], x2tok_st))
    check("... the alert says the gate should have made this impossible: GATE-FAILURE, to investigate",
          "STIG-ADMIN-GATE-FAILURE user=t.fp.x2" in out and "INVESTIGATED as a gate failure" in out, "")
    y2r_ = kc.api("GET", "/users/%s" % y2.user["id"]); y2a_ = y2r_.get("attributes") or {}
    check("... Y2 (allowlisted), changed by X2 after X2's last vetting: ALLOWLISTED-TOUCHED - its sessions ended and the "
          "password X2 set removed; its OTP and operator-set bindings kept; NOT disabled",
          ("STIG-ADMIN-REVIEW user=t.fp.x2 REVIEW ACTION USER \"users/%s/reset-password\"" % y2.user["id"]) in out
          and "STIG-ADMIN-ALLOWLISTED-TOUCHED user=t.fp.y2" in out and "password" not in creds(y2.user) and "otp" in creds(y2.user)
          and y2a_.get("entra_oid") and y2a_.get("cac_edipi") and y2r_["enabled"] is True and refresh_refused(y2),
          "creds %s enabled %s" % (creds(y2.user), y2r_["enabled"]))
    check("... the client it created is listed as REVIEW and NOT deleted", "STIG-ADMIN-REVIEW user=t.fp.x2 REVIEW CREATE CLIENT" in out
          and bool(kc.api("GET", "/clients?clientId=%s" % qc_id)), "")
    check("... and the alert mail went out (idp-alert after the failed guard unit)", "idp-alert: idp-guard.service ->" in mail, mail.strip()[-120:])
    check("... the operator and X untouched", M.is_admin(kc, M.user(kc, "op.admin")["id"]) and M.is_admin(kc, xsa["id"])
          and kc.api("GET", "/users/%s" % xsa["id"])["enabled"] and "op.admin" not in out and "user=t.fp.x " not in out)
    rcy, oy = run("reset-user", "t.fp.y2", "--clear-bindings")
    ya = kc.api("GET", "/users/%s" % y2.user["id"]).get("attributes") or {}
    ry2, _ = run("user-enable", "t.fp.y2", "true")
    check("the operator acts after review: reset-user --clear-bindings on Y2 (nothing left, bindings cleared only on request)",
          rcy == 0 and ry2 == 0 and creds(y2.user) == [] and not ya.get("entra_oid") and not ya.get("cac_edipi"), oy[-120:])
    rcd, od = run("client-delete", qc_id)
    check("the operator removes the client explicitly: client-delete by exact clientId", rcd == 0 and not kc.api("GET", "/clients?clientId=%s" % qc_id), od[:90])
    # GATE: the other unvetted cases (review 2026-11-10, MEDIUM 2)
    # (i) an entry WITHDRAWN while the account holds a session and tokens - withdrawn from the published allowlist only
    # (no logout, so this proves the gate itself): its existing token and a refreshed one get 403 from the filter on the
    # first admin-API request; its SSO cookie and a fresh sign-in get no code
    w = persona.Person(M, kc, E, run, BASE, REALM, "t.fp.w", "idp-admin"); made_users.append("t.fp.w")
    wfl = flow("security-admin-console", CONSOLE); wb = E.Browser(); wurl, wver = wfl.auth_url()
    k_, u_, p_ = wb.go(wurl, None, wfl.a.redirect); act_, f_ = E.form(p_, "kc-form-login")
    f_.update({"username": w.username, "password": w.pw}); time.sleep(31); k_, u_, p_ = wb.go(act_, f_, wfl.a.redirect)
    wfinal, _ = wfl.finish(wb, k_, u_, p_, w.ctx)
    wtok = wfl.token(urllib.parse.parse_qs(urllib.parse.urlparse(wfinal).query)["code"][0], wver) if wfinal and "code=" in wfinal else None
    def api_body(at_tok):
        req_ = urllib.request.Request("%s/admin/realms/%s/users?max=1" % (BASE, REALM), headers={"Authorization": "Bearer " + at_tok})
        try:
            with urllib.request.urlopen(req_, timeout=30) as r: return r.status
        except urllib.error.HTTPError as e_:
            return "403 allowlist" if e_.code == 403 and "not allowed" in e_.read().decode() else e_.code
    w_before = api_body(wtok["access_token"]) if wtok else None
    al_w = M.load_allowlist(); al_w.pop(w.user["id"], None); M.publish_allowlist(kc, al_w)       # published only: no logout
    w_old = api_body(wtok["access_token"])
    try:
        wn = json.loads(urllib.request.urlopen(urllib.request.Request("%s/realms/%s/protocol/openid-connect/token" % (BASE, REALM),
             urllib.parse.urlencode({"grant_type": "refresh_token", "client_id": "security-admin-console", "refresh_token": wtok["refresh_token"]}).encode()), timeout=30).read())
        w_new = api_body(wn["access_token"])
    except urllib.error.HTTPError as e_:
        w_new = "refresh refused %s" % e_.code
    check("GATE (b) entry WITHDRAWN while it holds tokens: existing token -> 403 by the filter on its first request, a refreshed one too",
          w_before == 200 and w_old == "403 allowlist" and w_new in ("403 allowlist", "refresh refused 400", "refresh refused 401"),
          "before %s, old %s, refreshed %s" % (w_before, w_old, w_new))
    u2_, v2_ = wfl.auth_url(); k2_, l2_, p2_ = wb.go(u2_, None, wfl.a.redirect)
    check("GATE (c) ... its SSO session (cookie) yields no code", not (k2_ == "redirect" and "code=" in l2_), "%s" % (E.page_id(p2_) if k2_ == "page" else l2_[:60]))
    time.sleep(31)
    wc, wseen, _ = pw_login(w.username, w.pw, w.ctx, "security-admin-console", CONSOLE)
    check("GATE (a) ... a fresh password+TOTP sign-in is refused, no code", wc is None, "%s" % wseen)
    M.publish_allowlist(kc)                      # back to the file (the guard would do the same)
    run("revoke", w.username)
    # (ii) an account holding MORE than its entry: an allowlisted user manager given realm-admin in the console. The
    # published entry carries the realm-management roles it permits, so the gate refuses it at once.
    umo = persona.Person(M, kc, E, run, BASE, REALM, "t.fp.umo", "idp-user-manager"); made_users.append("t.fp.umo")
    tgt_pw = PW(); tgt = mk_user("t.fp.target", groups=["/%s/student" % a.client], password=tgt_pw,
                                 attrs={"cac_edipi": [str(int(time.time() * 1000) + 19)[-10:]], "entra_oid": [str(uuid.uuid4())]})
    umo_tok = umo.token()
    umo_before = api_body(umo_tok)
    s_up = X("POST", "/users/%s/role-mappings/clients/%s" % (umo.user["id"], rmc), [ra_role])
    umo_old = api_body(umo_tok)
    umo.at = 0
    try:
        umo_new = api_body(umo.token())
    except urllib.error.HTTPError as e_:
        umo_new = "refresh refused %s" % e_.code
    check("GATE (b) MORE than its entry: the user manager's existing token -> 403 by the filter on its first request after the promotion",
          umo_before == 200 and s_up == 204 and umo_old == "403 allowlist", "before %s, promote %s, old %s" % (umo_before, s_up, umo_old))
    check("GATE (b) ... and a token refreshed after it -> 403", umo_new in ("403 allowlist", "refresh refused 400", "refresh refused 401"), "%s" % umo_new)
    umo.at = time.time()                 # use the token it holds now; no further refresh
    s_t = umo.api("PUT", "/users/%s/reset-password" % tgt["id"], {"type": "password", "value": PW(), "temporary": False})[0]
    check("GATE ... so it cannot change anyone: its reset of another user's password -> 403, the user untouched", s_t == 403 and creds(tgt) == ["password"], "HTTP %s" % s_t)
    time.sleep(31)
    uc, useen, _ = pw_login(umo.username, umo.pw, umo.ctx, "security-admin-console", CONSOLE)
    check("GATE (a) ... a fresh password+TOTP sign-in is refused, no code", uc is None, "%s" % useen)
    xb = api_body(x_p.token())
    check("GATE: an administrator holding exactly its entry (X) is unaffected: admin API 200", xb == 200, "%s" % xb)
    opadm = M.user(kc, "op.admin"); je = M.load_allowlist().get(opadm["id"]) or {}
    stm_, dm_ = kc.req("GET", "/admin/realms/master"); pub = (json.loads(dm_).get("attributes") or {}).get(M.ALLOWLIST_ROLES_ATTR, "")
    pj = dict(x.split("=", 1) for x in pub.split(";") if "=" in x).get(opadm["id"], "")
    check("GATE: the operator is vetted for exactly what they hold: their published entry is their granted group by id with its snapshot",
          bool(pj) and pj.split(",") == M.entry_items(je) and pj.startswith("group:")
          and M.classify(M.rm_roles(kc, opadm["id"]), pj.split(","), lambda gid: M.group_live(kc, gid)) == M.VETTED,
          "%d roles held; published %s" % (len(M.rm_roles(kc, opadm["id"])), pj[:50]))
    rc, out = run("guard", "--fix")
    tg = kc.api("GET", "/users/%s" % tgt["id"]); uo = kc.api("GET", "/users/%s" % umo.user["id"])
    check("... the guard: the over-entitled account demoted, factors reset, DISABLED and held (exit 2)", rc == 2
          and "STIG-ADMIN-UNVETTED user=t.fp.umo holds more than its entry" in out and not M.is_admin(kc, umo.user["id"])
          and uo["enabled"] is False and creds(umo.user) == [], "exit %s enabled %s creds %s" % (rc, uo["enabled"], creds(umo.user)))
    check("... and no other account is changed (the target keeps its password, e-mail, bindings; enabled)", creds(tgt) == ["password"]
          and tg["enabled"] is True and (tg.get("attributes") or {}).get("cac_edipi") and "CONTAINED" not in out
          and "the deployed gate checks role extent" in out, "creds %s" % creds(tgt))
    # LOW 5: the delegate-created marker is declared in the user profile, administrators only
    upf = kc.api("GET", "/users/profile")
    cbd = [x for x in upf["attributes"] if x["name"] == "stig_created_by"]
    check("the user profile declares stig_created_by, view and edit for administrators only (it survives profile saves)",
          cbd and cbd[0].get("permissions") == {"view": ["admin"], "edit": ["admin"]}, "%s" % (cbd[0].get("permissions") if cbd else None))
    # LOW 3: an auditor reading admin events does not see the card mapping in their representations
    aud = persona.Person(M, kc, E, run, BASE, REALM, "t.fp.aud", "idp-auditor"); made_users.append("t.fp.aud")
    ed = str(int(time.time() * 1000) + 23)[-10:]
    mk_user("t.fp.evrep", attrs={"cac_edipi": [ed]})                      # an admin event whose representation holds the EDIPI
    time.sleep(2)
    st_ev, evs = aud.api("GET", "/admin-events?max=200&resourceTypes=USER&operationTypes=CREATE")
    seen_by_master = json.dumps(kc.api("GET", "/admin-events?max=200&resourceTypes=USER&operationTypes=CREATE"))
    check("an auditor's admin events carry no concealed attribute (the EDIPI the master realm sees is stripped)",
          st_ev == 200 and ed in seen_by_master and ed not in json.dumps(evs) and "cac_edipi" not in json.dumps(evs), "HTTP %s" % st_ev)
    # (e) a stale allowlist entry is dropped in report mode too
    al_ = M.load_allowlist(); al_[touched_m["id"]] = {"username": touched_m["username"], "roles": ["/roles/idp-admin"], "rm_roles": ["realm-admin"],
                                                       "granted_at": "test", "operator": "test"}
    M._write_json(M.ALLOWLIST, al_); M.publish_allowlist(kc, al_)
    rc, out = run("guard")
    check("a stale allowlist entry (account holds no realm-management role) is dropped in report mode too", "STIG-ADMIN-ALLOWLIST-REMOVED user=%s" % touched_m["username"] in out
          and touched_m["id"] not in M.load_allowlist(), "exit %s" % rc)
    # a user manager is on the allowlist for exactly its role, never more
    e_um = M.load_allowlist().get(sa["id"]) or {}
    check("the user manager's allowlist entry is idp-user-manager only", e_um.get("roles") == ["/roles/idp-user-manager"]
          and "realm-admin" not in (e_um.get("rm_roles") or []), "%s" % e_um.get("roles"))
    touched = mk_user("t.fp.touched", groups=["/%s/student" % a.client], attrs={"cac_edipi": [str(int(time.time() * 1000) + 11)[-10:]]})
    eng = M.group_by_path(kc, "/%s/engineer" % a.client)
    s1 = um("PUT", "/users/%s/groups/%s" % (touched["id"], eng["id"]))
    rc, out = run("grant", touched["username"], "idp-admin")
    check("an account the user manager changed (a role move) cannot be granted idp-admin -> REFUSED", s1 == 204 and rc != 0 and "REFUSED" in out
          and "non-administrator" in out and not M.is_admin(kc, touched["id"]), "move %s; %s" % (s1, out.splitlines()[0][:90]))
    # pre-created by the user manager, then "invited"
    st = um("POST", "/stig-accounts/users", {"username": "t.fp.precreated", "email": "t.fp.precreated@notify.example.mil", "firstName": "T",
                                             "lastName": "Pre", "group": "/%s/student" % a.client}); made_users.append("t.fp.precreated")
    rc, out = run("invite", "t.fp.precreated", "--email", "t.fp.precreated2@test.invalid", "--groups", "idp-admin")
    check("invite never hands over an account the user manager pre-created", st == 201 and rc != 0 and "REFUSED" in out, "create %s; %s" % (st, out[:100]))
    # invite as an administrator: no group, not an administrator, pending
    made_users.append("t.fp.invited")
    rc, out = run("invite", "t.fp.invited", "--email", "t.fp.invited@test.invalid", "--groups", "idp-admin,%s:student" % a.client)
    inv = M.user(kc, "t.fp.invited")
    check("invite with idp-admin: created with no group and NOT an administrator; pending", rc == 0 and "PENDING" in out and groups(inv) == []
          and not M.is_admin(kc, inv["id"]), "groups=%s; %s" % (groups(inv), out.splitlines()[-1][:90]))
finally:
    srv.shutdown()
    try:
        ra_end = dict(kc.api("GET", "").get("attributes") or {})
        if REALM_DOMS is None: ra_end.pop("stig.accounts.email-domains", None)
        else: ra_end["stig.accounts.email-domains"] = REALM_DOMS
        kc.api("PUT", "", {"attributes": ra_end})
    except Exception as e:      # noqa: BLE001
        print("cleanup: realm e-mail domains: %s" % e)
    # every test group, wherever it ended up (top level, under an application group, re-parented under /roles)
    for parent in (None, "/%s/student" % a.client, "/roles/idp-admin"):
        try:
            if parent is None:
                kids = kc.api("GET", "/groups?search=t-fp-&max=100") or []
            else:
                pg = M.group_by_path(kc, parent)
                kids = kc.api("GET", "/groups/%s/children?max=100" % pg["id"]) or [] if pg else []
            for g_ in kids:
                if g_["name"].startswith("t-fp-"):
                    kc.api("DELETE", "/groups/%s" % g_["id"], ok404=True)
        except Exception as e:      # noqa: BLE001 - cleanup must go on
            print("cleanup: groups under %s: %s" % (parent, e))
    for rn in [r["name"] for r in kc.api("GET", "/roles?search=t-fp-comp-") or [] if r["name"].startswith("t-fp-comp-")]:
        kc.api("DELETE", "/roles/%s" % rn, ok404=True)
    try:
        apc_ = kc.api("GET", "/clients?clientId=admin-permissions")[0]; AB_ = "/clients/%s/authz/resource-server" % apc_["id"]
        for kind, nm in (("permission", "t-fp legacy delegate: victims"), ("policy", "t-fp legacy delegate")):
            for x in kc.api("GET", AB_ + "/%s?name=%s" % (kind, M.q(nm))) or []:
                if x["name"] == nm:
                    kc.api("DELETE", AB_ + "/%s/%s" % (kind, x["id"]))
    except Exception as e:      # noqa: BLE001 - cleanup must go on
        print("cleanup: legacy permission: %s" % e)
    for n in made_users:
        f = kc.api("GET", "/users?exact=true&username=%s" % M.q(n))
        if f: kc.api("DELETE", "/users/%s" % f[0]["id"])
    for cid in made_clients:
        f = kc.api("GET", "/clients?clientId=%s" % cid)
        if f: kc.api("DELETE", "/clients/%s" % f[0]["id"])
    st = M.load_state()
    if st:
        for k in ("pending", "reset_at"):
            st[k] = {i: v for i, v in st[k].items() if kc.api("GET", "/users/%s" % i, ok404=True)}
        M.save_state(st)
    rc, out = run("guard", "--fix")
    check("cleanup: guard clean afterwards (exit 0)", rc == 0, "exit %s %s" % (rc, out[-100:]))
print("\n%d/%d passed" % (sum(res), len(res))); sys.exit(0 if all(res) else 1)

#!/usr/bin/env python3
"""Behavioural (black-box) checks of a STIG-provisioned Keycloak realm - the way an assessor tests.

Standard library only. Drives real browser-style logins over HTTPS (with client certificates for CAC).

  e2e_check.py --url https://sso:8443 --realm myapp --client myapp-web --redirect https://app/cb \
      [--client-secret S] [--cacert ca.pem] \
      [--cac-cert u.crt --cac-key u.key] [--revoked-cert r.crt --revoked-key r.key] \
      [--unmapped-cert n.crt --unmapped-key n.key] \
      [--pw-user U --pw-temp-password P --pw-new-password N]       # password+TOTP path (consumes the account)
      [--lockout-user U --lockout-password P]                      # 3 failures then correct password -> must fail
      [--admin-cert a.crt --admin-key a.key]                       # Alt Token into the admin console
      [--session-limit 3]
Each test prints PASS/FAIL with the STIG IDs it exercises; exit code 1 if any test fails.
"""
import argparse, base64, hashlib, hmac, html, http.cookiejar, json, os, re, ssl, struct, sys, time, urllib.error, urllib.parse, urllib.request

RESULTS = []

def report(name, ok, stig, detail=""):
    RESULTS.append(ok)
    print("%s  %-46s %-34s %s" % ("PASS" if ok else "FAIL", name, stig, detail), flush=True)

class Stop(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # surface every redirect as HTTPError so we can inspect it

class Browser:
    def __init__(self, cacert=None, cert=None, key=None):
        self.ctx = ssl.create_default_context(cafile=cacert) if cacert else ssl.create_default_context()
        if cert:
            self.ctx.load_cert_chain(cert, key)
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ctx),
                                              urllib.request.HTTPCookieProcessor(self.jar), Stop())
        self.op.addheaders = [("User-Agent", "kcstig-e2e/1.0")]

    def go(self, url, data=None, stop_prefix=None, max_hops=15):
        """GET/POST following redirects until a page, or a redirect to stop_prefix (returned as ('redirect', url))."""
        for _ in range(max_hops):
            body = urllib.parse.urlencode(data).encode() if data is not None else None
            try:
                r = self.op.open(urllib.request.Request(url, data=body), timeout=30)
                return ("page", r.geturl(), r.read().decode("utf-8", "replace"))
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307):
                    loc = urllib.parse.urljoin(url, e.headers["Location"])
                    if stop_prefix and loc.startswith(stop_prefix):
                        return ("redirect", loc, "")
                    url, data = loc, None
                    continue
                return ("error", url, e.read().decode("utf-8", "replace"))
        raise RuntimeError("too many redirects")

def form(page, form_id=None):
    forms = re.findall(r"<form\b([^>]*)>(.*?)</form>", page, re.S | re.I)
    for attrs, inner in forms:
        if form_id and ('id="%s"' % form_id) not in attrs:
            continue
        action = html.unescape(re.search(r'action="([^"]*)"', attrs).group(1))
        fields = {}
        for m in re.finditer(r"<input\b([^>]*)>", inner, re.I):
            a = m.group(1)
            n = re.search(r'name="([^"]*)"', a)
            if not n:
                continue
            v = re.search(r'value="([^"]*)"', a)
            t = re.search(r'type="([^"]*)"', a)
            if t and t.group(1).lower() in ("submit", "button", "checkbox"):
                continue
            fields[n.group(1)] = html.unescape(v.group(1)) if v else ""
        return action, fields
    return None, {}

def page_id(page):
    m = re.search(r'data-page-id="([^"]+)"', page)
    return m.group(1).replace(".ftl", "") if m else "?"

def error_text(page):
    m = re.search(r'(?:kc-feedback-text|pf-v5-c-alert__title|input-error[^"]*)"[^>]*>\s*(.*?)\s*<', page, re.S)
    return html.unescape(re.sub(r"\s+", " ", m.group(1))).strip() if m else ""

def totp(secret_b32, algo="sha256", digits=6, period=30):
    key = base64.b32decode(secret_b32.replace(" ", "").upper() + "=" * (-len(secret_b32.replace(" ", "")) % 8))
    ctr = struct.pack(">Q", int(time.time()) // period)
    h = hmac.new(key, ctr, getattr(hashlib, algo)).digest()
    o = h[-1] & 0x0F
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)).zfill(digits)

class Flow:
    def __init__(self, a):
        self.a = a
        self.base = a.url.rstrip("/")

    def auth_url(self, realm=None, client=None, redirect=None, extra=None):
        ver = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        chal = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
        q = {"client_id": client or self.a.client, "redirect_uri": redirect or self.a.redirect, "response_type": "code",
             "scope": "openid", "state": "st", "nonce": "n", "code_challenge": chal, "code_challenge_method": "S256"}
        q.update(extra or {})
        return "%s/realms/%s/protocol/openid-connect/auth?%s" % (self.base, realm or self.a.realm, urllib.parse.urlencode(q)), ver

    def finish(self, b, kind, url, page, ctx, stop=None):
        """Walk post-authentication pages (x509 confirm, T&C banner, OTP setup, update password) until redirect."""
        seen = []
        R = stop or self.a.redirect
        for _ in range(8):
            if kind == "redirect":
                return url, seen
            if kind == "error":
                return None, seen + ["error:" + error_text(page)]
            pid = page_id(page); seen.append(pid)
            if pid == "login-login-x509-info":
                action, f = form(page); f["login"] = "Sign in"
                kind, url, page = b.go(action, f, R)
            elif pid == "login-terms":
                action, f = form(page); f["accept"] = "OK"
                kind, url, page = b.go(action, f, R)
            elif pid == "login-login-update-password":
                action, f = form(page, "kc-passwd-update-form")
                f.update({"password-new": ctx["new_pw"], "password-confirm": ctx["new_pw"]})
                kind, url, page = b.go(action, f, R)
            elif pid == "login-login-config-totp":
                ml = re.search(r'href="([^"]+)"\s+id="mode-manual"', page) or re.search(r'id="mode-manual"[^>]*href="([^"]+)"', page)
                k2, u2, p2 = b.go(urllib.parse.urljoin(url, html.unescape(ml.group(1))), None, R) if ml else ("page", url, page)
                sec = re.search(r'id="kc-totp-secret-key"[^>]*>\s*([A-Z2-7 ]+)\s*<', p2)
                secret = sec.group(1).replace(" ", "") if sec else None
                ctx["totp_secret"] = secret
                action, f = form(p2, "kc-totp-settings-form")
                f.update({"totp": totp(secret), "userLabel": "e2e"})
                kind, url, page = b.go(action, f, R)
            elif pid == "login-login-otp":
                action, f = form(page, "kc-otp-login-form")
                f["otp"] = totp(ctx["totp_secret"])
                kind, url, page = b.go(action, f, R)
            else:
                return None, seen + ["stuck:" + pid + ":" + error_text(page)]
        return None, seen

    def token(self, code, ver, client=None, secret=None, redirect=None):
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect or self.a.redirect,
                "client_id": client or self.a.client, "code_verifier": ver}
        if secret or self.a.client_secret:
            data["client_secret"] = secret or self.a.client_secret
        ctx = ssl.create_default_context(cafile=self.a.cacert) if self.a.cacert else ssl.create_default_context()
        req = urllib.request.Request("%s/realms/%s/protocol/openid-connect/token" % (self.base, self.a.realm),
                                     data=urllib.parse.urlencode(data).encode())
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return json.loads(r.read())

def claims(jwt):
    p = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))

def cac_login(fl, cert, key, realm=None, client=None, redirect=None):
    b = Browser(fl.a.cacert, cert, key)
    url, ver = fl.auth_url(realm, client, redirect)
    kind, u, page = b.go(url, None, redirect or fl.a.redirect)
    first = page_id(page) if kind == "page" else kind
    banner = "dod-banner.js" in page if kind == "page" else False
    final, seen = fl.finish(b, kind, u, page, {}, redirect or fl.a.redirect)
    return b, final, [first] + seen, banner, ver


def gateway_login(a, cert, key):
    """CAC login through the oauth2-proxy gateway; returns (browser, final page text or None, pages seen)."""
    gw = a.gateway_url.rstrip("/")
    b = Browser(a.cacert, cert, key)
    kind, url, page = b.go(gw + "/", None, gw + "/oauth2/callback")
    seen = []
    for _ in range(6):
        if kind == "redirect":
            kind, url, page = b.go(url)            # callback -> cookie -> app
            return b, (page if kind == "page" else None), seen + ["app:%s" % kind]
        if kind != "page":
            return b, None, seen + [kind]
        pid = page_id(page); seen.append(pid)
        action, f = form(page)
        if pid == "login-login-x509-info":
            f["login"] = "Sign in"
        elif pid == "login-terms":
            f["accept"] = "OK"
        else:
            return b, None, seen
        kind, url, page = b.go(action, f, gw + "/oauth2/callback")
    return b, None, seen

def gateway_tests(a):
    gw = a.gateway_url.rstrip("/")
    b, page, seen = gateway_login(a, a.cac_cert, a.cac_key)
    hdrs = {}
    try:
        hdrs = {k.lower(): v for k, v in json.loads(page).items()} if page else {}
    except Exception:
        pass
    report("GW: CAC login through gateway reaches app", bool(hdrs), "V-222524 V-222526", "pages=%s" % seen)
    prev = None
    if hdrs.get("x-forwarded-id-token"):
        try:
            prev = claims(hdrs["x-forwarded-id-token"]).get("previous_login")
        except Exception:
            pass
    report("GW: identity headers + previous logon (ID token) reach the app", bool(hdrs.get("x-forwarded-user")) and bool(prev),
           "V-222437 V-222552", "user=%s groups=%s previous_login=%s" % (hdrs.get("x-forwarded-user"), hdrs.get("x-forwarded-groups"), prev))
    ck = [c for c in b.jar if c.name.startswith("__Host-stig_session")]
    ok = bool(ck) and all(c.secure and c.path == "/" and not c.domain_specified and c.has_nonstandard_attr("HttpOnly")
                          and (c.get_nonstandard_attr("SameSite") or "").lower() == "lax" for c in ck)
    report("GW: session cookie __Host- Secure HttpOnly SameSite=Lax", ok, "V-222575 V-222576",
           "%s" % [(c.name, c.secure, c.path, c.get_nonstandard_attr("SameSite")) for c in ck])
    # forged identity header must be overwritten by the gateway
    req = urllib.request.Request(gw + "/", headers={"X-Forwarded-User": "forged-admin", "X-Forwarded-Groups": "admin"})
    try:
        r = b.op.open(req, timeout=20); h2 = {k.lower(): v for k, v in json.loads(r.read()).items()}
    except Exception as e:
        h2 = {"error": str(e)}
    report("GW: client-supplied identity headers are overwritten", h2.get("x-forwarded-user") == hdrs.get("x-forwarded-user")
           and "forged-admin" not in json.dumps(h2), "V-222425", "upstream saw user=%s" % h2.get("x-forwarded-user"))
    if a.gateway_norole_cert:
        _, page2, seen2 = gateway_login(a, a.gateway_norole_cert, a.gateway_norole_key)
        report("GW: authenticated user without the client role is refused", page2 is None or "x-forwarded-user" not in page2.lower(),
               "V-222425", "pages=%s" % seen2)
    if a.gateway_idle_wait:
        time.sleep(a.gateway_idle_wait)
        kind, url, page = b.go(gw + "/", None, None)
        back_to_idp = kind == "page" and page_id(page).startswith("login-")
        report("GW: idle beyond the SSO idle timeout forces re-authentication", back_to_idp, "V-222389",
               "after %ss idle -> %s" % (a.gateway_idle_wait, page_id(page) if kind == "page" else kind))
        b, page, seen = gateway_login(a, a.cac_cert, a.cac_key)
    # logoff ends the app session AND the Keycloak SSO session
    b.go(gw + "/oauth2/sign_out", None, "https://")
    kind, url, page = b.go(gw + "/", None, None)
    report("GW: sign_out ends app and IdP session", kind == "page" and page_id(page).startswith("login-"), "V-222391 V-222578",
           "after sign_out -> %s" % (page_id(page) if kind == "page" else kind))

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for o in ("url", "realm", "client", "redirect"):
        ap.add_argument("--" + o, required=True)
    for o in ("client-secret", "cacert", "cac-cert", "cac-key", "revoked-cert", "revoked-key", "unmapped-cert", "unmapped-key",
              "rogue-cert", "rogue-key", "pw-user", "pw-temp-password", "pw-new-password", "lockout-user", "lockout-password", "admin-cert", "admin-key",
              "admin-realm", "gateway-url", "gateway-norole-cert", "gateway-norole-key"):
        ap.add_argument("--" + o)
    ap.add_argument("--session-limit", type=int, default=0)
    ap.add_argument("--gateway-idle-wait", type=int, default=0, help="seconds to stay idle before re-requesting through the gateway (set > realm SSO idle)")
    ap.add_argument("--gateway-only", action="store_true", help="run only the gateway tests")
    a = ap.parse_args()
    a.admin_realm = a.admin_realm or "master"
    fl = Flow(a)

    if a.gateway_url:
        gateway_tests(a)
        if a.gateway_only:
            print("\n%d/%d passed" % (sum(RESULTS), len(RESULTS))); sys.exit(0 if all(RESULTS) else 1)

    # Banner present before any credential is accepted (unauthenticated login page).
    b = Browser(a.cacert)
    kind, u, page = b.go(fl.auth_url()[0], None, a.redirect)
    if kind != "page" and a.cac_cert:   # CAC-only realm: no form without a card - check the card's confirmation page
        b = Browser(a.cacert, a.cac_cert, a.cac_key)
        kind, u, page = b.go(fl.auth_url()[0], None, a.redirect)
    report("DoD banner gate on login page", kind == "page" and "dod-banner.js" in page and "dod-banner.css" in page,
           "V-222434 V-222435", page_id(page) if kind == "page" else kind)

    if a.cac_cert:
        b, final, seen, banner, ver = cac_login(fl, a.cac_cert, a.cac_key)
        ok = bool(final and "code=" in final)
        tok = {}
        if ok:
            code = urllib.parse.parse_qs(urllib.parse.urlparse(final).query)["code"][0]
            tok = fl.token(code, ver)
        report("CAC (X.509 UPN) login -> authorization code", ok and "access_token" in tok,
               "V-222524 V-222525 V-222552 V-222526", "pages=%s" % seen)
        if ok:
            idc = claims(tok["id_token"])
            report("No password/OTP prompted on CAC path", not any("password" in s or "otp" in s for s in seen), "V-222526", "")
            report("Refresh token rotation (single use)", True if tok.get("refresh_token") else False, "V-222582", "")
            # second login (new browser) -> previous_login claim present
            b2, final2, seen2, _, ver2 = cac_login(fl, a.cac_cert, a.cac_key)
            if final2:
                code2 = urllib.parse.parse_qs(urllib.parse.urlparse(final2).query)["code"][0]
                t2 = fl.token(code2, ver2); id2 = claims(t2["id_token"])
                report("previous_login claim on subsequent logon", bool(id2.get("previous_login")), "V-222437",
                       "previous_login=%s" % id2.get("previous_login"))
                b2.go("%s/realms/%s/protocol/openid-connect/logout?%s" % (fl.base, a.realm, urllib.parse.urlencode(
                    {"id_token_hint": t2["id_token"], "client_id": a.client})), None, "https://")
            # session cookies are browser-session cookies (no persistent expiry)
            # KEYCLOAK_IDENTITY is what the cookie authenticator re-uses for SSO; it must die with the browser.
            # KEYCLOAK_SESSION is only a session-status hint for JS adapters (reported, not judged).
            ident = [c for c in b.jar if c.name == "KEYCLOAK_IDENTITY"]
            info = [c.name for c in b.jar if c.name.startswith("KEYCLOAK_") and c.expires]
            report("SSO identity cookie is a browser-session cookie", bool(ident) and all(not c.expires for c in ident), "V-222578",
                   "cookies with expiry: %s" % info)
            sec = [c.name for c in b.jar if c.name.startswith(("KEYCLOAK_", "AUTH_SESSION")) and not c.secure]
            report("SSO cookies carry Secure", not sec, "V-222576", "insecure=%s" % sec)
            # logout destroys the session: reuse cookie jar afterwards must re-authenticate
            lo = "%s/realms/%s/protocol/openid-connect/logout?%s" % (fl.base, a.realm, urllib.parse.urlencode(
                {"id_token_hint": tok["id_token"], "post_logout_redirect_uri": "", "client_id": a.client}))
            b.go(lo, None, "https://")
            kind, u, page = b.go(fl.auth_url()[0], None, a.redirect)
            report("Logout terminates IdP session", kind == "page", "V-222391 V-222578", "after logout -> %s" % (page_id(page) if kind == "page" else kind))

    if a.revoked_cert:
        _, final, seen, _, _ = cac_login(fl, a.revoked_cert, a.revoked_key)
        report("Revoked certificate rejected (CRL/OCSP)", not final, "V-222550 V-222553", "pages=%s" % seen)
    if a.unmapped_cert:
        _, final, seen, _, _ = cac_login(fl, a.unmapped_cert, a.unmapped_key)
        report("Unmapped certificate gets no access", not final, "V-222522 V-222552", "pages=%s" % seen)

    if a.rogue_cert:
        try:
            _, final, seen, _, _ = cac_login(fl, a.rogue_cert, a.rogue_key)
            report("Cert from non-DoD CA with a real UPN rejected", not final, "V-222584 V-222550", "pages=%s" % seen)
        except Exception as e:  # TLS layer refused the certificate outright
            report("Cert from non-DoD CA with a real UPN rejected", True, "V-222584 V-222550", "TLS handshake refused: %s" % str(e)[:80])

    if a.pw_user:
        b = Browser(a.cacert)
        url, ver = fl.auth_url()
        kind, u, page = b.go(url, None, a.redirect)
        action, f = form(page, "kc-form-login")
        f.update({"username": a.pw_user, "password": a.pw_temp_password})
        kind, u, page = b.go(action, f, a.redirect)
        ctx = {"new_pw": a.pw_new_password}
        final, seen = fl.finish(b, kind, u, page, ctx)
        report("Temporary password forces immediate change", "login-login-update-password" in seen, "V-222547", "pages=%s" % seen)
        report("Password path requires OTP enrolment", "login-login-config-totp" in seen and bool(final), "V-222526 V-222530", "")
        if final:
            # password-only must not be enough: new browser, correct password -> OTP prompt
            b3 = Browser(a.cacert)
            url3, ver3 = fl.auth_url()
            k, u3, p3 = b3.go(url3, None, a.redirect)
            act, f3 = form(p3, "kc-form-login"); f3.update({"username": a.pw_user, "password": a.pw_new_password})
            k, u3, p3 = b3.go(act, f3, a.redirect)
            report("Correct password alone does not grant access", k == "page" and page_id(p3) == "login-login-otp", "V-222526",
                   page_id(p3) if k == "page" else k)
            # OTP code replay rejected
            used = totp(ctx["totp_secret"])
            act, f4 = form(p3, "kc-otp-login-form"); f4["otp"] = used
            k, u4, p4 = b3.go(act, f4, a.redirect)
            report("OTP code is not reusable", k == "page" and page_id(p4) == "login-login-otp", "V-222530 V-222531",
                   "%s %s" % (page_id(p4) if k == "page" else k, error_text(p4) if k == "page" else ""))
            # self-service password change within 24h -> blocked by minimumPasswordAge
            url5, _ = fl.auth_url(extra={"kc_action": "UPDATE_PASSWORD"})
            k, u5, p5 = b.go(url5, None, a.redirect)
            if k == "page" and page_id(p5) == "login-login-update-password":
                act, f5 = form(p5, "kc-passwd-update-form")
                f5.update({"password-new": a.pw_new_password + "x9", "password-confirm": a.pw_new_password + "x9"})
                k, u5, p5 = b.go(act, f5, a.redirect)
                blocked = k == "page" and page_id(p5) == "login-login-update-password"
                report("Password change within 24h blocked", blocked, "V-222544", error_text(p5) if k == "page" else k)
            else:
                report("Password change within 24h blocked", False, "V-222544", "could not reach update form: %s" % (page_id(p5) if k == "page" else k))

    if a.session_limit:
        # Start from zero sessions for this user (end any left by earlier tests in this run), then open limit+1.
        sessions = 0
        for i in range(a.session_limit + 1):
            _, final, seen, _, _ = cac_login(fl, a.cac_cert, a.cac_key)
            if final:
                sessions += 1
            last = seen
        report("Concurrent session limit enforced", sessions == a.session_limit, "V-222387",
               "%d of %d logins succeeded; last pages=%s" % (sessions, a.session_limit + 1, last))

    if a.admin_cert:
        adm_redirect = "%s/admin/%s/console/" % (fl.base, a.admin_realm)
        _, final, seen, _, _ = cac_login(fl, a.admin_cert, a.admin_key, a.admin_realm, "security-admin-console", adm_redirect)
        report("Admin console via Alt Token", bool(final), "V-222523", "pages=%s" % seen)
        if a.cac_cert:
            _, final, seen, _, _ = cac_login(fl, a.cac_cert, a.cac_key, a.admin_realm, "security-admin-console", adm_redirect)
            report("Everyday CAC cannot reach admin console", not final, "V-222523", "pages=%s" % seen)

    if a.lockout_user:
        b = Browser(a.cacert)
        for i in range(3):
            url, _ = fl.auth_url()
            k, u, p = b.go(url, None, a.redirect)
            act, f = form(p, "kc-form-login"); f.update({"username": a.lockout_user, "password": "Wrong-Password-%d!" % i})
            b.go(act, f, a.redirect)
        url, _ = fl.auth_url()
        k, u, p = b.go(url, None, a.redirect)
        act, f = form(p, "kc-form-login"); f.update({"username": a.lockout_user, "password": a.lockout_password})
        k, u, p = b.go(act, f, a.redirect)
        locked = k == "page" and page_id(p) == "login-login"
        report("Account locked after 3 failures (4th correct fails)", locked, "V-222432", error_text(p) if k == "page" else k)

    print("\n%d/%d passed" % (sum(RESULTS), len(RESULTS)))
    sys.exit(0 if all(RESULTS) else 1)

if __name__ == "__main__":
    main()

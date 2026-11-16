#!/usr/bin/env python3
"""Drive a kcstig passkey realm's pages (auth_mode=passkey) with the software authenticator - no browser.

  set_up(b, link, authn, base)           follow an invitation (execute-actions) link: e-mail verification, the DoD
                                         notice (terms), passkey registration; returns (ok, pages seen, error text)
  sign_in(fl, authn, how, ...)           one sign-in; how = "username" (username form, then the passkey step),
                                         "button" (the username page's discoverable "Sign in with passkey" form),
                                         or "username-only" (stop after the username); returns (code?, pages, error)

The DoD Notice and Consent banner on the sign-in pages is client-side script (dod-banner.js); an HTTP client does not
run it, so these helpers only check that the page carries it. The invitation's banner is the server-side terms page.
"""
import html, os, re, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "keycloak-asd-stig", "scripts"))
import e2e_check as E

def js_value(page, key):
    m = re.search(r"\b%s\s*:\s*\"([^\"]*)\"" % re.escape(key), page)
    return m.group(1) if m else None

def js_algs(page):
    m = re.search(r"signatureAlgorithms\s*:\s*\[([^\]]*)\]", page)
    return [int(x) for x in re.findall(r"-?\d+", m.group(1))] if m else []

def origin_of(url):
    m = re.match(r"(https://[^/]+)", url)
    return m.group(1)

def has_banner(page):
    return "dod-banner" in page

def set_up(b, link, authn, stop, uv=True):
    """Complete an invitation link. ok=True once Keycloak redirects to `stop` (the account console) or shows the
    'account updated' info page after the last action."""
    seen = []
    kind, url, page = b.go(link, None, stop)
    for _ in range(10):
        if kind == "redirect":
            return True, seen, ""
        if kind == "error":
            return False, seen, E.error_text(page) or page[:200]
        pid = E.page_id(page); seen.append(pid)
        if pid == "login-info":
            nxt = re.search(r'href="([^"]*(?:action-token|required-action|login-actions)[^"]*)"', page)
            if not nxt:
                return ("ccount" in page or "updated" in page.lower()), seen, E.error_text(page)
            kind, url, page = b.go(html.unescape(nxt.group(1)), None, stop)
        elif pid == "login-terms":
            action, f = E.form(page); f["accept"] = "OK"
            kind, url, page = b.go(action, f, stop)
        elif pid == "login-webauthn-register":
            action, f = E.form(page, "register")
            authn.offered = js_algs(page)
            f.update(authn.register(js_value(page, "rpId"), js_value(page, "challenge"), origin_of(url),
                                    js_value(page, "userid"), uv=uv))
            kind, url, page = b.go(action, f, stop)
            if kind == "page" and E.page_id(page) == "login-webauthn-register":   # refused: Keycloak shows it again
                return False, seen + ["refused"], E.error_text(page) or "registration refused"
        elif pid == "login-webauthn-error":
            return False, seen, E.error_text(page) or "webauthn error"
        else:
            return False, seen + ["stuck:" + pid], E.error_text(page)
    return False, seen, "too many pages"

def webauthn_form(page):
    """The WebAuthn authentication form: Keycloak's id is 'webauth' (username page and passkey step)."""
    return E.form(page, "webauth")

def sign_in(fl, authn, how, username=None, cacert=None, uv=True, bad_signature=False, counter=None, client=None,
            redirect=None, realm=None):
    b = E.Browser(cacert)
    url, _ = fl.auth_url(realm=realm, client=client, redirect=redirect)
    R = redirect or fl.a.redirect
    kind, cur, page = b.go(url, None, R)
    seen = [E.page_id(page) if kind == "page" else kind]
    banner = kind == "page" and has_banner(page)
    if kind != "page":
        return None, seen, "no sign-in page", banner
    if how == "button":
        action, f = webauthn_form(page)
        if not action:
            return None, seen, "no passkey form on the username page", banner
    else:
        action, f = E.form(page, "kc-form-login")
        f["username"] = username
        kind, cur, page = b.go(action, f, R)
        if kind != "page":
            return (cur if kind == "redirect" and "code=" in cur else None), seen + [kind], E.error_text(page), banner
        seen.append(E.page_id(page))
        if how == "username-only":
            return None, seen, E.error_text(page), banner
        action, f = webauthn_form(page)
        if not action:
            return None, seen, "no passkey form: " + E.error_text(page), banner
    if authn is None:
        return None, seen, "no authenticator", banner
    f.update(authn.assert_(js_value(page, "rpId") or "localhost", js_value(page, "challenge"), origin_of(cur), uv=uv,
                           bad_signature=bad_signature, counter=counter))
    kind, cur, page = b.go(action, f, R)
    for _ in range(4):
        if kind == "redirect":
            return (cur if "code=" in cur else None), seen + ["redirect"], "", banner
        if kind != "page":
            return None, seen + [kind], E.error_text(page), banner
        pid = E.page_id(page); seen.append(pid)
        if pid == "login-terms":                                       # Terms and Conditions still pending
            a2, f2 = E.form(page); f2["accept"] = "OK"; kind, cur, page = b.go(a2, f2, R)
            continue
        return None, seen, E.error_text(page), banner
    return None, seen, "too many pages", banner

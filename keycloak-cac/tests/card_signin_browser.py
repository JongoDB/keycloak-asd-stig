#!/usr/bin/env python3
"""The card sign-in page (stig-card-signin.ftl) in a REAL browser (Chromium via Playwright), against a throwaway
keycloak-cac container in lab mode with STIG_CARD_PORT=8444 (a TCP pass-through to 8443 here, as the host's port
mapping). Run by card-signin-browser.sh inside the container's network namespace.

The browser presents no certificate on the main port (8443), so the X.509 step shows the card sign-in page; on the card
port it holds the mock PKI's doe.john card (Playwright's client_certificates).

  [layout]   at 1440 and 360 px: the labels are exactly "Sign in with CAC/PIV" and the provider's display name
             ("Microsoft Entra ID (Example Org)"); an "or" divider between the card button and the provider buttons; at least
             16 px between the card button, the provider button and "Use another sign-in method", which is a link-styled
             (secondary) button; no horizontal scroll. Screenshots when SHOTS is set.
  [card]     "Sign in with CAC/PIV" with the card port answering at once: signed in, the blocked message never shown.
  [slowpick] the probe held for 14 s - the time a person spends in the browser's certificate picker and PIN prompt:
             the blocked message is NEVER shown; after 10 s a "still waiting" note is; then signed in.
  [refused]  the card port refuses the connection (a real network error): the blocked message appears, the button is
             back, "Use another sign-in method" has the focus.
  [hang]     the card port accepts and never answers: no blocked message (a hang looks exactly like an open picker),
             the "still waiting" note after 10 s, "Use another sign-in method" still works.
"""
import argparse, json, os, socket, ssl, sys, threading, time, urllib.parse, http.client

ap = argparse.ArgumentParser()
ap.add_argument("--cacert", required=True); ap.add_argument("--certs", required=True); ap.add_argument("--skill-scripts", required=True)
ap.add_argument("--shots", default=os.environ.get("SHOTS") or None); ap.add_argument("--tag", default="")
a = ap.parse_args()
sys.path.insert(0, a.skill_scripts); import e2e_check as E                        # noqa: E402
from playwright.sync_api import sync_playwright                                     # noqa: E402

REALM, PORT, CARD_PORT, HOST = "dod-cac", 8443, 8444, "localhost"
BASE = "https://%s:%d" % (HOST, PORT); ACCT = "%s/realms/%s/account/" % (BASE, REALM)
CARD_LABEL, IDP_LABEL = "Sign in with CAC/PIV", "Microsoft Entra ID (Example Org)"
CTX = ssl.create_default_context(cafile=a.cacert)
res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s  %-100s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

# ---- the card port: on / refuse / hang
MODE = {"m": "on"}; HUNG = []
def _pipe(x, y):
    try:
        while True:
            d = x.recv(65536)
            if not d:
                break
            y.sendall(d)
    except OSError:
        pass
    finally:
        for s_ in (x, y):
            try:
                s_.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
def _forward():
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", CARD_PORT)); ls.listen(64)
    while True:
        c, _ = ls.accept()
        if MODE["m"] == "refuse":
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00"); c.close(); continue   # RST
        if MODE["m"] == "hang":
            HUNG.append(c); continue
        up = socket.create_connection(("127.0.0.1", PORT))
        threading.Thread(target=_pipe, args=(c, up), daemon=True).start(); threading.Thread(target=_pipe, args=(up, c), daemon=True).start()
threading.Thread(target=_forward, daemon=True).start()

# ---- the admin API: one identity provider, as an organisation's Entra tenant is configured
def raw(method, path, body=None, headers=None):
    con = http.client.HTTPSConnection(HOST, PORT, context=CTX, timeout=60)
    con.request(method, path, body=body, headers=headers or {}); r = con.getresponse(); t = r.read().decode("utf-8", "replace"); con.close()
    return r.status, t
st, t = raw("POST", "/realms/master/protocol/openid-connect/token", urllib.parse.urlencode({
    "grant_type": "client_credentials", "client_id": "stig-automation", "client_secret": os.environ["AUTOMATION_SECRET"]}).encode(),
    {"Content-Type": "application/x-www-form-urlencoded"})
TOKEN = json.loads(t)["access_token"]
st, t = raw("POST", "/admin/realms/%s/identity-provider/instances" % REALM, json.dumps({
    "alias": "entra", "providerId": "oidc", "displayName": IDP_LABEL, "enabled": True, "hideOnLogin": False,
    "config": {"authorizationUrl": "https://login.example.invalid/tenant/oauth2/v2.0/authorize",
               "tokenUrl": "https://login.example.invalid/tenant/oauth2/v2.0/token", "clientId": "lab-entra",
               "clientSecret": "lab-entra-secret-not-used-0123456789", "clientAuthMethod": "client_secret_post",
               "defaultScope": "openid profile email", "syncMode": "IMPORT"}}).encode(),
    {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
check("setup: an identity provider \"%s\" (alias entra)" % IDP_LABEL, st in (201, 409), "HTTP %s %s" % (st, t[:120]))

fl = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client="account-console", redirect=ACCT, admin_url=None, client_secret=None, cacert=a.cacert))

def open_card_page(br, width, with_card):
    certs = [{"origin": "https://%s:%d" % (HOST, CARD_PORT), "certPath": a.certs + "/doe.john.crt",
              "keyPath": a.certs + "/doe.john.key"}] if with_card else []
    ctx = br.new_context(ignore_https_errors=True, viewport={"width": width, "height": 900}, client_certificates=certs)
    page = ctx.new_page(); url, _ = fl.auth_url(); page.goto(url)
    if page.query_selector("#dod-banner-ack"):                  # the DoD Notice and Consent banner
        page.click("#dod-banner-ack")
    page.wait_for_selector("#stig-card-signin", timeout=20000)
    return ctx, page

def box(page, sel):
    b = page.locator(sel).first.bounding_box()
    return b or {"x": 0, "y": 0, "width": 0, "height": 0}

def signed_in(page, timeout=40000):
    """After the card form: the banner, the X.509 confirmation and the terms (if shown) are accepted; True once the
    account console is reached - the card sign-in completed."""
    end = time.time() + timeout / 1000.0
    while time.time() < end:
        if page.url.startswith(ACCT):
            return True
        try:
            if page.query_selector("#dod-banner-ack") and page.is_visible("#dod-banner-ack"):   # the banner, on the card port's origin
                page.click("#dod-banner-ack"); continue
            if page.query_selector('[name="accept"]'):          # the lab users' terms-and-conditions required action
                page.click('[name="accept"]'); page.wait_for_load_state(); continue
            if page.query_selector("#kc-x509-login-info"):        # "you are signing in as ...": Continue
                page.click("#kc-login"); page.wait_for_load_state(); continue
        except Exception:
            pass
        page.wait_for_timeout(250)
    if not page.url.startswith(ACCT):
        try:
            print("      (not signed in: url=%s ids=%s)" % (page.url[:90], page.eval_on_selector_all(
                "form[id], input[id], div[id]", "es => es.map(e => e.id).slice(0, 12)")))
        except Exception:
            pass
    return page.url.startswith(ACCT)

def watch_blocked(page, seconds):
    """Poll the page for `seconds`: (was the blocked message ever visible, was the still-waiting note ever visible)."""
    blocked = waiting = False; end = time.time() + seconds
    while time.time() < end:
        try:
            blocked = blocked or page.is_visible("#stig-card-blocked")
            waiting = waiting or (page.query_selector("#stig-card-wait") is not None and page.is_visible("#stig-card-wait"))
        except Exception:
            break                                                # navigated away
        page.wait_for_timeout(200)
    return blocked, waiting

with sync_playwright() as pw:
    br = pw.chromium.launch()
    # [layout]
    for w in (1440, 360):
        ctx, page = open_card_page(br, w, False)
        if a.shots:
            page.screenshot(path=os.path.join(a.shots, "card-signin-%s%d.png" % (a.tag, w)), full_page=True)
        card = page.get_attribute("#kc-card-signin", "value")
        idp = (page.inner_text("#social-entra") if page.query_selector("#social-entra") else "").strip()
        bc, bi = box(page, "#kc-card-signin"), box(page, "#social-entra")
        bo = box(page, "#kc-card-other") if page.query_selector("#kc-card-other") else None
        check("[layout %d] the card button reads exactly \"%s\"" % (w, CARD_LABEL), card == CARD_LABEL, repr(card))
        check("[layout %d] the provider button reads exactly \"%s\"" % (w, IDP_LABEL), idp == IDP_LABEL, repr(idp))
        g1 = bi["y"] - (bc["y"] + bc["height"])
        check("[layout %d] >= 16 px between the card button and the provider button" % w, g1 >= 16, "%.0f px" % g1)
        orr = page.query_selector("#stig-card-or")
        ob = box(page, "#stig-card-or") if orr else None
        check("[layout %d] an \"or\" divider between them" % w, orr is not None and orr.inner_text().strip().lower() == "or"
              and ob["y"] >= bc["y"] + bc["height"] and ob["y"] + ob["height"] <= bi["y"], ob)
        if bo:
            g2 = bo["y"] - (bi["y"] + bi["height"])
            check("[layout %d] >= 16 px between the provider button and \"Use another sign-in method\"" % w, g2 >= 16, "%.0f px" % g2)
            bg = page.eval_on_selector("#kc-card-other", "e => getComputedStyle(e).backgroundColor")
            pbg = page.eval_on_selector("#kc-card-signin", "e => getComputedStyle(e).backgroundColor")
            check("[layout %d] \"Use another sign-in method\" is secondary (link-styled: no fill, the card button filled)" % w,
                  bg in ("rgba(0, 0, 0, 0)", "transparent") and pbg not in ("rgba(0, 0, 0, 0)", "transparent"), "%s / %s" % (bg, pbg))
        sp = box(page, "#social-entra span")
        off = abs((sp["x"] + sp["width"] / 2) - (bi["x"] + bi["width"] / 2))
        check("[layout %d] the provider label is centred like the card label" % w, off <= 4, "%.0f px off centre" % off)
        bt = box(page, "#stig-card-intro")
        g0 = bc["y"] - (bt["y"] + bt["height"])
        check("[layout %d] >= 16 px between the introduction and the card button" % w, g0 >= 16, "%.0f px" % g0)
        check("[layout %d] the card and provider buttons have the same width" % w, abs(bc["width"] - bi["width"]) <= 2,
              "%.0f / %.0f" % (bc["width"], bi["width"]))
        sw = page.evaluate("document.documentElement.scrollWidth")
        check("[layout %d] no horizontal scroll" % w, sw <= w, "scrollWidth %s" % sw)
        check("[layout %d] no blocked message on load" % w, not page.is_visible("#stig-card-blocked"))
        ctx.close()

    # [card] the card port answers at once
    MODE["m"] = "on"
    ctx, page = open_card_page(br, 1440, True)
    page.click("#kc-card-signin", no_wait_after=True)
    blocked, _ = watch_blocked(page, 1.5)
    ok = signed_in(page)
    check("[card] \"%s\" with the card port answering: signed in, no blocked message" % CARD_LABEL, ok and not blocked,
          "url=%s blocked=%s" % (page.url[:80], blocked))
    ctx.close()

    # [slowpick] the probe held 14 s (a person in the certificate picker and PIN prompt)
    ctx, page = open_card_page(br, 1440, True)
    held = []
    page.route("https://%s:%d/realms/%s/.well-known/**" % (HOST, CARD_PORT, REALM), lambda r: held.append(r))
    t0 = time.time(); page.click("#kc-card-signin", no_wait_after=True)
    blocked, waiting = watch_blocked(page, 14)
    page.unroute("https://%s:%d/realms/%s/.well-known/**" % (HOST, CARD_PORT, REALM))
    for r in held:
        try:
            r.continue_()
        except Exception as e:                                   # the page aborted the probe itself
            print("      (the held probe could not continue: %s)" % str(e)[:80])
    if not blocked:
        b2, _ = watch_blocked(page, 1.0); blocked = blocked or b2
    ok = signed_in(page)
    check("[slowpick] a 14 s certificate pick: the blocked message is never shown", not blocked and held, "held=%d" % len(held))
    check("[slowpick] ... a \"still waiting\" note is, after 10 s", waiting)
    check("[slowpick] ... and the sign-in completes", ok, page.url[:80])
    ctx.close()

    # [refused] a real connection error on the card port
    ctx, page = open_card_page(br, 1440, True)
    MODE["m"] = "refuse"
    t0 = time.time(); page.click("#kc-card-signin")
    try:
        page.wait_for_selector("#stig-card-blocked:not([hidden])", timeout=15000); shown = True
    except Exception:
        shown = False
    dt = time.time() - t0
    check("[refused] the card port refuses: the blocked message appears (%.1f s), the button is back" % dt,
          shown and dt < 9 and page.get_attribute("#kc-card-signin", "value") == CARD_LABEL and not page.is_disabled("#kc-card-signin"))
    check("[refused] ... and \"Use another sign-in method\" has the focus",
          page.evaluate("document.activeElement && document.activeElement.id") == "kc-card-other")
    ctx.close()

    # [hang] the card port accepts and never answers
    ctx, page = open_card_page(br, 1440, True)
    MODE["m"] = "hang"
    page.click("#kc-card-signin", no_wait_after=True)
    blocked, waiting = watch_blocked(page, 12)
    check("[hang] a card port that never answers: no blocked message (it looks exactly like an open picker), the note after 10 s",
          not blocked and waiting, "blocked=%s waiting=%s" % (blocked, waiting))
    page.click("#kc-card-other")
    page.wait_for_load_state()
    check("[hang] ... and \"Use another sign-in method\" still leads on (the password form)",
          page.query_selector("#kc-form-login") is not None or page.query_selector('input[name="password"]') is not None, page.url[:80])
    ctx.close()
    br.close()

print("%d/%d passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)

#!/usr/bin/env python3
"""Invite flow, end to end, with a throwaway mail.tm mailbox: wait for the IdP's execute-actions e-mail, check its
sender and the link's lifetime, open the link, accept the banner and terms, set a password, enrol TOTP, then prove a
password+TOTP sign-in works and that the link cannot be used twice. Prints PASS/FAIL; no secret is printed.
  invite_e2e.py --skill <keycloak-asd-stig>/keycloak-asd-stig --mailbox mailtm.json --username test.invitee"""
import argparse, html, json, os, re, secrets, sys, time, urllib.request

ap = argparse.ArgumentParser(); ap.add_argument("--skill", required=True); ap.add_argument("--mailbox", required=True)
ap.add_argument("--username", required=True); ap.add_argument("--idp", default="https://idp.example.mil"); ap.add_argument("--realm", default="example")
a = ap.parse_args()
sys.path.insert(0, os.path.join(a.skill, "scripts")); import e2e_check as E  # noqa: E402
mb = json.load(open(a.mailbox)); res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s  %-56s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)
def mt(path):
    return json.load(urllib.request.urlopen(urllib.request.Request("https://api.mail.tm" + path, headers={"Authorization": "Bearer " + mb["token"]})))

msg = None
for _ in range(40):
    ms = mt("/messages").get("hydra:member", [])
    if ms:
        msg = mt("/messages/%s" % ms[0]["id"]); break
    time.sleep(6)
check("invitation e-mail arrived", msg is not None, msg and "from %s, subject %r" % (msg["from"]["address"], msg["subject"]))
if not msg:
    sys.exit(1)
check("sent from the verified sender domain", msg["from"]["address"].endswith("@notify.example.mil"), msg["from"]["address"])
body = (msg.get("html") or [""])[0] if isinstance(msg.get("html"), list) else (msg.get("html") or msg.get("text") or "")
body = body or msg.get("text", "")
links = [html.unescape(u) for u in re.findall(r'https://[^"\s<>]+/login-actions/action-token\?[^"\s<>]+', body)]
check("contains the set-up link to this IdP", bool(links) and links[0].startswith(a.idp), "%d link(s)" % len(links))
lt = re.search(r"expire[s]? (?:within|in) ([^.<\n]+)", (msg.get("text") or ""))
check("states the link's lifetime", bool(lt), lt.group(1).strip() if lt else "")

ctx = {"new_pw": "Iv1!" + secrets.token_hex(12)}
b = E.Browser()
kind, url, page = b.go(links[0], None, "https://never.invalid")
seen = []
for _ in range(10):
    if kind != "page":
        break
    pid = E.page_id(page); seen.append(pid)
    if pid in ("login-info",):   # "Perform the following actions" / "click here to proceed"
        m = re.search(r'<a[^>]+href="([^"]+)"[^>]*>[^<]*Click here to proceed', page)
        if not m: break
        kind, url, page = b.go(html.unescape(m.group(1)), None, "https://never.invalid"); continue
    final, more = E.Flow.finish(type("F", (), {"a": type("A", (), {"redirect": "https://never.invalid"})()})(), b, kind, url, page, ctx, "https://never.invalid")
    seen += more
    break
ok_pages = {"login-login-update-password", "login-login-config-totp", "login-terms"} <= set(seen)
check("link walks through password, TOTP and terms", ok_pages, "pages=%s" % seen)
check("TOTP enrolled during set-up", bool(ctx.get("totp_secret")))
# sign in with the new password + TOTP through the account console client
time.sleep(31)
fl = E.Flow(argparse.Namespace(url=a.idp, realm=a.realm, client="account-console", redirect=a.idp + "/realms/%s/account/" % a.realm, admin_url=None))
b2 = E.Browser(); url, ver = fl.auth_url()
k, u, p = b2.go(url, None, fl.a.redirect)
act, f = E.form(p, "kc-form-login"); f.update({"username": a.username, "password": ctx["new_pw"]})
k, u, p = b2.go(act, f, fl.a.redirect)
final, seen2 = fl.finish(b2, k, u, p, ctx)
check("invitee signs in with password + TOTP", bool(final) and "login-login-otp" in seen2, "pages=%s" % seen2)
k, u, p = E.Browser().go(links[0], None, "https://never.invalid")
check("the link cannot be used twice", k == "page" and E.page_id(p) in ("error", "login-error", "login-login-page-expired", "info") or "expired" in p.lower() or "invalid" in p.lower(),
      E.page_id(p) if k == "page" else k)
print("\n%d/%d passed" % (sum(res), len(res))); sys.exit(0 if all(res) else 1)

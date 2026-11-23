#!/usr/bin/env python3
"""Live check of an onboarding client (`idp-onboarding`, or --client-id one of the config's onboarding.clientIds) on the deployed image (operating guide, "Portal account
administration", apply step 4). Runs ON the VM as root; joins the Keycloak container's network namespace itself.

A throwaway person `t.onb.<stamp>` is made a user manager by the operator's tooling (idp-admin.py grant, all apps:
no application role, no app-a access), signs in through idp-onboarding exactly as app-a's page will (PKCE, the
recorded redirect URI; the flow stops at the redirect, so nothing ever reaches app-a), and checks:
  1. the token: azp idp-onboarding; realm-management roles exactly query-users + query-groups; allowed-origins exactly
     the recorded origin; no refresh token;
  2. a call outside the profile (GET clients) -> 403, with CORS for the portal's origin;
  3. a read inside the profile (the first tree the client serves, e.g. /app-a) -> 200 with Access-Control-Allow-Origin = the portal; the
     same call with another Origin -> refused (403), no CORS grant for it;
  4. a stale write (the token's authentication older than max-auth-age; the test waits for it) -> 401 with the RFC 9470
     challenge (insufficient_user_authentication, max_age), WWW-Authenticate exposed to the page. The access token
     lives as long as max-auth-age (300 s), so after the wait it has EXPIRED and Keycloak itself would answer a plain
     401 before the step-up rule runs: the check first takes a new token silently through the IdP session (SSO, no
     max_age), which keeps the old auth_time - exactly what app-a's page holds 5 minutes after a sign-in. The write's
     body is invalid (a malformed username), so even a filter that let it through could create nothing.
It changes nothing else and removes the person (and so its allowlist entry, at the guard run it ends with). The
preflight through the path filter is checked from the operator Mac (the operating guide's curl line).

  sudo python3 onboarding_live_check.py [--client-id <onboarding client>] [--skill <keycloak-asd-stig skill dir>]
Run it under tmux or nohup: it waits out max-auth-age. A hang-up or SIGTERM still ends through the cleanup below; if
the run does not end with its "cleanup: ... deleted" line, run tests/cleanup_test_fixtures.py (it removes t.onb.*).
"""
import signal, sys
# a lost SSH session (SIGHUP) or a kill (SIGTERM) becomes a normal exit, so `finally` always deletes the person
signal.signal(signal.SIGHUP, lambda *a: sys.exit(130))
signal.signal(signal.SIGTERM, lambda *a: sys.exit(130))
import argparse, glob, importlib.machinery, importlib.util, json, os, socket, subprocess, time, urllib.error, urllib.parse, urllib.request

ADM = "/usr/local/sbin/idp-admin.py"
SKILL = (sys.argv[sys.argv.index("--skill") + 1] if "--skill" in sys.argv else
         sorted(glob.glob("/srv/idp/src/keycloak-asd-stig-*/keycloak-asd-stig"), key=os.path.getmtime)[-1])
ld = importlib.machinery.SourceFileLoader("idp_admin", ADM)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
kc = M.KC()                                          # joins the Keycloak container's network namespace
HOST, PORT, REALM = M.ADMIN_HOST, M.ADMIN_PORT, M.REALM
_gai = socket.getaddrinfo
socket.getaddrinfo = lambda h, p, *r, **k: _gai("127.0.0.1", PORT, *r, **k) if h == HOST else _gai(h, p, *r, **k)
BASE = "https://%s" % HOST
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import persona      # noqa: E402
sys.path.insert(0, os.path.join(SKILL, "scripts")); import e2e_check as E            # noqa: E402
# --client-id: which onboarding client to check (default the first, idp-onboarding); any of the config's onboarding.clientIds
OB = sys.argv[sys.argv.index("--client-id") + 1] if "--client-id" in sys.argv else M.ONBOARDING_CLIENT_IDS[0]
if OB not in M.ONBOARDING_CLIENT_IDS:
    sys.exit("%s is not an onboarding client (idp-onboarding or the config's onboarding.clientIds: %s)" % (OB, ", ".join(M.ONBOARDING_CLIENT_IDS)))
rec = M.load_onboarding().get(OB) or sys.exit("no record for %s: run onboarding-client-setup first" % OB)
REDIRECT, ORIGIN, MAXAGE = rec["redirect"], rec["origin"], int(rec.get("max_age", 300))
TREE = "/" + (rec.get("apps") or ["app-a"])[0]          # the first application tree the client serves (its record)
res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s  %-90s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

_last, _totp = {}, E.totp
def totp_once(secret, *x, **k):
    while int(time.time()) // 30 == _last.get(secret):
        time.sleep(1)
    _last[secret] = int(time.time()) // 30
    return _totp(secret, *x, **k)
E.totp = totp_once

def call(tok, method, path, body=None, origin=ORIGIN):
    h = {"Authorization": "Bearer " + tok["access_token"], "Content-Type": "application/json"}
    if origin:
        h["Origin"] = origin
    req = urllib.request.Request("%s/admin/realms/%s/%s" % (BASE, REALM, path.lstrip("/")), method=method, headers=h,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}

def run_adm(*args):
    p_ = subprocess.run([sys.executable, ADM] + list(args), capture_output=True, text=True, timeout=600)
    return p_.returncode, (p_.stdout + p_.stderr).strip()

name = "t.onb.%s" % time.strftime("%H%M%S")
try:
    p = persona.Person(M, kc, E, run_adm, BASE, REALM, name, "idp-user-manager")
    _last[p.ctx.get("totp_secret")] = int(time.time()) // 30          # the persona's own sign-in used this period's code
    fl = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client=OB, redirect=REDIRECT, admin_url=None, client_secret=None, cacert=None))
    b = E.Browser(); url, ver = fl.auth_url(extra={"max_age": "0"})
    k, u, pg = b.go(url, None, REDIRECT)
    act, f = E.form(pg, "kc-form-login"); f.update({"username": p.username, "password": p.pw})
    k, u, pg = b.go(act, f, REDIRECT)
    final, seen = fl.finish(b, k, u, pg, p.ctx)
    code = urllib.parse.parse_qs(urllib.parse.urlparse(final).query)["code"][0] if final and "code=" in final else None
    tok = fl.token(code, ver) if code else None
    check("sign-in through %s (password + TOTP, the realm's own flow)" % OB, tok is not None, seen)
    cl = E.claims(tok["access_token"]) if tok else {}
    rm = sorted((cl.get("resource_access") or {}).get("realm-management", {}).get("roles", []))
    check("1. token: realm-management roles exactly query-groups + query-users", rm == ["query-groups", "query-users"], rm)
    check("1. token: azp %s, allowed-origins exactly %s, no refresh token" % (OB, ORIGIN),
          cl.get("azp") == OB and cl.get("allowed-origins") == [ORIGIN] and not (tok or {}).get("refresh_token"),
          {k_: cl.get(k_) for k_ in ("azp", "allowed-origins")})
    st, hd = call(tok, "GET", "clients")
    check("2. outside the profile (GET clients): 403, CORS for the portal", st == 403 and hd.get("access-control-allow-origin") == ORIGIN,
          (st, hd.get("access-control-allow-origin")))
    g = M.group_by_path(kc, TREE)
    st, hd = call(tok, "GET", "groups/%s/children" % g["id"])
    check("3. inside the profile (the %s group's children): 200, CORS = the portal only" % TREE,
          st == 200 and hd.get("access-control-allow-origin") == ORIGIN, (st, hd.get("access-control-allow-origin")))
    st, hd = call(tok, "GET", "groups/%s/children" % g["id"], origin="https://example.invalid")
    check("3. the same call from another origin: refused, no CORS grant for it",
          st == 403 and hd.get("access-control-allow-origin") != "https://example.invalid", (st, hd.get("access-control-allow-origin")))
    wait = MAXAGE + 5 - (int(time.time()) - int(cl.get("auth_time") or 0))
    if wait > 0:
        print("... waiting %d s for the token's authentication to pass max-auth-age (%d s)" % (wait, MAXAGE), flush=True)
        time.sleep(wait)
    url2, ver2 = fl.auth_url()                      # silent: the session cookie, no max_age -> same auth_time, new token
    k2, u2, pg2 = b.go(url2, None, REDIRECT)
    fin2, seen2 = fl.finish(b, k2, u2, pg2, p.ctx)
    code2 = urllib.parse.parse_qs(urllib.parse.urlparse(fin2).query)["code"][0] if fin2 and "code=" in fin2 else None
    tok2 = fl.token(code2, ver2) if code2 else None
    cl2 = E.claims(tok2["access_token"]) if tok2 else {}
    check("4. a new token through the session, without signing in again: same auth_time, not expired",
          tok2 is not None and cl2.get("auth_time") == cl.get("auth_time") and cl2.get("exp", 0) > time.time(), (seen2, cl2.get("auth_time")))
    tok = tok2 or tok
    st, hd = call(tok, "POST", "stig-accounts/users", {"username": "INVALID", "email": "x", "firstName": "x", "lastName": "x",
                                                       "group": TREE + "/viewer"})
    wa = hd.get("www-authenticate", "")
    check("4. a stale write: 401 with the RFC 9470 challenge (insufficient_user_authentication, max_age=%d), CORS" % MAXAGE,
          st == 401 and "insufficient_user_authentication" in wa and 'max_age="%d"' % MAXAGE in wa
          and hd.get("access-control-allow-origin") == ORIGIN, (st, wa[:80]))
    exposed = [x.strip().lower() for x in hd.get("access-control-expose-headers", "").split(",")]
    check("4. ... and WWW-Authenticate is exposed to the page (Access-Control-Expose-Headers)", "www-authenticate" in exposed,
          hd.get("access-control-expose-headers"))
finally:
    f_ = kc.api("GET", "/users?exact=true&username=%s" % M.q(name))
    if f_:
        kc.api("DELETE", "/users/%s" % f_[0]["id"])
    rc, out = run_adm("guard")                     # drops the deleted person's allowlist entry
    print("cleanup: %s deleted; guard exit %d" % (name, rc))
print("\n%d/%d passed" % (sum(res), len(res))); sys.exit(0 if res and all(res) else 1)

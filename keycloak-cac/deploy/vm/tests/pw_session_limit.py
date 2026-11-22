#!/usr/bin/env python3
"""Concurrent-session limit (V-222387) on the password+TOTP path, for a realm where no test card exists.
Uses e2e_check.py's browser and flow helpers (sys.path: the keycloak-asd-stig scripts directory).

The user must be new, with a temporary password: the first sign-in changes it and enrols TOTP (secret kept in
memory only). Then `limit` sign-ins, each in a fresh browser with a fresh TOTP code, must succeed, and one more
must be refused. Consumes the account; disable it afterwards.

  pw_session_limit.py --url https://idp --realm R --client C --redirect URI --client-secret-file F \
      --user U --temp-password-file F --new-password-file F [--limit 3]
"""
import argparse, sys, time
sys.path.insert(0, "/opt/kcstig/scripts")
import e2e_check as E

ap = argparse.ArgumentParser()
for o in ("url", "realm", "client", "redirect", "client-secret-file", "user", "temp-password-file", "new-password-file"):
    ap.add_argument("--" + o, required=True)
ap.add_argument("--limit", type=int, default=3)
ap.add_argument("--cacert")
a = ap.parse_args()
rd = lambda f: open(f).read().strip()
a.client_secret = rd(a.client_secret_file)
fl = E.Flow(a)

def login(pw, ctx):
    b = E.Browser(a.cacert)
    url, ver = fl.auth_url()
    k, u, p = b.go(url, None, a.redirect)
    act, f = E.form(p, "kc-form-login"); f.update({"username": a.user, "password": pw})
    k, u, p = b.go(act, f, a.redirect)
    return fl.finish(b, k, u, p, ctx)

ctx = {"new_pw": rd(a.new_password_file)}
final, seen = login(rd(a.temp_password_file), ctx)
E.report("First sign-in: password change + TOTP enrolment", bool(final) and "login-login-config-totp" in seen, "V-222547 V-222526", "pages=%s" % seen)
ok = 1 if final else 0
last_step = int(time.time()) // 30
for i in range(a.limit):          # sessions 2..limit+1 (the enrolment sign-in is session 1)
    while int(time.time()) // 30 == last_step:   # a TOTP code is single-use: wait for the next period
        time.sleep(2)
    last_step = int(time.time()) // 30
    final, seen = login(ctx["new_pw"], ctx)
    if final:
        ok += 1
    last = seen
E.report("Concurrent session limit enforced (password+TOTP)", ok == a.limit, "V-222387",
         "%d of %d sign-ins succeeded; last pages=%s" % (ok, a.limit + 1, last))
print("\n%d/%d passed" % (sum(E.RESULTS), len(E.RESULTS)))
sys.exit(0 if all(E.RESULTS) else 1)

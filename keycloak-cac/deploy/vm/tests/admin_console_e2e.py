#!/usr/bin/env python3
"""The example realm's admin console on the public host: access by role, MFA on every sign-in. Runs on the operator's
Mac; creates two throwaway password accounts over SSH (passwords generated here, in memory only), deletes them after.

  1. grant idp-admin leaves a password-only account PENDING; it enrols TOTP as a non-admin (token refused by the admin
     API); promote makes it an administrator; then password + TOTP (prompt, never set-up) reaches the admin API
  1b. an administrator with a password and no second factor is refused at the console, with no TOTP set-up offered
  2. the same account with the correct password and no TOTP code gets no further than the TOTP prompt
  3. an account with only an application role signs in but its token is refused by the admin API
  4. the master realm (console, login, admin API, token endpoint) and dynamic client registration answer 404 from the
     network; the realm's discovery, keys and account console still answer
  5. the realm's own console is served on the public host

  admin_console_e2e.py --skill <keycloak-asd-stig>/keycloak-asd-stig
"""
import argparse, json, os, secrets, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

ap = argparse.ArgumentParser(); ap.add_argument("--skill", required=True)
ap.add_argument("--idp", default="https://idp.example.mil"); ap.add_argument("--realm", default="example")
a = ap.parse_args()
sys.path.insert(0, os.path.join(a.skill, "scripts")); import e2e_check as E  # noqa: E402
res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s  %-62s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)
def remote(cmd, stdin=None):
    p = subprocess.run(["ssh", "idp-host", cmd], input=stdin, capture_output=True, text=True); return (p.stdout + p.stderr).strip()
CONSOLE = "%s/admin/%s/console/" % (a.idp, a.realm)
stamp = time.strftime("%H%M%S")
users = {"boss": ("t.console-admin%s" % stamp, "idp-admin"), "plain": ("t.console-user%s" % stamp, None),
         "nootp": ("t.console-nootp%s" % stamp, None)}
pw = {k: "Tc1!" + secrets.token_hex(12) for k in users}
new = {k: "Tn2!" + secrets.token_hex(12) for k in users}
for k, (u, role) in users.items():
    f = "/tmp/.tc-%s" % stamp
    out = remote("umask 077; cat > %s && sudo idp-admin.py user-create-pw %s %s@test.invalid T Console app-b:member --temp-password-file %s --temporary; rm -f %s"
                 % (f, u, u, f, f), stdin=pw[k])
    if role:
        out += " | " + remote("sudo idp-admin.py grant %s %s" % (u, role))
        grant_out = out
    print("setup:", out.splitlines()[-1][:120])
def kc_py(code):
    return remote("sudo python3 -c \"import importlib.machinery as M; m=M.SourceFileLoader('a','/usr/local/sbin/idp-admin.py').load_module(); kc=m.KC(); %s\"" % code)
# an administrator holding a password and NO second factor (as a console promotion would make one)
kc_py("u=m.user(kc,'%s'); kc.api('PUT','/users/%%s/groups/%%s' %% (u['id'], m.group_by_path(kc,'/roles/idp-admin')['id'])); "
      "kc.api('PUT','/users/%%s' %% u['id'], dict(kc.api('GET','/users/%%s' %% u['id']), requiredActions=[]))" % users["nootp"][0])

def console_login(username, password, ctx):
    fl = E.Flow(argparse.Namespace(url=a.idp, realm=a.realm, client="security-admin-console", redirect=CONSOLE,
                                   admin_url=None, client_secret=None, cacert=None))
    b = E.Browser(); url, ver = fl.auth_url()
    k, u, p = b.go(url, None, CONSOLE)
    act, f = E.form(p, "kc-form-login"); f.update({"username": username, "password": password})
    k, u, p = b.go(act, f, CONSOLE)
    if k == "page" and E.page_id(p) == "login-login":
        return None, ["login-login:" + E.error_text(p)], (k, p)
    final, seen = fl.finish(b, k, u, p, ctx)
    tok = fl.token(urllib.parse.parse_qs(urllib.parse.urlparse(final).query)["code"][0], ver) if final and "code=" in final else None
    return tok, seen, (k, p)

def admin_get(tok, path):
    req = urllib.request.Request("%s/admin/realms/%s%s" % (a.idp, a.realm, path), headers={"Authorization": "Bearer " + tok["access_token"]})
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status
    except urllib.error.HTTPError as e: return e.code

try:
    st = urllib.request.urlopen(CONSOLE, timeout=30).status
    check("the realm's admin console is served on the public host", st == 200, "GET %s -> %s" % (CONSOLE, st))
    # 1. an administrator is never made on a password alone: grant leaves it pending; it enrols TOTP as a non-admin;
    #    promote finishes it; only then does its token read the admin API
    check("grant idp-admin to a password-only account: PENDING, not an administrator", "PENDING" in grant_out, grant_out.splitlines()[-1][:90])
    ctx = {"new_pw": new["boss"]}
    tok, seen, _ = console_login(users["boss"][0], pw["boss"], ctx)
    check("... it signs in as a non-admin, enrolling TOTP; its token is refused by the admin API", bool(tok) and "login-login-config-totp" in seen
          and admin_get(tok, "/users?max=1") == 403, "pages=%s HTTP %s" % (seen, tok and admin_get(tok, "/users?max=1")))
    pr = remote("sudo idp-admin.py promote %s" % users["boss"][0])
    check("... promote: an administrator now (sign-in path otp)", "promoted" in pr and "otp" in pr, pr.splitlines()[-1][:100] if pr else pr)
    time.sleep(31)
    tok, seen, _ = console_login(users["boss"][0], new["boss"], ctx)
    check("idp-admin signs in to the console with password + TOTP (prompt, never set-up)", bool(tok) and "login-login-otp" in seen
          and "login-login-config-totp" not in seen, "pages=%s" % seen)
    check("... and its token reads the admin API (users)", bool(tok) and admin_get(tok, "/users?max=1") == 200, "HTTP %s" % (tok and admin_get(tok, "/users?max=1")))
    # 1b. review 2026-11-10 HIGH 2: an administrator with a password and no second factor gets nothing - no console,
    #     no TOTP set-up (anyone holding that password would otherwise enrol their own TOTP)
    tok3, seen3, last3 = console_login(users["nootp"][0], pw["nootp"], {"new_pw": new["nootp"]})
    check("admin with password and no OTP: console refused, no TOTP set-up offered", tok3 is None and not any("config-totp" in x for x in seen3)
          and last3[0] == "page" and E.page_id(last3[1]) == "login-login", "pages=%s" % seen3)
    # 2. correct password, no TOTP: stops at the TOTP prompt
    time.sleep(31)
    fl = E.Flow(argparse.Namespace(url=a.idp, realm=a.realm, client="security-admin-console", redirect=CONSOLE, admin_url=None, client_secret=None, cacert=None))
    b = E.Browser(); url, ver = fl.auth_url(); k, u, p = b.go(url, None, CONSOLE)
    act, f = E.form(p, "kc-form-login"); f.update({"username": users["boss"][0], "password": new["boss"]})
    k, u, p = b.go(act, f, CONSOLE)
    check("idp-admin with the correct password alone stops at TOTP", k == "page" and E.page_id(p) == "login-login-otp", E.page_id(p) if k == "page" else k)
    # 3. application-only account
    ctx2 = {"new_pw": new["plain"]}
    tok2, seen2, _ = console_login(users["plain"][0], pw["plain"], ctx2)
    check("an application-only account's token is refused by the admin API", bool(tok2) and admin_get(tok2, "/users?max=1") == 403,
          "HTTP %s" % (tok2 and admin_get(tok2, "/users?max=1")))
    # 2026-11-10 incident check, as a PERSON signed in to the console: view, reset-password, impersonate an admin
    boss_id = remote("sudo python3 -c \"import importlib.machinery as M; m=M.SourceFileLoader('a','/usr/local/sbin/idp-admin.py').load_module(); print(m.user(m.KC(),'%s')['id'])\"" % users["boss"][0]).splitlines()[-1]
    def call(tok, method, path, body=None):
        req = urllib.request.Request("%s/admin/realms/%s%s" % (a.idp, a.realm, path), method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": "Bearer " + tok["access_token"], "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r: return r.status
        except urllib.error.HTTPError as e: return e.code
    r = (call(tok2, "GET", "/users/%s" % boss_id), call(tok2, "PUT", "/users/%s/reset-password" % boss_id, {"type": "password", "value": "Hijack-1234567890!", "temporary": False}),
         call(tok2, "POST", "/users/%s/impersonation" % boss_id))
    check("an ordinary person cannot view/reset/impersonate an administrator", all(x in (403, 404) for x in r), "view %s, reset %s, impersonate %s" % r)
    # 4. master realm: off the network (allowlist): its console, login and token endpoints all answer 404
    def status(url, data=None):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=30).status
        except urllib.error.HTTPError as e:
            return e.code
    for path in ("/admin/master/console/", "/realms/master/protocol/openid-connect/auth?client_id=security-admin-console", "/admin/realms/master/users"):
        st = status(a.idp + path)
        check("master realm unreachable from the network: %s" % path.split("?")[0], st == 404, "HTTP %s" % st)
    data = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": "stig-automation", "client_secret": "x"}).encode()
    st = status("%s/realms/master/protocol/openid-connect/token" % a.idp, data)
    check("master token endpoint unreachable from the network", st == 404, "HTTP %s" % st)
    # dynamic client registration bypasses the admin gate and no relying party uses it: off the network too
    for path in ("/realms/%s/clients-registrations/openid-connect" % a.realm, "/realms/%s/clients-registrations/default" % a.realm):
        st = status(a.idp + path, b"{}")
        check("client registration unreachable from the network: %s" % path, st == 404, "HTTP %s" % st)
    for path in ("/realms/%s/.well-known/openid-configuration" % a.realm, "/realms/%s/protocol/openid-connect/certs" % a.realm,
                 "/realms/%s/account/" % a.realm):
        st = status(a.idp + path)
        check("the realm's sign-in paths still answer: %s" % path, st == 200, "HTTP %s" % st)
finally:
    for k, (u, _) in users.items():
        print("cleanup:", remote("sudo idp-admin.py user-delete %s" % u))
print("\n%d/%d passed" % (sum(res), len(res))); sys.exit(0 if all(res) else 1)

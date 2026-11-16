#!/usr/bin/env python3
"""The checks behind keycloak-cac/tests/passkey-realm.sh (a lab container with a passkey extra realm "partners").

Admin calls use the lab image's automation account (its secret derives from the bootstrap password in lab mode only).
Every account here is a throwaway in a throwaway container.
"""
import argparse, base64, email, glob, hashlib, html, json, os, re, subprocess, sys, time, urllib.error, urllib.parse, urllib.request, uuid
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "keycloak-asd-stig", "scripts"))
import kcstig as K, e2e_check as E, softauthn as S, passkey_flow as PF

ap = argparse.ArgumentParser()
ap.add_argument("--name", required=True); ap.add_argument("--port", required=True); ap.add_argument("--dir", required=True)
ap.add_argument("--smtp-host", required=True); ap.add_argument("--smtp-port", required=True)
ap.add_argument("--realm", default="partners"); ap.add_argument("--client", default="partner-app")
A = ap.parse_args()
BASE = "https://localhost:%s" % A.port
CA = os.path.join(A.dir, "root.crt")
REALM, RR = A.realm, "/realms/%s" % A.realm
os.environ.update({"KC_CLIENT_ID": "stig-automation", "KC_CACERT": CA,
                   "KC_CLIENT_SECRET": hashlib.sha256(("cac-lab-automation:" + os.environ["LAB_BOOTSTRAP_PW"]).encode()).hexdigest()[:48]})
RES = []
def check(name, ok, detail=""):
    RES.append(bool(ok)); print("%s %-84s %s" % ("PASS" if ok else "FAIL", name, str(detail)[:220]), flush=True)

def admin():
    kc = K.KC(BASE, "master", CA); kc.login(); return kc
kc = admin()
MAIL = os.path.join(A.dir, "mail")
def smtp(realm=REALM):
    kc.api("PUT", "/realms/%s" % realm, {"smtpServer": {"host": A.smtp_host, "port": str(A.smtp_port), "from": "idp@lab.invalid",
                                                       "auth": "false", "ssl": "false", "starttls": "false"}})
def mails():
    return sorted(glob.glob(os.path.join(MAIL, "*.eml")))
def next_link(before, pattern=r"(https://\S+action-token\S+)"):
    for _ in range(40):
        new = [m for m in mails() if m not in before]
        if new:
            msg = email.message_from_bytes(open(new[-1], "rb").read())
            body = "".join(p.get_payload(decode=True).decode("utf-8", "replace") for p in msg.walk() if p.get_content_type() == "text/plain")
            m = re.search(pattern, body)
            return m.group(1) if m else None
        time.sleep(0.5)
    return None
def invite(username, actions=("VERIFY_EMAIL", "TERMS_AND_CONDITIONS", "webauthn-register-passwordless")):
    before = mails()
    uid = kc.api("POST", RR + "/users", {"username": username, "email": username + "@acme.example", "firstName": "Test",
                                          "lastName": "User", "enabled": True})
    kc.api("PUT", RR + "/users/%s/execute-actions-email?lifespan=3600" % uid, list(actions))
    return uid, next_link(before)
def set_up(link, alg="ES256", uv=True):
    a = S.Authenticator(alg, workdir=A.dir)
    ok, seen, err = PF.set_up(E.Browser(CA), link, a, BASE + RR + "/account")
    return a, ok, seen, err
def wait_healthy():
    for _ in range(120):
        r = subprocess.run(["docker", "exec", A.name, "/opt/keycloak-cac/bin/cac-entrypoint.sh", "health"], capture_output=True)
        if r.returncode == 0:
            return True
        time.sleep(5)
    return False
def logs(since):
    r = subprocess.run(["docker", "logs", "--since", str(since), A.name], capture_output=True, text=True)
    return r.stdout + r.stderr

fl = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client=A.client, redirect="https://app.example/cb", admin_url=None,
                               client_secret=None, cacert=CA))

# ---- 1. both realms applied, clients kept apart
start_logs = logs(0)
check("the main realm and the extra realm were applied on start", "realms/dod-cac" in start_logs and "realms/%s (extra realm)" % REALM in start_logs)
clients = {c["clientId"] for c in kc.api("GET", RR + "/clients")}
main_clients = {c["clientId"] for c in kc.api("GET", "/realms/dod-cac/clients")}
check("the extra realm has its own client and not the main realm's", A.client in clients and "main-app" not in clients
      and "main-app" in main_clients and A.client not in main_clients, sorted(clients - {"account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"}))
prof = os.path.join(A.dir, "partners-profile.json")
vr = subprocess.run([sys.executable, os.path.join(HERE, "..", "..", "..", "keycloak-asd-stig", "scripts", "kcstig.py"), "verify",
                     "--profile", prof, "--url", BASE, "--live-url", BASE, "--out", os.path.join(A.dir, "reports")],
                    capture_output=True, text=True)
results = {}
try:
    results = json.load(open(os.path.join(A.dir, "reports", "%s-asd-stig-results.json" % REALM)))["checks"]
except (OSError, ValueError):
    pass
want = ["flow.passkey_only", "flow.no_enrolment_at_sign_in", "webauthn.algorithms_fips", "realm.no_x509", "realm.no_idp", "realm.registration_flow_denied",
        "realm.required_actions", "flow.admin_allowlist_gate", "credentials.passkey_only", "realm.direct_grant_denied",
        "workflow.inactive_35d", "flow.session_limits"]
check("kcstig verify: every passkey-realm check passes", results and all(results.get(k, {}).get("status") == "pass" for k in want),
      {k: results.get(k, {}).get("status") for k in want} if results else vr.stderr[-300:])
fails = sorted(k for k, v in results.items() if v["status"] == "fail")
check("kcstig verify: no failing check at all", results and not fails, fails)

# ---- 2. invitation: e-mail verified, the DoD notice (terms), a passkey registered
smtp()
name = "jane.%s" % uuid.uuid4().hex[:6]
uid, link = invite(name)
check("the invitation mail carries an action link", bool(link))
a, ok, seen, err = set_up(link)
check("set-up completes: verify e-mail, DoD notice (terms page), passkey registration", ok and "login-terms" in seen
      and "login-webauthn-register" in seen, "%s %s" % (seen, err))
check("... the browser was offered exactly ES256 and RS256", getattr(a, "offered", None) == [-7, -257], getattr(a, "offered", None))
u = kc.api("GET", RR + "/users/%s" % uid)
check("... the address is verified and no action is left", u.get("emailVerified") is True and not u.get("requiredActions"),
      (u.get("emailVerified"), u.get("requiredActions")))
creds = kc.api("GET", RR + "/users/%s/credentials" % uid)
check("... exactly one credential: a passwordless ES256 passkey", [(c["type"], K.cose_alg(c["credentialData"])) for c in creds]
      == [("webauthn-passwordless", "ES256")], [(c["type"], K.cose_alg(c["credentialData"])) for c in creds])
# a set-up link sets up ONE passkey: once used, it is refused; a second browser that opened it in parallel cannot add one
creds_before = len(kc.api("GET", RR + "/users/%s/credentials" % uid))
b_re = E.Browser(CA)
trail, k_re, u_re, p_re = [], *b_re.go(link, None, "https://never.invalid/")
for _ in range(4):                          # follow whatever it offers, the way someone holding the link would
    trail.append((k_re, E.page_id(p_re) if k_re == "page" else u_re[:80]))
    if k_re != "page":
        break
    nxt = re.search(r'href="([^"]*(?:action-token|required-action|login-actions)[^"]*)"', p_re)
    act, f = E.form(p_re)
    if nxt:
        k_re, u_re, p_re = b_re.go(html.unescape(nxt.group(1)), None, "https://never.invalid/")
    elif act:
        k_re, u_re, p_re = b_re.go(act, f, "https://never.invalid/")
    else:
        break
reached = [t for t in trail if t[0] == "redirect" or "code=" in str(t[1])
           or t[1] in ("login-info", "login-terms", "login-webauthn-register", "login-verify-email")]
check("a set-up link, once used, is refused: no set-up page, no redirect, no code, no new credential",
      not reached and trail[0][0] == "error" and len(kc.api("GET", RR + "/users/%s/credentials" % uid)) == creds_before, trail)
par_id, par_link = invite("parallel.%s" % uuid.uuid4().hex[:6])
bA = E.Browser(CA); bA.go(par_link, None, BASE + RR + "/account")              # browser A opens it ...
_, okB, _, _ = set_up(par_link)                                                # ... browser B completes it ...
okA, seenA, errA = PF.set_up(bA, par_link, S.Authenticator("ES256", workdir=A.dir), BASE + RR + "/account")   # ... then A tries
check("... and a browser that opened it before another completed cannot add a second passkey",
      okB and not okA and len(kc.api("GET", RR + "/users/%s/credentials" % par_id)) == 1, (okB, okA, seenA))
uid_rs, link = invite("rsa.%s" % uuid.uuid4().hex[:6])
a_rs, ok, seen, err = set_up(link, "RS256")
check("an RS256 passkey registers (Windows Hello)", ok, err)
uid_ed, link = invite("eddsa.%s" % uuid.uuid4().hex[:6])
_, ok, seen, err = set_up(link, "Ed25519")
check("an Ed25519 passkey is refused at registration (not in the policy)", not ok and not kc.api("GET", RR + "/users/%s/credentials" % uid_ed),
      "%s %s" % (seen[-2:], err))

# ---- 3. sign-in
def signin(label, expect, *args, **kw):
    code, pages, err, banner = PF.sign_in(fl, *args, cacert=CA, **kw)
    check(label, bool(code) == expect and banner, "%s %s banner=%s" % (pages, err, banner))
signin("username, then the passkey: signed in (the DoD banner is on the page)", True, a, "username", name)
signin("the discoverable 'Sign in with passkey' button: signed in", True, a, "button")
signin("RS256 passkey: signed in", True, a_rs, "button")
since = int(time.time())
signin("no user verification (button path): refused by the SERVER", False, a, "button", uv=False)
signin("no user verification (passkey step): refused", False, a, "username", name, uv=False)
for _ in range(4):
    signin("a bad signature: refused", False, a, "button", bad_signature=True)
signin("a counter that went backwards (a cloned authenticator): refused", False, a, "button", counter=1)
other = S.Authenticator("ES256", workdir=A.dir); other.user_handle = a.user_handle
signin("a device without the credential: refused", False, other, "button")
signin("a username alone: no code (it stays on the passkey step)", False, a, "username-only", name)
bf = kc.api("GET", RR + "/attack-detection/brute-force/users/%s" % uid)
check("failed passkey assertions do not count towards the lockout (AC-7 rationale recorded)", bf.get("numFailures") == 0 and not bf.get("disabled"), bf)
for _ in range(4):                          # the username path: the account IS in the context when the assertion fails
    PF.sign_in(fl, a, "username", name, cacert=CA, bad_signature=True)
PF.sign_in(fl, other, "username", name, cacert=CA)
bf = kc.api("GET", RR + "/attack-detection/brute-force/users/%s" % uid)
check("... nor in the username path, with the account in context (no lockout anyone could cause, no 'locked' oracle)",
      bf.get("numFailures") == 0 and not bf.get("disabled"), bf)
signin("... and the account still signs in", True, a, "button")
# an account with NO passkey (an unclaimed invitation; one invited and half set up; one with nothing pending) is
# refused at sign-in by its username alone - never sent to a passkey set-up - and the e-mailed link still sets it up
def username_only(n):
    b2 = E.Browser(CA); url, _ = fl.auth_url(); k, u2, p = b2.go(url, None, fl.a.redirect)
    act, f = E.form(p, "kc-form-login"); f["username"] = n; k, u2, p = b2.go(act, f, fl.a.redirect)
    hops = [k if k != "page" else E.page_id(p)]
    for _ in range(3):                                     # follow anything it offers next, the way an attacker would
        if k != "page":
            break
        act, f = E.form(p)
        if not act:
            break
        k, u2, p = b2.go(act, f, fl.a.redirect); hops.append(k if k != "page" else E.page_id(p))
    return hops, (k == "redirect" and "code=" in u2)
unclaimed = {}
for label, ra, verified in (("invited, not set up", ["VERIFY_EMAIL", "TERMS_AND_CONDITIONS", "webauthn-register-passwordless"], False),
                            ("verified, passkey set-up pending", ["webauthn-register-passwordless"], True),
                            ("nothing pending", [], True)):
    n = "unclaimed.%s" % uuid.uuid4().hex[:6]
    vid = kc.api("POST", RR + "/users", {"username": n, "email": n + "@acme.example", "firstName": "Un", "lastName": "Claimed",
                                          "enabled": True, "emailVerified": verified, "requiredActions": ra})
    unclaimed[label] = (vid, n)
    since_u = int(time.time())
    hops, code = username_only(n)
    reg_pages = [h for h in hops if h in ("login-webauthn-register", "login-terms", "login-verify-email", "login-update-password", "login-config-totp")]
    check("no passkey (%s): the username alone is refused - no code, no set-up page" % label, not code and not reg_pages
          and not kc.api("GET", RR + "/users/%s/credentials" % vid), hops)
    time.sleep(1)
    check("... logged STIG-PASSKEY-NOT-ENROLLED", "STIG-PASSKEY-NOT-ENROLLED" in logs(since_u) and n in logs(since_u))
# the response to an account without a passkey must not differ from the response to an unknown username
def normal(page, name):
    p = page.replace(name, "<NAME>")
    p = re.sub(r"(session_code|execution|tab_id|client_data|key)=[A-Za-z0-9_\-.%]+", r"\1=X", p)
    p = re.sub(r'(challenge\s*:\s*")[^"]*"', r'\1X"', p)
    p = re.sub(r'checkAuthSession\(\s*"[^"]*"', 'checkAuthSession("X"', p)
    p = re.sub(r'/resources/[a-z0-9]+/', "/resources/X/", p)
    return p
def answer(n):
    b2 = E.Browser(CA); url, _ = fl.auth_url(); k, u2, p = b2.go(url, None, fl.a.redirect)
    act, f = E.form(p, "kc-form-login"); f["username"] = n
    req = urllib.request.Request(act, data=urllib.parse.urlencode(f).encode())
    try:
        r = b2.op.open(req, timeout=30); st, body = r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        st, body = e.code, e.read().decode("utf-8", "replace")
    return st, E.page_id(body), E.error_text(body), normal(body, n)
ghost = "ghost.%s" % uuid.uuid4().hex[:6]
since_c = int(time.time())
ans_unknown = answer(ghost)
ans_nopk = answer(unclaimed["nothing pending"][1])
ans_invited = answer(unclaimed["invited, not set up"][1])
check("unknown username vs an account without a passkey: same status, page, message and body",
      ans_unknown == ans_nopk == ans_invited, [x[:3] for x in (ans_unknown, ans_nopk, ans_invited)])
time.sleep(1)
evs = re.findall(r'type=\\?"LOGIN_ERROR\\?".*?error=\\?"([a-z_]+)', logs(since_c))
check("... and the same event for both (user_not_found)", evs[:3] == ["user_not_found"] * 3, evs[:3])
bfs = [kc.api("GET", RR + "/attack-detection/brute-force/users/%s" % v)["numFailures"] for v, _ in unclaimed.values()]
check("... and none of those attempts counts against the account (nobody can lock an unclaimed account)", bfs == [0, 0, 0], bfs)

# a DISABLED account (with or without a passkey) is answered the same way: Keycloak's "Account is disabled" would tell it apart
dis = "disabled.%s" % uuid.uuid4().hex[:6]
dis_id = kc.api("POST", RR + "/users", {"username": dis, "email": dis + "@acme.example", "firstName": "Dis", "lastName": "Abled", "enabled": False})
cur = kc.api("GET", RR + "/users/%s" % uid_rs)
kc.api("PUT", RR + "/users/%s" % uid_rs, dict(cur, enabled=False))
ans_dis = answer(dis)
ans_dispk = answer(cur["username"])
kc.api("PUT", RR + "/users/%s" % uid_rs, dict(kc.api("GET", RR + "/users/%s" % uid_rs), enabled=True))
check("a disabled account, with or without a passkey, is answered exactly as an unknown username (no 'Account is disabled')",
      ans_unknown == ans_dis == ans_dispk,
      [x[:3] for x in (ans_unknown, ans_dis, ans_dispk)])

vid, n = unclaimed["invited, not set up"]
before = mails()
kc.api("PUT", RR + "/users/%s/execute-actions-email?lifespan=3600" % vid, ["VERIFY_EMAIL", "TERMS_AND_CONDITIONS", "webauthn-register-passwordless"])
a_un, ok, seen, err = set_up(next_link(before))
check("... the e-mailed set-up link still registers its passkey", ok and kc.api("GET", RR + "/users/%s/credentials" % vid), "%s %s" % (seen, err))
signin("... and the account then signs in with it", True, a_un, "username", n)

b = E.Browser(CA)
st = None
try:
    b.op.open(urllib.request.Request(BASE + RR + "/protocol/openid-connect/token", data=urllib.parse.urlencode(
        {"grant_type": "password", "client_id": A.client, "username": name, "password": "x"}).encode()), timeout=20)
    st = 200
except urllib.error.HTTPError as e:
    st = e.code
check("the direct (password) grant is refused", st in (400, 401), st)

# ---- 4. an organization invitation creates nothing (registration flow denied)
kc.api("PUT", RR, {"organizationsEnabled": True})
alias = "org%s" % uuid.uuid4().hex[:6]
oid = kc.api("POST", RR + "/organizations", {"name": alias, "alias": alias, "enabled": True, "domains": [{"name": alias + ".example"}]})
inv = "inv%s@%s.example" % (uuid.uuid4().hex[:4], alias)
before = mails()
st, _, _ = kc.raw("POST", "/admin" + RR + "/organizations/%s/members/invite-user" % oid, urllib.parse.urlencode(
    {"email": inv, "firstName": "In", "lastName": "Vite"}).encode(),
    {"Authorization": "Bearer " + kc.token, "Content-Type": "application/x-www-form-urlencoded"})
reg = next_link(before, r"(https://\S+/protocol/openid-connect/registrations\S+)")
ver = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
reg_pkce = reg and reg + "&" + urllib.parse.urlencode({"code_challenge": base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode(),
                                                      "code_challenge_method": "S256"})
outcome = []
for l in filter(None, (reg, reg_pkce)):
    k, u2, p = E.Browser(CA).go(l, None, "https://never.invalid/")
    outcome.append((k, E.page_id(p) if k == "page" else u2[:60]))
made = kc.api("GET", RR + "/users?username=%s&exact=true" % urllib.parse.quote(inv)) or kc.api("GET", RR + "/users?email=%s&exact=true" % urllib.parse.quote(inv))
check("an organization invitation's registration link (with and without PKCE) shows no form and creates no account",
      reg and len(outcome) == 2 and not any(o[1] == "login-register" for o in outcome) and not made, outcome)
kc.api("DELETE", RR + "/organizations/%s" % oid)
kc.api("PUT", RR, {"organizationsEnabled": False})

# ---- verify fails when an account without a passkey could get past the username form
flows = kc.api("GET", RR + "/authentication/flows/%s/executions" % urllib.parse.quote(kc.api("GET", RR)["browserFlow"]))
guard = [e for e in flows if e.get("providerId") == "stig-passkey-required"]
kc.api("DELETE", RR + "/authentication/executions/%s" % guard[0]["id"])
ch = K.Checker(kc, K.load_profile(prof, "/nonexistent"), K.server_capabilities(kc), None)
ch.R = kc.api("GET", RR); ch.check_passkey()
check("verify FAILS once stig-passkey-required is removed (flow.no_enrolment_at_sign_in)",
      ch.results.get("flow.no_enrolment_at_sign_in", {}).get("status") == "fail", ch.results.get("flow.no_enrolment_at_sign_in"))

# ---- verify reads client browser-flow overrides too
builtin = [f for f in kc.api("GET", RR + "/authentication/flows") if f["alias"] == "browser"][0]
pc = kc.api("GET", RR + "/clients?clientId=%s" % A.client)[0]
kc.api("PUT", RR + "/clients/%s" % pc["id"], dict(pc, authenticationFlowBindingOverrides={"browser": builtin["id"]}))
ch2 = K.Checker(kc, K.load_profile(prof, "/nonexistent"), K.server_capabilities(kc), None)
ch2.R = kc.api("GET", RR); ch2.check_passkey()
check("verify FAILS when a client overrides the browser flow with a password flow (flow.passkey_only, flow.no_enrolment_at_sign_in)",
      ch2.results["flow.passkey_only"]["status"] == "fail" and ch2.results["flow.no_enrolment_at_sign_in"]["status"] == "fail",
      ch2.results["flow.passkey_only"]["evidence"][-200:])
pc = kc.api("GET", RR + "/clients?clientId=%s" % A.client)[0]
kc.api("PUT", RR + "/clients/%s" % pc["id"], dict(pc, authenticationFlowBindingOverrides={}))

# ---- 5. a stored credential outside the policy fails verify; drift is undone by a restart
loose = kc.api("GET", RR)
kc.api("PUT", RR, dict(loose, webAuthnPolicyPasswordlessSignatureAlgorithms=["ES256", "RS256", "Ed25519"], registrationFlow="registration"))
uid_old, link = invite("legacy.%s" % uuid.uuid4().hex[:6])
_, ok, seen, err = set_up(link, "Ed25519")
check("(set-up) under a looser policy an Ed25519 credential registers", ok, err)
since = int(time.time())
subprocess.run(["docker", "restart", A.name], capture_output=True)
check("after a restart the container is healthy again", wait_healthy())
kc = admin()
R = kc.api("GET", RR)
check("a restart re-applies the extra realm: policy, registration flow and the no-passkey refusal back",
      R["webAuthnPolicyPasswordlessSignatureAlgorithms"] == ["ES256", "RS256"] and R["registrationFlow"] == "STIG Registration - Deny"
      and any(e.get("providerId") == "stig-passkey-required" for e in kc.api("GET", RR + "/authentication/flows/%s/executions" % urllib.parse.quote(R["browserFlow"]))),
      (R["webAuthnPolicyPasswordlessSignatureAlgorithms"], R["registrationFlow"]))
ok2, ev = K.stored_credential_findings(kc, REALM, ["ES256", "RS256"])
check("the policy governs registration only: the stored Ed25519 credential is found and named", not ok2 and "legacy." in ev and "Ed25519" in ev, ev)
# ---- the default sign-in (realm "public", sign_in=discoverable): no username is ever asked for
pprof = os.path.join(A.dir, "public-profile.json")
pv = K.Checker(kc, K.load_profile(pprof, "/nonexistent"), K.server_capabilities(kc), None)
pv.R = kc.api("GET", "/realms/public"); pv.realm = "public"; pv.check_passkey()
check("default realm: verify passes (passkey alone, no username step)", all(pv.results.get(k, {}).get("status") == "pass"
      for k in ("flow.passkey_only", "flow.no_enrolment_at_sign_in", "webauthn.algorithms_fips")),
      {k: v["status"] for k, v in pv.results.items()})
smtp("public")
RR_SAVE = RR; RR = "/realms/public"
pn = "pub.%s" % uuid.uuid4().hex[:6]
puid, plink = invite(pn)
pa, ok, seen, err = set_up(plink)
RR = RR_SAVE
check("default realm: the invitation registers a passkey", ok, "%s %s" % (seen, err))
pfl = E.Flow(argparse.Namespace(url=BASE, realm="public", client="account-console", redirect=BASE + "/realms/public/account/",
                                admin_url=None, client_secret=None, cacert=CA))
b3 = E.Browser(CA); url, _ = pfl.auth_url(); k, u3, first = b3.go(url, None, pfl.a.redirect)
check("default realm: the sign-in page asks for no username (passkey only)", k == "page" and 'name="username"' not in first
      and E.page_id(first) == "login-webauthn-authenticate", E.page_id(first) if k == "page" else k)
code, pages, perr, _ = PF.sign_in(pfl, pa, "button", cacert=CA)
check("default realm: 'Sign in with passkey' signs in", bool(code), "%s %s" % (pages, perr))
stranger = S.Authenticator("ES256", workdir=A.dir); stranger.user_handle = os.urandom(16)
_, pages, perr, _ = PF.sign_in(pfl, stranger, "button", cacert=CA)
_, pages2, perr2, _ = PF.sign_in(pfl, S.Authenticator("ES256", workdir=A.dir), "button", cacert=CA)
check("default realm: a passkey nobody here holds is refused the same way with or without a user handle",
      pages == pages2 and perr == perr2 and "redirect" not in pages, (pages, perr, pages2, perr2))
sys.exit(0 if all(RES) else 1)

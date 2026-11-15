#!/usr/bin/env python3
"""The checks behind keycloak-cac/tests/passkey-realm.sh (a lab container with a passkey extra realm "partners").

Admin calls use the lab image's automation account (its secret derives from the bootstrap password in lab mode only).
Every account here is a throwaway in a throwaway container.
"""
import argparse, base64, email, glob, hashlib, json, os, re, subprocess, sys, time, urllib.error, urllib.parse, urllib.request, uuid
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
want = ["flow.passkey_only", "webauthn.algorithms_fips", "realm.no_x509", "realm.no_idp", "realm.registration_flow_denied",
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
signin("... and the account still signs in", True, a, "button")
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
check("a restart re-applies the extra realm: policy back to ES256 + RS256, registration denied again",
      R["webAuthnPolicyPasswordlessSignatureAlgorithms"] == ["ES256", "RS256"] and R["registrationFlow"] == "STIG Registration - Deny",
      (R["webAuthnPolicyPasswordlessSignatureAlgorithms"], R["registrationFlow"]))
ok2, ev = K.stored_credential_findings(kc, REALM, ["ES256", "RS256"])
check("the policy governs registration only: the stored Ed25519 credential is found and named", not ok2 and "legacy." in ev and "Ed25519" in ev, ev)
sys.exit(0 if all(RES) else 1)

#!/usr/bin/env python3
"""Live checks of a security review's MEDIUM/LOW fixes. Runs ON the VM as root; creates t.hd.* users and removes
them. Prints PASS/FAIL.

  sudo python3 hardening_test.py --skill /srv/idp/src/keycloak-asd-stig-<sha>/keycloak-asd-stig --client <client id>

  MEDIUM 3  the path filter trusts no address a network client can present: through docker-proxy (host loopback and
            the bridge gateway) the master realm is 404; over IPv6 nothing listens; only 127.0.0.1 inside the
            container's network namespace reaches it
  MEDIUM 4  3 wrong passwords lock the account TEMPORARILY (the account stays enabled; brute-force status shows the
            lock), so nobody can disable an account for good from the network
  LOW       a user cannot change their own e-mail; manage-account-links removed and idp_link off, and every brokered
            sign-in must carry the admin-set identity (Keycloak still lets manage-account link); OCSP fails closed
"""
import argparse, http.client, importlib.machinery, importlib.util, json, os, socket, ssl, subprocess, sys, time, urllib.error
import urllib.parse, urllib.request, uuid

ap = argparse.ArgumentParser(); ap.add_argument("--skill", required=True); ap.add_argument("--client", required=True)
a = ap.parse_args()
res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s  %-74s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)
ld = importlib.machinery.SourceFileLoader("idp_admin", "/usr/local/sbin/idp-admin.py")
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
HOST = M.ADMIN_HOST
CTX = ssl.create_default_context()

def get(addr, port, path, family=socket.AF_INET):
    """GET over TLS to addr:port (SNI = the public host name), from wherever this process's network namespace is."""
    try:
        s = socket.socket(family, socket.SOCK_STREAM); s.settimeout(15); s.connect((addr, port))
    except OSError as e:
        return "no connection (%s)" % type(e).__name__
    c = http.client.HTTPSConnection(HOST, port, context=CTX, timeout=15); c.sock = CTX.wrap_socket(s, server_hostname=HOST)
    c.request("GET", path, headers={"Host": HOST}); r = c.getresponse(); r.read(); return r.status

MASTER = "/realms/master/.well-known/openid-configuration"
OWN = "/realms/%s/.well-known/openid-configuration" % M.REALM
# ---- MEDIUM 3, from the HOST's namespace (before joining Keycloak's)
gw = subprocess.run(["docker", "network", "inspect", "-f", "{{(index .IPAM.Config 0).Gateway}}", "idp_egress"], capture_output=True, text=True).stdout.strip()
for label, addr in (("host loopback through docker-proxy", "127.0.0.1"), ("the bridge gateway %s" % gw, gw)):
    st_m, st_o = get(addr, 443, MASTER), get(addr, 443, OWN)
    check("%s: master realm 404, own realm 200" % label, st_m == 404 and st_o == 200, "master %s, %s %s" % (st_m, M.REALM, st_o))
st6 = get("::1", 443, MASTER, socket.AF_INET6)
check("IPv6: nothing listens on [::]:443", isinstance(st6, str) and "no connection" in st6, "%s" % st6)
kc = M.KC()                              # now inside Keycloak's network namespace
check("inside the container's namespace (127.0.0.1:8443): master realm reachable", get("127.0.0.1", M.ADMIN_PORT, MASTER) == 200)

# ---- MEDIUM 4 / LOW, as a network client would (through docker-proxy: leave the namespace is not possible, so use
# the in-namespace loopback - the realm's own paths behave the same either way)
_gai = socket.getaddrinfo
socket.getaddrinfo = lambda h, p, *r, **k: _gai("127.0.0.1", M.ADMIN_PORT, *r, **k) if h == HOST else _gai(h, p, *r, **k)
sys.path.insert(0, os.path.join(a.skill, "scripts")); import e2e_check as E   # noqa: E402
BASE = "https://" + HOST
made = []
def mk(name, pw):
    kc.api("POST", "/users", {"username": name, "email": name + "@test.invalid", "firstName": "T", "lastName": "H", "enabled": True,
                              "credentials": [{"type": "password", "value": pw, "temporary": False}]}); made.append(name)
    return M.user(kc, name)
try:
    app = kc.api("GET", "/clients?clientId=%s" % a.client)[0]
    fl = E.Flow(argparse.Namespace(url=BASE, realm=M.REALM, client=a.client, redirect=app["redirectUris"][0], admin_url=None,
                                   client_secret=kc.api("GET", "/clients/%s/client-secret" % app["id"])["value"], cacert=None))
    pw = "Th1!" + uuid.uuid4().hex[:20]; lk = mk("t.hd.lock", pw)
    for _ in range(3):
        b = E.Browser(); url, _v = fl.auth_url(); k, u, p = b.go(url, None, fl.a.redirect)
        act, f = E.form(p, "kc-form-login"); f.update({"username": "t.hd.lock", "password": "wrong-" + uuid.uuid4().hex}); b.go(act, f, fl.a.redirect)
    bf = kc.api("GET", "/attack-detection/brute-force/users/%s" % lk["id"])
    en = kc.api("GET", "/users/%s" % lk["id"])["enabled"]
    check("3 wrong passwords: locked (brute-force) but the account stays enabled (temporary)", bf.get("disabled") is True and en is True,
          "bruteforce=%s enabled=%s" % ({k: bf.get(k) for k in ("disabled", "numFailures")}, en))
    b = E.Browser(); url, _v = fl.auth_url(); k, u, p = b.go(url, None, fl.a.redirect)
    act, f = E.form(p, "kc-form-login"); f.update({"username": "t.hd.lock", "password": pw}); k, u, p = b.go(act, f, fl.a.redirect)
    check("... the right password is refused while locked", k == "page" and E.page_id(p) == "login-login", E.error_text(p)[:80] if k == "page" else k)
    r = kc.api("GET", "")
    check("realm lockout: temporary, 15 min growing to 24 h, failures kept 24 h", r["permanentLockout"] is False and r["waitIncrementSeconds"] == 900
          and r["maxFailureWaitSeconds"] == 86400 and r["maxDeltaTimeSeconds"] == 86400 and r["bruteForceStrategy"] == "MULTIPLE" and r["failureFactor"] == 3,
          "%s" % {k: r[k] for k in ("permanentLockout", "failureFactor", "waitIncrementSeconds", "maxFailureWaitSeconds", "maxDeltaTimeSeconds")})
    # a signed-in person (password + TOTP enrolled at first sign-in) against the account API
    pw2 = "Th2!" + uuid.uuid4().hex[:20]; me = mk("t.hd.self", pw2)
    acc = E.Flow(argparse.Namespace(url=BASE, realm=M.REALM, client="account-console", redirect="%s/realms/%s/account/" % (BASE, M.REALM),
                                    admin_url=None, client_secret=None, cacert=None))
    b = E.Browser(); url, ver = acc.auth_url(); k, u, p = b.go(url, None, acc.a.redirect)
    act, f = E.form(p, "kc-form-login"); f.update({"username": "t.hd.self", "password": pw2}); k, u, p = b.go(act, f, acc.a.redirect)
    final, seen = acc.finish(b, k, u, p, {})
    tok = acc.token(urllib.parse.parse_qs(urllib.parse.urlparse(final).query)["code"][0], ver)["access_token"] if final else None
    def account(method, path, body=None):
        req = urllib.request.Request("%s/realms/%s/account%s" % (BASE, M.REALM, path), method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r: return r.status, r.read().decode()
        except urllib.error.HTTPError as e: return e.code, e.read().decode()
    st, body = account("GET", "/")
    mine = json.loads(body) if st == 200 else {}
    st2, _ = account("POST", "/", dict(mine, email="t.hd.hijack@test.invalid"))
    now = kc.api("GET", "/users/%s" % me["id"]).get("email")
    check("a user cannot change their own e-mail", bool(tok) and now == "t.hd.self@test.invalid", "account POST %s; e-mail now %s" % (st2, now))
    # manage-account-links is gone from manage-account and the default roles. Keycloak 26.8 still lets manage-account
    # itself create/remove a link, so the control that matters is at use: a link nobody authorised signs nobody in
    # (idp-require-admin-attribute-match; proved by factor_promotion_test.py "planted link").
    accid = kc.api("GET", "/clients?clientId=account")[0]["id"]
    comp = [r["name"] for r in kc.api("GET", "/clients/%s/roles/manage-account/composites" % accid) or []]
    dflt = [r["name"] for r in kc.api("GET", "/roles/default-roles-%s/composites" % M.REALM.lower()) or []]
    check("manage-account-links in neither manage-account nor the default roles", "manage-account-links" not in comp + dflt,
          "manage-account composites %s" % comp)
    pb = [e.get("providerId") for e in kc.api("GET", "/authentication/flows/%s/executions" % M.q(M.POST_BROKER))]
    check("every brokered sign-in (any link) must carry the admin-set identity: post-broker check present",
          "idp-require-admin-attribute-match" in pb, "%s" % pb)
    ra = {x["alias"]: x for x in kc.api("GET", "/authentication/required-actions")}
    check("idp_link required action disabled", ra.get("idp_link", {}).get("enabled") is False, "%s" % ra.get("idp_link", {}).get("enabled"))
    bf = kc.api("GET", "/authentication/flows/STIG%20Browser/executions")
    provs = [e.get("providerId") for e in bf]
    check("browser flow: card form that password lockout does not block, password form without an oracle",
          "stig-x509-client-username-form" in provs and "stig-username-password-form" in provs
          and "auth-x509-client-username-form" not in provs and "auth-username-password-form" not in provs, "%s" % [p_ for p_ in provs if p_])
    rf = r.get("resetCredentialsFlow")
    rprov = [e.get("providerId") for e in kc.api("GET", "/authentication/flows/%s/executions" % M.q(rf))]
    check("reset-credentials flow: no self-service reset for administrators (and reset stays off)", "stig-admin-reset-credentials-gate" in rprov
          and r.get("resetPasswordAllowed") is False, "%s: %s" % (rf, rprov))
    x = [e for e in bf if e.get("providerId") == "stig-x509-client-username-form"][0]
    cfg = kc.api("GET", "/authentication/config/%s" % x["authenticationConfig"])["config"]
    check("OCSP fails closed (and CRL checking stays on)", cfg.get("x509-cert-auth.ocsp-fail-open") == "false" and
          cfg.get("x509-cert-auth.ocsp-checking-enabled") == "true" and cfg.get("x509-cert-auth.crl-checking-enabled") == "true", "")
finally:
    for n in made:
        f = kc.api("GET", "/users?exact=true&username=%s" % M.q(n))
        if f: kc.api("DELETE", "/users/%s" % f[0]["id"])
print("\n%d/%d passed" % (sum(res), len(res))); sys.exit(0 if all(res) else 1)

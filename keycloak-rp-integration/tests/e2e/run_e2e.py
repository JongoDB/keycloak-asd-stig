#!/usr/bin/env python3
"""End-to-end test of the three example relying parties against a real Keycloak.

  python3 keycloak-rp-integration/tests/e2e/run_e2e.py [--apps node,python,go] [--auth client-jwt,client-secret]

Needs docker (or podman as `docker`), node + npm, python3 with the python-flask example's requirements and
`requests`, and go. Starts a throwaway Keycloak (dev mode, HTTPS with a generated certificate, the same pinned image
as the IdP CI) with one realm. The client is registered the way the operator side does it: a dev client request is
validated and emitted by scripts/validate-client-request.py, turned into a Keycloak client by the IdP skill's
kcstig.client_rep (PKCE S256 required, no implicit or password grant, back-channel logout on), then created through
the admin API. This is NOT the hardened realm: it proves the app side of the contract, not the IdP's STIG settings.

For each example and client authentication method it checks:
  login with PKCE + nonce; roles from resource_access; role-gated route (200 for alice, 403 for bob);
  session cookie HttpOnly + SameSite and non-persistent; previous_login claim surfaced;
  local idle timeout; RP-initiated logout ends the IdP session too; back-channel logout (admin signs the user out)
  ends the app session; a forged logout token is refused.
"""
import argparse
import html
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import importlib.util
from urllib.parse import urljoin, urlsplit

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(os.path.dirname(HERE))
REPO = os.path.dirname(SKILL)
EX = os.path.join(SKILL, "examples")
IMAGE = os.environ.get("KEYCLOAK_IMAGE",
                       "quay.io/keycloak/keycloak:26.8.2@sha256:723b1d6e254c0fc96d5cffec860c7e0744d6a3277822b865bb538cf891575e41")
KC_PORT = int(os.environ.get("KC_PORT", "18443"))
KC = "https://localhost:%d" % KC_PORT
REALM = "rp-e2e"
ISSUER = KC + "/realms/" + REALM
# How the Keycloak container reaches apps on the host (jwks_url, backchannel_logout_url).
HOST_FROM_KC = os.environ.get("HOST_FROM_KC", "host.docker.internal")
CONTAINER = "kc-rp-e2e-%d" % os.getpid()
IDLE_SECONDS = 12


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vcr = load("vcr", os.path.join(SKILL, "scripts", "validate-client-request.py"))
kcstig = load("kcstig", os.path.join(REPO, "keycloak-asd-stig", "scripts", "kcstig.py"))

FAILS = []


def check(cond, what):
    print(("  ok   " if cond else "  FAIL ") + what, flush=True)
    if not cond:
        FAILS.append(what)
    return cond


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_http(url, timeout=180, verify=True):
    end = time.time() + timeout
    while time.time() < end:
        try:
            requests.get(url, timeout=3, verify=verify)
            return True
        except requests.RequestException:
            time.sleep(1)
    return False


class Admin:
    def __init__(self, ca, password):
        self.ca, self.s = ca, requests.Session()
        self.s.verify = ca
        t = requests.post(KC + "/realms/master/protocol/openid-connect/token", verify=ca, data={
            "grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": password}).json()
        self.s.headers["Authorization"] = "Bearer " + t["access_token"]

    def call(self, method, path, body=None, ok=(200, 201, 204)):
        r = self.s.request(method, KC + "/admin/realms" + path, json=body)
        if r.status_code not in ok:
            raise RuntimeError("%s %s -> %s %s" % (method, path, r.status_code, r.text[:300]))
        return r.json() if r.text and r.headers.get("content-type", "").startswith("application/json") else r


def start_keycloak(work, password):
    cert, key = os.path.join(work, "tls.crt"), os.path.join(work, "tls.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost", "-keyout", key, "-out", cert],
                   check=True, capture_output=True)
    os.chmod(key, 0o644)   # read by the container's non-root user; throwaway lab key in a temp dir
    subprocess.run(["docker", "run", "-d", "--rm", "--name", CONTAINER, "-p", "127.0.0.1:%d:8443" % KC_PORT,
                    "--add-host", "host.docker.internal:host-gateway", "-v", "%s:/certs:ro" % work,
                    "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + password,
                    IMAGE, "start-dev", "--http-enabled=false", "--hostname=" + KC,
                    "--https-certificate-file=/certs/tls.crt", "--https-certificate-key-file=/certs/tls.key"],
                   check=True, capture_output=True)
    if not wait_http(KC + "/realms/master/.well-known/openid-configuration", verify=cert):
        subprocess.run(["docker", "logs", CONTAINER])
        sys.exit("keycloak did not start")
    return cert


def setup_realm(adm):
    adm.call("POST", "", {"realm": REALM, "enabled": True, "ssoSessionIdleTimeout": 900, "ssoSessionMaxLifespan": 28800,
                          "accessTokenLifespan": 300, "registrationAllowed": False})
    users = {}
    for name in ("alice", "bob"):
        adm.call("POST", "/%s/users" % REALM, {"username": name, "enabled": True, "emailVerified": True,
                                              "email": name + "@example.test", "firstName": name.title(),
                                              "lastName": "Tester", "requiredActions": [],
                                              "credentials": [{"type": "password", "value": "pw-" + name + "-e2e-test",
                                                               "temporary": False}]})
        users[name] = adm.call("GET", "/%s/users?username=%s&exact=true" % (REALM, name))[0]["id"]
    return users


def register_client(adm, users, port, auth, work):
    """Dev client request -> validator -> operator client file -> kcstig.client_rep -> Keycloak."""
    base = "http://localhost:%d" % port
    cid = "e2e-%s-%d" % (auth.split("-")[1], port)
    req = {"client_id": cid, "dev_request": True, "root_url": base,
           "redirect_uris": [base + "/oauth2/callback"], "post_logout_redirect_uris": [base + "/logged-out"],
           "backchannel_logout_url": base + "/oauth2/backchannel-logout", "auth": auth,
           "roles": ["viewer", "approver"], "contact": {"name": "E2E", "email": "e2e@example.test"}}
    if auth == "client-jwt":
        req["jwks_url"] = base + "/.well-known/jwks.json"
    path = os.path.join(work, cid + "-request.json")
    with open(path, "w") as f:
        json.dump(req, f)
    out = os.path.join(work, cid + "-client.json")
    rc = vcr.main(["--quiet", "--emit-client", out, path])
    check(rc == 0, "%s: dev client request validates" % cid)
    with open(out) as f:
        client = json.load(f)
    # Test harness only: the container reaches the app through the Docker host, not localhost.
    for k in ("jwks_url", "backchannel_logout_url"):
        if k in client:
            client[k] = client[k].replace("localhost", HOST_FROM_KC)
    rep = kcstig.client_rep(client, {"sessions": {"admin_idle_minutes": 10}})
    roles = rep.pop("_roles")
    rep.setdefault("protocolMappers", []).append({
        "name": "previous_login", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": {"claim.name": "previous_login", "claim.value": "2026-01-01T00:00:00Z", "jsonType.label": "String",
                   "id.token.claim": "true", "access.token.claim": "false", "userinfo.token.claim": "true"}})
    adm.call("POST", "/%s/clients" % REALM, rep)
    kid = adm.call("GET", "/%s/clients?clientId=%s" % (REALM, cid))[0]["id"]
    for role in roles:
        adm.call("POST", "/%s/clients/%s/roles" % (REALM, kid), {"name": role})
    for user, rs in (("alice", ["viewer", "approver"]), ("bob", ["viewer"])):
        reps = [adm.call("GET", "/%s/clients/%s/roles/%s" % (REALM, kid, r)) for r in rs]
        adm.call("POST", "/%s/users/%s/role-mappings/clients/%s" % (REALM, users[user], kid), reps)
    secret = adm.call("GET", "/%s/clients/%s/client-secret" % (REALM, kid))["value"] if auth == "client-secret" else None
    return cid, base, secret


def app_command(name):
    if name == "node":
        return ["node", os.path.join(EX, "node-express", "app.mjs")], os.path.join(EX, "node-express")
    if name == "python":
        return [sys.executable, os.path.join(EX, "python-flask", "app.py")], os.path.join(EX, "python-flask")
    if name == "go":
        return [os.environ.get("GO_RP_BIN", os.path.join(EX, "go", "keycloak-rp"))], os.path.join(EX, "go")
    raise ValueError(name)


def follow(s, url, max_hops=10):
    """Follow redirects by hand so every Set-Cookie and Location is visible. Returns (final response, hops)."""
    hops = []
    for _ in range(max_hops):
        r = s.get(url, allow_redirects=False, timeout=15)
        hops.append(r)
        if r.status_code not in (301, 302, 303, 307, 308):
            return r, hops
        url = urljoin(url, r.headers["Location"])
    raise RuntimeError("too many redirects")


def login(s, base, user):
    page, hops = follow(s, base + "/login")
    auth_req = next(h for h in hops if "/protocol/openid-connect/auth" in h.url)
    q = urlsplit(auth_req.url).query
    m = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page.text)
    if not m:
        return None, q, hops
    r = s.post(html.unescape(m.group(1)), data={"username": user, "password": "pw-%s-e2e-test" % user},
               allow_redirects=False, timeout=15)
    final, more = follow(s, urljoin(r.url, r.headers.get("Location", "/")))
    return final, q, hops + [r] + more


def run_app(name, auth, adm, users, ca, work):
    port = free_port()
    cid, base, secret = register_client(adm, users, port, auth, work)
    tag = "%s/%s" % (name, auth)
    print("== %s (client %s)" % (tag, cid), flush=True)
    envv = dict(os.environ, OIDC_ISSUER=ISSUER, OIDC_CLIENT_ID=cid, APP_BASE_URL=base, PORT=str(port),
                HOST="0.0.0.0", SESSION_IDLE_MINUTES=str(IDLE_SECONDS / 60),   # short, to test the idle limit
                NODE_EXTRA_CA_CERTS=ca, REQUESTS_CA_BUNDLE=ca, SSL_CERT_FILE=ca, OIDC_CA_FILE=ca)
    sf = os.path.join(work, cid + "-session-secret")
    with open(sf, "w") as f:
        f.write(secrets.token_urlsafe(32))
    envv["SESSION_SECRET_FILE"] = sf
    if auth == "client-jwt":
        kf = os.path.join(work, cid + ".key")
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", kf],
                       check=True, capture_output=True)
        envv.update(OIDC_PRIVATE_KEY_FILE=kf, OIDC_KEY_ID="e2e-" + secrets.token_hex(4))
    else:
        cf = os.path.join(work, cid + ".secret")
        with open(cf, "w") as f:
            f.write(secret + "\n")
        envv["OIDC_CLIENT_SECRET_FILE"] = cf
    cmd, cwd = app_command(name)
    log = open(os.path.join(work, cid + ".log"), "w")
    proc = subprocess.Popen(cmd, cwd=cwd, env=envv, stdout=log, stderr=subprocess.STDOUT)
    try:
        if not check(wait_http(base + "/logged-out", timeout=60), "%s: app starts" % tag):
            return
        if auth == "client-jwt":
            j = requests.get(base + "/.well-known/jwks.json").json()
            check(len(j["keys"]) == 1 and "d" not in j["keys"][0] and j["keys"][0]["kid"] == envv["OIDC_KEY_ID"],
                  "%s: JWKS serves one public key with the configured kid" % tag)

        s = requests.Session()
        s.verify = ca
        final, q, hops = login(s, base, "alice")
        check(final is not None and final.status_code == 200 and final.url == base + "/", "%s: alice logs in" % tag)
        check("code_challenge_method=S256" in q and "nonce=" in q and "state=" in q,
              "%s: auth request carries PKCE S256, nonce, state" % tag)
        cookies = [h.headers.get("Set-Cookie", "") for h in hops if h.url.startswith(base + "/oauth2/callback")]
        ck = cookies[0] if cookies else ""
        check("HttpOnly" in ck and "SameSite=Lax" in ck and "Expires" not in ck and "Max-Age" not in ck,
              "%s: session cookie HttpOnly, SameSite=Lax, non-persistent (%s)" % (tag, ck.split(";")[0][:12] + "..."))
        def logged_in(sess):          # 200 without a redirect; a redirect to /logged-out is "no"
            return sess.get(base + "/me", allow_redirects=False).status_code == 200

        me = s.get(base + "/me", allow_redirects=False)
        body = me.json() if me.status_code == 200 else {}
        check(sorted(body.get("roles", [])) == ["approver", "viewer"], "%s: roles from resource_access.%s.roles" % (tag, cid))
        check(body.get("previousLogin") == "2026-01-01T00:00:00Z", "%s: previous_login surfaced" % tag)
        check(s.get(base + "/approve", allow_redirects=False).status_code == 200, "%s: alice may approve" % tag)
        check(requests.get(base + "/me", allow_redirects=False).status_code != 200, "%s: no cookie, no access" % tag)

        sb = requests.Session()
        sb.verify = ca
        login(sb, base, "bob")
        check(logged_in(sb), "%s: bob logs in" % tag)
        check(sb.get(base + "/approve", allow_redirects=False).status_code == 403,
              "%s: bob is refused the approver route (403)" % tag)

        # forged back-channel logout token
        r = requests.post(base + "/oauth2/backchannel-logout", data={"logout_token": "eyJhbGciOiJub25lIn0.e30."})
        check(r.status_code == 400, "%s: forged logout token refused" % tag)
        check(logged_in(s), "%s: alice still logged in after the forged logout" % tag)

        # back-channel logout: an administrator signs alice out at the IdP (well inside the idle limit)
        adm.call("POST", "/%s/users/%s/logout" % (REALM, users["alice"]))
        time.sleep(2)
        check(not logged_in(s), "%s: back-channel logout ends the app session" % tag)
        check(logged_in(sb), "%s: bob's session is untouched by alice's logout" % tag)

        # RP-initiated logout ends the IdP session too
        s2 = requests.Session()
        s2.verify = ca
        login(s2, base, "alice")
        check(logged_in(s2), "%s: alice logs in again" % tag)
        out, ohops = follow(s2, base + "/logout")
        check(any("/protocol/openid-connect/logout" in h.url and "id_token_hint=" in h.url for h in ohops)
              and out.url == base + "/logged-out", "%s: logout goes through end_session with id_token_hint" % tag)
        check(not logged_in(s2), "%s: app session gone after logout" % tag)
        page, _ = follow(s2, base + "/login")
        check('id="kc-form-login"' in page.text, "%s: IdP asks for credentials again (SSO session ended)" % tag)

        # local idle limit (IDLE_SECONDS in this run)
        s3 = requests.Session()
        s3.verify = ca
        login(s3, base, "bob")
        check(logged_in(s3), "%s: bob logs in again" % tag)
        time.sleep(IDLE_SECONDS + 2)
        check(not logged_in(s3), "%s: idle session ends after %d s" % (tag, IDLE_SECONDS))
    finally:
        proc.terminate()
        proc.wait(10)
        log.close()
        if FAILS or os.environ.get("E2E_SHOW_LOG"):
            with open(os.path.join(work, cid + ".log")) as f:
                print("  --- app log (%s) ---\n  " % tag + f.read()[-3000:].replace("\n", "\n  "))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apps", default="node,python,go")
    ap.add_argument("--auth", default="client-jwt,client-secret")
    ap.add_argument("--keep", action="store_true", help="leave Keycloak running")
    a = ap.parse_args()
    apps = a.apps.split(",")
    if "go" in apps and not os.environ.get("GO_RP_BIN"):
        subprocess.run(["go", "build", "-o", "keycloak-rp", "."], cwd=os.path.join(EX, "go"), check=True)
    work = tempfile.mkdtemp(prefix="rp-e2e-")
    password = secrets.token_urlsafe(18)
    try:
        ca = start_keycloak(work, password)
        adm = Admin(ca, password)
        users = setup_realm(adm)
        for name in apps:
            for auth in a.auth.split(","):
                adm = Admin(ca, password)     # fresh admin token per run
                run_app(name, auth, adm, users, ca, work)
    finally:
        if not a.keep:
            subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
        shutil.rmtree(work, ignore_errors=True)
    print("\n%d failure(s)" % len(FAILS) + ("".join("\n - " + f for f in FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())

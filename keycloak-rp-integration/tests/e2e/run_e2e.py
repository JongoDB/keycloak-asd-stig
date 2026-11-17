#!/usr/bin/env python3
"""End-to-end test of the three example relying parties against a real Keycloak.

  python3 keycloak-rp-integration/tests/e2e/run_e2e.py [--apps node,python,go] [--auth client-jwt,client-secret]

This is the reference test of this repository's examples and of the operator's `kcstig.py add-client`. It runs
inside a keycloak-asd-stig checkout (it needs keycloak-asd-stig/scripts/kcstig.py beside this skill); it is not
something an app team runs standalone - copy its checks into the app's own tests instead.

Needs docker (or podman as `docker`), node + npm, python3 with the python-flask example's requirements and
`requests`, and go. Starts a throwaway Keycloak (dev mode, HTTPS with a generated certificate, the same pinned image
as the IdP CI) with one realm. Every client is registered the way an operator does it: `kcstig.py add-client` with a
dev client request (validated with scripts/validate-client-request.py's rules, refused for reserved ids or clients
add-client did not create, applied through the admin API, written to clients.d). This is NOT the hardened realm: it
proves the app side of the contract and add-client's guards, not the IdP's STIG settings.

add-client: an existing client needs --update; a hand-made one also --adopt (with a warning); another owner's
client is refused even with --update unless --transfer; updates print a before/after diff; --owner records the
operator's owner id; --prune-roles; a clients.d file with no live client is not replaced; reserved ids and a
clients.d file overriding one are refused; warnings refuse by default (--no-strict); the client secret goes to a
0600 file and is never printed.

For each example and client authentication method:
  login with PKCE + nonce; roles from resource_access; role-gated route (200 for alice, 403 for bob);
  session cookie HttpOnly + SameSite, non-persistent, carrying only a session id; previous_login surfaced;
  logout is POST-only and refused without a same-origin Origin/Referer; RP-initiated logout ends the IdP session too;
  back-channel logout (admin signs the user out) ends the app session; a forged logout token is refused;
  local idle timeout.
"""
import argparse
import base64
import contextlib
import io
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
import zlib
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
LOGIN_RATE = 16     # per-IP login starts per 10 minutes in this run; each app run uses 11 before the limit test
MAX_PENDING = 3     # logins in progress each app holds in this run, to see the oldest evicted


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


KCSTIG = os.path.join(REPO, "keycloak-asd-stig", "scripts", "kcstig.py")
if not os.path.isfile(KCSTIG):
    sys.exit("run_e2e.py is the repository's reference test: it needs %s (a full keycloak-asd-stig checkout, with "
             "keycloak-rp-integration/ beside keycloak-asd-stig/). Not found - nothing run." % KCSTIG)
vcr = load("vcr", os.path.join(SKILL, "scripts", "validate-client-request.py"))
kcstig = load("kcstig", KCSTIG)

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
    # The container runs as uid 1000: give it its own traversable directory (mkdtemp's is 0700, owned by the caller).
    certs = os.path.join(work, "certs")
    os.mkdir(certs)
    os.chmod(certs, 0o755)
    cert, key = os.path.join(certs, "tls.crt"), os.path.join(certs, "tls.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost", "-keyout", key, "-out", cert],
                   check=True, capture_output=True)
    os.chmod(key, 0o644)   # read by the container's non-root user; throwaway lab key in a temp dir
    os.chmod(cert, 0o644)
    subprocess.run(["docker", "run", "-d", "--name", CONTAINER, "-p", "127.0.0.1:%d:8443" % KC_PORT,
                    "--add-host", "host.docker.internal:host-gateway", "-v", "%s:/certs:ro" % certs,
                    "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + password,
                    IMAGE, "start-dev", "--http-enabled=false", "--hostname=" + KC,
                    "--https-certificate-file=/certs/tls.crt", "--https-certificate-key-file=/certs/tls.key"],
                   check=True, capture_output=True)
    if not wait_http(KC + "/realms/master/.well-known/openid-configuration", verify=cert):
        subprocess.run(["docker", "logs", "--tail", "60", CONTAINER])
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


class Operator:
    """What the IdP operator holds: a profile, a clients.d directory and admin credentials for kcstig.py."""
    def __init__(self, work, ca, password):
        self.dir = os.path.join(work, "operator")
        self.clients = os.path.join(self.dir, "clients.d")
        os.makedirs(self.clients)
        self.profile = os.path.join(self.dir, "profile.json")
        with open(self.profile, "w") as f:
            json.dump({"keycloak": {"url": KC}, "realm": {"name": REALM}}, f)
        pw = os.path.join(self.dir, "admin-password")
        fd = os.open(pw, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(password)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("KC_")}
        self.env.update(KC_ADMIN_USER="admin", KC_ADMIN_PASSWORD_FILE=pw, KC_CACERT=ca)

    def add_client(self, req, *extra):
        path = os.path.join(self.dir, "request-%s.json" % secrets.token_hex(4))
        with open(path, "w") as f:
            json.dump(req, f)
        return subprocess.run([sys.executable, KCSTIG, "add-client", path, "--profile", self.profile,
                               "--clients-dir", self.clients] + list(extra),
                              capture_output=True, text=True, env=self.env, timeout=120)


def dev_request(cid, base, auth):
    req = {"client_id": cid, "dev_request": True, "root_url": base,
           "redirect_uris": [base + "/oauth2/callback"], "post_logout_redirect_uris": [base + "/logged-out"],
           "backchannel_logout_url": base + "/oauth2/backchannel-logout", "auth": auth,
           "roles": ["viewer", "approver"], "contact": {"name": "E2E", "email": "e2e@example.test"}}
    if auth == "client-jwt":
        req["jwks_url"] = base + "/.well-known/jwks.json"
    return req


def get_client(adm, cid):
    found = [c for c in adm.call("GET", "/%s/clients?clientId=%s" % (REALM, cid)) if c["clientId"] == cid]
    return found[0] if found else None


def register_client(adm, op, users, port, auth, work):
    """The operator registers the app with kcstig.py add-client, exactly as documented."""
    base = "http://localhost:%d" % port
    cid = "e2e-%s-%d" % (auth.split("-")[1], port)
    req = dev_request(cid, base, auth)
    secret_file = os.path.join(op.dir, cid + ".secret")
    extra = ["--allow-dev", "--owner", "e2e-apps"] + (["--secret-out", secret_file] if auth == "client-secret" else [])
    r = op.add_client(req, *extra)
    if not check(r.returncode == 0, "%s: kcstig.py add-client registers the dev request" % cid):
        print(r.stdout + r.stderr)
        raise SystemExit(1)
    with open(os.path.join(op.clients, cid + ".json")) as f:
        filed = json.load(f)
    owner_keys = {"owner": "e2e-apps", "owner_contact": "e2e@example.test"}
    check(filed == dict(vcr.to_client(req), **owner_keys),
          "%s: add-client wrote clients.d/%s.json = the request's client + its owner" % (cid, cid))
    c = get_client(adm, cid)
    check(c["attributes"].get("stig.created-by") == "add-client", "%s: client carries the add-client ownership marker" % cid)
    check(c["attributes"].get("pkce.code.challenge.method") == "S256" and not c["implicitFlowEnabled"]
          and not c["directAccessGrantsEnabled"], "%s: PKCE S256 required, implicit and password grants off" % cid)
    secret = None
    if auth == "client-secret":
        mode = os.stat(secret_file).st_mode & 0o777
        with open(secret_file) as f:
            secret = f.read().strip()
        live = adm.call("GET", "/%s/clients/%s/client-secret" % (REALM, c["id"]))["value"]
        check(mode == 0o600 and secret == live, "%s: --secret-out wrote the live secret, mode 0600" % cid)
        check(secret not in r.stdout + r.stderr, "%s: add-client never prints the secret" % cid)
    # Test harness only: the container reaches the app through the Docker host, not localhost.
    for k in ("jwks.url", "backchannel.logout.url"):
        if k in c["attributes"]:
            c["attributes"][k] = c["attributes"][k].replace("localhost", HOST_FROM_KC)
    adm.call("PUT", "/%s/clients/%s" % (REALM, c["id"]), c)
    # The hardened realm supplies previous_login (stig-claims scope + extension); simulate it here.
    adm.call("POST", "/%s/clients/%s/protocol-mappers/models" % (REALM, c["id"]), {
        "name": "previous_login", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": {"claim.name": "previous_login", "claim.value": "2026-01-01T00:00:00Z", "jsonType.label": "String",
                   "id.token.claim": "true", "access.token.claim": "false", "userinfo.token.claim": "true"}})
    for user, rs in (("alice", ["viewer", "approver"]), ("bob", ["viewer"])):
        reps = [adm.call("GET", "/%s/clients/%s/roles/%s" % (REALM, c["id"], role)) for role in rs]
        adm.call("POST", "/%s/users/%s/role-mappings/clients/%s" % (REALM, users[user], c["id"]), reps)
    return cid, base, secret


def operator_checks(adm, op):
    """add-client's guards against the live Keycloak."""
    print("== kcstig.py add-client guards", flush=True)
    base = "http://localhost:3999"
    alice_team = {"name": "Team A", "email": "team-a@example.test"}
    other_team = {"name": "Team B", "email": "team-b@example.test"}

    def redirects(cid):
        return get_client(adm, cid)["redirectUris"]

    # 1. a client the operator made by hand: needs --update, and --adopt
    adm.call("POST", "/%s/clients" % REALM, {"clientId": "handmade-app", "protocol": "openid-connect",
                                             "redirectUris": ["https://handmade.example.test/cb"]})
    req = dict(dev_request("handmade-app", base, "client-jwt"), contact=alice_team)
    r = op.add_client(req, "--allow-dev")
    check(r.returncode != 0 and "--update handmade-app" in r.stderr + r.stdout,
          "an existing client needs --update")
    r = op.add_client(req, "--allow-dev", "--update", "handmade-app")
    check(r.returncode != 0 and "not created by add-client" in r.stderr + r.stdout,
          "--update alone does not modify a client add-client did not create")
    check(redirects("handmade-app") == ["https://handmade.example.test/cb"]
          and not os.path.exists(os.path.join(op.clients, "handmade-app.json")), "... and nothing changed")
    r = op.add_client(req, "--allow-dev", "--update", "handmade-app", "--adopt", "handmade-app")
    check(r.returncode == 0 and "WARNING add-client: adopting" in r.stderr, "--update --adopt takes it over, with a warning")
    c = get_client(adm, "handmade-app")
    check(c["attributes"].get("stig.created-by") == "add-client" and c["attributes"].get("stig.owner") == alice_team["email"]
          and c["attributes"].get("stig.owner-contact") == alice_team["email"] and c["redirectUris"] == req["redirect_uris"],
          "... marks it, records owner and contact, and applies the request")
    with open(os.path.join(op.clients, "handmade-app.json")) as f:
        filed = json.load(f)
    check(filed.get("owner") == alice_team["email"] and filed.get("owner_contact") == alice_team["email"],
          "the clients.d file records the owner too")

    # 2. a second request for the same id without --update: refused, nothing changes
    before = redirects("handmade-app")
    req2 = dict(req, redirect_uris=req["redirect_uris"] + [base + "/oauth2/callback2"])
    r = op.add_client(req2, "--allow-dev")
    check(r.returncode != 0 and redirects("handmade-app") == before, "a second request without --update is refused, nothing changes")

    # 3. the same owner with --update: applied, with a before/after diff
    r = op.add_client(req2, "--allow-dev", "--update", "handmade-app")
    check(r.returncode == 0 and "changes to apply:" in r.stdout and "redirect_uris:" in r.stdout
          and base + "/oauth2/callback2" in r.stdout, "the owner's --update prints the before/after diff")
    check(sorted(redirects("handmade-app")) == sorted(req2["redirect_uris"]), "... and applies it")

    # 4. a request from a different owner: refused even with --update; --transfer moves it
    req3 = dict(req2, contact=other_team, redirect_uris=[base + "/hijack"])
    before = redirects("handmade-app")
    r = op.add_client(req3, "--allow-dev", "--update", "handmade-app")
    check(r.returncode != 0 and "belongs to" in r.stderr + r.stdout and redirects("handmade-app") == before,
          "another owner's request is refused even with --update, nothing changes")
    r = op.add_client(req3, "--allow-dev", "--update", "handmade-app", "--transfer")
    c = get_client(adm, "handmade-app")
    check(r.returncode == 0 and "WARNING add-client: transferring" in r.stderr
          and c["attributes"].get("stig.owner") == other_team["email"], "--transfer moves the client to the new owner")

    # 5. an operator-assigned --owner decides, not the contact email
    reqo = dict(dev_request("owned-app", base, "client-jwt"), contact=alice_team)
    r = op.add_client(reqo, "--allow-dev", "--owner", "team-alpha")
    check(r.returncode == 0 and get_client(adm, "owned-app")["attributes"].get("stig.owner") == "team-alpha",
          "--owner records the operator's owner id")
    r = op.add_client(reqo, "--allow-dev", "--update", "owned-app")
    check(r.returncode != 0 and "belongs to" in r.stderr + r.stdout, "the same contact without the owner id is refused")
    r = op.add_client(dict(reqo, contact=other_team), "--allow-dev", "--update", "owned-app", "--owner", "team-alpha")
    check(r.returncode == 0, "the owner id with --update is accepted")

    # 6. --prune-roles
    r = op.add_client(dict(reqo, roles=["viewer"]), "--allow-dev", "--update", "owned-app", "--owner", "team-alpha")
    names = lambda: sorted(x["name"] for x in adm.call("GET", "/%s/clients/%s/roles" % (REALM, get_client(adm, "owned-app")["id"])))
    check(r.returncode == 0 and "no longer requested, kept" in r.stdout and names() == ["approver", "viewer"],
          "roles dropped from a request are kept without --prune-roles")
    r = op.add_client(dict(reqo, roles=["viewer"]), "--allow-dev", "--update", "owned-app", "--owner", "team-alpha",
                      "--prune-roles")
    check(r.returncode == 0 and names() == ["viewer"], "--prune-roles deletes them")

    # 7. a clients.d file for a client that is not live is someone's configuration
    r = op.add_client(dict(dev_request("brand-new-app", base, "client-jwt")), "--allow-dev")
    check(r.returncode != 0 and "needs --owner" in r.stderr + r.stdout and get_client(adm, "brand-new-app") is None,
          "a new client needs --owner")
    ghost = os.path.join(op.clients, "ghost-app.json")
    with open(ghost, "w") as f:
        json.dump({"client_id": "ghost-app", "type": "oidc-confidential", "redirect_uris": ["https://ghost.example.test/cb"],
                   "owner": "team-ghost", "owner_contact": "ghost@example.test"}, f)
    greq = dict(dev_request("ghost-app", base, "client-jwt"), contact=other_team)
    r = op.add_client(greq, "--allow-dev", "--owner", "team-beta")
    with open(ghost) as f:
        unchanged = json.load(f)["redirect_uris"] == ["https://ghost.example.test/cb"]
    check(r.returncode != 0 and "already exists although" in r.stderr + r.stdout and unchanged
          and get_client(adm, "ghost-app") is None, "a clients.d file without a live client is not silently replaced")
    r = op.add_client(greq, "--allow-dev", "--owner", "team-beta", "--adopt", "ghost-app")
    check(r.returncode != 0 and "without --transfer" in r.stderr + r.stdout and get_client(adm, "ghost-app") is None,
          "--adopt of a clients.d file recording another owner needs --transfer")
    r = op.add_client(greq, "--allow-dev", "--owner", "team-beta", "--adopt", "ghost-app", "--transfer")
    check(r.returncode == 0 and "changes to apply:" in r.stdout and "https://ghost.example.test/cb" in r.stdout
          and get_client(adm, "ghost-app")["attributes"].get("stig.owner") == "team-beta",
          "... with --transfer it is adopted, showing the diff against the file")

    # 8. reserved ids, the strict default, dev requests
    r = op.add_client(dict(req, client_id="admin-cli"), "--allow-dev")
    check(r.returncode != 0 and "reserved" in r.stderr + r.stdout, "a reserved client_id is refused")
    evil = os.path.join(op.clients, "zz-evil.json")
    with open(evil, "w") as f:
        json.dump({"client_id": "realm-management", "redirect_uris": ["https://x.example.test/cb"]}, f)
    r = op.add_client(dict(dev_request("new-app", base, "client-jwt")), "--allow-dev")
    check(r.returncode != 0 and "reserved" in r.stderr + r.stdout, "a clients.d file overriding a reserved id stops add-client")
    r = subprocess.run([sys.executable, KCSTIG, "apply", "--profile", op.profile, "--clients-dir", op.clients],
                       capture_output=True, text=True, env=op.env, timeout=120)
    check(r.returncode != 0 and "reserved" in r.stderr + r.stdout, "... and stops kcstig.py apply")
    os.unlink(evil)
    r = op.add_client(dict(dev_request("dev-only-app", base, "client-jwt")))
    check(r.returncode != 0 and "--allow-dev" in r.stderr + r.stdout, "a dev_request needs --allow-dev")
    wild = dict(dev_request("wild-app", base, "client-jwt"), dev_request=False, root_url="https://wild.127.0.0.1.nip.io",
                redirect_uris=["https://wild.127.0.0.1.nip.io/cb"], post_logout_redirect_uris=["https://wild.127.0.0.1.nip.io/out"],
                backchannel_logout_url="https://wild.127.0.0.1.nip.io/bcl", jwks_url="https://wild.127.0.0.1.nip.io/jwks")
    r = op.add_client(wild, "--owner", "team-wild")
    check(r.returncode != 0 and "nip.io" in r.stderr and get_client(adm, "wild-app") is None,
          "a wildcard-DNS host is refused by default (strict)")
    r = op.add_client(wild, "--no-strict", "--owner", "team-wild")
    check(r.returncode == 0 and get_client(adm, "wild-app") is not None, "... and accepted only with --no-strict")
    apply_bypass_checks(adm, op)


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


def apply_bypass_checks(adm, op):
    """The apply path (load_profile + upsert_client) cannot override an owned client either."""
    print("== apply path: ownership", flush=True)
    d = os.path.join(op.dir, "apply-path")
    cdir = os.path.join(d, "clients.d")
    os.makedirs(cdir)
    prof = os.path.join(d, "profile.json")
    owned = {"client_id": "owned-app", "type": "oidc-confidential", "redirect_uris": ["https://evil.example.test/cb"]}
    # a duplicate client_id across the profile and clients.d
    with open(prof, "w") as f:
        json.dump({"keycloak": {"url": KC}, "realm": {"name": REALM}, "clients": [owned]}, f)
    with open(os.path.join(cdir, "owned-app.json"), "w") as f:
        json.dump(dict(owned, owner="team-alpha"), f)
    r = subprocess.run([sys.executable, KCSTIG, "render", "--profile", prof, "--clients-dir", cdir, "--out", d],
                       capture_output=True, text=True, timeout=60)
    check(r.returncode != 0 and "defined twice" in r.stderr + r.stdout, "load_profile refuses a client_id defined twice")
    os.unlink(os.path.join(cdir, "owned-app.json"))
    # owner keys outside clients.d/<client_id>.json are ignored (with a warning)
    with open(prof, "w") as f:
        json.dump({"keycloak": {"url": KC}, "realm": {"name": REALM}}, f)
    with open(os.path.join(cdir, "zz-other.json"), "w") as f:
        json.dump(dict(owned, owner="team-alpha", owner_contact="team-a@example.test"), f)
    old = dict(os.environ)
    os.environ.update({k: v for k, v in op.env.items() if k.startswith("KC_")})
    try:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            p = kcstig.load_profile(prof, cdir)
        (c,) = [c for c in p["clients"] if c["client_id"] == "owned-app"]
        check("owner" not in c and "owner/owner_contact ignored" in err.getvalue(),
              "owner in a file not named <client_id>.json is ignored, with a warning")
        kc = kcstig.KC(KC, "master", op.env["KC_CACERT"])
        before = get_client(adm, "owned-app")
        for label, rep in (("carrying no owner", kcstig.client_rep(c, p)),
                           ("naming another owner", kcstig.client_rep(dict(c, owner="team-mallory"), p))):
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    kcstig.upsert_client(kc, REALM, rep)
                refused = False
            except SystemExit as e:
                refused = "belongs to" in str(e.code)
            after = get_client(adm, "owned-app")
            check(refused and after["redirectUris"] == before["redirectUris"]
                  and after["attributes"].get("stig.owner") == "team-alpha",
                  "upsert_client (the apply path) refuses a definition %s for an owned client" % label)
        rep = kcstig.client_rep(dict(c, owner="team-alpha", redirect_uris=before["redirectUris"]), p)
        with contextlib.redirect_stdout(io.StringIO()):
            kcstig.upsert_client(kc, REALM, rep)
        check(get_client(adm, "owned-app")["attributes"].get("stig.owner") == "team-alpha",
              "... and accepts one from the same owner")
    finally:
        os.environ.clear()
        os.environ.update(old)


def cookie_payload(value):
    """Flask's signed cookie: base64 JSON (zlib-compressed when it starts with '.'), then timestamp and signature."""
    comp = value.startswith(".")
    seg = value.lstrip(".").split(".")[0]
    data = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    return json.loads(zlib.decompress(data) if comp else data)


def post_logout(sess, base, origin):
    headers = {"Origin": origin} if origin else {}
    r = sess.post(base + "/logout", headers=headers, allow_redirects=False, timeout=15)
    if r.status_code not in (301, 302, 303, 307, 308):
        return r, [r]
    final, hops = follow(sess, urljoin(base + "/logout", r.headers["Location"]))
    return final, [r] + hops


def run_app(name, auth, adm, op, users, ca, work):
    port = free_port()
    cid, base, secret = register_client(adm, op, users, port, auth, work)
    tag = "%s/%s" % (name, auth)
    print("== %s (client %s)" % (tag, cid), flush=True)
    envv = dict(os.environ, OIDC_ISSUER=ISSUER, OIDC_CLIENT_ID=cid, APP_BASE_URL=base, PORT=str(port),
                HOST="0.0.0.0", SESSION_IDLE_MINUTES=str(IDLE_SECONDS / 60),   # short, to test the idle limit
                LOGIN_RATE_PER_IP=str(LOGIN_RATE), MAX_PENDING_LOGINS=str(MAX_PENDING),
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
        value = ck.split(";")[0].partition("=")[2]
        check(0 < len(value) < 200, "%s: cookie is small - no tokens in it (%d chars)" % (tag, len(value)))
        if name == "python":
            check(set(cookie_payload(value)) == {"lsid"}, "%s: Flask cookie carries only the session id" % tag)
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
        # logout CSRF: GET, no Origin/Referer, or a foreign Origin must not log anyone out
        g = s2.get(base + "/logout", allow_redirects=False)
        check(g.status_code in (404, 405) and logged_in(s2), "%s: GET /logout does nothing (%d)" % (tag, g.status_code))
        r0, _ = post_logout(s2, base, None)
        check(r0.status_code == 403 and logged_in(s2), "%s: POST /logout without Origin/Referer refused" % tag)
        r1, _ = post_logout(s2, base, "https://evil.example.test")
        check(r1.status_code == 403 and logged_in(s2), "%s: POST /logout from another origin refused" % tag)
        out, ohops = post_logout(s2, base, base)
        check(any("/protocol/openid-connect/logout" in h.url and "id_token_hint=" in h.url for h in ohops)
              and out.url == base + "/logged-out", "%s: same-origin POST /logout goes through end_session with id_token_hint" % tag)
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

        # a full pending-login store drops its oldest entry; it never refuses a new login
        s_old = requests.Session()
        s_old.verify = ca
        page, _ = follow(s_old, base + "/login")
        form = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page.text)
        fresh = [requests.get(base + "/login", allow_redirects=False).status_code for _ in range(MAX_PENDING + 1)]
        check(fresh == [302] * (MAX_PENDING + 1), "%s: a full pending-login store never refuses a new login (%s)" % (tag, fresh))
        if form:
            r = s_old.post(html.unescape(form.group(1)), data={"username": "alice", "password": "pw-alice-e2e-test"},
                           allow_redirects=False, timeout=15)
            follow(s_old, urljoin(r.url, r.headers.get("Location", "/")))
        check(form is not None and not logged_in(s_old), "%s: ... the oldest unfinished login was evicted" % tag)
        s_new = requests.Session()
        s_new.verify = ca
        login(s_new, base, "bob")
        check(logged_in(s_new), "%s: ... and a new login still completes" % tag)

        # per-IP limit on login starts (IPv4 here; IPv6 is counted per /64)
        codes = [requests.get(base + "/login", allow_redirects=False).status_code for _ in range(LOGIN_RATE + 2)]
        r429 = requests.get(base + "/login", allow_redirects=False)
        check(429 in codes and 503 not in codes and r429.status_code == 429 and r429.headers.get("Retry-After"),
              "%s: /login is limited per client IP (429 + Retry-After)" % tag)
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
        op = Operator(work, ca, password)
        operator_checks(adm, op)
        for name in apps:
            for auth in a.auth.split(","):
                adm = Admin(ca, password)     # fresh admin token per run
                run_app(name, auth, adm, op, users, ca, work)
    finally:
        if not a.keep:
            subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
        shutil.rmtree(work, ignore_errors=True)
    print("\n%d failure(s)" % len(FAILS) + ("".join("\n - " + f for f in FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())

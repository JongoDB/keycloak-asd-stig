#!/usr/bin/env python3
"""Unit test of idp-admin.py add-client / check-clients with a fake Keycloak - no live call, no root, runs anywhere.

What it proves: the client rules refuse what they must (wildcards, http, localhost, IP literals in every spelling,
unknown fields, auth without its material, roles); the names Keycloak fetches (jwks_url, back-channel) are refused
unless they resolve to public addresses only; the representation applied is the one the image's kcstig renders at a restart; the apply is
idempotent (a re-run makes no write); a failed apply never writes the host file; extra live roles are kept and
reported, as a restart keeps them; check-clients finds every kind of drift; a dry run writes nothing; the secret
reaches only its 0600 file.

  python3 add_client_unit_test.py --kcstig <keycloak-asd-stig checkout>/keycloak-asd-stig [--admin ../host/idp-admin.py] [--clients DIR]

On the VM the image's own kcstig can be used: sudo docker cp idp-keycloak-1:/opt/kcstig /tmp/kcstig, then
--kcstig /tmp/kcstig --clients /srv/idp/clients.
"""
import argparse, contextlib, copy, importlib.machinery, importlib.util, io, json, os, shutil, socket, stat, sys, tempfile, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser()
ap.add_argument("--admin", default=os.path.join(HERE, "..", "host", "idp-admin.py"))
ap.add_argument("--kcstig", required=True, help="directory holding scripts/kcstig.py and references/")
ap.add_argument("--clients", default=os.path.join(HERE, "fixtures", "clients"), help="client files that must pass the rules (on the VM: /srv/idp/clients)")
a = ap.parse_args()

os.environ.setdefault("IDP_ADMIN_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures", "idp-admin.test.json"))   # the lab/unit config; on a host the real one is used
ld = importlib.machinery.SourceFileLoader("idp_admin", a.admin)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
WORK = tempfile.mkdtemp(prefix="add-client-test-")
PROFILE = os.path.join(WORK, "profile.json")
json.dump({"realm": {"name": "example"}, "auth_mode": "cac_or_mfa"}, open(PROFILE, "w"))
KS, P, _, _ = M.load_kcstig(a.kcstig, PROFILE)
M.RESOLVE_BACKOFF = (0, 0)          # the retries are exercised, without the waits
REPO_CLIENTS = a.clients
REPO_CLIENTS_LIST = sorted(f for f in os.listdir(REPO_CLIENTS) if f.endswith(".json"))

res = []
def check(n, ok, d=""):
    res.append(bool(ok)); print("%s  %-86s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

def fake(table):
    """a resolver: {name: [addresses]}; anything else does not resolve"""
    def r(h, port, proto=0):
        if h not in table: raise socket.gaierror("no such name")
        return [(0, 0, 0, "", (ad, port)) for ad in table[h]]
    return r

GOOD = {"client_id": "zz-unit", "name": "Unit", "type": "oidc-confidential", "auth": "client-jwt",
        "jwks_url": "https://zz.example.mil/jwks", "root_url": "https://zz.example.mil",
        "redirect_uris": ["https://zz.example.mil/cb"], "post_logout_redirect_uris": ["https://zz.example.mil/out"],
        "backchannel_logout_url": "https://zz.example.mil/bcl", "web_origins": ["https://zz.example.mil"],
        "roles": ["admin", "USER_ROLE"], "owner": "team-a", "owner_contact": "lead@team-a.example.mil"}

class FakeKC:
    """The admin-API calls add-client and check-clients make, over an in-memory realm."""
    def __init__(self):
        self.clients, self.roles, self.dscopes, self.oscopes, self.writes = {}, {}, {}, {}, []
        self.scopes = [{"id": "s-claims", "name": "stig-claims"}, {"id": "s-off", "name": "offline_access"}]
        self.freeze = False          # True: writes are accepted but change nothing (an apply that silently fails)
    def _new(self, rep):
        cu = str(uuid.uuid4()); c = copy.deepcopy(rep); c["id"] = cu
        c.setdefault("attributes", {})["client.secret.creation.time"] = "1"; c["secret"] = "S3CRET-" + cu[:8]
        self.clients[cu] = c; self.roles[cu] = []; self.dscopes[cu] = ["profile"]; self.oscopes[cu] = ["offline_access"]
        return cu
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        if method != "GET":
            self.writes.append((method, path))
        parts = path.split("?")[0].strip("/").split("/")
        if path.startswith("/clients?clientId="):
            cid = path.split("=", 1)[1]
            return [copy.deepcopy(c) for c in self.clients.values() if c["clientId"] == cid]
        if path == "/clients":
            if method == "GET": return [copy.deepcopy(c) for c in self.clients.values()]
            if not self.freeze: self._new(obj)
            return None
        if path == "/client-scopes": return copy.deepcopy(self.scopes)
        cu = parts[1]
        if len(parts) == 2:
            if method == "PUT" and not self.freeze: self.clients[cu] = copy.deepcopy(obj)
            if method == "DELETE": self.clients.pop(cu, None); return None
            return copy.deepcopy(self.clients[cu]) if method == "GET" else None
        if parts[2] == "client-secret": return {"type": "secret", "value": self.clients[cu]["secret"]}
        if parts[2] == "roles":
            if len(parts) == 4:
                return {"name": parts[3]} if parts[3] in self.roles[cu] else (None if ok404 else sys.exit("404"))
            if method == "POST" and not self.freeze: self.roles[cu].append(obj["name"])
            return [{"name": r} for r in self.roles[cu]]
        if parts[2] in ("default-client-scopes", "optional-client-scopes"):
            lst = (self.dscopes if parts[2].startswith("default") else self.oscopes)[cu]
            name = {s["id"]: s["name"] for s in self.scopes}.get(parts[3]) if len(parts) == 4 else None
            if method == "PUT" and not self.freeze and name not in lst: lst.append(name)
            if method == "DELETE" and not self.freeze and name in lst: lst.remove(name)
            ids = {s["name"]: s["id"] for s in self.scopes}
            return [{"id": ids.get(n, n), "name": n} for n in lst] if method == "GET" else None
        raise AssertionError("unexpected call %s %s" % (method, path))

def args(**kw):
    d = dict(file="zz-unit.json", dry_run=False, adopt=None, owner="team-a", owner_contact="lead@team-a.example.mil",
             update=None, transfer=False, lenient=False, secret_to=None, secret_to_keyvault=None, secret_stdout=False,
             repo=None, inheritance_statement=None, host=None, remote_path=M.REMOTE_ADMIN)
    d.update(kw); return argparse.Namespace(**d)

def run(fn, *x, **kw):
    """(result, output, exit message or None)"""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            return fn(*x, **kw), buf.getvalue(), None
    except SystemExit as ex:
        return None, buf.getvalue(), str(ex.code)

def raw(c):
    return (json.dumps(c, indent=2) + "\n").encode()

def fresh_dir():
    d = tempfile.mkdtemp(dir=WORK); M.CLIENTS_DIR = d; return d

try:
    # ------------------------------------------------------------------ validation refusals
    def refused(name, mutate, needle):
        c = copy.deepcopy(GOOD); mutate(c)
        errs = M.validate_client(c)
        check("refused: " + name, any(needle in e for e in errs), (errs or ["(accepted)"])[0][:70])
    refused("a wildcard redirect URI", lambda c: c.update(redirect_uris=["https://zz.example.mil/*"]), "wildcard")
    refused("an http redirect URI", lambda c: c.update(redirect_uris=["http://zz.example.mil/cb"]), "must use https")
    refused("a localhost redirect URI", lambda c: c.update(redirect_uris=["https://localhost:3002/cb"]), "localhost")
    refused("a 127.0.0.1 redirect URI", lambda c: c.update(redirect_uris=["https://127.0.0.1/cb"]), "IP literal")
    refused("a *.localhost redirect URI", lambda c: c.update(redirect_uris=["https://app.localhost/cb"]), "localhost")
    refused("a [::1] post-logout URI", lambda c: c.update(post_logout_redirect_uris=["https://[::1]/out"]), "IP literal")
    refused("a redirect URI with a fragment", lambda c: c.update(redirect_uris=["https://zz.example.mil/cb#x"]), "fragment")
    refused("no redirect URIs", lambda c: c.update(redirect_uris=[]), "redirect_uris")
    refused("no post-logout URIs", lambda c: c.pop("post_logout_redirect_uris"), "post_logout_redirect_uris: required")
    for host in ("127.1", "2130706433", "0x7f.1", "0177.0.0.1", "127.0.0.1", "10.0.0.5", "169.254.169.254", "[::1]",
                 "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[fe80::1]", "93.184.216.34"):
        for field in ("redirect_uris", "post_logout_redirect_uris", "jwks_url", "backchannel_logout_url"):
            u = "https://%s/x" % host
            refused("IP literal %s in %s" % (host, field),
                    lambda c, f=field, u=u: c.update({f: [u] if f.endswith("uris") else u}), "IP literal")
    for host in ("127.0.0.1.", "0x7f000001", "017700000001", "[::ffff:7f00:1]", "[0:0:0:0:0:0:0:1]", "10.1"):
        refused("IP literal %s (the public validator's spellings)" % host, lambda c, h=host: c.update(redirect_uris=["https://%s/cb" % h]), "IP")
    # localhost: never on the production IdP (no --allow-dev: the option does not exist)
    for u in ("https://localhost:3002/cb", "http://localhost:3002/cb", "https://LOCALHOST/cb", "https://localhost./cb",
              "https://app.localhost/cb", "https://localhost.localdomain/cb"):
        refused("localhost %s" % u, lambda c, u=u: c.update(redirect_uris=[u]), "localhost")
    check("add-client has no --allow-dev option", "--allow-dev" not in open(a.admin).read())
    # M1: a trailing newline never passes an anchored pattern
    refused("a client_id with a trailing newline", lambda c: c.update(client_id="zz-unit\n"), "client_id")
    refused("a role with a trailing newline", lambda c: c.update(roles=["admin\n"]), "must match")
    for r in ("OFFLINE_ACCESS", "Realm-Admin", "uma_authorization"):
        refused("a built-in role name in any case (%s)" % r, lambda c, r=r: c.update(roles=[r]), "built-in role")
    # L1: duplicate JSON keys
    _, out, ex = run(M.parse_client_file, b'{"client_id": "zz-unit", "client_id": "admin-cli"}', "dup.json")
    check("refused: duplicate JSON keys", ex and "duplicate key" in ex, (ex or "")[:70])
    _, out, ex = run(M.parse_client_file, raw(GOOD)[:-2] + b', "roles": ["x"]}\n', "dup2.json")
    check("refused: a duplicate key at the end (roles twice)", ex and "duplicate key" in ex, (ex or "")[:70])
    # rules the public validator covers since 53ae148, reached through add-client
    _, out, ex = run(M.parse_client_file, b'{"client_id": "zz-unit", "x": NaN}', "nan.json")
    check("refused: NaN in the JSON (upstream's parse_constant hook)", ex and "NaN" in ex, (ex or "")[:60])
    refused("a wildcard-DNS host (nip.io) under strict", lambda c: c.update(redirect_uris=["https://10.0.0.1.nip.io/cb"]), "wildcard-DNS")
    refused("port 0", lambda c: c.update(redirect_uris=["https://zz.example.mil:0/cb"]), "port 0")
    refused("a non-ASCII path", lambda c: c.update(redirect_uris=["https://zz.example.mil/caf\u00e9"]), "non-ASCII")
    # L2: name, list sizes, case-variant duplicates
    refused("a name over 100 characters", lambda c: c.update(name="x" * 101), "name:")
    refused("a name with a bidi control (U+202E)", lambda c: c.update(name="Unit \u202eevil"), "name:")
    refused("a name with a newline", lambda c: c.update(name="Unit\nX"), "name:")
    refused("21 redirect URIs", lambda c: c.update(redirect_uris=["https://zz.example.mil/cb%d" % i for i in range(21)]), "at most 20")
    refused("case-variant duplicate redirect URIs", lambda c: c.update(redirect_uris=["https://zz.example.mil/cb", "https://ZZ.example.mil/cb"]), "duplicate")
    refused("a Keycloak built-in role name", lambda c: c.update(roles=["offline_access"]), "built-in role")
    check("accepted: 20 redirect URIs", M.validate_client(dict(GOOD, redirect_uris=["https://zz.example.mil/cb%d" % i for i in range(20)])) == [])
    refused("a client_id ending in a hyphen (public rule)", lambda c: c.update(client_id="zz-unit-"), "client_id")
    # the public validator is used unmodified: from this checkout, the relying-party skill's own file
    M.vcr()
    upstream = os.path.realpath(os.path.join(HERE, "..", "..", "..", "..", "keycloak-rp-integration", "scripts", "validate-client-request.py"))
    check("add-client uses the relying-party skill's validate-client-request.py itself (not a copy)",
          os.environ.get("IDP_VCR") or os.path.realpath(M.vcr.mod.__file__) == upstream, M.vcr.mod.__file__)
    refused("a single-label name (intranet)", lambda c: c.update(redirect_uris=["https://intranet/cb"]), "local-only")
    refused("a .internal name", lambda c: c.update(jwks_url="https://keys.internal/jwks"), "local-only")
    refused("a .local name", lambda c: c.update(backchannel_logout_url="https://app.local/bcl"), "local-only")
    refused("an invalid port", lambda c: c.update(redirect_uris=["https://zz.example.mil:99999/cb"]), "not a valid URL")
    # names Keycloak fetches: resolved at add time, refused unless every address is public
    for ad in ("127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
               "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "240.0.0.1", "224.0.0.1"):
        errs = M.resolve_errors(GOOD, fake({"zz.example.mil": [ad]}))
        check("refused: jwks/back-channel name resolving to %s" % ad, any("not a public address" in e for e in errs), (errs or ["(accepted)"])[0][:60])
    errs = M.resolve_errors(GOOD, fake({"zz.example.mil": ["93.184.216.34", "10.0.0.1"]}))
    check("refused: a name with one public and one private address", any("10.0.0.1" in e for e in errs))
    errs = M.resolve_errors(GOOD, fake({}))
    check("refused: a jwks/back-channel name that does not resolve", any("does not resolve" in e for e in errs))
    check("accepted: names resolving only to public addresses", M.resolve_errors(GOOD, fake({"zz.example.mil": ["93.184.216.34", "2606:2800:220:1::1"]})) == [])
    M.RESOLVER = fake({"zz.example.mil": ["93.184.216.34"]})       # the apply tests below
    refused("an http back-channel URL", lambda c: c.update(backchannel_logout_url="http://zz.example.mil/bcl"), "must use https")
    refused("a web origin with a path", lambda c: c.update(web_origins=["https://zz.example.mil/app"]), "must be an origin")
    refused("a wildcard web origin", lambda c: c.update(web_origins=["*"]), "wildcard")
    refused("an unknown field (typo)", lambda c: c.update(redirect_uri=["https://zz.example.mil/cb"]), "unknown field 'redirect_uri'")
    refused("a kcstig key add-client does not accept (service_account)", lambda c: c.update(service_account=True), "unknown field 'service_account'")
    refused("auth client-x509", lambda c: c.update(auth="client-x509"), "auth:")
    refused("no auth", lambda c: c.pop("auth"), "auth:")
    refused("client-jwt without jwks_url", lambda c: c.pop("jwks_url"), "jwks_url is required")
    refused("client-jwt with an http jwks_url", lambda c: c.update(jwks_url="http://zz.example.mil/jwks"), "must use https")
    refused("client-secret with a jwks_url", lambda c: c.update(auth="client-secret"), "only for auth client-jwt")
    refused("a public client", lambda c: c.update(type="oidc-public"), "type:")
    refused("a SAML client", lambda c: c.update(type="saml"), "type:")
    refused("no roles", lambda c: c.pop("roles"), "roles: required")
    refused("a duplicate role", lambda c: c.update(roles=["a", "a"]), "duplicate")
    refused("a role with a space", lambda c: c.update(roles=["bad role"]), "must match")
    refused("an upper-case client_id", lambda c: c.update(client_id="ZZ-Unit"), "client_id")
    for rid in ("account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console",
                "master-realm", "example-realm", "anything-realm", "stig-automation", "break-glass-recovery",
                "admin-permissions", "app-a-admin"):
        refused("a reserved client_id %s" % rid, lambda c, r=rid: c.update(client_id=r), "reserved")
    # hosts: ASCII DNS names only (IDNA must be written in its xn-- form)
    for u, why in (("https://xn--exmple-cua.mil/cb", None), ("https://exämple.mil/cb", "non-ASCII"),
                   ("https://ехample.mil/cb", "non-ASCII"), ("https://zz.example.mil/cb\u2028", "whitespace"),
                   ("https://%31%32%37.0.0.1/cb", "not a DNS name"), ("https://zz.example.mil\\@evil.mil/cb", "user:password"),
                   ("https://under_score.example.mil/cb", "not a DNS name"), ("https://-bad.example.mil/cb", "not a DNS name")):
        u = u.encode().decode("unicode_escape") if "\\u" in u else u
        c = copy.deepcopy(GOOD); c["redirect_uris"] = [u]; errs = M.validate_client(c, strict=why is not None)
        if why is None:
            check("accepted: an IDNA (xn--) host %s" % u, errs == [], errs[:1])
        else:
            check("refused: host %r (%s)" % (u, why), any(why in e for e in errs), (errs or ["(accepted)"])[0][:60])
    refused("standard_flow false", lambda c: c.update(standard_flow=False), "standard_flow")
    check("refused: a list of clients in one file", M.validate_client([GOOD]) != [])
    _, out, ex = run(M.parse_client_file, b"{not json", "x.json")
    check("refused: a file that is not JSON", ex and ex.startswith("REFUSED"), ex[:60] if ex else "")
    check("accepted: the good client", M.validate_client(GOOD) == [], M.validate_client(GOOD))
    for f in sorted(os.listdir(REPO_CLIENTS)):
        check("accepted: repo client file %s" % f, M.validate_client(json.load(open(os.path.join(REPO_CLIENTS, f)))) == [])

    # ------------------------------------------------------------------ rendering = the image's kcstig
    rep, roles = M.desired_client(KS, P, GOOD)
    want = KS.client_rep(GOOD, P); want_roles = want.pop("_roles")
    check("the representation is kcstig's client_rep, unchanged", rep == want and roles == want_roles)
    at = rep["attributes"]
    check("enforced: PKCE S256, no implicit, no direct grants, no full scope, back-channel session required",
          at["pkce.code.challenge.method"] == "S256" and rep["implicitFlowEnabled"] is False and rep["directAccessGrantsEnabled"] is False
          and rep["fullScopeAllowed"] is False and at["backchannel.logout.session.required"] == "true")
    check("client-jwt: authenticator and JWKS URL set", rep["clientAuthenticatorType"] == "client-jwt" and at["jwks.url"] == GOOD["jwks_url"])

    # ------------------------------------------------------------------ apply, idempotency, host file
    kc, d = FakeKC(), fresh_dir()
    (cid, created, ch), out, ex = run(M.add_client, kc, raw(GOOD), args())
    hp = os.path.join(d, "zz-unit.json")
    check("create: new client, roles, scopes applied", not ex and created and [c["clientId"] for c in kc.clients.values()] == ["zz-unit"]
          and sorted(kc.roles[next(iter(kc.clients))]) == ["USER_ROLE", "admin"], ex or "")
    cu = next(iter(kc.clients))
    check("create: stig-claims default scope, offline_access optional scope removed",
          "stig-claims" in kc.dscopes[cu] and "offline_access" not in kc.oscopes[cu])
    check("create: the diff names the redirect URIs and roles", "redirectUris" in out and "USER_ROLE" in out)
    check("create: host file written verbatim, mode 0444", os.path.exists(hp) and open(hp, "rb").read() == raw(GOOD)
          and stat.S_IMODE(os.stat(hp).st_mode) == 0o444, oct(stat.S_IMODE(os.stat(hp).st_mode)) if os.path.exists(hp) else "missing")
    check("the secret never appears in the output", "S3CRET" not in out)
    kc.writes.clear()
    (cid, created, ch), out, ex = run(M.add_client, kc, raw(GOOD), args(update="zz-unit"))
    check("re-run: idempotent - no change listed, no write made", not ex and ch == [] and kc.writes == [] and "already matches" in out, kc.writes)
    check("re-run: host file reported unchanged", "unchanged" in out)

    c2 = copy.deepcopy(GOOD); c2["redirect_uris"] = ["https://zz.example.mil/cb2"]
    kc.writes.clear()
    (cid, created, ch), out, ex = run(M.add_client, kc, raw(c2), args(update="zz-unit"))
    check("update: exactly the changed field is listed; one client PUT (+ kcstig's scope PUT)",
          not ex and [x[0] for x in ch] == ["redirectUris"] and [w[0] for w in kc.writes].count("PUT") == 2, [x[0] for x in ch or []])
    check("update: host file rewritten", open(hp, "rb").read() == raw(c2))

    kc.roles[cu].append("LEGACY")
    (cid, created, ch), out, ex = run(M.add_client, kc, raw(c2), args(update="zz-unit"))
    check("an extra live role is kept and reported with its role-delete command",
          not ex and "LEGACY" in kc.roles[cu] and "role-delete zz-unit:LEGACY" in out)

    # a dry run changes nothing, live or on disk
    c3 = copy.deepcopy(c2); c3["name"] = "Unit renamed"; kc.writes.clear()
    (cid, created, ch), out, ex = run(M.add_client, kc, raw(c3), args(dry_run=True, update="zz-unit"))
    check("dry run: the change is shown, nothing written", not ex and [x[0] for x in ch] == ["name"] and kc.writes == []
          and open(hp, "rb").read() == raw(c2) and "dry run" in out)

    # a failed apply never writes the host file
    kc.freeze = True
    _, out, ex = run(M.add_client, kc, raw(c3), args(update="zz-unit"))
    check("an apply that does not stick FAILS and leaves the host file alone",
          ex and "NOT written" in ex and open(hp, "rb").read() == raw(c2), (ex or "")[:70])
    kc.freeze = False

    # an existing live client nobody manages by file is never taken over
    kc2, d2 = FakeKC(), fresh_dir()
    kc2._new(dict(M.desired_client(KS, P, GOOD)[0]))
    _, out, ex = run(M.add_client, kc2, raw(GOOD), args())
    check("refused: a live client with no host file and no marker (not taken over)", ex and "not taken over" in ex and not os.listdir(d2))

    check("create: the client is marked stig.created-by=add-client",
          kc.clients[cu]["attributes"].get("stig.created-by") == "add-client")
    # no takeover: a live client with a host file but no marker needs --adopt, and only for the known clients
    for adoptee, ok_adopt in (("app-b", True), ("zz-other", False)):
        kc6, d6 = FakeKC(), fresh_dir()
        cx = dict(GOOD, client_id=adoptee)
        kc6._new(dict(M.desired_client(KS, P, cx)[0])); open(os.path.join(d6, adoptee + ".json"), "wb").write(raw(cx))
        _, out, ex = run(M.add_client, kc6, raw(cx), args(file=adoptee + ".json"))
        check("refused: %s exists live without the add-client marker (no --adopt)" % adoptee, ex and "not created by add-client" in ex, (ex or "")[:60])
        _, out, ex = run(M.add_client, kc6, raw(cx), args(file=adoptee + ".json", adopt=adoptee))
        cu6 = next(iter(kc6.clients))
        if ok_adopt:
            check("--adopt %s: warns, marks it, nothing else changes" % adoptee, not ex and "WARNING: adopting" in out
                  and kc6.clients[cu6]["attributes"].get("stig.created-by") == "add-client", (ex or "")[:60])
            _, out, ex = run(M.add_client, kc6, raw(cx), args(file=adoptee + ".json", update=adoptee))
            check("after adoption a re-run with --update is accepted and idempotent", not ex and "already matches" in out)
        else:
            check("refused: --adopt of a client outside the adoptable list", ex and "only app-b" in ex, (ex or "")[:60])
    _, out, ex = run(M.add_client, kc, raw(c3), args(adopt="app-b"))
    check("refused: --adopt naming a different client than the file", ex and "does not name" in ex)
    # the same client_id in a second host file
    kc3, d3 = FakeKC(), fresh_dir()
    json.dump(GOOD, open(os.path.join(d3, "old-name.json"), "w"))
    _, out, ex = run(M.add_client, kc3, raw(GOOD), args())
    check("refused: the client_id is already in another host file", ex and "also defined" in ex and not kc3.clients)

    # secrets: client-secret client, --secret-to file 0600; nothing in output
    kc4, d4 = FakeKC(), fresh_dir()
    cs = copy.deepcopy(GOOD); cs.pop("jwks_url"); cs["auth"] = "client-secret"
    sf = os.path.join(WORK, "secret.out")
    M.KC = lambda: kc4                     # cmd_add_client builds its own KC
    src = os.path.join(WORK, "zz-unit.json"); open(src, "wb").write(raw(cs))
    _, out, ex = run(M.cmd_add_client, args(file=src, secret_to=sf))
    check("client-secret: secret written to its file, mode 0600, never printed",
          not ex and open(sf).read().startswith("S3CRET-") and stat.S_IMODE(os.stat(sf).st_mode) == 0o600 and "S3CRET" not in out, ex or "")
    _, out, ex = run(M.cmd_add_client, args(file=src, secret_to_keyvault="bad name"))
    check("refused: a malformed --secret-to-keyvault", ex and "REFUSED" in ex)
    src2 = os.path.join(WORK, "zz-jwt.json"); open(src2, "wb").write(raw(GOOD))
    _, out, ex = run(M.cmd_add_client, args(file=src2, secret_to=sf))
    check("refused: --secret-to on a client-jwt client (it has no secret)", ex and "has no secret" in ex)

    # ------------------------------------------------------------------ check-clients
    kc5, d5 = FakeKC(), fresh_dir()
    run(M.add_client, kc5, raw(GOOD), args())
    drift, out, ex = run(M.check_clients, kc5)
    check("check-clients: live = host file -> no drift", drift == [] and "ok    zz-unit" in out, drift)
    cu5 = next(iter(kc5.clients)); kc5.clients[cu5]["redirectUris"] = ["https://localhost:3002/cb"]
    drift, out, ex = run(M.check_clients, kc5)
    check("check-clients: a live change the file would undo -> drift naming the field", drift and "redirectUris" in out)
    kc5.clients[cu5]["redirectUris"] = GOOD["redirect_uris"]
    json.dump(dict(GOOD, client_id="zz-ghost"), open(os.path.join(d5, "zz-ghost.json"), "w"))
    drift, out, ex = run(M.check_clients, kc5)
    check("check-clients: a host file with no live client -> drift (a restart creates it)", any("zz-ghost" in x and "CREATES" in x for x in drift))
    os.remove(os.path.join(d5, "zz-ghost.json"))
    repo = tempfile.mkdtemp(dir=WORK); rc = os.path.join(repo, M.REPO_CLIENTS); os.makedirs(rc)
    open(os.path.join(rc, "zz-unit.json"), "wb").write(raw(GOOD))
    drift, out, ex = run(M.check_clients, kc5, rc)
    check("check-clients --repo: equal repo copy -> no drift", drift == [], drift)
    open(os.path.join(rc, "zz-unit.json"), "wb").write(raw(dict(GOOD, name="Stale")))
    drift, out, ex = run(M.check_clients, kc5, rc)
    check("check-clients --repo: a stale repo copy -> drift", any("differ" in x for x in drift))
    os.remove(os.path.join(rc, "zz-unit.json"))
    drift, out, ex = run(M.check_clients, kc5, rc)
    check("check-clients --repo: no repo copy -> drift", any("no repo copy" in x for x in drift))
    M.RESOLVER = fake({"zz.example.mil": ["10.0.1.20"]})          # the name was re-pointed at an internal address
    drift, out, ex = run(M.check_clients, kc5)
    check("check-clients: a jwks/back-channel host now resolving to a private address -> drift",
          any("10.0.1.20" in x and "not a public address" in x for x in drift), drift[:1])
    M.RESOLVER = fake({})
    drift, out, ex = run(M.check_clients, kc5)
    check("check-clients: a jwks/back-channel host that no longer resolves -> drift", any("does not resolve" in x for x in drift))
    M.RESOLVER = fake({"zz.example.mil": ["93.184.216.34"]})
    kc5._new(dict(M.desired_client(KS, P, dict(GOOD, client_id="zz-unmanaged"))[0]))
    drift, out, ex = run(M.check_clients, kc5)
    check("check-clients: a live client with no file is reported as info, not drift", "info  zz-unmanaged" in out and drift == [])
    # ------------------------------------------------------------------ ownership (upstream review): owner, --update, --transfer
    kcA, dA = FakeKC(), fresh_dir()
    nofile = {k: v for k, v in GOOD.items() if k not in ("owner", "owner_contact")}
    _, out, ex = run(M.add_client, kcA, raw(nofile), args())
    check("refused: a file without owner / owner_contact", ex and "must carry" in ex and not kcA.clients, (ex or "")[:60])
    _, out, ex = run(M.add_client, kcA, raw(GOOD), args(owner="team-b"))
    check("refused: --owner differs from the file's owner", ex and "must carry" in ex and not kcA.clients)
    _, out, ex = run(M.add_client, kcA, raw(GOOD), args(owner=None))
    check("refused: no --owner", ex and "--owner" in ex)
    _, out, ex = run(M.add_client, kcA, raw(GOOD), args(update="zz-unit"))
    check("refused: --update for a client that does not exist", ex and "no such client" in ex and not kcA.clients)
    _, out, ex = run(M.add_client, kcA, raw(GOOD), args(transfer=True))
    check("refused: --transfer for a client that does not exist", ex and "does not exist" in ex and not kcA.clients)
    _, out, ex = run(M.add_client, kcA, raw(GOOD), args())
    cuA = next(iter(kcA.clients)); atA = kcA.clients[cuA]["attributes"]
    check("create: owner and contact recorded (stig.owner, stig.owner-contact)",
          not ex and atA.get("stig.owner") == "team-a" and atA.get("stig.owner-contact") == "lead@team-a.example.mil", (ex or "")[:60])
    _, out, ex = run(M.add_client, kcA, raw(GOOD), args())
    check("refused: the client exists and there is no --update (a second request with the same client_id)",
          ex and "--update zz-unit" in ex)
    _, out, ex = run(M.add_client, kcA, raw(GOOD), args(update="other-id"))
    check("refused: --update naming another client", ex and "does not name" in ex)
    teamB = dict(GOOD, owner="team-b", owner_contact="lead@team-b.example.mil", redirect_uris=["https://zz.example.mil/b-cb"])
    _, out, ex = run(M.add_client, kcA, raw(teamB), args(update="zz-unit", owner="team-b", owner_contact="lead@team-b.example.mil"))
    check("refused: another owner's --update without --transfer; nothing changed",
          ex and "owned by team-a" in ex and kcA.clients[cuA]["redirectUris"] == GOOD["redirect_uris"], (ex or "")[:60])
    _, out, ex = run(M.add_client, kcA, raw(teamB), args(update="zz-unit", owner="team-b", owner_contact="lead@team-b.example.mil", transfer=True))
    atA = kcA.clients[cuA]["attributes"]
    check("--transfer: warns, moves the owner, applies the file", not ex and "WARNING: transferring zz-unit from team-a" in out
          and atA.get("stig.owner") == "team-b" and kcA.clients[cuA]["redirectUris"] == ["https://zz.example.mil/b-cb"], (ex or "")[:60])
    check("update: a before/after diff of the URI fields (- removed, + added)",
          "URI fields of zz-unit" in out and "- https://zz.example.mil/cb" in out and "+ https://zz.example.mil/b-cb" in out)
    _, out, ex = run(M.add_client, kcA, raw(teamB), args(update="zz-unit", owner="team-b", owner_contact="lead@team-b.example.mil", transfer=True))
    check("refused: --transfer to the current owner", ex and "already owned" in ex)
    # strict by default
    q = dict(GOOD, redirect_uris=["https://zz.example.mil/cb?x=1"])
    check("strict: a query string in a redirect URI is refused", any("query" in e for e in M.validate_client(q)))
    check("--lenient: the same is accepted", M.validate_client(q, strict=False) == [])
    off = dict(GOOD, post_logout_redirect_uris=["https://other.example.mil/out"])
    check("strict: a post-logout URI off root_url's origin is refused", any("root_url's origin" in e for e in M.validate_client(off)))
    check("--lenient: the same is accepted", M.validate_client(off, strict=False) == [])
    noroot = {k: v for k, v in GOOD.items() if k != "root_url"}
    check("strict: a file without root_url is refused", any("root_url: required" in e for e in M.validate_client(noroot)))
    check("--lenient: a file without root_url is accepted", M.validate_client(noroot, strict=False) == [])
    wo = dict(GOOD, web_origins=["https://other.example.mil"])
    check("strict: a web_origins entry on a foreign origin is refused", any("web_origins[0]" in e and "origin" in e for e in M.validate_client(wo)))
    jw = dict(GOOD, jwks_url="https://keys.other.example.mil/jwks")
    check("strict: a jwks_url on a foreign origin is refused", any(e.startswith("jwks_url") and "origin" in e for e in M.validate_client(jw)))
    check("--lenient: foreign web origin and jwks_url accepted", M.validate_client(wo, strict=False) == [] and M.validate_client(jw, strict=False) == [])
    kcL, dL = FakeKC(), fresh_dir()
    _, out, ex = run(M.add_client, kcL, raw(q), args())
    check("add-client is strict unless --lenient", ex and "query" in ex and not kcL.clients)
    _, out, ex = run(M.add_client, kcL, raw(q), args(lenient=True))
    check("add-client --lenient registers it", not ex and kcL.clients, (ex or "")[:60])
    for f in REPO_CLIENTS_LIST:
        check("strict: repo client file %s passes" % f, M.validate_client(json.load(open(os.path.join(REPO_CLIENTS, f)))) == [])
    # the three pre-existing clients are adopted with owner ops-team
    kcJ, dJ = FakeKC(), fresh_dir()
    cj = dict(GOOD, client_id="app-b", owner="ops-team", owner_contact="op.admin@example.mil")
    kcJ._new(dict(M.desired_client(KS, P, cj)[0])); open(os.path.join(dJ, "app-b.json"), "wb").write(raw(cj))
    _, out, ex = run(M.add_client, kcJ, raw(cj), args(file="app-b.json", adopt="app-b", owner="ops-team",
                                                       owner_contact="op.admin@example.mil"))
    ADOPT_OUT = out
    atJ = kcJ.clients[next(iter(kcJ.clients))]["attributes"]
    check("--adopt app-b records owner ops-team", not ex and atJ.get("stig.owner") == "ops-team" and atJ.get("stig.created-by") == "add-client", (ex or "")[:60])
    # check-clients: the owner in the host file must be the live one; a file without owner is info only
    drift, out, ex = run(M.check_clients, kcJ)
    check("check-clients: owner in host file = live owner -> no drift", drift == [], drift[:1])
    kcJ.clients[next(iter(kcJ.clients))]["attributes"]["stig.owner"] = "someone-else"
    drift, out, ex = run(M.check_clients, kcJ)
    check("check-clients: live owner differs from the host file's -> drift", any("owner" in x for x in drift))
    # N3: an unowned existing client - first owner recorded only via --update/--adopt, said so; --transfer refused
    kcU, dU = FakeKC(), fresh_dir()
    run(M.add_client, kcU, raw(GOOD), args())
    for k in ("stig.owner", "stig.owner-contact"): kcU.clients[next(iter(kcU.clients))]["attributes"].pop(k)
    _, out, ex = run(M.add_client, kcU, raw(GOOD), args())
    check("unowned client: refused without --update (no silent claim)", ex and "--update zz-unit" in ex)
    _, out, ex = run(M.add_client, kcU, raw(GOOD), args(update="zz-unit", transfer=True))
    check("unowned client: --transfer refused (nothing to transfer)", ex and "no owner recorded yet" in ex
          and not kcU.clients[next(iter(kcU.clients))]["attributes"].get("stig.owner"))
    _, out, ex = run(M.add_client, kcU, raw(GOOD), args(update="zz-unit"))
    check("unowned client + --update: 'first owner recorded' printed and the owner set",
          not ex and "first owner recorded for zz-unit: team-a" in out
          and kcU.clients[next(iter(kcU.clients))]["attributes"].get("stig.owner") == "team-a", (ex or "")[:60])
    check("--adopt also prints 'first owner recorded'", "first owner recorded" in ADOPT_OUT)
    kcK, dK = FakeKC(), fresh_dir()
    run(M.add_client, kcK, raw(GOOD), args())                     # a client as it was before owners were recorded:
    for k in ("stig.owner", "stig.owner-contact"): kcK.clients[next(iter(kcK.clients))]["attributes"].pop(k)
    os.chmod(os.path.join(dK, "zz-unit.json"), 0o644); open(os.path.join(dK, "zz-unit.json"), "wb").write(raw(nofile))
    drift, out, ex = run(M.check_clients, kcK)
    check("check-clients: a pre-existing file without owner is info, not drift", drift == [] and "no owner recorded" in out, drift[:1])

    # ------------------------------------------------------------------ L10
    # check-clients: a missing stig-claims default scope is drift (a restart would add it)
    kc7, d7 = FakeKC(), fresh_dir(); run(M.add_client, kc7, raw(GOOD), args())
    kc7.dscopes[next(iter(kc7.clients))].remove("stig-claims")
    drift, out, ex = run(M.check_clients, kc7)
    check("check-clients: a client without the stig-claims default scope -> drift", drift and "stig-claims" in out, drift[:1])
    # check-clients retries resolution: one transient failure is not drift
    calls = {"n": 0}
    def flaky(h, port, proto=0):
        calls["n"] += 1
        if calls["n"] == 1: raise socket.gaierror("temporary failure")
        return [(0, 0, 0, "", ("93.184.216.34", port))]
    M.RESOLVER = flaky
    kc7.dscopes[next(iter(kc7.clients))].append("stig-claims")
    drift, out, ex = run(M.check_clients, kc7)
    check("check-clients: a transient resolver failure is retried, not drift", drift == [] and calls["n"] >= 2, drift[:1])
    M.RESOLVER = fake({"zz.example.mil": ["93.184.216.34"]})
    # cmd_add_client resolves BEFORE KC() (inside Keycloak's netns the host resolver is unreachable)
    order = []
    def order_resolver(h, port, proto=0):
        order.append("resolve"); return [(0, 0, 0, "", ("93.184.216.34", port))]
    kc8, d8 = FakeKC(), fresh_dir()
    M.RESOLVER = order_resolver
    M.KC = lambda: (order.append("KC"), kc8)[1]
    src8 = os.path.join(WORK, "zz-order.json"); open(src8, "wb").write(raw(GOOD))
    _, out, ex = run(M.cmd_add_client, args(file=src8))
    check("add-client resolves the Keycloak-fetched names before joining Keycloak's namespace",
          not ex and order and order[0] == "resolve" and order.index("KC") > 0, order[:4])
    check("add-client says the new client has no delegation groups (not in the config's applications) and how to add them",
          "not in the config's applications" in out and "roles-setup" in out)
    M.RESOLVER = fake({"zz.example.mil": ["93.184.216.34"]})
    # client-delete removes the client's own host file; refuses (before deleting anything) when the file holds others
    M.KC = lambda: kc8
    _, out, ex = run(M.cmd_client_delete, argparse.Namespace(client="zz-unit"))
    check("client-delete: deletes the client and removes its host file", not ex and not kc8.clients
          and not os.path.exists(os.path.join(d8, "zz-unit.json")), (ex or "")[:60])
    kc9, d9 = FakeKC(), fresh_dir(); M.KC = lambda: kc9
    kc9._new(dict(M.desired_client(KS, P, GOOD)[0]))
    json.dump([GOOD, dict(GOOD, client_id="zz-other")], open(os.path.join(d9, "shared.json"), "w"))
    _, out, ex = run(M.cmd_client_delete, argparse.Namespace(client="zz-unit"))
    check("client-delete: refused for a client inside a multi-client host file; nothing deleted",
          ex and "holds other clients" in ex and kc9.clients and os.path.exists(os.path.join(d9, "shared.json")), (ex or "")[:60])
    # L7: the secret file is never written through a symlink
    target = os.path.join(WORK, "elsewhere"); link = os.path.join(WORK, "secret.link"); os.symlink(target, link)
    try:
        M.write_secret_file(link, "x"); followed = True
    except OSError:
        followed = False
    check("the secret file refuses a symlink (O_NOFOLLOW)", not followed and not os.path.exists(target))
finally:
    shutil.rmtree(WORK, True)
print("\n%d/%d passed" % (sum(res), len(res))); sys.exit(0 if all(res) else 1)

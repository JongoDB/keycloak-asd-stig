#!/usr/bin/env python3
"""Tests for the client request format.

  python3 keycloak-rp-integration/tests/test_client_request.py

- the example and tests/fixtures/valid/* pass the validator; every tests/fixtures/invalid/* fails it
- the JSON Schema agrees with the validator on every fixture (needs `pip install jsonschema`;
  REQUIRE_JSONSCHEMA=1 makes its absence a failure, as CI sets)
- 1:1 with the operator side: the client file emitted for each valid request loads through the IdP skill's
  kcstig.py (keycloak-asd-stig/scripts) with no profile warnings, and renders to a Keycloak client with PKCE S256,
  no implicit or password grant, the requested authenticator, JWKS URL, logout URLs and roles
"""
import contextlib
import subprocess
import glob
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
REPO = os.path.dirname(SKILL)
EXAMPLE = os.path.join(SKILL, "assets", "client-request.example.json")
SCHEMA = os.path.join(SKILL, "assets", "client-request.schema.json")
VALID = sorted(glob.glob(os.path.join(HERE, "fixtures", "valid", "*.json"))) + [EXAMPLE]
INVALID = sorted(glob.glob(os.path.join(HERE, "fixtures", "invalid", "*.json")))
# Refused by the validator; JSON Schema cannot express these (secret-looking free text, duplicate keys, NaN).
VALIDATOR_ONLY = sorted(glob.glob(os.path.join(HERE, "fixtures", "invalid-validator-only", "*.json")))
# Valid, with warnings that --strict turns into failures (wildcard-DNS services, single-label hosts).
STRICT_INVALID = sorted(glob.glob(os.path.join(HERE, "fixtures", "strict-invalid", "*.json")))
KCSTIG = os.path.join(REPO, "keycloak-asd-stig", "scripts", "kcstig.py")


def jload(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vcr = load_module("vcr", os.path.join(SKILL, "scripts", "validate-client-request.py"))


def run_cli(*args):
    err = io.StringIO()
    out = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
        rc = vcr.main(list(args))
    return rc, out.getvalue(), err.getvalue()


class Validator(unittest.TestCase):
    def test_fixtures_exist(self):
        self.assertGreaterEqual(len(VALID), 3)
        self.assertGreaterEqual(len(INVALID), 15)

    def test_valid_requests_pass(self):
        for f in VALID:
            with self.subTest(f=os.path.basename(f)):
                rc, _, err = run_cli(f)
                self.assertEqual(rc, 0, err)

    def test_invalid_requests_fail(self):
        for f in INVALID:
            with self.subTest(f=os.path.basename(f)):
                rc, _, err = run_cli(f)
                self.assertEqual(rc, 1, "accepted: " + err)
                self.assertIn("ERROR ", err)

    def test_validator_only_fixtures_fail(self):
        self.assertGreaterEqual(len(VALIDATOR_ONLY), 5)
        for f in VALIDATOR_ONLY:
            with self.subTest(f=os.path.basename(f)):
                rc, _, err = run_cli(f)
                self.assertEqual(rc, 1, "accepted: " + err)

    def test_duplicate_keys_refused(self):
        rc, _, err = run_cli(os.path.join(HERE, "fixtures", "invalid-validator-only", "duplicate-client-id-key.json"))
        self.assertEqual(rc, 1)
        self.assertIn("duplicate key 'client_id'", err)

    def test_warnings_fail_only_under_strict(self):
        self.assertGreaterEqual(len(STRICT_INVALID), 3)
        for f in STRICT_INVALID:
            with self.subTest(f=os.path.basename(f)):
                rc, _, err = run_cli(f)
                self.assertEqual(rc, 0, err)
                self.assertTrue("wildcard-DNS" in err or "single-label" in err, err)
                self.assertEqual(run_cli("--strict", f)[0], 1)

    def test_trailing_newlines_never_match(self):
        ex = jload(EXAMPLE)
        for field, value in (("client_id", "myapp-web\n"), ("client_id", "account\n"), ("client_id", "master-realm\n"),
                             ("roles", ["viewer\n"]), ("roles", ["viewer\r\n"])):
            with self.subTest(field=field, value=value):
                self.assertTrue(vcr.validate(dict(ex, **{field: value})).errors)
        self.assertTrue(vcr.validate(dict(ex, contact=dict(ex["contact"], email="a@example.mil\n"))).errors)
        self.assertTrue(vcr.host_problem("myapp.example.mil\n"))

    def test_notes_scanned_for_secrets(self):
        ex = jload(EXAMPLE)
        for notes in ("password: correct-horse", "api_key=abc123", "AKIAABCDEFGHIJKLMNOP",
                      "ghp_abcdefghijklmnopqrstuvwxyz0123", "Zx9Kq2LmP7vR4tY8wN1aB3cD5eF6gH0j"):
            with self.subTest(notes=notes):
                self.assertTrue(any(e.startswith("notes") for e in vcr.validate(dict(ex, notes=notes)).errors))
        for notes in ("The JWKS is served behind the internal proxy.", "Ticket 4411; contact the ops desk",
                      "https://myapp.example.mil/oauth2/callback must stay exact"):
            with self.subTest(notes=notes):
                self.assertEqual(vcr.validate(dict(ex, notes=notes)).errors, [])

    def test_strict_turns_warnings_into_failure(self):
        rc, _, _ = run_cli("--strict", EXAMPLE)   # placeholder domain warning
        self.assertEqual(rc, 1)

    def test_emit_client_is_the_operator_format(self):
        rc, out, err = run_cli("--quiet", "--emit-client", "-", EXAMPLE)
        self.assertEqual(rc, 0, err)
        c = json.loads(out)
        req = jload(EXAMPLE)
        self.assertEqual(c["type"], "oidc-confidential")
        for k, v in req.items():
            if k in ("$schema", "contact", "dev_request", "notes"):
                self.assertNotIn(k, c)
            else:
                self.assertEqual(c[k], v, k)

    def test_no_emit_when_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "c.json")
            rc, _, _ = run_cli("--emit-client", out, INVALID[0])
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(out))


class HostRules(unittest.TestCase):
    """IP literals are refused in every URL field in every spelling; only DNS names, plus `localhost` in dev."""
    IP_FORMS = ["127.0.0.1", "127.1", "127.0.1", "2130706433", "0x7f000001", "0X7F000001", "0x7f.0.0.1",
                "0177.0.0.1", "017700000001", "127.0.0.1.", "10.1", "192.0.2.10", "[::1]", "[::ffff:127.0.0.1]",
                "[::ffff:7f00:1]", "[0:0:0:0:0:ffff:7f00:1]", "[fe80::1%25eth0]", "app.localhost", "x.localhost."]
    FIELDS = ("root_url", "redirect_uris", "post_logout_redirect_uris", "backchannel_logout_url", "jwks_url")

    def _with(self, req, field, url):
        req = dict(req)
        req[field] = [url] if field.endswith("uris") else url
        return req

    def test_ip_forms_refused_in_every_field_prod_and_dev(self):
        prod = jload(EXAMPLE)
        dev = jload(os.path.join(HERE, "fixtures", "valid", "dev-localhost.json"))
        for host in self.IP_FORMS:
            for field in self.FIELDS:
                for name, base, scheme in (("prod", prod, "https"), ("dev", dev, "http"), ("dev-https", dev, "https")):
                    with self.subTest(host=host, field=field, request=name):
                        r = vcr.validate(self._with(base, field, "%s://%s/x" % (scheme, host)))
                        self.assertTrue(any(e.startswith(field) for e in r.errors), r.errors)

    def test_non_ascii_hosts_refused(self):
        # Look-alikes that case-fold or IDNA-map onto other names, Unicode digits and dots, and plain IDNs.
        for host in ("loca\u017fhost", "app.\u212aloc.mil", "m\u00fcnchen.example.mil", "127.\u0661", "\u0661\u0662\u0667.1",
                     "myapp\uff0eexample.mil", "myapp.example.mi\u217c", "xn--mnchen-3ya.example.mil\u200b"):
            with self.subTest(host=host):
                self.assertIsNotNone(vcr.host_problem(host))
                r = vcr.validate(self._with(jload(EXAMPLE), "redirect_uris", "https://%s/x" % host))
                self.assertTrue(any("non-ASCII" in e for e in r.errors), r.errors)
        self.assertIsNone(vcr.host_problem("xn--mnchen-3ya.example.mil"))   # punycode is fine

    def test_reserved_client_ids_refused(self):
        for cid in sorted(vcr.RESERVED_CLIENT_IDS) + ["master-realm", "apps-realm"]:
            with self.subTest(cid=cid):
                r = vcr.validate(dict(jload(EXAMPLE), client_id=cid))
                self.assertTrue(any(e.startswith("client_id") and "reserved" in e for e in r.errors), r.errors)
        for cid in ("myapp-web", "realm-viewer", "accounts-web", "broker-ui"):
            with self.subTest(cid=cid):
                self.assertFalse([e for e in vcr.validate(dict(jload(EXAMPLE), client_id=cid)).errors
                                  if e.startswith("client_id")])

    def test_dns_names_with_digits_are_fine(self):
        for host in ("app1.example.mil", "10-1.example.mil", "127.example.mil", "xn--bcher-kva.example.mil",
                     "a0x1.example.mil"):
            with self.subTest(host=host):
                self.assertIsNone(vcr.host_problem(host))

    def test_localhost_only_in_dev(self):
        prod = jload(EXAMPLE)
        dev = jload(os.path.join(HERE, "fixtures", "valid", "dev-localhost.json"))
        for url in ("http://localhost:3000/x", "https://localhost/x", "https://LOCALHOST./x"):
            with self.subTest(url=url):
                self.assertTrue(vcr.validate(self._with(prod, "redirect_uris", url)).errors)
                self.assertEqual(vcr.validate(self._with(dev, "redirect_uris", url)).errors, [])
        # dev does not relax https for real hosts
        self.assertTrue(vcr.validate(self._with(dev, "redirect_uris", "http://myapp.example.mil/x")).errors)


class Schema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            if os.environ.get("REQUIRE_JSONSCHEMA") == "1":
                raise
            raise unittest.SkipTest("jsonschema not installed")
        import jsonschema
        schema = jload(SCHEMA)
        jsonschema.Draft202012Validator.check_schema(schema)
        cls.v = jsonschema.Draft202012Validator(schema)

    def test_schema_accepts_valid(self):
        for f in VALID:
            with self.subTest(f=os.path.basename(f)):
                errs = [e.message for e in self.v.iter_errors(jload(f))]
                self.assertEqual(errs, [])

    def test_schema_rejects_invalid(self):
        # Every invalid fixture is something the schema can express too; the validator stays the authority.
        for f in INVALID:
            with self.subTest(f=os.path.basename(f)):
                self.assertFalse(self.v.is_valid(jload(f)), "schema accepted " + f)


@unittest.skipUnless(os.path.exists(KCSTIG), "IdP skill (keycloak-asd-stig) not beside this one")
class OperatorSide(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kc = load_module("kcstig", KCSTIG)

    def test_emitted_clients_load_and_render_cleanly(self):
        for f in VALID:
            with self.subTest(f=os.path.basename(f)), tempfile.TemporaryDirectory() as d:
                req = jload(f)
                cdir = os.path.join(d, "clients.d")
                os.mkdir(cdir)
                rc, _, err = run_cli("--quiet", "--emit-client", os.path.join(cdir, "app.json"), f)
                self.assertEqual(rc, 0, err)
                prof = os.path.join(d, "profile.json")
                with open(prof, "w") as pf:
                    json.dump({"realm": {"name": "apps"}}, pf)
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    p = self.kc.load_profile(prof, cdir)
                self.assertNotIn("WARNING", err.getvalue())
                (c,) = [c for c in p["clients"] if c["client_id"] == req["client_id"]]
                rep = self.kc.client_rep(c, p)
                at = rep["attributes"]
                self.assertEqual(at["pkce.code.challenge.method"], "S256")
                self.assertFalse(rep["implicitFlowEnabled"])
                self.assertFalse(rep["directAccessGrantsEnabled"])
                self.assertFalse(rep["publicClient"])
                self.assertFalse(rep["fullScopeAllowed"])
                self.assertEqual(rep["redirectUris"], req["redirect_uris"])
                self.assertEqual(at["post.logout.redirect.uris"], "##".join(req["post_logout_redirect_uris"]))
                self.assertEqual(at["backchannel.logout.url"], req["backchannel_logout_url"])
                self.assertEqual(rep["_roles"], req["roles"])
                self.assertEqual(rep["clientAuthenticatorType"], req["auth"])
                if req["auth"] == "client-jwt":
                    self.assertEqual(at["jwks.url"], req["jwks_url"])
                if req.get("privileged"):
                    self.assertEqual(at["client.session.idle.timeout"], str(p["sessions"]["admin_idle_minutes"] * 60))

    def test_reserved_ids_agree(self):
        self.assertEqual(vcr.RESERVED_CLIENT_IDS, self.kc.RESERVED_CLIENT_IDS)

    def _profile_dir(self, d, clients):
        prof = os.path.join(d, "profile.json")
        with open(prof, "w") as f:
            json.dump({"realm": {"name": "apps"}, "keycloak": {"url": "https://127.0.0.1:9"}}, f)
        cdir = os.path.join(d, "clients.d")
        os.mkdir(cdir)
        for name, c in clients.items():
            with open(os.path.join(cdir, name), "w") as f:
                json.dump(c, f)
        return prof, cdir

    def test_load_profile_refuses_reserved_ids_in_clients_d(self):
        for cid in ("admin-cli", "account", "master-realm", "Security-Admin-Console"):
            with self.subTest(cid=cid), tempfile.TemporaryDirectory() as d:
                prof, cdir = self._profile_dir(d, {"x.json": {"client_id": cid, "redirect_uris": ["https://a.example.mil/cb"]}})
                with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
                    self.kc.load_profile(prof, cdir)
                self.assertIn("reserved", str(cm.exception.code))

    def test_load_profile_refuses_duplicate_client_ids(self):
        c = {"client_id": "myapp-web", "redirect_uris": ["https://a.example.mil/cb"]}
        with tempfile.TemporaryDirectory() as d:
            prof, cdir = self._profile_dir(d, {"a.json": c, "b.json": c})
            with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
                self.kc.load_profile(prof, cdir)
            self.assertIn("defined twice", str(cm.exception.code))

    def test_owner_only_from_its_own_file(self):
        c = {"client_id": "myapp-web", "redirect_uris": ["https://a.example.mil/cb"], "owner": "team-a",
             "owner_contact": "a@example.mil"}
        for fname, kept in (("myapp-web.json", True), ("other-name.json", False)):
            with self.subTest(fname=fname), tempfile.TemporaryDirectory() as d:
                prof, cdir = self._profile_dir(d, {fname: c})
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    p = self.kc.load_profile(prof, cdir)
                (got,) = p["clients"]
                self.assertEqual("owner" in got, kept)
                self.assertEqual("owner/owner_contact ignored" in err.getvalue(), not kept)
                self.assertEqual(self.kc.client_rep(got, p)["attributes"].get("stig.owner"), "team-a" if kept else None)

    def test_upsert_client_refuses_another_owner(self):
        class FakeKC:
            def __init__(self, owner):
                self.owner, self.writes = owner, []
            def api(self, method, path, obj=None, ok404=False):
                if method == "GET" and "clients?clientId=" in path:
                    return [{"id": "u1", "clientId": "myapp-web", "attributes": {"stig.owner": self.owner}}]
                if method != "GET":
                    self.writes.append((method, path))
                return []
        for want, allowed in ((None, False), ("team-b", False), ("team-a", True)):
            with self.subTest(want=want):
                kc = FakeKC("team-a")
                rep = {"clientId": "myapp-web", "protocol": "openid-connect",
                       "attributes": {"stig.owner": want} if want else {}}
                if allowed:
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.kc.upsert_client(kc, "apps", rep)
                    self.assertTrue(kc.writes)
                else:
                    with self.assertRaises(SystemExit):
                        self.kc.upsert_client(kc, "apps", rep)
                    self.assertEqual(kc.writes, [])
        kc = FakeKC("team-a")
        with contextlib.redirect_stdout(io.StringIO()):
            self.kc.upsert_client(kc, "apps", {"clientId": "myapp-web", "protocol": "openid-connect",
                                               "attributes": {"stig.owner": "team-b"}}, allow_owner_change=True)
        self.assertTrue(kc.writes)

    def test_upsert_client_refuses_reserved_ids(self):
        class NoCalls:
            def api(self, *a, **k):
                raise AssertionError("upsert_client called the admin API for a reserved id")
        for cid in ("realm-management", "apps-realm"):
            with self.subTest(cid=cid), self.assertRaises(SystemExit):
                self.kc.upsert_client(NoCalls(), "apps", {"clientId": cid, "attributes": {}})

    def _add_client(self, d, req, *extra, clients=None):
        prof, cdir = self._profile_dir(d, clients or {})
        rpath = os.path.join(d, "req.json")
        with open(rpath, "w") as f:
            json.dump(req, f) if isinstance(req, dict) else f.write(req)
        env = {k: v for k, v in os.environ.items() if not k.startswith("KC_")}   # no admin credentials: must stop first
        return subprocess.run([sys.executable, KCSTIG, "add-client", rpath, "--profile", prof, "--clients-dir", cdir] +
                              list(extra), capture_output=True, text=True, env=env, timeout=60), cdir

    def test_add_client_refuses_before_touching_keycloak(self):
        ex = jload(EXAMPLE)
        dev = jload(os.path.join(HERE, "fixtures", "valid", "dev-localhost.json"))
        cases = {
            "invalid request": (dict(ex, redirect_uris=["https://myapp.example.mil/*"]), [], None, "request refused"),
            "reserved id": (dict(ex, client_id="admin-cli"), [], None, "request refused"),
            "trailing newline id": (dict(ex, client_id="account\n"), [], None, "request refused"),
            "warnings are errors by default": (ex, [], None, "warnings are errors by default"),
            "wildcard-DNS host refused by default": (
                dict(ex, redirect_uris=["https://myapp.127.0.0.1.nip.io/oauth2/callback"]), [], None, "nip.io"),
            "dev without --allow-dev": (dev, ["--no-strict"], None, "--allow-dev"),
            "defined by another clients.d file": (ex, ["--no-strict"], {"other.json": {"client_id": "myapp-web"}},
                                                  "already defined"),
            "adopt mismatch": (ex, ["--no-strict", "--adopt", "other-app"], None, "does not match"),
            "update mismatch": (ex, ["--no-strict", "--update", "other-app"], None, "does not match"),
            "bad owner id": (ex, ["--no-strict", "--owner", "team a; rm"], None, "--owner"),
            "missing --validator path": (ex, ["--validator", "/nonexistent/validate.py"], None, "does not exist"),
            "duplicate keys": ('{"client_id": "myapp-web", "client_id": "admin-cli"}', [], None, "duplicate key"),
        }
        for name, (req, extra, clients, expect) in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as d:
                r, cdir = self._add_client(d, req, *extra, clients=clients)
                self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn(expect, r.stdout + r.stderr)
                self.assertNotIn("Set KC_CLIENT_ID", r.stdout + r.stderr)       # stopped before any login attempt
                self.assertFalse(os.path.exists(os.path.join(cdir, "%s.json" % ex["client_id"])))

    def test_client_fields_are_operator_keys(self):
        self.assertTrue(set(vcr.CLIENT_FIELDS) <= self.kc.CLIENT_KEYS, set(vcr.CLIENT_FIELDS) - self.kc.CLIENT_KEYS)


if __name__ == "__main__":
    unittest.main(verbosity=2)

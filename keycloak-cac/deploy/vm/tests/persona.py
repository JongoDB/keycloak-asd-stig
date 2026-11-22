"""A real person holding an IdP role, for the live tests. Service accounts are never administrators (or user managers),
so a test's user manager / administrator is a person: created with a password, TOTP enrolled at a first sign-in as an
ordinary account, granted the role by the operator's tooling (idp-admin.py grant: allowlisted), then signed in with
password + TOTP on the realm's admin console client. .token() returns a fresh access token (refreshed as needed).

  p = Person(M, kc, E, run, BASE, REALM, "t.fp.um", "idp-user-manager")
  p.token(); p.api("GET", "/users?max=1") -> (status, body)
"""
import argparse, json, time, urllib.error, urllib.parse, urllib.request, uuid


class Person:
    def __init__(self, M, kc, E, run, base, realm, username, role, email_domain="notify.example.mil"):
        self.M, self.kc, self.E, self.base, self.realm = M, kc, E, base, realm
        self.username, self.pw, self.ctx = username, "Pp1!" + uuid.uuid4().hex[:20], {}
        self.console = "%s/admin/%s/console/" % (base, realm)
        kc.api("POST", "/users", {"username": username, "email": "%s@%s" % (username, email_domain), "firstName": "Test",
                                  "lastName": "Person", "enabled": True, "requiredActions": ["CONFIGURE_TOTP"],
                                  "credentials": [{"type": "password", "value": self.pw, "temporary": False}]})
        self.user = M.user(kc, username)
        self._sign_in()                                  # an ordinary account: enrols TOTP
        rc, out = run("grant", username, role)
        if rc != 0 or not M.is_admin(kc, self.user["id"]):
            raise RuntimeError("could not grant %s %s: %s" % (username, role, out[-300:]))
        time.sleep(31)                                   # a TOTP code is good once
        self.tok, self.at = self._sign_in(), time.time()

    def _flow(self):
        return self.E.Flow(argparse.Namespace(url=self.base, realm=self.realm, client="security-admin-console", redirect=self.console,
                                              admin_url=None, client_secret=None, cacert=None))

    def _sign_in(self):
        fl = self._flow(); b = self.E.Browser(); url, ver = fl.auth_url()
        k, u, p = b.go(url, None, self.console)
        act, f = self.E.form(p, "kc-form-login"); f.update({"username": self.username, "password": self.pw})
        k, u, p = b.go(act, f, self.console)
        final, seen = fl.finish(b, k, u, p, self.ctx)
        if not final or "code=" not in final:
            raise RuntimeError("%s could not sign in: %s" % (self.username, seen))
        return fl.token(urllib.parse.parse_qs(urllib.parse.urlparse(final).query)["code"][0], ver)

    def token(self):
        if time.time() - self.at > 45:
            data = urllib.parse.urlencode({"grant_type": "refresh_token", "client_id": "security-admin-console",
                                           "refresh_token": self.tok["refresh_token"]}).encode()
            with urllib.request.urlopen(urllib.request.Request("%s/realms/%s/protocol/openid-connect/token" % (self.base, self.realm),
                                                               data=data), timeout=30) as r:
                self.tok, self.at = json.loads(r.read()), time.time()
        return self.tok["access_token"]

    def api(self, method, path, body=None):
        """(status, parsed body) of an admin-API call as this person; `path` is relative to /admin/realms/<realm>."""
        req = urllib.request.Request("%s/admin/realms/%s%s" % (self.base, self.realm, path), method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": "Bearer " + self.token(), "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                t = r.read().decode(); return r.status, (json.loads(t) if t.strip().startswith(("{", "[")) else t)
        except urllib.error.HTTPError as e:
            t = e.read().decode(); return e.code, (json.loads(t) if t.strip().startswith(("{", "[")) else t)

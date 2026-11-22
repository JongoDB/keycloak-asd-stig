#!/usr/bin/env python3
"""A forged client-certificate header must never sign anyone in (security review).

In edge mode Keycloak trusts the `ssl-client-cert` header a proxy sets. This deployment is
passthrough -- Keycloak reads the certificate from the TLS handshake and its image is built
with the default x509 lookup, which reads no header at all -- so a header carrying a real
user's certificate, sent with NO client certificate in the handshake, must be ignored:

  1. directly to the Keycloak service (bypassing Traefik), and
  2. through Traefik on the public name.

Either way the login must not complete as that user: no authorization code, and the page must
not be the "You will be logged in as ..." X.509 confirmation for the forged identity.

  forged_header_check.py --url https://sso.example --direct https://keycloak-stig:8443 \
      --realm example --client example-e2e --redirect https://e2e/callback --cacert ca.crt \
      --forged-cert doe.john.crt
Exit 0 only if every attempt was refused.
"""

import argparse
import base64
import hashlib
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

HEADERS = ("ssl-client-cert", "SSL_CLIENT_CERT", "X-SSL-Client-Cert", "X-Client-Cert")


class Stop(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def attempt(base, realm, client, redirect, ctx, header_value, host=None):
    ver = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    chal = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
    q = {
        "client_id": client,
        "redirect_uri": redirect,
        "response_type": "code",
        "scope": "openid",
        "state": "s",
        "nonce": "n",
        "code_challenge": chal,
        "code_challenge_method": "S256",
    }
    url = f"{base}/realms/{realm}/protocol/openid-connect/auth?{urllib.parse.urlencode(q)}"
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), Stop())
    req = urllib.request.Request(url)
    for name in HEADERS:
        req.add_header(name, header_value)
    if host:
        req.add_header("Host", host)
    try:
        resp = opener.open(req, timeout=30)
        body = resp.read().decode("utf-8", "replace")
        location = ""
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", "replace")
        location = err.headers.get("Location", "")
    page = re.search(r'data-page-id="([^"]+)"', body)
    return location, (page.group(1) if page else "?"), body


def main():
    ap = argparse.ArgumentParser()
    for o in ("url", "direct", "realm", "client", "redirect", "cacert", "forged-cert"):
        ap.add_argument("--" + o, required=True)
    # Positive control: the forged card's own key, presented in the handshake, MUST reach the
    # X.509 confirmation for that user -- proof this check can see a sign-in when one happens.
    ap.add_argument("--control-key")
    a = ap.parse_args()
    ctx = ssl.create_default_context(cafile=a.cacert)
    pem = open(a.forged_cert).read()
    # nginx's $ssl_client_escaped_cert form, and the raw PEM on one line.
    values = [urllib.parse.quote(pem, safe=""), pem.replace("\n", " ")]
    public_host = urllib.parse.urlparse(a.url).hostname
    failures = 0
    for label, base, host in (("direct to the service", a.direct, public_host), ("through the public URL", a.url, None)):
        for value in values:
            location, page, body = attempt(base, a.realm, a.client, a.redirect, ctx, value, host)
            signed_in = "code=" in location
            confirm_as_victim = page.startswith("login-login-x509-info") and ("1234567890" in body or "doe.john" in body)
            ok = not signed_in and not confirm_as_victim
            failures += not ok
            print("%s  forged ssl-client-cert %-22s -> %s" % ("PASS" if ok else "FAIL", label, location or page))
    if a.control_key:
        cctx = ssl.create_default_context(cafile=a.cacert)
        cctx.load_cert_chain(a.forged_cert, a.control_key)
        location, page, body = attempt(a.url, a.realm, a.client, a.redirect, cctx, "", None)
        seen = page.startswith("login-login-x509-info") and ("1234567890" in body or "doe.john" in body)
        failures += not seen
        print("%s  control: the real card in the handshake reaches the X.509 confirmation -> %s"
              % ("PASS" if seen else "FAIL", page))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

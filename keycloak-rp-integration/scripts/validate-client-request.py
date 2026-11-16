#!/usr/bin/env python3
"""Validate a relying-party client request (client-request.json) before it goes to the IdP operator.

Applies the rules the operator side enforces for an OIDC confidential client on the ASD STIG-hardened Keycloak
(keycloak-asd-stig/references/profile.md, clients[]), and some it only warns about, so a request either passes
here and registers cleanly or is fixed by the app team first:

  - every URL host is a DNS name. IP literals are refused in every URL field, in every request, in every
    spelling a client or resolver may accept: dotted (192.0.2.1), short (127.1), decimal (2130706433),
    hex (0x7f000001), octal (0177.0.0.1), bracketed IPv6 including IPv4-mapped ([::ffff:127.0.0.1])
  - https only, with one separate exception: a request marked "dev_request": true may use the host name
    `localhost` (http or https). That allowance is by name only; 127.0.0.1 and [::1] are IP literals
  - exact URIs: no wildcard ('*'), no Keycloak shorthand ('+', '-'), no fragment, no user:password@
  - client-jwt needs jwks_url; client-secret must not send one; no secret, key or password in the file, ever
  - role names: lowercase, start with a letter, [a-z0-9] runs separated by - _ or . , <= 64 chars, not a
    Keycloak built-in role name
  - unknown keys are errors (the operator side would silently ignore them)

Stdlib only. Exit status: 0 valid (warnings allowed), 1 invalid (or warnings with --strict), 2 usage error.

  validate-client-request.py client-request.json
  validate-client-request.py client-request.json --emit-client clients.d/myapp.json   # operator client file
  validate-client-request.py client-request.json --emit-client -                      # ... to stdout
"""
import argparse
import json
import re
import sys
from urllib.parse import urlsplit

# Request field -> same-named key in the operator's client file (profile.md clients[]). 1:1, no renames.
CLIENT_FIELDS = ("client_id", "name", "root_url", "redirect_uris", "post_logout_redirect_uris",
                 "backchannel_logout_url", "web_origins", "auth", "jwks_url", "roles", "privileged")
META_FIELDS = ("$schema", "contact", "dev_request", "notes")
REQUIRED = ("client_id", "root_url", "redirect_uris", "post_logout_redirect_uris", "backchannel_logout_url",
            "auth", "roles", "contact")
CONTACT_FIELDS = {"name", "email", "organization", "phone"}

CLIENT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}[a-z0-9]$")
ROLE_RE = re.compile(r"^[a-z][a-z0-9]*([-_.][a-z0-9]+)*$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Keycloak's own role names (realm defaults, realm-management, account). As app roles they confuse every reviewer
# and any code that checks a role name without its client.
RESERVED_ROLES = {"offline_access", "uma_authorization", "uma_protection", "realm-admin", "create-client",
                  "impersonation", "read-token", "delete-account", "manage-account", "manage-account-links",
                  "manage-consent", "view-profile", "view-consent", "view-groups", "view-applications"}
SECRET_HINT = re.compile(r"secret|password|passwd|private|credential|token|_key$|^key$", re.I)
PLACEHOLDER_HOSTS = re.compile(r"(^|\.)example\.(com|org|net|mil|gov)$|^example$", re.I)
MAX_URL = 2048


class Result:
    def __init__(self):
        self.errors, self.warnings = [], []

    def err(self, field, msg):
        self.errors.append("%s: %s" % (field, msg))

    def warn(self, field, msg):
        self.warnings.append("%s: %s" % (field, msg))


# A DNS name: letters, digits and hyphens in dot-separated labels (punycode for IDNs), optional trailing dot.
DNS_NAME_RE = re.compile(r"^(?=.{1,253}\.?$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$",
                         re.I)
NUMERIC_LABEL_RE = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$", re.I)
DEV_HOST = "localhost"   # the one non-public host name a dev request may use


def raw_host(netloc):
    """The host exactly as written in the URL (urlsplit's .hostname strips brackets and lowercases)."""
    hostport = netloc.rpartition("@")[2]
    if hostport.startswith("["):
        return hostport[:hostport.find("]") + 1] if "]" in hostport else hostport
    return hostport.split(":", 1)[0]


def host_problem(host):
    """None for a DNS name; otherwise why the host is refused. Follows the WHATWG URL rule that a host whose last
    label is numeric (decimal or 0x-hex) is an IPv4 address, which is how 127.1, 2130706433, 0x7f000001 and
    0177.0.0.1 all reach 127.0.0.1 in browsers and HTTP clients."""
    if not host:
        return "has no host"
    if host.startswith("[") or ":" in host:
        return "uses an IPv6 literal"
    if not DNS_NAME_RE.match(host):
        return "is not a DNS name (letters, digits, hyphens and dots only; use punycode for IDNs)"
    labels = host.rstrip(".").lower().split(".")
    if NUMERIC_LABEL_RE.match(labels[-1]):
        return "is an IPv4 address in one of its spellings"
    if labels[-1] == DEV_HOST and len(labels) > 1:
        return "is under .localhost, which resolves to loopback"
    return None


def check_url(r, field, url, dev, origin_only=False):
    """Return the parsed URL, or None after recording why it is unacceptable."""
    if not isinstance(url, str) or not url:
        r.err(field, "must be a non-empty string")
        return None
    if len(url) > MAX_URL:
        r.err(field, "longer than %d characters" % MAX_URL)
        return None
    if any(c.isspace() for c in url):
        r.err(field, "contains whitespace: %r" % url)
        return None
    if url in ("+", "-") or "*" in url:
        r.err(field, "%r: wildcards and Keycloak shorthands ('*', '+', '-') are not allowed - list exact URIs" % url)
        return None
    try:
        u = urlsplit(url)
        port = u.port  # raises on a malformed port
    except ValueError as e:
        r.err(field, "%r is not a valid URL (%s)" % (url, e))
        return None
    if u.scheme not in ("https", "http") or not u.hostname:
        r.err(field, "%r must be an absolute https:// URL" % url)
        return None
    if u.username is not None or u.password is not None:
        r.err(field, "%r must not carry user:password@" % url)
        return None
    if u.fragment or url.endswith("#"):
        r.err(field, "%r must not contain a fragment (#...)" % url)
        return None
    host = raw_host(u.netloc)
    why = host_problem(host)
    if why:
        r.err(field, "%r: host %r %s - IP literals are refused in every URL; use the DNS name the certificate is "
                     "issued for" % (url, host, why))
        return None
    is_dev_host = host.lower().rstrip(".") == DEV_HOST
    # The dev allowance, kept separate from the rules above: the name `localhost`, only with "dev_request": true.
    if is_dev_host and not dev:
        r.err(field, "%r points at localhost - allowed only in a request with \"dev_request\": true" % url)
        return None
    if u.scheme == "http" and not is_dev_host:
        r.err(field, "%r must use https (http only for localhost in a dev request)" % url)
        return None
    if origin_only and (u.path not in ("", "/") or u.query):
        r.err(field, "%r must be an origin (scheme://host[:port]) with no path or query" % url)
        return None
    if u.query and not origin_only:
        r.warn(field, "%r has a query string; Keycloak matches it exactly, so every variant must be listed" % url)
    del port
    return u


def origin(u):
    return (u.scheme, (u.hostname or "").lower(), u.port or (443 if u.scheme == "https" else 80))


def validate(req):
    r = Result()
    if not isinstance(req, dict):
        r.err("(file)", "the request must be a JSON object")
        return r
    for k in req:
        if k in CLIENT_FIELDS or k in META_FIELDS:
            continue
        if SECRET_HINT.search(k):
            r.err(k, "never put secrets, keys or passwords in the request; the operator sends a client secret "
                     "out of band, and a client-jwt private key never leaves the app")
        else:
            r.err(k, "unknown field (allowed: %s)" % ", ".join(CLIENT_FIELDS + META_FIELDS[1:]))
    for k in REQUIRED:
        if k not in req:
            r.err(k, "required")

    dev = req.get("dev_request", False)
    if not isinstance(dev, bool):
        r.err("dev_request", "must be true or false")
        dev = False
    if dev:
        r.warn("dev_request", "development request: the operator registers it in a non-production realm only")

    cid = req.get("client_id")
    if cid is not None and (not isinstance(cid, str) or not CLIENT_ID_RE.match(cid)):
        r.err("client_id", "%r: use 3-64 lowercase letters, digits and hyphens, starting with a letter" % (cid,))

    if "name" in req and (not isinstance(req["name"], str) or not req["name"].strip() or len(req["name"]) > 100):
        r.err("name", "must be a non-empty string of at most 100 characters")

    root = check_url(r, "root_url", req["root_url"], dev) if "root_url" in req else None
    if root is not None and root.query:
        r.err("root_url", "must not have a query string")
    if root is not None and PLACEHOLDER_HOSTS.search(root.hostname or ""):
        r.warn("root_url", "%s is a placeholder domain - replace it with the app's real host" % root.hostname)

    parsed = {}
    for field in ("redirect_uris", "post_logout_redirect_uris"):
        if field not in req:
            continue
        v = req[field]
        if not isinstance(v, list) or not v:
            r.err(field, "must be a non-empty list of exact URIs")
            continue
        if len(v) > 10:
            r.err(field, "at most 10 entries")
        if len(set(map(str, v))) != len(v):
            r.err(field, "contains duplicates")
        parsed[field] = [u for u in (check_url(r, "%s[%d]" % (field, i), x, dev) for i, x in enumerate(v)) if u]

    if "backchannel_logout_url" in req:
        bc = check_url(r, "backchannel_logout_url", req["backchannel_logout_url"], dev)
        if bc is not None:
            parsed["backchannel_logout_url"] = [bc]
            if req["backchannel_logout_url"] in (req.get("redirect_uris") or []):
                r.err("backchannel_logout_url", "must be its own endpoint, not a redirect URI")

    if "web_origins" in req:
        v = req["web_origins"]
        if not isinstance(v, list):
            r.err("web_origins", "must be a list of origins")
        else:
            if len(set(map(str, v))) != len(v):
                r.err("web_origins", "contains duplicates")
            for i, x in enumerate(v):
                check_url(r, "web_origins[%d]" % i, x, dev, origin_only=True)

    auth = req.get("auth")
    if "auth" in req and auth not in ("client-jwt", "client-secret"):
        r.err("auth", "%r: use client-jwt (preferred, with jwks_url) or client-secret" % (auth,))
    if auth == "client-jwt":
        if "jwks_url" not in req:
            r.err("jwks_url", "required with auth client-jwt (where Keycloak fetches the app's public keys)")
        else:
            j = check_url(r, "jwks_url", req["jwks_url"], dev)
            if j is not None:
                parsed["jwks_url"] = [j]
    elif auth == "client-secret":
        r.warn("auth", "client-secret is a shared secret the operator must deliver out of band; "
                       "client-jwt (private_key_jwt) is preferred")
        if "jwks_url" in req:
            r.err("jwks_url", "only valid with auth client-jwt")

    roles = req.get("roles")
    if "roles" in req:
        if not isinstance(roles, list) or not roles:
            r.err("roles", "must be a non-empty list of role names")
        else:
            if len(roles) > 20:
                r.err("roles", "at most 20 roles")
            if len(set(map(str, roles))) != len(roles):
                r.err("roles", "contains duplicates")
            for i, role in enumerate(roles):
                if not isinstance(role, str) or len(role) > 64 or not ROLE_RE.match(role):
                    r.err("roles[%d]" % i, "%r: lowercase, start with a letter, letters/digits joined by single "
                                           "'-', '_' or '.', at most 64 characters (e.g. viewer, report-approver)"
                          % (role,))
                elif role in RESERVED_ROLES:
                    r.err("roles[%d]" % i, "%r is a Keycloak built-in role name - choose an app-specific name" % role)

    if "privileged" in req and not isinstance(req["privileged"], bool):
        r.err("privileged", "must be true or false")

    c = req.get("contact")
    if "contact" in req:
        if not isinstance(c, dict):
            r.err("contact", "must be an object with name and email")
        else:
            for k in set(c) - CONTACT_FIELDS:
                r.err("contact.%s" % k, "unknown field (allowed: %s)" % ", ".join(sorted(CONTACT_FIELDS)))
            for k in ("name", "email"):
                if not isinstance(c.get(k), str) or not c.get(k, "").strip():
                    r.err("contact.%s" % k, "required")
            if isinstance(c.get("email"), str) and c["email"] and not EMAIL_RE.match(c["email"]):
                r.err("contact.email", "%r is not an email address" % c["email"])

    if "notes" in req and (not isinstance(req["notes"], str) or len(req["notes"]) > 1000):
        r.err("notes", "must be a string of at most 1000 characters")

    # Every browser-facing URL should live on the app's own origin; a mismatch is usually a copy-paste slip.
    if root is not None:
        for field in ("redirect_uris", "post_logout_redirect_uris", "backchannel_logout_url"):
            for u in parsed.get(field, []):
                if origin(u) != origin(root):
                    r.warn(field, "%s://%s is not the root_url's origin - confirm this is intended"
                           % (u.scheme, u.netloc))
    return r


def to_client(req):
    """The operator's client file for this request: same keys, plus the fixed client type."""
    c = {"client_id": req["client_id"], "type": "oidc-confidential"}
    for k in CLIENT_FIELDS[1:]:
        if k in req:
            c[k] = req[k]
    return c


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("request", help="client-request.json")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    ap.add_argument("--emit-client", metavar="PATH", help="write the operator client file ('-' for stdout) if valid")
    ap.add_argument("--quiet", action="store_true", help="print only problems")
    a = ap.parse_args(argv)
    try:
        with open(a.request) as f:
            req = json.load(f)
    except (OSError, ValueError) as e:
        print("ERROR (file): cannot read %s: %s" % (a.request, e), file=sys.stderr)
        return 1
    r = validate(req)
    for e in r.errors:
        print("ERROR " + e, file=sys.stderr)
    for w in r.warnings:
        print("WARNING " + w, file=sys.stderr)
    bad = bool(r.errors) or (a.strict and bool(r.warnings))
    if bad:
        print("%s: INVALID (%d error(s), %d warning(s))" % (a.request, len(r.errors), len(r.warnings)), file=sys.stderr)
        return 1
    if a.emit_client:
        out = json.dumps(to_client(req), indent=2) + "\n"
        if a.emit_client == "-":
            sys.stdout.write(out)
        else:
            with open(a.emit_client, "w") as f:
                f.write(out)
    if not a.quiet:
        print("%s: valid (%d warning(s))" % (a.request, len(r.warnings)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

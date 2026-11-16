#!/usr/bin/env python3
"""cac-config - turns the container's environment into a kcstig profile, and small runtime helpers.

  cac-config.py profile <out.json>        render the profile from CAC_* env (see README "Environment")
  cac-config.py wait-ready <seconds>      wait for Keycloak's readiness endpoint on the management port
  cac-config.py clear-crl-cache           make every node drop its cached CRLs (after a refresh on disk)
  cac-config.py sync-crl-list             online mode: point the X.509 authenticators at the CRLs actually installed
  cac-config.py lab-users <pki-dir>       print users/admins JSON for the generated mock CACs (lab mode)
"""
import glob, json, os, re, ssl, subprocess, sys, time, urllib.request

sys.path.insert(0, "/opt/kcstig/scripts")
PKI = os.environ.get("CAC_PKI_DIR", "/opt/keycloak/data/cac")

def env(k, default=None, aliases=()):
    for n in (k,) + tuple(aliases):
        if os.environ.get(n) not in (None, ""):
            return os.environ[n]
        if os.environ.get(n + "_FILE"):
            return open(os.environ[n + "_FILE"]).read().strip()
    return default

def flag(k, default=False):
    return str(env(k, str(default))).lower() in ("1", "true", "yes", "on")

def die(msg):
    print("cac-config: ERROR " + msg, file=sys.stderr); sys.exit(2)

# Which certificate field identifies the person. SERIALNUMBER is deliberately not offered: the serial number
# changes every time a card is reissued, so it identifies a certificate, not a user.
USERNAME_SOURCES = {
    "upn":        ("Subject's Alternative Name otherName (UPN)", "(.*?)(?:$)", "cac_upn"),
    "edipi":      ("Match SubjectDN using regular expression", r"CN=[^,]*\.([0-9]{10})(?:,|$)", "cac_edipi"),
    "cn":         ("Subject's Common Name", "(.*?)(?:$)", "cac_cn"),
    "subject-dn": ("Match SubjectDN using regular expression", "(.*?)(?:$)", "cac_subject_dn"),
}
ALIASES = {"subjectaltname.othername": "upn", "san.upn": "upn", "othername": "upn", "principalname": "upn",
           "edipi": "edipi", "dodid": "edipi", "cn": "cn", "commonname": "cn", "subjectdn": "subject-dn", "dn": "subject-dn"}

def username_source():
    raw = env("CAC_USERNAME_SOURCE", aliases=("CAC_USERNAME_ATTRIBUTE",)) or "upn"
    k = raw.strip().lower()
    if k in ("serialnumber", "serial", "certificate serial number"):
        die("CAC_USERNAME_SOURCE=%s is not allowed: a certificate serial number changes on every card reissue. "
            "Use upn (default), edipi, cn or subject-dn." % raw)
    k = ALIASES.get(k.replace("_", "").replace(" ", ""), k)
    if k not in USERNAME_SOURCES:
        die("CAC_USERNAME_SOURCE must be upn | edipi | cn | subject-dn (got %r)" % raw)
    return k

def crl_mode():
    m = (env("CRL_MODE", "online") or "online").strip().lower()
    m = {"offline": "file", "local": "file", "disabled": "none", "off": "none"}.get(m, m)
    if m not in ("online", "file", "ocsp", "none"):
        die("CRL_MODE must be online | file (OFFLINE) | ocsp | none (got %r)" % m)
    if m == "none" and not flag("CAC_LAB_MODE"):
        die("CRL_MODE=none disables revocation checking (V-222550 CAT I path validation with status, V-222553 local revocation cache). It is only accepted with CAC_LAB_MODE=true.")
    return m

def json_items(var_json, var_dir):
    """A JSON list (or object) in an env var, plus every *.json file in a directory."""
    out = []
    raw = env(var_json)
    if raw:
        obj = json.loads(raw); out += obj if isinstance(obj, list) else [obj]
    d = env(var_dir)
    if d and os.path.isdir(d):
        for f in sorted(glob.glob(os.path.join(d, "*.json"))):
            obj = json.load(open(f)); out += obj if isinstance(obj, list) else [obj]
    return out

def pairs(var, attr):
    """CAC_USERS=doe.john=1234567890@mil,roe.jane=2345678901@mil  ->  [{username, <attr>: value}]"""
    out = []
    for item in filter(None, (x.strip() for x in (env(var) or "").split(","))):
        if "=" not in item:
            die("%s entries must be username=value (got %r)" % (var, item))
        u, v = item.split("=", 1); u = u.strip()
        if not re.fullmatch(r"[A-Za-z0-9._@-]{3,255}", u):
            die("%s: username %r must be 3-255 characters (letters, digits, . _ @ -)" % (var, u))
        out.append({"username": u, attr: v.strip()})
    return out

def installed_crl_files():
    return ["cac/crl/" + os.path.basename(f) for f in sorted(glob.glob(os.path.join(PKI, "crl", "*.crl")))]

X509_FORMS = ("stig-x509-client-username-form", "auth-x509-client-username-form")

def sync_crl_list():
    """Set crl-relative-path of every X.509 authenticator (user realm and master) to the CRLs installed now."""
    import kcstig
    pf = os.path.join(PKI, "profile.json")
    p = json.load(open(pf))
    if not p["x509"].get("crl"):
        return
    want = installed_crl_files() or ["cac/crl/none.crl"]
    joined = "##".join(want)
    kc = kcstig.KC(p["keycloak"]["url"], "master"); kc.login()
    changed = 0
    for realm in dict.fromkeys([p["realm"]["name"], p["keycloak"].get("admin_realm", "master")]):
        q = kcstig.q(realm)
        for fl in kc.api("GET", "/realms/%s/authentication/flows" % q) or []:
            for e in kc.api("GET", "/realms/%s/authentication/flows/%s/executions" % (q, kcstig.q(fl["alias"]))) or []:
                if e.get("providerId") not in X509_FORMS or not e.get("authenticationConfig"):
                    continue
                c = kc.api("GET", "/realms/%s/authentication/config/%s" % (q, e["authenticationConfig"]))
                if (c.get("config") or {}).get("x509-cert-auth.crl-relative-path") == joined:
                    continue
                c["config"]["x509-cert-auth.crl-relative-path"] = joined
                kc.api("PUT", "/realms/%s/authentication/config/%s" % (q, c["id"]), c)
                changed += 1
    p["x509"]["crl_files"] = want
    fd = os.open(pf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(p, f, indent=1)
    print("cac-config: CRL list %s (%d CRLs installed, %d authenticator configs updated)" % (
        "updated" if changed else "unchanged", len(want), changed), file=sys.stderr)

def read_lines(path):
    return [l.strip() for l in open(path)] if os.path.exists(path) else []

def build_profile():
    src = username_source(); mode = crl_mode()
    source, regex, attr = USERNAME_SOURCES[src]
    rel = (env("KC_HTTP_RELATIVE_PATH", "/") or "/").rstrip("/")
    ocsp_default = mode in ("online", "ocsp")
    ocsp = flag("CAC_OCSP", ocsp_default) and mode != "none"
    crl_files = []
    if mode == "online":
        # Only CRLs actually installed (verified against the anchors). The downloads run after Keycloak starts, so
        # sync-crl-list re-points the authenticators after every refresh. A CA whose CRL is missing is a coverage gap
        # (crl-coverage, kcstig pki.crl_coverage) and its cards are refused; the others keep signing in.
        crl_files = installed_crl_files()
    elif mode == "file":
        crl_files = installed_crl_files()
        if not crl_files:
            die("CRL_MODE=file but no CRL in %s verified against the trust anchors (mount them at CAC_CRL_DIR)" % env("CAC_CRL_DIR", "/crl"))
    realm = env("CAC_REALM", "dod-cac", aliases=("KC_REALM_NAME",))
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", realm):
        die("CAC_REALM must be 1-64 letters, digits, . _ -")
    users = pairs("CAC_USERS", attr) + json_items("CAC_USERS_JSON", "CAC_USERS_DIR")
    admins = pairs("CAC_ADMINS", "alt_token_upn") + json_items("CAC_ADMINS_JSON", "CAC_ADMINS_DIR")
    if flag("CAC_LAB_MODE") and flag("CAC_LAB_USERS", True) and os.path.isdir(os.path.join(PKI, "lab")):
        lu, la = lab_users(os.path.join(PKI, "lab"), src, attr)
        users += lu; admins += la
    lockout = (env("CAC_LOCKOUT", "permanent") or "permanent").lower()
    if lockout not in ("permanent", "temporary"):
        die("CAC_LOCKOUT must be permanent | temporary (got %r)" % lockout)
    p = {
        "lockout": {"permanent": lockout == "permanent"},
        "keycloak": {"url": "https://127.0.0.1:%s%s" % (env("KC_HTTPS_PORT", "8443"), rel), "admin_realm": "master"},
        "realm": {"name": realm, "display_name": env("CAC_REALM_DISPLAY_NAME", realm)},
        "auth_mode": env("CAC_AUTH_MODE", "cac"),
        "mfa": env("CAC_MFA", "otp"),
        "x509": {
            "mapping_attribute": attr, "mapping_source": source, "regex": regex,
            "ocsp": ocsp, "ocsp_responder_uri": env("CAC_OCSP_RESPONDER_URI", ""),
            "ocsp_fail_open": flag("CAC_OCSP_FAIL_OPEN", True),
            "crl": mode in ("online", "file"), "crl_files": crl_files or ["cac/crl/none.crl"],
            "ca_subject_dns": [l for l in read_lines(os.path.join(PKI, "ca-subject-dns.txt")) if l],
            "certificate_policies": [x for x in (env("CAC_CERT_POLICIES", "") or "").split(",") if x],
            "extended_key_usage": env("CAC_EXTENDED_KEY_USAGE", ""),
        },
        "users": users,
        "admin": {"users": admins, "mfa": env("CAC_ADMIN_MFA", "x509"),
                  "automation_client": "stig-automation"},
    }
    # Everything else (timeouts, lockout, password rules, banner, clients...) keeps the STIG defaults, and can be
    # overridden as a JSON overlay: CAC_PROFILE_JSON='{"sessions":{"max_hours":10}}' or CAC_PROFILE_FILE=/path.json
    from kcstig import deep_merge
    for overlay in (open(env("CAC_PROFILE_FILE")).read() if env("CAC_PROFILE_FILE") else None, env("CAC_PROFILE_JSON")):
        if overlay:
            p = deep_merge(p, json.loads(overlay))
    # Clients: CAC_CLIENTS_JSON here; CAC_CLIENTS_DIR (one *.json per app) is read by kcstig via STIG_CLIENTS_DIR.
    p["clients"] = p.get("clients", []) + json_items("CAC_CLIENTS_JSON", "")
    return p

def lab_users(labdir, src, attr):
    """The mock CACs from make_test_pki.sh, mapped the same way real cards would be."""
    users, admins = [], []
    for crt in sorted(glob.glob(os.path.join(labdir, "users", "*.crt"))):
        name = os.path.basename(crt)[:-4]
        if name in ("unmapped", "rogue.doe"):
            continue  # must stay unknown: the tests expect them to be refused
        dn = subprocess.run(["openssl", "x509", "-in", crt, "-noout", "-subject", "-nameopt", "RFC2253"],
                            capture_output=True, text=True).stdout.strip().replace("subject=", "")
        san = subprocess.run(["openssl", "x509", "-in", crt, "-noout", "-ext", "subjectAltName"],
                             capture_output=True, text=True).stdout
        upn = (re.search(r"UPN:([^,\s]+)|othername:\s*UPN::?([^,\s]+)|1\.3\.6\.1\.4\.1\.311\.20\.2\.3::?([^,\s]+)", san, re.I) or [None])
        upn = next((g for g in upn.groups() if g), None) if upn else None
        cn = re.search(r"CN=([^,]+)", dn).group(1)
        edipi = (re.search(r"\.([0-9]{10})$", cn) or [None, None])[1]
        if name == "admin.alt":
            admins.append({"username": "lab.admin", "email": "lab.admin@example.mil", "firstName": "Lab",
                           "lastName": "Admin", "alt_token_upn": upn})
            continue
        val = {"upn": upn, "edipi": edipi, "cn": cn, "subject-dn": dn}[src]
        users.append({"username": name, "email": name + "@example.mil", "firstName": name.split(".")[-1].title(),
                      "lastName": name.split(".")[0].title(), attr: val})
    return users, admins

def wait_ready(seconds):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE  # loopback only
    rel = (env("KC_HTTP_MANAGEMENT_RELATIVE_PATH", "") or (env("KC_HTTP_RELATIVE_PATH", "/") or "/")).rstrip("/")
    url = "https://127.0.0.1:%s%s/health/ready" % (env("KC_HTTP_MANAGEMENT_PORT", "9000"), rel)
    end = time.time() + seconds
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, context=ctx, timeout=5) as r:
                if r.status == 200:
                    return 0
        except Exception:
            pass
        time.sleep(3)
    die("Keycloak not ready after %ss (%s)" % (seconds, url))

def clear_crl_cache():
    import kcstig
    p = json.load(open(os.path.join(PKI, "profile.json")))
    kc = kcstig.KC(p["keycloak"]["url"], "master"); kc.login()
    kc.api("POST", "/realms/%s/clear-crl-cache" % kcstig.q(p["realm"]["name"]))
    print("cac-config: CRL cache cleared (all nodes)", file=sys.stderr)

if __name__ == "__main__":
    c = sys.argv[1] if len(sys.argv) > 1 else ""
    if c == "profile":
        prof = build_profile()
        fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(prof, f, indent=1)
        x = prof["x509"]
        print("cac-config: realm=%s auth=%s username<-%s crl=%s(%d files) ocsp=%s users=%d admins=%d clients=%d" % (
            prof["realm"]["name"], prof["auth_mode"], username_source(), crl_mode(), len(x["crl_files"]) if x["crl"] else 0,
            x["ocsp"], len(prof["users"]), len(prof["admin"]["users"]),
            len(prof.get("clients", [])) + len(glob.glob(os.path.join(env("CAC_CLIENTS_DIR", "/nonexistent"), "*.json")))), file=sys.stderr)
    elif c == "wait-ready":
        wait_ready(int(sys.argv[2]) if len(sys.argv) > 2 else 300)
    elif c == "clear-crl-cache":
        clear_crl_cache()
    elif c == "sync-crl-list":
        sync_crl_list()
    elif c == "check":
        username_source(); crl_mode()
    else:
        print(__doc__); sys.exit(2)

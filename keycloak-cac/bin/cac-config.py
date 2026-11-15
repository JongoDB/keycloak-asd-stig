#!/usr/bin/env python3
"""cac-config - turns the container's environment into a kcstig profile, and small runtime helpers.

  cac-config.py profile <out.json>        render the profile from CAC_* env (see README "Environment")
  cac-config.py extra-profiles <out-dir>  render one profile per extra realm (CAC_EXTRA_REALM_PROFILES); prints
                                          "<realm> <profile> <clients-dir>" per realm, in apply order
  cac-config.py wait-ready <seconds>      wait for Keycloak's readiness endpoint on the management port
  cac-config.py clear-crl-cache           make every node drop its cached CRLs (after a refresh on disk)
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
        die("CRL_MODE=none disables revocation checking (V-222551/V-222553, CAT I). It is only accepted with CAC_LAB_MODE=true.")
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
        crl_files = ["cac/crl/" + n for n in read_lines(os.path.join(PKI, "crl-names.txt")) if n]
        # plus CRLs already installed and verified (e.g. the lab CA's next to the DoD ones)
        crl_files += ["cac/crl/" + os.path.basename(f) for f in sorted(glob.glob(os.path.join(PKI, "crl", "*.crl")))
                      if "cac/crl/" + os.path.basename(f) not in crl_files]
    elif mode == "file":
        crl_files = ["cac/crl/" + os.path.basename(f) for f in sorted(glob.glob(os.path.join(PKI, "crl", "*.crl")))]
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

# Keys an extra realm's profile may not set: the server, the admin realm and its administrators belong to the main
# profile (only its apply hardens master), and the realm's clients come from its own clients directory.
EXTRA_FORBIDDEN = ("keycloak", "admin")

def extra_profiles(main):
    """CAC_EXTRA_REALM_PROFILES: a directory of kcstig profiles, one per additional realm, applied after the main realm
    on every start (so a restart re-hardens every realm). Each is merged over the main profile - an extra CAC realm
    inherits the PKI, CRL and lockout settings - without the main realm's users and clients. Its clients come from
    <CAC_CLIENTS_DIR>/<realm>/*.json only (never the main realm's), its users from its own profile."""
    from kcstig import deep_merge
    d = env("CAC_EXTRA_REALM_PROFILES")
    if not d:
        return []
    if not os.path.isdir(d):
        die("CAC_EXTRA_REALM_PROFILES=%s is not a directory" % d)
    # inherited: server, PKI/CRL, sessions, lockout, password, banner, events...; NOT the realm's own choices
    base = {k: v for k, v in main.items() if k not in ("users", "clients", "realm", "registration_flow", "webauthn")}
    base["admin"] = dict(main["admin"], users=[])          # an extra realm's apply never touches the admin realm
    seen, out = {main["realm"]["name"], "master"}, []
    for f in sorted(glob.glob(os.path.join(d, "*.json"))):
        try:
            raw = json.load(open(f))
        except (OSError, ValueError) as e:
            die("%s: not a JSON profile (%s)" % (f, e))
        if not isinstance(raw, dict):
            die("%s: a profile is one JSON object" % f)
        bad = [k for k in EXTRA_FORBIDDEN if k in raw]
        if bad:
            die("%s: %s may only be set by the main realm's profile" % (f, ", ".join(bad)))
        name = ((raw.get("realm") or {}).get("name") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name):
            die("%s: realm.name must be 1-64 letters, digits, . _ -" % f)
        if name.lower() in {x.lower() for x in seen}:
            die("%s: realm %s is the main realm, master, or already defined by another profile" % (f, name))
        seen.add(name)
        p = deep_merge(base, raw)
        p.setdefault("users", raw.get("users", []))
        p["clients"] = list(raw.get("clients", []))
        cdir = os.path.join(env("CAC_CLIENTS_DIR", "") or "/nonexistent", name)
        out.append((name, p, cdir))
    return out

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
    elif c == "extra-profiles":
        os.makedirs(sys.argv[2], mode=0o700, exist_ok=True)
        main = json.load(open(os.path.join(PKI, "profile.json"))) if len(sys.argv) < 4 else json.load(open(sys.argv[3]))
        sys.path.insert(0, "/opt/kcstig/scripts")
        import kcstig
        for name, prof, cdir in extra_profiles(main):
            path = os.path.join(sys.argv[2], "%s.json" % name)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(prof, f, indent=1)
            try:   # fail fast: the profile must load (auth mode, WebAuthn names, STIG limits) before Keycloak starts
                kcstig.load_profile(path, cdir if os.path.isdir(cdir) else "/nonexistent")
            except SystemExit as e:
                die("extra realm %s: %s" % (name, e))
            print("%s %s %s" % (name, path, cdir))
            print("cac-config: extra realm=%s auth=%s clients=%s" % (name, prof["auth_mode"], cdir if os.path.isdir(cdir) else "none"),
                  file=sys.stderr)
    elif c == "wait-ready":
        wait_ready(int(sys.argv[2]) if len(sys.argv) > 2 else 300)
    elif c == "clear-crl-cache":
        clear_crl_cache()
    elif c == "check":
        username_source(); crl_mode()
    else:
        print(__doc__); sys.exit(2)

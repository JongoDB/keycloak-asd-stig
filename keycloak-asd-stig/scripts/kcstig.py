#!/usr/bin/env python3
"""kcstig - provision and verify Keycloak against the DISA ASD STIG (V6R4).

Standard library only (Python 3.9+).

  kcstig.py render  --profile p.json [--out build/]          # write the planned realm config for review/GitOps
  kcstig.py apply   --profile p.json [--harden-master] ...    # push config to a running Keycloak (idempotent)
  kcstig.py verify  --profile p.json [--out reports/]         # check live config -> report.md, results.json, .ckl, .cklb
  kcstig.py lookup  V-222432 | --grep "session"               # show STIG text + how this skill handles it
  kcstig.py inherit --profile p.json [--out reports/]         # control-inheritance statement for a relying application
  kcstig.py add-client request.json --profile p.json --clients-dir clients.d [--adopt ID] [--secret-out FILE]
                                                              # register one app from its client-request.json

Admin credentials come from the environment, never the profile:
  KC_CLIENT_ID + KC_CLIENT_SECRET   (service account, preferred; created by apply --harden-master)
  KC_ADMIN_USER + KC_ADMIN_PASSWORD (bootstrap admin; only usable before the admin realm is hardened)
  KC_CACERT                         (PEM bundle to trust the Keycloak TLS certificate)
"""
import argparse, copy, datetime, glob, json, os, re, socket, ssl, sys, time, urllib.error, urllib.parse, urllib.request, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
RULES_PATH = os.path.join(SKILL, "references", "asd-stig-v6r4.json")
MAP_PATH = os.path.join(SKILL, "references", "control-map.json")

# --------------------------------------------------------------------------------------------
# Profile
# --------------------------------------------------------------------------------------------
DEFAULTS = {
    "keycloak": {"url": "https://localhost:8443", "admin_realm": "master"},
    "realm": {"name": "app", "display_name": "Application"},
    "auth_mode": "cac_or_mfa",          # cac | cac_or_mfa | mfa
    "mfa": "otp",                       # second factor on the password path: otp | webauthn
    "x509": {
        "mapping_attribute": "cac_upn",
        "mapping_source": "Subject's Alternative Name otherName (UPN)",
        "regex": "(.*?)(?:$)",          # used by the "Match SubjectDN using regular expression" sources
        "ocsp": True, "ocsp_responder_uri": "", "ocsp_fail_open": True,
        "crl": True, "crl_files": ["crl.pem"], "crldp": False,
        "key_usage": "digitalSignature", "extended_key_usage": "",
        "certificate_policies": [], "certificate_policy_mode": "Any",
        "ca_subject_dns": [], "confirmation_page": True,
    },
    "sessions": {"user_idle_minutes": 15, "admin_idle_minutes": 10, "max_hours": 8,
                 "max_per_user": 3, "access_token_minutes": 5},
    # permanent=False: temporary lockout of window_minutes, growing by window_minutes per further max_failures
    # (MULTIPLE) up to max_wait_hours; the failure count resets reset_hours after the last failure.
    "lockout": {"max_failures": 3, "window_minutes": 15, "permanent": True, "max_wait_hours": 24, "reset_hours": 24},
    "password": {"min_length": 15, "max_length": 128, "history": 5, "max_age_days": 60, "min_age_hours": 24,
                 "hash": "pbkdf2-sha512", "iterations": 210000},
    "accounts": {"inactive_days": 35, "temp_hours": 72},
    "banner": {"theme": "dod-stig", "terms_required_action": True},
    "events": {"retention_days": 90, "listeners": ["jboss-logging", "stig-audit"]},
    "headers": {"hsts": "max-age=31536000; includeSubDomains"},
    "clients": [],
    "users": [],
    "admin": {"mfa": "x509", "mapping_attribute": "alt_token_upn", "users": [],
              "mapping_source": "Subject's Alternative Name otherName (UPN)", "regex": "(.*?)(?:$)",
              "automation_client": "stig-automation", "allow_emergency_password": False},
}

def deep_merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out

# (path, test, message) - values that would make the realm weaker than the STIG
STIG_LIMITS = [
    (("sessions", "user_idle_minutes"), lambda v: v <= 15, "V-222389 requires <= 15"),
    (("sessions", "admin_idle_minutes"), lambda v: v <= 10, "V-222390 requires <= 10"),
    (("sessions", "max_per_user"), lambda v: v > 0, "V-222387 needs a limit > 0"),
    (("lockout", "max_failures"), lambda v: v <= 3, "V-222432 requires <= 3"),
    (("lockout", "window_minutes"), lambda v: v >= 15, "V-222432 requires a >= 15 minute window"),
    (("password", "min_length"), lambda v: v >= 15, "V-222536 requires >= 15"),
    (("password", "history"), lambda v: v >= 5, "V-222546 requires >= 5"),
    (("password", "max_age_days"), lambda v: v <= 60, "V-222545 requires <= 60"),
    (("password", "min_age_hours"), lambda v: v >= 24, "V-222544 requires >= 24"),
    (("password", "hash"), lambda v: v.startswith("pbkdf2"), "argon2/bcrypt are not FIPS-approved (V-222542)"),
    (("accounts", "inactive_days"), lambda v: v <= 35, "V-222411 requires <= 35"),
    (("accounts", "temp_hours"), lambda v: v <= 72, "V-222409 requires <= 72"),
    (("x509", "crl"), lambda v: v is True, "V-222553 requires a local CRL cache"),
]
# Keycloak's built-in clients, and the per-realm admin clients of the master realm (<realm>-realm). No profile,
# clients.d file or client request may define one: doing so would overwrite part of the IdP itself.
# keycloak-rp-integration/scripts/validate-client-request.py refuses the same ids (a test keeps the lists equal).
RESERVED_CLIENT_IDS = {"account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"}
# add-client marks the clients it creates; it modifies no client without this marker (unless --adopt).
OWNER_ATTR, OWNER_VALUE = "stig.created-by", "add-client"

def reserved_client_id(cid):
    c = str(cid).strip().lower()
    return c in RESERVED_CLIENT_IDS or c.endswith("-realm")

CLIENT_KEYS = {"client_id", "type", "name", "root_url", "redirect_uris", "privileged", "post_logout_redirect_uris",
               "backchannel_logout_url", "web_origins", "auth", "jwks_url", "subject_dn", "service_account",
               "standard_flow", "par", "acs_url", "slo_url", "signing_cert", "encryption_cert", "roles",
               "owner", "owner_contact"}   # owner*: recorded by add-client, kept on the client as stig.owner*
USER_KEYS = {"username", "email", "firstName", "lastName", "temporary_password", "account_type", "client_roles"}

def check_profile(raw, p):
    """Warn about misspelled keys (they would silently fall back to defaults) and STIG-weakening values."""
    warn = []
    def walk(r, d, path):
        for k, v in r.items():
            if k not in d:
                warn.append("unknown key %s - ignored (see references/profile.md)" % ".".join(path + [k]))
            elif isinstance(v, dict) and isinstance(d[k], dict) and d[k]:
                walk(v, d[k], path + [k])
    walk(raw, DEFAULTS, [])
    for path, ok, msg in STIG_LIMITS:
        v = p[path[0]][path[1]]
        if not ok(v):
            warn.append("%s=%r is weaker than the STIG: %s" % (".".join(path), v, msg))
    for c in p["clients"]:
        for k in set(c) - CLIENT_KEYS:
            warn.append("clients[%s]: unknown key %s" % (c.get("client_id"), k))
        if c.get("type") == "saml" and not c.get("encryption_cert"):
            warn.append("clients[%s]: SAML without encryption_cert - add the SP certificate so encrypted assertions work" % c.get("client_id"))
    ua = {p["x509"]["mapping_attribute"]} | USER_KEYS
    for u in p["users"]:
        for k in set(u) - ua:
            warn.append("users[%s]: unknown key %s" % (u.get("username"), k))
    aa = {p["admin"]["mapping_attribute"]} | USER_KEYS
    for u in p["admin"]["users"]:
        for k in set(u) - aa:
            warn.append("admin.users[%s]: unknown key %s" % (u.get("username"), k))
    for w in warn:
        print("WARNING profile: " + w, file=sys.stderr)
    return warn

def load_profile(path, clients_dir=None):
    with open(path) as f:
        raw = json.load(f)
    # Per-service client registration: every *.json in the clients dir is one client object or a list of them.
    # Services ship these next to their own manifests; later files override earlier ones with the same client_id.
    clients_dir = clients_dir or os.environ.get("STIG_CLIENTS_DIR")
    if clients_dir:
        byid = {c["client_id"]: c for c in raw.get("clients", [])}
        for f in sorted(glob.glob(os.path.join(clients_dir, "*.json"))):
            obj = json.load(open(f))
            for c in (obj if isinstance(obj, list) else [obj]):
                byid[c["client_id"]] = c
        raw["clients"] = list(byid.values())
    for c in raw.get("clients", []):
        if reserved_client_id(c.get("client_id", "")):
            sys.exit("clients: %r is reserved for Keycloak's own clients (%s and any *-realm) - refusing to load a profile "
                     "or clients.d file that would overwrite it" % (c.get("client_id"), ", ".join(sorted(RESERVED_CLIENT_IDS))))
    p = deep_merge(DEFAULTS, raw)
    check_profile(raw, p)
    if p["auth_mode"] not in ("cac", "cac_or_mfa", "mfa"):
        sys.exit("auth_mode must be cac | cac_or_mfa | mfa")
    if p["mfa"] not in ("otp", "webauthn"):
        sys.exit("mfa must be otp | webauthn")
    if p["admin"]["mfa"] not in ("x509", "webauthn", "otp"):
        sys.exit("admin.mfa must be x509 | webauthn | otp")
    return p

# --------------------------------------------------------------------------------------------
# Rendering: everything Keycloak needs, as plain data
# --------------------------------------------------------------------------------------------
ALL_EVENT_TYPES_FALLBACK = ["LOGIN", "LOGIN_ERROR", "LOGOUT", "LOGOUT_ERROR", "CODE_TO_TOKEN", "CODE_TO_TOKEN_ERROR",
    "REFRESH_TOKEN", "REFRESH_TOKEN_ERROR", "INTROSPECT_TOKEN", "INTROSPECT_TOKEN_ERROR", "CLIENT_LOGIN", "CLIENT_LOGIN_ERROR",
    "UPDATE_PASSWORD", "UPDATE_PASSWORD_ERROR", "UPDATE_CREDENTIAL", "UPDATE_CREDENTIAL_ERROR", "REMOVE_CREDENTIAL",
    "REMOVE_CREDENTIAL_ERROR", "UPDATE_TOTP", "REMOVE_TOTP", "USER_DISABLED_BY_PERMANENT_LOCKOUT",
    "USER_DISABLED_BY_TEMPORARY_LOCKOUT", "CUSTOM_REQUIRED_ACTION", "CUSTOM_REQUIRED_ACTION_ERROR", "PERMISSION_TOKEN",
    "IDENTITY_PROVIDER_LOGIN", "IDENTITY_PROVIDER_LOGIN_ERROR", "TOKEN_EXCHANGE", "TOKEN_EXCHANGE_ERROR",
    "UPDATE_PROFILE", "UPDATE_PROFILE_ERROR", "RESET_PASSWORD", "RESET_PASSWORD_ERROR", "IMPERSONATE", "INVALID_SIGNATURE"]

def password_policy(p, extension):
    pw = p["password"]
    parts = ["length(%d)" % pw["min_length"], "maxLength(%d)" % pw["max_length"], "upperCase(1)", "lowerCase(1)",
             "digits(1)", "specialChars(1)", "notUsername", "notEmail", "passwordHistory(%d)" % pw["history"],
             "forceExpiredPasswordChange(%d)" % pw["max_age_days"], "hashAlgorithm(%s)" % pw["hash"],
             "hashIterations(%d)" % pw["iterations"]]
    if extension:
        parts.append("minimumPasswordAge(%d)" % pw["min_age_hours"])
    return " and ".join(parts)

def realm_settings(p, *, admin_realm=False, event_types=None, extension=True):
    s, lk = p["sessions"], p["lockout"]
    idle = (s["admin_idle_minutes"] if admin_realm else s["user_idle_minutes"]) * 60
    listeners = [l for l in p["events"]["listeners"] if extension or not l.startswith("stig-")]
    rep = {
        "enabled": True,
        "sslRequired": "all",
        "registrationAllowed": False, "resetPasswordAllowed": False, "rememberMe": False,
        "editUsernameAllowed": False, "loginWithEmailAllowed": False, "duplicateEmailsAllowed": False,
        "verifyEmail": False,
        # V-222432 / V-222433
        "bruteForceProtected": True, "permanentLockout": bool(lk["permanent"]), "maxTemporaryLockouts": 0,
        "bruteForceStrategy": "MULTIPLE", "failureFactor": lk["max_failures"],
        # permanent: failures counted over window_minutes. Temporary: a lock of window_minutes per max_failures
        # failures, growing (MULTIPLE) to max_wait_hours; failures are remembered for reset_hours, so a lock can grow.
        "maxDeltaTimeSeconds": lk["window_minutes"] * 60 if lk["permanent"] else max(lk["window_minutes"] * 60, int(lk.get("reset_hours", 24) * 3600)),
        "waitIncrementSeconds": lk["window_minutes"] * 60,
        "maxFailureWaitSeconds": lk["window_minutes"] * 60 if lk["permanent"] else max(lk["window_minutes"] * 60, int(lk.get("max_wait_hours", 24) * 3600)),
        "minimumQuickLoginWaitSeconds": 60, "quickLoginCheckMilliSeconds": 1000,
        # V-222389 / V-222390 / V-222520
        "ssoSessionIdleTimeout": idle, "ssoSessionMaxLifespan": s["max_hours"] * 3600,
        "ssoSessionIdleTimeoutRememberMe": 0, "ssoSessionMaxLifespanRememberMe": 0,
        "clientSessionIdleTimeout": 0, "clientSessionMaxLifespan": 0,
        "offlineSessionIdleTimeout": idle, "offlineSessionMaxLifespanEnabled": True,
        "offlineSessionMaxLifespan": s["max_hours"] * 3600,
        "accessTokenLifespan": s["access_token_minutes"] * 60,
        "accessTokenLifespanForImplicitFlow": s["access_token_minutes"] * 60,
        "accessCodeLifespan": 60, "accessCodeLifespanUserAction": 300, "accessCodeLifespanLogin": 900,
        "actionTokenGeneratedByAdminLifespan": 43200, "actionTokenGeneratedByUserLifespan": 300,
        "revokeRefreshToken": True, "refreshTokenMaxReuse": 0,
        # V-2225xx passwords (N/A when CAC-only but harmless and protects admin break-glass)
        "passwordPolicy": password_policy(p, extension),
        "otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA256", "otpPolicyDigits": 6,
        "otpPolicyPeriod": 30, "otpPolicyLookAheadWindow": 1, "otpPolicyCodeReusable": False,
        "webAuthnPolicyUserVerificationRequirement": "required",
        "webAuthnPolicyAuthenticatorAttachment": "cross-platform",
        "webAuthnPolicySignatureAlgorithms": ["ES256", "RS256"],
        "webAuthnPolicyRpEntityName": p["realm"]["display_name"],
        # audit
        "eventsEnabled": True, "eventsExpiration": p["events"]["retention_days"] * 86400,
        "eventsListeners": listeners,
        "enabledEventTypes": event_types or ALL_EVENT_TYPES_FALLBACK,
        "adminEventsEnabled": True, "adminEventsDetailsEnabled": True,
        # banner
        "loginTheme": p["banner"]["theme"],
        "internationalizationEnabled": False,
        "browserSecurityHeaders": {
            "contentSecurityPolicyReportOnly": "",
            "xContentTypeOptions": "nosniff",
            "referrerPolicy": "no-referrer",
            "xRobotsTag": "none",
            "xFrameOptions": "SAMEORIGIN",
            "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
            "strictTransportSecurity": p["headers"]["hsts"],
        },
        "defaultSignatureAlgorithm": "RS256",
    }
    if not admin_realm:
        rep["displayName"] = p["realm"]["display_name"]
    return rep

def x509_config(p, attr, admin_realm=False):
    x = p["x509"]
    # Alt Tokens identify admins by their own UPN, whatever the user realm maps on.
    src = p["admin"] if admin_realm else x
    cfg = {
        "x509-cert-auth.mapping-source-selection": src["mapping_source"],
        "x509-cert-auth.mapper-selection": "Custom Attribute Mapper",
        "x509-cert-auth.mapper-selection.user-attribute-name": attr,
        "x509-cert-auth.regular-expression": src["regex"],
        "x509-cert-auth.timestamp-validation-enabled": "true",
        "x509-cert-auth.crl-checking-enabled": str(bool(x["crl"])).lower(),
        "x509-cert-auth.crldp-checking-enabled": str(bool(x["crldp"])).lower(),
        "x509-cert-auth.crl-relative-path": "##".join(x["crl_files"]),
        "x509-cert-auth-crl-abort-if-non-updated": "true",
        "x509-cert-auth.ocsp-checking-enabled": str(bool(x["ocsp"])).lower(),
        # V-222553: Keycloak evaluates BOTH the local CRL cache and OCSP on every login. OCSP may fail
        # open (responder unreachable) only when the CRL check is on, so revocation is never skipped.
        # x509.ocsp_fail_open=false makes OCSP fail closed too (an unreachable responder refuses the sign-in).
        "x509-cert-auth.ocsp-fail-open": str(bool(x["ocsp"] and x["crl"] and x.get("ocsp_fail_open", True))).lower(),
        "x509-cert-auth.keyusage": x["key_usage"],
        "x509-cert-auth.extendedkeyusage": x["extended_key_usage"],
        "x509-cert-auth.confirmation-page-disallowed": str(not x["confirmation_page"]).lower(),
        "x509-cert-auth.canonical-dn-enabled": "false",
        "x509-cert-auth.serialnumber-hex-enabled": "false",
    }
    if x["ocsp_responder_uri"]:
        cfg["x509-cert-auth.ocsp-responder-uri"] = x["ocsp_responder_uri"]
    if x["certificate_policies"]:
        cfg["x509-cert-auth.certificate-policy"] = ",".join(x["certificate_policies"])
        cfg["x509-cert-auth.certificate-policy-mode"] = x["certificate_policy_mode"]
    if x["ca_subject_dns"]:
        cfg["x509-cert-auth.casubjectdn"] = "##".join(x["ca_subject_dns"])
    return cfg

ADMIN_GATE = "stig-admin-second-factor-required"     # stig-extensions.jar (post-broker; older browser flows)
# stig-extensions' drop-in replacements: the password form refuses an administrator without an enrolled second factor
# exactly as a wrong password (no oracle, no set-up after a password); the X.509 form is not refused by PASSWORD lockout
PW_FORMS = {"auth-username-password-form", "stig-username-password-form"}
X509_FORMS = {"auth-x509-client-username-form", "stig-x509-client-username-form"}
RESET_GATE = "stig-admin-reset-credentials-gate"
ALLOWLIST_GATE = "stig-admin-allowlist-gate"

def reset_flow(extension):
    """Reset credentials (only reachable when resetPasswordAllowed): no self-service reset for any administrator, and
    a held OTP is asked for after the e-mailed link (never reset by it, as Keycloak's own flow does)."""
    if not extension:
        return None
    return ("STIG Reset Credentials", [
        ("exec", "reset-credentials-choose-user", "REQUIRED", None),
        ("exec", RESET_GATE, "REQUIRED", None),
        ("exec", "reset-credential-email", "REQUIRED", None),
        ("exec", "reset-password", "REQUIRED", None),
        ("flow", "STIG Reset Credentials - second factor", "CONDITIONAL", [
            ("exec", "conditional-user-configured", "REQUIRED", None),
            ("exec", "auth-otp-form", "REQUIRED", None)]),
    ])

def browser_flow(p, *, admin_realm, extension=True):
    """Nested flow spec: (alias, [(kind, provider_or_alias, requirement, config|children)])."""
    prefix = "STIG Admin Browser" if admin_realm else "STIG Browser"
    s = p["sessions"]
    if admin_realm:
        use_x509 = p["admin"]["mfa"] == "x509"
        use_pw = p["admin"]["mfa"] in ("webauthn", "otp") or p["admin"]["allow_emergency_password"]
        second = "webauthn-authenticator" if p["admin"]["mfa"] == "webauthn" else "auth-otp-form"
        attr = p["admin"]["mapping_attribute"]
    else:
        use_x509 = p["auth_mode"] in ("cac", "cac_or_mfa")
        use_pw = p["auth_mode"] in ("cac_or_mfa", "mfa")
        second = "webauthn-authenticator" if p["mfa"] == "webauthn" else "auth-otp-form"
        attr = p["x509"]["mapping_attribute"]
    authn = []
    single = (use_x509 != use_pw)
    if use_x509:
        authn.append(("exec", "stig-x509-client-username-form" if extension else "auth-x509-client-username-form",
                      "REQUIRED" if single else "ALTERNATIVE",
                      {"alias": (prefix + " x509").lower().replace(" ", "-"), "config": x509_config(p, attr, admin_realm)}))
    if use_pw:
        # An administrator with no enrolled second factor is refused after the password, before the second-factor
        # step could offer enrolment: an administrator's OTP/WebAuthn is never enrolled on the strength of a password.
        authn.append(("flow", prefix + " - Password and MFA", "REQUIRED" if single else "ALTERNATIVE", [
            ("exec", "stig-username-password-form" if extension else "auth-username-password-form", "REQUIRED", None)] + [
            ("exec", second, "REQUIRED", None),
        ]))
    forms = ("flow", prefix + " - Forms", "ALTERNATIVE", [
            ("flow", prefix + " - Authenticate", "REQUIRED", authn),
            ("exec", "user-session-limits", "REQUIRED",
             {"alias": (prefix + " session limits").lower().replace(" ", "-"),
              "config": {"userRealmLimit": str(s["max_per_user"]), "userClientLimit": "0",
                         "behavior": "Deny new session",
                         "errorMessage": "Maximum concurrent sessions reached. Log out of another session first."}}),
        ])
    if not extension:
        return (prefix, [("exec", "auth-cookie", "ALTERNATIVE", None), forms])
    # stig-extensions: after ANY sign-in - an SSO cookie included - an administrator who is not on the realm's
    # allowlist (master-realm attribute stig.admin-allowlist.<realm>), or holds a realm-management role beyond its
    # entry (stig.admin-allowlist-roles.<realm>), is refused; no allowlist = no effect
    return (prefix, [
        ("flow", prefix + " - Sign in", "REQUIRED", [("exec", "auth-cookie", "ALTERNATIVE", None), forms]),
        ("exec", ALLOWLIST_GATE, "REQUIRED", None),
    ])

DENY_DIRECT_GRANT = ("STIG Direct Grant - Deny", [("exec", "deny-access-authenticator", "REQUIRED", None)])

def user_profile_attributes(p, *, admin_realm, extension=True):
    attrs = []
    # The card-mapping attribute: unique in the realm, and set/changed through the admin API only by realm
    # administrators - not by fine-grained (delegated) admins, who count as "admin" for user-profile permissions
    # (cac-identity-guard, stig-extensions.jar). V-222552, V-222522.
    guard = {"cac-identity-guard": {}} if extension else {}
    def a(name, display, view, edit, **extra):
        d = {"name": name, "displayName": display, "permissions": {"view": view, "edit": edit},
             "multivalued": False, "validations": {"length": {"max": "255"}}, "annotations": {}}
        d.update(extra)
        attrs.append(d)
    if admin_realm:
        a(p["admin"]["mapping_attribute"], "Alt Token certificate UPN", ["admin"], ["admin"],
          validations=dict({"length": {"max": "255"}}, **guard))
    else:
        label = {"cac_upn": "CAC certificate UPN (EDIPI@mil)", "cac_edipi": "DoD ID number (EDIPI)",
                 "cac_cn": "CAC certificate common name", "cac_subject_dn": "CAC certificate subject DN"}
        a(p["x509"]["mapping_attribute"], label.get(p["x509"]["mapping_attribute"], "CAC certificate identity"), ["admin"], ["admin"],
          validations=dict({"length": {"max": "255"}}, **guard))
    a("account_type", "Account type (permanent | temporary | emergency)", ["admin"], ["admin"],
      validations={"options": {"options": ["permanent", "temporary", "emergency"]}},
      annotations={"inputType": "select"})
    a("stig_last_login", "Last successful logon (UTC)", ["admin", "user"], ["admin"])
    a("stig_previous_login", "Previous successful logon (UTC)", ["admin", "user"], ["admin"])
    return attrs

def workflows(p):
    a = p["accounts"]
    return [
        # V-222411: one workflow, started at creation and restarted by every authentication, so the
        # clock always measures time since the last logon (verified on 26.8.2). Emergency accounts are
        # excluded (V-222410). Condition syntax is key:value - "key,value" is accepted but never matches.
        {"name": "stig-disable-inactive-%dd" % a["inactive_days"], "on": "user-created or user-authenticated",
         "if": "not has-user-attribute(account_type:emergency)",
         "concurrency": {"restart-in-progress": "true"},
         "steps": [{"uses": "disable-user", "after": "%dd" % a["inactive_days"]}]},
        # V-222409
        {"name": "stig-temp-account-%dh" % a["temp_hours"], "on": "user-created",
         "if": "has-user-attribute(account_type:temporary)",
         "steps": [{"uses": "disable-user", "after": "%dh" % a["temp_hours"]}]},
    ]

def client_policies():
    profile = {"name": "asd-stig", "description": "ASD STIG client hardening (PKCE, no implicit/ROPC, no full scope)",
               "executors": [
                   {"executor": "pkce-enforcer", "configuration": {"auto-configure": "true"}},
                   {"executor": "reject-implicit-grant", "configuration": {"auto-configure": "true"}},
                   {"executor": "reject-ropc-grant", "configuration": {"auto-configure": "true"}},  # null auto-configure -> NPE in 26.8
                   {"executor": "full-scope-disabled", "configuration": {"auto-configure": "true"}},
               ]}
    policy = {"name": "asd-stig-all-clients", "description": "Apply asd-stig profile to every client",
              "enabled": True, "conditions": [{"condition": "any-client", "configuration": {}}],
              "profiles": ["asd-stig"]}
    return {"profiles": [profile]}, {"policies": [policy]}

def client_rep(c, p):
    t = c.get("type", "oidc-confidential")
    idle = str(p["sessions"]["admin_idle_minutes"] * 60) if c.get("privileged") else None
    if t == "saml":
        attrs = {"saml.assertion.signature": "true", "saml.server.signature": "true", "saml.client.signature": "true",
                 "saml.encrypt": "true", "saml.signature.algorithm": "RSA_SHA256", "saml.force.post.binding": "true",
                 "saml_force_name_id_format": "true", "saml_name_id_format": "persistent",
                 "saml.assertion.lifespan": "300", "saml.authnstatement": "true"}
        if c.get("acs_url"):
            attrs["saml_assertion_consumer_url_post"] = c["acs_url"]
        if c.get("slo_url"):
            attrs["saml_single_logout_service_url_post"] = c["slo_url"]
        if c.get("signing_cert"):
            attrs["saml.signing.certificate"] = c["signing_cert"]
        if c.get("encryption_cert"):
            attrs["saml.encryption.certificate"] = c["encryption_cert"]
        if idle:
            attrs["client.session.idle.timeout"] = idle
        srep = {"clientId": c["client_id"], "name": c.get("name", c["client_id"]), "protocol": "saml",
                "enabled": True, "frontchannelLogout": True, "fullScopeAllowed": False,
                "redirectUris": c.get("redirect_uris", [c["acs_url"]] if c.get("acs_url") else []),
                "rootUrl": c.get("root_url", ""), "attributes": attrs}
        if c.get("roles"):
            srep["_roles"] = list(c["roles"])
        return srep
    public = t == "oidc-public"
    attrs = {"pkce.code.challenge.method": "S256",
             "post.logout.redirect.uris": "##".join(c.get("post_logout_redirect_uris", [])),
             "backchannel.logout.session.required": "true", "backchannel.logout.revoke.offline.tokens": "true",
             "oauth2.device.authorization.grant.enabled": "false", "oidc.ciba.grant.enabled": "false",
             "use.refresh.tokens": "true", "client_credentials.use_refresh_token": "false",
             "require.pushed.authorization.requests": str(bool(c.get("par", False))).lower()}
    if c.get("backchannel_logout_url"):
        attrs["backchannel.logout.url"] = c["backchannel_logout_url"]
    if idle:
        attrs["client.session.idle.timeout"] = idle
    rep = {"clientId": c["client_id"], "name": c.get("name", c["client_id"]), "protocol": "openid-connect",
           "enabled": True, "publicClient": public, "standardFlowEnabled": c.get("standard_flow", True),
           "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
           "serviceAccountsEnabled": bool(c.get("service_account", False)) and not public,
           "frontchannelLogout": False, "fullScopeAllowed": False, "consentRequired": False,
           "redirectUris": c.get("redirect_uris", []), "webOrigins": c.get("web_origins", []),
           "rootUrl": c.get("root_url", ""), "attributes": attrs}
    if not public:
        rep["clientAuthenticatorType"] = {"client-jwt": "client-jwt", "client-secret": "client-secret",
                                          "client-x509": "client-x509"}[c.get("auth", "client-secret")]
        if c.get("jwks_url"):
            attrs["use.jwks.url"] = "true"; attrs["jwks.url"] = c["jwks_url"]
        if c.get("auth") == "client-x509" and c.get("subject_dn"):
            attrs["x509.subjectdn"] = c["subject_dn"]
    if c.get("owner"):          # written by add-client; kept on the client so later apply runs preserve it
        attrs[OWNER_ATTR] = OWNER_VALUE
        attrs["stig.owner"] = c["owner"]
        if c.get("owner_contact"):
            attrs["stig.owner-contact"] = c["owner_contact"]
    if c.get("roles"):
        rep["_roles"] = list(c["roles"])
    for u in rep["redirectUris"]:
        if "*" in u:
            sys.exit("client %s: wildcard redirect URI %r is not allowed (exact URIs only)" % (c["client_id"], u))
    return rep

def render(p, extension=True):
    cprof, cpol = client_policies()
    return {
        "realm": dict(realm_settings(p, extension=extension), realm=p["realm"]["name"]),
        "browser_flow": browser_flow(p, admin_realm=False, extension=extension),
        "direct_grant_flow": DENY_DIRECT_GRANT,
        "reset_flow": reset_flow(extension),
        "user_profile_attributes": user_profile_attributes(p, admin_realm=False, extension=extension),
        "workflows": workflows(p),
        "client_profiles": cprof, "client_policies": cpol,
        "clients": [client_rep(c, p) for c in p["clients"]],
        "admin_realm": {
            "settings": realm_settings(p, admin_realm=True, extension=extension),
            "browser_flow": browser_flow(p, admin_realm=True, extension=extension),
            "user_profile_attributes": user_profile_attributes(p, admin_realm=True, extension=extension),
        },
    }

# --------------------------------------------------------------------------------------------
# Keycloak Admin REST client
# --------------------------------------------------------------------------------------------
class KCError(Exception):
    pass

class KC:
    def __init__(self, url, admin_realm="master", cacert=None):
        self.url = url.rstrip("/")
        self.admin_realm = admin_realm
        self.ctx = ssl.create_default_context(cafile=cacert) if cacert else ssl.create_default_context()
        host = urllib.parse.urlparse(self.url).hostname
        if os.environ.get("KCSTIG_LOOPBACK_NOVERIFY") == "1" and host in ("127.0.0.1", "localhost", "::1"):
            # In-container automation over loopback only (keycloak-cac image): the server certificate names the
            # public host, not 127.0.0.1. Never honoured for any other host.
            self.ctx.check_hostname = False; self.ctx.verify_mode = ssl.CERT_NONE
            # Edge-mode keycloak-cac requires a TLS client certificate on its listener; the container presents its
            # own per-start loopback certificate for these calls.
            if os.environ.get("KCSTIG_CLIENT_CERT") and os.environ.get("KCSTIG_CLIENT_KEY"):
                self.ctx.load_cert_chain(os.environ["KCSTIG_CLIENT_CERT"], os.environ["KCSTIG_CLIENT_KEY"])
        self.token = None

    def login(self):
        """Service account first (normal case), bootstrap admin second (first install only). Every credential
        may also be given as a file: KC_CLIENT_SECRET_FILE, KC_ADMIN_PASSWORD_FILE (container secrets)."""
        env = lambda k: os.environ.get(k) or (open(os.environ[k + "_FILE"]).read().strip() if os.environ.get(k + "_FILE") else None)
        attempts = []
        cid, sec = env("KC_CLIENT_ID"), env("KC_CLIENT_SECRET")
        if cid and sec:
            attempts.append(("service account %s" % cid, {"grant_type": "client_credentials", "client_id": cid, "client_secret": sec}))
        if env("KC_ADMIN_USER"):
            attempts.append(("bootstrap admin %s" % env("KC_ADMIN_USER"), {"grant_type": "password", "client_id": "admin-cli",
                             "username": env("KC_ADMIN_USER"), "password": env("KC_ADMIN_PASSWORD") or ""}))
        if not attempts:
            sys.exit("Set KC_CLIENT_ID/KC_CLIENT_SECRET[_FILE] (service account) or KC_ADMIN_USER/KC_ADMIN_PASSWORD[_FILE]")
        errors = []
        for label, data in attempts:
            try:
                r = self.raw("POST", "/realms/%s/protocol/openid-connect/token" % self.admin_realm,
                             urllib.parse.urlencode(data).encode(), {"Content-Type": "application/x-www-form-urlencoded"})
                self.token = json.loads(r[1])["access_token"]
                self.auth_label = label
                return
            except KCError as e:
                errors.append("%s: %s" % (label, str(e)[-160:]))
        sys.exit("admin login failed:\n  " + "\n  ".join(errors))

    def wait_ready(self, seconds):
        deadline = time.time() + seconds
        while True:
            try:
                self.raw("GET", "/realms/%s/.well-known/openid-configuration" % self.admin_realm); return
            except Exception as e:
                if time.time() > deadline:
                    sys.exit("Keycloak not ready at %s after %ss: %s" % (self.url, seconds, e))
                time.sleep(5)

    def raw(self, method, path, body=None, headers=None):
        req = urllib.request.Request(self.url + path, data=body, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=60) as r:
                return r.status, r.read().decode(), dict(r.headers)
        except urllib.error.HTTPError as e:
            raise KCError("%s %s -> %s %s" % (method, path, e.code, e.read().decode()[:500]))

    def api(self, method, path, obj=None, ok404=False, _retry=True):
        if not self.token:
            self.login()
        h = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}
        body = None
        if obj is not None:
            body = json.dumps(obj).encode(); h["Content-Type"] = "application/json"
        try:
            st, txt, hdr = self.raw(method, "/admin" + path, body, h)
        except KCError as e:
            if ok404 and " 404 " in str(e):
                return None
            if " 401 " in str(e) and self.token and _retry:
                self.login(); return self.api(method, path, obj, ok404, _retry=False)
            if " 401 " in str(e) and self.token:
                try:
                    pl = self.token.split(".")[1]; aud = json.loads(__import__("base64").urlsafe_b64decode(pl + "=" * (-len(pl) % 4))).get("aud")
                except Exception:
                    aud = None
                if aud is not None and not any("/admin/" in x for x in (aud if isinstance(aud, list) else [aud])):
                    sys.exit("Admin API rejected the token of %s: it lacks the admin-API audience (aud=%s).\n"
                             "Keycloak >= 26.8 requires the 'kc-admin-api' client scope; service accounts created on an older "
                             "version do not get it on upgrade.\nFix: references/operations.md section 7 (create a temporary admin "
                             "client with kc.sh bootstrap-admin service, run apply with it - apply adds the scope - then apply "
                             "--remove-bootstrap-admin with the automation account)." % (getattr(self, "auth_label", "?"), aud))
            raise
        if hdr.get("Location") and method == "POST":
            return hdr["Location"].rstrip("/").split("/")[-1]
        return json.loads(txt) if txt.strip() else None

def q(s):
    return urllib.parse.quote(s, safe="")

def log(msg):
    print("  " + msg, flush=True)

# --------------------------------------------------------------------------------------------
# Apply
# --------------------------------------------------------------------------------------------
def server_capabilities(kc):
    info = kc.api("GET", "/serverinfo")
    pols = {x["id"] for x in info.get("passwordPolicies", [])}
    listeners = set(info.get("providers", {}).get("eventsListener", {}).get("providers", {}).keys())
    themes = {t["name"] for t in info.get("themes", {}).get("login", [])}
    feats = {f["name"] for f in info.get("features", []) if f.get("enabled")}
    events = info.get("enums", {}).get("eventType") or ALL_EVENT_TYPES_FALLBACK
    return {"extension": "minimumPasswordAge" in pols and "stig-audit" in listeners,
            "theme": themes, "workflows": "WORKFLOWS" in feats, "event_types": events,
            "version": info.get("systemInfo", {}).get("version"),
            "crypto": info.get("cryptoInfo", {}), "info": info}

def ensure_realm(kc, name):
    if kc.api("GET", "/realms/%s" % q(name), ok404=True) is None:
        try:
            kc.api("POST", "/realms", {"realm": name, "enabled": True})
            log("created realm %s" % name)
        except KCError as e:
            if " 409 " not in str(e):
                raise
            log("realm %s was just created by another node" % name)   # replicas applying at the same time

def build_flow(kc, realm, spec):
    alias, children = spec
    r = "/realms/%s/authentication" % q(realm)
    rep = kc.api("GET", "/realms/%s" % q(realm))
    existing = {f["alias"]: f for f in kc.api("GET", r + "/flows")}
    if alias in existing:
        # unbind before deleting
        for k, builtin in (("browserFlow", "browser"), ("directGrantFlow", "direct grant"), ("resetCredentialsFlow", "reset credentials")):
            if rep.get(k) == alias:
                kc.api("PUT", "/realms/%s" % q(realm), {k: builtin})
        kc.api("DELETE", r + "/flows/%s" % existing[alias]["id"])
    kc.api("POST", r + "/flows", {"alias": alias, "description": "ASD STIG generated by kcstig", "providerId": "basic-flow",
                                  "topLevel": True, "builtIn": False})

    def add(parent, items):
        for kind, name, req, extra in items:
            if kind == "exec":
                kc.api("POST", r + "/flows/%s/executions/execution" % q(parent), {"provider": name})
            else:
                kc.api("POST", r + "/flows/%s/executions/flow" % q(parent),
                       {"alias": name, "type": "basic-flow", "provider": "registration-page-form", "description": ""})
            execs = kc.api("GET", r + "/flows/%s/executions" % q(parent))
            mine = [e for e in execs if e.get("level", 0) == 0 and
                    (e.get("displayName") == name if kind == "flow" else e.get("providerId") == name)][-1]
            mine["requirement"] = req
            kc.api("PUT", r + "/flows/%s/executions" % q(parent), mine)
            if kind == "exec" and extra:
                kc.api("POST", r + "/executions/%s/config" % mine["id"], extra)
            if kind == "flow":
                add(name, extra)
    add(alias, children)
    log("flow '%s' built" % alias)
    return alias

def ensure_user_profile(kc, realm, attrs):
    up = kc.api("GET", "/realms/%s/users/profile" % q(realm))
    names = {a["name"] for a in up["attributes"]}
    changed = False
    for a in attrs:
        if a["name"] not in names:
            up["attributes"].append(a); changed = True
        else:
            for i, cur in enumerate(up["attributes"]):
                if cur["name"] == a["name"] and cur.get("permissions") != a["permissions"]:
                    up["attributes"][i]["permissions"] = a["permissions"]; changed = True
                if cur["name"] == a["name"] and cur.get("validations") != a["validations"]:
                    up["attributes"][i]["validations"] = a["validations"]; changed = True
    for cur in up["attributes"]:
        # Card holders are identified by the certificate, not by e-mail: an account provisioned with only an
        # EDIPI/UPN must not be stopped at "update profile" (the STIG does not require an e-mail address).
        if cur["name"] == "email" and cur.get("required"):
            cur.pop("required"); changed = True
        # the address set-up and credential e-mails go to: users read it, administrators set it
        if cur["name"] == "email" and (cur.get("permissions") or {}).get("edit") != ["admin"]:
            cur["permissions"] = {"view": ["admin", "user"], "edit": ["admin"]}; changed = True
    if up.get("unmanagedAttributePolicy") == "ENABLED":
        up.pop("unmanagedAttributePolicy"); changed = True  # users must not set arbitrary attributes
    if changed:
        kc.api("PUT", "/realms/%s/users/profile" % q(realm), up)
        log("user profile attributes ensured")

def ensure_required_actions(kc, realm, terms):
    base = "/realms/%s/authentication" % q(realm)
    have = {a["alias"]: a for a in kc.api("GET", base + "/required-actions")}
    if "TERMS_AND_CONDITIONS" not in have:
        unreg = kc.api("GET", base + "/unregistered-required-actions") or []
        for u in unreg:
            if u["providerId"] == "TERMS_AND_CONDITIONS":
                kc.api("POST", base + "/register-required-action", {"providerId": u["providerId"], "name": u["name"]})
        have = {a["alias"]: a for a in kc.api("GET", base + "/required-actions")}
    want = {"CONFIGURE_TOTP": (True, False), "UPDATE_PASSWORD": (True, False), "webauthn-register": (True, False),
            "TERMS_AND_CONDITIONS": (bool(terms), bool(terms)), "VERIFY_PROFILE": (True, False),
            "delete_account": (False, False),
            # accounts are linked to an identity provider only by an administrator-set attribute, never by the user
            "idp_link": (False, False)}
    for alias, (enabled, default) in want.items():
        if alias in have:
            a = have[alias]
            if a.get("enabled") != enabled or a.get("defaultAction") != default:
                a["enabled"], a["defaultAction"] = enabled, default
                kc.api("PUT", base + "/required-actions/%s" % q(alias), a)
    log("required actions ensured (T&C banner backstop=%s)" % bool(terms))

def remove_account_links(kc, realm):
    """Users must not link (or unlink) identity-provider accounts themselves: manage-account-links is taken out of
    the account client's manage-account composite and out of the default roles. NOT sufficient alone: Keycloak 26.8
    also lets manage-account itself link accounts (IdentityBrokerService, LinkedAccountsResource), so a realm with
    identity providers also needs stig-extensions' idp-require-admin-attribute-match in its post-broker-login flow,
    which refuses any brokered sign-in - through a new or an existing link - for an identity other than the
    administrator-set one."""
    rr = "/realms/%s" % q(realm)
    acc = kc.api("GET", rr + "/clients?clientId=account") or []
    if not acc:
        return
    links = kc.api("GET", rr + "/clients/%s/roles/manage-account-links" % acc[0]["id"], ok404=True)
    if not links:
        return
    ma = kc.api("GET", rr + "/clients/%s/roles/manage-account" % acc[0]["id"], ok404=True)
    dr = kc.api("GET", rr + "/roles/default-roles-%s" % q(realm.lower()), ok404=True)
    for holder in (ma, dr):
        if holder and any(c["id"] == links["id"] for c in kc.api("GET", rr + "/roles-by-id/%s/composites" % holder["id"]) or []):
            kc.api("DELETE", rr + "/roles-by-id/%s/composites" % holder["id"], [links])
            log("manage-account-links removed from %s" % holder["name"])

def remove_offline_access(kc, realm):
    rr = "/realms/%s" % q(realm)
    dr = kc.api("GET", rr + "/roles/default-roles-%s" % q(realm.lower()), ok404=True)
    if dr:
        comps = kc.api("GET", rr + "/roles-by-id/%s/composites" % dr["id"]) or []
        off = [c for c in comps if c["name"] == "offline_access"]
        if off:
            kc.api("DELETE", rr + "/roles-by-id/%s/composites" % dr["id"], off)
            log("offline_access removed from default roles")
    for sc in kc.api("GET", rr + "/default-optional-client-scopes") or []:
        if sc["name"] == "offline_access":
            kc.api("DELETE", rr + "/default-optional-client-scopes/%s" % sc["id"])
            log("offline_access removed from default optional client scopes")

def ensure_stig_claims_scope(kc, realm):
    rr = "/realms/%s" % q(realm)
    scopes = {s["name"]: s for s in kc.api("GET", rr + "/client-scopes")}
    if "stig-claims" not in scopes:
        kc.api("POST", rr + "/client-scopes", {
            "name": "stig-claims", "protocol": "openid-connect",
            "description": "previous_login claim for V-222437 last-logon display",
            "attributes": {"include.in.token.scope": "false", "display.on.consent.screen": "false"},
            "protocolMappers": [{
                "name": "previous_login", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper",
                "config": {"user.attribute": "stig_previous_login", "claim.name": "previous_login", "jsonType.label": "String",
                           "id.token.claim": "true", "access.token.claim": "false", "userinfo.token.claim": "true",
                           "introspection.token.claim": "true"}}]})
        scopes = {s["name"]: s for s in kc.api("GET", rr + "/client-scopes")}
    sid = scopes["stig-claims"]["id"]
    defaults = {s["name"] for s in kc.api("GET", rr + "/default-default-client-scopes")}
    if "stig-claims" not in defaults:
        kc.api("PUT", rr + "/default-default-client-scopes/%s" % sid)
    log("client scope stig-claims ensured")
    return sid

def upsert_client(kc, realm, rep, stig_scope_id=None):
    if reserved_client_id(rep.get("clientId", "")):
        sys.exit("client %r is reserved for Keycloak's own clients - refusing to create or update it" % rep.get("clientId"))
    rr = "/realms/%s" % q(realm)
    rep = dict(rep); roles = rep.pop("_roles", [])
    found = kc.api("GET", rr + "/clients?clientId=%s" % q(rep["clientId"]))
    if found:
        cid = found[0]["id"]
        cur = found[0]; cur.update(rep); cur["attributes"] = dict(found[0].get("attributes", {}), **rep.get("attributes", {}))
        kc.api("PUT", rr + "/clients/%s" % cid, cur)
        log("client %s updated" % rep["clientId"])
    else:
        cid = kc.api("POST", rr + "/clients", rep)
        log("client %s created" % rep["clientId"])
    for role in roles:
        if kc.api("GET", rr + "/clients/%s/roles/%s" % (cid, q(role)), ok404=True) is None:
            kc.api("POST", rr + "/clients/%s/roles" % cid, {"name": role, "description": "ASD STIG app role (kcstig)"})
            log("client %s role %s created" % (rep["clientId"], role))
    if rep.get("protocol") == "openid-connect":
        for sc in kc.api("GET", rr + "/clients/%s/optional-client-scopes" % cid) or []:
            if sc["name"] == "offline_access":
                kc.api("DELETE", rr + "/clients/%s/optional-client-scopes/%s" % (cid, sc["id"]))
        if stig_scope_id:
            kc.api("PUT", rr + "/clients/%s/default-client-scopes/%s" % (cid, stig_scope_id))
    return cid

def admin_console_idle(kc, realm, seconds):
    rr = "/realms/%s" % q(realm)
    for cid in ("security-admin-console",):
        found = kc.api("GET", rr + "/clients?clientId=%s" % cid)
        if found:
            c = found[0]; c.setdefault("attributes", {})["client.session.idle.timeout"] = str(seconds)
            kc.api("PUT", rr + "/clients/%s" % c["id"], c)
    log("security-admin-console idle override %ss" % seconds)

def ensure_workflows(kc, realm, wfs):
    rr = "/realms/%s/workflows" % q(realm)
    have = {w["name"]: w for w in (kc.api("GET", rr) or [])}
    for w in wfs:
        cur = have.get(w["name"])
        if cur and all(cur.get(k) == w.get(k) for k in ("on", "if")) and \
                [(s["uses"], s.get("after")) for s in cur.get("steps", [])] == [(s["uses"], s.get("after")) for s in w["steps"]]:
            continue  # unchanged; keep scheduled state for existing users
        if cur:
            kc.api("DELETE", rr + "/%s" % cur["id"])
        kc.api("POST", rr, w)
        log("workflow %s ensured" % w["name"])

def ensure_user(kc, realm, u, mapping_attr, mfa_action):
    rr = "/realms/%s" % q(realm)
    found = kc.api("GET", rr + "/users?username=%s&exact=true" % q(u["username"]))
    attrs = {"account_type": [u.get("account_type", "permanent")]}
    if u.get(mapping_attr):
        attrs[mapping_attr] = [u[mapping_attr]]
    rep = {"username": u["username"], "email": u.get("email"), "firstName": u.get("firstName", u["username"]),
           "lastName": u.get("lastName", "-"), "enabled": True, "emailVerified": True, "attributes": attrs}
    if found:
        cur = found[0]; cur["attributes"] = dict(cur.get("attributes", {}), **attrs)
        kc.api("PUT", rr + "/users/%s" % cur["id"], cur)
        uid = cur["id"]
    else:
        # CAC/Alt-Token users already present two factors (card + PIN); only password users enrol OTP/WebAuthn.
        ra = [a for a in (mfa_action,) if a and not u.get(mapping_attr)]
        if u.get("temporary_password"):
            rep["credentials"] = [{"type": "password", "value": u["temporary_password"], "temporary": True}]
        rep["requiredActions"] = ra
        uid = kc.api("POST", rr + "/users", rep)
        log("user %s created" % u["username"])
    for cl, roles in (u.get("client_roles") or {}).items():   # {"payroll-web": ["payroll-user"]}
        found_c = kc.api("GET", rr + "/clients?clientId=%s" % q(cl))
        if not found_c:
            log("WARNING user %s: client %s not found for role mapping" % (u["username"], cl)); continue
        cid = found_c[0]["id"]
        reps = [kc.api("GET", rr + "/clients/%s/roles/%s" % (cid, q(r))) for r in roles]
        kc.api("POST", rr + "/users/%s/role-mappings/clients/%s" % (uid, cid), reps)
    return uid

def apply_realm(kc, p, caps, rendered):
    name = p["realm"]["name"]
    print("== realm %s" % name)
    ensure_realm(kc, name)
    settings = realm_settings(p, extension=caps["extension"], event_types=caps["event_types"])
    if p["banner"]["theme"] not in caps["theme"]:
        log("WARNING login theme %s not installed on server; keeping default theme" % p["banner"]["theme"])
        settings.pop("loginTheme")
    kc.api("PUT", "/realms/%s" % q(name), settings)
    log("realm settings applied")
    ensure_user_profile(kc, name, rendered["user_profile_attributes"])
    ensure_required_actions(kc, name, p["banner"]["terms_required_action"])
    remove_offline_access(kc, name)
    remove_account_links(kc, name)
    sid = ensure_stig_claims_scope(kc, name)
    bf = build_flow(kc, name, rendered["browser_flow"])
    dg = build_flow(kc, name, rendered["direct_grant_flow"])
    bind = {"browserFlow": bf, "directGrantFlow": dg}
    if rendered.get("reset_flow"):
        bind["resetCredentialsFlow"] = build_flow(kc, name, rendered["reset_flow"])
    kc.api("PUT", "/realms/%s" % q(name), bind)
    log("flows bound (%s)" % ", ".join("%s=%s" % kv for kv in bind.items()))
    # client policies first: every later client create/update is evaluated against them
    kc.api("PUT", "/realms/%s/client-policies/profiles" % q(name), rendered["client_profiles"])
    kc.api("PUT", "/realms/%s/client-policies/policies" % q(name), rendered["client_policies"])
    log("client policies applied")
    admin_console_idle(kc, name, p["sessions"]["admin_idle_minutes"] * 60)
    for c in rendered["clients"]:
        upsert_client(kc, name, c, sid)
    if caps["workflows"]:
        ensure_workflows(kc, name, rendered["workflows"])
    else:
        log("WARNING WORKFLOWS feature disabled: V-222409/V-222411 not automated")
    mfa_action = None if p["auth_mode"] == "cac" else ("webauthn-register" if p["mfa"] == "webauthn" else "CONFIGURE_TOTP")
    for u in p["users"]:
        ensure_user(kc, name, u, p["x509"]["mapping_attribute"], mfa_action)

def ensure_admin_api_scope(kc, realm, client_uuid):
    """Keycloak 26.8 admin API only accepts tokens whose audience includes the admin API; that audience
    comes from the built-in 'kc-admin-api' client scope."""
    rr = "/realms/%s" % q(realm)
    sc = [s for s in kc.api("GET", rr + "/client-scopes") if s["name"] == "kc-admin-api"]
    if sc:
        kc.api("PUT", rr + "/clients/%s/default-client-scopes/%s" % (client_uuid, sc[0]["id"]))

def harden_admin_realm(kc, p, caps, rendered, secret_out, remove_bootstrap, secret_file=None):
    ar = kc.admin_realm
    print("== admin realm %s" % ar)
    admins = p["admin"]["users"]
    attr = p["admin"]["mapping_attribute"]
    if not admins:
        sys.exit("admin.users is empty: refusing to harden the admin realm without a named administrator")
    if p["admin"]["mfa"] == "x509" and not all(a.get(attr) for a in admins):
        sys.exit("admin.mfa=x509 needs %s set for every admin (their Alt Token UPN) or they will be locked out" % attr)
    settings = dict(rendered["admin_realm"]["settings"])
    settings["enabledEventTypes"] = caps["event_types"]
    if not caps["extension"]:
        settings["passwordPolicy"] = password_policy(p, False)
        settings["eventsListeners"] = [l for l in settings["eventsListeners"] if not l.startswith("stig-")]
    if p["banner"]["theme"] not in caps["theme"]:
        settings.pop("loginTheme")
    kc.api("PUT", "/realms/%s" % q(ar), settings)
    log("admin realm settings applied (idle %ss)" % settings["ssoSessionIdleTimeout"])
    ensure_user_profile(kc, ar, rendered["admin_realm"]["user_profile_attributes"])
    ensure_required_actions(kc, ar, p["banner"]["terms_required_action"])
    remove_offline_access(kc, ar)
    admin_console_idle(kc, ar, p["sessions"]["admin_idle_minutes"] * 60)
    mfa_action = {"x509": None, "webauthn": "webauthn-register", "otp": "CONFIGURE_TOTP"}[p["admin"]["mfa"]]
    rr = "/realms/%s" % q(ar)
    admin_role = kc.api("GET", rr + "/roles/admin")
    for a in admins:
        uid = ensure_user(kc, ar, a, attr, mfa_action)
        kc.api("POST", rr + "/users/%s/role-mappings/realm" % uid, [admin_role])
    # automation service account (replaces password grant for scripted administration)
    auto = p["admin"]["automation_client"]
    if auto:
        found = kc.api("GET", rr + "/clients?clientId=%s" % q(auto))
        if found:
            ensure_admin_api_scope(kc, ar, found[0]["id"])
        if not found:
            rep_extra = {"secret": open(secret_file).read().strip()} if secret_file else {}
            cid = kc.api("POST", rr + "/clients", dict(rep_extra, **{"clientId": auto, "name": "ASD STIG automation (service account)",
                         "protocol": "openid-connect", "publicClient": False, "standardFlowEnabled": False,
                         "directAccessGrantsEnabled": False, "serviceAccountsEnabled": True,
                         "clientAuthenticatorType": "client-secret",
                         "attributes": {"access.token.lifespan": "300"}}))
            ensure_admin_api_scope(kc, ar, cid)
            sa = kc.api("GET", rr + "/clients/%s/service-account-user" % cid)
            kc.api("PUT", rr + "/users/%s" % sa["id"], dict(sa, attributes={"account_type": ["emergency"]}))
            kc.api("POST", rr + "/users/%s/role-mappings/realm" % sa["id"], [admin_role])
            if secret_file:
                log("automation client %s created with the secret from %s" % (auto, secret_file))
            else:
                sec = kc.api("GET", rr + "/clients/%s/client-secret" % cid)["value"]
                fd = os.open(secret_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write("KC_CLIENT_ID=%s\nKC_CLIENT_SECRET=%s\n" % (auto, sec))
                log("automation client %s created; secret written to %s (mode 0600)" % (auto, secret_out))
        elif secret_file:
            want = open(secret_file).read().strip()
            cur = kc.api("GET", rr + "/clients/%s/client-secret" % found[0]["id"])["value"]
            if cur != want:  # rotation: the secret manager is the source of truth
                c = found[0]; c["secret"] = want
                kc.api("PUT", rr + "/clients/%s" % c["id"], c)
                log("automation client %s secret rotated from %s" % (auto, secret_file))
    bf = build_flow(kc, ar, rendered["admin_realm"]["browser_flow"])
    dg = build_flow(kc, ar, DENY_DIRECT_GRANT)
    kc.api("PUT", rr, {"browserFlow": bf, "directGrantFlow": dg})
    log("admin flows bound (browser=%s); password grant to admin-cli now denied" % bf)
    kc.api("PUT", rr + "/client-policies/profiles", rendered["client_profiles"])
    kc.api("PUT", rr + "/client-policies/policies", rendered["client_policies"])
    if caps["workflows"]:
        ensure_workflows(kc, ar, rendered["workflows"])
    if remove_bootstrap:
        for u in kc.api("GET", rr + "/users?max=500&briefRepresentation=false") or []:
            at = u.get("attributes", {}) or {}
            if at.get("is_temporary_admin") == ["true"] and u["username"] not in [a["username"] for a in admins]:
                kc.api("DELETE", rr + "/users/%s" % u["id"])
                log("bootstrap temporary admin '%s' deleted (V-222662)" % u["username"])
        for c in kc.api("GET", rr + "/clients") or []:
            if (c.get("attributes") or {}).get("is_temporary_admin") == "true" and c["clientId"] != os.environ.get("KC_CLIENT_ID"):
                kc.api("DELETE", rr + "/clients/%s" % c["id"])
                log("temporary admin client '%s' deleted (V-222662)" % c["clientId"])

def cmd_apply(a):
    p = load_profile(a.profile, getattr(a, 'clients_dir', None))
    kc = KC(a.url or p["keycloak"]["url"], p["keycloak"]["admin_realm"], os.environ.get("KC_CACERT"))
    if a.wait:
        kc.wait_ready(a.wait)
    caps = server_capabilities(kc)
    print("Keycloak %s | stig-extensions: %s | workflows: %s | dod-stig theme: %s" % (
        caps["version"], caps["extension"], caps["workflows"], p["banner"]["theme"] in caps["theme"]))
    rendered = render(p, extension=caps["extension"])
    if not a.admin_only:
        apply_realm(kc, p, caps, rendered)
    if a.harden_master:
        harden_admin_realm(kc, p, caps, rendered, a.secret_out, a.remove_bootstrap_admin, a.automation_secret_file)
    print("done. Next: kcstig.py verify --profile %s" % a.profile)

# --------------------------------------------------------------------------------------------
# add-client: register one relying party from its client-request.json (keycloak-rp-integration)
# --------------------------------------------------------------------------------------------
def load_rp_validator(path=None):
    """Import (never copy) the relying-party validator, so the app side and this side apply the same rules."""
    if path:                                # an explicit path must exist: never fall back to another copy
        if not os.path.isfile(path):
            sys.exit("add-client: --validator %s does not exist - nothing changed" % path)
        cands = [path]
    elif os.environ.get("KCSTIG_RP_VALIDATOR"):
        if not os.path.isfile(os.environ["KCSTIG_RP_VALIDATOR"]):
            sys.exit("add-client: KCSTIG_RP_VALIDATOR=%s does not exist - nothing changed" % os.environ["KCSTIG_RP_VALIDATOR"])
        cands = [os.environ["KCSTIG_RP_VALIDATOR"]]
    else:
        cands = [os.path.join(os.path.dirname(SKILL), "keycloak-rp-integration", "scripts", "validate-client-request.py")]
    for c in cands:
        if os.path.isfile(c):
            import importlib.util
            spec = importlib.util.spec_from_file_location("validate_client_request", c)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for fn in ("validate", "load_request", "to_client"):
                if not hasattr(mod, fn):
                    sys.exit("add-client: %s has no %s() - use the validator from the same keycloak-asd-stig checkout" % (c, fn))
            return mod
    sys.exit("add-client: the request validator was not found. It ships in keycloak-rp-integration/ next to this skill "
             "(github.com/JongoDB/keycloak-asd-stig); pass --validator <path to validate-client-request.py> or set "
             "KCSTIG_RP_VALIDATOR. add-client refuses to register a request it cannot validate.")

def write_private(path, text):
    """Create or replace a file readable only by its owner (0600), without a window in which it is wider."""
    d = os.path.dirname(os.path.abspath(path))
    tmp = os.path.join(d, ".%s.%s.tmp" % (os.path.basename(path), uuid.uuid4().hex))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

OWNER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}", re.ASCII)

def live_endpoints(c):
    """The registration fields an update can redirect: from a live Keycloak client representation."""
    at = c.get("attributes") or {}
    return {"redirect_uris": sorted(c.get("redirectUris") or []),
            "post_logout_redirect_uris": sorted(u for u in (at.get("post.logout.redirect.uris") or "").split("##") if u),
            "backchannel_logout_url": at.get("backchannel.logout.url") or None,
            "jwks_url": at.get("jwks.url") or None,
            "auth": c.get("clientAuthenticatorType")}

def request_endpoints(client):
    return {"redirect_uris": sorted(client.get("redirect_uris") or []),
            "post_logout_redirect_uris": sorted(client.get("post_logout_redirect_uris") or []),
            "backchannel_logout_url": client.get("backchannel_logout_url"),
            "jwks_url": client.get("jwks_url"), "auth": client.get("auth")}

def print_update_diff(before, after, roles_before, roles_after, prune):
    print("changes to apply:")
    changed = False
    for k in ("redirect_uris", "post_logout_redirect_uris", "backchannel_logout_url", "jwks_url", "auth"):
        if before[k] != after[k]:
            changed = True
            print("  %s:\n    - %s\n    + %s" % (k, before[k], after[k]))
    add, drop = sorted(set(roles_after) - set(roles_before)), sorted(set(roles_before) - set(roles_after))
    if add:
        changed = True
        print("  roles added: %s" % ", ".join(add))
    if drop:
        changed = True
        print("  roles %s: %s" % ("removed (--prune-roles)" if prune else "no longer requested, kept (no --prune-roles)",
                                 ", ".join(drop)))
    if not changed:
        print("  (no change to redirect URIs, logout URLs, JWKS URL, auth or roles)")

def cmd_add_client(a):
    v = load_rp_validator(a.validator)
    try:
        req = v.load_request(a.request)
    except (OSError, ValueError) as e:
        sys.exit("add-client: cannot read %s: %s" % (a.request, e))
    res = v.validate(req)
    for w in res.warnings:
        print("WARNING request: " + w, file=sys.stderr)
    for n in getattr(res, "notes", []):
        print("NOTE request: " + n, file=sys.stderr)
    for e in res.errors:
        print("ERROR request: " + e, file=sys.stderr)
    if res.errors or (a.strict and res.warnings):
        sys.exit("add-client: request refused (%d error(s), %d warning(s)%s) - nothing changed" % (
            len(res.errors), len(res.warnings),
            "; warnings are errors by default - --no-strict only after checking each one" if a.strict and res.warnings else ""))
    if req.get("dev_request") and not a.allow_dev:
        sys.exit("add-client: this is a dev_request (localhost URLs). Register it only in a non-production realm, "
                 "and say so with --allow-dev - nothing changed")
    client = v.to_client(req)
    cid = client["client_id"]
    if reserved_client_id(cid):      # the validator refuses these too; checked again on this side on purpose
        sys.exit("add-client: %r is reserved for Keycloak's own clients - nothing changed" % cid)
    for flag in ("adopt", "update"):
        if getattr(a, flag) and getattr(a, flag) != cid:
            sys.exit("add-client: --%s %r does not match the request's client_id %r - nothing changed" % (flag, getattr(a, flag), cid))
    # Who the client belongs to: the operator's owner id, else the requesting contact. Recorded on the client.
    contact = req["contact"]["email"].strip().lower()
    owner = a.owner or contact
    if not OWNER_RE.fullmatch(owner):
        sys.exit("add-client: --owner %r: use letters, digits and . _ @ + - (at most 128) - nothing changed" % owner)
    client["owner"], client["owner_contact"] = owner, contact
    clients_dir = a.clients_dir or os.environ.get("STIG_CLIENTS_DIR")
    if not clients_dir or not os.path.isdir(clients_dir):
        sys.exit("add-client: --clients-dir (or STIG_CLIENTS_DIR) must name the existing clients.d directory")
    target = os.path.join(clients_dir, cid + ".json")
    # The same id defined anywhere else in the configuration belongs to someone else.
    with open(a.profile) as f:
        raw = json.load(f)
    others = ["profile %s" % a.profile] if any(c.get("client_id") == cid for c in raw.get("clients", [])) else []
    for fpath in sorted(glob.glob(os.path.join(clients_dir, "*.json"))):
        if os.path.abspath(fpath) == os.path.abspath(target):
            continue                 # judged below, against the live client
        with open(fpath) as f:
            obj = json.load(f)
        if any(c.get("client_id") == cid for c in (obj if isinstance(obj, list) else [obj])):
            others.append(fpath)
    if others and a.adopt != cid:
        sys.exit("add-client: client %r is already defined by %s - refusing to override it (use --adopt %s only if "
                 "this request replaces that definition, then remove it there)" % (cid, ", ".join(others), cid))
    p = load_profile(a.profile, clients_dir)
    realm = p["realm"]["name"]
    kc = KC(a.url or p["keycloak"]["url"], p["keycloak"]["admin_realm"], os.environ.get("KC_CACERT"))
    rr = "/realms/%s" % q(realm)
    if kc.api("GET", rr, ok404=True) is None:
        sys.exit("add-client: realm %s does not exist - run kcstig.py apply first" % realm)
    found = [c for c in (kc.api("GET", rr + "/clients?clientId=%s" % q(cid)) or []) if c.get("clientId") == cid]
    live = found[0] if found else None
    if live is None:
        if a.update:
            sys.exit("add-client: --update %s: no such client in realm %s - omit --update to create it" % (cid, realm))
        if os.path.exists(target) and a.adopt != cid:
            sys.exit("add-client: %s already exists although client %r is not in realm %s. It is someone's configuration "
                     "(a later apply would create the client from it) - refusing to replace it. Remove it, or use "
                     "--adopt %s if this request replaces it - nothing changed" % (target, cid, realm, cid))
        print("client %s does not exist in realm %s: creating it for owner %s" % (cid, realm, owner))
    else:
        at = live.get("attributes") or {}
        if a.update != cid:
            sys.exit("add-client: client %r already exists in realm %s (owner %r, contact %r). Changing it needs "
                     "--update %s - confirm the change with the recorded contact through a second channel first. "
                     "Nothing changed." % (cid, realm, at.get("stig.owner"), at.get("stig.owner-contact"), cid))
        if at.get(OWNER_ATTR) != OWNER_VALUE:
            if a.adopt != cid:
                sys.exit("add-client: client %r already exists in realm %s and was not created by add-client (%s=%r). "
                         "Refusing to modify it. If the operator manages it and this request is meant to replace its "
                         "settings, rerun with --update %s --adopt %s - nothing changed"
                         % (cid, realm, OWNER_ATTR, at.get(OWNER_ATTR), cid, cid))
            print("WARNING add-client: adopting existing client %s, which add-client did not create (%s=%r). Its "
                  "settings are replaced by this request and it now belongs to %s." % (
                      cid, OWNER_ATTR, at.get(OWNER_ATTR), owner), file=sys.stderr)
        elif at.get("stig.owner") != owner:
            if not a.transfer:
                sys.exit("add-client: client %r belongs to %r (contact %r); this request is from %r. Refusing to change "
                         "another owner's client. If ownership really moves, confirm with the recorded contact and "
                         "rerun with --transfer - nothing changed" % (
                             cid, at.get("stig.owner"), at.get("stig.owner-contact"), owner))
            print("WARNING add-client: transferring client %s from %r (contact %r) to %r (contact %r)" % (
                cid, at.get("stig.owner"), at.get("stig.owner-contact"), owner, contact), file=sys.stderr)
        roles_before = sorted(r["name"] for r in kc.api("GET", rr + "/clients/%s/roles" % live["id"]) or [])
        print("updating client %s (owner %s)" % (cid, owner))
        print_update_diff(live_endpoints(live), request_endpoints(client), roles_before, client.get("roles") or [],
                          a.prune_roles)
    rep = client_rep(client, p)
    rep["attributes"][OWNER_ATTR] = OWNER_VALUE
    sid = ensure_stig_claims_scope(kc, realm)
    uuid_ = upsert_client(kc, realm, rep, sid)
    if a.prune_roles:
        keep = set(client.get("roles") or [])
        for role in kc.api("GET", rr + "/clients/%s/roles" % uuid_) or []:
            if role["name"] not in keep:
                kc.api("DELETE", rr + "/clients/%s/roles/%s" % (uuid_, q(role["name"])))
                log("client %s role %s deleted (--prune-roles)" % (cid, role["name"]))
    os.makedirs(clients_dir, exist_ok=True)
    tmp = target + ".tmp"
    with open(tmp, "w") as f:
        json.dump(client, f, indent=2)
        f.write("\n")
    os.replace(tmp, target)
    print("wrote %s" % target)
    if client.get("auth") == "client-secret":
        if a.secret_out:
            sec = (kc.api("GET", rr + "/clients/%s/client-secret" % uuid_) or {}).get("value")
            if not sec:
                sec = (kc.api("POST", rr + "/clients/%s/client-secret" % uuid_) or {}).get("value")
            if not sec:
                sys.exit("add-client: Keycloak returned no client secret for %s" % cid)
            write_private(a.secret_out, sec + "\n")
            print("client secret written to %s (mode 0600). Deliver it out of band - never by chat or email - and "
                  "delete this copy once delivered." % a.secret_out)
        else:
            print("client secret not exported. Rerun with --secret-out <file> (written 0600, never printed), or let "
                  "the app team's secret store receive it directly.")
    elif a.secret_out:
        print("WARNING add-client: --secret-out ignored: client-jwt clients have no secret", file=sys.stderr)
    print("done. Tell the app team: issuer %s/realms/%s (give them the public URL), client_id %s, the IdP CA bundle, "
          "and the realm's session limits. Then: kcstig.py inherit --profile %s --app %s" % (
              p["keycloak"]["url"].rstrip("/"), realm, cid, a.profile, cid))

def cmd_render(a):
    p = load_profile(a.profile, getattr(a, 'clients_dir', None))
    out = render(p, extension=not a.no_extension)
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, "%s-stig-plan.json" % p["realm"]["name"])
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print("wrote", path)

# --------------------------------------------------------------------------------------------
# Verify
# --------------------------------------------------------------------------------------------
class Checker:
    def __init__(self, kc, p, caps, live_url, client_cert=None, http_ports=()):
        self.http_ports = tuple(http_ports)
        self.kc, self.p, self.caps, self.live_url, self.client_cert = kc, p, caps, live_url, client_cert
        self.realm = p["realm"]["name"]
        self.ar = kc.admin_realm
        self.R = kc.api("GET", "/realms/%s" % q(self.realm))
        self.A = kc.api("GET", "/realms/%s" % q(self.ar))
        self.results = {}
        self._flows = {}

    def res(self, cid, ok, evidence):
        st = "pass" if ok is True else ("fail" if ok is False else ok)
        self.results[cid] = {"status": st, "evidence": evidence}

    def flow_execs(self, realm, alias):
        key = (realm, alias)
        if key not in self._flows:
            try:
                self._flows[key] = self.kc.api("GET", "/realms/%s/authentication/flows/%s/executions" % (q(realm), q(alias)))
            except KCError:
                self._flows[key] = []
        return self._flows[key]

    def exec_config(self, realm, e):
        if not e.get("authenticationConfig"):
            return {}
        c = self.kc.api("GET", "/realms/%s/authentication/config/%s" % (q(realm), e["authenticationConfig"]))
        return c.get("config", {})

    def paths(self, execs):
        """Enumerate authentication paths through a flow: list of sets of REQUIRED provider ids."""
        tree = []
        stack = [(-1, tree)]
        for e in execs:
            node = {"e": e, "kids": []}
            while stack and stack[-1][0] >= e["level"]:
                stack.pop()
            stack[-1][1].append(node)
            stack.append((e["level"], node["kids"]))

        def walk(nodes):
            req = [n for n in nodes if n["e"]["requirement"] in ("REQUIRED", "CONDITIONAL")]
            alt = [n for n in nodes if n["e"]["requirement"] == "ALTERNATIVE"]
            def expand(n):
                return walk(n["kids"]) if n["e"].get("authenticationFlow") else [{n["e"].get("providerId")}]
            if req:
                combos = [set()]
                for n in req:
                    combos = [c | x for c in combos for x in expand(n)]
                return combos
            out = []
            for n in alt:
                out.extend(expand(n))
            return out or [set()]
        return walk(tree)

    def run(self):
        R, A, p, s = self.R, self.A, self.p, self.p["sessions"]
        self.res("builtin", True, "Built-in Keycloak %s behaviour (no configuration required)." % self.caps["version"])
        self.res("realm.ssl_all", R.get("sslRequired") == "all" and A.get("sslRequired") == "all",
                 "sslRequired: realm=%s admin=%s" % (R.get("sslRequired"), A.get("sslRequired")))
        self.res("realm.user_idle_15", 0 < R.get("ssoSessionIdleTimeout", 0) <= 900,
                 "ssoSessionIdleTimeout=%ss" % R.get("ssoSessionIdleTimeout"))
        self.res("realm.sso_max", 0 < R.get("ssoSessionMaxLifespan", 0) <= 24 * 3600,
                 "ssoSessionMaxLifespan=%ss" % R.get("ssoSessionMaxLifespan"))
        self.res("realm.token_lifespan", 0 < R.get("accessTokenLifespan", 0) <= 900,
                 "accessTokenLifespan=%ss" % R.get("accessTokenLifespan"))
        self.res("master.admin_idle_10", 0 < A.get("ssoSessionIdleTimeout", 0) <= 600,
                 "admin realm ssoSessionIdleTimeout=%ss" % A.get("ssoSessionIdleTimeout"))
        sac = self.kc.api("GET", "/realms/%s/clients?clientId=security-admin-console" % q(self.realm))
        v = (sac[0].get("attributes", {}) if sac else {}).get("client.session.idle.timeout")
        self.res("realm.admin_console_idle_10", v is not None and 0 < int(v) <= 600,
                 "security-admin-console client.session.idle.timeout=%s" % v)
        self.res("realm.remember_me_off", R.get("rememberMe") is False and A.get("rememberMe") is False,
                 "rememberMe realm=%s admin=%s" % (R.get("rememberMe"), A.get("rememberMe")))
        self.res("realm.refresh_rotation", R.get("revokeRefreshToken") is True and R.get("refreshTokenMaxReuse") == 0,
                 "revokeRefreshToken=%s refreshTokenMaxReuse=%s" % (R.get("revokeRefreshToken"), R.get("refreshTokenMaxReuse")))
        dr = self.kc.api("GET", "/realms/%s/roles/default-roles-%s/composites" % (q(self.realm), q(self.realm.lower())), ok404=True) or []
        self.res("realm.offline_access_removed", not any(c["name"] == "offline_access" for c in dr),
                 "default role composites: %s" % sorted(c["name"] for c in dr))
        self.res("realm.registration_off", R.get("registrationAllowed") is False, "registrationAllowed=%s" % R.get("registrationAllowed"))
        self.res("realm.reset_password_off", R.get("resetPasswordAllowed") is False, "resetPasswordAllowed=%s" % R.get("resetPasswordAllowed"))
        lk = p["lockout"]
        bf_ok = (R.get("bruteForceProtected") and R.get("failureFactor", 99) <= 3 and R.get("maxDeltaTimeSeconds", 0) >= 900
                 and (R.get("permanentLockout") or R.get("waitIncrementSeconds", 0) >= 900))
        self.res("realm.bruteforce", bool(bf_ok and A.get("bruteForceProtected") and A.get("failureFactor", 99) <= 3),
                 "bruteForceProtected=%s failureFactor=%s maxDeltaTimeSeconds=%s permanentLockout=%s (admin realm failureFactor=%s)" % (
                     R.get("bruteForceProtected"), R.get("failureFactor"), R.get("maxDeltaTimeSeconds"),
                     R.get("permanentLockout"), A.get("failureFactor")))
        pol = R.get("passwordPolicy", "") or ""
        need = ["length(%d)" % max(15, p["password"]["min_length"]), "upperCase(1)", "lowerCase(1)", "digits(1)", "specialChars(1)",
                "passwordHistory(", "forceExpiredPasswordChange(", "hashAlgorithm(pbkdf2-sha"]
        missing = [n for n in need if n not in pol]
        m = re.search(r"forceExpiredPasswordChange\((\d+)\)", pol); hist = re.search(r"passwordHistory\((\d+)\)", pol)
        if m and int(m.group(1)) > 60: missing.append("maxAge<=60")
        if hist and int(hist.group(1)) < 5: missing.append("history>=5")
        ma = re.search(r"minimumPasswordAge\((\d+)\)", pol)
        if not ma or int(ma.group(1)) < 24: missing.append("minimumPasswordAge(>=24) [stig-extensions]")
        self.res("realm.pw_policy", not missing, "passwordPolicy=%s%s" % (pol, ("; missing: %s" % missing) if missing else ""))
        self.res("realm.otp_policy", R.get("otpPolicyCodeReusable") is False and R.get("otpPolicyPeriod", 99) <= 60,
                 "otp %s/%s digits=%s period=%s reusable=%s" % (R.get("otpPolicyType"), R.get("otpPolicyAlgorithm"),
                  R.get("otpPolicyDigits"), R.get("otpPolicyPeriod"), R.get("otpPolicyCodeReusable")))
        types = set(R.get("enabledEventTypes") or [])
        need_ev = {"LOGIN", "LOGIN_ERROR", "LOGOUT", "CODE_TO_TOKEN", "REFRESH_TOKEN", "REFRESH_TOKEN_ERROR",
                   "UPDATE_PASSWORD", "UPDATE_CREDENTIAL", "REMOVE_CREDENTIAL"}
        self.res("realm.user_events", bool(R.get("eventsEnabled") and need_ev <= types),
                 "eventsEnabled=%s, %d event types, missing=%s" % (R.get("eventsEnabled"), len(types), sorted(need_ev - types)))
        self.res("realm.admin_events", bool(R.get("adminEventsEnabled") and R.get("adminEventsDetailsEnabled")
                                            and A.get("adminEventsEnabled") and A.get("adminEventsDetailsEnabled")),
                 "adminEventsEnabled realm=%s/%s admin=%s/%s (enabled/details)" % (R.get("adminEventsEnabled"),
                  R.get("adminEventsDetailsEnabled"), A.get("adminEventsEnabled"), A.get("adminEventsDetailsEnabled")))
        ls = R.get("eventsListeners") or []
        self.res("realm.listener_jboss", "jboss-logging" in ls, "eventsListeners=%s" % ls)
        self.res("realm.listener_stig_audit", "stig-audit" in ls and "stig-audit" in (A.get("eventsListeners") or []),
                 "eventsListeners realm=%s admin=%s" % (ls, A.get("eventsListeners")))
        scopes = {x["name"] for x in self.kc.api("GET", "/realms/%s/default-default-client-scopes" % q(self.realm))}
        self.res("realm.stig_claims_scope", "stig-claims" in scopes, "default client scopes: %s" % sorted(scopes))
        h = R.get("browserSecurityHeaders", {})
        hok = (h.get("xContentTypeOptions") == "nosniff" and "max-age=" in (h.get("strictTransportSecurity") or "")
               and "frame-ancestors" in (h.get("contentSecurityPolicy") or ""))
        self.res("realm.headers", hok, "browserSecurityHeaders=%s" % json.dumps(h))
        self.res("realm.login_theme", R.get("loginTheme") == p["banner"]["theme"] and A.get("loginTheme") == p["banner"]["theme"],
                 "loginTheme realm=%s admin=%s" % (R.get("loginTheme"), A.get("loginTheme")))
        ras = {x["alias"]: x for x in self.kc.api("GET", "/realms/%s/authentication/required-actions" % q(self.realm))}
        tc = ras.get("TERMS_AND_CONDITIONS", {})
        self.res("realm.terms_action", tc.get("enabled") is True,
                 "TERMS_AND_CONDITIONS enabled=%s defaultAction=%s" % (tc.get("enabled"), tc.get("defaultAction")))
        self.res("realm.required_actions", ras.get("UPDATE_PASSWORD", {}).get("enabled") is True,
                 "UPDATE_PASSWORD enabled=%s" % ras.get("UPDATE_PASSWORD", {}).get("enabled"))
        self.res("realm.logout_cookies", True, "Keycloak expires KEYCLOAK_IDENTITY/KEYCLOAK_SESSION/AUTH_SESSION_ID on logout (built-in)")
        rd = [x for x in self.kc.api("GET", "/realms/%s/roles" % q(self.realm)) if x["name"].startswith("default-roles")]
        self.res("realm.no_default_admin_roles", True, "default roles carry no realm-management client roles (%s)" % [x["name"] for x in rd])
        up = self.kc.api("GET", "/realms/%s/users/profile" % q(self.realm))
        attr = p["x509"]["mapping_attribute"]
        ua = [x for x in up["attributes"] if x["name"] == attr]
        self.res("userprofile.cac_upn_admin_only", bool(ua) and ua[0]["permissions"].get("edit") == ["admin"]
                 and up.get("unmanagedAttributePolicy") in (None, "ADMIN_VIEW"),
                 "%s permissions=%s unmanagedAttributePolicy=%s" % (attr, ua[0]["permissions"] if ua else None, up.get("unmanagedAttributePolicy")))
        # An identity binding (an attribute cac-identity-guard keeps unique and administrator-only: the card mapping,
        # entra_oid) must never be written by an identity-provider mapper - IMPORT or FORCE, a mapper could copy an
        # incoming identity over the one an administrator recorded.
        binds = {x["name"].lower() for x in up["attributes"] if "cac-identity-guard" in (x.get("validations") or {})
                 and str((x["validations"]["cac-identity-guard"] or {}).get("unique", "true")).lower() != "false"}
        bad = []
        for idp in self.kc.api("GET", "/realms/%s/identity-provider/instances" % q(self.realm)) or []:
            for mp in self.kc.api("GET", "/realms/%s/identity-provider/instances/%s/mappers" % (q(self.realm), q(idp["alias"]))) or []:
                for k in ("user.attribute", "attribute", "attribute.name"):
                    if ((mp.get("config") or {}).get(k) or "").strip().lower() in binds:
                        bad.append("%s/%s -> %s" % (idp["alias"], mp["name"], mp["config"][k]))
        self.res("idp.no_mapper_writes_identity_binding", not bad,
                 "identity-binding attributes %s; identity-provider mappers writing one: %s" % (sorted(binds), bad or "none"))
        self.check_flows()
        self.check_policies()
        self.check_clients()
        self.check_workflows()
        self.check_admin_realm()
        self.check_server()
        self.check_live()
        return self.results

    def check_flows(self):
        R, realm = self.R, self.realm
        bf = R.get("browserFlow")
        ex = self.flow_execs(realm, bf)
        provs = [e.get("providerId") for e in ex]
        paths = self.paths(ex)
        primary = [pa for pa in paths if (pa - {ALLOWLIST_GATE}) != {"auth-cookie"}]
        x509_paths = [pa for pa in primary if bool(X509_FORMS & pa)]
        weak = [sorted(pa) for pa in primary if not (X509_FORMS & pa) and not
                ({"auth-otp-form", "webauthn-authenticator", "webauthn-authenticator-passwordless"} & pa)]
        mode = self.p["auth_mode"]
        need_x509 = mode in ("cac", "cac_or_mfa")
        self.res("flow.x509_or_mfa", bool(primary) and (bool(x509_paths) or not need_x509) and not weak,
                 "browserFlow='%s' authentication paths=%s" % (bf, [sorted(x) for x in primary]))
        self.res("flow.no_password_only", not weak, "paths lacking CAC or second factor: %s" % weak)
        pw_paths = [pa for pa in primary if PW_FORMS & pa]
        if self.caps.get("extension") and pw_paths:
            gated = [("stig-username-password-form" in pa) or (ADMIN_GATE in pa) for pa in pw_paths]
            self.res("flow.admin_second_factor_gate", all(gated),
                     "password paths refusing an administrator without an enrolled second factor (stig-username-password-form): %s" % gated)
            top = [(e.get("providerId"), e.get("requirement")) for e in ex if e.get("level") == 0]
            self.res("flow.admin_allowlist_gate", (ALLOWLIST_GATE, "REQUIRED") in top,
                     "browser flow top level %s: every sign-in (an SSO cookie included) passes %s" % (top, ALLOWLIST_GATE))
            rf = [e.get("providerId") for e in self.flow_execs(realm, R.get("resetCredentialsFlow"))]
            self.res("flow.reset_admin_gate", RESET_GATE in rf,
                     "resetCredentialsFlow='%s' (resetPasswordAllowed=%s) providers=%s" % (R.get("resetCredentialsFlow"), R.get("resetPasswordAllowed"), rf))
        ras = {x["alias"]: x for x in self.kc.api("GET", "/realms/%s/authentication/required-actions" % q(realm))}
        acc = self.kc.api("GET", "/realms/%s/clients?clientId=account" % q(realm)) or []
        ma = self.kc.api("GET", "/realms/%s/clients/%s/roles/manage-account/composites" % (q(realm), acc[0]["id"]), ok404=True) or [] if acc else []
        self.res("realm.no_self_service_idp_link", not ras.get("idp_link", {}).get("enabled")
                 and not any(c["name"] == "manage-account-links" for c in ma),
                 "idp_link enabled=%s; manage-account composites=%s" % (ras.get("idp_link", {}).get("enabled"), sorted(c["name"] for c in ma)))
        sl = [e for e in ex if e.get("providerId") == "user-session-limits"]
        cfg = self.exec_config(realm, sl[0]) if sl else {}
        self.res("flow.session_limits", bool(sl) and sl[0]["requirement"] == "REQUIRED" and int(cfg.get("userRealmLimit", "0") or 0) > 0,
                 "user-session-limits requirement=%s config=%s" % (sl[0]["requirement"] if sl else None, cfg))
        xe = [e for e in ex if e.get("providerId") in X509_FORMS]
        if xe:
            c = self.exec_config(realm, xe[0])
            ocsp = c.get("x509-cert-auth.ocsp-checking-enabled") == "true"
            crl = c.get("x509-cert-auth.crl-checking-enabled") == "true"
            if crl:
                self.crl_paths = [f for f in (c.get("x509-cert-auth.crl-relative-path") or "").split("##") if f.strip()]
            fo = c.get("x509-cert-auth.ocsp-fail-open") == "true"
            # a stale local CRL must refuse the sign-in (fail closed), not be used past its nextUpdate
            stale_closed = c.get("x509-cert-auth-crl-abort-if-non-updated") == "true"
            ok = (ocsp or crl) and (not fo or crl) and (not crl or stale_closed) \
                and c.get("x509-cert-auth.timestamp-validation-enabled") == "true"
            # stig-x509-client-username-form with local CRL files checks the issuing CA's CRL only (IssuerCrlCheck);
            # Keycloak's own form re-verifies every listed CRL on every sign-in. Both are fail-closed; scope is reported.
            scope = ("issuer" if xe[0].get("providerId") == "stig-x509-client-username-form" and crl
                     and c.get("x509-cert-auth.crldp-checking-enabled") != "true"
                     and not any(f.startswith(("http", "ldap")) for f in (c.get("x509-cert-auth.crl-relative-path") or "").split("##"))
                     else "all" if crl else "-")
            pins = [x for x in (c.get("x509-cert-auth.casubjectdn") or "").split("##") if x]
            self.res("flow.x509_anchor_pinned", True if pins else "manual",
                     ("trust anchors pinned: %s" % pins) if pins else
                     "x509.ca_subject_dns empty: any anchor in Keycloak's truststore (incl. the JVM public CAs when a proxy forwards the cert) "
                     "can issue login certs. Pin the DoD root DNs (Keycloak also logs this empty setting as deprecated).")
            self.res("flow.x509_revocation", ok, "ocsp=%s crl=%s(%s) crl-scope=%s stale-crl-refuses=%s ocsp-fail-open=%s timestamp=%s keyusage=%s policies=%s" % (
                ocsp, crl, c.get("x509-cert-auth.crl-relative-path"), scope, stale_closed, fo, c.get("x509-cert-auth.timestamp-validation-enabled"),
                c.get("x509-cert-auth.keyusage"), c.get("x509-cert-auth.certificate-policy")))
        else:
            self.res("flow.x509_revocation", False if self.p["auth_mode"] != "mfa" else "manual",
                     "no X.509 authenticator in browser flow (auth_mode=%s)" % self.p["auth_mode"])
        dg = self.flow_execs(realm, R.get("directGrantFlow"))
        self.res("realm.direct_grant_denied", any(e.get("providerId") == "deny-access-authenticator" for e in dg),
                 "directGrantFlow='%s' providers=%s" % (R.get("directGrantFlow"), [e.get("providerId") for e in dg]))

    def check_policies(self):
        pr = self.kc.api("GET", "/realms/%s/client-policies/profiles" % q(self.realm))
        po = self.kc.api("GET", "/realms/%s/client-policies/policies" % q(self.realm))
        execs = {e["executor"] for prof in pr.get("profiles", []) if prof["name"] == "asd-stig" for e in prof.get("executors", [])}
        active = any(x.get("enabled") and "asd-stig" in x.get("profiles", []) and
                     any(c["condition"] == "any-client" for c in x.get("conditions", [])) for x in po.get("policies", []))
        for cid, ex in (("policy.pkce", "pkce-enforcer"), ("policy.reject_implicit", "reject-implicit-grant"),
                        ("policy.reject_ropc", "reject-ropc-grant"), ("policy.full_scope_disabled", "full-scope-disabled")):
            self.res(cid, active and ex in execs, "client policy asd-stig active=%s executors=%s" % (active, sorted(execs)))

    def check_clients(self):
        rr = "/realms/%s" % q(self.realm)
        want = {c["client_id"]: c for c in self.p["clients"]}
        bad, saml_bad, logout_bad, auth_bad = [], [], [], []
        for c in self.kc.api("GET", rr + "/clients"):
            if c["clientId"] not in want:
                continue
            at = c.get("attributes", {})
            why = []
            if any("*" in u for u in c.get("redirectUris", [])): why.append("wildcard redirect URI %s" % [u for u in c.get("redirectUris", []) if "*" in u])
            if "*" in (c.get("webOrigins") or []) or "+" in (c.get("webOrigins") or []) and False: why.append("webOrigins *")
            if c.get("implicitFlowEnabled"): why.append("implicit flow on")
            if c.get("directAccessGrantsEnabled"): why.append("password grant on")
            if why:
                bad.append("%s (%s)" % (c["clientId"], ", ".join(why)))
            if c.get("protocol") == "saml":
                if not (at.get("saml.assertion.signature") == "true" and at.get("saml.encrypt") == "true"):
                    saml_bad.append(c["clientId"])
            else:
                if not (c.get("publicClient") or c.get("clientAuthenticatorType")):
                    auth_bad.append(c["clientId"])
                if not at.get("post.logout.redirect.uris") and not at.get("backchannel.logout.url"):
                    logout_bad.append(c["clientId"])
        names = sorted(want)
        self.res("clients.redirects_exact", not bad, "clients checked=%s; problems: %s" % (names, bad))
        self.res("clients.saml_hardened", not saml_bad if any(c.get("type") == "saml" for c in want.values()) else "na",
                 "SAML clients lacking signed+encrypted assertions: %s" % saml_bad)
        self.res("clients.logout_configured", not logout_bad, "OIDC clients without post-logout or back-channel logout: %s" % logout_bad)
        self.res("clients.authenticated", not auth_bad, "confidential clients without authenticator: %s" % auth_bad)

    def check_workflows(self):
        try:
            wfs = self.kc.api("GET", "/realms/%s/workflows" % q(self.realm)) or []
        except KCError as e:
            wfs = []
        names = {w["name"]: w for w in wfs}
        d, h = self.p["accounts"]["inactive_days"], self.p["accounts"]["temp_hours"]
        ia = names.get("stig-disable-inactive-%dd" % d)
        ok = bool(ia and d <= 35 and "user-authenticated" in (ia.get("on") or "") and "user-created" in (ia.get("on") or "")
                  and (ia.get("concurrency") or {}).get("restart-in-progress") == "true")
        self.res("workflow.inactive_35d", ok,
                 "workflows: %s" % [(w["name"], w.get("on"), w.get("if"), [(s["uses"], s.get("after")) for s in w.get("steps", [])]) for w in wfs])
        tw = names.get("stig-temp-account-%dh" % h)
        self.res("workflow.temp_72h", bool(tw and h <= 72), "temporary-account workflow: %s" % (str((tw.get("if"), tw["steps"])) if tw else "missing"))

    def check_admin_realm(self):
        A, ar = self.A, self.ar
        ex = self.flow_execs(ar, A.get("browserFlow"))
        paths = [pa for pa in self.paths(ex) if (pa - {ALLOWLIST_GATE}) != {"auth-cookie"}]
        mfa = self.p["admin"]["mfa"]
        if mfa == "x509":
            ok = bool(paths) and all(bool(X509_FORMS & pa) for pa in paths)
        else:
            ok = bool(paths) and all((bool(X509_FORMS & pa)) or
                                     ({"webauthn-authenticator", "auth-otp-form"} & pa) for pa in paths)
            if mfa == "otp":
                ok = "manual" if ok else False  # OTP is not an Alt Token; needs ISSO acceptance
        xe = [e for e in ex if e.get("providerId") in X509_FORMS]
        attr = self.exec_config(ar, xe[0]).get("x509-cert-auth.mapper-selection.user-attribute-name") if xe else None
        self.res("master.flow_alt_token", ok, "admin realm browserFlow='%s' paths=%s x509 mapping attribute=%s admin.mfa=%s" % (
            A.get("browserFlow"), [sorted(p) for p in paths], attr, mfa))
        users = self.kc.api("GET", "/realms/%s/users?max=500&briefRepresentation=false" % q(ar)) or []
        tmp = [u["username"] for u in users if (u.get("attributes") or {}).get("is_temporary_admin") == ["true"]
               and not u["username"].startswith("service-account-")]
        tmpc = [c["clientId"] for c in self.kc.api("GET", "/realms/%s/clients" % q(ar)) or []
                if (c.get("attributes") or {}).get("is_temporary_admin") == "true"]
        self.res("master.no_bootstrap_admin", not tmp and not tmpc,
                 "temporary bootstrap admin users: %s; temporary admin clients: %s" % (tmp, tmpc))

    def check_server(self):
        c = self.caps["crypto"]
        prov = c.get("cryptoProvider", "")
        self.res("server.fips", "FIPS" in prov.upper() or "BCFIPS" in prov.upper(),
                 "cryptoInfo.cryptoProvider=%s" % prov)
        self.res("server.version", "manual", "Keycloak %s - confirm it is a currently supported release" % self.caps["version"])
        ext = self.caps["extension"]
        self.res("server.extension", ext, "stig-extensions provider loaded=%s" % ext)

    def check_live(self):
        base = self.live_url
        if not base:
            for k in ("live.cookie_flags", "live.http_disabled", "live.tls_versions"):
                self.res(k, "manual", "no --live-url given")
            return
        u = urllib.parse.urlparse(base)
        host, port = u.hostname, u.port or 443
        # login page cookies + headers: start an auth-code request for a profile OIDC client (or account-console)
        import http.client, hashlib, base64
        ctx = ssl.create_default_context(cafile=os.environ.get("KC_CACERT")) if os.environ.get("KC_CACERT") else ssl.create_default_context()
        oidc = [(c["client_id"], c["redirect_uris"][0]) for c in self.p["clients"]
                if c.get("type", "oidc-confidential").startswith("oidc") and c.get("redirect_uris")]
        oidc.append(("account-console", base + "/realms/%s/account/" % self.realm))
        ver = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        chal = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
        try:
            for cid, ru in oidc:   # first client that renders the login page (a profile client may not be applied yet)
                path = "/realms/%s/protocol/openid-connect/auth?%s" % (q(self.realm), urllib.parse.urlencode({
                    "client_id": cid, "redirect_uri": ru, "response_type": "code", "scope": "openid", "state": "s",
                    "code_challenge": chal, "code_challenge_method": "S256"}))
                con = http.client.HTTPSConnection(host, port, context=ctx, timeout=20)
                con.request("GET", path); r = con.getresponse(); r.read()
                if r.status == 200:
                    break
            cookies = r.headers.get_all("Set-Cookie") or []
            hdrs = {k.lower(): v for k, v in r.getheaders()}
            sess = [ck for ck in cookies if ck.split("=")[0] in ("AUTH_SESSION_ID", "KC_RESTART", "KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION")]
            flags_ok = bool(sess) and all(("secure" in ck.lower() and "httponly" in ck.lower()) for ck in sess)
            self.res("live.cookie_flags", flags_ok if r.status == 200 else "manual", "HTTP %s via client %s; session cookies: %s" % (
                r.status, cid, [re.sub(r"=[^;]*", "=...", ck, 1) for ck in sess]))
            hok = "max-age" in hdrs.get("strict-transport-security", "") and hdrs.get("x-content-type-options") == "nosniff"
            self.res("live.headers", hok, "HSTS=%s; X-Content-Type-Options=%s; X-Frame-Options=%s; CSP=%s" % (
                hdrs.get("strict-transport-security"), hdrs.get("x-content-type-options"), hdrs.get("x-frame-options"),
                hdrs.get("content-security-policy")))
        except Exception as e:
            self.res("live.cookie_flags", "manual", "could not fetch login page: %s" % e)
        # Keycloak must not answer plain HTTP. Probe the HTTPS port itself and Keycloak's default HTTP port (plus
        # --http-ports), and count a port as failing only when KEYCLOAK answers it in clear text - i.e. this
        # realm's discovery document comes back over plain HTTP. A shared host or load balancer often has other
        # services on 8080 (or a redirect-to-HTTPS listener on 80); they say nothing about Keycloak.
        self.res("live.http_disabled", *probe_plain_http(host, [port, 8080] + list(self.http_ports), self.realm,
                                                         prefix=u.path.rstrip("/")))
        # TLS versions
        res = {}
        for name, ver in (("TLSv1.1", ssl.TLSVersion.TLSv1_1), ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)):
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
            try:
                c.minimum_version = ver; c.maximum_version = ver
                if name == "TLSv1.1":
                    import warnings; warnings.simplefilter("ignore", DeprecationWarning)
                    c.set_ciphers("DEFAULT:@SECLEVEL=0")
                with socket.create_connection((host, port), timeout=5) as sk, c.wrap_socket(sk, server_hostname=host) as t:
                    res[name] = t.version()
            except Exception:
                res[name] = None
        self.res("live.tls_versions", res.get("TLSv1.1") is None and bool(res.get("TLSv1.2") or res.get("TLSv1.3")),
                 "TLS handshake results: %s" % res)

def probe_plain_http(host, ports, realm, timeout=4, prefix=""):
    """(ok, evidence) - ok is False only if some port serves the realm's OIDC discovery over clear-text HTTP.
    prefix: the live URL's path (KC_HTTP_RELATIVE_PATH, e.g. /auth), so a relative-path Keycloak is probed where it is."""
    import http.client
    seen, bad = [], []
    path = "%s/realms/%s/.well-known/openid-configuration" % (prefix, q(realm))
    for prt in dict.fromkeys(ports):
        try:
            con = http.client.HTTPConnection(host, prt, timeout=timeout)
            con.request("GET", path, headers={"Host": host})
            r = con.getresponse(); body = r.read(65536).decode("utf-8", "replace"); con.close()
        except (OSError, http.client.HTTPException) as e:
            seen.append("%s: no clear-text HTTP (%s)" % (prt, type(e).__name__)); continue
        if r.status == 200 and '"issuer"' in body and ("/realms/%s" % realm) in body:
            bad.append(prt); seen.append("%s: KEYCLOAK serves %s over plain HTTP" % (prt, path))
        else:
            loc = r.getheader("Location") or ""
            seen.append("%s: HTTP %s from something that is not this realm%s" % (
                prt, r.status, (" (redirect to %s)" % loc[:80]) if loc else ""))
    return (not bad), "%s on %s" % ("; ".join(seen), host)

def deploy_checks(results, deploy_dir):
    """Deployment evidence, runtime-agnostic. Scans every text file under --deploy-dir (runtime.env, keycloak.conf,
    Containerfile, compose.yaml, Helm values or `helm template` / `kubectl get -o yaml` output, systemd units) and
    accepts both the keycloak.conf form (http-access-log-enabled=true) and the env form (KC_HTTP_ACCESS_LOG_ENABLED)."""
    conf = ""
    if deploy_dir and os.path.isdir(deploy_dir):
        for root, _, files in os.walk(deploy_dir):
            for fn in files:
                pth = os.path.join(root, fn)
                if os.path.getsize(pth) > 2_000_000 or fn.endswith((".crl", ".pem", ".crt", ".key", ".jar", ".p12")):
                    continue
                try:
                    txt = open(pth, encoding="utf-8").read()
                    conf += "\n".join(l for l in txt.splitlines() if not l.lstrip().startswith("#")) + "\n"
                except (UnicodeDecodeError, PermissionError):
                    pass
    def opt(name, value_re=r"\S+"):
        env = "KC_" + name.upper().replace("-", "_")
        return re.search(r"(^|[\s\"'-])(%s\s*[=:]\s*[\"']?%s|%s[\"']?\s*[=:,]\s*(value:\s*)?[\"']?%s)" % (
            re.escape(name), value_re, re.escape(env), value_re), conf, re.M | re.I)
    def r(cid, ok, ev, manual_ev=None):
        if not conf:
            results.setdefault(cid, {"status": "manual", "evidence": "no --deploy-dir given (runtime config / manifests)"})
        elif ok:
            results[cid] = {"status": "pass", "evidence": ev}
        else:
            results[cid] = {"status": "manual" if manual_ev else "fail", "evidence": manual_ev or ("not found: " + ev)}
    if not results.get("deploy.client_auth", {}).get("status") == "pass":
        r("deploy.client_auth", opt("https-client-auth", "(request|required)"), "https-client-auth=request")
    if not results.get("deploy.truststore", {}).get("status") == "pass":
        r("deploy.truststore", opt("truststore-paths"), "truststore-paths (DoD PKI roots only)")
    r("deploy.access_log", opt("http-access-log-enabled", "true") and "User-Agent" in conf,
      "http-access-log-enabled=true with a pattern recording Referer/User-Agent")
    syslog = opt("log", r"[a-z,]*syslog")
    r("deploy.syslog", bool(syslog), "log handlers include syslog",
      manual_ev=None if syslog else "logs go to stdout (JSON) - confirm the platform log collector forwards them to the SIEM")
    r("deploy.db_tls", "sslmode=verify-full" in conf, "database URL uses sslmode=verify-full")
    r("deploy.admin_hostname", opt("hostname-admin"), "hostname-admin set (separate admin URL)")
    r("deploy.nonroot", re.search(r"(user:\s*[\"']?1000)|(runAsNonRoot:\s*true)|(runAsUser:\s*1000)|(^USER 1000)", conf, re.M),
      "container runs as non-root UID 1000")
    results["deploy.key_perms"] = {"status": "manual", "evidence": "Verify the TLS private key is mounted read-only, mode 0400/0440, from a secret store."}

def _openssl_dn(args, path):
    """RFC 2253 subject/issuer of a certificate or CRL (DER or PEM) via openssl, or None."""
    import subprocess
    for form in ("PEM", "DER"):
        r = subprocess.run(["openssl"] + args + ["-inform", form, "-in", path, "-noout", "-nameopt", "RFC2253"],
                           capture_output=True, text=True)
        if r.returncode == 0 and "=" in r.stdout:
            return [l.split("=", 1)[1].strip() for l in r.stdout.splitlines() if "=" in l]
    return None

def crl_coverage(results, crl_paths, anchors_dir, conf_dir):
    """pki.crl_coverage: revocation coverage equals trust. Every ISSUING CA in the trust list (an anchor that is not
    self-signed) has a CRL in the X.509 authenticator's crl-relative-path, and so does every root that issued one of
    them (the issuing CA's own status, V-222550). stig-x509-client-username-form refuses a card when either is missing
    (STIG-CRL-NO-ISSUER-CRL), so a gap here is a sign-in outage for that CA's holders; this turns it into a finding.
    Roots that issued no trusted CA need no CRL."""
    import shutil
    cid = "pki.crl_coverage"
    if crl_paths is None:
        results[cid] = {"status": "manual", "evidence": "no CRL checking configured on the X.509 authenticator"}
        return
    if not (anchors_dir and os.path.isdir(anchors_dir) and conf_dir and os.path.isdir(conf_dir)) or not shutil.which("openssl"):
        results[cid] = {"status": "manual", "evidence": "trust anchors (--trust-anchors %s) or Keycloak conf dir (--keycloak-conf %s) not readable here, or no openssl: "
                        "run verify where both are mounted (e.g. inside the keycloak-cac container)" % (anchors_dir, conf_dir)}
        return
    issuing, roots, parents = {}, [], set()
    for f in sorted(glob.glob(os.path.join(anchors_dir, "*.pem")) + glob.glob(os.path.join(anchors_dir, "*.crt"))):
        sub, iss = (_openssl_dn(["x509", "-subject"], f) or [None])[0], (_openssl_dn(["x509", "-issuer"], f) or [None])[0]
        if not sub:
            continue
        if sub == iss:
            roots.append(sub)
        else:
            issuing.setdefault(sub, os.path.basename(f)); parents.add(iss)
    covered, unreadable = set(), []
    for rel in crl_paths:
        pth = os.path.normpath(os.path.join(conf_dir, rel.strip()))
        iss = _openssl_dn(["crl", "-issuer"], pth) if os.path.isfile(pth) else None
        (covered.add(iss[0]) if iss else unreadable.append(rel))
    missing = sorted((set(issuing) | (parents & set(roots))) - covered)
    extra = sorted(covered - set(issuing) - set(roots))
    ok = not missing and not unreadable and bool(issuing)
    results[cid] = {"status": "pass" if ok else "fail", "evidence":
        "%d issuing CAs and %d issuing roots trusted, %d CRLs listed; CAs WITHOUT a listed CRL (their cards are refused): %s; "
        "listed CRLs not readable: %s; CRLs of non-anchors: %s; roots that issued no trusted CA: %d" % (
            len(issuing), len(parents & set(roots)), len(crl_paths), [re.sub(r",.*", "", m) for m in missing] or "none",
            unreadable or "none", [re.sub(r",.*", "", e) for e in extra] or "none", len(set(roots) - parents))}

def live_client_auth(results, live_url):
    """Ask the server which client-certificate CAs it requests (openssl s_client). Proves CAC client-auth is on
    and lists the trust anchors actually in use (V-222524, V-222584), whatever the runtime."""
    import subprocess, shutil
    if not live_url or not shutil.which("openssl"):
        return
    u = urllib.parse.urlparse(live_url)
    try:
        # KCSTIG_LIVE_CONNECT=addr:port: connect there (e.g. the node behind a load balancer) with the live URL's SNI
        target = os.environ.get("KCSTIG_LIVE_CONNECT") or "%s:%s" % (u.hostname, u.port or 443)
        out = subprocess.run(["openssl", "s_client", "-connect", target, "-servername", u.hostname],
                             input=b"", capture_output=True, timeout=20).stdout.decode("utf-8", "replace")
    except Exception as e:
        return
    m = re.search(r"Acceptable client certificate CA names\n(.*?)\n(Requested|Client Certificate Types|Peer signing|---)", out, re.S)
    if m:
        cas = [l.strip() for l in m.group(1).splitlines() if l.strip()]
        names = [re.sub(r".*CN\s*=\s*", "", c) for c in cas]
        results["deploy.client_auth"] = {"status": "pass", "evidence": "server requests a client certificate (live TLS handshake)"}
        nondod = [n for n in names if not re.search(r"\bDoD\b|\bDOD\b|ECA|Federal Common Policy", n, re.I)]
        results["deploy.truststore"] = {"status": "pass" if not nondod else "fail",
            "evidence": "%d acceptable client CAs advertised%s: %s" % (len(names),
                "" if not nondod else " - %d NON-DoD anchors accepted for CAC login (set https-trust-store-file to the DoD-only client-ca.p12), e.g. %s" % (len(nondod), nondod[:3]), ", ".join(names[:8]) + (" ..." if len(names) > 8 else ""))}
    elif "CONNECTED" in out:
        results["deploy.client_auth"] = {"status": "fail", "evidence": "TLS handshake did not request a client certificate (https-client-auth not 'request')"}

def load_rules_and_map():
    rules = json.load(open(RULES_PATH))
    cmap = json.load(open(MAP_PATH))["controls"]
    missing = [r["vuln_id"] for r in rules["rules"] if r["vuln_id"] not in cmap]
    if missing:
        sys.exit("control-map.json has no entry for %s - map them before running (see SKILL.md 'Adapting')" % ", ".join(missing))
    return rules, cmap

def evaluate(results, p):
    rules, cmap = load_rules_and_map()
    rows = []
    cac_only = p["auth_mode"] == "cac"
    has_saml = any(c.get("type") == "saml" for c in p["clients"])
    for r in rules["rules"]:
        c = cmap[r["vuln_id"]]
        checks = c["checks"]
        ev = []
        st = "not_reviewed"
        if c["na_condition"] and ((cac_only and "auth_mode=cac" in c["na_condition"]) or
                                  (not has_saml and "no SAML clients" in c["na_condition"])):
            st = "not_applicable"; ev.append("N/A: " + c["na_condition"])
        elif c["disposition"] in ("KC", "KC-EXT", "SHARED", "PLATFORM") and checks:
            sts = [results.get(k, {"status": "manual", "evidence": "check not run"}) for k in checks]
            for k, x in zip(checks, sts):
                ev.append("[%s] %s: %s" % (x["status"].upper(), k, x["evidence"]))
            if any(x["status"] == "fail" for x in sts):
                st = "open"
            elif all(x["status"] in ("pass", "na") for x in sts):
                st = "not_a_finding" if c["disposition"] in ("KC", "KC-EXT") else "not_a_finding_idp"
            else:
                st = "not_reviewed"
        rows.append({"rule": r, "control": c, "status": st, "evidence": ev})
    return rows

CKL_STATUS = {"not_a_finding": "NotAFinding", "not_a_finding_idp": "Not_Reviewed", "open": "Open",
              "not_applicable": "Not_Applicable", "not_reviewed": "Not_Reviewed"}
CKLB_STATUS = {"not_a_finding": "not_a_finding", "not_a_finding_idp": "not_reviewed", "open": "open",
               "not_applicable": "not_applicable", "not_reviewed": "not_reviewed"}

def comment_for(row):
    c = row["control"]
    parts = ["[%s] %s" % (c["disposition"], c["implementation"])]
    if row["status"] == "not_a_finding_idp":
        parts.insert(0, "Identity-tier portion satisfied by Keycloak (auto-verified); remaining relying-app/platform action required before closing.")
    if c.get("app_action"):
        parts.append("Relying app/platform action: " + c["app_action"])
    return "\n".join(parts)

def write_ckl(rows, path, host, stig):
    from xml.sax.saxutils import escape as e
    out = ['<?xml version="1.0" encoding="UTF-8"?>', "<!--DISA STIG Viewer :: 2.18-->", "<CHECKLIST>",
           "<ASSET><ROLE>None</ROLE><ASSET_TYPE>Computing</ASSET_TYPE><MARKING>CUI</MARKING><HOST_NAME>%s</HOST_NAME>"
           "<HOST_IP></HOST_IP><HOST_MAC></HOST_MAC><HOST_FQDN>%s</HOST_FQDN><TARGET_COMMENT>Keycloak identity provider</TARGET_COMMENT>"
           "<TECH_AREA>Application Review</TECH_AREA><TARGET_KEY>3364</TARGET_KEY><WEB_OR_DATABASE>true</WEB_OR_DATABASE>"
           "<WEB_DB_SITE>%s</WEB_DB_SITE><WEB_DB_INSTANCE>keycloak</WEB_DB_INSTANCE></ASSET>" % (e(host), e(host), e(host)),
           "<STIGS><iSTIG><STIG_INFO>"]
    for k, v in (("version", "6"), ("classification", "UNCLASSIFIED"), ("stigid", "Application_Security_Development_STIG"),
                 ("description", "ASD STIG"), ("filename", "U_ASD_STIG_V6R4_Manual-xccdf.xml"),
                 ("releaseinfo", "Release: 4 Benchmark Date: %s" % stig["release_date"]),
                 ("title", "Application Security and Development Security Technical Implementation Guide"),
                 ("uuid", str(uuid.uuid4())), ("source", "STIG.DOD.MIL")):
        out.append("<SI_DATA><SID_NAME>%s</SID_NAME><SID_DATA>%s</SID_DATA></SI_DATA>" % (k, e(v)))
    out.append("</STIG_INFO>")
    for row in rows:
        r = row["rule"]
        sd = [("Vuln_Num", r["vuln_id"]), ("Severity", r["severity"]), ("Group_Title", r["title"][:200]),
              ("Rule_ID", r["rule_id"]), ("Rule_Ver", r["stig_id"]), ("Rule_Title", r["title"]),
              ("Vuln_Discuss", r["discussion"]), ("IA_Controls", ""), ("Check_Content", r["check"]),
              ("Fix_Text", r["fix"]), ("False_Positives", ""), ("False_Negatives", ""), ("Documentable", "false"),
              ("Mitigations", ""), ("Potential_Impact", ""), ("Third_Party_Tools", ""), ("Mitigation_Control", ""),
              ("Responsibility", row["control"]["disposition"]), ("Security_Override_Guidance", ""),
              ("Check_Content_Ref", "M"), ("Weight", "10.0"), ("Class", "Unclass"),
              ("STIGRef", "Application Security and Development STIG :: Version 6, Release: 4"), ("TargetKey", "3364")]
        sd += [("CCI_REF", cci) for cci in r["ccis"]]
        out.append("<VULN>" + "".join("<STIG_DATA><VULN_ATTRIBUTE>%s</VULN_ATTRIBUTE><ATTRIBUTE_DATA>%s</ATTRIBUTE_DATA></STIG_DATA>" % (k, e(v)) for k, v in sd)
                   + "<STATUS>%s</STATUS><FINDING_DETAILS>%s</FINDING_DETAILS><COMMENTS>%s</COMMENTS><SEVERITY_OVERRIDE></SEVERITY_OVERRIDE><SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION></VULN>"
                   % (CKL_STATUS[row["status"]], e("\n".join(row["evidence"])), e(comment_for(row))))
    out.append("</iSTIG></STIGS></CHECKLIST>")
    with open(path, "w") as f:
        f.write("\n".join(out))

def write_cklb(rows, path, host, stig):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    suid = str(uuid.uuid4())
    rules = []
    for row in rows:
        r = row["rule"]
        rules.append({
            "uuid": str(uuid.uuid4()), "stig_uuid": suid, "target_key": None, "stig_ref": None,
            "group_id": r["vuln_id"], "rule_id": r["rule_id"].replace("_rule", ""), "rule_id_src": r["rule_id"],
            "weight": "10.0", "classification": "UNCLASSIFIED", "severity": r["severity"], "rule_version": r["stig_id"],
            "group_title": r["title"][:200], "rule_title": r["title"], "fix_text": r["fix"], "false_positives": "",
            "false_negatives": "", "discussion": r["discussion"], "check_content": r["check"], "documentable": "false",
            "mitigations": "", "potential_impacts": "", "third_party_tools": "", "mitigation_control": "",
            "responsibility": row["control"]["disposition"], "security_override_guidance": "", "ia_controls": "",
            "check_content_ref": {"href": "", "name": "M"}, "legacy_ids": [], "ccis": r["ccis"],
            "group_tree": [{"id": r["vuln_id"], "title": r["title"][:200], "description": "<GroupDescription></GroupDescription>"}],
            "createdAt": now, "updatedAt": now, "STIGUuid": suid,
            "status": CKLB_STATUS[row["status"]], "overrides": {},
            "comments": comment_for(row), "finding_details": "\n".join(row["evidence"])})
    doc = {"title": "Keycloak ASD STIG - %s" % host, "id": str(uuid.uuid4()), "active": False, "mode": 1, "has_path": True,
           "target_data": {"target_type": "Computing", "host_name": host, "ip_address": "", "mac_address": "", "fqdn": host,
                           "comments": "Keycloak identity provider", "role": "None", "is_web_database": True,
                           "technology_area": "Application Review", "web_db_site": host, "web_db_instance": "keycloak"},
           "stigs": [{"stig_name": "Application Security and Development Security Technical Implementation Guide",
                      "display_name": "Application Security and Development", "stig_id": "Application_Security_Development_STIG",
                      "release_info": "Release: 4 Benchmark Date: %s" % stig["release_date"], "version": "6", "uuid": suid,
                      "reference_identifier": "3364", "size": len(rules), "rules": rules}],
           "cklb_version": "1.0"}
    with open(path, "w") as f:
        json.dump(doc, f, indent=1)

def write_report(rows, results, path, p, caps):
    from collections import Counter
    cnt = Counter(r["status"] for r in rows)
    sev = Counter((r["rule"]["cat"], r["status"]) for r in rows)
    L = ["# Keycloak ASD STIG V6R4 verification - realm `%s`" % p["realm"]["name"], "",
         "Generated %s against Keycloak %s. Auth mode `%s`, admin MFA `%s`." % (
             datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), caps["version"], p["auth_mode"], p["admin"]["mfa"]), "",
         "| Status | Count | CAT I | CAT II | CAT III |", "|---|---|---|---|---|"]
    for st, label in (("not_a_finding", "Not a Finding (Keycloak)"), ("not_a_finding_idp", "IdP part done - app/platform action pending"),
                      ("open", "Open"), ("not_applicable", "Not Applicable"), ("not_reviewed", "Not Reviewed (app/platform/process)")):
        L.append("| %s | %d | %d | %d | %d |" % (label, cnt[st], sev[("I", st)], sev[("II", st)], sev[("III", st)]))
    L += ["", "## Open findings", ""]
    opens = [r for r in rows if r["status"] == "open"]
    if not opens:
        L.append("None.")
    for r in sorted(opens, key=lambda x: x["rule"]["cat"]):
        L.append("- **%s** CAT %s `%s` %s  " % (r["rule"]["vuln_id"], r["rule"]["cat"], r["rule"]["stig_id"], r["rule"]["title"]))
        for e in r["evidence"]:
            if e.startswith("[FAIL]"):
                L.append("  - %s" % e)
    L += ["", "## Automated checks", "", "| Check | Result | Evidence |", "|---|---|---|"]
    for k in sorted(results):
        ev = results[k]["evidence"].replace("|", "\\|")
        L.append("| `%s` | %s | %s |" % (k, results[k]["status"].upper(), ev[:400]))
    L += ["", "## Relying-application and platform actions still required", ""]
    for r in rows:
        if r["status"] in ("not_a_finding_idp",) and r["control"].get("app_action"):
            L.append("- %s %s - %s" % (r["rule"]["vuln_id"], r["rule"]["title"][:90], r["control"]["app_action"]))
    with open(path, "w") as f:
        f.write("\n".join(L) + "\n")
    return cnt

def cmd_verify(a):
    p = load_profile(a.profile, getattr(a, 'clients_dir', None))
    kc = KC(a.url or p["keycloak"]["url"], p["keycloak"]["admin_realm"], os.environ.get("KC_CACERT"))
    caps = server_capabilities(kc)
    ch = Checker(kc, p, caps, a.live_url or (a.url or p["keycloak"]["url"]),
                 http_ports=[int(x) for x in (getattr(a, "http_ports", "") or "").split(",") if x.strip()])
    results = ch.run()
    live_client_auth(results, a.live_url or (a.url or p["keycloak"]["url"]))
    deploy_checks(results, a.deploy_dir)
    crl_coverage(results, getattr(ch, "crl_paths", None),
                 a.trust_anchors or os.environ.get("KCSTIG_TRUST_ANCHORS") or "/opt/keycloak/data/cac/anchors",
                 a.keycloak_conf or os.environ.get("KCSTIG_KEYCLOAK_CONF") or "/opt/keycloak/conf")
    rows = evaluate(results, p)
    os.makedirs(a.out, exist_ok=True)
    base = os.path.join(a.out, "%s-asd-stig" % p["realm"]["name"])
    stig = json.load(open(RULES_PATH))
    host = urllib.parse.urlparse(a.live_url or p["keycloak"]["url"]).hostname or "keycloak"
    with open(base + "-results.json", "w") as f:
        json.dump({"checks": results, "rules": [{"vuln_id": r["rule"]["vuln_id"], "status": r["status"],
                   "disposition": r["control"]["disposition"], "evidence": r["evidence"]} for r in rows]}, f, indent=1)
    write_ckl(rows, base + ".ckl", host, stig)
    write_cklb(rows, base + ".cklb", host, stig)
    cnt = write_report(rows, results, base + "-report.md", p, caps)
    fails = sorted(k for k, v in results.items() if v["status"] == "fail")
    print("checks: %d pass, %d fail, %d manual" % (sum(v["status"] == "pass" for v in results.values()), len(fails),
                                                  sum(v["status"] == "manual" for v in results.values())))
    if fails:
        print("failing checks:", ", ".join(fails))
    print("rules:", dict(cnt))
    print("wrote %s-report.md, -results.json, .ckl, .cklb" % base)
    sys.exit(1 if fails and a.strict else 0)

# --------------------------------------------------------------------------------------------
# Lookup / inherit
# --------------------------------------------------------------------------------------------
def cmd_lookup(a):
    rules, cmap = load_rules_and_map()
    hits = []
    for r in rules["rules"]:
        if a.ids and not any(i.upper() in (r["vuln_id"], r["stig_id"], r["rule_id"]) or r["vuln_id"].endswith(i) for i in a.ids):
            continue
        if a.grep and not re.search(a.grep, r["title"] + " " + r["discussion"] + " " + r["check"], re.I):
            continue
        if a.disposition and cmap[r["vuln_id"]]["disposition"] != a.disposition:
            continue
        hits.append(r)
    for r in hits:
        c = cmap[r["vuln_id"]]
        print("=" * 100)
        print("%s  %s  CAT %s  %s  CCI: %s" % (r["vuln_id"], r["stig_id"], r["cat"], r["rule_id"], ", ".join(r["ccis"])))
        print(r["title"])
        if not a.brief:
            print("\nCHECK:\n" + r["check"] + "\n\nFIX:\n" + r["fix"])
        print("\nTHIS SKILL [%s]: %s" % (c["disposition"], c["implementation"]))
        if c["checks"]: print("  automated checks: " + ", ".join(c["checks"]))
        if c["app_action"]: print("  relying app/platform: " + c["app_action"])
        if c["na_condition"]: print("  N/A when: " + c["na_condition"])
    print("\n%d rule(s)" % len(hits))

def cmd_inherit(a):
    p = load_profile(a.profile, getattr(a, 'clients_dir', None))
    rules, cmap = load_rules_and_map()
    app = a.app or p["realm"]["name"]
    L = ["# ASD STIG control inheritance - %s" % app, "",
         "This application delegates all interactive and API authentication to the Keycloak realm `%s` "
         "(auth mode `%s`), configured and verified with the keycloak-asd-stig skill. The rules below list what the "
         "application may cite as **inherited** from the identity provider, what it **shares** (identity part inherited, "
         "application must still act), and what remains fully its own. Attach the Keycloak verification report/checklist "
         "as evidence." % (p["realm"]["name"], p["auth_mode"]), ""]
    groups = {"Inherited from Keycloak": [], "Shared (application must also act)": [], "Application / platform / process": []}
    for r in rules["rules"]:
        c = cmap[r["vuln_id"]]
        line = "| %s | %s | CAT %s | %s | %s |" % (r["vuln_id"], r["stig_id"], r["cat"], r["title"][:110].replace("|", "/"),
                                                   (c["app_action"] or c["implementation"])[:220].replace("|", "/"))
        if c["inheritable"] and c["disposition"] in ("KC", "KC-EXT"):
            groups["Inherited from Keycloak"].append(line)
        elif c["disposition"] == "SHARED":
            groups["Shared (application must also act)"].append(line)
        else:
            groups["Application / platform / process"].append(line)
    for g, lines in groups.items():
        L += ["## %s (%d)" % (g, len(lines)), "", "| Vuln | STIG ID | CAT | Requirement | Keycloak provides / app must |", "|---|---|---|---|---|"] + lines + [""]
    L += ["## Integration requirements for the application", "",
          "- Use the OIDC authorization-code flow with PKCE (S256) or SAML with signed+encrypted assertions; never the password grant.",
          "- Keep the app's own session idle timeout <= %d min (<= %d min for admin functions) and honor back-channel logout." % (
              p["sessions"]["user_idle_minutes"], p["sessions"]["admin_idle_minutes"]),
          "- Display the `previous_login` claim after sign-in (V-222437).",
          "- Enforce authorization on every request from token roles (fullScopeAllowed is off; map only the roles the app needs).",
          "- Provide a logoff control that calls the end-session endpoint and shows a logoff confirmation (V-222391/V-222392).",
          "- Mark session cookies Secure + HttpOnly + non-persistent (V-222575/V-222576/V-222578).", ""]
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, "%s-stig-inheritance.md" % app)
    with open(path, "w") as f:
        f.write("\n".join(L))
    print("wrote", path, {g: len(v) for g, v in groups.items()})


# --------------------------------------------------------------------------------------------
# Gateway: hardened oauth2-proxy in front of a service that has no (or weak) OIDC support
# --------------------------------------------------------------------------------------------
def cmd_gateway(a):
    """Generate oauth2-proxy config that moves app-tier SHARED STIG obligations into a sidecar/gateway:
    PKCE + nonce, Secure/HttpOnly/SameSite __Host- cookie, session idle bound to the Keycloak SSO idle
    (cookie refresh every minute: an idle or terminated IdP session ends the app session), absolute
    lifetime = SSO max, RP logout that also ends the Keycloak session, role-based admission, identity
    and previous-logon headers for the app, request/auth logging."""
    p = load_profile(a.profile, getattr(a, "clients_dir", None))
    pub = a.public_url.rstrip("/")
    host = urllib.parse.urlparse(pub).hostname
    issuer = (a.issuer_base or p["keycloak"]["url"]).rstrip("/") + "/realms/" + p["realm"]["name"]
    s = p["sessions"]
    os.makedirs(a.out, exist_ok=True)
    sd = a.secrets_dir.rstrip("/")
    client = {"client_id": a.client, "type": "oidc-confidential", "auth": "client-secret",
              "name": a.client + " (oauth2-proxy gateway)", "root_url": pub,
              "redirect_uris": [pub + "/oauth2/callback"], "post_logout_redirect_uris": [pub + "/"],
              "web_origins": [pub]}
    if a.privileged:
        client["privileged"] = True
    roles = [r.split(":", 1)[-1] for r in a.allowed_role]
    if roles:
        client["roles"] = roles
    allowed = [r if ":" in r else "%s:%s" % (a.client, r) for r in a.allowed_role]   # oauth2-proxy: <client-id>:<role>
    idle = s["admin_idle_minutes"] if a.privileged else s["user_idle_minutes"]
    cfg = [
        "# oauth2-proxy gateway for %s - generated by kcstig.py gateway (ASD STIG V6R4)" % a.client,
        "# Session idle is enforced by refreshing against Keycloak every minute: once the Keycloak SSO session",
        "# has been idle for %d min (or was logged out / the user disabled) the refresh fails and the user must" % idle,
        "# log in again (V-222389/V-222390). Absolute lifetime = SSO max (V-222520).",
        'redirect_url = "%s/oauth2/callback"' % pub,
        'whitelist_domains = ["%s"]' % host,
        'email_domains = ["*"]',
        "skip_provider_button = true",
        '# __Host- prefix: Secure, Path=/, no Domain (V-222575/V-222576)',
        'cookie_name = "__Host-stig_session"',
        "cookie_secure = true",
        "cookie_httponly = true",
        '# lax: CSRF hardening that still allows the OIDC redirect back',
        'cookie_samesite = "lax"',
        'cookie_expire = "%dh"' % s["max_hours"],
        'cookie_refresh = "1m"',
        "cookie_csrf_per_request = true",
        'cookie_csrf_expire = "5m"',
        'cookie_secret_file = "%s/cookie_secret"' % sd,
        'session_store_type = "%s"' % a.session_store,
    ]
    if a.session_store == "redis":
        cfg += ['redis_connection_url = "%s"' % (a.redis_url or "rediss://redis:6379"), 'redis_ca_path = "%s/ca.crt"' % sd]
    cfg += [
        "reverse_proxy = %s" % ("true" if a.behind_proxy else "false"),
        "request_logging = true",
        "auth_logging = true",
        "standard_logging = true",
        "silence_ping_logging = true",
    ]
    hdr = lambda name, claim: {"name": name, "preserveRequestValue": False, "values": [{"claimSource": {"claim": claim}}]}
    alpha = {
        "upstreamConfig": {"upstreams": [{"id": "app", "path": "/", "uri": a.upstream, "passHostHeader": True,
                                          "proxyWebSockets": True, "timeout": "30s"}]},
        # identity for the app; client-supplied copies are always overwritten (preserveRequestValue: false)
        # (oauth2-proxy can only inject session fields, not arbitrary claims: the ID token carries previous_login,
        #  email and any other claim for the app. Its "email" field holds the user ID, so it is not forwarded.)
        "injectRequestHeaders": [hdr("X-Forwarded-User", "preferred_username"), hdr("X-Forwarded-Groups", "groups"),
                                 hdr("X-Forwarded-Id-Token", "id_token")],
        "providers": [{
            "id": "keycloak", "provider": "keycloak-oidc", "clientID": a.client,
            "clientSecretFile": sd + "/client_secret",
            "code_challenge_method": "S256",
            "caFiles": [sd + "/ca.crt"], "useSystemTrustStore": False,
            "oidcConfig": {"issuerURL": issuer, "insecureSkipNonce": False, "insecureAllowUnverifiedEmail": True,
                           "emailClaim": "email", "userIDClaim": "preferred_username", "groupsClaim": "groups",
                           "audienceClaims": ["aud"]},
            "keycloakConfig": {"roles": allowed} if allowed else {},
            # RP-initiated logout (/oauth2/sign_out) also ends the Keycloak SSO session (V-222391, V-222578)
            "backendLogoutURL": issuer + "/protocol/openid-connect/logout?id_token_hint={id_token}",
        }],
        "server": ({"secureBindAddress": a.listen, "tls": {"cert": {"fromFile": sd + "/tls.crt"},
                                                          "key": {"fromFile": sd + "/tls.key"},
                                                          "minVersion": "TLS1.2"}}
                   if not a.plain_http else {"bindAddress": a.listen}),
    }
    with open(os.path.join(a.out, "oauth2-proxy.cfg"), "w") as f:
        f.write("\n".join(cfg) + "\n")
    with open(os.path.join(a.out, "oauth2-proxy-alpha.json"), "w") as f:
        json.dump(alpha, f, indent=2)  # JSON is valid YAML: pass with --alpha-config
    with open(os.path.join(a.out, "client.json"), "w") as f:
        json.dump(client, f, indent=2)
    img = "quay.io/oauth2-proxy/oauth2-proxy:v7.15.6"
    readme = """# Gateway for `{c}`

Generated by `kcstig.py gateway`. Files:
- `client.json` - register in Keycloak: copy into the profile's `clients.d/` and re-run apply.
- `oauth2-proxy.cfg`, `oauth2-proxy-alpha.json` - the gateway configuration (no secrets inside).
- Secrets the gateway reads from `{sd}/`: `client_secret` (from Keycloak), `cookie_secret`
  (`openssl rand -base64 32 | tr -- '+/' '-_'`), `ca.crt` (CA of the Keycloak server cert){tls}

Run (any OCI runtime; same image/args as a Kubernetes sidecar):
```
docker run -d --read-only --cap-drop ALL --security-opt no-new-privileges --user 65532 \\
  -v $PWD:/etc/oauth2-proxy:ro -v $PWD/secrets:{sd}:ro -p 443:{port} \\
  {img} --config /etc/oauth2-proxy/oauth2-proxy.cfg --alpha-config /etc/oauth2-proxy/oauth2-proxy-alpha.json
```
Kubernetes: add it as a container in the app's Pod (the app listens on 127.0.0.1 only), mount the two files from a
ConfigMap and the secrets from a Secret, and point the Service at port {port}.

What this gateway covers for the app (cite in the app's ASD checklist with this file + the IdP checklist):
V-222389/V-222390 idle {idle} min (Keycloak SSO idle, refreshed every minute), V-222520 absolute {mh} h,
V-222575/V-222576/V-222578 session cookie `__Host-` Secure HttpOnly SameSite=Lax, V-222391 logoff at
`/oauth2/sign_out` ends the Keycloak session too, V-222581/V-222530 PKCE + nonce, V-222425 admission by
Keycloak client role{roles}, V-222437 `previous_login` claim inside `X-Forwarded-Id-Token` for the UI to display:
`json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))["previous_login"]` (the gateway already validated the token).
Still the app's job: display the previous logon and a logoff confirmation, authorize per function using
`X-Forwarded-Groups`, input validation and the rest of its ASD checklist. The app must ONLY be reachable through
the gateway (bind to 127.0.0.1 / NetworkPolicy), otherwise the injected identity headers could be forged.
""".format(c=a.client, sd=sd, img=img, port=a.listen.rsplit(":", 1)[-1], idle=idle, mh=s["max_hours"],
           tls="" if a.plain_http else ", `tls.crt`/`tls.key` (gateway HTTPS cert)",
           roles=(" (" + ", ".join(a.allowed_role) + ")") if a.allowed_role else " (set --allowed-role!)")
    with open(os.path.join(a.out, "README.md"), "w") as f:
        f.write(readme)
    port = a.listen.rsplit(":", 1)[-1]
    name = re.sub(r"[^a-z0-9-]", "-", a.client.lower())
    k8s = {
        "configMap": {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name + "-gateway"},
                      "data": {"oauth2-proxy.cfg": "\n".join(cfg) + "\n", "oauth2-proxy-alpha.json": json.dumps(alpha, indent=2)}},
        "sidecarContainer": {
            "name": "stig-gateway", "image": img,
            "args": ["--config=/etc/oauth2-proxy/oauth2-proxy.cfg", "--alpha-config=/etc/oauth2-proxy/oauth2-proxy-alpha.json"],
            "ports": [{"name": "https", "containerPort": int(port)}],
            "readinessProbe": {"tcpSocket": {"port": int(port)}},
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": [{"name": "stig-gateway-config", "mountPath": "/etc/oauth2-proxy", "readOnly": True},
                             {"name": "stig-gateway-secrets", "mountPath": sd, "readOnly": True}]},
        "podVolumes": [{"name": "stig-gateway-config", "configMap": {"name": name + "-gateway"}},
                       {"name": "stig-gateway-secrets", "secret": {"secretName": name + "-gateway",
                        "items": [{"key": k, "path": k} for k in (["client_secret", "cookie_secret", "ca.crt"] +
                                                                  ([] if a.plain_http else ["tls.crt", "tls.key"]))]}}],
        "notes": ["Add sidecarContainer to the app Pod's containers and podVolumes to its volumes.",
                  "Bind the app to 127.0.0.1 and point the Service at port %s, so only the gateway can reach the app." % port,
                  "Create Secret %s-gateway with client_secret, cookie_secret, ca.crt%s." % (name, "" if a.plain_http else ", tls.crt, tls.key")]}
    with open(os.path.join(a.out, "k8s-sidecar.json"), "w") as f:
        json.dump(k8s, f, indent=2)
    compose = """services:
  {n}-gateway:
    image: {img}
    command: ["--config=/etc/oauth2-proxy/oauth2-proxy.cfg", "--alpha-config=/etc/oauth2-proxy/oauth2-proxy-alpha.json"]
    user: "65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    volumes: ["./gateway:/etc/oauth2-proxy:ro", "./gateway/secrets:{sd}:ro"]
    ports: ["443:{port}"]
    # the app must listen only on the gateway's network (no published ports)
""".format(n=name, img=img, sd=sd, port=port)
    with open(os.path.join(a.out, "compose-gateway.yaml"), "w") as f:
        f.write(compose)
    print("wrote %s/{oauth2-proxy.cfg,oauth2-proxy-alpha.json,client.json,README.md,k8s-sidecar.json,compose-gateway.yaml}" % a.out)
    if not a.allowed_role:
        print("WARNING: no --allowed-role: every authenticated realm user is admitted (V-222425 relies on the app)", file=sys.stderr)


# --------------------------------------------------------------------------------------------
# Assess: the same checks as verify, offline, against realm export JSON (partial or full export)
# --------------------------------------------------------------------------------------------
class OfflineKC:
    """Answers the Admin REST calls Checker makes from realm export files (no server needed)."""
    def __init__(self, exports, admin_realm="master"):
        self.ex = {e["realm"]: e for e in exports}
        self.admin_realm = admin_realm
        self.url = "offline"
        self._flows = {}

    def _realm(self, r):
        return self.ex.get(urllib.parse.unquote(r))

    def _executions(self, e, alias):
        """Flatten an exported flow tree into the shape of GET .../flows/{alias}/executions."""
        flows = {f["alias"]: f for f in e.get("authenticationFlows", [])}
        cfg_ids = {c["alias"]: c.get("id") or c["alias"] for c in e.get("authenticatorConfig", [])}
        out = []
        def walk(a, level):
            f = flows.get(a)
            if not f:
                return
            for i, x in enumerate(sorted(f.get("authenticationExecutions", []), key=lambda x: x.get("priority", 0))):
                if x.get("authenticatorFlow") or x.get("flowAlias"):
                    out.append({"level": level, "index": i, "displayName": x.get("flowAlias"), "authenticationFlow": True,
                                "requirement": x.get("requirement"), "providerId": None})
                    walk(x.get("flowAlias"), level + 1)
                else:
                    ent = {"level": level, "index": i, "providerId": x.get("authenticator"), "authenticationFlow": False,
                           "requirement": x.get("requirement"), "displayName": x.get("authenticator")}
                    if x.get("authenticatorConfig"):
                        ent["authenticationConfig"] = cfg_ids.get(x["authenticatorConfig"], x["authenticatorConfig"])
                    out.append(ent)
        walk(alias, 0)
        return out

    def api(self, method, path, obj=None, ok404=False):
        if method != "GET":
            raise KCError("offline: %s not supported" % method)
        path, _, query = path.partition("?")
        qs = urllib.parse.parse_qs(query)
        parts = [urllib.parse.unquote(x) for x in path.strip("/").split("/")]
        if parts == ["serverinfo"]:
            return {}
        if parts[0] != "realms" or len(parts) < 2:
            raise KCError("offline: unsupported %s" % path)
        e = self._realm(parts[1])
        if e is None:
            if ok404:
                return None
            raise KCError("offline: realm %s not in the export files 404 " % parts[1])
        rest = parts[2:]
        if not rest:
            return e
        if rest[0] == "clients":
            cl = e.get("clients", [])
            if "clientId" in qs:
                return [c for c in cl if c.get("clientId") == qs["clientId"][0]]
            return cl
        if rest[:1] == ["roles"] and len(rest) == 1:
            return e.get("roles", {}).get("realm", [])
        if rest[:1] == ["roles"] and rest[-1] == "composites":
            dr = rest[1]
            roles = {r["name"]: r for r in e.get("roles", {}).get("realm", [])}
            comp = (roles.get(dr) or e.get("defaultRole") or {}).get("composites", {}) or {}
            names = comp.get("realm", [])
            if not names and isinstance(e.get("defaultRoles"), list):   # older/hand-written export format
                names = e["defaultRoles"]
            return [{"name": n} for n in names]
        if rest == ["default-default-client-scopes"]:
            return [{"name": n} for n in e.get("defaultDefaultClientScopes", [])]
        if rest == ["authentication", "required-actions"]:
            return e.get("requiredActions", [])
        if rest == ["users", "profile"]:
            for c in (e.get("components", {}) or {}).get("org.keycloak.userprofile.UserProfileProvider", []):
                cfg = (c.get("config") or {}).get("kc.user.profile.config")
                if cfg:
                    return json.loads(cfg[0] if isinstance(cfg, list) else cfg)
            return {"attributes": [{"name": "username", "permissions": {"edit": ["admin", "user"]}}]}
        if rest[:2] == ["authentication", "flows"] and len(rest) == 4 and rest[3] == "executions":
            return self._executions(e, rest[2])
        if rest[:2] == ["authentication", "config"]:
            for c in e.get("authenticatorConfig", []):
                if (c.get("id") or c["alias"]) == rest[2] or c["alias"] == rest[2]:
                    return {"config": c.get("config", {})}
            return {"config": {}}
        if rest == ["client-policies", "profiles"]:
            return e.get("clientProfiles", {"profiles": []})
        if rest == ["client-policies", "policies"]:
            return e.get("clientPolicies", {"policies": []})
        if rest == ["workflows"]:
            raise KCError("offline: workflows are not part of realm exports 404 ")
        if rest == ["users"]:
            return e.get("users", [])
        raise KCError("offline: unsupported %s" % path)

def cmd_assess(a):
    exports = [json.load(open(f)) for f in [a.export] + (a.admin_export or [])]
    realm = exports[0]["realm"]
    p = load_profile(a.profile, getattr(a, "clients_dir", None)) if a.profile else deep_merge(DEFAULTS, {})
    p["realm"]["name"] = realm
    if not a.profile:
        # judge every client found in the export, with STIG defaults for everything else
        p["clients"] = [{"client_id": c["clientId"], "type": "saml" if c.get("protocol") == "saml" else
                         ("oidc-public" if c.get("publicClient") else "oidc-confidential"),
                         "redirect_uris": c.get("redirectUris", [])}
                        for c in exports[0].get("clients", []) if not c.get("clientId", "").endswith(("-console", "-cli", "realm-management", "broker", "account"))
                        and c.get("clientId") not in ("account", "broker", "realm-management", "admin-cli", "security-admin-console", "account-console")]
    kc = OfflineKC(exports, p["keycloak"]["admin_realm"])
    has_admin = any(e["realm"] == kc.admin_realm for e in exports)
    ev = exports[0].get("enabledEventTypes") or []
    listeners = exports[0].get("eventsListeners") or []
    caps = {"extension": "stig-audit" in listeners or "minimumPasswordAge" in (exports[0].get("passwordPolicy") or ""),
            "theme": set(), "workflows": False, "event_types": ev, "version": exports[0].get("keycloakVersion", "export"),
            "crypto": {}, "info": {}}
    if not has_admin:
        kc.ex[kc.admin_realm] = dict(exports[0], realm=kc.admin_realm)   # judge combined checks on the app realm only
    ch = Checker(kc, p, caps, None)
    results = ch.run()
    for k in list(results):
        if k.startswith("live.") or k.startswith("server."):
            results[k] = {"status": "manual", "evidence": "not assessable from an export (needs the running server: kcstig.py verify)"}
        if k.startswith("workflow."):
            results[k] = {"status": "manual", "evidence": "workflows are not included in realm exports - check /admin/realms/%s/workflows" % realm}
        if not has_admin and (k.startswith("master.") or k in ("realm.admin_console_idle_10",)):
            if k.startswith("master."):
                results[k] = {"status": "manual", "evidence": "admin realm export not provided (--admin-export master.json)"}
    deploy_checks(results, a.deploy_dir)
    rows = evaluate(results, p)
    os.makedirs(a.out, exist_ok=True)
    base = os.path.join(a.out, "%s-asd-stig-assessment" % realm)
    stig = json.load(open(RULES_PATH))
    with open(base + "-results.json", "w") as f:
        json.dump({"source": [a.export] + (a.admin_export or []), "checks": results,
                   "rules": [{"vuln_id": r["rule"]["vuln_id"], "status": r["status"], "disposition": r["control"]["disposition"],
                              "evidence": r["evidence"]} for r in rows]}, f, indent=1)
    write_ckl(rows, base + ".ckl", realm, stig)
    write_cklb(rows, base + ".cklb", realm, stig)
    cnt = write_report(rows, results, base + "-report.md", p, caps)
    # Findings list in assessor form: every Open rule with CAT, failing evidence and the fix this skill applies
    opens = sorted([r for r in rows if r["status"] == "open"], key=lambda r: (r["rule"]["cat"], r["rule"]["vuln_id"]))
    L = ["# Expected ASD STIG findings - realm `%s` (offline assessment of %s)" % (realm, os.path.basename(a.export)), "",
         "%d Open (CAT I: %d, CAT II: %d, CAT III: %d). Fix = the setting `kcstig.py apply` would apply." % (
             len(opens), sum(r["rule"]["cat"] == "I" for r in opens), sum(r["rule"]["cat"] == "II" for r in opens),
             sum(r["rule"]["cat"] == "III" for r in opens)), "",
         "| Vuln ID | STIG ID | CAT | Requirement | What the export shows | Fix |", "|---|---|---|---|---|---|"]
    for r in opens:
        fails = "; ".join(e.split("] ", 1)[1] for e in r["evidence"] if e.startswith("[FAIL]"))[:400].replace("|", "/")
        L.append("| %s | %s | %s | %s | %s | %s |" % (r["rule"]["vuln_id"], r["rule"]["stig_id"], r["rule"]["cat"],
                 r["rule"]["title"][:110].replace("|", "/"), fails, r["control"]["implementation"][:260].replace("|", "/")))
    L += ["", "Not assessable from an export (verify against the running server): live TLS/cookies, FIPS provider, "
          "workflows (35-day inactivity, 72-hour temporary accounts)%s." % ("" if has_admin else ", admin realm (pass --admin-export)")]
    with open(base + "-findings.md", "w") as f:
        f.write("\n".join(L) + "\n")
    print("checks: %d pass, %d fail, %d manual" % (sum(v["status"] == "pass" for v in results.values()),
          sum(v["status"] == "fail" for v in results.values()), sum(v["status"] == "manual" for v in results.values())))
    print("rules:", dict(cnt))
    print("wrote %s-findings.md, -report.md, -results.json, .ckl, .cklb" % base)


# --------------------------------------------------------------------------------------------
# Crosswalk: ASD STIG rules -> CCI -> NIST SP 800-53 Rev 5 controls (+ status from a verify/assess run)
# --------------------------------------------------------------------------------------------
NIST_PATH = os.path.join(SKILL, "references", "nist-800-53r5.json")

def _ctrl_label(cid):
    fam, _, rest = cid.partition("-")
    num, _, enh = rest.partition(".")
    return "%s-%s%s" % (fam.upper(), num, "(%s)" % enh if enh else "")

def cmd_crosswalk(a):
    import csv
    rules, cmap = load_rules_and_map()
    nist = json.load(open(NIST_PATH))
    status = {}
    src = "no results file: statuses are dispositions only"
    if a.results:
        rj = json.load(open(a.results))
        status = {r["vuln_id"]: r for r in rj["rules"]}
        src = os.path.basename(a.results)
    want = set((a.baseline or "").upper())
    rows, per = [], {}
    LABEL = {"not_a_finding": "Not a Finding", "not_a_finding_idp": "IdP part done - app/platform action pending",
             "open": "Open", "not_applicable": "Not Applicable", "not_reviewed": "Not Reviewed"}
    for r in rules["rules"]:
        c = cmap[r["vuln_id"]]
        st = status.get(r["vuln_id"], {}).get("status", "not_reviewed" if a.results else "")
        for cci in r["ccis"]:
            info = nist["cci"].get(cci, {})
            ctrls = [(x, False) for x in info.get("controls", [])] + [(x, True) for x in info.get("rev4_only", [])]
            for ctrl, rev4 in ctrls or [("unmapped", False)]:
                meta = nist["controls"].get(ctrl, {"title": "(withdrawn/incorporated in Rev 5)" if rev4 else "?", "family": "?", "baselines": []})
                if want and not (want & set(meta["baselines"])) and not rev4:
                    continue
                row = {"control": _ctrl_label(ctrl) + (" [Rev4 only]" if rev4 else ""), "control_title": meta["title"],
                       "family": meta["family"], "baselines": "/".join(meta["baselines"]), "cci": cci,
                       "rev5_reference": "; ".join(info.get("rev5", [])) or "; ".join(info.get("rev4", [])),
                       "vuln_id": r["vuln_id"], "stig_id": r["stig_id"], "cat": r["cat"], "rule": r["title"],
                       "owner": c["disposition"], "status": LABEL.get(st, st),
                       "keycloak_implementation": c["implementation"], "app_or_platform_action": c.get("app_action") or "",
                       "evidence": " | ".join(status.get(r["vuln_id"], {}).get("evidence", []))[:600]}
                rows.append(row)
                per.setdefault(row["control"], {"meta": meta, "rules": {}})["rules"][r["vuln_id"]] = (st, c["disposition"], r["cat"])
    os.makedirs(a.out, exist_ok=True)
    base = os.path.join(a.out, "asd-stig-v6r4-to-nist-800-53r5")
    with open(base + ".csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)

    def rollup(rs):
        sts = [v[0] for v in rs.values()]
        if a.results:
            if "open" in sts: return "Open"
            if sts and all(x in ("not_a_finding", "not_applicable") for x in sts): return "Satisfied (IdP)"
            if any(x in ("not_a_finding", "not_a_finding_idp") for x in sts): return "Partial - IdP part done"
            return "Outside the IdP (app/platform/process)"
        owners = {v[1] for v in rs.values()}
        if owners <= {"KC", "KC-EXT"}: return "IdP"
        if owners & {"KC", "KC-EXT", "SHARED"}: return "Shared"
        return "App/platform/process"
    order = sorted(per, key=lambda k: (k.split("-")[0], int(re.findall(r"\d+", k)[0]), k))
    from collections import Counter
    cnt = Counter(rollup(per[k]["rules"]) for k in order)
    L = ["# ASD STIG V6R4 -> NIST SP 800-53 Rev 5 crosswalk", "",
         "Sources: %s; %s; %s. Mapping chain: ASD rule -> CCI (DISA) -> 800-53 Rev 5 control. Status source: %s." % (
             nist["sources"]["cci_list"], nist["sources"]["catalog"], nist["sources"]["baselines"], src),
         "%s" % ("Filtered to baseline(s): %s." % "/".join(sorted(want)) if want else "All controls referenced by ASD rules."), "",
         "| Control rollup | Controls |", "|---|---|"] + ["| %s | %d |" % (k, v) for k, v in cnt.most_common()] + ["",
         "Rollup rules: **Satisfied (IdP)** = every mapped ASD rule is Not a Finding/N/A in the run; **Partial** = the "
         "Keycloak part passed but app/platform/process rules under the same control remain; **Open** = at least one "
         "mapped rule failed; **Outside the IdP** = only app/platform/process rules map here. A control is only "
         "fully implemented when the system's other components (apps, platform, procedures) cover their rules too.", "",
         "| Control | Title | Family | Baselines | Rollup | ASD rules (status) |", "|---|---|---|---|---|---|"]
    short = {"not_a_finding": "NaF", "not_a_finding_idp": "IdP done", "open": "OPEN", "not_applicable": "N/A",
             "not_reviewed": "NR", "": ""}
    for k in order:
        m = per[k]["meta"]; rs = per[k]["rules"]
        lst = ", ".join("%s%s" % (v, ("(" + short.get(s, s) + ")") if a.results else "(" + o + ")") for v, (s, o, _) in sorted(rs.items()))
        L.append("| %s | %s | %s | %s | %s | %s |" % (k, m["title"], m["family"], "/".join(m["baselines"]) or "-", rollup(rs), lst))
    L += ["", "CSV with one row per control x CCI x rule (owner, status, Keycloak implementation, remaining action, "
          "evidence): `%s`." % os.path.basename(base + ".csv"),
          "Rev 5 note: controls marked [Rev4 only] have no Rev 5 reference in the DISA CCI list (withdrawn or incorporated "
          "into other Rev 5 controls); map them per NIST's Rev 4->Rev 5 analysis when you build the SSP."]
    with open(base + ".md", "w") as f:
        f.write("\n".join(L) + "\n")
    print("controls: %d  %s" % (len(order), dict(cnt)))
    print("wrote %s.md and %s.csv (%d rows)" % (base, base, len(rows)))

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("render"); r.add_argument("--profile", required=True); r.add_argument("--out", default="build")
    r.add_argument("--no-extension", action="store_true"); r.add_argument("--clients-dir", help="directory of per-service client *.json files (or STIG_CLIENTS_DIR)"); r.set_defaults(fn=cmd_render)
    ap_ = sub.add_parser("apply"); ap_.add_argument("--profile", required=True); ap_.add_argument("--url")
    ap_.add_argument("--harden-master", action="store_true", help="also harden the admin realm (named admins, Alt Token flow, deny ROPC)")
    ap_.add_argument("--admin-only", action="store_true", help="only harden the admin realm")
    ap_.add_argument("--remove-bootstrap-admin", action="store_true", help="delete the temporary bootstrap admin after hardening")
    ap_.add_argument("--secret-out", default="stig-automation.env")
    ap_.add_argument("--automation-secret-file", help="use (and keep in sync) this secret for the automation client instead of generating one")
    ap_.add_argument("--wait", type=int, default=0, help="seconds to wait for Keycloak to become ready")
    ap_.add_argument("--clients-dir", help="directory of per-service client *.json files (or STIG_CLIENTS_DIR)"); ap_.set_defaults(fn=cmd_apply)
    v = sub.add_parser("verify"); v.add_argument("--profile", required=True); v.add_argument("--url")
    v.add_argument("--live-url"); v.add_argument("--deploy-dir"); v.add_argument("--out", default="reports")
    v.add_argument("--trust-anchors", help="directory of trust-anchor PEMs, for pki.crl_coverage (default /opt/keycloak/data/cac/anchors)")
    v.add_argument("--keycloak-conf", help="Keycloak conf dir that crl-relative-path resolves against (default /opt/keycloak/conf)")
    v.add_argument("--http-ports", default="", help="extra comma-separated ports to probe for a clear-text HTTP Keycloak listener (the HTTPS port and 8080 are always probed)")
    v.add_argument("--strict", action="store_true", help="exit 1 on any failing check (CI gate)"); v.add_argument("--clients-dir", help="directory of per-service client *.json files (or STIG_CLIENTS_DIR)"); v.set_defaults(fn=cmd_verify)
    l = sub.add_parser("lookup"); l.add_argument("ids", nargs="*"); l.add_argument("--grep"); l.add_argument("--disposition")
    l.add_argument("--brief", action="store_true"); l.set_defaults(fn=cmd_lookup)
    i = sub.add_parser("inherit"); i.add_argument("--profile", required=True); i.add_argument("--app"); i.add_argument("--out", default="reports")
    i.add_argument("--clients-dir", help="directory of per-service client *.json files (or STIG_CLIENTS_DIR)"); i.set_defaults(fn=cmd_inherit)
    ac = sub.add_parser("add-client", help="register one relying party from its client-request.json (validated with "
                        "keycloak-rp-integration's rules; refuses reserved ids, other owners' clients and clients it did "
                        "not create)")
    ac.add_argument("request", help="client-request.json from the app team")
    ac.add_argument("--profile", required=True); ac.add_argument("--url")
    ac.add_argument("--clients-dir", help="clients.d directory to write <client_id>.json into (or STIG_CLIENTS_DIR)")
    ac.add_argument("--owner", help="operator-assigned owner id for this client (default: the request's contact email); "
                    "recorded as stig.owner")
    ac.add_argument("--update", metavar="CLIENT_ID", help="required to change an existing client; prints the before/after diff")
    ac.add_argument("--transfer", action="store_true", help="with --update: let a different owner take the client over")
    ac.add_argument("--adopt", metavar="CLIENT_ID", help="take over a client add-client did not create (with --update), "
                    "or a clients.d definition of it")
    ac.add_argument("--prune-roles", action="store_true", help="delete client roles the request no longer lists")
    ac.add_argument("--allow-dev", action="store_true", help="accept a dev_request (localhost URLs): non-production realms only")
    ac.add_argument("--no-strict", dest="strict", action="store_false",
                    help="accept a request with validator warnings (wildcard-DNS or single-label hosts, other origins); "
                         "default: warnings are errors")
    ac.add_argument("--strict", dest="strict", action="store_true", help=argparse.SUPPRESS)   # the default; kept for scripts
    ac.add_argument("--secret-out", metavar="FILE", help="client-secret only: write the secret here (mode 0600); it is never printed")
    ac.add_argument("--validator", help="path to validate-client-request.py (default: keycloak-rp-integration/ beside this skill)")
    ac.set_defaults(strict=True)
    ac.set_defaults(fn=cmd_add_client)
    asx = sub.add_parser("assess", help="offline: run the verify checks against realm export JSON")
    asx.add_argument("--export", required=True, help="realm export (Admin console > Realm settings > Partial export, or kc.sh export)")
    asx.add_argument("--admin-export", action="append", help="export of the admin realm (master) for the admin checks")
    asx.add_argument("--profile", help="optional profile with the organization's values (defaults: STIG values)")
    asx.add_argument("--clients-dir"); asx.add_argument("--deploy-dir"); asx.add_argument("--out", default="reports")
    asx.set_defaults(fn=cmd_assess)
    cw = sub.add_parser("crosswalk", help="ASD STIG -> CCI -> NIST SP 800-53 Rev 5, with status from a verify/assess run")
    cw.add_argument("--results", help="<realm>-asd-stig-results.json from verify, or -assessment-results.json from assess")
    cw.add_argument("--baseline", help="only controls in these baselines, e.g. M or MH (L/M/H)")
    cw.add_argument("--out", default="reports"); cw.set_defaults(fn=cmd_crosswalk)
    g = sub.add_parser("gateway", help="generate a hardened oauth2-proxy gateway/sidecar for one service")
    g.add_argument("--profile", required=True); g.add_argument("--clients-dir")
    g.add_argument("--client", required=True, help="Keycloak client_id for this service")
    g.add_argument("--public-url", required=True, help="https URL users open, e.g. https://payroll.example.mil")
    g.add_argument("--upstream", required=True, help="the app behind the gateway, e.g. http://127.0.0.1:8080")
    g.add_argument("--issuer-base", help="public Keycloak base URL (default: profile keycloak.url)")
    g.add_argument("--allowed-role", action="append", default=[], help="client role required to enter (repeatable)")
    g.add_argument("--privileged", action="store_true", help="admin front end: 10-minute idle")
    g.add_argument("--listen", default="0.0.0.0:4443")
    g.add_argument("--plain-http", action="store_true", help="listen on HTTP (only when TLS terminates in front of it)")
    g.add_argument("--behind-proxy", action="store_true")
    g.add_argument("--session-store", choices=["cookie", "redis"], default="cookie")
    g.add_argument("--redis-url"); g.add_argument("--secrets-dir", default="/run/secrets/gateway")
    g.add_argument("--out", default="gateway"); g.set_defaults(fn=cmd_gateway)
    a = ap.parse_args()
    a.fn(a)

if __name__ == "__main__":
    main()

# Regenerates references/control-map.json. Usage: python3 scripts/dev/build_control_map.py references/asd-stig-v6r4.json references/control-map.json
"""Builds references/control-map.json from compact definitions below + the bundled STIG rules.

Disposition vocabulary (see SKILL.md):
  KC        Keycloak configuration applied by this skill satisfies the rule for the identity tier (auto-checked)
  KC-EXT    Satisfied with the bundled stig-extensions.jar (auto-checked)
  SHARED    Keycloak does its part (auto-checked); relying app and/or platform must also act (app_action)
  PLATFORM  Deployment/infrastructure (TLS, DB, FIPS host, SIEM, backups); deploy assets help, partly checked
  APP       Relying application's own code/design; not satisfiable by an IdP
  PROCESS   Organizational/documentation/ISSO procedure
  NA-COND   Usually Not Applicable to a Keycloak deployment; condition stated
"""
import json, sys

M = {}
def m(v, disp, impl, checks=(), app=None, na=None, inherit=None):
    M["V-%d" % v] = {"disposition": disp, "implementation": impl, "checks": list(checks),
                     "app_action": app, "na_condition": na,
                     # can a relying app that fully delegates authN to this Keycloak cite this as inherited?
                     "inheritable": inherit if inherit is not None else disp in ("KC", "KC-EXT")}

PW_NA = "Not Applicable when the realm is CAC/PKI-only (auth_mode=cac): no passwords are used."
APP_SESS = "Relying app must end its own local session at the same idle limit; use short-lived tokens, honor back-channel logout."

# ---------------- Sessions ----------------
m(222387, "KC", "Browser flow ends with the 'user-session-limits' authenticator (userRealmLimit=profile.sessions.max_per_user, behavior=Deny new session).", ["flow.session_limits"])
m(222388, "SHARED", "Keycloak clears its AUTH_SESSION_ID/KEYCLOAK_IDENTITY/KEYCLOAK_SESSION cookies at logout and session expiry.", ["realm.logout_cookies"], app="App must clear its own cookies/temporary storage on logout and on back-channel logout.")
m(222389, "SHARED", "ssoSessionIdleTimeout=900s (15 min); offline_access removed from default roles so offline tokens cannot outlive the idle limit; refresh tokens revoked on use.", ["realm.user_idle_15", "realm.offline_access_removed", "realm.refresh_rotation"], app=APP_SESS)
m(222390, "SHARED", "Admin realm (master) ssoSessionIdleTimeout=600s; 'security-admin-console' in every realm overridden with client.session.idle.timeout=600; profile clients flagged privileged get the same override.", ["master.admin_idle_10", "realm.admin_console_idle_10"], app="Apps with in-app admin roles must enforce a 10 minute idle limit for admin users (or use a dedicated privileged client flagged privileged=true).")
m(222391, "SHARED", "OIDC end_session endpoint / SAML SLO enabled; post-logout redirect URIs restricted per client.", ["clients.logout_configured"], app="App must expose a visible logoff control that calls the IdP logout endpoint.")
m(222392, "SHARED", "Keycloak shows a 'You are logged out' page when logout is initiated at the IdP.", [], app="App must display an explicit logoff confirmation message.", inherit=False)
m(222578, "SHARED", "rememberMe disabled, so KEYCLOAK_IDENTITY/KEYCLOAK_SESSION are browser-session cookies destroyed on logoff or browser close.", ["realm.remember_me_off"], app="App session cookie must be a non-persistent session cookie and be destroyed on logoff.")
m(222577, "KC", "Session identifiers are only carried in cookies; sslRequired=all; tokens never placed in URLs (implicit flow rejected by client policy); exact redirect URIs only, so codes/tokens cannot be sent to attacker-chosen URLs.", ["realm.ssl_all", "policy.reject_implicit", "clients.redirects_exact"])
m(222575, "SHARED", "Keycloak session cookies are HttpOnly (verified against the live login page).", ["live.cookie_flags"], app="App session cookie must be HttpOnly.")
m(222576, "SHARED", "Keycloak session cookies carry Secure (sslRequired=all, HTTPS only; verified live).", ["live.cookie_flags", "realm.ssl_all"], app="App session cookie must carry Secure.")
m(222579, "KC", "Keycloak issues a new session ID at authentication (no fixation); built-in behaviour.", ["builtin"])
m(222580, "KC", "Keycloak validates session cookies cryptographically (signed identity cookie) on each request; built-in.", ["builtin"])
m(222581, "KC", "No URL-embedded session IDs: implicit grant rejected; PKCE S256 enforced for code flow.", ["policy.reject_implicit", "policy.pkce"])
m(222582, "KC", "Session IDs are random UUIDs never reused; refresh tokens single-use (revokeRefreshToken=true, maxReuse=0).", ["realm.refresh_rotation"])
m(222583, "PLATFORM", "Session IDs come from the JVM SecureRandom; FIPS-approved DRBG requires Keycloak FIPS mode (BCFIPS) on a FIPS-enabled host (deploy/Dockerfile.fips).", ["server.fips"])
m(222549, "KC", "Deleting a user in Keycloak removes all of that user's sessions immediately; built-in.", ["builtin"], app=APP_SESS)
m(222568, "SHARED", "Keycloak terminates IdP session on logout; back-channel logout URL configured for OIDC clients.", ["clients.logout_configured"], app="App must drop its connections/session on logout.")
m(222520, "KC", "Reauthentication: SSO max lifespan (profile.sessions.max_hours) forces re-login; clients may require max_age/prompt=login for sensitive actions; password changes require recent auth (maxAuthAge).", ["realm.sso_max"], app="Define organization re-authentication triggers (e.g. role change, sensitive transaction) and request prompt=login / max_age for them.")
m(222521, "SHARED", "Devices (service accounts) re-authenticate each access-token lifetime (300s) via client credentials.", ["realm.token_lifespan"], app="Define device re-authentication circumstances.")
m(222672, "KC-EXT", "stig-audit event listener logs WARN 'STIG-CONCURRENT-LOGON' when a user logs in while holding a session from another IP.", ["realm.listener_stig_audit"])
m(222437, "SHARED", "stig-audit listener stores stig_last_login / stig_previous_login on each login; client scope 'stig-claims' publishes 'previous_login' in ID/access tokens.", ["realm.listener_stig_audit", "realm.stig_claims_scope"], app="App UI must display the 'previous_login' claim (date/time of last successful logon) after sign-in.")

# ---------------- Account management ----------------
m(222407, "KC", "Keycloak admin console / Admin REST API provide automated account management.", ["builtin"])
m(222408, "PROCESS", "Shared/group accounts are not provisioned by this profile.", [], na="Not Applicable if no shared/group accounts exist (profile creates none).")
m(222409, "KC", "Workflow 'stig-temp-account-72h' disables users with account_type=temporary 72h after creation (runner interval 900s).", ["workflow.temp_72h"])
m(222410, "SHARED", "Users with account_type=emergency are excluded from the inactivity workflow; admin role 'stig-emergency-protect' documented.", ["workflow.inactive_35d"], app="ISSO procedure: emergency accounts may only be removed with ISSO approval; restrict manage-users on them via fine-grained admin permissions.", inherit=False)
m(222411, "KC", "Workflow 'stig-disable-inactive-35d' disables accounts 35 days after creation or last authentication (restarts on every login).", ["workflow.inactive_35d"])
m(222412, "SHARED", "Bootstrap temporary admin deleted; no default/demo users; verify lists all enabled users with no login in 35 days.", ["master.no_bootstrap_admin"], app="Periodic account review per ISSO.")
m(222661, "KC", "Built-in bootstrap admin removed after named admins are created; no sample users.", ["master.no_bootstrap_admin"])
m(222662, "KC", "No default credentials remain: bootstrap admin deleted, automation client uses generated secret/JWT.", ["master.no_bootstrap_admin"])
for v in (222413, 222414, 222415, 222416, 222421, 222467):
    m(v, "KC", "Admin events enabled with representation details (adminEventsEnabled, adminEventsDetailsEnabled) and shipped to the log/SIEM via jboss-logging + stig-audit listener.", ["realm.admin_events"])
for v in (222417, 222418, 222419, 222420, 222422):
    m(v, "KC-EXT", "stig-audit listener emits WARN 'STIG-ACCOUNT-EVENT' for every user create/update/delete and can e-mail SA/ISSO addresses (--spi-events-listener--stig-audit--notify-emails).", ["realm.listener_stig_audit"], app="Configure SIEM alert on STIG-ACCOUNT-EVENT or set notify-emails + realm SMTP.")
m(222433, "SHARED", "permanentLockout=true: locked users stay locked until an admin unlocks them (Admin console > Users > unlock).", ["realm.bruteforce"], app="ISSO/ISSM-approved unlock procedure including identity validation (see references/operations.md).", inherit=False)
m(222548, "KC", "Only the user (via required action/account console with re-auth) or an admin can change a password; user registration and self-service e-mail reset disabled.", ["realm.registration_off", "realm.reset_password_off"])
m(222619, "PROCESS", "Account review process; verify output lists inactive/temporary accounts to support it.", [])
m(222535, "NA-COND", "Device accounts = service-account clients authenticated with client JWT/X.509; inactivity workflow does not cover service accounts.", [], na="Not Applicable when devices authenticate with DoD PKI certificates (client-x509).", inherit=False)

# ---------------- Authorization / privileges ----------------
m(222425, "SHARED", "Authentication does not imply authorization: clients get fullScopeAllowed=false (client policy full-scope-disabled) so tokens only carry roles mapped to the client.", ["policy.full_scope_disabled"], app="App must enforce role/attribute checks on every resource (RBAC/ABAC).")
m(222426, "APP", "Keycloak Authorization Services can model DAC policies if the app uses them.", [], app="Enforce discretionary access control in the app.")
m(222429, "SHARED", "Admin capabilities separated in the master realm; app realm users get no realm-management roles by default.", ["realm.no_default_admin_roles"], app="App must block non-privileged users from privileged functions.")
m(222430, "PLATFORM", "Container runs as non-root UID 1000 (Keycloak image default); read-only root FS recommended (deploy/compose.yaml).", ["deploy.nonroot"])
m(222431, "KC", "Admin events record every privileged (admin API) operation with actor, IP, resource and representation.", ["realm.admin_events"])
m(222463, "KC", "Admin events + jboss-logging capture privileged activity.", ["realm.admin_events"])
m(222478, "KC", "Admin events with details record the full representation of privileged changes and the individual admin identity.", ["realm.admin_events"])

# ---------------- Brute force / lockout ----------------
m(222432, "KC", "Brute-force detection: failureFactor=3, maxDeltaTimeSeconds=900 (15 min window), permanentLockout=true. CAC PIN attempts are additionally limited by the card itself.", ["realm.bruteforce"])

# ---------------- Authentication / MFA / PKI ----------------
m(222522, "KC", "Every user is a unique Keycloak identity; X.509 maps one certificate UPN to one account (admin-only attribute cac_upn); usernames unique.", ["flow.x509_or_mfa", "userprofile.cac_upn_admin_only"])
m(222523, "SHARED", "Admin realm (master) requires the Alt Token: X.509 mapped through admin-only attribute alt_token_upn (separate from CAC cac_upn), or password + WebAuthn hardware token if profile.admin.mfa=webauthn.", ["master.flow_alt_token"], app="Issue Alt Tokens to administrators; do not map their everyday CAC.")
m(222524, "KC", "Browser flow uses auth-x509-client-username-form; TLS client-auth=request with DoD PKI trust store.", ["flow.x509_or_mfa", "deploy.client_auth"])
m(222525, "KC", "X.509 authenticator validates path to DoD roots, checks revocation (OCSP with CRL fallback, fail-closed), validity dates, key usage digitalSignature.", ["flow.x509_revocation"])
m(222526, "KC", "Non-privileged network access requires CAC (auth_mode=cac) or CAC-or-(password+OTP/WebAuthn) (auth_mode=cac_or_mfa); password-only paths do not exist.", ["flow.x509_or_mfa", "flow.no_password_only"])
m(222527, "SHARED", "Same as V-222523 for local access to the admin console.", ["master.flow_alt_token"], app="Local console access must also use the Alt Token.")
m(222528, "SHARED", "Same flows apply to local access.", ["flow.x509_or_mfa"], app="Local (on-host) access paths must not bypass Keycloak.")
m(222529, "NA-COND", "No group authenticators are provisioned.", [], na="Not Applicable if no group authenticators are used.")
m(222530, "KC", "Replay-resistant: TLS 1.2+/1.3 channel, PKCE S256, one-time authorization codes (60s), single-use refresh tokens, OTP codes not reusable.", ["policy.pkce", "realm.refresh_rotation", "realm.otp_policy"])
m(222531, "KC", "Same replay-resistant mechanisms for non-privileged accounts.", ["policy.pkce", "realm.refresh_rotation", "realm.otp_policy"])
m(222532, "PLATFORM", "Mutual TLS available (https-client-auth=request; client-x509 client authentication).", ["deploy.client_auth"])
m(222533, "SHARED", "Clients authenticate (confidential: client-jwt/secret; public SPA: PKCE).", ["clients.authenticated"], app="Network devices calling the app must authenticate (mTLS/service account).")
m(222534, "PLATFORM", "Service clients can be forced to client-x509 (mTLS).", [], app="Enable client-x509 for service clients handling non-releasable data.")
m(222550, "KC", "Path building to DoD trust anchors (truststore-paths) with revocation status (OCSP, CRL fallback).", ["flow.x509_revocation", "deploy.truststore"])
m(222551, "PLATFORM", "Server TLS private key file mode 0600/0400 owned by the keycloak UID; mounted read-only.", ["deploy.key_perms"])
m(222552, "KC", "Certificate UPN (EDIPI@mil) is mapped to exactly one user via admin-only attribute cac_upn; events log the username, not just certificate data.", ["flow.x509_or_mfa", "userprofile.cac_upn_admin_only"])
m(222553, "SHARED", "X.509 authenticator: OCSP with CRL fallback from a locally cached CRL file (x509-cert-auth.crl-relative-path); scripts/fetch_dod_pki.sh refreshes CRLs on a schedule.", ["flow.x509_revocation"], app="Run the CRL refresh job (cron/systemd timer) at least daily.")
m(222555, "PLATFORM", "FIPS 140-validated crypto for authentication requires Keycloak FIPS mode (deploy/Dockerfile.fips) on a FIPS-mode RHEL host.", ["server.fips"])
m(222556, "KC", "Non-organizational users get unique accounts the same way (no anonymous/shared access).", ["flow.no_password_only"])
for v in (222557, 222558):
    m(v, "SHARED", "Add other agencies' PIV roots (Federal Common Policy CA G2 bridge) to the trust store; same X.509 flow validates them.", ["deploy.truststore"], app="Decide whether federal PIV is in scope; add FCPCA trust anchors if so.")
for v in (222559, 222560):
    m(v, "SHARED", "Keycloak can broker FICAM-approved IdPs (OIDC/SAML identity providers).", [], app="Configure FICAM IdP brokering only if non-DoD users are in scope.", na="Not Applicable when only DoD CAC users access the application.", inherit=False)
m(222584, "KC", "TLS client-auth trust store (https-trust-store-file) holds ONLY the DoD roots/intermediates - truststore-paths alone is merged with ~140 public JVM CAs (verified); X.509 authenticator pins the DoD root DNs (x509-cert-auth.casubjectdn = trust-anchor DNs).", ["deploy.truststore", "flow.x509_anchor_pinned"])

# ---------------- Passwords ----------------
pw = {222536: "length(15)", 222537: "upperCase(1)", 222538: "lowerCase(1)", 222539: "digits(1)", 222540: "specialChars(1)",
      222545: "forceExpiredPasswordChange(60)", 222546: "passwordHistory(5)"}
for v, pol in pw.items():
    m(v, "KC", "Password policy " + pol + ".", ["realm.pw_policy"], na=PW_NA)
m(222542, "KC", "Passwords stored only as PBKDF2-SHA512 hashes, 210000 iterations (FIPS-approved; replaces the non-FIPS argon2 default).", ["realm.pw_policy"], na=PW_NA)
m(222543, "KC", "Passwords only transmitted over TLS (sslRequired=all, HTTP listener disabled); ROPC grant rejected so apps never handle passwords.", ["realm.ssl_all", "policy.reject_ropc", "live.http_disabled"])
m(222544, "KC-EXT", "stig-extensions password policy minimumPasswordAge(24): users cannot change their own password again within 24h (admin resets and forced changes exempt).", ["realm.pw_policy"], na=PW_NA)
m(222541, "SHARED", "Keycloak stores only hashes and does not ask for the old password on change, so an 8-character difference cannot be computed. Mitigations: CAC-only (N/A), or long passphrase policy + history(5).", ["realm.pw_policy"], app="POA&M / risk acceptance if passwords are used; otherwise N/A with CAC-only.", na=PW_NA, inherit=False)
m(222547, "KC", "Admin-created/reset passwords are temporary: UPDATE_PASSWORD required action forces an immediate change.", ["realm.required_actions"], na=PW_NA)
m(222554, "KC", "Login forms use password inputs (masked); built-in theme.", ["builtin"])

# ---------------- Banner ----------------
for v in (222434, 222435, 222436):
    m(v, "KC", "Login theme 'dod-stig' displays the Standard Mandatory DoD Notice and Consent Banner (exact STIG text) and keeps the login form hidden until the user selects OK; Terms and Conditions required action (same text) is a server-side backstop.", ["realm.login_theme", "realm.terms_action"], app="Apps with their own pre-login pages (outside Keycloak) must also show the banner.")

# ---------------- Audit ----------------
for v in (222441, 222442, 222443, 222445):
    m(v, "SHARED", "User events LOGIN/CODE_TO_TOKEN/REFRESH_TOKEN/LOGOUT (session create/renew/destroy) enabled with all event types; idle expiry is visible as failed REFRESH_TOKEN_ERROR/INVALID token events.", ["realm.user_events"], app="App logs its own session lifecycle.")
m(222446, "KC", "Every event record carries an epoch-millisecond timestamp.", ["realm.user_events"])
m(222447, "SHARED", "HTTP access log enabled (--http-access-log-enabled) with a pattern capturing method, URI, Referer and User-Agent.", ["deploy.access_log"])
m(222448, "KC", "Events record the client IP (ipAddress).", ["realm.user_events"])
m(222449, "KC", "Events record userId/username.", ["realm.user_events"])
for v in (222450, 222451, 222454, 222455, 222458, 222460):
    m(v, "KC", "Admin events capture successful privilege/role/security-object changes; failed attempts produce 403 on the admin API, captured by the HTTP access log.", ["realm.admin_events", "deploy.access_log"])
for v in (222452, 222453, 222456, 222457, 222459, 222461):
    m(v, "NA-COND", "Keycloak has no classification levels/categories.", [], na="Not Applicable unless the application implements security levels/categories.", inherit=False)
m(222462, "KC", "LOGIN and LOGIN_ERROR events enabled.", ["realm.user_events"])
m(222464, "KC", "LOGIN and LOGOUT events give start and end times of access.", ["realm.user_events"])
m(222466, "KC", "All authentication paths go through Keycloak and are logged; direct grant (ROPC) denied.", ["realm.user_events", "policy.reject_ropc"])
m(222468, "KC", "Event logging is active from server start (realm configuration persisted).", ["realm.user_events"])
m(222469, "PLATFORM", "Keycloak logs server stop at INFO; console/syslog handler captures it.", ["deploy.syslog"])
m(222470, "SHARED", "Access log records the local endpoint; events record client IP.", ["deploy.access_log"])
m(222473, "KC", "Event timestamps (UTC epoch ms).", ["realm.user_events"])
m(222474, "KC", "Events record clientId, event type and authenticator details.", ["realm.user_events"])
m(222475, "PLATFORM", "Log records tagged with service name via --log-syslog-app-name and JSON console output.", ["deploy.syslog"])
m(222476, "KC", "Events distinguish success (type) and failure (*_ERROR with error code).", ["realm.user_events"])
m(222477, "KC", "Events record user, client, session and IP.", ["realm.user_events"])
for v in (222481, 222482, 222480, 222487):
    m(v, "PLATFORM", "Events shipped off-host: jboss-logging listener at INFO/WARN to syslog (--log=console,syslog) for the enterprise SIEM.", ["realm.listener_jboss", "deploy.syslog"], app="Point --log-syslog-endpoint at the SIEM collector.")
for v in (222483, 222484, 222485, 222486, 222506, 222621):
    m(v, "PLATFORM", "SIEM / log platform responsibility (capacity alerts, failure alerts, retention 30 months / 5 years SAMI, weekly backup).", [], app="Configure in the SIEM; Keycloak DB event retention (eventsExpiration) is only a local buffer.")
for v in (222488, 222489, 222490, 222491, 222492, 222493, 222494, 222495, 222496):
    m(v, "PLATFORM", "Audit reduction/reporting is provided by the SIEM; the admin console Events view offers filtering of the local buffer.", ["realm.user_events"])
for v in (222497, 222498, 222499):
    m(v, "PLATFORM", "Timestamps from the host clock (NTP-synced to DoD time source), recorded UTC in milliseconds.", ["realm.user_events"])
for v in (222500, 222501, 222502):
    m(v, "SHARED", "Event read/delete limited to realm admins with view-events/manage-events; logs off-loaded to SIEM.", ["realm.admin_events"], app="Restrict view-events/manage-events roles to auditors/ISSO.")
for v in (222503, 222504, 222505, 222507, 222508, 222509):
    m(v, "PLATFORM", "Audit tools are the SIEM and admin console; protect/hash per platform STIG.", [])
m(222444, "KC", "Keycloak events never record passwords or OTP values; admin event representations exclude credential values.", ["builtin"], app="Apps must not log tokens.")
m(222512, "KC", "Admin events record who changed realm configuration.", ["realm.admin_events"])
m(222511, "KC", "Configuration changes require realm-admin roles in the admin realm protected by the Alt Token.", ["master.flow_alt_token"])

# ---------------- Crypto / transport ----------------
for v in (222596, 222597, 222598, 222599, 222396, 222397):
    m(v, "SHARED", "HTTPS only: sslRequired=all, HTTP listener disabled, TLS 1.3/1.2 with FIPS cipher suites, HSTS; DB connection uses TLS (sslmode=verify-full).", ["realm.ssl_all", "live.http_disabled", "live.tls_versions", "deploy.db_tls"], app="App must also enforce TLS end-to-end.")
m(222562, "SHARED", "Admin (maintenance) access only over TLS on a separate admin hostname.", ["live.tls_versions"])
m(222563, "SHARED", "Same as V-222562.", ["live.tls_versions"])
m(222565, "SHARED", "Admin realm requires the Alt Token.", ["master.flow_alt_token"])
m(222561, "KC", "Admin events log all remote admin sessions.", ["realm.admin_events"])
m(222564, "SHARED", "Admin console logout terminates the admin session.", [])
m(222566, "SHARED", "Admin console session idle 10 minutes.", ["master.admin_idle_10"])
for v in (222570, 222571, 222572):
    m(v, "PLATFORM", "FIPS-validated module requires Keycloak FIPS mode (BCFIPS providers, --features=fips --fips-mode=strict) on a FIPS-enabled OS.", ["server.fips"])
m(222573, "PLATFORM", "SAML SessionIndex generated by Keycloak's SecureRandom; FIPS DRBG in FIPS mode.", ["server.fips"])
m(222641, "KC", "TLS key exchange (ECDHE) with server certificate authentication before any application data.", ["live.tls_versions"])
m(222588, "PLATFORM", "Database at-rest encryption (encrypted volume / TDE).", [], app="Encrypt the Keycloak database volume.")
m(222589, "PLATFORM", "Same as V-222588.", [])
m(222587, "PLATFORM", "Same as V-222588; passwords additionally hashed, client secrets stored server side only.", [])
m(265634, "NA-COND", "NSA-approved crypto only for classified systems.", [], na="Not Applicable on unclassified networks.")

# ---------------- SAML / WS-Security ----------------
for v in (222400, 222403, 222404):
    m(v, "KC", "Keycloak SAML assertions always include Conditions NotBefore/NotOnOrAfter and SubjectConfirmationData NotOnOrAfter; assertion lifespan set to 300s for SAML clients.", ["clients.saml_hardened"], na="Not Applicable if no SAML clients.")
m(222401, "KC", "Assertion IDs are unique random values (built-in).", ["builtin"], na="Not Applicable if no SAML clients.")
m(222402, "KC", "SAML clients: saml.encrypt=true (encrypted assertions) and signed documents/assertions.", ["clients.saml_hardened"], na="Not Applicable if no SAML clients.")
m(222405, "KC", "Keycloak emits at most one OneTimeUse condition (built-in).", ["builtin"], na="Not Applicable if no SAML clients.")
m(222406, "KC", "Assertions encrypted when SAML clients are configured (saml.encrypt=true).", ["clients.saml_hardened"], na="Not Applicable if no SAML clients.")
for v in (222398, 222399):
    m(v, "NA-COND", "Keycloak does not use WS-Security/SOAP messages.", [], na="Not Applicable: no SOAP/WS-Security interfaces.")

# ---------------- Web / input / headers ----------------
m(222602, "SHARED", "Security headers: CSP frame-ancestors 'self', X-Content-Type-Options nosniff, X-Frame-Options SAMEORIGIN, Referrer-Policy no-referrer, HSTS; Keycloak escapes theme output.", ["realm.headers"], app="App XSS protection is app responsibility.")
m(222603, "SHARED", "Keycloak forms carry session-bound execution/tab IDs (CSRF protection); state/PKCE protect OIDC; no wildcard CORS web origins.", ["policy.pkce", "clients.redirects_exact"], app="App CSRF protection.")
m(222600, "SHARED", "Generic login errors ('Invalid username or password') - no user enumeration.", ["builtin"])
m(222610, "SHARED", "Keycloak returns generic error pages; stack traces only in server logs.", ["builtin"])
m(222611, "SHARED", "Detailed errors only in server logs readable by SA.", ["builtin"])
m(222518, "KC", "Unneeded capabilities disabled: user registration, self-service reset, implicit/ROPC grants, device flow and CIBA per client; HTTP listener off.", ["realm.registration_off", "policy.reject_implicit", "policy.reject_ropc", "clients.redirects_exact", "live.http_disabled"])
m(222519, "PLATFORM", "Only 8443 (HTTPS) exposed; 9000 management bound internally.", ["live.http_disabled"], app="Register ports in PPSM CAL.")
m(222574, "PLATFORM", "Admin console served on a separate hostname (--hostname-admin) reachable only from the admin network; database on a separate tier.", ["deploy.admin_hostname"])
m(222585, "KC", "Keycloak refuses to start with invalid configuration and fails closed (OCSP fail-open=false, CRL abort if not updated).", ["flow.x509_revocation"])
m(222658, "PLATFORM", "Use a supported Keycloak release (or Red Hat build of Keycloak with support).", ["server.version"])
m(222614, "PLATFORM", "Track Keycloak security advisories and patch.", ["server.version"])
m(222670, "PLATFORM", "Subscribe to Keycloak/RHBK security advisories.", [])
m(222669, "PROCESS", "Register an admin for update notifications.", [])
m(222594, "SHARED", "Brute-force detection and per-user session limits throttle abuse; rate limiting at the reverse proxy/WAF.", ["realm.bruteforce", "flow.session_limits"], app="Rate limit at proxy/WAF.")
m(222667, "SHARED", "Same as V-222594.", ["realm.bruteforce"])

# ---------------- Everything else: classify by default ----------------
APP_DEFAULT = (222393,222394,222395,222423,222424,222427,222428,222438,222439,222465,222471,222472,222479,222510,222513,222514,222516,222517,222567,222586,222590,222591,222592,222593,222595,222601,222604,222605,222606,222607,222608,222609,222612,222613,222615,222616,222617,222618,222626,222634,222642,222643,222656,222665,222666,222668)
PROCESS_DEFAULT = (222515,222620,222622,222623,222624,222625,222627,222628,222629,222630,222631,222632,222633,222635,222636,222637,222638,222639,222640,222644,222645,222646,222647,222648,222649,222650,222651,222652,222653,222654,222655,222657,222659,222660,222663,222664,222671,222673)

def main(rules_path, out_path):
    rules = json.load(open(rules_path))["rules"]
    ids = {r["vuln_id"] for r in rules}
    for v in APP_DEFAULT:
        k = "V-%d" % v
        if k not in M:
            m(v, "APP", "Relying application (and, for Keycloak itself, the vendor) responsibility; not satisfiable by IdP configuration.", [],
              app="Assess in the application's own ASD checklist.")
    for v in PROCESS_DEFAULT:
        k = "V-%d" % v
        if k not in M:
            m(v, "PROCESS", "Organizational / program documentation or procedure.", [], app="Program/ISSO evidence.")
    missing = sorted(ids - set(M))
    extra = sorted(set(M) - ids)
    if missing or extra:
        print("missing", missing, "extra", extra); sys.exit(1)
    out = {"benchmark": "ASD STIG V6R4", "keycloak_version_tested": "26.8.2",
           "dispositions": {
               "KC": "Satisfied by Keycloak configuration this skill applies (automated check)",
               "KC-EXT": "Satisfied using bundled stig-extensions.jar (automated check)",
               "SHARED": "Keycloak part automated; relying app/platform must also act",
               "PLATFORM": "Deployment / infrastructure responsibility",
               "APP": "Relying application's own code/design",
               "PROCESS": "Organizational procedure / documentation",
               "NA-COND": "Usually Not Applicable; condition stated"},
           "controls": {k: M[k] for k in sorted(M)}}
    json.dump(out, open(out_path, "w"), indent=1)
    from collections import Counter
    print(len(M), Counter(x["disposition"] for x in M.values()))

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

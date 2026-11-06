# Keycloak ASD STIG V6R4 verification - realm `labapp`

Generated 2026-11-05 21:15 UTC against Keycloak 26.8.2. Auth mode `cac_or_mfa`, admin MFA `x509`.

| Status | Count | CAT I | CAT II | CAT III |
|---|---|---|---|---|
| Not a Finding (Keycloak) | 86 | 13 | 63 | 10 |
| IdP part done - app/platform action pending | 71 | 5 | 64 | 2 |
| Open | 6 | 1 | 5 | 0 |
| Not Applicable | 0 | 0 | 0 | 0 |
| Not Reviewed (app/platform/process) | 123 | 15 | 98 | 10 |

## Open findings

- **V-222555** CAT I `APSC-DV-001860` The application must use mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.  
  - [FAIL] server.fips: cryptoInfo.cryptoProvider=DefaultCryptoProvider
- **V-222570** CAT II `APSC-DV-002020` The application must utilize FIPS-validated cryptographic modules when signing application components.  
  - [FAIL] server.fips: cryptoInfo.cryptoProvider=DefaultCryptoProvider
- **V-222571** CAT II `APSC-DV-002030` The application must utilize FIPS-validated cryptographic modules when generating cryptographic hashes.  
  - [FAIL] server.fips: cryptoInfo.cryptoProvider=DefaultCryptoProvider
- **V-222572** CAT II `APSC-DV-002040` The application must utilize FIPS-validated cryptographic modules when protecting unclassified information that requires cryptographic protection.  
  - [FAIL] server.fips: cryptoInfo.cryptoProvider=DefaultCryptoProvider
- **V-222573** CAT II `APSC-DV-002050` Applications making SAML assertions must use FIPS-approved random numbers in the generation of SessionIndex in the SAML element AuthnStatement.  
  - [FAIL] server.fips: cryptoInfo.cryptoProvider=DefaultCryptoProvider
- **V-222583** CAT II `APSC-DV-002290` The application must generate a unique session identifier using a FIPS 140-2/140-3 approved random number generator.  
  - [FAIL] server.fips: cryptoInfo.cryptoProvider=DefaultCryptoProvider

## Automated checks

| Check | Result | Evidence |
|---|---|---|
| `builtin` | PASS | Built-in Keycloak 26.8.2 behaviour (no configuration required). |
| `clients.authenticated` | PASS | confidential clients without authenticator: [] |
| `clients.logout_configured` | PASS | OIDC clients without post-logout or back-channel logout: [] |
| `clients.redirects_exact` | PASS | profile clients=['https://legacy.test.mil/saml', 'lab-admin', 'lab-web']; wildcard/implicit/ROPC: [] |
| `clients.saml_hardened` | PASS | SAML clients lacking signed+encrypted assertions: [] |
| `deploy.access_log` | PASS | http-access-log-enabled + pattern with User-Agent/Referer |
| `deploy.admin_hostname` | PASS | hostname-admin set (separate admin URL) |
| `deploy.client_auth` | PASS | https-client-auth=request (build-time: Dockerfile KC_HTTPS_CLIENT_AUTH) |
| `deploy.db_tls` | PASS | db-url sslmode=verify-full |
| `deploy.key_perms` | MANUAL | Verify TLS private key mode 0400/0600 owned by UID 1000 (ls -l). |
| `deploy.nonroot` | PASS | container user 1000 |
| `deploy.syslog` | PASS | log handlers include syslog |
| `deploy.truststore` | PASS | keycloak.conf truststore-paths (DoD PKI roots only) |
| `flow.no_password_only` | PASS | paths lacking CAC or second factor: [] |
| `flow.session_limits` | PASS | user-session-limits requirement=REQUIRED config={'userClientLimit': '0', 'errorMessage': 'Maximum concurrent sessions reached. Log out of another session first.', 'behavior': 'Deny new session', 'userRealmLimit': '3'} |
| `flow.x509_or_mfa` | PASS | browserFlow='STIG Browser' authentication paths=[['auth-x509-client-username-form', 'user-session-limits'], ['auth-otp-form', 'auth-username-password-form', 'user-session-limits']] |
| `flow.x509_revocation` | PASS | ocsp=True crl=True(crl/test-id-ca.crl) ocsp-fail-open=True timestamp=true keyusage=digitalSignature policies=None |
| `live.cookie_flags` | PASS | HTTP 200; session cookies: ['AUTH_SESSION_ID=...;Version=1;Path=/realms/labapp/;Secure;HttpOnly;SameSite=None', 'KC_RESTART=...;Version=1;Path=/realms/labapp/;Secure;HttpOnly;SameSite=None'] |
| `live.headers` | PASS | HSTS=max-age=31536000; includeSubDomains; X-Content-Type-Options=nosniff; X-Frame-Options=SAMEORIGIN; CSP=frame-src 'self'; frame-ancestors 'self'; object-src 'none'; |
| `live.http_disabled` | PASS | no HTTP listener on localhost:8080 |
| `live.tls_versions` | PASS | TLS handshake results: {'TLSv1.1': None, 'TLSv1.2': 'TLSv1.2', 'TLSv1.3': 'TLSv1.3'} |
| `master.admin_idle_10` | PASS | admin realm ssoSessionIdleTimeout=600s |
| `master.flow_alt_token` | PASS | admin realm browserFlow='STIG Admin Browser' paths=[['auth-x509-client-username-form', 'user-session-limits']] x509 mapping attribute=alt_token_upn admin.mfa=x509 |
| `master.no_bootstrap_admin` | PASS | temporary bootstrap admin users: []; temporary admin clients: [] |
| `policy.full_scope_disabled` | PASS | client policy asd-stig active=True executors=['full-scope-disabled', 'pkce-enforcer', 'reject-implicit-grant', 'reject-ropc-grant'] |
| `policy.pkce` | PASS | client policy asd-stig active=True executors=['full-scope-disabled', 'pkce-enforcer', 'reject-implicit-grant', 'reject-ropc-grant'] |
| `policy.reject_implicit` | PASS | client policy asd-stig active=True executors=['full-scope-disabled', 'pkce-enforcer', 'reject-implicit-grant', 'reject-ropc-grant'] |
| `policy.reject_ropc` | PASS | client policy asd-stig active=True executors=['full-scope-disabled', 'pkce-enforcer', 'reject-implicit-grant', 'reject-ropc-grant'] |
| `realm.admin_console_idle_10` | PASS | security-admin-console client.session.idle.timeout=600 |
| `realm.admin_events` | PASS | adminEventsEnabled realm=True/True admin=True/True (enabled/details) |
| `realm.bruteforce` | PASS | bruteForceProtected=True failureFactor=3 maxDeltaTimeSeconds=900 permanentLockout=True (admin realm failureFactor=3) |
| `realm.direct_grant_denied` | PASS | directGrantFlow='STIG Direct Grant - Deny' providers=['deny-access-authenticator'] |
| `realm.headers` | PASS | browserSecurityHeaders={"contentSecurityPolicyReportOnly": "", "xContentTypeOptions": "nosniff", "referrerPolicy": "no-referrer", "xRobotsTag": "none", "xFrameOptions": "SAMEORIGIN", "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';", "strictTransportSecurity": "max-age=31536000; includeSubDomains"} |
| `realm.listener_jboss` | PASS | eventsListeners=['stig-audit', 'jboss-logging'] |
| `realm.listener_stig_audit` | PASS | eventsListeners realm=['stig-audit', 'jboss-logging'] admin=['stig-audit', 'jboss-logging'] |
| `realm.login_theme` | PASS | loginTheme realm=dod-stig admin=dod-stig |
| `realm.logout_cookies` | PASS | Keycloak expires KEYCLOAK_IDENTITY/KEYCLOAK_SESSION/AUTH_SESSION_ID on logout (built-in) |
| `realm.no_default_admin_roles` | PASS | default roles carry no realm-management client roles (['default-roles-labapp']) |
| `realm.offline_access_removed` | PASS | default role composites: ['manage-account', 'uma_authorization', 'view-profile'] |
| `realm.otp_policy` | PASS | otp totp/HmacSHA256 digits=6 period=30 reusable=False |
| `realm.pw_policy` | PASS | passwordPolicy=length(15) and maxLength(128) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and notUsername and notEmail and passwordHistory(5) and forceExpiredPasswordChange(60) and hashAlgorithm(pbkdf2-sha512) and hashIterations(210000) and minimumPasswordAge(24) |
| `realm.refresh_rotation` | PASS | revokeRefreshToken=True refreshTokenMaxReuse=0 |
| `realm.registration_off` | PASS | registrationAllowed=False |
| `realm.remember_me_off` | PASS | rememberMe realm=False admin=False |
| `realm.required_actions` | PASS | UPDATE_PASSWORD enabled=True |
| `realm.reset_password_off` | PASS | resetPasswordAllowed=False |
| `realm.ssl_all` | PASS | sslRequired: realm=all admin=all |
| `realm.sso_max` | PASS | ssoSessionMaxLifespan=28800s |
| `realm.stig_claims_scope` | PASS | default client scopes: ['AuthnContextClassRef', 'acr', 'basic', 'email', 'profile', 'role_list', 'roles', 'saml_organization', 'stig-claims', 'web-origins'] |
| `realm.terms_action` | PASS | TERMS_AND_CONDITIONS enabled=True defaultAction=True |
| `realm.token_lifespan` | PASS | accessTokenLifespan=300s |
| `realm.user_events` | PASS | eventsEnabled=True, 132 event types, missing=[] |
| `realm.user_idle_15` | PASS | ssoSessionIdleTimeout=900s |
| `server.extension` | PASS | stig-extensions provider loaded=True |
| `server.fips` | FAIL | cryptoInfo.cryptoProvider=DefaultCryptoProvider |
| `server.version` | MANUAL | Keycloak 26.8.2 - confirm it is a currently supported release |
| `userprofile.cac_upn_admin_only` | PASS | cac_upn permissions={'view': ['admin'], 'edit': ['admin']} unmanagedAttributePolicy=None |
| `workflow.inactive_35d` | PASS | workflows: [('stig-disable-inactive-35d', 'user-created or user-authenticated', 'not has-user-attribute(account_type:emergency)', [('disable-user', '35d')]), ('stig-temp-account-72h', 'user-created', 'has-user-attribute(account_type:temporary)', [('disable-user', '72h')])] |
| `workflow.temp_72h` | PASS | temporary-account workflow: ('has-user-attribute(account_type:temporary)', [{'uses': 'disable-user', 'after': '72h', 'id': '49893c0d-8d56-496b-a62d-e87353b6f6ed'}]) |

## Relying-application and platform actions still required

- V-222388 The application must clear temporary storage and cookies when the session is terminated. - App must clear its own cookies/temporary storage on logout and on back-channel logout.
- V-222389 The application must automatically terminate the non-privileged user session and log off n - Relying app must end its own local session at the same idle limit; use short-lived tokens, honor back-channel logout.
- V-222390 The application must automatically terminate the admin user session and log off admin user - Apps with in-app admin roles must enforce a 10 minute idle limit for admin users (or use a dedicated privileged client flagged privileged=true).
- V-222391 Applications requiring user access authentication must provide a logoff capability for use - App must expose a visible logoff control that calls the IdP logout endpoint.
- V-222396 The application must implement DoD-approved encryption to protect the confidentiality of r - App must also enforce TLS end-to-end.
- V-222397 The application must implement cryptographic mechanisms to protect the integrity of remote - App must also enforce TLS end-to-end.
- V-222410 The application must have a process, feature or function that prevents removal or disablin - ISSO procedure: emergency accounts may only be removed with ISSO approval; restrict manage-users on them via fine-grained admin permissions.
- V-222412 Unnecessary application accounts must be disabled, or deleted. - Periodic account review per ISSO.
- V-222425 The application must enforce approved authorizations for logical access to information and - App must enforce role/attribute checks on every resource (RBAC/ABAC).
- V-222429 The application must prevent non-privileged users from executing privileged functions to i - App must block non-privileged users from privileged functions.
- V-222433 The application administrator must follow an approved process to unlock locked user accoun - ISSO/ISSM-approved unlock procedure including identity validation (see references/operations.md).
- V-222437 The application must display the time and date of the users last successful logon. - App UI must display the 'previous_login' claim (date/time of last successful logon) after sign-in.
- V-222441 The application must provide audit record generation capability for the creation of sessio - App logs its own session lifecycle.
- V-222442 The application must provide audit record generation capability for the destruction of ses - App logs its own session lifecycle.
- V-222443 The application must provide audit record generation capability for the renewal of session - App logs its own session lifecycle.
- V-222445 The application must provide audit record generation capability for session timeouts. - App logs its own session lifecycle.
- V-222480 The application must provide centralized management and configuration of the content to be - Point --log-syslog-endpoint at the SIEM collector.
- V-222481 The application must off-load audit records onto a different system or media than the syst - Point --log-syslog-endpoint at the SIEM collector.
- V-222482 The application must be configured to write application logs to a centralized log reposito - Point --log-syslog-endpoint at the SIEM collector.
- V-222487 The application must provide the capability to centrally review and analyze audit records  - Point --log-syslog-endpoint at the SIEM collector.
- V-222500 The application must protect audit information from any type of unauthorized read access. - Restrict view-events/manage-events roles to auditors/ISSO.
- V-222501 The application must protect audit information from unauthorized modification. - Restrict view-events/manage-events roles to auditors/ISSO.
- V-222502 The application must protect audit information from unauthorized deletion. - Restrict view-events/manage-events roles to auditors/ISSO.
- V-222519 The application must be configured to use only functions, ports, and protocols permitted t - Register ports in PPSM CAL.
- V-222521 The application must require devices to reauthenticate when organization-defined circumsta - Define device re-authentication circumstances.
- V-222523 The application must use multifactor (Alt. Token) authentication for network access to pri - Issue Alt Tokens to administrators; do not map their everyday CAC.
- V-222527 The application must use multifactor (Alt. Token) authentication for local access to privi - Local console access must also use the Alt Token.
- V-222528 The application must use multifactor (e.g., CAC, Alt. Token) authentication for local acce - Local (on-host) access paths must not bypass Keycloak.
- V-222533 The application must authenticate all network connected endpoint devices before establishi - Network devices calling the app must authenticate (mTLS/service account).
- V-222541 The application must require the change of at least eight of the total number of character - POA&M / risk acceptance if passwords are used; otherwise N/A with CAC-only.
- V-222553 The application, for PKI-based authentication, must implement a local cache of revocation  - Run the CRL refresh job (cron/systemd timer) at least daily.
- V-222557 The application must accept Personal Identity Verification (PIV) credentials from other fe - Decide whether federal PIV is in scope; add FCPCA trust anchors if so.
- V-222558 The application must electronically verify Personal Identity Verification (PIV) credential - Decide whether federal PIV is in scope; add FCPCA trust anchors if so.
- V-222568 The application must terminate all network connections associated with a communications se - App must drop its connections/session on logout.
- V-222575 The application must set the HTTPOnly flag on session cookies. - App session cookie must be HttpOnly.
- V-222576 The application must set the secure flag on session cookies. - App session cookie must carry Secure.
- V-222578 The application must destroy the session ID value and/or cookie on logoff or browser close - App session cookie must be a non-persistent session cookie and be destroyed on logoff.
- V-222594 The application must restrict the ability to launch Denial of Service (DoS) attacks agains - Rate limit at proxy/WAF.
- V-222596 The application must protect the confidentiality and integrity of transmitted information. - App must also enforce TLS end-to-end.
- V-222597 The application must implement cryptographic mechanisms to prevent unauthorized disclosure - App must also enforce TLS end-to-end.
- V-222598 The application must maintain the confidentiality and integrity of information during prep - App must also enforce TLS end-to-end.
- V-222599 The application must maintain the confidentiality and integrity of information during rece - App must also enforce TLS end-to-end.
- V-222602 The application must protect from Cross-Site Scripting (XSS) vulnerabilities. - App XSS protection is app responsibility.
- V-222603 The application must protect from Cross-Site Request Forgery (CSRF) vulnerabilities. - App CSRF protection.

# ASD STIG control inheritance - lab-web

This application delegates all interactive and API authentication to the Keycloak realm `labapp` (auth mode `cac_or_mfa`), configured and verified with the keycloak-asd-stig skill. The rules below list what the application may cite as **inherited** from the identity provider, what it **shares** (identity part inherited, application must still act), and what remains fully its own. Attach the Keycloak verification report/checklist as evidence.

## Inherited from Keycloak (86)

| Vuln | STIG ID | CAT | Requirement | Keycloak provides / app must |
|---|---|---|---|---|
| V-222387 | APSC-DV-000010 | CAT II | The application must provide a capability to limit the number of logon sessions per user. | Browser flow ends with the 'user-session-limits' authenticator (userRealmLimit=profile.sessions.max_per_user, behavior=Deny new session). |
| V-222400 | APSC-DV-000200 | CAT I | Validity periods must be verified on all application messages using WS-Security or SAML assertions. | Keycloak SAML assertions always include Conditions NotBefore/NotOnOrAfter and SubjectConfirmationData NotOnOrAfter; assertion lifespan set to 300s for SAML clients. |
| V-222401 | APSC-DV-000210 | CAT II | The application must ensure each unique asserting party provides unique assertion ID references for each SAML  | Assertion IDs are unique random values (built-in). |
| V-222402 | APSC-DV-000220 | CAT II | The application must ensure encrypted assertions, or equivalent confidentiality protections are used when asse | SAML clients: saml.encrypt=true (encrypted assertions) and signed documents/assertions. |
| V-222403 | APSC-DV-000230 | CAT I | The application must use the NotOnOrAfter condition when using the SubjectConfirmation element in a SAML asser | Keycloak SAML assertions always include Conditions NotBefore/NotOnOrAfter and SubjectConfirmationData NotOnOrAfter; assertion lifespan set to 300s for SAML clients. |
| V-222404 | APSC-DV-000240 | CAT I | The application must use both the NotBefore and NotOnOrAfter elements or OneTimeUse element when using the Con | Keycloak SAML assertions always include Conditions NotBefore/NotOnOrAfter and SubjectConfirmationData NotOnOrAfter; assertion lifespan set to 300s for SAML clients. |
| V-222405 | APSC-DV-000250 | CAT II | The application must ensure if a OneTimeUse element is used in an assertion, there is only one of the same use | Keycloak emits at most one OneTimeUse condition (built-in). |
| V-222406 | APSC-DV-000260 | CAT II | The application must ensure messages are encrypted when the SessionIndex is tied to privacy data. | Assertions encrypted when SAML clients are configured (saml.encrypt=true). |
| V-222407 | APSC-DV-000280 | CAT II | The application must provide automated mechanisms for supporting account management functions. | Keycloak admin console / Admin REST API provide automated account management. |
| V-222409 | APSC-DV-000300 | CAT II | The application must automatically remove or disable temporary user accounts 72 hours after account creation. | Workflow 'stig-temp-account-72h' disables users with account_type=temporary 72h after creation (runner interval 900s). |
| V-222411 | APSC-DV-000320 | CAT III | The application must automatically disable accounts after a 35 day period of account inactivity. | Workflow 'stig-disable-inactive-35d' disables accounts 35 days after creation or last authentication (restarts on every login). |
| V-222413 | APSC-DV-000340 | CAT II | The application must automatically audit account creation. | Admin events enabled with representation details (adminEventsEnabled, adminEventsDetailsEnabled) and shipped to the log/SIEM via jboss-logging + stig-audit listener. |
| V-222414 | APSC-DV-000350 | CAT II | The application must automatically audit account modification. | Admin events enabled with representation details (adminEventsEnabled, adminEventsDetailsEnabled) and shipped to the log/SIEM via jboss-logging + stig-audit listener. |
| V-222415 | APSC-DV-000360 | CAT II | The application must automatically audit account disabling actions. | Admin events enabled with representation details (adminEventsEnabled, adminEventsDetailsEnabled) and shipped to the log/SIEM via jboss-logging + stig-audit listener. |
| V-222416 | APSC-DV-000370 | CAT II | The application must automatically audit account removal actions. | Admin events enabled with representation details (adminEventsEnabled, adminEventsDetailsEnabled) and shipped to the log/SIEM via jboss-logging + stig-audit listener. |
| V-222417 | APSC-DV-000380 | CAT III | The application must notify system administrators (SAs) and information system security officers (ISSOs) when  | Configure SIEM alert on STIG-ACCOUNT-EVENT or set notify-emails + realm SMTP. |
| V-222418 | APSC-DV-000390 | CAT III | The application must notify system administrators (SAs) and information system security officers (ISSOs) when  | Configure SIEM alert on STIG-ACCOUNT-EVENT or set notify-emails + realm SMTP. |
| V-222419 | APSC-DV-000400 | CAT III | The application must notify system administrators (SAs) and information system security officers (ISSOs) of ac | Configure SIEM alert on STIG-ACCOUNT-EVENT or set notify-emails + realm SMTP. |
| V-222420 | APSC-DV-000410 | CAT III | The application must notify system administrators (SAs) and information system security officers (ISSOs) of ac | Configure SIEM alert on STIG-ACCOUNT-EVENT or set notify-emails + realm SMTP. |
| V-222421 | APSC-DV-000420 | CAT II | The application must automatically audit account enabling actions. | Admin events enabled with representation details (adminEventsEnabled, adminEventsDetailsEnabled) and shipped to the log/SIEM via jboss-logging + stig-audit listener. |
| V-222422 | APSC-DV-000430 | CAT III | The application must notify system administrators (SAs) and information system security officers (ISSOs) of ac | Configure SIEM alert on STIG-ACCOUNT-EVENT or set notify-emails + realm SMTP. |
| V-222431 | APSC-DV-000520 | CAT II | The application must audit the execution of privileged functions. | Admin events record every privileged (admin API) operation with actor, IP, resource and representation. |
| V-222432 | APSC-DV-000530 | CAT I | The application must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minut | Brute-force detection: failureFactor=3, maxDeltaTimeSeconds=900 (15 min window), permanentLockout=true. CAC PIN attempts are additionally limited by the card itself. |
| V-222434 | APSC-DV-000550 | CAT III | The application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to th | Apps with their own pre-login pages (outside Keycloak) must also show the banner. |
| V-222435 | APSC-DV-000560 | CAT III | The application must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users ack | Apps with their own pre-login pages (outside Keycloak) must also show the banner. |
| V-222436 | APSC-DV-000570 | CAT III | The publicly accessible application must display the Standard Mandatory DoD Notice and Consent Banner before g | Apps with their own pre-login pages (outside Keycloak) must also show the banner. |
| V-222444 | APSC-DV-000650 | CAT II | The application must not write sensitive data into the application logs. | Apps must not log tokens. |
| V-222446 | APSC-DV-000670 | CAT II | The application must record a time stamp indicating when the event occurred. | Every event record carries an epoch-millisecond timestamp. |
| V-222448 | APSC-DV-000690 | CAT II | The application must provide audit record generation capability for connecting system IP addresses. | Events record the client IP (ipAddress). |
| V-222449 | APSC-DV-000700 | CAT II | The application must record the username or user ID of the user associated with the event. | Events record userId/username. |
| V-222450 | APSC-DV-000710 | CAT II | The application must generate audit records when successful/unsuccessful attempts to grant privileges occur. | Admin events capture successful privilege/role/security-object changes; failed attempts produce 403 on the admin API, captured by the HTTP access log. |
| V-222451 | APSC-DV-000720 | CAT II | The application must generate audit records when successful/unsuccessful attempts to access security objects o | Admin events capture successful privilege/role/security-object changes; failed attempts produce 403 on the admin API, captured by the HTTP access log. |
| V-222454 | APSC-DV-000750 | CAT II | The application must generate audit records when successful/unsuccessful attempts to modify privileges occur. | Admin events capture successful privilege/role/security-object changes; failed attempts produce 403 on the admin API, captured by the HTTP access log. |
| V-222455 | APSC-DV-000760 | CAT II | The application must generate audit records when successful/unsuccessful attempts to modify security objects o | Admin events capture successful privilege/role/security-object changes; failed attempts produce 403 on the admin API, captured by the HTTP access log. |
| V-222458 | APSC-DV-000790 | CAT II | The application must generate audit records when successful/unsuccessful attempts to delete privileges occur. | Admin events capture successful privilege/role/security-object changes; failed attempts produce 403 on the admin API, captured by the HTTP access log. |
| V-222460 | APSC-DV-000810 | CAT II | The application must generate audit records when successful/unsuccessful attempts to delete application databa | Admin events capture successful privilege/role/security-object changes; failed attempts produce 403 on the admin API, captured by the HTTP access log. |
| V-222462 | APSC-DV-000830 | CAT II | The application must generate audit records when successful/unsuccessful logon attempts occur. | LOGIN and LOGIN_ERROR events enabled. |
| V-222463 | APSC-DV-000840 | CAT II | The application must generate audit records for privileged activities or other system-level access. | Admin events + jboss-logging capture privileged activity. |
| V-222464 | APSC-DV-000850 | CAT II | The application must generate audit records showing starting and ending time for user access to the system. | LOGIN and LOGOUT events give start and end times of access. |
| V-222466 | APSC-DV-000870 | CAT II | The application must generate audit records for all direct access to the information system. | All authentication paths go through Keycloak and are logged; direct grant (ROPC) denied. |
| V-222467 | APSC-DV-000880 | CAT II | The application must generate audit records for all account creations, modifications, disabling, and terminati | Admin events enabled with representation details (adminEventsEnabled, adminEventsDetailsEnabled) and shipped to the log/SIEM via jboss-logging + stig-audit listener. |
| V-222468 | APSC-DV-000910 | CAT II | The application must initiate session auditing upon startup. | Event logging is active from server start (realm configuration persisted). |
| V-222473 | APSC-DV-000980 | CAT II | The application must produce audit records containing information to establish when (date and time) the events | Event timestamps (UTC epoch ms). |
| V-222474 | APSC-DV-000990 | CAT II | The application must produce audit records containing enough information to establish which component, feature | Events record clientId, event type and authenticator details. |
| V-222476 | APSC-DV-001010 | CAT II | The application must produce audit records that contain information to establish the outcome of the events. | Events distinguish success (type) and failure (*_ERROR with error code). |
| V-222477 | APSC-DV-001020 | CAT II | The application must generate audit records containing information that establishes the identity of any indivi | Events record user, client, session and IP. |
| V-222478 | APSC-DV-001030 | CAT II | The application must generate audit records containing the full-text recording of privileged commands or the i | Admin events with details record the full representation of privileged changes and the individual admin identity. |
| V-222511 | APSC-DV-001410 | CAT II | The application must enforce access restrictions associated with changes to application configuration. | Configuration changes require realm-admin roles in the admin realm protected by the Alt Token. |
| V-222512 | APSC-DV-001420 | CAT II | The application must audit who makes configuration changes to the application. | Admin events record who changed realm configuration. |
| V-222518 | APSC-DV-001500 | CAT II | The application must be configured to disable non-essential capabilities. | Unneeded capabilities disabled: user registration, self-service reset, implicit/ROPC grants, device flow and CIBA per client; HTTP listener off. |
| V-222520 | APSC-DV-001520 | CAT II | The application must require users to reauthenticate when organization-defined circumstances or situations req | Define organization re-authentication triggers (e.g. role change, sensitive transaction) and request prompt=login / max_age for them. |
| V-222522 | APSC-DV-001540 | CAT I | The application must uniquely identify and authenticate organizational users (or processes acting on behalf of | Every user is a unique Keycloak identity; X.509 maps one certificate UPN to one account (admin-only attribute cac_upn); usernames unique. |
| V-222524 | APSC-DV-001560 | CAT II | The application must accept Personal Identity Verification (PIV) credentials. | Browser flow uses auth-x509-client-username-form; TLS client-auth=request with DoD PKI trust store. |
| V-222525 | APSC-DV-001570 | CAT II | The application must electronically verify Personal Identity Verification (PIV) credentials. | X.509 authenticator validates path to DoD roots, checks revocation (OCSP with CRL fallback, fail-closed), validity dates, key usage digitalSignature. |
| V-222526 | APSC-DV-001580 | CAT II | The application must use multifactor (e.g., CAC, Alt. Token) authentication for network access to non-privileg | Non-privileged network access requires CAC (auth_mode=cac) or CAC-or-(password+OTP/WebAuthn) (auth_mode=cac_or_mfa); password-only paths do not exist. |
| V-222530 | APSC-DV-001620 | CAT II | The application must implement replay-resistant authentication mechanisms for network access to privileged acc | Replay-resistant: TLS 1.2+/1.3 channel, PKCE S256, one-time authorization codes (60s), single-use refresh tokens, OTP codes not reusable. |
| V-222531 | APSC-DV-001630 | CAT II | The application must implement replay-resistant authentication mechanisms for network access to nonprivileged  | Same replay-resistant mechanisms for non-privileged accounts. |
| V-222536 | APSC-DV-001680 | CAT I | The application must enforce a minimum 15-character password length. | Password policy length(15). |
| V-222537 | APSC-DV-001690 | CAT II | The application must enforce password complexity by requiring that at least one uppercase character be used. | Password policy upperCase(1). |
| V-222538 | APSC-DV-001700 | CAT II | The application must enforce password complexity by requiring that at least one lowercase character be used. | Password policy lowerCase(1). |
| V-222539 | APSC-DV-001710 | CAT II | The application must enforce password complexity by requiring that at least one numeric character be used. | Password policy digits(1). |
| V-222540 | APSC-DV-001720 | CAT II | The application must enforce password complexity by requiring that at least one special character be used. | Password policy specialChars(1). |
| V-222542 | APSC-DV-001740 | CAT I | The application must only store cryptographic representations of passwords. | Passwords stored only as PBKDF2-SHA512 hashes, 210000 iterations (FIPS-approved; replaces the non-FIPS argon2 default). |
| V-222543 | APSC-DV-001750 | CAT I | The application must transmit only cryptographically-protected passwords. | Passwords only transmitted over TLS (sslRequired=all, HTTP listener disabled); ROPC grant rejected so apps never handle passwords. |
| V-222544 | APSC-DV-001760 | CAT II | The application must enforce 24 hours/1 day as the minimum password lifetime. | stig-extensions password policy minimumPasswordAge(24): users cannot change their own password again within 24h (admin resets and forced changes exempt). |
| V-222545 | APSC-DV-001770 | CAT II | The application must enforce a 60-day maximum password lifetime restriction. | Password policy forceExpiredPasswordChange(60). |
| V-222546 | APSC-DV-001780 | CAT II | The application must prohibit password reuse for a minimum of five generations. | Password policy passwordHistory(5). |
| V-222547 | APSC-DV-001790 | CAT II | The application must allow the use of a temporary password for system logons with an immediate change to a per | Admin-created/reset passwords are temporary: UPDATE_PASSWORD required action forces an immediate change. |
| V-222548 | APSC-DV-001795 | CAT II | The application password must not be changeable by users other than the administrator or the user with which t | Only the user (via required action/account console with re-auth) or an admin can change a password; user registration and self-service e-mail reset disabled. |
| V-222549 | APSC-DV-001800 | CAT II | The application must terminate existing user sessions upon account deletion. | Relying app must end its own local session at the same idle limit; use short-lived tokens, honor back-channel logout. |
| V-222550 | APSC-DV-001810 | CAT I | The application, when utilizing PKI-based authentication, must validate certificates by constructing a certifi | Path building to DoD trust anchors (truststore-paths) with revocation status (OCSP, CRL fallback). |
| V-222552 | APSC-DV-001830 | CAT II | The application must map the authenticated identity to the individual user or group account for PKI-based auth | Certificate UPN (EDIPI@mil) is mapped to exactly one user via admin-only attribute cac_upn; events log the username, not just certificate data. |
| V-222554 | APSC-DV-001850 | CAT I | The application must not display passwords/PINs as clear text. | Login forms use password inputs (masked); built-in theme. |
| V-222556 | APSC-DV-001870 | CAT II | The application must uniquely identify and authenticate non-organizational users (or processes acting on behal | Non-organizational users get unique accounts the same way (no anonymous/shared access). |
| V-222561 | APSC-DV-001930 | CAT II | Applications used for non-local maintenance sessions must audit non-local maintenance and diagnostic sessions  | Admin events log all remote admin sessions. |
| V-222577 | APSC-DV-002230 | CAT I | The application must not expose session IDs. | Session identifiers are only carried in cookies; sslRequired=all; tokens never placed in URLs (implicit flow rejected by client policy). |
| V-222579 | APSC-DV-002250 | CAT II | Applications must use system-generated session identifiers that protect against session fixation. | Keycloak issues a new session ID at authentication (no fixation); built-in behaviour. |
| V-222580 | APSC-DV-002260 | CAT II | Applications must validate session identifiers. | Keycloak validates session cookies cryptographically (signed identity cookie) on each request; built-in. |
| V-222581 | APSC-DV-002270 | CAT II | Applications must not use URL embedded session IDs. | No URL-embedded session IDs: implicit grant rejected; PKCE S256 enforced for code flow. |
| V-222582 | APSC-DV-002280 | CAT II | The application must not re-use or recycle session IDs. | Session IDs are random UUIDs never reused; refresh tokens single-use (revokeRefreshToken=true, maxReuse=0). |
| V-222584 | APSC-DV-002300 | CAT II | The application must only allow the use of DoD-approved certificate authorities for verification of the establ | Trust store contains only DoD (and optionally ECA) roots; x509-cert-auth.casubjectdn can pin issuing CAs. |
| V-222585 | APSC-DV-002310 | CAT I | The application must fail to a secure state if system initialization fails, shutdown fails, or aborts fail. | Keycloak refuses to start with invalid configuration and fails closed (OCSP fail-open=false, CRL abort if not updated). |
| V-222641 | APSC-DV-003100 | CAT II | The application must use encryption to implement key exchange and authenticate endpoints prior to establishing | TLS key exchange (ECDHE) with server certificate authentication before any application data. |
| V-222661 | APSC-DV-003270 | CAT II | Unnecessary built-in application accounts must be disabled. | Built-in bootstrap admin removed after named admins are created; no sample users. |
| V-222662 | APSC-DV-003280 | CAT I | Default passwords must be changed. | No default credentials remain: bootstrap admin deleted, automation client uses generated secret/JWT. |
| V-222672 | APSC-DV-003360 | CAT III | The application must generate audit records when concurrent logons from different workstations occur. | stig-audit event listener logs WARN 'STIG-CONCURRENT-LOGON' when a user logs in while holding a session from another IP. |

## Shared (application must also act) (53)

| Vuln | STIG ID | CAT | Requirement | Keycloak provides / app must |
|---|---|---|---|---|
| V-222388 | APSC-DV-000060 | CAT II | The application must clear temporary storage and cookies when the session is terminated. | App must clear its own cookies/temporary storage on logout and on back-channel logout. |
| V-222389 | APSC-DV-000070 | CAT II | The application must automatically terminate the non-privileged user session and log off non-privileged users  | Relying app must end its own local session at the same idle limit; use short-lived tokens, honor back-channel logout. |
| V-222390 | APSC-DV-000080 | CAT II | The application must automatically terminate the admin user session and log off admin users after a 10 minute  | Apps with in-app admin roles must enforce a 10 minute idle limit for admin users (or use a dedicated privileged client flagged privileged=true). |
| V-222391 | APSC-DV-000090 | CAT II | Applications requiring user access authentication must provide a logoff capability for user initiated communic | App must expose a visible logoff control that calls the IdP logout endpoint. |
| V-222392 | APSC-DV-000100 | CAT III | The application must display an explicit logoff message to users indicating the reliable termination of authen | App must display an explicit logoff confirmation message. |
| V-222396 | APSC-DV-000160 | CAT II | The application must implement DoD-approved encryption to protect the confidentiality of remote access session | App must also enforce TLS end-to-end. |
| V-222397 | APSC-DV-000170 | CAT II | The application must implement cryptographic mechanisms to protect the integrity of remote access sessions. | App must also enforce TLS end-to-end. |
| V-222410 | APSC-DV-000310 | CAT III | The application must have a process, feature or function that prevents removal or disabling of emergency accou | ISSO procedure: emergency accounts may only be removed with ISSO approval; restrict manage-users on them via fine-grained admin permissions. |
| V-222412 | APSC-DV-000330 | CAT II | Unnecessary application accounts must be disabled, or deleted. | Periodic account review per ISSO. |
| V-222425 | APSC-DV-000460 | CAT I | The application must enforce approved authorizations for logical access to information and system resources in | App must enforce role/attribute checks on every resource (RBAC/ABAC). |
| V-222429 | APSC-DV-000500 | CAT II | The application must prevent non-privileged users from executing privileged functions to include disabling, ci | App must block non-privileged users from privileged functions. |
| V-222433 | APSC-DV-000540 | CAT II | The application administrator must follow an approved process to unlock locked user accounts. | ISSO/ISSM-approved unlock procedure including identity validation (see references/operations.md). |
| V-222437 | APSC-DV-000580 | CAT III | The application must display the time and date of the users last successful logon. | App UI must display the 'previous_login' claim (date/time of last successful logon) after sign-in. |
| V-222441 | APSC-DV-000620 | CAT II | The application must provide audit record generation capability for the creation of session IDs. | App logs its own session lifecycle. |
| V-222442 | APSC-DV-000630 | CAT II | The application must provide audit record generation capability for the destruction of session IDs. | App logs its own session lifecycle. |
| V-222443 | APSC-DV-000640 | CAT II | The application must provide audit record generation capability for the renewal of session IDs. | App logs its own session lifecycle. |
| V-222445 | APSC-DV-000660 | CAT II | The application must provide audit record generation capability for session timeouts. | App logs its own session lifecycle. |
| V-222447 | APSC-DV-000680 | CAT II | The application must provide audit record generation capability for HTTP headers including User-Agent, Referer | HTTP access log enabled (--http-access-log-enabled) with a pattern capturing method, URI, Referer and User-Agent. |
| V-222470 | APSC-DV-000950 | CAT II | The application must log destination IP addresses. | Access log records the local endpoint; events record client IP. |
| V-222500 | APSC-DV-001280 | CAT II | The application must protect audit information from any type of unauthorized read access. | Restrict view-events/manage-events roles to auditors/ISSO. |
| V-222501 | APSC-DV-001290 | CAT II | The application must protect audit information from unauthorized modification. | Restrict view-events/manage-events roles to auditors/ISSO. |
| V-222502 | APSC-DV-001300 | CAT II | The application must protect audit information from unauthorized deletion. | Restrict view-events/manage-events roles to auditors/ISSO. |
| V-222521 | APSC-DV-001530 | CAT II | The application must require devices to reauthenticate when organization-defined circumstances or situations r | Define device re-authentication circumstances. |
| V-222523 | APSC-DV-001550 | CAT II | The application must use multifactor (Alt. Token) authentication for network access to privileged accounts. | Issue Alt Tokens to administrators; do not map their everyday CAC. |
| V-222527 | APSC-DV-001590 | CAT II | The application must use multifactor (Alt. Token) authentication for local access to privileged accounts. | Local console access must also use the Alt Token. |
| V-222528 | APSC-DV-001600 | CAT II | The application must use multifactor (e.g., CAC, Alt. Token) authentication for local access to nonprivileged  | Local (on-host) access paths must not bypass Keycloak. |
| V-222533 | APSC-DV-001650 | CAT II | The application must authenticate all network connected endpoint devices before establishing any connection. | Network devices calling the app must authenticate (mTLS/service account). |
| V-222541 | APSC-DV-001730 | CAT II | The application must require the change of at least eight of the total number of characters when passwords are | POA&M / risk acceptance if passwords are used; otherwise N/A with CAC-only. |
| V-222553 | APSC-DV-001840 | CAT II | The application, for PKI-based authentication, must implement a local cache of revocation data to support path | Run the CRL refresh job (cron/systemd timer) at least daily. |
| V-222557 | APSC-DV-001880 | CAT II | The application must accept Personal Identity Verification (PIV) credentials from other federal agencies. | Decide whether federal PIV is in scope; add FCPCA trust anchors if so. |
| V-222558 | APSC-DV-001890 | CAT II | The application must electronically verify Personal Identity Verification (PIV) credentials from other federal | Decide whether federal PIV is in scope; add FCPCA trust anchors if so. |
| V-222559 | APSC-DV-001900 | CAT II | The application must accept Federal Identity, Credential, and Access Management (FICAM)-approved third-party c | Configure FICAM IdP brokering only if non-DoD users are in scope. |
| V-222560 | APSC-DV-001910 | CAT II | The application must conform to Federal Identity, Credential, and Access Management (FICAM)-issued profiles. | Configure FICAM IdP brokering only if non-DoD users are in scope. |
| V-222562 | APSC-DV-001940 | CAT II | Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the in | Admin (maintenance) access only over TLS on a separate admin hostname. |
| V-222563 | APSC-DV-001950 | CAT II | Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the co | Same as V-222562. |
| V-222564 | APSC-DV-001960 | CAT II | Applications used for non-local maintenance sessions must verify remote disconnection at the termination of no | Admin console logout terminates the admin session. |
| V-222565 | APSC-DV-001970 | CAT II | The application must employ strong authenticators in the establishment of non-local maintenance and diagnostic | Admin realm requires the Alt Token. |
| V-222566 | APSC-DV-001980 | CAT II | The application must terminate all sessions and network connections when nonlocal maintenance is completed. | Admin console session idle 10 minutes. |
| V-222568 | APSC-DV-002000 | CAT II | The application must terminate all network connections associated with a communications session at the end of  | App must drop its connections/session on logout. |
| V-222575 | APSC-DV-002210 | CAT II | The application must set the HTTPOnly flag on session cookies. | App session cookie must be HttpOnly. |
| V-222576 | APSC-DV-002220 | CAT II | The application must set the secure flag on session cookies. | App session cookie must carry Secure. |
| V-222578 | APSC-DV-002240 | CAT I | The application must destroy the session ID value and/or cookie on logoff or browser close. | App session cookie must be a non-persistent session cookie and be destroyed on logoff. |
| V-222594 | APSC-DV-002400 | CAT II | The application must restrict the ability to launch Denial of Service (DoS) attacks against itself or other in | Rate limit at proxy/WAF. |
| V-222596 | APSC-DV-002440 | CAT I | The application must protect the confidentiality and integrity of transmitted information. | App must also enforce TLS end-to-end. |
| V-222597 | APSC-DV-002450 | CAT II | The application must implement cryptographic mechanisms to prevent unauthorized disclosure of information and/ | App must also enforce TLS end-to-end. |
| V-222598 | APSC-DV-002460 | CAT II | The application must maintain the confidentiality and integrity of information during preparation for transmis | App must also enforce TLS end-to-end. |
| V-222599 | APSC-DV-002470 | CAT II | The application must maintain the confidentiality and integrity of information during reception. | App must also enforce TLS end-to-end. |
| V-222600 | APSC-DV-002480 | CAT II | The application must not disclose unnecessary information to users. | Generic login errors ('Invalid username or password') - no user enumeration. |
| V-222602 | APSC-DV-002490 | CAT I | The application must protect from Cross-Site Scripting (XSS) vulnerabilities. | App XSS protection is app responsibility. |
| V-222603 | APSC-DV-002500 | CAT II | The application must protect from Cross-Site Request Forgery (CSRF) vulnerabilities. | App CSRF protection. |
| V-222610 | APSC-DV-002570 | CAT II | The application must generate error messages that provide information necessary for corrective actions without | Keycloak returns generic error pages; stack traces only in server logs. |
| V-222611 | APSC-DV-002580 | CAT II | The application must reveal error messages only to the ISSO, ISSM, or SA. | Detailed errors only in server logs readable by SA. |
| V-222667 | APSC-DV-003320 | CAT II | Protections against DoS attacks must be implemented. | Same as V-222594. |

## Application / platform / process (147)

| Vuln | STIG ID | CAT | Requirement | Keycloak provides / app must |
|---|---|---|---|---|
| V-222393 | APSC-DV-000110 | CAT II | The application must associate organization-defined types of security attributes having organization-defined s | Assess in the application's own ASD checklist. |
| V-222394 | APSC-DV-000120 | CAT II | The application must associate organization-defined types of security attributes having organization-defined s | Assess in the application's own ASD checklist. |
| V-222395 | APSC-DV-000130 | CAT II | The application must associate organization-defined types of security attributes having organization-defined s | Assess in the application's own ASD checklist. |
| V-222398 | APSC-DV-000180 | CAT II | Applications with SOAP messages requiring integrity must include the following message elements:-Message ID-Se | Keycloak does not use WS-Security/SOAP messages. |
| V-222399 | APSC-DV-000190 | CAT I | Messages protected with WS_Security must use time stamps with creation and expiration times. | Keycloak does not use WS-Security/SOAP messages. |
| V-222408 | APSC-DV-000290 | CAT II | Shared/group account credentials must be terminated when members leave the group. | Shared/group accounts are not provisioned by this profile. |
| V-222423 | APSC-DV-000440 | CAT II | Application data protection requirements must be identified and documented. | Assess in the application's own ASD checklist. |
| V-222424 | APSC-DV-000450 | CAT II | The application must utilize organization-defined data mining detection techniques for organization-defined da | Assess in the application's own ASD checklist. |
| V-222426 | APSC-DV-000470 | CAT II | The application must enforce organization-defined discretionary access control policies over defined subjects  | Enforce discretionary access control in the app. |
| V-222427 | APSC-DV-000480 | CAT II | The application must enforce approved authorizations for controlling the flow of information within the system | Assess in the application's own ASD checklist. |
| V-222428 | APSC-DV-000490 | CAT II | The application must enforce approved authorizations for controlling the flow of information between interconn | Assess in the application's own ASD checklist. |
| V-222430 | APSC-DV-000510 | CAT I | The application must execute without excessive account permissions. | Container runs as non-root UID 1000 (Keycloak image default); read-only root FS recommended (deploy/compose.yaml). |
| V-222438 | APSC-DV-000590 | CAT II | The application must protect against an individual (or process acting on behalf of an individual) falsely deny | Assess in the application's own ASD checklist. |
| V-222439 | APSC-DV-000600 | CAT II | For applications providing audit record aggregation, the application must compile audit records from organizat | Assess in the application's own ASD checklist. |
| V-222452 | APSC-DV-000730 | CAT II | The application must generate audit records when successful/unsuccessful attempts to access security levels oc | Keycloak has no classification levels/categories. |
| V-222453 | APSC-DV-000740 | CAT II | The application must generate audit records when successful/unsuccessful attempts to access categories of info | Keycloak has no classification levels/categories. |
| V-222456 | APSC-DV-000770 | CAT II | The application must generate audit records when successful/unsuccessful attempts to modify security levels oc | Keycloak has no classification levels/categories. |
| V-222457 | APSC-DV-000780 | CAT II | The application must generate audit records when successful/unsuccessful attempts to modify categories of info | Keycloak has no classification levels/categories. |
| V-222459 | APSC-DV-000800 | CAT II | The application must generate audit records when successful/unsuccessful attempts to delete security levels oc | Keycloak has no classification levels/categories. |
| V-222461 | APSC-DV-000820 | CAT II | The application must generate audit records when successful/unsuccessful attempts to delete categories of info | Keycloak has no classification levels/categories. |
| V-222465 | APSC-DV-000860 | CAT II | The application must generate audit records when successful/unsuccessful accesses to objects occur. | Assess in the application's own ASD checklist. |
| V-222469 | APSC-DV-000940 | CAT II | The application must log application shutdown events. | Keycloak logs server stop at INFO; console/syslog handler captures it. |
| V-222471 | APSC-DV-000960 | CAT II | The application must log user actions involving access to data. | Assess in the application's own ASD checklist. |
| V-222472 | APSC-DV-000970 | CAT II | The application must log user actions involving changes to data. | Assess in the application's own ASD checklist. |
| V-222475 | APSC-DV-001000 | CAT II | When using centralized logging; the application must include a unique identifier in order to distinguish itsel | Log records tagged with service name via --log-syslog-app-name and JSON console output. |
| V-222479 | APSC-DV-001040 | CAT II | The application must implement transaction recovery logs when transaction based. | Assess in the application's own ASD checklist. |
| V-222480 | APSC-DV-001050 | CAT II | The application must provide centralized management and configuration of the content to be captured in audit r | Point --log-syslog-endpoint at the SIEM collector. |
| V-222481 | APSC-DV-001070 | CAT II | The application must off-load audit records onto a different system or media than the system being audited. | Point --log-syslog-endpoint at the SIEM collector. |
| V-222482 | APSC-DV-001080 | CAT II | The application must be configured to write application logs to a centralized log repository. | Point --log-syslog-endpoint at the SIEM collector. |
| V-222483 | APSC-DV-001090 | CAT II | The application must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit recor | Configure in the SIEM; Keycloak DB event retention (eventsExpiration) is only a local buffer. |
| V-222484 | APSC-DV-001100 | CAT II | Applications categorized as having a moderate or high impact must provide an immediate real-time alert to the  | Configure in the SIEM; Keycloak DB event retention (eventsExpiration) is only a local buffer. |
| V-222485 | APSC-DV-001110 | CAT II | The application must alert the ISSO and SA (at a minimum) in the event of an audit processing failure. | Configure in the SIEM; Keycloak DB event retention (eventsExpiration) is only a local buffer. |
| V-222486 | APSC-DV-001120 | CAT II | The application must shut down by default upon audit failure (unless availability is an overriding concern). | Configure in the SIEM; Keycloak DB event retention (eventsExpiration) is only a local buffer. |
| V-222487 | APSC-DV-001130 | CAT II | The application must provide the capability to centrally review and analyze audit records from multiple compon | Point --log-syslog-endpoint at the SIEM collector. |
| V-222488 | APSC-DV-001140 | CAT II | The application must provide the capability to filter audit records for events of interest based upon organiza | Audit reduction/reporting is provided by the SIEM; the admin console Events view offers filtering of the local buffer. |
| V-222489 | APSC-DV-001150 | CAT II | The application must provide an audit reduction capability that supports on-demand reporting requirements. | Audit reduction/reporting is provided by the SIEM; the admin console Events view offers filtering of the local buffer. |
| V-222490 | APSC-DV-001160 | CAT II | The application must provide an audit reduction capability that supports on-demand audit review and analysis. | Audit reduction/reporting is provided by the SIEM; the admin console Events view offers filtering of the local buffer. |
| V-222491 | APSC-DV-001170 | CAT II | The application must provide an audit reduction capability that supports after-the-fact investigations of secu | Audit reduction/reporting is provided by the SIEM; the admin console Events view offers filtering of the local buffer. |
| V-222492 | APSC-DV-001180 | CAT II | The application must provide a report generation capability that supports on-demand audit review and analysis. | Audit reduction/reporting is provided by the SIEM; the admin console Events view offers filtering of the local buffer. |
| V-222493 | APSC-DV-001190 | CAT II | The application must provide a report generation capability that supports on-demand reporting requirements. | Audit reduction/reporting is provided by the SIEM; the admin console Events view offers filtering of the local buffer. |
| V-222494 | APSC-DV-001200 | CAT II | The application must provide a report generation capability that supports after-the-fact investigations of sec | Audit reduction/reporting is provided by the SIEM; the admin console Events view offers filtering of the local buffer. |
| V-222495 | APSC-DV-001210 | CAT II | The application must provide an audit reduction capability that does not alter original content or time orderi | Audit reduction/reporting is provided by the SIEM; the admin console Events view offers filtering of the local buffer. |
| V-222496 | APSC-DV-001220 | CAT II | The application must provide a report generation capability that does not alter original content or time order | Audit reduction/reporting is provided by the SIEM; the admin console Events view offers filtering of the local buffer. |
| V-222497 | APSC-DV-001250 | CAT II | The applications must use internal system clocks to generate time stamps for audit records. | Timestamps from the host clock (NTP-synced to DoD time source), recorded UTC in milliseconds. |
| V-222498 | APSC-DV-001260 | CAT II | The application must record time stamps for audit records that can be mapped to Coordinated Universal Time (UT | Timestamps from the host clock (NTP-synced to DoD time source), recorded UTC in milliseconds. |
| V-222499 | APSC-DV-001270 | CAT II | The application must record time stamps for audit records that meet a granularity of one second for a minimum  | Timestamps from the host clock (NTP-synced to DoD time source), recorded UTC in milliseconds. |
| V-222503 | APSC-DV-001310 | CAT II | The application must protect audit tools from unauthorized access. | Audit tools are the SIEM and admin console; protect/hash per platform STIG. |
| V-222504 | APSC-DV-001320 | CAT II | The application must protect audit tools from unauthorized modification. | Audit tools are the SIEM and admin console; protect/hash per platform STIG. |
| V-222505 | APSC-DV-001330 | CAT II | The application must protect audit tools from unauthorized deletion. | Audit tools are the SIEM and admin console; protect/hash per platform STIG. |
| V-222506 | APSC-DV-001340 | CAT II | The application must back up audit records at least every seven days onto a different system or system compone | Configure in the SIEM; Keycloak DB event retention (eventsExpiration) is only a local buffer. |
| V-222507 | APSC-DV-001350 | CAT II | The application must use cryptographic mechanisms to protect the integrity of audit information. | Audit tools are the SIEM and admin console; protect/hash per platform STIG. |
| V-222508 | APSC-DV-001360 | CAT II | Application audit tools must be cryptographically hashed. | Audit tools are the SIEM and admin console; protect/hash per platform STIG. |
| V-222509 | APSC-DV-001370 | CAT II | The integrity of the audit tools must be validated by checking the files for changes in the cryptographic hash | Audit tools are the SIEM and admin console; protect/hash per platform STIG. |
| V-222510 | APSC-DV-001390 | CAT II | The application must prohibit user installation of software without explicit privileged status. | Assess in the application's own ASD checklist. |
| V-222513 | APSC-DV-001430 | CAT II | The application must have the capability to prevent the installation of patches, service packs, or application | Assess in the application's own ASD checklist. |
| V-222514 | APSC-DV-001440 | CAT II | The applications must limit privileges to change the software resident within software libraries. | Assess in the application's own ASD checklist. |
| V-222515 | APSC-DV-001460 | CAT II | An application vulnerability assessment must be conducted. | Program/ISSO evidence. |
| V-222516 | APSC-DV-001480 | CAT II | The application must prevent program execution in accordance with organization-defined policies regarding soft | Assess in the application's own ASD checklist. |
| V-222517 | APSC-DV-001490 | CAT II | The application must employ a deny-all, permit-by-exception (whitelist) policy to allow the execution of autho | Assess in the application's own ASD checklist. |
| V-222519 | APSC-DV-001510 | CAT II | The application must be configured to use only functions, ports, and protocols permitted to it in the PPSM CAL | Register ports in PPSM CAL. |
| V-222529 | APSC-DV-001610 | CAT II | The application must ensure users are authenticated with an individual authenticator prior to using a group au | No group authenticators are provisioned. |
| V-222532 | APSC-DV-001640 | CAT II | The application must utilize mutual authentication when endpoint device non-repudiation protections are requir | Mutual TLS available (https-client-auth=request; client-x509 client authentication). |
| V-222534 | APSC-DV-001660 | CAT II | Service-Oriented Applications handling non-releasable data must authenticate endpoint devices via mutual SSL/T | Enable client-x509 for service clients handling non-releasable data. |
| V-222535 | APSC-DV-001670 | CAT II | The application must disable device identifiers after 35 days of inactivity unless a cryptographic certificate | Device accounts = service-account clients authenticated with client JWT/X.509; inactivity workflow does not cover service accounts. |
| V-222551 | APSC-DV-001820 | CAT I | The application, when using PKI-based authentication, must enforce authorized access to the corresponding priv | Server TLS private key file mode 0600/0400 owned by the keycloak UID; mounted read-only. |
| V-222555 | APSC-DV-001860 | CAT I | The application must use mechanisms meeting the requirements of applicable federal laws, Executive Orders, dir | FIPS 140-validated crypto for authentication requires Keycloak FIPS mode (deploy/Dockerfile.fips) on a FIPS-mode RHEL host. |
| V-222567 | APSC-DV-001995 | CAT II | The application must not be vulnerable to race conditions. | Assess in the application's own ASD checklist. |
| V-265634 | APSC-DV-002010 | CAT II | The application must implement NSA-approved cryptography to protect classified information in accordance with  | NSA-approved crypto only for classified systems. |
| V-222570 | APSC-DV-002020 | CAT II | The application must utilize FIPS-validated cryptographic modules when signing application components. | FIPS-validated module requires Keycloak FIPS mode (BCFIPS providers, --features=fips --fips-mode=strict) on a FIPS-enabled OS. |
| V-222571 | APSC-DV-002030 | CAT II | The application must utilize FIPS-validated cryptographic modules when generating cryptographic hashes. | FIPS-validated module requires Keycloak FIPS mode (BCFIPS providers, --features=fips --fips-mode=strict) on a FIPS-enabled OS. |
| V-222572 | APSC-DV-002040 | CAT II | The application must utilize FIPS-validated cryptographic modules when protecting unclassified information tha | FIPS-validated module requires Keycloak FIPS mode (BCFIPS providers, --features=fips --fips-mode=strict) on a FIPS-enabled OS. |
| V-222573 | APSC-DV-002050 | CAT II | Applications making SAML assertions must use FIPS-approved random numbers in the generation of SessionIndex in | SAML SessionIndex generated by Keycloak's SecureRandom; FIPS DRBG in FIPS mode. |
| V-222574 | APSC-DV-002150 | CAT II | The application user interface must be either physically or logically separated from data storage and manageme | Admin console served on a separate hostname (--hostname-admin) reachable only from the admin network; database on a separate tier. |
| V-222583 | APSC-DV-002290 | CAT II | The application must generate a unique session identifier using a FIPS 140-2/140-3 approved random number gene | Session IDs come from the JVM SecureRandom; FIPS-approved DRBG requires Keycloak FIPS mode (BCFIPS) on a FIPS-enabled host (deploy/Dockerfile.fips). |
| V-222586 | APSC-DV-002320 | CAT II | In the event of a system failure, applications must preserve any information necessary to determine cause of f | Assess in the application's own ASD checklist. |
| V-222587 | APSC-DV-002330 | CAT II | The application must protect the confidentiality and integrity of stored information when required by DOD poli | Same as V-222588; passwords additionally hashed, client secrets stored server side only. |
| V-222588 | APSC-DV-002340 | CAT I | The application must implement approved cryptographic mechanisms to prevent unauthorized modification of organ | Encrypt the Keycloak database volume. |
| V-222589 | APSC-DV-002350 | CAT I | The application must use appropriate cryptography in order to protect stored DOD information when required by  | Same as V-222588. |
| V-222590 | APSC-DV-002360 | CAT II | The application must isolate security functions from non-security functions. | Assess in the application's own ASD checklist. |
| V-222591 | APSC-DV-002370 | CAT II | The application must maintain a separate execution domain for each executing process. | Assess in the application's own ASD checklist. |
| V-222592 | APSC-DV-002380 | CAT II | Applications must prevent unauthorized and unintended information transfer via shared system resources. | Assess in the application's own ASD checklist. |
| V-222593 | APSC-DV-002390 | CAT II | XML-based applications must mitigate DoS attacks by using XML filters, parser options, or gateways. | Assess in the application's own ASD checklist. |
| V-222595 | APSC-DV-002410 | CAT II | The web service design must include redundancy mechanisms when used with high-availability systems. | Assess in the application's own ASD checklist. |
| V-222601 | APSC-DV-002485 | CAT I | The application must not store sensitive information in hidden fields. | Assess in the application's own ASD checklist. |
| V-222604 | APSC-DV-002510 | CAT I | The application must protect from command injection. | Assess in the application's own ASD checklist. |
| V-222605 | APSC-DV-002520 | CAT II | The application must protect from canonical representation vulnerabilities. | Assess in the application's own ASD checklist. |
| V-222606 | APSC-DV-002530 | CAT II | The application must validate all input. | Assess in the application's own ASD checklist. |
| V-222607 | APSC-DV-002540 | CAT I | The application must not be vulnerable to SQL Injection. | Assess in the application's own ASD checklist. |
| V-222608 | APSC-DV-002550 | CAT I | The application must not be vulnerable to XML-oriented attacks. | Assess in the application's own ASD checklist. |
| V-222609 | APSC-DV-002560 | CAT I | The application must not be subject to input handling vulnerabilities. | Assess in the application's own ASD checklist. |
| V-222612 | APSC-DV-002590 | CAT I | The application must not be vulnerable to overflow attacks. | Assess in the application's own ASD checklist. |
| V-222613 | APSC-DV-002610 | CAT II | The application must remove organization-defined software components after updated versions have been installe | Assess in the application's own ASD checklist. |
| V-222614 | APSC-DV-002630 | CAT II | Security-relevant software updates and patches must be kept up to date. | Track Keycloak security advisories and patch. |
| V-222615 | APSC-DV-002760 | CAT II | The application performing organization-defined security functions must verify correct operation of security f | Assess in the application's own ASD checklist. |
| V-222616 | APSC-DV-002770 | CAT II | The application must perform verification of the correct operation of security functions: upon system startup  | Assess in the application's own ASD checklist. |
| V-222617 | APSC-DV-002780 | CAT III | The application must notify the ISSO and ISSM of failed security verification tests. | Assess in the application's own ASD checklist. |
| V-222618 | APSC-DV-002870 | CAT II | Unsigned Category 1A mobile code must not be used in the application in accordance with DoD policy. | Assess in the application's own ASD checklist. |
| V-222619 | APSC-DV-002880 | CAT II | The ISSO must ensure an account management process is implemented, verifying only authorized users can gain ac | Account review process; verify output lists inactive/temporary accounts to support it. |
| V-222620 | APSC-DV-002890 | CAT I | Application web servers must be on a separate network segment from the application and database servers if it  | Program/ISSO evidence. |
| V-222621 | APSC-DV-002900 | CAT II | The ISSO must ensure application audit trails are retained for at least 30 months (12 months active + 18 month | Configure in the SIEM; Keycloak DB event retention (eventsExpiration) is only a local buffer. |
| V-222622 | APSC-DV-002910 | CAT II | The ISSO must review audit trails periodically based on system documentation recommendations or immediately up | Program/ISSO evidence. |
| V-222623 | APSC-DV-002920 | CAT II | The ISSO must report all suspected violations of IA policies in accordance with DoD information system IA proc | Program/ISSO evidence. |
| V-222624 | APSC-DV-002930 | CAT II | The ISSO must ensure active vulnerability testing is performed. | Program/ISSO evidence. |
| V-222625 | APSC-DV-002950 | CAT II | Execution flow diagrams and design documents must be created to show how deadlock and recursion issues in web  | Program/ISSO evidence. |
| V-222626 | APSC-DV-002960 | CAT II | The designer must ensure the application does not store configuration and control files in the same directory  | Assess in the application's own ASD checklist. |
| V-222627 | APSC-DV-002970 | CAT II | The ISSO must ensure if a DoD STIG or NSA guide is not available, a third-party product will be configured by  | Program/ISSO evidence. |
| V-222628 | APSC-DV-002980 | CAT II | New IP addresses, data services, and associated ports used by the application must be submitted to the appropr | Program/ISSO evidence. |
| V-222629 | APSC-DV-002990 | CAT II | The application must be registered with the DoD Ports and Protocols Database. | Program/ISSO evidence. |
| V-222630 | APSC-DV-002995 | CAT II | The Configuration Management (CM) repository must be properly patched and STIG compliant. | Program/ISSO evidence. |
| V-222631 | APSC-DV-003000 | CAT II | Access privileges to the Configuration Management (CM) repository must be reviewed every three months. | Program/ISSO evidence. |
| V-222632 | APSC-DV-003010 | CAT II | A Software Configuration Management (SCM) plan describing the configuration control and change management proc | Program/ISSO evidence. |
| V-222633 | APSC-DV-003020 | CAT II | A Configuration Control Board (CCB) that meets at least every release cycle, for managing the Configuration Ma | Program/ISSO evidence. |
| V-222634 | APSC-DV-003030 | CAT II | The application services and interfaces must be compatible with and ready for IPv6 networks. | Assess in the application's own ASD checklist. |
| V-222635 | APSC-DV-003040 | CAT II | The application must not be hosted on a general purpose machine if the application is designated as critical o | Program/ISSO evidence. |
| V-222636 | APSC-DV-003050 | CAT II | A contingency plan must exist in accordance with DOD policy based on the application's availability requiremen | Program/ISSO evidence. |
| V-222637 | APSC-DV-003060 | CAT II | Recovery procedures and technical system features must exist so recovery is performed in a secure and verifiab | Program/ISSO evidence. |
| V-222638 | APSC-DV-003070 | CAT II | Data backup must be performed at required intervals in accordance with DoD policy. | Program/ISSO evidence. |
| V-222639 | APSC-DV-003080 | CAT II | Back-up copies of the application software or source code must be stored in a fire-rated container or stored s | Program/ISSO evidence. |
| V-222640 | APSC-DV-003090 | CAT II | Procedures must be in place to assure the appropriate physical and technical protection of the backup and rest | Program/ISSO evidence. |
| V-222642 | APSC-DV-003110 | CAT I | The application must not contain embedded authentication data. | Assess in the application's own ASD checklist. |
| V-222643 | APSC-DV-003120 | CAT I | The application must have the capability to mark sensitive/classified output when required. | Assess in the application's own ASD checklist. |
| V-222644 | APSC-DV-003130 | CAT III | Prior to each release of the application, updates to system, or applying patches; tests plans and procedures m | Program/ISSO evidence. |
| V-222645 | APSC-DV-003140 | CAT II | Application files must be cryptographically hashed prior to deploying to DoD operational networks. | Program/ISSO evidence. |
| V-222646 | APSC-DV-003150 | CAT II | At least one tester must be designated to test for security flaws in addition to functional testing. | Program/ISSO evidence. |
| V-222647 | APSC-DV-003160 | CAT III | Test procedures must be created and at least annually executed to ensure system initialization, shutdown, and  | Program/ISSO evidence. |
| V-222648 | APSC-DV-003170 | CAT II | An application code review must be performed on the application. | Program/ISSO evidence. |
| V-222649 | APSC-DV-003180 | CAT III | Code coverage statistics must be maintained for each release of the application. | Program/ISSO evidence. |
| V-222650 | APSC-DV-003190 | CAT II | Flaws found during a code review must be tracked in a defect tracking system. | Program/ISSO evidence. |
| V-222651 | APSC-DV-003200 | CAT II | The changes to the application must be assessed for IA and accreditation impact prior to implementation. | Program/ISSO evidence. |
| V-222652 | APSC-DV-003210 | CAT II | Security flaws must be fixed or addressed in the project plan. | Program/ISSO evidence. |
| V-222653 | APSC-DV-003215 | CAT III | The application development team must follow a set of coding standards. | Program/ISSO evidence. |
| V-222654 | APSC-DV-003220 | CAT III | The designer must create and update the Design Document for each release of the application. | Program/ISSO evidence. |
| V-222655 | APSC-DV-003230 | CAT II | Threat models must be documented and reviewed for each application release and updated as required by design a | Program/ISSO evidence. |
| V-222656 | APSC-DV-003235 | CAT II | The application must not be subject to error handling vulnerabilities. | Assess in the application's own ASD checklist. |
| V-222657 | APSC-DV-003236 | CAT II | The application development team must provide an application incident response plan. | Program/ISSO evidence. |
| V-222658 | APSC-DV-003240 | CAT I | All products must be supported by the vendor or the development team. | Use a supported Keycloak release (or Red Hat build of Keycloak with support). |
| V-222659 | APSC-DV-003250 | CAT I | The application must be decommissioned when maintenance or support is no longer available. | Program/ISSO evidence. |
| V-222660 | APSC-DV-003260 | CAT III | Procedures must be in place to notify users when an application is decommissioned. | Program/ISSO evidence. |
| V-222663 | APSC-DV-003285 | CAT II | An Application Configuration Guide must be created and included with the application. | Program/ISSO evidence. |
| V-222664 | APSC-DV-003290 | CAT II | If the application contains classified data, a Security Classification Guide must exist containing data elemen | Program/ISSO evidence. |
| V-222665 | APSC-DV-003300 | CAT II | The designer must ensure uncategorized or emerging mobile code is not used in applications. | Assess in the application's own ASD checklist. |
| V-222666 | APSC-DV-003310 | CAT II | Production database exports must have database administration credentials and sensitive data removed before re | Assess in the application's own ASD checklist. |
| V-222668 | APSC-DV-003330 | CAT II | The system must alert an administrator when low resource conditions are encountered. | Assess in the application's own ASD checklist. |
| V-222669 | APSC-DV-003340 | CAT III | At least one application administrator must be registered to receive update notifications, or security alerts, | Register an admin for update notifications. |
| V-222670 | APSC-DV-003345 | CAT III | The application must provide notifications or alerts when product update and security related patches are avai | Subscribe to Keycloak/RHBK security advisories. |
| V-222671 | APSC-DV-003350 | CAT II | Connections between the DoD enclave and the Internet or other public or commercial wide area networks must req | Program/ISSO evidence. |
| V-222673 | APSC-DV-003400 | CAT II | The Program Manager must verify all levels of program management, designers, developers, and testers receive a | Program/ISSO evidence. |

## Integration requirements for the application

- Use the OIDC authorization-code flow with PKCE (S256) or SAML with signed+encrypted assertions; never the password grant.
- Keep the app's own session idle timeout <= 15 min (<= 10 min for admin functions) and honor back-channel logout.
- Display the `previous_login` claim after sign-in (V-222437).
- Enforce authorization on every request from token roles (fullScopeAllowed is off; map only the roles the app needs).
- Provide a logoff control that calls the end-session endpoint and shows a logoff confirmation (V-222391/V-222392).
- Mark session cookies Secure + HttpOnly + non-persistent (V-222575/V-222576/V-222578).

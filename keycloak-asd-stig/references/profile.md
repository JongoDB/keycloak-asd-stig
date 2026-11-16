# Profile reference (`profile.json`)

The profile is the only file a user edits. `kcstig.py` deep-merges it over the defaults below, so a profile
only needs the keys that differ (realm, clients, users, admins, CRL files). Unknown keys and values weaker than
the STIG produce warnings when any command loads the profile. Start from `assets/profile.example.json`.

Defaults are the STIG values - only change them to be **stricter** (organization-defined values), never looser.

## Contents
- Top level: `keycloak`, `realm`, `auth_mode`, `mfa`
- `x509` (CAC / PIV)
- `sessions`, `lockout`, `password`, `accounts`
- `banner`, `events`, `headers`
- `clients[]` (OIDC confidential, OIDC public, SAML)
- `users[]`
- `admin` (admin realm hardening)
- Minimal profiles for common situations

## Top level

| Key | Type / values | Default | Meaning | STIG |
|---|---|---|---|---|
| `keycloak.url` | URL | `https://localhost:8443` | Base URL used by apply/verify (overridable with `--url`) | - |
| `keycloak.admin_realm` | string | `master` | Realm whose admins run Keycloak; hardened by `--harden-master` | V-222390, V-222523 |
| `realm.name` | string | `app` | Realm to create/harden (also names report files) | - |
| `realm.display_name` | string | `Application` | Shown on the login page and as WebAuthn RP name | - |
| `auth_mode` | `cac` \| `cac_or_mfa` \| `mfa` | `cac_or_mfa` | `cac`: certificate only (password rules become N/A). `cac_or_mfa`: certificate, or password + second factor for people without a card. `mfa`: no PKI - V-222524/525 stay Open | V-222524..528 |
| `mfa` | `otp` \| `webauthn` | `otp` | Second factor on the password path | V-222526, V-222530 |

## `x509` - CAC / PIV authenticator

| Key | Type | Default | Meaning |
|---|---|---|---|
| `mapping_attribute` | string | `cac_upn` | Admin-only user attribute holding the certificate UPN (`EDIPI@mil`). Users cannot edit it (V-222552) |
| `mapping_source` | Keycloak option text | `Subject's Alternative Name otherName (UPN)` | Which certificate field identifies the user. Other values: `Subject's Common Name`, `Subject's Alternative Name E-mail`, `Match SubjectDN using regular expression`, `SHA-256 Thumbprint`, ... |
| `ocsp` | bool | `true` | Check revocation with OCSP (AIA URL or `ocsp_responder_uri`) |
| `ocsp_responder_uri` | URL | `""` | Override the OCSP URL from the certificate |
| `ocsp_fail_open` | bool | `true` | With `crl` on, skip OCSP when the responder is unreachable (the CRL still decides). `false`: OCSP fails closed too |
| `crl` | bool | `true` | Check the local CRL cache. Keep on: OCSP may only fail open when this is on (V-222553) |
| `crl_files` | list of paths | `["crl.pem"]` | Paths **relative to `/opt/keycloak/conf`**, e.g. `crl/DODIDCA_71.crl`. Paste the fragment printed by `fetch_dod_pki.sh` |
| `crldp` | bool | `false` | Also download CRLs from the certificate's CRL distribution point at login (slow; leave off with a local cache) |
| `key_usage` | string | `digitalSignature` | Required KeyUsage bits |
| `extended_key_usage` | string | `""` | Required EKU OIDs/names, comma separated (e.g. `1.3.6.1.5.5.7.3.2`) |
| `certificate_policies` | list of OIDs | `[]` | Accept only these certificate policies. Take OIDs from the current DoD CP; test with real cards first |
| `certificate_policy_mode` | `All` \| `Any` | `Any` | How `certificate_policies` are matched |
| `ca_subject_dns` | list of DNs | `[]` | Pin acceptable issuing CAs |
| `confirmation_page` | bool | `true` | Show the "You will be logged in as ..." page (the banner gate appears there) |

## `sessions`, `lockout`, `password`, `accounts`

| Key | Default | STIG ceiling/floor | Meaning | STIG |
|---|---|---|---|---|
| `sessions.user_idle_minutes` | 15 | <= 15 | SSO idle timeout (and offline session idle) | V-222389 |
| `sessions.admin_idle_minutes` | 10 | <= 10 | Admin realm idle, `security-admin-console` override, and every client with `privileged: true` | V-222390 |
| `sessions.max_hours` | 8 | org-defined | SSO max lifespan - forces re-authentication | V-222520 |
| `sessions.max_per_user` | 3 | org-defined, > 0 | Concurrent sessions per user (`user-session-limits`, deny new) | V-222387 |
| `sessions.access_token_minutes` | 5 | short | Access token lifetime | V-222521 |
| `lockout.max_failures` | 3 | <= 3 | Failures before lockout | V-222432 |
| `lockout.window_minutes` | 15 | >= 15 | Counting window (and wait if not permanent) | V-222432 |
| `lockout.permanent` | true | - | Locked until an admin unlocks (approved procedure) | V-222433 |
| `lockout.max_wait_hours` | 24 | - | Temporary lockout only: the lock grows by `window_minutes` per further `max_failures` failures, up to this | V-222432 |
| `lockout.reset_hours` | 24 | >= window | Temporary lockout only: how long failures are remembered (so the lock can grow) | V-222432 |
| `password.min_length` | 15 | >= 15 | `length()` | V-222536 |
| `password.max_length` | 128 | - | `maxLength()` | - |
| `password.history` | 5 | >= 5 | `passwordHistory()` | V-222546 |
| `password.max_age_days` | 60 | <= 60 | `forceExpiredPasswordChange()` | V-222545 |
| `password.min_age_hours` | 24 | >= 24 | `minimumPasswordAge()` from stig-extensions.jar | V-222544 |
| `password.hash` | `pbkdf2-sha512` | FIPS-approved | Never `argon2` (not FIPS) | V-222542, V-222571 |
| `password.iterations` | 210000 | - | PBKDF2 iterations | - |
| `accounts.inactive_days` | 35 | <= 35 | Workflow: disable after N days without logon | V-222411 |
| `accounts.temp_hours` | 72 | <= 72 | Workflow: disable `account_type=temporary` users N hours after creation | V-222409 |

Upper/lower/digit/special (1 each), `notUsername`, `notEmail` are always added.

## `banner`, `events`, `headers`

| Key | Default | Meaning | STIG |
|---|---|---|---|
| `banner.theme` | `dod-stig` | Login theme with the DoD Notice & Consent gate (must be installed on the server) | V-222434..436 |
| `banner.terms_required_action` | true | Also enable Terms & Conditions (same text) as a server-side backstop on first login | V-222435 |
| `events.retention_days` | 90 | Local event buffer in the DB; long-term retention belongs in the SIEM | V-222621 |
| `events.listeners` | `["jboss-logging","stig-audit"]` | Event listeners; `stig-audit` is dropped automatically if the extension is not installed | V-222417..422, V-222437, V-222672 |
| `headers.hsts` | `max-age=31536000; includeSubDomains` | Strict-Transport-Security value | V-222596 |

## `clients[]`

Reserved: `client_id` may not be one of Keycloak's own clients (`account`, `account-console`, `admin-cli`,
`broker`, `realm-management`, `security-admin-console`) or end in `-realm`. `load_profile` stops on such a profile or
clients.d file, and `upsert_client` refuses them, so no clients.d file can overwrite part of the IdP.

Registering an application team's client: take their `client-request.json` (format and validator in
`keycloak-rp-integration/`) and run `kcstig.py add-client client-request.json --profile p.json --clients-dir
clients.d --owner <owner id>`. It validates the request with the relying-party validator's rules (warnings refuse
too unless `--no-strict`) and refuses reserved ids. It records the owner (`stig.owner`, `stig.owner-contact`, and
`owner`/`owner_contact` in the clients.d file), applies the client live and writes `clients.d/<client_id>.json`.
Changing an existing client needs `--update <id>` and prints a before/after diff of the redirect, logout and JWKS
URLs. Another owner's client also needs `--transfer`, a client add-client did not create also needs `--adopt <id>`,
and `--prune-roles` deletes roles the request dropped. With `auth: client-secret`, `--secret-out FILE` writes the
secret (0600, never printed). Run `validate-client-request.py --strict` on the file you received first, and confirm
any change request with the recorded contact through a second channel (`keycloak-rp-integration/references/operator-handoff.md`).

Keys only `add-client` writes: `owner`, `owner_contact` (become the client attributes `stig.owner`,
`stig.owner-contact` and `stig.created-by=add-client`). They are honoured only in `clients.d/<client_id>.json` and
dropped, with a warning, anywhere else. Each `client_id` may be defined once across the profile and clients.d: a
second definition stops the load. `apply` refuses to change a live client whose `stig.owner` differs from the
definition's. `--owner` is required when `add-client` creates a client.

Common keys:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `client_id` | string | required | OIDC client ID, or the SAML entity ID |
| `type` | `oidc-confidential` \| `oidc-public` \| `saml` | `oidc-confidential` | Server app / SPA or native app / SAML SP |
| `name` | string | `client_id` | Display name |
| `root_url` | URL | `""` | Base URL |
| `redirect_uris` | list | `[]` | **Exact** URIs. Any `*` makes the generator stop with an error |
| `privileged` | bool | false | Applies the admin idle timeout (`admin_idle_minutes`) to this client: use for admin front ends | 

OIDC-only keys:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `post_logout_redirect_uris` | list | `[]` | Allowed RP-initiated logout targets |
| `backchannel_logout_url` | URL | none | Keycloak calls it when the SSO session ends (V-222568). Set `post_logout_redirect_uris` or this, or verify reports `clients.logout_configured` failing |
| `web_origins` | list | `[]` | CORS origins (exact, no `*`) |
| `auth` | `client-secret` \| `client-jwt` \| `client-x509` | `client-secret` | Confidential client authentication. Prefer `client-jwt` |
| `jwks_url` | URL | none | Public keys for `client-jwt` |
| `subject_dn` | DN | none | Expected certificate subject for `client-x509` (mTLS) |
| `service_account` | bool | false | Enable client-credentials grant (confidential only) |
| `standard_flow` | bool | true | Authorization-code flow |
| `par` | bool | false | Require Pushed Authorization Requests |

Always enforced for OIDC: PKCE S256, implicit off, direct access grants off, `fullScopeAllowed=false`, no
offline_access scope, device flow and CIBA off.

SAML-only keys:

| Key | Type | Meaning |
|---|---|---|
| `acs_url` | URL | Assertion Consumer Service (POST binding); also the default redirect URI |
| `slo_url` | URL | Single Logout URL |
| `signing_cert` | PEM body | SP certificate used to verify signed AuthnRequests |
| `encryption_cert` | PEM body | SP certificate Keycloak encrypts assertions to. **Required** in practice because `saml.encrypt=true` is always set (V-222402) |

Always enforced for SAML: signed documents and assertions, client signature required, RSA-SHA256, POST binding,
persistent NameID, assertion lifespan 300 s.

## `users[]` (optional seed users)

| Key | Meaning |
|---|---|
| `username` | Required, at least 3 characters |
| `email`, `firstName`, `lastName` | Profile fields (the user profile requires them) |
| `cac_upn` (= `x509.mapping_attribute`) | Certificate UPN `EDIPI@mil`. Users with it get no OTP enrolment: the card and PIN are already two factors |
| `temporary_password` | Password users only. Must be changed at first login (V-222547); OTP/WebAuthn enrolment follows |
| `account_type` | `permanent` (default) \| `temporary` (72 h workflow) \| `emergency` (exempt from inactivity) |

## `admin` (admin realm, applied with `--harden-master`)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `mfa` | `x509` \| `webauthn` \| `otp` | `x509` | `x509` = Alt Token (STIG intent, V-222523). `webauthn` = password + FIDO2 key (needs ISSO acceptance). `otp` = lab only; verify marks it for manual review |
| `mapping_attribute` | string | `alt_token_upn` | Admin-only attribute holding the Alt Token UPN. Keep it different from `x509.mapping_attribute` so an everyday CAC cannot open the console |
| `users[]` | list | `[]` | Named administrators: `username`, `email`, `firstName`, `lastName`, `alt_token_upn` (required for `x509`). Hardening refuses to run with an empty list |
| `automation_client` | string or `null` | `stig-automation` | Service account created for scripted admin (secret written to `--secret-out`, mode 0600). `null` = none: you then need break-glass for every later run |
| `allow_emergency_password` | bool | false | Adds a password + second-factor path to the admin flow next to the Alt Token (break-glass accounts). Leave false unless the ISSO approves |

## Minimal profiles

CAC only, one server app (most DoD apps):
```json
{"realm": {"name": "logtrack", "display_name": "LogTrack"},
 "auth_mode": "cac",
 "x509": {"crl_files": ["crl/DODIDCA_71.crl", "crl/DODIDCA_72.crl"]},
 "clients": [{"client_id": "logtrack-web", "auth": "client-jwt", "jwks_url": "https://logtrack.army.mil/jwks",
              "redirect_uris": ["https://logtrack.army.mil/oauth2/callback"],
              "backchannel_logout_url": "https://logtrack.army.mil/oauth2/bc-logout"}],
 "admin": {"users": [{"username": "doe.jane.adm", "email": "jane.doe@army.mil", "firstName": "Jane",
                      "lastName": "Doe", "alt_token_upn": "1234567890.alt@mil"}]}}
```

CAC users plus contractors without cards: same, with `"auth_mode": "cac_or_mfa"` and contractors in `users[]`
with `temporary_password` and no `cac_upn`.

Lab without PKI: `"auth_mode": "mfa"` and `"admin": {"mfa": "otp", ...}` - verify will keep the PKI rules Open.

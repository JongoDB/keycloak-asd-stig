# Operations runbook (procedures assessors ask for)

## Contents
1. Break-glass / admin recovery
2. Unlocking a locked account (V-222433)
3. Temporary and emergency accounts (V-222409, V-222410)
4. CRL refresh (V-222553)
5. Audit off-load and alerts (V-222481..V-222485, V-222417..V-222422)
6. Re-running apply / verify (drift control)
7. Upgrading Keycloak
8. Delegated account creation: allowed e-mail domains (stig-accounts)
9. Account administration from another application's page (admin-API client profile, step-up)
10. First sign-in through an identity provider binds a pending invite (optional)

## 1. Break-glass / admin recovery
After hardening, the admin realm has no password grant (ROPC denied), the bootstrap admin is deleted, and
admins log in only with the Alt Token. If every admin is locked out:
```
# on the Keycloak host, same image/config/DB as the running server
export RECOVERY_SECRET=$(openssl rand -hex 24)
docker compose run --rm --no-deps -e RECOVERY_SECRET keycloak \
  bootstrap-admin service --client-id=break-glass-recovery --client-secret:env=RECOVERY_SECRET --optimized
```
Kubernetes: run the same command as a one-off pod with the Keycloak Deployment's image, env and secret volumes
(e.g. `kubectl debug deploy/keycloak --copy-to=kc-recovery --container=keycloak -- /opt/keycloak/bin/kc.sh
bootstrap-admin service --client-id=break-glass-recovery --client-secret:env=RECOVERY_SECRET --optimized`, with
RECOVERY_SECRET added to the copy's env), then delete the copy. (Tested with Compose against the same database.)

This creates a temporary admin *service client* (flagged `is_temporary_admin`). Use it via
`KC_CLIENT_ID=break-glass-recovery KC_CLIENT_SECRET=$RECOVERY_SECRET kcstig.py ...` to repair, then run
`kcstig.py apply --profile p.json --admin-only --harden-master --remove-bootstrap-admin` with the normal
automation credentials - it deletes temporary admin users AND clients, and `verify` fails
`master.no_bootstrap_admin` until it is gone. Log the event and notify the ISSO (tested in the lab).

## 2. Unlocking a locked account (V-222433)
`permanentLockout=true`: after 3 failures in 15 minutes the account stays disabled until an admin acts.
Approved procedure (have the ISSM/ISSO sign it):
1. The user contacts the service desk; identity is verified in person or by a callback to the number of record
   plus a second identity attribute (never by e-mail alone).
2. Admin console > realm > Users > the user > toggle *Enabled* (or Sessions/Brute force "Unlock").
3. If a password compromise is suspected: Credentials > Reset password (temporary) - the user must change it
   at next login (V-222547).
4. Record ticket number, verifier, time. The admin event (`STIG-ACCOUNT-EVENT action=ENABLED_OR_MODIFIED`)
   is the system record.

## 3. Temporary and emergency accounts
- Temporary: create with attribute `account_type=temporary`; workflow `stig-temp-account-72h` disables it
  72 h after creation. The runner interval (`step-runner-task-interval=900` s) bounds the lateness to 15 min.
- Emergency: `account_type=emergency` exempts the account from the 35-day inactivity workflow. Restrict who
  may delete such accounts (fine-grained admin permissions) and review them quarterly.
- Inactivity: workflow `stig-disable-inactive-35d` (`on: user-created or user-authenticated`,
  `restart-in-progress: true`) disables users 35 days after creation or their last logon.

## 4. CRL refresh
`scripts/fetch_dod_pki.sh /srv/keycloak-stig --crl-only` daily, e.g. systemd timer or
`17 3 * * * root /opt/kcstig/scripts/fetch_dod_pki.sh /srv/keycloak-stig --crl-only >> /var/log/kc-crl.log 2>&1`.
Alert if a CRL's nextUpdate is within 24 h (Keycloak refuses stale CRLs: logins would fail closed).

## 5. Audit off-load and alerts
- Events reach the SIEM through `log=console,syslog` (`log-syslog-endpoint`), JSON console, and the HTTP access
  log. User events (LOGIN, LOGIN_ERROR, LOGOUT, CODE_TO_TOKEN, REFRESH_TOKEN, UPDATE_PASSWORD ...) and admin
  events (with representation) are logged by `jboss-logging` at INFO/WARN.
- SIEM alert rules to create:
  - `STIG-ACCOUNT-EVENT` -> notify SA + ISSO (account create/modify/disable/enable/remove).
  - `STIG-CONCURRENT-LOGON` -> notify (concurrent logons from different workstations, V-222672).
  - `error="user_temporarily_disabled"` / lockouts -> notify.
  - syslog silence > 5 min from a Keycloak node -> audit-failure alert (V-222484/V-222485).
- Retention: 30 months (12 online + 18 cold), 5 years for SAMI (V-222621) in the SIEM. `eventsExpiration` in
  Keycloak is only the local buffer (default 90 days).

## 6. Drift control
Run `kcstig.py verify --profile p.json --live-url https://... --deploy-dir <stack> --strict` from CI nightly
with the automation service account. Non-zero exit = drift. Attach the generated `.ckl/.cklb` to eMASS.
`apply` is idempotent: flows are rebuilt, workflows are only replaced when their definition changed (so the
inactivity clocks of existing users are preserved).

## 7. Upgrading Keycloak (tested 26.7.5 -> 26.8.2 in place on the same database)
1. `scripts/build_images.sh --base-image <new image> --tag <new>-stig ...` (recompiles the SPI for that version).
2. Roll the Keycloak image; Keycloak migrates the database on start ("Migrating older model to 26.8.0").
3. Run the apply job. Workflows are left untouched when unchanged, so users' 35-day/72-hour timers survive
   (same workflow IDs before and after, verified).
4. **Crossing into 26.8 from an older release:** the admin API starts requiring the `kc-admin-api` audience and the
   existing automation service account does not get that scope during migration - the apply job fails with 401
   (`kcstig.py` prints this diagnosis). Recover once:
   ```
   export RECOVERY_SECRET=$(openssl rand -hex 24)
   <run the new Keycloak image with the same env/secrets>: kc.sh bootstrap-admin service --client-id=break-glass-recovery --client-secret:env=RECOVERY_SECRET --optimized
   KC_CLIENT_ID=break-glass-recovery KC_CLIENT_SECRET=$RECOVERY_SECRET kcstig.py apply --profile p.json --harden-master --automation-secret-file <file>   # adds kc-admin-api
   KC_CLIENT_ID=stig-automation ... kcstig.py apply --profile p.json --harden-master --remove-bootstrap-admin ...           # deletes the recovery client
   ```
5. Run `verify` and `e2e_check.py` (tested: 20/20 and clean verify after the upgrade).
6. Re-check `references/keycloak-notes.md` against the release notes (build-time options, admin API, client-policy
   executors, theme page IDs, workflow syntax).

## 8. Delegated account creation: allowed e-mail domains (stig-accounts)

> **Upgrade note.** The built-in default no longer includes any domain other than `.mil`, and a configured value
> is now authoritative and fails closed. **Before upgrading**, set `stig.accounts.email-domains` (on the realm, or
> on the calling client) to the list you rely on, or creations for those domains are refused with 403.
>
> | Situation | Before | After |
> |---|---|---|
> | Attribute unset on both client and realm | `.mil` plus one built-in non-`.mil` domain | `.mil` only |
> | Client attribute set but blank | fell through to the realm attribute | no domain allowed for that caller |
> | Realm attribute set but blank | fell back to the built-in default | no domain allowed |
> | A list with one malformed entry (`*.mil`, `@x.org`, `x .org`, a trailing dot as in `example.org.`, an underscore as in `my_org.mil`) | the bad entry was skipped and the rest applied | no domain allowed: one bad entry disables the whole list |
> | A well-formed list | applied | applied (unchanged) |
The `stig-accounts` admin endpoint (in `stig-extensions.jar`) lets an IdP user manager, or an application's service
account holding `realm-management/query-users`, create accounts. It creates them only for e-mail addresses in an
allowlist of domains:

| Where | Attribute | Scope |
|---|---|---|
| The caller's client (service-account callers) | `stig.accounts.email-domains` | that caller only; wins over the realm |
| The realm | `stig.accounts.email-domains` | every caller without a client value |

- Value: a comma list. `.mil` matches any domain ending in `.mil`; `example.org` matches exactly that domain, not
  its subdomains. Example: `.mil,example.org`.
- **Unset on both: `.mil` only.** Every other organization's domain must be configured explicitly.
- **Set but with no entries, or with any malformed entry** (`*.mil`, `@example.org`, `x .org`): **no domain is
  allowed**. The endpoint fails closed and refuses every creation with "e-mail domain not allowed for this caller".
  To switch delegated creation off for a caller, set `,`. Keycloak may drop an attribute set to an empty string,
  which would bring back the `.mil` default.
- A configured value replaces the default. Keep `.mil` in it if you still want it.
- `kcstig.py apply` does not touch realm attributes, so the value survives re-runs.

Set it on the realm (every caller):
```bash
kcadm.sh update realms/<realm> -s 'attributes."stig.accounts.email-domains"=".mil,example.org"'
```
or on one calling client:
```bash
kcadm.sh update clients/<client uuid> -r <realm> -s 'attributes."stig.accounts.email-domains"="example.org"'
```
Check it with `kcadm.sh get realms/<realm> --fields attributes`. Refusals are logged as `STIG-ACCOUNTS-REFUSED`
and name the domain list in force.

Other `stig-accounts` limits, whoever calls: at most **20 creations and 20 disables per caller in any 60 minutes**
(a sliding window: each one holds a slot for exactly an hour; 429 beyond; a refused disable leaves the account enabled;
a creation claims its slot after the caller's own mistakes - malformed input, a domain, a lifespan or a group it
cannot manage, which spend none - and BEFORE the username/e-mail existence check, so every 409 spends one and probing
whether an account exists is capped at 20 an hour; the 409 never says which of the two is taken), a set-up e-mail re-sent at most once per 15 minutes and only
while the account is not set up. Every call may carry an optional `reference` (a body field of `POST /users`,
`?reference=` on the others; 1-64 characters of `A-Z a-z 0-9 . _ : -`, otherwise 400), for example the id of the
request a call fulfils. It is recorded in the admin event's representation and in the `STIG-ACCOUNTS` log line, so an
application's own records can be matched to the IdP's exactly.

## 9. Account administration from another application's page (admin-API client profile, step-up)

Use this when an application wants a page on which **your delegated user managers** create, re-send, disable and move
accounts, without the application holding any credential that can do so. The person signed in to the page acts with
**their own token**; the IdP decides every call by that person's own permissions.

**The client.** A dedicated public OIDC client for that page:

| Setting | Value |
|---|---|
| Client type | public, standard flow with PKCE S256 only (no implicit, direct grant, device, CIBA or token exchange), no service account |
| Redirect URI / web origin | exactly the page's callback, and its origin (the only origin the admin API then answers CORS for) |
| `fullScopeAllowed` | `false` |
| Scope mappings | `realm-management` **`query-users` and `query-groups` only**. Keycloak honours a realm-management role on the admin API only if the client may carry it, so no token from this client ever carries more, whoever signs in (a realm administrator included) |
| Default client scopes | the admin console's: `kc-admin-api` (the admin-API audience), `web-origins` (allowed origins), `basic` (`auth_time`), `acr`, `roles`, `profile`, `email`; no optional scopes, no protocol mappers |
| Tokens | refresh tokens off, short access tokens (300 s), client session idle 10 minutes (V-222390 for an administrative page) |
| `stig.admin-api.profile` | `account-onboarding` |
| `stig.admin-api.max-auth-age` | seconds (30..900, default 300) |
| `stig.admin-api.operations` | optional: the writes it may make, a comma list of `create`, `setup-email`, `disable`, `membership` (group PUT/DELETE). Unset: all four. Set but blank, or naming anything else: every request refused. Capability `admin-api-profile=2` |
| Optional | `dpop.bound.access.tokens=true`: tokens bound to a key the page holds (RFC 9449). Keycloak's admin API then refuses the token without a proof from that key, so a token copied out of the page is useless elsewhere |

**What `AdminApiGuardFilter` enforces for such a client** (every caller, administrators included):

- Reads: `users` (search and count), `users/{id}`, `users/{id}/groups`, `groups`, `groups/{id}`, `groups/{id}/children`,
  `groups/{id}/members`, `group-by-path/...`.
- Writes: `POST stig-accounts/users`, `POST stig-accounts/users/{id}/setup-email`, `POST stig-accounts/users/{id}/disable`,
  `PUT` and `DELETE users/{id}/groups/{groupId}`.
- **Anything else: 403**, logged `STIG-ADMIN-API-PROFILE-REFUSED`. Edits, credentials, resets, execute-actions mail,
  impersonation, role mappings, events and clients are therefore unreachable through the page, whoever is signed in.
- **A write whose authentication is older than `stig.admin-api.max-auth-age`** (the token's `auth_time`; a token
  without one counts as too old): **401** with an RFC 9470 challenge,
  `WWW-Authenticate: Bearer error="insufficient_user_authentication", ..., max_age="300"`, logged
  `STIG-ADMIN-API-STEP-UP-REQUIRED`. The page signs the person in again with `max_age` (the realm's full flow: card, or
  password plus OTP) and retries. Reads are not stepped up.
- Another value of `stig.admin-api.profile`, or a malformed max age - **a set but blank value included** (as for
  `stig.accounts.email-domains`): every request from that client is refused (fail closed). No attribute: the client is
  not restricted by this rule.
- A **master-realm** client carrying `stig.admin-api.profile` is refused outright: the master realm is never confined,
  so a client there must not look as if it were.
- **The profile confines the admin API only** (`/admin/realms/...`). The same token still works wherever any token of
  the realm does (userinfo, the account console's API for that person's own account); nothing there reaches other
  accounts, but do not read the profile as a general token restriction.
- Within the profile, Keycloak's own permissions and `stig-accounts`' rules still decide: a delegated user manager
  reaches only the groups their fine-grained permissions cover.

The filter states its capability as `admin-api-profile=<version>` in the allowlist gate's `operationalInfo` (server
info, `providers.authenticator.providers.stig-admin-allowlist-gate`). The version is a number, compared numerically:
**`>= 1` before creating a client with `stig.admin-api.profile`**, and **`>= 2` before setting
`stig.admin-api.operations`**. An older extension ignores the attribute it does not know, which silently widens the
client: at version 1 an operations list is not enforced, so the client may make all four writes. An operations list
on a client WITHOUT `stig.admin-api.profile` (version 2 and later) refuses every request from that client (403,
`STIG-ADMIN-API-PROFILE-REFUSED`), rather than confining nothing. Its audit lines (`STIG-ADMIN-API-PROFILE-REFUSED`,
`STIG-ADMIN-API-STEP-UP-REQUIRED`, and the filter's `STIG-ADMIN-NOT-ALLOWLISTED` and `STIG-ATTRIBUTE-PROBE-REFUSED`) log
the raw request path with control characters replaced, so a `%0a` in a request cannot forge a line. **Read it before
creating such a client**: on an older
extension the attribute is ignored and the client would reach the whole admin API with no step-up. Also check the
client's shape regularly (scope mappings above all): an added `realm-admin` mapping would put administrator-grade
tokens on an application's origin.

**CORS.** Keycloak answers a preflight from any origin, and on the actual response grants only an origin in the token's
`allowed-origins` (from the client's web origins); a request from another origin carrying such a token is refused (403).
Refusals (401, 403, 409, 429) carry the CORS header too, so the page can show the reason. The step-up 401 also
sends `Access-Control-Expose-Headers: WWW-Authenticate`, without which a browser page cannot read the challenge (or its
`max_age`) cross-origin. Tell it apart from an EXPIRED token: that 401 comes from Keycloak itself, before the profile
is checked, and carries no `insufficient_user_authentication` challenge - get a new token silently and retry. Record the application origin
as an admin-API client in your V-222574 (separate admin interface) assessment.

## 10. First sign-in through an identity provider binds a pending invite (optional)

Off by default. With it on, a delegated user manager invites a person who signs in through the realm's external
identity provider (for example the organisation's Microsoft Entra tenant) WITHOUT copying the provider's object id: the
person's FIRST sign-in binds it.

**How to switch it on.** In the realm's first-broker-login flow, the `idp-link-by-admin-attribute` execution's
configuration gains `stig.pending-invite-domain` (the provider's UPN domain; empty = off) and optionally
`stig.pending-invite-max-age-days` (1..30, default 7), `stig.vouched-upn-attribute` (default `entra_vouched_upn`),
`stig.card-attribute` (default `cac_edipi`) and `stig.created-by-attribute` (default `stig_created_by`). Add an
identity-provider mapper copying the provider's principal-name claim (Entra: `preferred_username`, the UPN) into the
vouched-UPN attribute. Set the realm attribute `stig.accounts.entra-domain` to the same domain so `stig-accounts` can make
such invites. A malformed domain or max age switches the binding off (fail closed).

**When it binds.** Only after the usual checks passed (the configured provider alias and tenant, no mapper writing the
binding attribute, a vouched object id) and NO account carries that object id; then ALL of these, or the sign-in is
refused exactly as without the option:
- the vouched principal name is `local@<domain>` (the provider's UPN claim, never its e-mail claim);
- exactly one account has it as username or e-mail (case-insensitive);
- that account was invited FOR the provider: it carries the `entra_pending` marker (only `stig-accounts`' `"signIn":
  "entra"` sets it), its e-mail is in the domain, and it owes no password, OTP or passkey set-up - a password-type
  invite still in set-up is never claimed through the provider;
- it carries the delegate-creation marker, is enabled, has no binding, no stored credential and no card binding, and is
  at most the configured number of days old (Keycloak's creation time, the delegate marker's and the pending marker's;
  the oldest counts; any time in the future refuses).

**Guests are never bound.** A guest of the tenant (B2B from another tenant, e-mail one-time passcode, a Microsoft
account) carries the tenant's `tid` but its HOME sign-in name as `preferred_username`, which may well be in the domain.
Entra marks it with the `idp` claim (absent for the tenant's members, or naming the tenant itself) and the optional `acct`
claim (1 for a guest): map `idp` into `stig.vouched-idp-attribute` (default `entra_vouched_idp`) and `acct` into
`stig.vouched-acct-attribute` (default `entra_vouched_acct`; ask the provider to send that optional claim); a guest is refused. The binding also refuses unless the
mappers are pinned: EXACTLY ONE mapper in the realm writes the UPN attribute, and it is this provider's attribute importer
of `preferred_username`; the same for the idp attribute from `idp` and the acct attribute from `acct`. Only use a domain that is one of the tenant's VERIFIED domains - only then does the tenant own every
UPN in it.

The marker's value is fixed (`entra_pending` = `pending`), so tooling finds pending invites with an exact attribute search
(`q=entra_pending:pending`); their age comes from Keycloak's creation time and the delegate marker's.

**The binding stands even if a later step fails.** The binding is written during the first-broker step; if a later step
of the sign-in then refuses (the post-broker checks, an administrator's MFA, the session limit, the terms not accepted),
the account stays bound to that identity and the person simply signs in again. It is never bound to anyone else.

The binding happens once: a cluster-wide single-use slot per account admits one binding sign-in (a racing second one is
refused), and the binding sets the attribute and removes the pending marker, after which the account no longer
qualifies.

On success the binding attribute is set, the `entra_pending` marker removed, an admin event recorded (UPDATE USER,
attributed to the account, with the binding in its representation, which the concealment filter hides from
non-administrators) and `STIG-IDP-PENDING-INVITE-BOUND` logged. From then on the binding is fixed like an administrator-set
one: a different object id is refused. Nothing is ever created from a provider sign-in.

**Inviting.** `stig-accounts` `POST /users` takes `"signIn": "entra"`: the account gets only the terms required
action (no password or OTP set-up), no set-up mail (`setupEmail: none`), and the `entra_pending` marker; it is refused
(403) unless the address is exactly in the realm's `stig.accounts.entra-domain`. `setup-email` answers 409 for it.
The trust added: the provider's tenant owns its UPN domain, and a user manager's invite of that address is the
authorization; the identity is pinned on first use.

### Card accounts (`"signIn": "cac"`)

`stig-accounts` `POST /users` with `"signIn": "cac", "edipi": "<10 digits>"` creates an account whose card is bound at
creation, server-side: the extension writes the realm's card attribute (realm attribute `stig.accounts.card-attribute`,
e.g. `cac_edipi`; unset or malformed = no card accounts, 403). Only on create, for a brand-new account: a username or
e-mail already in use, or a card already bound to ANY account (the cac-identity-guard uniqueness rule; two concurrent
creates with one card cannot both pass), is a 409 with one generic message. Malformed EDIPI, or an `edipi` with another
`signIn`: 400. The account gets the terms action only, no set-up mail; `setup-email` answers 409. Every other rule of the
endpoint applies unchanged (the caller's groups, e-mail domains, the admin-API profile's step-up and `create` operation,
the hourly limit, which a 409 also spends). The EDIPI never appears in full in a log line, an admin event or the answer
(`******1234`). Binding a card to an EXISTING account stays with realm administrators (cac-identity-guard).

### Both on one account (`"signIn": ["entra", "cac"]`)

The create does NOT bind the card. It only NAMES it: `<card attribute>_pending` (e.g. `cac_edipi_pending`, admin-only and
concealed), reserved while live (no other create may name a card that is bound anywhere or named by a live invite: 409).
After the person's first provider sign-in has bound the provider identity, the required action `stig-present-card`
(register and enable it; `PresentCardRequiredAction`) asks them to present their card in the same session. Set
`STIG_CARD_PORT` to a second public port of the same listener (e.g. 8444, the host mapping it to the container's HTTPS port):
the step's form then posts there. A browser asks for a client certificate only during a TLS handshake and keeps its
connection to the main port, typically made without a certificate (a provider sign-in); the card port is a new
connection, TLS session and certificate decision, while the cookies (not port-scoped) keep the same authentication
session. Unset: the form posts to its own origin, and works only if that connection already carries the card. With a card port the page is the extension's own template
(`stig-present-card.ftl`): "Sign in with CAC/PIV" posts to the card port; "Continue without the card" posts to the page's
own origin, so a client network that allows only 443 out (which cannot reach the card port) can always go on; a small
script reaches the card port first and, only if that fails with a network error (refused, reset, unreachable), says the
network blocks the card step and points at continuing without it. There is no timeout: the probe is where the browser
asks for the certificate and the card for its PIN, which takes a person as long as it takes (a 10 s timeout used to fire
during the picker and report a block on a sign-in that then succeeded). After 10 s a neutral "still waiting" note says
what is going on; a card port that silently drops packets looks exactly like an open picker, so that case gets the
note, not the warning, until the browser itself gives up on the connection. A browser that scopes cookies by port (Chrome's "Origin-Bound Cookies" experiment)
would break the card port (no session cookie there); continuing without the card still works. The card is
validated exactly as a card sign-in validates it (trust, CA, validity, key usage, policy, revocation) and its identity
extracted by the realm's own X.509 mapping; it is bound only if that identity EQUALS the named value and no account holds
it. A different card, or one bound elsewhere, is refused (audited) and the named value cleared: the account stays
provider-only. That proves one human holds both - a delegate who names their OWN card for someone else's account gets
nothing, since the account holder cannot present it. No card reader: the person may skip (asked again at each sign-in);
after 7 days the named value is ignored, never bound, free for another invite, and the operator's tooling reports it.

The provider binding itself refuses an account with any card binding, and an account that already has a session
(signed into by any means before the provider link).

**Accepted risk, card-only creates (`"signIn": "cac"`):** the card IS bound at create. A delegate who names their own
card gets an account inside their own delegation and nothing more, attributed to them by `stig_created_by`; a victim's
card gives only the victim access.

`signIn` forms: absent (password, set-up mail; `lifespan` optional), `"password"`, `"entra"`, `"cac"`, or a list of
`entra` and/or `cac` in any order, each once. An empty list, a duplicate, `password` in a list: 400. A `lifespan` with
any form but password: 400 (there is no set-up mail to time).

The present-card step binds only when `stig.accounts.card-attribute` equals the browser flow's X.509 step's
`x509-cert-auth.mapper-selection.user-attribute-name`, and every X.509 step in that flow carries the same configuration
(else nothing is bound and `STIG-CARD-PRESENT-MISCONFIGURED` is logged). Log lines of the card sign-in, the issuer-CRL
check and the step never carry a full EDIPI (last four digits). Accepted risk: the generic 409 tells a delegate whether an
EDIPI is bound or reserved; it is capped by the hourly create limit and every attempt is logged with the caller.

### A card for an existing account (an administrator's link request)

The same step binds a card to an account that already exists (it signs in with a password and OTP, or through the
provider). This happens when an administrator writes a LINK REQUEST: `stig_card_link` = the request's epoch-ms
(admin-only and concealed; declare it in the user profile with `cac-identity-guard` `{"unique": "false"}`), plus the
required action on the account. The keycloak-cac VM tool's `link-cac` does both. A request is live for 7 days from
the time it was made, whatever the account's age. While it is live, the step runs at every sign-in, by any means,
until the person presents a card or the request expires. The card attribute is the browser flow's X.509 step's
mapping attribute, which must be pinned as above. `stig.accounts.card-attribute` is not needed, so card accounts
may stay off.

- With `<card attribute>_pending` also set, only that card binds, as for an invite.
- Without it, the card the holder presents binds.

The request counts only while the user profile declares `stig_card_link` with `cac-identity-guard` (realm
administrators only); otherwise the extension ignores it (`STIG-CARD-LINK-UNGUARDED`). An IdP administrator (any
effective realm-management role, or a member of `/roles` or a group beneath it), or an account recorded as one when
the request was made (`<ms> admin`), never binds "any card". That request is refused before the page is shown and
again at bind time, then cleared and audited. Only a named card binds.

A card is never bound if another account holds it, another account's pending value names it, or the account already
holds a different card. A bind or a refusal clears the request, and each is logged with `request=link`
(`STIG-CARD-PRESENT-BOUND` / `-REFUSED`, last four digits) and recorded as an admin event.

An "any card" request binds only in a sign-in where the person entered credentials: one that reuses the SSO session
(`AuthenticationManager.SSO_AUTH`) skips the step and keeps the request (`STIG-CARD-PRESENT-NEEDS-SIGNIN`). The card
is claimed (`stig-accounts-card:<realm>:<card>`, the key `stig-accounts` uses) before it is checked and bound.

**`/admin/realms/{realm}/stig-bindings/users/{id}`** (realm administrators only, 403 otherwise; refused under an
admin-API profile) writes identity bindings server-side. It sets `cac_edipi` or `cac_edipi_pending` (ten digits),
`stig_card_link` or `entra_oid`, and removes those or `stig_created_by`, with an optional `presentCard` add/remove
and a `reason`. It can also write a `profile` (username, e-mail, names, `enabled`, `emailVerified`, and the exact
required actions) without touching any attribute. A value held by another account answers 409; nothing else may be written (400). Its admin event shows
the card masked. Keycloak's admin event for `PUT /users/{id}` holds the account's attributes, even when the request
sent none, so any such update of a card account stores the full EDIPI there.

Possession is what makes this safe without the administrator ever typing the number: only the person who can sign
in to the account AND holds the card can attach it.

**EDIPIs in events and logs.** A card sign-in's login event never carries the card's identity: until an account is
matched, its `username` detail (and the attempted username the login page may echo) is `card:******NNNN#xxxxxxxx` - the
last four digits and an 8-hex keyed hash (HMAC-SHA-256 under the realm's active HMAC key), so repeated attempts by one card
correlate without the number; once an account is matched, it is that account's username. The certificate subject the event
records (`x509_cert_subject_distinguished_name`) has its EDIPI masked the same way. The HTTP access log records the request path WITHOUT its query string (`%m %R %H`; `%U` would keep the query string), and
no raw Referer (it can carry one): the extension records it sanitised instead (V-222447), `STIG-REFERER ip=<client> METHOD
<path> referer=<scheme>://<host>[:port]<path>` (no query, fragment or user info; digits masked; the same client, method and
path as the access log line, for correlation; `STIG_REFERER_AUDIT=sanitised`, required by `verify`, which fails on ANY `STIG_REFERER_AUDIT=off` in the deployment
config; at runtime the extension logs `STIG-REFERER-AUDIT on|OFF` at start-up (WARN when off) and publishes
`referer-audit=sanitised|off` in the allowlist gate's operationalInfo, which the live `verify` (`server.referer_audit`)
reads. Not covered: a request matching no JAX-RS resource (a 404 route) or a static resource outside JAX-RS): an admin search such as `users?q=cac_edipi:<EDIPI>` would otherwise write the number to the
log. Admin-API query strings of ALLOWED requests are audited instead by the extension, `STIG-ADMIN-QUERY realm user client
METHOD path?query`: a `q=` naming a concealed attribute anywhere (as decoded by the extension or by Keycloak, quotes and
case ignored) is logged as `q=<concealed>`; a parameter named after, or naming, a concealed attribute gets `<concealed>`; a
value that does not decode cleanly gets `<concealed>`; every other run of four or more digits becomes `####`. A refused request is logged by its refusal line,
without the query. Card labels use a dedicated subkey derived from the realm's
active HMAC key (`stig-card-label-v1`): activating a new HMAC key changes every label, so correlation holds within one
key's lifetime. **Never enable DEBUG (or TRACE) for
`org.keycloak.authentication.authenticators.x509` or `org.keycloak.services.x509` in production**: Keycloak's own debug
lines print certificate subjects and identities. Keep those categories at INFO or above (e.g.
`KC_LOG_LEVEL=INFO,org.keycloak.authentication.authenticators.x509:info,org.keycloak.services.x509:info`).

### The CAC sign-in through the card port

With `STIG_CARD_PORT` set, the X.509 step itself uses the card port too: when the request carries no client certificate
- typically because the browser reuses a connection to the main port made without one (a page load, an attempt with
another method) - it does not silently fall through. It shows `stig-card-signin.ftl`: "Sign in with CAC/PIV" re-runs
this step on the card port (its refresh URL there: a new connection and TLS handshake, which asks for the card; the
same cookies, so the same sign-in), and, where the step is an ALTERNATIVE, "Use another sign-in method" posts `cancel`
to this step on the page's own origin and the flow goes on to the password / identity-provider methods. The same script
probes the card port first in the same way: "blocked" only on a network error, the "still waiting" note after 10 s. On the
card port without a certificate (the prompt declined) it says so (`STIG-CARD-SIGNIN-NO-CERT`). A browser that already
presents the card on the main port signs in as before, without the page. The page also lists the realm's identity providers
(`social.providers`, as the stock login page does) under their display names, below an "or" divider, so a person who
signs in with one (e.g. Microsoft Entra ID) goes straight there; "Use another sign-in method" remains, link-styled and
last, for the password and other methods. It is the page's only "other method" control: where it is offered, the
layout's own "Try Another Way" is hidden (it leads to the same alternatives, and the next page - the password form -
still carries it); where it is not (no other step in the step's own flow), Keycloak's stays as the way on. Both templates carry their own small style block: `[hidden]` must beat the
theme's alert `display` (PatternFly's alert class sets one, which overrides the browser's `[hidden]` rule - before this,
the "blocked" warning showed on every load of the page), and the spacing and divider do not depend on the login theme.
`keycloak-cac/tests/card-signin-browser.sh` checks the labels, the spacing at 1440 and 360 px and the blocked/waiting
behaviour in Chromium. It is offered only where the step is an
ALTERNATIVE with another enabled step in its flow.

Two limits to know:

- **`hasOtherMethod` reads only the step's own flow, one level deep.** "Use another sign-in method" is offered when the
  X.509 step is an ALTERNATIVE and any other execution in its parent flow is not DISABLED. It does not model hand-built
  flows: a sibling sub-flow that is itself enabled but whose own steps are all DISABLED still counts as "another method"
  (the button is shown and leads nowhere useful), and a REQUIRED sibling counts too, although it is not an alternative
  to the card (Keycloak ignores ALTERNATIVE executions beside a REQUIRED one). The flows `kcstig.py` builds have neither
  shape; after editing a browser flow by hand, check that the card page offers the button only when there is somewhere
  to go.
- **A CAC-only realm with a visible, enabled identity provider is not CAC-only in practice.** The provider list is
  rendered whatever `cardOther` is - as on the stock login page, every enabled identity provider not marked "Hide on
  login page" is a button, and following it signs in without a card. For a realm meant to be card-only, disable its
  identity providers, not just the flow's other steps. "Hide on login page" only removes the button: an enabled
  provider is still reachable through Keycloak's broker endpoint (`/realms/<realm>/broker/<alias>/login`) from any
  sign-in in progress, and through `kc_idp_hint` where a flow has an Identity Provider Redirector step.

### An administrator with no second factor after an identity-provider sign-in

`stig-admin-second-factor-required` refuses such an administrator with a policy page (`stig-admin-second-factor.ftl`:
"Administrators must sign in with their CAC, or enrol an authenticator app first", with a link that restarts the sign-in
where the CAC is offered). It is a challenge, not a failure: a policy refusal after a successful identity-provider
sign-in is not a wrong credential and never counts toward brute-force lockout. (In the password flow the refusal still
looks like a wrong password, so it never confirms that the password was right.)


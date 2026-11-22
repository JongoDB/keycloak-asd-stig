# Pattern: a passkey-only public realm beside a CAC realm

How to give an application's outside users (contractors and readers who hold no CAC) a passwordless, FIPS-compatible
sign-in on the same hardened Keycloak that serves its CAC users, without loosening anything in the CAC realm.

Names used throughout (all placeholders): `example` is the existing CAC realm, `app-a` the application, `app-a-public`
the new realm, and `idp.example.mil` / `app-a.example.mil` the hosts. The application's outside-user roles are
`partner-reader`, `contractor`, `partner-auditor` and `partner-lead`.

The keycloak-asd-stig pieces it relies on are kcstig's `passkey` auth mode and the `stig-accounts` extensions listed in
§10; they arrive with the repository's passkey work, so until that is merged, read §10 as the specification it implements. The lab evidence behind §4 and §7 is in [`lab-evidence/passkey-fips-spike/`](../lab-evidence/passkey-fips-spike/README.md).

## 1. The design in one page

| # | Element | Why |
|---|---|---|
| 1 | **Two realms on one Keycloak.** `example` is unchanged (CAC, and whatever else it already allows). `app-a-public` serves people who have neither a CAC nor an `example` account. Someone who holds a CAC signs in through `example`, one account per person. | A realm is Keycloak's isolation boundary: users, credentials, sessions, lockout, flows, clients and events are all separate. Public users can never reach the CAC realm's accounts or administrators. |
| 2 | **The public realm has no human administrators and no admin console on the network.** The operator administers it from the master realm. The only admin-API caller from outside is one service account, the application's delegate. | The administrator allowlist then becomes trivial there: the vetted set is exactly that one delegate. Anyone else holding a realm-management role is refused and contained. |
| 3 | **Passkeys (WebAuthn, passwordless) are the only standing credential.** ES256 and RS256; user verification and discoverable credentials required; attestation `none`; platform or roaming authenticators. No password, no TOTP. | A FIPS-approved verification path (ECDSA P-256 and RSA ≥ 2048 with SHA-256 under BC-FIPS approved mode), phishing-resistant, and it works with platform passkeys and FIPS-validated security keys alike (§4, Appendix A). |
| 4 | **E-mail only proves an address**, once at invitation and once per recovery. It is never a sign-in factor, and every recovery needs an approver. | A compromised mailbox must not become an account takeover. |
| 5 | **Self-registration is an access request in the application; the IdP account is created only on approval.** Keycloak's own registration page stays off, and the registration flow is bound to a deny flow. | When the IdP host uses TLS passthrough (so cards work), no WAF or edge rate limit sits in front of it, and an open registration page could not be rate-limited per source. The application can sit behind an edge that rate-limits and challenges. Nothing exists in the IdP until someone approves. Appendix C describes the alternative (pending accounts in Keycloak) and its cost. |
| 6 | **Contractors are invite-only, by company.** Each company is a Keycloak Organization with its own domains, in whichever realm its people sign in to. Invitations go through `stig-accounts`, which adds the account to its organization and requires an address in one of that organization's domains. | Builds on a narrow, audited endpoint rather than widening the admin API. |
| 7 | **Cross-realm authorization stays in the application.** An approver signs in to `example`; the application checks that token (issuer, the `partner-lead` role, a sign-in within 15 minutes) and calls `app-a-public` through its own delegate service account (private_key_jwt). The IdP bounds what the delegate can do; the application decides who may ask. | No brokering between realms, no token exchange, no second account for approvers. A compromised application's worst case is bounded (§6). |
| 8 | **A CAC holder can hold `partner-reader` in `example`** too. | One account per person, and CAC is the stronger credential. The application keys every user on (issuer, sub), never on e-mail, so the two populations cannot collide. |
| 9 | **The allowlist gate and the guard extend to the new realm without loosening anything in `example`** (§7). | The CAC realm's rules stay exactly as they are. |
| 10 | **Every account carries its affiliation through Keycloak Organizations**: one organization per contractor company, one for the operating organization's own staff. Tokens carry the `organization` claim (alias and id). Membership changes only through the operator's tooling or `stig-accounts` at creation (§8). | Contractor people, including CAC-holding contractor staff in `example`, are always distinguishable from staff. |

## 2. Realm layout

```
idp.example.mil (one Keycloak, strict FIPS, one database)
├── master          unreachable from the network
├── example         CAC (and its existing methods)                    <- CAC holders, staff
│   ├── /roles/*                    unchanged
│   ├── /app-a/<application roles>  unchanged
│   ├── /app-a/partner-lead | partner-auditor | partner-reader | contractor
│   └── organizations: staff + one per contractor company (CAC-holding contractor staff)
└── app-a-public    passkey only; no CAC, no identity brokering, no admin console
    ├── /app-a/partner-reader       client `app-a` (this realm's): role partner-reader
    ├── /app-a/contractor           role contractor
    └── organizations: one per contractor company (domains = the invitation allowlist)
```

| Population | Realm | Sign-in | Roles available |
|---|---|---|---|
| CAC holder | `example` | CAC | partner-lead, partner-auditor, partner-reader (and the application's own roles) |
| Contractor with a CAC | `example` | CAC | contractor, member of their company's organization |
| Contractor without a CAC | `app-a-public` | passkey | contractor, member of their company's organization |
| Anyone else (reader) | `app-a-public` | passkey | partner-reader |

The `app-a` client in `app-a-public` defines **only** `contractor` and `partner-reader`. The approver and auditor roles
do not exist there, so nothing in that realm can grant them. The application holds the same line: for each issuer it
accepts only that realm's role set (Appendix D).

## 3. The application: two issuers, two clients

| | `example` client `app-a` | `app-a-public` client `app-a` |
|---|---|---|
| Issuer | `https://idp.example.mil/realms/example` | `https://idp.example.mil/realms/app-a-public` |
| Redirect | `https://app-a.example.mil/auth/example/callback` | `https://app-a.example.mil/auth/public/callback` |
| Back-channel logout | `.../auth/example/backchannel-logout` | `.../auth/public/backchannel-logout` |
| Client auth | `client-jwt`, the application's JWKS | the same JWKS, or a key per realm |
| Claims | `resource_access.app-a.roles` + `organization` (alias and id) | the same |

Client rules are the IdP's (`keycloak-rp-integration`): exact URIs, PKCE S256, no implicit flow, no direct grant, no
full scope. A **separate callback per issuer** with RFC 9207 `iss` checking prevents an IdP mix-up between the two
realms. The application identifies a user by **(iss, sub)**: `jane.doe` in one realm and `jane.doe` in the other are
different people. The sign-in page offers two buttons, one per realm.

## 4. Sign-in and the WebAuthn policy under FIPS

**Browser flow of the public realm** (kcstig `auth_mode: "passkey"`, `webauthn.sign_in: discoverable`, the default):

```
DoD Notice and Consent banner (dod-stig theme + TERMS_AND_CONDITIONS)
  -> cookie | "Sign in with passkey" (webauthn-authenticator-passwordless, UV required)
  -> user-session-limits (3)
  -> stig-admin-allowlist-gate (REQUIRED: refuses any unvetted realm-management holder)
Direct grant: denied.  Registration: deny flow.  No x509 execution.  No identity providers.  Reset credentials: off.
```

With `sign_in: username` (opt-in, keeps autofill):

```
  -> cookie | stig-passkey-username-form (passkeys; an account without a passkey answers as an unknown username)
       -> stig-passkey-required (REQUIRED: a second refusal of an account without a passkey)
       -> CONDITIONAL [conditional-credential (webauthn-passwordless, not used) -> webauthn-authenticator-passwordless]
```

The passkey step must be **conditional**: with a plain REQUIRED step, someone who uses the "Sign in with passkey" button
or autofill is asked for a second assertion and never finishes. An account without a passkey is **refused at sign-in,
never enrolled there**: a passkey is registered only through an e-mailed set-up link (invitation) or recovery link,
which proves control of the address on record. Otherwise anyone who knows an unclaimed username could register their
own passkey on a Keycloak release that allows set-up during sign-in. `kcstig verify` checks both shapes
(`flow.no_enrolment_at_sign_in`).

**Username enumeration.** Keycloak's username form tells a known username from an unknown one. Discoverable sign-in has
no username step, so nothing can be probed; that is why it is the default. The username mode answers an account without
a passkey, and a disabled account, through Keycloak's own unknown-user path (same page, status, message and
`user_not_found` event), without counting the attempt against the account. It still distinguishes an account that holds
a passkey from an unknown one.

**The WebAuthn Passwordless Policy** (and the 2FA policy, set the same, so no weaker path exists):

| Setting | Value | Reason |
|---|---|---|
| Signature algorithms | **ES256, RS256** | FIPS-approved verifications under BC-FIPS. RS256 is needed for Windows Hello. **Ed25519 stays off** until the CMVP certificate of the BC-FIPS version in the image is confirmed to cover EdDSA (it verified in the lab). Use Keycloak's names only: an unrecognised name is silently dropped and can leave the realm unable to register anyone. |
| User verification | required | Makes the passkey multi-factor (possession plus PIN or biometric), as V-222522/524 need. The server refuses a UV=0 assertion on every path. |
| Discoverable credential | required | A passkey is a discoverable credential; conditional UI needs it. |
| Authenticator attachment | not specified | Platform passkeys, password managers, security keys, or a phone over hybrid/QR. |
| Attestation conveyance | **none** | Synced passkeys send no usable attestation, so `direct` plus an AAGUID allowlist would exclude them. A validated-authenticator-only variant is possible if an assessor requires it. |
| RP ID | the IdP host (default) | Never a parent domain, which would make the passkey usable on every subdomain. |
| Avoid same authenticator registration | on | |

The policy governs **registration only**: a credential registered under an older policy keeps signing in after the list
is narrowed. The guard therefore checks the algorithm of every stored passkey credential and contains an account that
holds any other.

**Real authenticators** (Appendix A): platform passkeys register ES256 (Windows Hello may use RS256). They are not
FIPS 140-validated authenticators and FIPS 140 does not require them to be; the requirement applies to the IdP's own
cryptography. Under NIST SP 800-63B-4 synced passkeys qualify for AAL2. A YubiKey 5 FIPS (firmware 5.7.4, FIPS 140-3)
works with ES256 and is in approved mode only once a FIDO2 PIN is set. TOTP is not offered: a phone over hybrid covers
almost everyone, and TOTP would bring back a password plus a phishable code.

**Lockout and audit.** Keycloak does not count a failed passkey assertion towards brute-force lockout, and its
`LOGIN_ERROR` event carries no user. The realm's record for V-222432/433 therefore takes the card's rationale (a
public-key signature cannot be guessed); lockout still applies to anything password-based, which this realm has none
of. The `stig-audit` listener resolves a failed assertion from the posted user handle and checks the posted credential
id against that account's passkeys, recording `this-account`, `not-this-account` or no user. Without a user handle it
records no user: finding an account by credential id alone would mean scanning every account's credentials on demand.

## 5. Accounts: request, approve, invite, recover

```
Reader:     application "request access" (edge rate limit + challenge, domain screen)
              -> request stored in the application (no IdP account)
              -> a partner-lead approves (signed in to example, recent authentication)
              -> application -> stig-accounts POST /users  group=/app-a/partner-reader
              -> mail: verify address + accept terms + register passkey (one completed set-up, 12 h)
Contractor: a partner-lead picks a company -> invite (same call, group=/app-a/contractor, organization=<org id>)
              -> refused unless the address is in one of that organization's domains
            (a contractor who holds a CAC is created by the operator in example instead)
Recover:    user asks in the application -> a partner-lead approves -> stig-accounts POST /users/{id}/recover
              -> passkeys removed, sessions ended, mail to the address ON RECORD (once, 1 h)
```

The set-up actions for the public realm are `VERIFY_EMAIL, TERMS_AND_CONDITIONS, webauthn-register-passwordless`
(without `VERIFY_EMAIL`, completing an invitation leaves `emailVerified=false`). A set-up link registers **one** passkey:
it can be opened more than once while nobody has finished, the first browser to complete it wins, and the link is then
refused, also after a later recovery.

| Threat | Control |
|---|---|
| Request flooding and bots | The application's edge: rate limits per address and network, a challenge, a cap on open requests per e-mail domain, disposable-mail domains refused. No IdP state until approval. |
| Mass creation through a compromised application | `stig-accounts` allows 20 creations per caller per hour, atomically. Every call writes an admin event; creations are marked `stig_created_by`. |
| A contractor invited into the wrong company | The organization's domains are enforced by the IdP, not only by the application. |
| Readers with CAC-realm addresses | Refused for `partner-reader` in the public realm (a realm denylist): those people belong in `example`. |
| Enumeration | The application answers requests and recoveries the same way whether or not the address exists; the 409 from `stig-accounts` stays server-side. Discoverable sign-in (§4). |
| Mailbox takeover used for recovery | Recovery needs an approver, mails only the address on record, the link lives one hour, previous sessions end, and the account is refused at sign-in until the link is used. |
| Dormant accounts | The 35-day inactivity workflow disables them (V-222411). Reactivation goes through an approver and `reactivate`, never self-service. |

## 6. Cross-realm authorization

1. The approver signs in to `example`. The application verifies `iss`, signature, audience, `partner-lead` in
   `resource_access.app-a.roles`, and `auth_time` within 15 minutes for any account-changing action
   (`prompt=login` / `max_age=900` step-up).
2. The application's backend obtains a token for its delegate in `app-a-public` (client credentials, private_key_jwt,
   a key that never leaves the application's secret store) and calls only: `stig-accounts` `POST /users`,
   `/users/{id}/setup-email`, `/users/{id}/disable`, `/recover`, `/reactivate`; `PUT`/`DELETE /users/{id}/groups/{gid}`
   within `/app-a/*`; and reads of the tree's groups and members. Its FGAP scopes are `view`, `view-members`,
   `manage-membership` and `manage-membership-of-members` on the `/app-a` tree. It has no `manage-members`, so it
   cannot edit, reset, link or enable anything.
3. Each call may carry `onBehalfOf: <example sub> <username>`, recorded in the admin event and `stig_created_by` as
   asserted by the caller. The application keeps its own audit log of every decision.

**A compromised application could** create or disable reader and contractor accounts (20 an hour), move them between
`/app-a` groups, and send set-up or recovery mail to addresses on record. **It could not** touch anything in `example`,
sign in as anyone, read or plant a credential, create an administrator, or reach an account outside `/app-a`.

| Rejected option | Why |
|---|---|
| Broker `example` into the public realm so approvers hold accounts there | Brings CAC into the public realm, a second account per approver, and human administrators in the public realm. |
| Token exchange from an `example` token | Disabled by design (the IdP's token-exchange gate); cross-realm exchange is not a supported Keycloak feature. |
| Approvers hold `query-users` in `example` and an endpoint reads across realms | An admin token is scoped to one realm; this needs a custom cross-realm authorizer on the most sensitive path. |

## 7. Allowlist gate and guard: same rules, two realms

- `STIG_ALLOWLIST_ENFORCED_REALMS=example,app-a-public`. A missing published allowlist fails closed in both.
- The delegate counts as an administrator under the gate (`stig-accounts` requires `query-users`). It is vetted by a
  dedicated command that writes an allowlist entry of kind `delegate` granting exactly `query-users` and
  `query-groups`; `grant` keeps refusing every service account. The guard refuses a `delegate` entry in `example`.
- The guard runs per realm. In the public realm the expected realm-management holders are exactly {the delegate, with
  exactly its entry}; anyone else is unvetted and contained. It also checks there: no identity provider, no x509
  execution, registration and reset off, the WebAuthn algorithms ⊆ {ES256, RS256} with UV required, no password or OTP
  credential on any user, the stored-credential algorithms (§4), the client's roles exactly {contractor,
  partner-reader}, and no client but the application's and its delegate with a service account or the standard flow.
- The path allowlist gains the realm's sign-in paths and the delegate's admin paths only, never `/admin/app-a-public/`.

## 8. Affiliation: Keycloak Organizations

Assessed on Keycloak 26.8 in strict FIPS (lab evidence: `organizations*.json`):

| Question | Answer |
|---|---|
| Works in strict FIPS? | Yes: `organizationsEnabled` turns on and organizations with domains are created. |
| Token claim | The built-in `organization` client scope puts `"organization": ["acme"]` in the token; with *add organization id* on, `{"acme": {"id": "…"}}`. The application keys on the id. Roles are unaffected. |
| Allowlist gate and guard | No interaction: organizations carry no roles, and their internal groups do not appear in `/groups`. `manage-organizations`, `view-organizations` and `query-organizations` are realm-management roles, so a holder is an administrator to the gate and guard. |
| Sign-in flows | Enabling organizations adds an identity-first step to the built-in `browser` flow only; the STIG flows are untouched. Never link an identity provider to an organization or set a domain to redirect. |
| Can the delegate reach users through membership? | No: 403 on every organization endpoint, and on a user in the same organization but outside its tree. |
| Who can change membership? | `manage-organizations` **and** `manage-users`: in practice a realm administrator, i.e. the operator's tooling. In the public realm `stig-accounts` adds the account at creation, so the delegate never holds an organization role. |

**A risk and its controls.** A holder of `manage-organizations` alone can create accounts: the organization invitation
mails a registration link that worked with realm registration off and created a password account, bypassing
`stig-accounts`, its domain checks, its rate limit and the passkey-only rule. Controls: (1) nobody but allowlisted realm
administrators holds an organization role, and the guard alerts on one; (2) the organization invitation is never used;
(3) both realms' registration flow is a deny flow - tested: the invitation's registration link then creates no account,
with or without PKCE added (the realm's PKCE client policy refuses the bare link first), while with Keycloak's own
registration flow it did; (4) the registration path is not special-cased in the path allowlist, so the deny flow is
what closes it.

A point-of-contact flag, if the application needs one, is application data keyed by organization id: it changes no IdP
authority. The fallback if Organizations were unsuitable: an administrator-only user attribute set by `stig-accounts`
at creation, which delegates (no `manage-members`) cannot write.

## 9. STIG impact for the public realm

- **Inherited:** FIPS crypto, TLS, database encryption, master realm hardening, the path filter, audit transport and
  retention, backups.
- **The same kcstig settings as `example`:** 15-minute idle and 8-hour maximum sessions, 3 concurrent sessions,
  temporary lockout, DoD banner and terms, events with 90-day retention to `stig-audit`, the 35-day inactivity
  workflow, denied direct grant, security headers.
- **Not applicable, with the rationale recorded:** the PKI rules, the password rules (no password credential; the
  policy stays set), and V-222574 (no admin console on the network).
- **Per realm:** its own checklist (`kcstig assess --realm app-a-public`) and the lockout rationale in §4.

Backups need no new mechanism (`pg_dump` covers every realm). A realm cannot be rolled back alone in place because the
database is shared: restore onto a scratch host, export the realm, and import it with overwrite in a change window.

## 10. keycloak-asd-stig pieces

| | What |
|---|---|
| kcstig `auth_mode: "passkey"` | The flows in §4, the policy table, `webauthn.sign_in` (`discoverable` default, `username` opt-in), verify checks (`flow.passkey_only`, `flow.no_enrolment_at_sign_in`, `webauthn.algorithms_fips`, `realm.no_x509`, `realm.no_idp`). |
| Extra realms in `cac-config.py` | Applied from `CAC_EXTRA_REALM_PROFILES` on every start, so a restart re-hardens both realms. |
| `stig-accounts` set-up actions per realm | The public realm's list as in §5. |
| Organization-scoped invitations | `POST /users` takes an optional `organization` id, accepted only if it is in the calling client's `stig.accounts.organizations` list (written by the operator's tooling, never the staff organization); the address must be in that organization's domains. A realm denylist `stig.accounts.email-domains-deny`. |
| `recover` and `reactivate` | Recover removes passkeys, ends sessions and mails the address on record (1 h, once per 24 h), never for an administrator. Reactivate re-enables only an account the inactivity workflow disabled; the marker is withdrawn by `disable`, any sign-in and any administrative update. |
| Who may switch them on | The set-up actions and the `recover` / `reactivate` switches are **master-realm attributes keyed by realm id** (`stig.accounts.setup-actions.<realm id>` and so on), writable only by the operator's tooling: a realm administrator cannot give its user managers the power to remove credentials or re-enable accounts, and a realm re-created under the same name inherits nothing. Unset, `recover` and `reactivate` answer 403. |
| `onBehalfOf` | Recorded in the admin event and `stig_created_by` as asserted by the caller. |
| `stig-audit` | Resolves a failed passkey assertion to its target account (§4). |

---

# Appendices

## A. WebAuthn under strict FIPS: sources

| Point | Finding | Source |
|---|---|---|
| Strict mode | BC-FIPS in approved mode: RSA keys under 2048 bits fail, HMAC keys need 112 bits, passwords 14 characters. Nothing WebAuthn-specific. | [Keycloak FIPS guide](https://www.keycloak.org/server/fips) |
| EdDSA | Supported in FIPS mode from Bouncy Castle FIPS 2.1. Check the image's FIPS jar version and its CMVP certificate before listing it. | [Keycloak 26.4.0 release](https://www.keycloak.org/2025/09/keycloak-2640-released), [keycloak#42958](https://github.com/keycloak/keycloak/issues/42958) |
| Defaults | ES256 and RS256 when none is configured; Windows Hello needs RS256 in the passwordless policy. | [webauthn.adoc][kcwa] |
| Attestation | Verified against the truststore; `none` skips verification. An AAGUID allowlist needs `direct`, because with `none` the AAGUID can be anonymised to zero. | [webauthn.adoc][kcwa] |
| Passkeys | Supported since 26.4: conditional and modal UI, the passwordless policy and the `webauthn-register-passwordless` required action. | [passkeys.adoc][kcpk] |
| YubiKey 5 FIPS | Firmware 5.7.4, FIPS 140-3. In approved mode for WebAuthn only once a PIN is set. Require 5.7.4 or later where validated keys are required. | [Yubico FIPS specifics](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-fips-specifics.html), [FIDO with FIPS](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-fips-fido.html) |
| Synced passkeys | SP 800-63B-4 allows syncable authenticators at AAL2; AAL3 needs a non-exportable key. | [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) |

webauthn4j verifies through JCA, and in a FIPS JVM Keycloak puts BCFIPS first in the provider list, so ES256 and RS256
verify through BC-FIPS. The lab evidence shows it on the image rather than assuming it.

## B. ASD STIG rules for the public realm

| Rule(s) | Status | How |
|---|---|---|
| V-222389 / V-222390 (idle) | Applies | kcstig, 15 min (no admin console; 10 min set anyway) |
| V-222387 (concurrent sessions) | Applies | `user-session-limits` 3 |
| V-222432 / V-222433 (lockout) | Applies, with rationale | Temporary lockout configured; failed passkey assertions are not counted by Keycloak, and a public-key assertion cannot be guessed (§4) |
| V-222411 (35-day inactivity) | Applies | kcstig workflow; reactivation through an approver |
| V-222409 (temporary accounts) | N/A | No temporary accounts |
| V-222522 / V-222524 / V-222530 (MFA, replay-resistant) | Met by a passkey with UV | A multi-factor cryptographic authenticator, replay-resistant by challenge |
| DoD Notice | Applies | dod-stig theme and the terms required action on sign-in and on every action-token page |
| Audit | Applies, inherited mechanism | Events and admin events on, `stig-audit`, 90 days |
| Passwords (V-2225xx) | N/A | No password credential; the guard alerts if one appears |
| PKI | N/A | No x509 execution; the guard alerts if one appears |
| V-222574 (admin hostname) | Not a finding | No console path in the allowlist |
| FIPS crypto (V-222570 / V-222571) | Inherited | Same image, strict mode |
| V-222619 (account review) | Process | Approvers review `/app-a` members; the operator reviews the delegate's admin events |

## C. The alternative: pending accounts inside Keycloak

Turn on registration in the public realm without a password, with required actions `VERIFY_EMAIL`,
`webauthn-register-passwordless` and terms, a default group `/app-a/pending` (no role), approval as a group move by the
delegate, and a workflow deleting pending members after 72 hours. Costs over §1 item 5: new code to throttle
registration per source (Keycloak has none), a domain check at registration, an edge in front of the IdP host,
unvetted accounts that can sign in and hold sessions, and enumeration through the registration page.

## D. Checks the application must enforce

- Exactly two issuers, each with its own client, callback and JWKS cache; `iss` checked on the authorization response
  (RFC 9207).
- Role sets per issuer: `example` → {partner-lead, partner-auditor, partner-reader, contractor, the application's own
  roles}; `app-a-public` → {contractor, partner-reader}. Drop and log any other.
- Identity = (iss, sub). Never link accounts across issuers by e-mail.
- Account-changing actions need an `example` token with `partner-lead` and `auth_time` ≤ 15 min. The delegate's key is
  stored server-side only.
- Affiliation from the `organization` claim (alias and id); a contractor sees only their own company.
- Enumeration-neutral answers on request and recovery; rate limits and a challenge at the edge.

## E. A kcstig profile sketch for the public realm

```json
{ "realm": {"name": "app-a-public", "display_name": "app-a Partners"},
  "auth_mode": "passkey",
  "sessions": {"user_idle_minutes": 15, "admin_idle_minutes": 10, "max_hours": 8, "max_per_user": 3},
  "lockout": {"max_failures": 3, "window_minutes": 15, "permanent": false, "max_wait_hours": 24},
  "accounts": {"inactive_days": 35, "temp_hours": 72},
  "banner": {"theme": "dod-stig", "terms_required_action": true},
  "webauthn": {"algorithms": ["ES256", "RS256"], "attestation": "none", "attachment": "",
               "user_verification": "required", "discoverable": "required", "sign_in": "discoverable"} }
```

[kcpk]: https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/authentication/passkeys.adoc
[kcwa]: https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/authentication/webauthn.adoc

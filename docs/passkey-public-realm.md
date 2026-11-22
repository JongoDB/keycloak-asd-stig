# Design: a passkey-only public realm (`app-a-public`) beside a CAC realm (`example`)

A worked design for giving an application's outside users (vendors and readers without a CAC) a passwordless,
FIPS-compatible sign-in on the same hardened Keycloak that serves its CAC users, without loosening anything in the
CAC realm. The names are placeholders: `example` is the existing CAC/staff realm, `app-a` the application, and
`app-a.example.mil` / `idp.example.mil` its hosts.

**Status:** all eight decisions in §11 approved by the IdP's operator. Later sections: §12 (spike findings), §13
(affiliation), §14 (build findings: the sign-in flow gains a no-passkey refusal; username enumeration). The
keycloak-asd-stig pieces it calls for are U1–U7 and kcstig's `passkey` mode (Appendix E).
**Context:** a shared IdP operated on a VM (`keycloak-cac/deploy/vm/`). The application's portal is gaining a
vendor-review area, and it goes live at `https://app-a.example.mil`.

## 1. Decisions in one page

| # | Decision | Why |
|---|---|---|
| D1 | **Two realms on one Keycloak.** `example` is unchanged for uniformed members (CAC) and Example Org staff (CAC, password + TOTP, or Entra). A new realm, **`app-a-public`**, serves vendors without a CAC and anyone who has neither a CAC nor an example.mil account. **A vendor employee who holds a CAC signs in through `example`**, one account per person (decision 7). | A realm is Keycloak's isolation boundary: users, credentials, sessions, lockout, flows, clients and events are all separate. Vendors can never reach the CAC realm's accounts or its administrators. |
| D2 | **`app-a-public` has no human administrators and no admin console on the network.** The operator administers it from the master realm (`idp-admin.py --realm app-a-public`). The only admin-API caller from outside is one service account, the app's delegate. | The example allowlist model then becomes trivial in the new realm: the vetted set is exactly that one delegate, and anyone else holding a realm-management role is refused and contained. |
| D3 | **Passkeys (WebAuthn, passwordless) are the only standing credential.** Accepted algorithms are **ES256 and RS256**. User verification and discoverable credentials are required. Attestation is `none`. Platform or roaming authenticators are both allowed. Accounts have no password and no TOTP. | This is a FIPS-approved verification path (ECDSA P-256 and RSA ≥ 2048 with SHA-256 under BC-FIPS approved mode), and it works with both platform passkeys and a YubiKey 5 FIPS. It is also phishing-resistant. See §4 and Appendix A. |
| D4 | **E-mail only proves an address**, once at invitation and once per recovery. It is never a sign-in factor, and every recovery needs a REVIEW_LEAD to approve it. | This is the requirement, and it stops a compromised mailbox from becoming an account takeover. |
| D5 | **Self-registration becomes an access request in the app, and the IdP account is created only when the request is approved.** Keycloak's own registration page stays **off**. | `idp.example.mil` uses TLS passthrough so cards work, which means no WAF or edge rate limit can sit in front of it. An open Keycloak registration page could not be rate-limited per source, and it creates unvetted accounts that the STIG account controls then have to clean up. The app sits behind Cloudflare and can rate-limit, challenge and screen requests. The result is the same as "pending until approved", but nothing exists in the IdP until a REVIEW_LEAD says yes. Appendix C describes the variant first asked for (a pending account in Keycloak) and what it costs. |
| D6 | **Vendors are invite-only, by company.** Each company is a **Keycloak Organization** with its own domains, in whichever realm the person signs in to; the role is `/app-a/VENDOR` (§13). Invitations in `app-a-public` go through `stig-accounts`, extended to add the account to its organization and to require an address in one of that organization's domains (U2, U7). | This builds on the narrow, audited endpoint that already exists rather than widening the admin API. |
| D7 | **Cross-realm authorization works like this:** the REVIEW_LEAD signs in to `example`. The app checks the lead's `example` token (issuer, `REVIEW_LEAD` role, a sign-in within the last 15 minutes) and then calls `app-a-public` through **its own delegate service account** (private_key_jwt). The IdP bounds what the delegate can do, and the app decides who may ask. | No brokering between the realms, no token exchange and no second account for leads. The worst case from a compromised app is bounded (§6). |
| D8 | **A CAC holder can also hold `REVIEW_READER` in `example`** through `/app-a/REVIEW_READER`. | One account per person. CAC is stronger than a passkey, and it avoids a second identity for the same human. The app keys every user on (issuer, sub), never on e-mail, so the two populations cannot collide (§3). |
| D9 | **Same hostname for now** (`idp.example.mil/realms/app-a-public`). A dedicated, edge-proxied hostname is an option for later (§11 item 5). | This is enough once D5 removes the open registration page. |
| D10 | **The allowlist gate and the guard extend to the new realm without loosening anything in `example`.** The enforced realms become `example,app-a-public`, the guard runs per realm, and the delegate is allowlisted by a dedicated command, never by `grant` (§7). | The example rules stay exactly as they are. |
| D11 | **Every account is tagged with its affiliation by Keycloak Organizations**: one organization per vendor company (in whichever realm its people sign in to) and one for Example Org (in `example`). Tokens carry the `organization` claim (alias and id). The app keeps the point-of-contact flag, keyed by organization id. Membership is changed only by the operator or by `stig-accounts` at creation (§13). | The operator's requirement: vendor people, including CAC-holding vendor staff in `example`, are always distinguishable from Example Org staff. Assessed and tested on our image (§13). |

## 2. Realm layout

```
idp.example.mil (one Keycloak 26.8.2, strict FIPS, one DB)
├── master            unreachable from the network (unchanged)
├── example          CAC | password+TOTP | Entra (admin-set entra_oid)        <- members, staff
│   ├── /roles/*                   (unchanged)
│   ├── /app-a/<11 app-a roles>       (unchanged)
│   ├── /app-a/REVIEW_LEAD | REVIEW_ASSESSOR | REVIEW_READER | VENDOR   NEW roles on the
│   │                                             existing client `app-a`, repointed to app-a.example.mil
│   └── organizations: `example` (staff) + one per vendor company (CAC-holding vendor staff)
└── app-a-public      passkey only; no CAC, no IdP brokering, no admin console  <- vendors, readers
    ├── /app-a/REVIEW_READER          client `app-a` (this realm's): role REVIEW_READER
    ├── /app-a/VENDOR                  role VENDOR
    └── organizations: one per vendor company (domains = the invitation allowlist)
```

| Population | Realm | Sign-in | Roles available |
|---|---|---|---|
| Uniformed member | `example` | CAC | REVIEW_ASSESSOR, REVIEW_LEAD, REVIEW_READER (and app-a, as today) |
| Example Org staff | `example` | CAC, password + TOTP, or Entra | as above |
| Vendor employee with a CAC | `example` | CAC | VENDOR, member of their company's organization |
| Vendor employee without a CAC | `app-a-public` | passkey | VENDOR, member of their company's organization |
| Anyone else (reader) | `app-a-public` | passkey | REVIEW_READER |

The `app-a` client in `app-a-public` **defines only** `VENDOR` and `REVIEW_READER`. REVIEW_LEAD, REVIEW_ASSESSOR and the app-a roles do not exist in that realm, so nothing there can grant them. In `example` the repointed `app-a` client gains `REVIEW_LEAD`, `REVIEW_ASSESSOR`, `REVIEW_READER` and `VENDOR` beside its 11 app-a roles. The app holds the same line: for each issuer it accepts only that realm's role set (Appendix D).

## 3. The app: two issuers, two clients

| | `example` client `app-a` | `app-a-public` client `app-a` |
|---|---|---|
| Issuer | `https://idp.example.mil/realms/example` | `https://idp.example.mil/realms/app-a-public` |
| Redirect | `https://app-a.example.mil/api/v1/auth/oidc/example/callback` | `https://app-a.example.mil/api/v1/auth/oidc/public/callback` |
| Post-logout | `https://app-a.example.mil/logged-out` | same |
| Back-channel logout | `https://app-a.example.mil/api/v1/auth/oidc/example/backchannel-logout` | `.../public/backchannel-logout` |
| Client auth | `client-jwt`, JWKS `https://app-a.example.mil/api/v1/auth/oidc/jwks` | same JWKS (or a separate key per realm, the app's choice) |
| Roles claim | `resource_access.app-a.roles` + `organization` (alias and id) | `resource_access.app-a.roles` + `organization` (alias and id) |

In `example` this is the **existing** `app-a` client (decision 4): its redirect, post-logout and web-origin URIs move from `http://localhost:3002` to `https://app-a.example.mil`, and it switches from `client-secret` to `client-jwt` (decision 6: the host is not behind Cloudflare Access, so the IdP can fetch its JWKS). Its app-a roles, groups and delegate stay. `app-a-public` gets a client of the same name. The name can change later.

The path names are proposals, and the app owns them. The rules are the IdP's client rules (`keycloak-rp-integration`): exact URIs, PKCE S256, no implicit flow, no direct grant, no full scope. A **separate callback per issuer** together with RFC 9207 `iss` checking prevents an IdP mix-up between the two realms. The app identifies a user by **(iss, sub)**, never by e-mail or username: `jane.doe` in `app-a-public` and `jane.doe` in `example` are different people.

The sign-in page has two buttons: "DoD CAC or Example Org account" goes to `example`, and "Vendor / partner (passkey)" goes to `app-a-public`. Entra brokering for staff is already in `example`, and nothing about it changes.

## 4. Sign-in and the WebAuthn policy under FIPS

**`app-a-public` browser flow** (new kcstig `auth_mode: "passkey"`, Appendix F):

```
DoD Notice and Consent banner (dod-stig theme + TERMS_AND_CONDITIONS)
  -> cookie | Username form with passkeys (conditional UI + "Sign in with passkey")
       -> webauthn-authenticator-passwordless (UV required)
  -> user-session-limits (3)
  -> stig-admin-allowlist-gate (REQUIRED: refuses any unvetted realm-management holder)
Direct grant: denied.  No x509 execution.  No identity providers.  Reset credentials: off.
```

**The WebAuthn Passwordless Policy** (and the 2FA policy, set the same way so that no weaker path exists):

| Setting | Value | Reason |
|---|---|---|
| Signature algorithms | **ES256, RS256** | Both are FIPS-approved verifications under BC-FIPS approved mode. RS256 is needed for Windows Hello. **EdDSA stays off** until it is proved on our image: Keycloak says EdDSA works in FIPS mode from BC-FIPS 2.1 ([26.4.0 release notes][kc264]), but our FIPS jars and the CMVP status of that version must be checked first. Every common passkey offers ES256 anyway. |
| User verification | required | This makes the passkey multi-factor (possession plus PIN or biometric), which V-222522/524 need. |
| Discoverable credential | required | A passkey is a discoverable credential, and conditional UI needs it ([passkeys][kcpk]). |
| Authenticator attachment | not specified (platform and cross-platform) | This lets people use iCloud Keychain, Google Password Manager, Windows Hello, 1Password, a YubiKey, or a phone over hybrid/QR. |
| Attestation conveyance | **none** | Synced platform passkeys send no usable attestation, so `direct` plus an AAGUID allowlist would exclude them ([WebAuthn policy][kcwa]: "Default attestation `None` ... can anonymize the AAGUID to zero"). Under §11 item 3, a FIPS-authenticator-only variant comes later only if the ISSO requires it. |
| RP ID | `idp.example.mil` (default) | Never `example.mil`, which would make the passkey usable on every subdomain. |
| Avoid same authenticator registration | on | |
| Passkey mediation | `conditional` | |

**What this means for real passkeys** (details and sources in Appendix A):

- **Platform passkeys** (Apple, Google, Microsoft) register ES256 (Windows Hello may use RS256), so all of them work. They are not FIPS 140-validated *authenticators*, and FIPS 140 does not require them to be. The FIPS requirement applies to the IdP's own cryptography (verification in BC-FIPS), and the IdP meets it. Under NIST SP 800-63B-4, synced passkeys qualify for AAL2, which fits the vendor and reader population.
- **YubiKey 5 FIPS** (firmware 5.7.4, FIPS 140-3) works with ES256. It is in approved mode only once a FIDO2 PIN is set, and the PIN is also what satisfies `UV required`. This is the option for anyone who needs a validated authenticator.
- **TOTP is not offered.** Its only advantage would be serving someone with no passkey-capable device, and a phone over hybrid covers nearly everyone. TOTP would also bring back a password plus a phishable code. Revisit only if support requests show a real gap. If it is added, use the kcstig `mfa` path (password of 15 or more characters + TOTP HmacSHA256), granted per user by a lead.

## 5. Accounts: invite, request, approve, recover

```
Reader:  app "request access" (Cloudflare rate limit + challenge, domain screen)
           -> request stored in the app (no IdP account)
           -> REVIEW_LEAD approves in the app (signed in to example, recent auth)
           -> app -> stig-accounts POST /users  group=/app-a/REVIEW_READER
           -> mail: verify address + accept terms + register passkey (link: one completed set-up, 12 h; see §14 item 5)
Vendor:  REVIEW_LEAD picks a company -> invite (same call, group=/app-a/VENDOR, organization=<org id>)
           -> refused unless the address's domain is one of that organization's domains
         (a vendor with a CAC is not invited here: the operator creates them in example, §13)
Recover: user asks in the app -> REVIEW_LEAD approves -> app -> stig-accounts POST /users/{id}/recover
           -> passkeys removed, sessions ended, mail to the address ON RECORD (once, 1 h)
```

**Abuse controls**

| Threat | Control |
|---|---|
| Request flooding and bots | App edge: Cloudflare rate limit per IP and per /24, a Turnstile challenge, and at most N open requests per e-mail domain. Disposable-mail domains are refused. No IdP state exists until approval. |
| Mass account creation through a compromised app | `stig-accounts` allows 20 creations per caller per hour, enforced atomically (existing). Every call writes an admin event, and creations are marked `stig_created_by`. |
| A vendor invited into the wrong company | The organization's domains are enforced by the IdP, not only by the app (Appendix E, U2 and U7). |
| Readers using `.mil` or `example.mil` addresses | Refused for `REVIEW_READER` in `app-a-public` (a realm-level denylist, U2). Those people belong in `example`. |
| Enumeration | The app answers a request or a recovery the same way whether or not the address exists ("if this address can be served, you will get mail"). The 409 from `stig-accounts` stays server-side. Keycloak's registration and reset pages are off. **Corrected in §14:** with the username step, the sign-in page *does* reveal whether a username exists; `sign_in: discoverable` removes the username step. |
| Mailbox takeover used for recovery | Recovery needs a lead to approve it, mails only the address on record, the link lives one hour, and the account's previous sessions end. |
| Dormant accounts | The 35-day inactivity workflow disables them (V-222411). Reactivation goes through a lead and U4, never through self-service. |

## 6. Cross-realm authorization

**Choice: the app uses a service-account delegate in `app-a-public` and does its own authorization of the lead.**

1. The lead signs in to `example`. The app verifies the token's `iss`, its signature, its audience, `REVIEW_LEAD` in `resource_access.app-a.roles`, and `auth_time` within 15 minutes for any account-changing action (`prompt=login`/`max_age=900` step-up).
2. The app's backend obtains a token for `app-a-public-delegate` (client credentials, private_key_jwt with a key that never leaves the app's secret store) and calls only:
   - `stig-accounts` `POST /users`, `/users/{id}/setup-email`, `/users/{id}/disable`, and the new `/recover` and `/reactivate` (U3, U4);
   - `PUT`/`DELETE /users/{id}/groups/{gid}` within `/app-a/*` (a role change);
   - `GET` on `group-by-path`, members, and a user's groups.
   The FGAP scopes are `view`, `view-members`, `manage-membership` and `manage-membership-of-members` on the `/app-a` tree, the same shape as the delegate `app-a` already has in `example`. It has no `manage-members`, so it cannot edit, reset, link or enable anything.
3. Each call carries `onBehalfOf: <example sub> <username>`. The IdP records it in the admin event and in `stig_created_by`, labelled "asserted by caller" (U5). The app keeps its own audit log of every decision.

**What a compromised app could do:** create or disable reader and vendor accounts (20 an hour), move them between `/app-a` groups, and send set-up or recovery mail to addresses on record. **What it could not do:** anything in `example`, sign in as anyone, read or plant a credential, create an administrator, or touch an account outside `/app-a`.

**Options considered and rejected**

| Option | Why not |
|---|---|
| Broker `example` into `app-a-public` so leads hold delegate accounts there | It brings CAC into the public realm, creates a second account per lead, and makes human administrators in the public realm (allowlist, factor and promotion rules all over again). |
| Token exchange from an `example` token to `app-a-public` | It is disabled by design (the IdP's token-exchange gate), and cross-realm exchange is not a supported Keycloak feature. |
| Leads hold `query-users` in `example` and the endpoint reads across realms | An admin token is scoped to one realm, so this would need a custom cross-realm authorizer: new trusted code on the most sensitive path. |
| The operator approves everything | It does not scale, and it is still available as the break-glass path. |

## 7. Allowlist gate and guard: same rules, two realms, `example` untouched

- Set `STIG_ALLOWLIST_ENFORCED_REALMS=example,app-a-public`. If the published allowlist is missing, the new realm also fails closed.
- `stig-accounts` requires the caller to hold realm-management `query-users`, so the delegate counts as an "administrator" under the gate. It is vetted by a **new, separate command**, `idp-admin.py delegate-setup --realm app-a-public`. That command writes an allowlist entry of kind `delegate` granting exactly `query-users` and `query-groups`. `grant` keeps refusing every service account, so the `example` rule "service accounts are never administrators or user managers" does not change. The guard refuses a `delegate` entry anywhere except `app-a-public`.
- The guard runs per enforced realm. In `app-a-public` the expected set of realm-management holders is exactly {the delegate, with exactly its entry}. Anyone else is UNVETTED and contained with the existing logic. The guard also checks invariants specific to that realm (Appendix E, G1).
- The path allowlist gains the realm's sign-in paths and only the delegate's admin paths. It does **not** gain `/admin/app-a-public/` (no console). The change to `example` is limited to the new client `app-a`, the `/app-a/*` groups (managed by the existing IdP user managers, see §11 item 2) and the added client file. No `example` flow, policy, filter, validator or role changes.

## 8. STIG impact for `app-a-public` (summary; the per-rule list is in Appendix B)

- **Inherited from the host and image (no new work):** FIPS 140 crypto, TLS, DB encryption and SCRAM, master realm hardening, the path filter, audit transport and retention, backups.
- **The same kcstig settings as `example`:** 15-minute idle and 8-hour maximum sessions, 3 concurrent sessions, temporary lockout (3 failures, growing to 24 h), DoD banner and terms, events with 90-day retention to `stig-audit`, the 35-day inactivity workflow, denied direct grant, security headers.
- **Not applicable in this realm, with the rationale recorded:** the PKI rules (no certificate sign-in), the password rules (no password credential exists, though the policy stays set), and V-222574 (no admin console on the network). V-222574 therefore stays Open only for `example`.
- **New work:** the passkey flow and its `kcstig verify` checks; a separate checklist per realm (`kcstig assess --realm app-a-public`); a test showing that lockout counts failed WebAuthn assertions (AC-7) or a written rationale if Keycloak does not; and the reactivation and recovery procedures.

## 9. Backup and restore

- **Backup:** no change in mechanism. `pg_dump` already covers every realm, and `/srv/idp/state` gains per-realm sections in `admins.json`. One addition: a nightly, encrypted **realm export of `app-a-public` without secrets** for diffing and audit, in the same gpg bundle.
- **Restore of the whole host:** as in the host's restore procedure, and its final check covers **both** realms (`idp-admin.py allowlist --realm ...` and `guard` per realm) before the timer starts.
- **Rolling back one realm:** not possible in place, because the database is shared. Restore the backup onto a scratch VM, export `app-a-public` there, and import it with overwrite, in a change window. This procedure is documented; it is not routine. Passkeys survive both paths because they are rows in the database.

## 10. Rollout

1. **Spike (lab, throwaway realm, deployed image, strict FIPS):** passkey registration and sign-in with ES256 and RS256, a YubiKey 5 FIPS, iCloud/Google passkeys over hybrid, and EdDSA (to confirm it is refused when not listed, and whether BC-FIPS accepts it at all). Also: lockout behaviour on failed assertions, the banner on every page, and conditional UI.
2. **Upstream `keycloak-asd-stig`:** kcstig `passkey` mode with verify checks, multi-realm apply in `cac-config.py`, and the `stig-accounts` changes U1–U5 with unit tests. Upstream PR, image re-pin.
3. **`idp-admin.py` and tests** (Appendix E). Run on the VM against a throwaway public realm first.
4. **Create `app-a-public`** in production with no users. Re-run every existing suite against `example` and confirm no regression (65/65, 81/81, 55/55, 60-pass verify). Add the new suites.
5. **App integration** on a staging host: two issuers, request and approval, vendor invite, recovery.
6. **Pilot:** one vendor company and five readers. Then open it up.

## 11. Decisions (approved 2026-11-15)

The operator approved every recommendation. These replace the open questions that were here. Items 4 and 7 were confirmed later the same day, after two different answers had been relayed. The operator also added a requirement: every vendor account carries its company and whether the person is that company's point of contact (§13).

| # | Question | Decision |
|---|---|---|
| 1 | Reader sign-up | **D5 as proposed.** An access request in the app, and the IdP account is created only on a REVIEW_LEAD's approval. Keycloak registration stays off, and Appendix C is not built. |
| 2 | Who grants roles in `example` | **The IdP administrators** (user managers and the operator) grant `REVIEW_LEAD` and `REVIEW_ASSESSOR`. A REVIEW_LEAD may grant **only `REVIEW_READER`** to a CAC holder in `example`, from the app. That needs a narrow delegate over `/app-a/REVIEW_READER` alone, specified at build time like the existing `app-a-admin` delegate. |
| 3 | Authenticator assurance | **AAL2 synced passkeys are accepted** for VENDOR and REVIEW_READER. Attestation stays `none`. Hardware or attested keys (`direct` plus an AAGUID allowlist) come only if the ISSO requires them. |
| 4 | Client identity | **Repoint the existing `app-a` client** to `app-a.example.mil`, and give it the Review roles. No new `app-a` client; the name can change later. Confirmed by the operator later the same day. |
| 5 | Hostname | **The same host, `idp.example.mil`**, for now. |
| 6 | Cloudflare Access on `app-a.example.mil` | **Not behind Access**, so `client-jwt` with the app's public JWKS and direct back-channel logout work as in §3. |
| 7 | A vendor employee who holds a CAC | **`example`, with their CAC**, one account per person, and a member of their company's organization (§13). Confirmed with item 4. |
| 8 | DoD Notice | **Shown unchanged to everyone.** The ISSO is to confirm. |

Next: rollout step 1, the lab spike (§10).

## 12. Addendum: what the lab spike changed (2026-11-15)

Rollout step 1 ran on a throwaway local container built from the IdP's own image source (`1ec4b6b`, strict FIPS);
the report is [`lab-evidence/passkey-fips-spike/`](../lab-evidence/passkey-fips-spike/README.md).
**Passkeys work in strict FIPS mode**: ES256 and RS256 register and sign in, and attestation `none`, discoverable
credentials and required user verification all behave as §4 specifies. Five findings change the build. Each one
supersedes the section named.

1. **The browser flow (supersedes the diagram in §4).** The passkey step must be **conditional**:
   username form (passkeys enabled) → CONDITIONAL [`conditional-credential` (webauthn-passwordless, *not used*) →
   `webauthn-authenticator-passwordless`]. **Amended in §14:** `stig-passkey-required` sits between the username form
   and that sub-flow. With a plain REQUIRED passkey step, someone who uses the
   "Sign in with Passkey" button or autofill is asked for a second assertion and never finishes. kcstig's `passkey`
   mode (Appendix E) builds this shape and `kcstig verify` asserts it. The new realm test keeps the spike's
   negative cases: a username alone, a device without the credential, and no user verification never sign in.
2. **Lockout and audit (supersedes the "new test" for V-222432/433 in §8 and Appendix B).** Keycloak 26.8.2 does not
   count a failed passkey assertion towards brute-force lockout. Its `LOGIN_ERROR` event carries no user id. Two
   changes follow:
   - **V-222432/433:** the realm's record takes the card's rationale, that a public-key signature cannot be
     guessed. Lockout still applies to anything password-based, which this realm does not have.
   - **The `stig-audit` listener gains a new upstream item, U6.** It resolves the failed assertion to the user and logs
     the account, so the audit record names who was targeted. *As built (§14 item 6):* the account is found from the
     posted user handle, and the posted credential id is checked against that account's passkeys.
3. **Algorithm names (adds to G1 in Appendix E).** The guard and `kcstig verify` accept only algorithm names that
   Keycloak recognises (`ES256`, `RS256`, …; Keycloak spells EdDSA as `Ed25519`). An unrecognised name is silently
   dropped and leaves the realm unable to register anyone.
4. **Stored credentials (adds to G1).** The policy's algorithm list governs registration only. A credential
   registered under an older policy keeps signing in after the list is narrowed. The guard therefore checks the
   algorithm of every stored `webauthn-passwordless` credential against {ES256, RS256}, alerts on any other, and
   contains the account with the existing logic.
5. **E-mail verification (supersedes U1's action list in Appendix E).** The invitation must include `VERIFY_EMAIL`.
   Without it, completing the invitation leaves `emailVerified=false`. U1's set-up actions for `app-a-public` are
   **`VERIFY_EMAIL, TERMS_AND_CONDITIONS, webauthn-register-passwordless`**. Keycloak 26.8.2 also does not expose the
   passkey-mediation setting, so the default (conditional) applies, which is what §4 chose.

**Ed25519 stays off.** It worked on bc-fips 2.1.3, but it is enabled only once the CMVP status of the deployed
BC-FIPS version is confirmed to cover EdDSA (§4).

**Rollout (amends §10).** The build's **first step** is a real-device test on the lab image. The operator registers and signs
in with a phone or laptop passkey (iCloud Keychain, Google Password Manager or Windows Hello), with a YubiKey 5 FIPS
if one is to hand. That test also covers what the spike could not prove: the DoD banner on the autofill path, and a
real platform authenticator's algorithm and attestation. No vendor uses the realm before that test passes.

## 13. Affiliation: Keycloak Organizations (2026-11-15)

**The requirement (the operator, 2026-11-15).** Every vendor account carries its company and whether the person is that
company's point of contact, so vendor people are always distinguishable from Example Org staff. This matters most for
CAC-holding vendor staff in `example`.

**The proposal (the application team).** Keycloak Organizations in both realms: one organization per vendor company with its
domains, one for Example Org, the `organization` claim in tokens, and the point-of-contact flag in app data keyed by
organization id.

**Verdict: suitable, with four controls.** Each point below was tested in the spike lab: the IdP's image at `1ec4b6b`,
strict FIPS, a throwaway realm. The evidence is in
[`lab-evidence/passkey-fips-spike/`](../lab-evidence/passkey-fips-spike/) (`organizations*.json`, `*.txt`).

| Question | Answer | Proof |
|---|---|---|
| Supported on 26.8.2 in strict FIPS? | **Yes.** `organizationsEnabled` turns on, and organizations with domains are created. The image logged `BCFIPS … Approved Mode` throughout. | T1 |
| The token claim? | The built-in `organization` client scope (mapper `oidc-organization-membership-mapper`) puts `"organization": ["acme"]` in the token. With *add organization id* on, it becomes `{"acme": {"id": "…"}}`, so the app keys on the id. Roles are unaffected (`resource_access.app-a.roles: ["VENDOR"]`). | T2 |
| The allowlist gate and the guard? | **No interaction.** Organizations carry no roles: a member's role mappings are unchanged. Their internal groups do not appear in `/groups` or in a user's `/groups`, so the guard's group walk, `groupCarriesAdmin` and the "no administrator in an application group" invariant see nothing new. The new realm-management roles (`manage-organizations`, `view-organizations`, `query-organizations`) are realm-management roles, so **a holder is an administrator to the gate and the guard**: refused unless allowlisted, contained otherwise. | T4, T5 |
| The user profile? | **Unchanged.** Enabling organizations adds no attribute. | T4 |
| The sign-in flows? | Enabling organizations adds an *Organization* identity-first step to the **built-in** `browser` flow only. Our realms use their own STIG flows, which are untouched. Never link an identity provider to an organization, or set a domain to redirect (G2). | T4 |
| Does membership let a delegate reach users it should not? | **No.** The delegate (`query-users`, `query-groups` + FGAP on its group tree, as designed) got 403 on every organization endpoint (list, read, members, add, remove, create, a user's organizations). It also got 403 on a user in the *same* organization but outside its tree, while 200 on its own tree member and 204 on a role move as before. It cannot write the group attribute that would bind a group to an organization (403, unchanged), nor send an organization invitation (403). | T3, `organizations-delegate-group-attr.txt` |
| Who can change membership? | Adding a member needs **`manage-organizations` and `manage-users`**. Either alone, `manage-realm` or `view-users` all got 403. In practice that is a realm administrator, so: the operator (`idp-admin.py`, master realm), or another realm administrator. | T5, `organizations-roles*.json` |
| Can organization admins be kept from administering users? | **Keycloak 26.8.2 has no per-organization administrator.** The only organization roles are realm-wide, and `manage-organizations` alone could not read, edit or reset any user (403). The risk is elsewhere (below). | T5 |
| How is a CAC vendor in `example` linked, and by whom? | **By the operator only**: `idp-admin.py org-member <user> <org>`, or `--org` on `user-create-cac` / `invite`. IdP user managers cannot, because they would need realm-wide `manage-users`, which the user-manager model deliberately withholds (user managers act only through fine-grained permissions on application groups). Staff join the `example` organization the same way. In `app-a-public`, `stig-accounts` adds the account at creation (U7), so the delegate never holds an organization role. | — |

**A risk found and its controls.** A holder of `manage-organizations` **alone** can *create accounts*. The
organization invitation (`POST /organizations/{id}/members/invite-user`) mails a registration link
(`/protocol/openid-connect/registrations`). That link worked **with realm registration off**, and it created a
password account in the organization (`organizations-invite-registration.txt`). This would bypass `stig-accounts`, its
domain checks, its rate limit and the passkey-only rule. The controls:

1. **Nobody but allowlisted realm administrators holds any organization role.** The gate already refuses an
   unallowlisted holder, and G2 alerts on one.
2. **The invitation is never used.** Membership goes through `idp-admin.py` and U7 only.
3. **Both realms' registration flow is set to a deny flow** (as the direct grant is today), so even a mistaken
   invitation cannot register anyone. The build must prove this closes the invitation path: the spike did not test
   it.
4. **The registration path stays out of the allowlist.** `STIG_PUBLIC_PATHS` keeps the realm's `/protocol/` prefix
   for sign-in, so the deny flow (3) is what closes it, not the path filter. A test asserts that
   `/protocol/openid-connect/registrations` with an invitation token returns an error.

**The point-of-contact flag** stays in the app, keyed by organization id, as app-a proposes. It changes no IdP
authority and needs no IdP write path.

**The fallback, if Organizations were rejected later:** a user attribute (`affiliation_org`, plus an organization
registry in the app) declared in the user profile as editable by administrators only, the same pattern as
`stig_created_by`. Delegates lack `manage-members`, so they could not write it, and `stig-accounts` would set it at
creation. It is not needed: Organizations met every question above once the four controls are in place.

[kc264]: https://www.keycloak.org/2025/09/keycloak-2640-released
[kcpk]: https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/authentication/passkeys.adoc
[kcwa]: https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/authentication/webauthn.adoc

---

# Appendices

## A. WebAuthn under strict FIPS: what the sources say

| Point | Finding | Source |
|---|---|---|
| What strict mode does | BC-FIPS in approved mode. RSA keys under 2048 bits fail, HMAC keys must be at least 112 bits, passwords at least 14 characters. The guide says nothing specific about WebAuthn. | [Keycloak FIPS guide](https://www.keycloak.org/server/fips) |
| EdDSA | "FIPS 140-2 mode now supports EdDSA ... with the upgrade to Bouncy Castle 2.1.x." Our image pins its own FIPS jars (`keycloak-cac/fips/fips-jars.sha256`), so check that the version is 2.1 or later and that it is on a CMVP certificate before listing EdDSA. | [Keycloak 26.4.0 release](https://www.keycloak.org/2025/09/keycloak-2640-released), [keycloak#42958](https://github.com/keycloak/keycloak/issues/42958) |
| Default algorithms | ES256 and RS256 when none is configured. Windows Hello needs RS256 in the passwordless policy. | [webauthn.adoc][kcwa] |
| Attestation | Verified against the truststore. `none` skips verification. An AAGUID allowlist needs `direct` attestation, because with `none` the AAGUID "can be anonymized to zero". | [webauthn.adoc][kcwa] |
| Passkeys | Supported since 26.4. Conditional and modal UI in the username forms. Uses the *passwordless* policy and the `webauthn-register-passwordless` required action. Mediation is configurable. | [passkeys.adoc][kcpk], [26.4.0 release][kc264] |
| PQC | No ML-DSA authenticators exist yet. webauthn4j has a draft. Nothing to do now. | [keycloak#48826](https://github.com/keycloak/keycloak/issues/48826) |
| YubiKey 5 FIPS | Firmware 5.7.4 validated under FIPS 140-3 (Level 2; physical security Level 3; Yubico reports certificate #5291). The FIDO2 PIN is 8–63 bytes under 140-3. "For the YubiKey WebAuthn application to be in a FIPS approved mode of operation, set a WebAuthn PIN." U2F is disabled. The 5.4.x (140-2) certificate went to the historical list on 22 Sep 2026, so require 5.7.4 or later if the ISSO ever requires validated keys (§11 item 3). | [Yubico FIPS specifics](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-fips-specifics.html), [FIDO with FIPS](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-fips-fido.html), [Yubico press release](https://www.yubico.com/press-releases/yubico-announces-upgraded-yubikey-5-fips-series-now-fips-140-3-validated/) |
| Synced passkeys and assurance | SP 800-63B-4 allows syncable authenticators at AAL2; AAL3 needs a non-exportable key. | [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) |

**Not documented anywhere we found:** whether webauthn4j's signature verification is routed through BC-FIPS on our image. It uses JCA, and in a FIPS JVM the JCA providers are the FIPS ones, so ES256 and RS256 should verify and anything unapproved should fail. The spike (rollout step 1) proves this on the deployed image rather than assuming it.

## B. ASD STIG rules for `app-a-public`

| Rule(s) | Status in `app-a-public` | How |
|---|---|---|
| V-222389 / V-222390 (idle) | Applies, same settings | kcstig, 15 min (no admin console, so 10 min is moot but set) |
| V-222387 (concurrent sessions) | Applies | `user-session-limits` 3 |
| V-222432 / V-222433 (lockout) | Applies, **new test** | Temporary lockout as in `example`. Prove that failed passkey assertions count. If they do not, record that a public-key assertion cannot be guessed (the same reasoning already accepted for the card) |
| V-222411 (35-day inactivity) | Applies | kcstig workflow; reactivation via lead + U4 |
| V-222409 (temporary accounts, 72 h) | N/A | No temporary accounts. Under Appendix C, pending accounts would use it |
| V-222522 / V-222524 / V-222530 (MFA, replay-resistant) | Applies, **met by a passkey with UV** | A multi-factor cryptographic authenticator; replay-resistant by challenge |
| V-222434-type banner (DoD Notice) | Applies | dod-stig theme + terms required action on sign-in and on every action-token page |
| Audit (V-2224xx, V-2226xx event content and retention) | Applies, inherited mechanism | Events and admin events on, `stig-audit` listener, 90 days; `idp-events` gains `--realm` |
| Passwords (V-2225xx) | N/A (no password credential) | Policy kept configured. The guard alerts if any password credential appears in the realm |
| PKI (V-222551 / V-222553 …) | N/A | No x509 execution. The guard alerts if one appears |
| V-222574 (admin hostname) | Not a finding for this realm | No console path in the allowlist; delegate API paths only |
| FIPS crypto (V-222570 / V-222571) | Inherited | Same image, strict mode |
| V-222619 (account review) | Process | Monthly: leads review `/app-a` members (app report), and the operator reviews the delegate's admin events |

## C. The variant as asked: a pending account inside Keycloak

Turn on registration in `app-a-public`. The registration form has no password (Password Validation disabled), and its required actions are VERIFY_EMAIL, `webauthn-register-passwordless` and TERMS. The realm's **default group** is `/app-a/PENDING` (no role). Approval is a group move from PENDING to REVIEW_READER by the delegate, which is already within its scopes. A Keycloak workflow deletes PENDING members after 72 hours (`is-member-of` condition and `delete-user` step; check both names on 26.8.2).

What this costs over D5:

1. **New upstream code.** A registration form action that throttles per source IP, because Keycloak has no per-IP limit on registration.
2. **A domain check at registration.** It refuses `.mil` and `example.mil`, plus a disposable-mail list.
3. **An edge.** Without the dedicated proxied hostname (§11 item 5), there is no WAF.
4. **Lingering unvetted accounts.** Pending accounts can sign in and hold sessions, so the app must deny roleless tokens.
5. **Enumeration.** Registration reveals whether an address is already in use unless the page is changed.

None of this is needed under D5.

## D. Checks the app must enforce

- Accept exactly two issuers, each with its own client, callback and JWKS cache. Check `iss` on the authorization response (RFC 9207).
- Role sets per issuer: `example` → {REVIEW_LEAD, REVIEW_ASSESSOR, REVIEW_READER, plus the app-a roles and VENDOR (§11 items 4 and 7)}; `app-a-public` → {VENDOR, REVIEW_READER}. Drop any other role and log it.
- Identity = (iss, sub). Never link accounts across issuers by e-mail.
- Account-changing actions need `example` + REVIEW_LEAD + `auth_time` ≤ 15 min. The delegate's key is stored server-side only.
- Role sets per issuer now include `VENDOR` from `example` too (CAC-holding vendor staff).
- Affiliation comes from the `organization` claim (alias and id): a vendor organization means vendor staff, the `example` organization means Example Org staff, and none means neither. The app shows it everywhere a person is shown. The point-of-contact flag is app data keyed by organization id.
- A vendor sees only their own company (their organization id).
- Enumeration-neutral answers on request and recovery. Rate limits and a challenge at the Cloudflare edge.

## E. Changes to `idp-admin.py`, `stig-extensions` and the tests

**`idp-admin.py`**

- A global `--realm` (default `example`). `REALM` comes from it, not only from `CAC_REALM`. Each realm has a kind: `staff` or `public`. Commands that make no sense in a public realm refuse there: `entra`, `link-entra`, `user-create-cac`, `grant idp-*`, `promote`, `set-password`.
- Per-realm state. `admins.json` becomes `{realm: entries}` with a one-time migration. The published attributes `stig.admin-allowlist.<realm>` and `...-roles.<realm>` per realm.
- New commands:
  - `public-setup --realm app-a-public`: groups, organizations on, the `organization` scope as a default scope of `app-a` (with the id), the denylist attribute.
  - `delegate-setup --realm app-a-public`: client `app-a-public-delegate` (client-jwt), FGAP permission on the `/app-a` tree, the `delegate` allowlist entry.
  - `org-add <alias> --domains a.com,b.com --realm <r>` and `org-domains <alias> ...`: a vendor organization in either realm, also added to the delegate's allowed list (U7).
  - `org-member <username> <alias> [--remove] --realm <r>`: the only way to link an existing account (for example a CAC vendor in `example`, or a staff member to `example`). `user-create-cac` and `invite` gain `--org`.
  - `invite --realm app-a-public`, which uses the passkey set-up actions.
- **G1, the guard in the public realm.** The only realm-management holder is the delegate, with exactly its entry. The guard also checks:
  - no identity provider, no x509 execution, `registrationAllowed=false` (under D5), `resetPasswordAllowed=false`;
  - WebAuthn policy algorithms ⊆ {ES256, RS256} and UV required;
  - no password or OTP credential on any user;
  - the `app-a` client roles are exactly {VENDOR, REVIEW_READER};
  - no client other than `app-a` and `app-a-public-delegate` holds a service account or `standardFlow`.

  A violation exits 2 and is mailed. Containment reuses `contain_user`.
- `roles-setup` (`example`): the client file `clients/app-a.json` is repointed and gains the four Review roles, so `/app-a/REVIEW_*` and `/app-a/VENDOR` are created. The tree's delegated permission is **split into two disjoint permissions**: the app-a role groups and `REVIEW_READER` (user managers and app-a's delegate), and `REVIEW_LEAD`, `REVIEW_ASSESSOR` and `VENDOR` (user managers only). That way a lead, through the app, can grant only `REVIEW_READER` (decision 2).
  *As built:* one write permission **per group** rather than two, which is the same split with no group shared between two permissions: `app-a-admin` writes the 11 app-a groups and `REVIEW_READER`; the bare `/app-a`, `REVIEW_LEAD`, `REVIEW_ASSESSOR` and `VENDOR` are the user managers' alone, as is any role added later. Review O3's reader-only delegate is built too: `app-a-reader-delegate`, `REVIEW_READER` only, no realm-management role (J1). The tests are `split_delegation_unit_test.py` and `fgap/split_delegation_test.py` beside `idp-admin.py`.
- **G2, organizations, both realms:** nobody but allowlisted realm administrators holds `manage-organizations` or `view-organizations`. No identity provider is linked to an organization, and no domain is verified or set to redirect. Organization ids in the delegate's allowed list exist, and the staff organization is never in it.
- `idp-events`, `backup.sh` (realm export) and `restore.sh` (checks per realm).

**`stig-extensions` (upstream PR to `keycloak-asd-stig`)**

| | Change |
|---|---|
| U1 | Set-up actions per realm (realm attribute `stig.accounts.setup-actions`). Default unchanged (password, TOTP, terms). For `app-a-public`: VERIFY_EMAIL, `webauthn-register-passwordless`, TERMS. |
| U2 | Domain policy: with an `organization` in the request, the address must be in **that organization's domains**; otherwise the client's, then the realm's list as today. Plus a realm denylist `stig.accounts.email-domains-deny`. |
| U3 | `POST /users/{id}/recover`: removes WebAuthn credentials, ends sessions, mails the set-up link to the address on record (1 h, once per 24 h). Never for an administrator. |
| U4 | `POST /users/{id}/reactivate`: re-enables only an account the **inactivity workflow** disabled (marker attribute). Never one disabled by the guard or by `disable`. *As built (keycloak-asd-stig #7):* the marker is withdrawn by `disable`, by any sign-in and by **any administrative update of the account**, so an account an administrator touched after the workflow disabled it stays disabled; the guard's containment must also clear it (step 4). |
| U7 | `POST /users` takes an optional `organization` (id). The new account is added to it, only if the id is in the caller client's `stig.accounts.organizations` list, which the operator's tooling writes. Never the staff organization. |
| U5 | An optional `onBehalfOf` field, recorded in the admin event and `stig_created_by` as asserted by the caller. |
| — | kcstig `auth_mode: "passkey"` (passwordless flow, policy as §4, verify checks `flow.passkey_only`, `webauthn.algorithms_fips`, `realm.no_x509`, `realm.no_idp`). `cac-config.py`: apply extra realms from `CAC_EXTRA_REALM_PROFILES` (a directory of profiles) on every start, so a restart re-hardens both realms. |

**Tests (new or extended)**

- `tests/public_realm_test.py` (live, throwaway realm first):
  - no x509 and no identity provider on the page;
  - passkey sign-in works (virtual authenticator, ES256 and RS256), an EdDSA-only authenticator is refused, a UV-less assertion is refused;
  - the banner is shown;
  - direct grant denied;
  - an `app-a-public` token never carries an `example` role;
  - lockout on failed assertions.
- `tests/accounts_endpoint_test.py`: an `app-a-public` section:
  - organization-domain allow and deny, an organization outside the delegate's list refused, the reader denylist (`.mil`, `example.mil`);
  - recover and reactivate rules, `onBehalfOf` recorded;
  - delegate refused outside `/app-a`, every non-delegate path 403.
- `fgap/roles_isolation_test.py`: the delegate cannot reach anything in `example`, and an `example` token is useless on the `app-a-public` admin API (and the other way round).
- `tests/guard_contain_unit_test.py`: G1 invariants. A `delegate` entry is refused in `example`. `grant` still refuses service accounts.
- **Regression:** the full existing `example` suites unchanged (§10 step 4).

## F. The kcstig profile sketch for `app-a-public` (no secrets)

```json
{ "realm": {"name": "app-a-public", "display_name": "app-a Partners"},
  "auth_mode": "passkey",
  "sessions": {"user_idle_minutes": 15, "admin_idle_minutes": 10, "max_hours": 8, "max_per_user": 3},
  "lockout": {"max_failures": 3, "window_minutes": 15, "permanent": false, "max_wait_hours": 24},
  "accounts": {"inactive_days": 35, "temp_hours": 72},
  "banner": {"theme": "dod-stig", "terms_required_action": true},
  "webauthn": {"algorithms": ["ES256", "RS256"], "attestation": "none", "attachment": "",
               "user_verification": "required", "discoverable": "required"} }
```

`auth_mode: "passkey"` and the `webauthn` block do not exist in kcstig yet. They are part of the upstream PR. The clients come from a per-realm clients directory (`/srv/idp/clients/app-a-public/`), as `example`'s do today.

## 14. Addendum: what the build changed (2026-11-15)

Found while building rollout step 2 (upstream `keycloak-asd-stig` PR #6), in the lab on the IdP's image, strict FIPS.

**1. An account without a passkey is refused at sign-in, never enrolled there (supersedes the flow in §4 and §12
item 1).** In the §12 flow, an account that has no passkey reaches the passkey step on its username alone. That covers
an unclaimed invitation, or an account mid-recovery once U3 has removed its passkeys. What happens next depends on
Keycloak's own passkey authenticator. On 26.8.2 it refuses ("credential setup required"), but a release that allowed
set-up during sign-in would let anyone who knows an unclaimed username register their own passkey. The automated
security review raised this as HIGH. The flow is now:

```
DoD Notice and Consent banner
  -> cookie | "Sign in with passkey" (webauthn-authenticator-passwordless)    <- default, sign_in: discoverable
  or, with sign_in: username:
  -> cookie | stig-passkey-username-form (passkeys; no passkey = unknown username, logged STIG-PASSKEY-NOT-ENROLLED)
       -> stig-passkey-required                      (REQUIRED: a second refusal of an account without a passkey)
       -> CONDITIONAL [conditional-credential (webauthn-passwordless, not used) -> webauthn-authenticator-passwordless]
  -> user-session-limits (3)
  -> stig-admin-allowlist-gate
```

A passkey is registered **only** through the e-mailed set-up link (invitation, U1) or recovery link (U3). Following
that link proves control of the address on record. `kcstig verify` fails (`flow.no_enrolment_at_sign_in`) unless
every username form is followed by `stig-passkey-required`. The image test drives three accounts without a passkey
(invited; verified with set-up pending; nothing pending). For each, the username alone gets no code and no set-up
page. The invited one is then set up through its e-mailed link and signs in.

**2. Username enumeration (corrects §5); the default becomes discoverable sign-in.** Keycloak's username form answers
an unknown username with "Invalid username", and a known one with the passkey step. A first version of the no-passkey
refusal (item 1) added a third, distinct answer. The security review raised this as MEDIUM. Now:

- **`webauthn.sign_in` defaults to `discoverable`.** There is no username step: the page offers only "Sign in with
  passkey", and nothing can be probed. Autofill is lost.
- **`sign_in: username` stays available as an opt-in.** Its username form (`stig-passkey-username-form`) answers an
  account without a passkey, and a **disabled** account, through Keycloak's own unknown-user path: the same page,
  status, message and `user_not_found` event. Without this, Keycloak answers a disabled account with "Account is
  disabled"; the review raised it and the fix is tested. The attempt is not counted against the account, so nobody can
  lock an unclaimed account. The username mode still tells an account that holds a passkey from an unknown one.

The image test compares the answer for an unknown username with the answer for two accounts without a passkey; they
are identical. **Decided 2026-11-15** (the coordinator's recommendation, on the operator's delegation): `app-a-public` uses **`discoverable`**
sign-in. This supersedes the username step chosen in §12 item 1. The username mode stays available as an opt-in,
hardened as described above.

**3. The server refuses an assertion without user verification.** The spike could not show this, because Chrome
refuses first. The software authenticator used in the image test sends UV=0 assertions, and the server refuses them on
both paths.

**§13 controls re-checked against this flow.**

| Control | Still holds? |
|---|---|
| 1. Only allowlisted realm administrators hold organization roles | Yes. Unaffected by the sign-in flow. G2 (guard) is still to be built (rollout step 3). |
| 2. The organization invitation is never used | Yes. Unaffected. |
| 3. The registration flow is a deny flow | Yes, and now proved: an organization invitation's registration link creates no account in a realm with the deny flow, with or without PKCE added. In a control run with Keycloak's own registration flow, the same link created one. Note that the realm's PKCE client policy refuses the bare link first, so the PKCE-added case is the one that proves the deny flow. |
| 4. The registration path stays out of the path allowlist's special cases | Yes. The deny flow closes it (control 3), not the path filter. |
| U3 recovery (Appendix E) | Strengthened. After recovery removes the passkeys, the account is refused at sign-in until the e-mailed recovery link is used. Before this change, that relied on the Keycloak release. |

**4. Who can switch on recovery, reactivation and set-up actions (tightens Appendix E, U1/U3/U4; decided 2026-11-15).**
Appendix E put U1's set-up actions in a realm attribute. The build keeps these switches, and the new ones that
enable `recover` (U3) and `reactivate` (U4), in **master-realm attributes keyed by realm**: `stig.accounts.setup-actions.<realm id>`,
`stig.accounts.recover.<realm id>` and `stig.accounts.reactivate.<realm id>`, keyed by the realm's **id**, so a realm
renamed or re-created under the same name does not inherit a switch. Only the operator (master realm, `idp-admin.py`)
can write them, the same model as the administrator allowlist. A realm administrator in `example` therefore cannot
give its user managers the power to remove credentials or re-enable accounts. With no attribute set, `recover` and
`reactivate` answer 403, and set-up actions are `example`'s existing defaults. The organization allow-list (U7)
stays a client attribute of the delegate, as Appendix E says.

**5. Set-up and recovery links (corrects §5's "link: once"; lab check 2026-11-15, 26.8.2).** A link sets up **one**
passkey. It can be opened more than once while nobody has finished, but the first browser to complete it wins. After
that the link is refused, a second browser that had opened it cannot add another passkey, and an older link stays
refused even after a later recovery puts the passkey set-up back on the account. The image test checks the first two
cases. A strict "opens once" guard would add no protection against someone who intercepts the link (whoever completes
first wins either way), and it would break a person who reopens their own mail, so none is added.

**6. Who a failed passkey attempt targeted (§12 item 2, as built in keycloak-asd-stig #8).** The account is found
from the user handle the browser posts with a discoverable passkey. The posted credential id is then checked against
that account's passkeys. The record says `this-account` (a real passkey whose assertion failed), `not-this-account`
(a credential that only claims the account) or `user=-` (no account). When there is no user handle, the record has
no user: finding an account by credential id alone would mean scanning every account's credentials, and anyone on
the network could trigger that scan.

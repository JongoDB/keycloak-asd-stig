# Passkey (WebAuthn) under strict FIPS: lab spike

The lab evidence for the [passkey public realm pattern](../../docs/passkey-public-realm.md) (§4 and §8).

Everything ran in a throwaway local container, torn down afterwards: containers, volumes and network removed.

## Result

**Passkey registration and sign-in work on the IdP's image in strict FIPS mode.** ES256 and RS256 both
register and authenticate. FIPS mode broke nothing in any case tried. Ed25519 also works, but it stays **off**
until its CMVP status is confirmed (pattern §4, Appendix A).

## Set-up

| | |
|---|---|
| Image | `keycloak-cac`, built locally from this repository. Built with `FIPS=true`, `FIPS_MODE=strict`, Keycloak 26.8.2. A local arm64 build. |
| FIPS jars | bc-fips 2.1.3, bctls-fips 2.1.25, bcutil-fips 2.1.8, bcpkix-fips 2.1.13 (`keycloak-cac/fips/fips-jars.sha256`) |
| Startup line | `FIPS1402Provider created: KC(BCFIPS version 2.0103 Approved Mode, FIPS-JVM: unknown)`. Keycloak puts BCFIPS first in the JCA provider list (`Security.insertProviderAt(bcFipsProvider, 1)` in `FIPS1402Provider`), so WebAuthn signature checks resolve to it first. `FIPS-JVM: unknown` reflects the Mac host. |
| Deployment | The repository's `compose.lab.yaml` (Keycloak + PostgreSQL 17), with a local mail sink for the invitation mail |
| Realm | A throwaway realm, `spike-public`. dod-stig login theme, Terms and Conditions on, registration and reset off, temporary lockout (3 failures). The WebAuthn Passwordless policy is as in pattern §4: UV required, discoverable credential required, attestation `none`, attachment not specified, avoid same authenticator, passkeys enabled. |
| Browser flow | cookie, or [username form (passkeys) → CONDITIONAL [`conditional-credential` (webauthn-passwordless, not used) → `webauthn-authenticator-passwordless`]]. See finding 1. |
| Invitation | Admin API `execute-actions-email` with Terms and Conditions + `webauthn-register-passwordless` (+ `VERIFY_EMAIL`, see finding 5). The link was taken from the mail sink. |
| Authenticator | The Chrome DevTools-protocol virtual authenticator (Playwright Chromium 140) standing in for a platform passkey: CTAP2.1, internal transport, resident key, user verification. Every sign-in ran in a **new** browser context holding a copy of the credential, so cookies and session storage were clean each time. |

## What was proved

The algorithms offered come from the browser's own `navigator.credentials.create` call. The stored algorithm comes
from decoding the credential's COSE key out of Keycloak.

| Registration policy | Offered (COSE) | Stored credential | Attestation | Discoverable / UV requested |
|---|---|---|---|---|
| ES256 | [-7] | ES256 (-7, EC2) | `none` | required / required |
| RS256 | [-257] | RS256 (-257, RSA) | `none` | required / required |
| **ES256 + RS256 (the design's policy)** | [-7, -257] | ES256 (the authenticator took the first) | `none` | required / required |
| Ed25519 | [-8] | EdDSA (-8, OKP) | `none` | required / required |

Sign-in, for each of the four credentials:

| Attempt | Result |
|---|---|
| Username, then passkey | **Signed in.** `LOGIN`, `credential_type=webauthn-passwordless`, `web_authn_authenticator_user_verification_checked=true` |
| "Sign in with Passkey" button, no username (discoverable) | **Signed in**, same event |
| Conditional UI (autofill) | **Signed in**, same event |
| Authenticator without user verification | Refused, no `LOGIN` (the browser refuses because UV is required) |
| A device without the credential | Refused, no `LOGIN` |
| Username only, no passkey | No `LOGIN`; it stays on the passkey step |
| Forged assertion, wrong challenge | Refused: "Passkey challenge mismatch or expired" |
| Forged assertion, right challenge, bad signature (×4) | Refused: "Passkey signature verification failed" (`Assertion signature is not valid.`) |
| Copied authenticator whose counter went backwards | Refused: `MaliciousCounterValueException` (clone detection works) |

The DoD Notice and Consent banner appeared on every new sign-in page and had to be acknowledged. On the invitation
path the notice is the Terms and Conditions page, which is required and carries the DoD text. The one exception is
the autofill path; see "Not proved".

## Five requirements for the build

1. **The browser flow needs a conditional passkey step.** The design's flow (username form, then a REQUIRED passkey
   step) asks a discoverable passkey for a second assertion, so the button and autofill paths never complete. The
   working shape is a CONDITIONAL sub-flow: `conditional-credential` with `credentials=webauthn-passwordless`,
   `included=false`, followed by `webauthn-authenticator-passwordless`. Its negative cases above all passed: a
   username alone, a device without the credential, and no user verification never sign in. kcstig's `passkey`
   mode must build exactly this, and `kcstig verify` must check it.
2. **Failed passkey assertions do not count towards lockout, and their events name no user.** Four bad-signature
   assertions for a real user left `numFailures` at 0. Each `LOGIN_ERROR` had `userId=null` and no username, only
   `web_authn_authentication_error=webauthn-error-bad-signature`. Two things follow:
   - **V-222432 (AC-7)** needs a recorded rationale, the same as the one already accepted for the card: a
     public-key signature cannot be guessed. Alternatively, upstream code could count these failures.
   - **The `stig-audit` listener should attribute these failures**, for example by resolving the credential id to
     the user, so the audit record names the account.
3. **Algorithm names must be validated.** Keycloak's policy value is `Ed25519`, not `EdDSA`. An unknown name is
   silently ignored: the browser was offered ES256 while the server refused it ("alg not listed in
   options.pubKeyCredParams"), so nobody could register (`eddsa-label-EdDSA.json`). The guard and
   `kcstig verify` should accept only names Keycloak recognises.
4. **The algorithm policy only governs registration.** An Ed25519 credential went on signing in after the policy was
   narrowed to ES256 + RS256. The guard must check the algorithm of every **stored** credential, not just the
   policy.
5. **E-mail is verified only when `VERIFY_EMAIL` is a set-up action.** With Terms and Conditions + passkey
   registration alone, `emailVerified` stayed `false`. Adding `VERIFY_EMAIL` to the invitation's actions made it
   `true`. `stig-accounts`' set-up actions for a passkey realm should be `VERIFY_EMAIL, TERMS_AND_CONDITIONS, webauthn-register-passwordless`.
   Separately, 26.8.2's admin API has no passkey-mediation setting, so the default (conditional) applies.

## Not proved

- **Real authenticators.** The tests used only the Chrome virtual authenticator, not iCloud Keychain, Google
  Password Manager, Windows Hello or a YubiKey 5 FIPS. Test with a real phone or laptop passkey, and a
  security key, before anyone relies on the realm.
- **Server-side user verification.** Chrome refuses a non-UV request when UV is required, so the server never saw a
  UV=0 assertion. That the server rejects one was not observed.
- **A server host's startup line.** The lab shows `FIPS-JVM: unknown` because of the local host.
- **The banner on the autofill path.** A virtual authenticator answers autofill without user action, so it signed in
  before the banner was acknowledged. A person has to click into the username field, which the banner overlay
  covers, but the banner is client-side script, not a server-side step. Check this with a real device.
- **Ed25519's CMVP coverage.** Ed25519 works on bc-fips 2.1.3. Whether that version's certificate covers EdDSA is
  not confirmed, so Ed25519 stays off.

## Part 2: Keycloak Organizations on the same image

The lab was brought back up from the same image to assess Keycloak Organizations for affiliation, then torn down again. The
assessment and its controls are in pattern §8. In short:

- Organizations work in strict FIPS mode, and the `organization` claim carries the alias and id.
- Organizations carry no roles and their internal groups are invisible to the group APIs, so the gate, the guard and
  the user profile are unaffected.
- The designed delegate gets 403 on every organization endpoint, and shared membership gives it no extra reach.
- Membership changes need `manage-organizations` **and** `manage-users`.
- **`manage-organizations` alone can create a password account** through an organization invitation, even with
  registration off. That is why pattern §8 adds controls.

## Evidence (in this directory)

| File | Holds |
|---|---|
| `es256.json`, `rs256.json`, `policy.json`, `ed25519.json` | One case each: the WebAuthn call options the browser saw (binary values shown as byte counts), the stored credential (algorithm, attestation format, test AAGUID), the user state after the invite, every sign-in attempt and the IdP events |
| `eddsa-label-EdDSA.json` | The mis-named policy (finding 3) |
| `lockout-badsig.txt` | Four forged assertions with valid challenges and the brute-force status after each (finding 2) |
| `organizations.json` | Part 2, T1–T5: organizations enabled, the token claim, group and profile visibility, the delegate's reach, roles probed |
| `organizations-roles.json`, `organizations-roles2.json` | Which realm-management roles read or change organizations and membership, and what `invite-user` does |
| `organizations-invite-registration.txt` | The invitation link creating a password account with registration off |
| `organizations-delegate-group-attr.txt` | The delegate refused a group's organization binding and the invitation endpoint |

Identifiers (organization, role and realm ids, and the virtual authenticator's test AAGUID) are replaced by
placeholders; the realm and organization aliases are the lab's own throwaway names. Lab-only values throughout: `localhost:18443`, `*.lab.invalid` and `*.example` addresses, a virtual authenticator. Nothing here is a
credential for any real system. The driver scripts are not committed; they disable TLS verification against the
lab's self-signed certificate.

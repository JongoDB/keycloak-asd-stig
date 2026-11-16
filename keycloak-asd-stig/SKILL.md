---
name: keycloak-asd-stig
description: Provision, harden and verify Keycloak as a DoD identity provider against the DISA Application Security and Development (ASD) STIG V6R4 - CAC/PIV (X.509 with UPN mapping, OCSP+CRL), MFA, Alt Token for admins, 15/10-minute idle timeouts, 3-strike lockout, DoD Notice and Consent banner, password rules, 35-day inactivity / 72-hour temp-account disable, audit to SIEM, FIPS - and produce STIG Viewer checklists (.ckl/.cklb) plus a control-inheritance statement for each application that uses it. Use this whenever someone wants Keycloak (or SSO/IdP/login for a DoD, federal or STIG-governed app) set up, hardened, assessed or evidenced; mentions CAC/PIV login, ASD STIG, APSC-DV-xxxxxx or V-2224xx/V-2225xx/V-2226xx IDs, eMASS/ATO evidence for authentication, or wants to reuse one hardened login across multiple solutions - even if they do not say "STIG" or "Keycloak" explicitly.
---

# Keycloak ASD STIG

Turns a stock Keycloak 26.x into an identity provider whose configuration traces line-by-line to the ASD STIG
V6R4 (286 rules, bundled), proves it with automated and behavioural tests, and emits assessor-ready evidence.
Every solution you build afterwards points at this IdP and inherits the identity controls.

Everything here was exercised end-to-end against Keycloak 26.8.2 with a CAC-like test PKI and the real DoD PKI
bundle/CRLs: 20/20 behavioural checks on every topology (single container, edge proxy, 2-node cluster, Helm
manifests), strict FIPS with zero Open findings, and a 6/6 gateway suite. Keycloak behaviours that surprised us
are in `references/keycloak-notes.md` - read it before changing generator code or upgrading.

## Files
| Path | Use |
|---|---|
| `scripts/kcstig.py` | `render` / `apply` / `verify` / `assess` / `crosswalk` / `lookup` / `inherit` / `gateway` (stdlib Python) |
| `scripts/e2e_check.py` | Black-box assessor tests (CAC, revoked/unmapped/rogue-CA certs, MFA, lockout, session limit, Alt Token, min password age, gateway) |
| `scripts/build_images.sh` | Build `keycloak-stig` + `kcstig-tools` OCI images with docker/podman/buildah; base image choice (Iron Bank/RHBK/upstream), `--fips`, `--x509-lookup`, SBOM, cosign |
| `scripts/fetch_dod_pki.sh` | DoD trust store + verified CRL cache from the official DISA bundle; prints `crl_files` and `ca_subject_dns` |
| `scripts/make_test_pki.sh` | Lab-only CAC-like PKI (UPN SAN, revoked cert, rogue CA, OCSP signer) |
| `assets/profile.example.json` | The one file a user edits per deployment |
| `references/profile.md` | **Every profile field**: type, default, STIG limit, client/user/admin keys, minimal profiles. Read this instead of the script source when writing a profile |
| `assets/deploy/image`, `assets/deploy/tools` | Containerfiles + entrypoints (env-only config, `*_FILE` secrets, PKI init/refresh, jobs) |
| `assets/deploy/runtime.env.example` | Complete runtime configuration (same for every runtime) |
| `assets/deploy/compose`, `assets/deploy/helm/keycloak-stig` | Reference deployments: Compose and Helm (Pod Security restricted) |
| `assets/deploy/proxy` | Edge-verify proxy (nginx) config for CAC behind a TLS-terminating ingress |
| `assets/theme/dod-stig` | Login theme: DoD Notice & Consent banner gate (exact STIG text) |
| `assets/extension` | `stig-extensions.jar` source + `build.sh`: `minimumPasswordAge` policy (V-222544), `stig-audit` listener (last logon V-222437, concurrent logon V-222672, account-change alerts V-222417..422) |
| `references/asd-stig-v6r4.json` | Full rule text: discussion, check, fix, CCIs, severity |
| `references/nist-800-53r5.json` | ASD CCIs -> NIST SP 800-53 Rev 5 controls (DISA CCI list 2025-01-23), titles (NIST OSCAL 5.2.0), L/M/H baselines |
| `references/control-map.json` | Every rule -> disposition, Keycloak implementation, automated checks, app action, N/A condition |
| `references/deployment.md` | Runtime-agnostic pattern, images, PKI volume, jobs, ingress modes, HA, **measured sizing**, test matrix |
| `references/gateway.md` | Hardened oauth2-proxy gateway per service: what it enforces, rules for the app behind it |
| `references/cac-pki.md` | CAC flow, DoD-only client trust, root-DN pinning, CRLs, cert-policy OIDs, Alt Token, proxy forwarding |
| `references/app-integration.md` | What each relying app must still do; one realm vs many |
| `references/operations.md` | Break-glass recovery, unlock procedure, temp/emergency accounts, CRL refresh, SIEM alerts, drift, upgrades |
| `references/keycloak-notes.md` | Verified Keycloak/oauth2-proxy quirks that silently break compliance |

## Workflow

### 0. Default: the single `keycloak-cac` image (v2)
For a new deployment, use the self-configuring image in the repository's `keycloak-cac/` directory
(github.com/JongoDB/keycloak-asd-stig; clone it if only this skill is installed). It is ONE container configured only with env
vars - DoD trust anchors baked at build (or dropped in offline), CRL `online|file|ocsp`, the realm applied by
the container itself, no sidecars/jobs - and it runs the same on Compose, Helm/Kubernetes, ECS (`keycloak-cac/deploy/`).
Per application you only add a client JSON (`CAC_CLIENTS_DIR`) and point the app at
`<CAC_PUBLIC_URL>/realms/<CAC_REALM>` as its OIDC issuer. Read `keycloak-cac/README.md` (env reference, username
sources upn|edipi|cn|subject-dn, what it refuses). The steps below still apply for profile semantics (the
container's env becomes a kcstig profile; `CAC_PROFILE_JSON` overlays any field), verification (`verify`, e2e),
integration, findings and crosswalk. Use the multi-container v1 layout (`assets/deploy`, steps 3-4) only for an
existing Keycloak or when the user asks for it.

### 1. Establish the situation (ask only for what you cannot infer)
- **Target**: new deployment from the `keycloak-cac` image (default, step 0), the v1 images (Compose, Helm, podman - `references/deployment.md`),
  or an existing Keycloak (then its image still needs the theme, the extension jar and the build-time options
  `KC_HTTPS_CLIENT_AUTH=request`, `KC_LOG_MDC_ENABLED=true`; reuse `assets/deploy/image/Containerfile` with that
  image as `BASE_IMAGE`).
- **Base image**: Iron Bank or Red Hat build of Keycloak for an ATO (supported software, V-222658); upstream for labs.
- **Ingress**: TLS passthrough to Keycloak (default) or edge-verify proxy (`-nginx` image variant).
- **Users**: `auth_mode` = `cac` (CAC only - password rules become N/A), `cac_or_mfa` (CAC, or password + OTP/WebAuthn
  for people without a card), `mfa` (no PKI; lab or non-PK-enabled public data only - V-222524 stays open).
- **Admins**: `admin.mfa` = `x509` (Alt Token, STIG-intended), `webauthn` (needs ISSO acceptance), `otp` (lab only).
- **Solutions**: the OIDC/SAML clients to register (exact redirect URIs, back-channel logout URL, privileged flag).
- **PKI**: production -> `fetch_dod_pki.sh`; lab -> `make_test_pki.sh`.
**Assessing an existing Keycloak (no changes)?** Run the same checks offline on its exports - do not eyeball JSON:
`python3 scripts/kcstig.py assess --export realm.json [--admin-export master.json] --out reports` ->
`<realm>-asd-stig-assessment-findings.md` (every Open rule with CAT, the evidence from the export and the fix),
report, .ckl/.cklb. Then add judgement on top (procedures, platform) and say what an export cannot show (live
TLS, FIPS, workflows).
Use the `lookup` command whenever a question is really "what does the STIG say about X":
`python3 scripts/kcstig.py lookup --grep "session" --brief`, `lookup V-222432`, `lookup --disposition SHARED`.

### 2. Write the profile
Read `references/profile.md` (field reference + minimal profiles), then copy `assets/profile.example.json`;
change names, clients, users (with `cac_upn` = EDIPI@mil for CAC users,
`temporary_password` for password users) and `admin.users` (with `alt_token_upn`). Leave STIG numbers at their
defaults unless the organization defines stricter values; never loosen below STIG - every command prints
`WARNING profile:` for unknown keys and STIG-weakening values, so fix those before applying.
`python3 scripts/kcstig.py render --profile p.json` writes the exact plan for review / GitOps.

### 3. Build and deploy
```
scripts/build_images.sh --engine docker|podman --registry REG --base-image <iron bank|rhbk|upstream> [--fips] \
   [--x509-lookup nginx] --push --sbom --sign cosign.key
```
Then deploy with `assets/deploy/compose` (`docker compose` / `podman compose`) or the Helm chart
`assets/deploy/helm/keycloak-stig` - same containers, env (`runtime.env.example`) and jobs. PKI comes from the
`pki-init`/`pki-refresh` containers (`PKI_SOURCE=dod`, or `dir:/seed` air-gapped). Put the `crl_files` and
`ca_subject_dns` fragments printed by `fetch_dod_pki.sh` into the profile. Size the container for the CRLs
(>= 8 GiB limit with the full DoD set) - `references/deployment.md` §8.

### 4. Apply
The deployment's apply job runs `kcstig-tools apply --wait 900 --harden-master --remove-bootstrap-admin
--automation-secret-file <secret>` after every install/upgrade (Helm hook / Compose one-shot service). By hand:
```
export KC_CACERT=ca-bundle.pem KC_ADMIN_USER=<bootstrap> KC_ADMIN_PASSWORD_FILE=<file>
export KC_CLIENT_ID=stig-automation KC_CLIENT_SECRET_FILE=<secret-manager file>
python3 scripts/kcstig.py apply --profile p.json --clients-dir clients.d --harden-master --remove-bootstrap-admin \
   --automation-secret-file <secret-manager file>
```
Login falls back from the service account to the bootstrap admin on the first run, so one command works for
install and every later run. `--harden-master` refuses to run without named admins (and their `alt_token_upn`
for x509) so nobody is locked out, then denies the password grant. Lost access? `references/operations.md` §1.

### 5. Verify (configuration) and prove (behaviour)
```
python3 scripts/kcstig.py verify --profile p.json --live-url https://sso.example.mil --deploy-dir <runtime.env + manifests + keycloak-stig-image.env> --out reports [--strict]
python3 scripts/e2e_check.py --url https://... --realm <realm> --client <client> --redirect <uri> --client-secret ... \
   --cac-cert u.crt --cac-key u.key --revoked-cert ... --unmapped-cert ... --admin-cert alt.crt ... \
   --rogue-cert ... --pw-user ... --lockout-user ... --session-limit 3
```
`--deploy-dir` takes any mix of runtime.env, Compose files, `helm template` / `kubectl get -o yaml` output; the
live TLS probe checks which client-certificate CAs the server really accepts (must be DoD only).
`verify` writes `<realm>-asd-stig-report.md`, `-results.json`, `.ckl` (STIG Viewer 2 / eMASS) and `.cklb`
(STIG Viewer 3). Status rules: KC/KC-EXT rules whose checks pass -> Not a Finding; SHARED/PLATFORM rules whose
Keycloak part passes stay **Not Reviewed** with a comment naming the remaining app/platform action; any failing
check -> Open; APP/PROCESS rules -> Not Reviewed. Never hand-edit statuses to look better - fix the cause.
`e2e_check.py` consumes accounts (lockout, password change) - use dedicated test users, never real ones.

### 6. Per-solution integration
- App teams integrating with an IdP you run use the `keycloak-rp-integration` skill (beside this one) and send a
  `client-request.json`. Check the file you received with
  `keycloak-rp-integration/scripts/validate-client-request.py --strict`, then register it with
  `python3 scripts/kcstig.py add-client client-request.json --profile p.json --clients-dir clients.d --owner <id> [--secret-out FILE]`.
  It validates with the same rules (warnings refuse too), refuses reserved ids, records the owner, and changes an
  existing client only with `--update` (plus `--transfer` for another owner's, `--adopt` for one it did not create),
  printing a diff first. Confirm change requests with the recorded contact through a second channel.
  See `references/profile.md`.
- `python3 scripts/kcstig.py inherit --profile p.json --app <solution>`: inherited / shared / app-owned rules.
- Services without a strong OIDC stack get a generated gateway (`references/gateway.md`):
  `python3 scripts/kcstig.py gateway --profile p.json --client <svc>-web --public-url https://<svc> --upstream http://127.0.0.1:<port> --allowed-role <role> --out gateway/`
  -> client.json for `clients.d/`, oauth2-proxy config, Kubernetes sidecar + Compose snippets, evidence README.
  It enforces idle timeout, cookie flags, PKCE/nonce, role admission and IdP-wide logoff for the service.

### Writing findings and responsibility documents
- Take every vuln ID, STIG ID and CAT level from tool output (`assess`/`verify` reports, `lookup`), not from
  memory - CAT levels are easy to misremember (V-222578 and V-222596 are CAT I, V-222544 is CAT II) and an
  assessor will reject a list with wrong CATs.
- Never summarize inherited rules as a range ("V-222536..547 inherited"): ranges silently include rules the IdP
  does not satisfy (V-222541 is never inherited). List IDs individually, as `inherit` does.
- When you judge a tool finding as mitigated, keep it in the report with the compensating control and the
  recommended clean-up, rather than deleting it.

### NIST SP 800-53 Rev 5 crosswalk
`python3 scripts/kcstig.py crosswalk --results reports/<realm>-asd-stig-results.json [--baseline M] --out reports`
-> `asd-stig-v6r4-to-nist-800-53r5.md` (per-control rollup: Satisfied by IdP / Partial / Open / Outside the IdP)
and `.csv` (control x CCI x rule with owner, status, implementation, remaining action, evidence) for the SSP/eMASS.
Works with `assess` results too. Controls flagged `[Rev4 only]` have no Rev 5 reference in the DISA CCI list.
Do not describe a control as implemented for the system when its rollup is Partial or Outside: the remaining
rules belong to apps, platform or procedures.

### 7. Report back
Summarize: what was applied, verify counts (pass/fail/manual), e2e results, the Open findings with the reason
and fix, and the honest gaps below. Hand over the reports and the checklist files.

## Honest gaps - say these out loud, do not paper over them
- **V-222541** (8 changed characters): impossible with hashed passwords and no old-password prompt. N/A in
  `cac` mode; otherwise POA&M/risk acceptance.
- **FIPS** (V-222555, V-222570..573, V-222583): closed by the `--fips` image (strict, verified 0 Open findings);
  a validated configuration also needs a FIPS-mode host. Strict FIPS adds ~4-5 s per CAC login with the full DoD
  CRL set - list only the issuing CAs you need.
- **Platform/process rules** (SIEM retention and alerts, backups, PPSM, DB encryption at rest, code review,
  CM, training): Keycloak cannot satisfy them; the checklist leaves them Not Reviewed with guidance.
- **Banner**: the theme gate is client-side; the Terms & Conditions required action (same text) is the
  server-side backstop on first login. Apps with their own pre-login pages must show the banner too.
- **Idle timeout** is per IdP session; each app must enforce its own local session idle (SHARED) - or sit behind
  the gateway, which enforces it.
- **Not tested in this skill's lab**: a full Kubernetes cluster (Helm chart validated on a real API server and run
  with podman kube play), Iron Bank/RHBK base images, real CAC hardware, FIPS on a FIPS-mode kernel.
- Certificate policy OIDs are left empty by default - fill them from the current DoD CP after testing with real cards.

## Adapting
- Different numbers (stricter org policy): change the profile; the generator and verifier read the same values.
- New Keycloak version: rebuild the extension (`assets/extension/build.sh <image>`), re-run apply/verify/e2e,
  re-check `references/keycloak-notes.md`.
- New STIG release: replace `references/asd-stig-v6r4.json` with the new rules (same fields), then extend
  `references/control-map.json` for new/changed V-IDs - `verify` fails fast if a rule has no mapping.

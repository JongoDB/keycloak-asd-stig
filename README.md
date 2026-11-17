# keycloak-asd-stig

Keycloak 26.8.2 configured and checked against the **DISA Application Security and Development (ASD) STIG V6R4**
(286 rules). It covers CAC/PIV login (X.509 with UPN mapping, OCSP and CRL), MFA, an Alt Token for admins,
15/10-minute idle timeouts, a 3-strike lockout, the DoD Notice and Consent banner, password rules,
disabling accounts after 35 days of inactivity (72 hours for temporary accounts), auditing and FIPS. It also
produces STIG Viewer checklists, a NIST SP 800-53 Rev 5 crosswalk and a control-inheritance statement for each
application that uses this login.

| Path | What it is |
|---|---|
| `keycloak-cac/` | **Start here (v2).** One self-configuring container image: DoD CAC/PIV login hardened to the ASD STIG and configured only through env vars. DoD anchors are baked in at build (or dropped in offline), CRLs work online or air-gapped, and it deploys to Compose, Helm/K8s or ECS. See `keycloak-cac/README.md`, and `keycloak-cac/DEPLOY.md` for each platform and registry. |
| `keycloak-asd-stig/` | The Claude Code skill: `SKILL.md`, `scripts/kcstig.py` (render, apply, verify, assess, crosswalk, inherit, gateway), the e2e checker, image build, DoD PKI fetch, references, deploy assets (Compose, Helm, Podman, proxy), the theme and extension. |
| `keycloak-asd-stig.skill` | The packaged skill. Install it by unzipping into `~/.claude/skills/`. |
| `kc-cac-setup/` | `kc-cac-setup.sh`: a self-contained, one-command local CAC test stack (Docker or Podman). The README is the runbook. `build.sh` rebuilds it from `header.sh` plus the skill. |
| `lab-evidence/` | Lab results: verify reports, screenshots, strict-FIPS runs, SBOMs, deployment notes, the 800-53 Rev 5 crosswalk (.md/.csv). |
| `docs/integrate-cac-in-your-app.md` | **Start here** for adding CAC login to another app: how to install the skill and a fill-in prompt for Claude Code. |
| `docs/keycloak-gateway-integration-prompt.md` | A prompt for putting apps behind the hardened oauth2-proxy gateway. |
| `evals/` | Skill-creator eval runs (iterations 1–4, with and without the skill) and the HTML viewers. Iteration 4: 42/42 with the skill, 90% without. |

## Quick start
```bash
docker build -f keycloak-cac/Containerfile -t keycloak-cac:26.8.2 .                 # v2 image (from the repo root)
docker compose -f keycloak-cac/deploy/compose/compose.lab.yaml up -d               # lab with mock CACs
bash kc-cac-setup/kc-cac-setup.sh --upn <your card's Principal Name>               # v1 one-command local test, real CAC
```
Use the card's UPN exactly as it appears. Many cards use 16 digits (the EDIPI plus a suffix). See `kc-cac-setup/README.md`.

## Upgrade notes
- **Delegated account creation (`stig-accounts`) allows `.mil` only unless configured.** The built-in default no
  longer includes any other domain. A blank client or realm value, or a list with one malformed entry, now allows
  nothing, where it used to fall back or skip the bad entry. For example, `.mil,example.org.` (trailing dot) or
  `.mil,my_org.mil` (underscore) disables the whole list. Before upgrading, set the realm (or calling client)
  attribute `stig.accounts.email-domains` to the list you rely on, for example `.mil,example.org`. The
  before/after table is in `keycloak-asd-stig/references/operations.md` section 8.

## Status
- All lab topologies pass the e2e suite: env-only, edge proxy, 2-node HA, Helm through Podman, strict FIPS, and the 26.7 to 26.8 upgrade.
- The gateway passes its tests.
- A live DoD CAC (DOD ID CA-80) logged in successfully.

Compliance is the assessor's call. The crosswalk marks what is satisfied by the IdP and what is partial or
outside it (app, platform or process).

Lab and test material only: the generated PKI and passwords exist only at runtime and are never committed.
Production trusts only the DoD PKI (`scripts/fetch_dod_pki.sh`).

# Add CAC/PIV login to an app (prompt for Claude Code)

Use this to add CAC login, meeting the DISA ASD STIG V6R4, to any app with Claude Code and the `keycloak-asd-stig` skill.

## 1. Make the skill available to the session

Pick one:

- **Local Claude Code, every project:**
  ```bash
  mkdir -p ~/.claude/skills && cp -R keycloak-asd-stig ~/.claude/skills/
  ```
- **Cloud sessions or a team:** commit the skill into the app repo at `.claude/skills/keycloak-asd-stig/`.
  Cloud sessions start fresh, so they don't see `~/.claude`. Run this from the app repo, with this repo
  cloned beside it:
  ```bash
  mkdir -p .claude/skills && cp -R ../keycloak-asd-stig/keycloak-asd-stig .claude/skills/ && git add .claude/skills && git commit -m "Add keycloak-asd-stig skill"
  ```
- **Without copying:** attach `JongoDB/keycloak-asd-stig` to the session. The prompt below tells Claude
  to load the skill from it.

## 2. The prompt

Paste this into the app's session and fill in the brackets:

```
Integrate CAC/PIV authentication for this app using my keycloak-asd-stig skill (DISA ASD STIG V6R4).

Skill: use the installed keycloak-asd-stig skill. If it isn't installed, copy keycloak-asd-stig/ from the
JongoDB/keycloak-asd-stig repo (add that repo to this session if needed) into .claude/skills/, then load SKILL.md.
The identity provider is the single keycloak-cac image from that repo (keycloak-cac/README.md): one container,
configured only with env vars. Do not build a separate Keycloak setup.

App:
- Name / client ID: [myapp]
- Stack: [e.g. FastAPI + React SPA / Spring Boot / Node / static app with no auth today]
- Deploy target: [docker compose / podman / k8s+helm / ECS]; public URL: [https://myapp.example.mil]
- Identity provider: [existing keycloak-cac at https://sso.example.mil, realm dod-cac | add keycloak-cac to my deployment]
- Users: [CAC-only | CAC + password+MFA fallback]; admins use Alt Token
- Roles needed: [viewer, editor, admin]

Pick the integration pattern from the skill and tell me why:
- Native OIDC (the app validates tokens itself), or
- the hardened oauth2-proxy gateway in front of the app (the default if the app has no auth or can't
  meet the STIG session rules itself).

Then:
1. Write this app's client registration as one JSON file (keycloak-cac README "Registering an application")
   and add it to the identity provider's CAC_CLIENTS_DIR (Compose clients/ dir, Helm `clients:`, or
   CAC_CLIENTS_JSON). Generate the gateway config if you chose the gateway (kcstig.py gateway).
2. Wire up the app against the issuer <CAC_PUBLIC_URL>/realms/<CAC_REALM>: login and logout (including the
   backchannel logout endpoint), role checks, previous logon display, the 15-minute idle timeout, the DoD banner.
3. If the app does not have an identity provider yet, add keycloak-cac to its deployment from
   keycloak-cac/deploy/ (lab mode for development: compose.lab.yaml with mock CACs).
4. Run the e2e checks against a lab stack (CAC_LAB_MODE=true mock cards) and kcstig.py verify; fix failures.
5. Produce the control-inheritance statement (kcstig.py inherit) and list what stays the app's job.

Rules: take vuln IDs and CATs only from the tool output (never guess or use ranges). No secrets in git:
use *_FILE secrets. Production trusts only the DoD PKI.
```

## Tips

- **Keycloak already runs for another app:** say "reuse the existing Keycloak at [URL], realm [name]".
  Claude then adds a client instead of standing up a new stack.
- **Gateway route:** [`keycloak-gateway-integration-prompt.md`](keycloak-gateway-integration-prompt.md) has
  a more detailed prompt. Use it instead of, or after, the one above.
- **Testing with a real card:** map the card's UPN exactly as it appears. Many cards use 16 digits (the
  EDIPI plus a suffix). See [`../kc-cac-setup/README.md`](../kc-cac-setup/README.md).
- **ATO evidence:** ask "generate the STIG checklist (.cklb) and the 800-53 crosswalk for [app]".

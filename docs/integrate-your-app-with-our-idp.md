# Connect your app to a hardened Keycloak someone else runs

Use this when your organization already operates the STIG-hardened Keycloak and you only need your application to
log people in through it. Your coding agent builds the app side and writes a `client-request.json`. You send that to
the IdP operator, who registers the client.

If you also have to stand up the IdP itself, use [`integrate-cac-in-your-app.md`](integrate-cac-in-your-app.md) and
the `keycloak-asd-stig` skill instead.

## 1. Give your agent the skill

Pick one:

- **Every project on this machine:**
  ```bash
  git clone https://github.com/JongoDB/keycloak-asd-stig.git
  mkdir -p ~/.claude/skills && cp -R keycloak-asd-stig/keycloak-rp-integration ~/.claude/skills/
  ```
  or unzip `keycloak-rp-integration.skill` into `~/.claude/skills/`.
- **This app's repo** (cloud sessions and teammates see it too):
  ```bash
  mkdir -p .claude/skills && cp -R ../keycloak-asd-stig/keycloak-rp-integration .claude/skills/
  git add .claude/skills && git commit -m "Add keycloak-rp-integration skill"
  ```
- **Without copying:** attach `JongoDB/keycloak-asd-stig` to the session. The prompt below tells the agent where the
  skill is.

The skill is self-contained (validator, schema, references, examples). Its operator-compatibility tests also use
`keycloak-asd-stig/` when it sits next to the skill in this repository.

## 2. Ask

The skill triggers on requests like these:

> Add SSO to this app through our Keycloak.

> Add CAC login via the organization's IdP. What do I need to send the identity team?

For a more complete start, paste this and fill in the brackets:

```
Integrate this app with our STIG-hardened Keycloak as an OIDC relying party, using the keycloak-rp-integration skill
(from JongoDB/keycloak-asd-stig if it is not installed).
- Environments and public URLs: [dev https://myapp-dev.example.mil, prod https://myapp.example.mil]
- Issuer: [the operator gave us https://idp.example.mil/realms/<realm> | not yet - use configuration]
- Roles: [viewer = read; editor = change records; approver = sign off]
- Client auth: client-jwt unless you find a reason not to
- Contact for the operator: [name, email]
Implement it, add the tests, write deploy/idp/client-request.<env>.json, validate them with --strict, and tell me
exactly what to send the operator and how I will receive anything secret.
```

## 3. What you get back from the agent

- App changes: login, callback, logout, back-channel logout, JWKS endpoint, role checks, session limits, tests.
- `client-request.<env>.json` files that pass `validate-client-request.py --strict`.
- A checklist for the operator: what to send, what to expect back, and how to receive a client secret **out of
  band**, never by chat or email.
- The ASD STIG split: which rules the app inherits from the IdP, which it shares (and how it now meets them), and
  which it still owns.

## 4. Send it to the operator

The operator validates the same file with the same rules and registers it. They reply with the issuer URL, the CA
bundle, the realm's timeout values, and the IdP checklist plus `kcstig.py inherit` output for your ATO package. If
you chose `client-secret`, the secret arrives separately. Configure those, then run the test plan the agent left
you.

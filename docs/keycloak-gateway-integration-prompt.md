You are integrating my services with our ASD STIG-hardened Keycloak IdP, using the hardened oauth2-proxy gateway pattern from the `keycloak-asd-stig` skill. Work through every service in this repository.

## Setup
1. Make sure the `keycloak-asd-stig` skill is available to you (installed under `~/.claude/skills/keycloak-asd-stig`, or install it from `keycloak-asd-stig.skill`). Load it, then read `references/gateway.md`, `references/app-integration.md` and `references/profile.md` before changing anything.
2. Ask me for anything you cannot find in the repo:
   - the IdP profile (`profile.json`) and where its `clients.d/` directory lives (the IdP repo or ConfigMap)
   - the public Keycloak URL (`--issuer-base`) and the CA bundle that signed its certificate
   - each service's public HTTPS URL
   - the client roles each service should require to enter
   Do not invent hostnames, roles or secrets.

## For each service
1. **Decide the pattern.** The default is the gateway. Skip it only when the service already has a mature OIDC library and also meets every row in the "What it enforces" table of `references/gateway.md`; if you skip it, list how each row is met.
2. **Generate the gateway config:**
   ```
   python3 <skill>/scripts/kcstig.py gateway --profile <idp profile.json> --clients-dir <idp clients.d> \
     --client <service>-web --public-url https://<service host> --upstream http://127.0.0.1:<app port> \
     --issuer-base <public keycloak url> --allowed-role <role> [--privileged for admin UIs] --out deploy/gateway/
   ```
   Fix any `WARNING profile:` lines it prints.
3. **Register the client** by adding the generated `client.json` to the IdP's `clients.d/` through a change to the IdP repo. Never hand-edit Keycloak in the admin console. Note that the IdP apply job must run before the gateway can log anyone in.
4. **Wire the deployment.** Use the runtime the service already uses:
   - **Kubernetes/Helm:** merge `k8s-sidecar.json` into the Pod: add the sidecar container and its volumes. Point the Service at the gateway port. Add a NetworkPolicy so only the gateway reaches the app.
   - **Compose/podman:** add `compose-gateway.yaml` and remove the app's published ports.
   In every case the app must bind to `127.0.0.1` or a private network only the gateway can reach. Otherwise the identity headers can be forged.
5. **Secrets.** These come from our secret manager or platform secrets, mounted at `/run/secrets/gateway/`. Never put them in the repo or image.
   - `client_secret`: from Keycloak, for the new client
   - `cookie_secret`: generate it with `openssl rand -base64 32 | tr -- '+/' '-_'`
   - `ca.crt`: the CA that signed Keycloak's certificate
   - `tls.crt` / `tls.key`: unless TLS terminates in front of the gateway (then use `--plain-http --behind-proxy`)
6. **Change the app code:**
   - Trust identity only from `X-Forwarded-User`, and authorize every function from `X-Forwarded-Groups` (format `role:<client>:<role>`).
   - After sign-in, display the date and time of the previous logon (V-222437), read from the `previous_login` claim in the `X-Forwarded-Id-Token` JWT payload. The gateway already validated the token: base64url-decode the middle segment.
   - Make the logoff control go to `/oauth2/sign_out?rd=/logged-out`, and show an explicit "you are logged off" page there (V-222391, V-222392).
   - Remove the app's own login form and password handling. Any remaining app cookie must be Secure, HttpOnly, SameSite and non-persistent.
   - Never log `X-Forwarded-Id-Token` or other tokens.
7. **Tests:**
   - Add a unit or integration test proving the app rejects requests that lack `X-Forwarded-User`, and that a function is denied without its role.
   - Where a staging Keycloak with test CAC certs exists, run `<skill>/scripts/e2e_check.py --gateway-url https://<service> --gateway-only ...` with a user who has the role and one who doesn't.
8. **Evidence:**
   - Run `kcstig.py inherit --profile <idp profile.json> --app <service>` and commit the output with `deploy/gateway/README.md` under `docs/stig/`.
   - In that folder, list which ASD rules the service now cites as inherited from the IdP, which it satisfies through the gateway, and which remain the app's own.

## Hard rules
- Never weaken a generated setting: idle, cookie flags, PKCE, nonce, role check, `__Host-` cookie name, read-only/non-root container.
- Never enable the password grant, implicit flow or wildcard redirect URIs.
- Pin the oauth2-proxy image (`quay.io/oauth2-proxy/oauth2-proxy:v7.15.6`) by digest, and mirror it into our registry if one is configured.
- Never commit secrets, and never print them in logs or chat.
- If a service cannot sit behind the gateway (for example machine-to-machine APIs), stop and tell me. Those need client-credentials or mTLS service accounts instead.

## When you finish, report back
Give one table row per service with these columns:
- pattern (gateway or native)
- client ID and required role
- files changed
- secrets I still need to create
- tests added and their results
- open questions

Then list anything you could not complete and why.

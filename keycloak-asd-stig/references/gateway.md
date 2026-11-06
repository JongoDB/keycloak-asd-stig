# Hardened gateway (oauth2-proxy) for services

Most services cannot meet the app-tier half of the SHARED ASD rules on their own (idle timeout, cookie flags,
logoff, PKCE/nonce, role admission). Put a generated oauth2-proxy in front of each one and those move into a
standard, tested component. Generate with:

```
python3 scripts/kcstig.py gateway --profile p.json [--clients-dir clients.d] \
  --client payroll-web --public-url https://payroll.example.mil --upstream http://127.0.0.1:8080 \
  --allowed-role payroll-user [--privileged] [--issuer-base https://sso.example.mil] [--plain-http --behind-proxy] \
  [--session-store redis --redis-url rediss://redis:6379] --out gateway/
```
Outputs: `client.json` (drop into the IdP's `clients.d/` and re-run apply - creates the client and its role),
`oauth2-proxy.cfg` + `oauth2-proxy-alpha.json` (no secrets), `k8s-sidecar.json` (ConfigMap, sidecar container,
pod volumes), `compose-gateway.yaml`, `README.md` (evidence text for the app's checklist).
Image: `quay.io/oauth2-proxy/oauth2-proxy:v7.15.6` (pin by digest in production; mirror into your registry).

## What it enforces (tested live against Keycloak 26.8.2, 6/6 + idle test)
| Control | How | STIG |
|---|---|---|
| Idle timeout | `cookie_refresh=1m`: every request after a minute refreshes against Keycloak; once the SSO session is idle past 15 min (10 for `--privileged` clients) or ended, refresh fails (`Token is not active`) and the user is sent back to the IdP. Tested with a 2-minute realm idle: re-login forced after 155 s idle | V-222389, V-222390 |
| Absolute lifetime | `cookie_expire` = profile `sessions.max_hours` | V-222520 |
| Session cookie | `__Host-stig_session`: Secure, HttpOnly, SameSite=Lax, Path=/, no Domain; per-request CSRF cookie | V-222575, V-222576, V-222603 |
| Logoff | `/oauth2/sign_out` clears the cookie and calls Keycloak end-session (`backendLogoutURL`): the IdP session ends too | V-222391, V-222578 |
| Code flow hardening | PKCE S256, nonce validated (`insecureSkipNonce: false` - the oauth2-proxy default converter emits `true`) | V-222530, V-222581 |
| Admission | `keycloakConfig.roles` = `<client>:<role>`; authenticated users without the role get 403 | V-222425 |
| Identity to the app | `X-Forwarded-User`, `X-Forwarded-Groups` (`role:<client>:<role>`), `X-Forwarded-Id-Token`; client-supplied copies are overwritten (`preserveRequestValue: false`) - tested with a forged header | V-222552 |
| Last logon | `previous_login` claim inside `X-Forwarded-Id-Token` (oauth2-proxy cannot inject arbitrary claims as headers). App decodes the payload: `json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))["previous_login"]` | V-222437 |
| Audit | request + auth logging to stdout (JSON-able) | V-222462 |
| Container | read-only root FS, UID 65532, all capabilities dropped, no privilege escalation (passes Pod Security `restricted`) | V-222430 |

## Rules for the app behind it
1. Listen on `127.0.0.1` (sidecar) or a network only the gateway can reach. If the app is reachable directly,
   the identity headers can be forged.
2. Authorize every function from `X-Forwarded-Groups`; the gateway only checks the entry role.
3. Display `previous_login` after sign-in and a logged-off page after `/oauth2/sign_out?rd=/logged-out`.
4. Remove the app's own login form/session cookie, or make it comply (Secure, HttpOnly, no persistence, same idle).
5. Never log `X-Forwarded-Id-Token`.

## Choices
- `--session-store redis` keeps tokens server-side (smaller cookies, central revocation) - use TLS (`rediss://`).
- `--plain-http --behind-proxy` when an ingress terminates TLS in front of the gateway; the cookie stays
  `Secure` because users reach it over HTTPS.
- Services that already speak OIDC well (Spring Security, ASP.NET, Go `coreos/go-oidc`, etc.) can skip the gateway,
  but must then implement every row above themselves.

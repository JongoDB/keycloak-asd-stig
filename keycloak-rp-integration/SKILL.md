---
name: keycloak-rp-integration
description: Integrate an application, as an OIDC relying party, with a STIG-hardened Keycloak identity provider that someone else operates. Implements login (authorization code + PKCE S256), private_key_jwt or client-secret client auth, ID/access token validation, roles from resource_access, idle and absolute session limits, RP-initiated and back-channel logout, and proxy handling in the app's own stack (Node/Express, Python, Go, or any other OIDC library). Then writes and validates the client-request.json the IdP operator needs. Use this whenever someone wants to add SSO, OIDC, Keycloak, CAC/PIV or "DoD login" to their app through an existing or organization-run Keycloak; asks what to send the IdP or identity team to register an app; or asks which ASD STIG rules an app inherits from the IdP. This holds even if they do not say "relying party" or "STIG". For building or hardening the Keycloak itself, use the keycloak-asd-stig skill instead.
---

# Keycloak relying-party integration

The IdP is a Keycloak hardened to the DISA ASD STIG and run by someone else: the **operator**. Your job, in the
app's repository:

1. Build the app side correctly.
2. Produce a validated `client-request.json` for the operator.
3. Tell the human what to send and what they will get back.

The operator registers the client from that file with the IdP skill's `kcstig.py add-client` (which validates it
with this skill's validator, refuses reserved ids and records your team as the owner) and returns the issuer URL, plus
a client secret if one was chosen. CAC/PIV, MFA, the DoD banner, lockout and password rules all happen at the IdP.
The app sees ordinary OIDC users.

## Files
| Path | Use |
|---|---|
| `references/integration.md` | **Read before writing code.** What the IdP enforces, the flow, client auth and JWKS, token validation, roles, sessions and timeouts, logout, banner/CAC, proxies, and snippets for Node/Python/Go |
| `references/operator-handoff.md` | What to send the operator, what comes back, receiving a secret safely |
| `references/stig-inheritance.md` | ASD STIG rules the app inherits, shares and owns (generated from the IdP skill's control map) |
| `assets/client-request.schema.json` | JSON Schema for the request |
| `assets/client-request.example.json` | Starting point for the request |
| `scripts/validate-client-request.py` | Validator, the same rules the operator side applies; `--emit-client -` shows what will be registered |
| `examples/node-express`, `examples/python-flask`, `examples/go` | Complete minimal relying parties, tested end to end against Keycloak |
| `tests/` | Validator, schema and operator-compatibility tests. `tests/e2e/run_e2e.py` is the repository's **reference** test (examples + `add-client` against a real Keycloak); it needs the full keycloak-asd-stig checkout and is not meant to be run from an app repo - copy its checks instead |

## Workflow

### 1. Look before asking
Read the repo: language and framework, any existing auth (login forms, session middleware, an OIDC library), how
it is deployed (container, Kubernetes, behind which proxy), and where secrets come from. Note every existing
login path. All of them must go away or go through the IdP, or the STIG inheritance claims fail.

### 2. Ask the human only for what you cannot find
- **The issuer URL** (`https://idp.example.mil/realms/<realm>` is a placeholder). If they don't have it, the operator
  provides it after registration. Build against configuration and use a placeholder until then. Never invent or
  reuse an issuer from elsewhere.
- **The app's public base URL** in each environment (dev, test, prod). One client request per environment.
- **Roles**: what kinds of user exist, and which functions each may use. Turn the answers into a short list of
  lowercase role names and a mapping from route or function to role.
- **Client authentication**: recommend `client-jwt` (private_key_jwt; no shared secret to deliver). Use
  `client-secret` only if the platform cannot hold a private key or serve a JWKS URL the IdP can reach.
- **Admin front end?** If so, it gets its own client with `"privileged": true` (10-minute idle).
- **Proxy**: is TLS terminated in front of the app, and does that proxy overwrite `X-Forwarded-*`?
- **Contact**: name and email for the operator to reach. Use a team address if they prefer.
- **The realm's limits**, if the organization set values stricter than the STIG defaults (15 min idle, 10 min admin
  idle, 8 h max).

### 3. Implement (see `references/integration.md`)
Use the example for the app's stack as the reference design. For other stacks, use the platform's maintained OIDC
library (Spring Security, ASP.NET Core OpenIdConnect, `next-auth`/Auth.js and so on) and apply the same rules. Every
item below is required:

- Authorization code + PKCE S256 + state + nonce. No implicit flow, no password grant, no tokens in the browser.
- `client-jwt`: generate the key at deploy time, never in the repo; serve **public** keys at `jwks_url`. With
  `client-secret`: read it from a file (or a platform-injected env var), never from the repo.
- Validate the ID token (signature via JWKS, `iss`, `aud`, `exp`, `nonce`). Read roles from the verified access token
  at `resource_access.<client_id>.roles`. Check authorization server-side on every request.
- Server-side session; idle timeout at most the realm's (15 min, 10 for admin), absolute lifetime at most the
  realm's max (8 h); cookie Secure, HttpOnly, SameSite, no Expires, `__Host-` prefix; a fresh session ID at login;
  session-lifecycle audit log.
- Log off is a **POST** with a CSRF check (same-origin `Origin`/`Referer`, or the framework's CSRF token), never a
  GET link. It goes (303) to `end_session_endpoint` with `id_token_hint` and lands on a logged-off page.
- The back-channel logout endpoint validates the logout token (signature, `iss`, `aud`, header `typ` `logout+jwt`,
  the back-channel `events` member, `iat` neither stale nor in the future, no `nonce`) and destroys sessions by
  `sid`, or every session of `sub` when there is no `sid`, in a store every replica shares.
- **No open redirects.** A "return to the page you asked for" path is stored server-side with the login state,
  accepted only as a relative path starting with a single `/` (never `//`, `/\`, a scheme or an absolute URL),
  and defaults to `/`. Never redirect to a URL taken from a query parameter or `Referer`.
- Pre-login state (PKCE verifier, nonce) is server-side, expires (about 10 minutes) and the session store is
  capped, so anonymous `/login` requests cannot exhaust memory.
- Show `previous_login` after sign-in. Remove local login forms and password handling. Never log tokens or
  secrets.
- Build URLs from `APP_BASE_URL`; trust `X-Forwarded-*` only behind your own overwriting proxy (`TRUST_PROXY=1`).
- Don't add banner pages, client-certificate handling or MFA to the app: the IdP does them.

Add tests to the app's own suite: unauthenticated request → 401 or redirect; missing role → 403; a forged
back-channel token → 400; `GET /logout` and a cross-origin `POST /logout` do nothing; the JWKS contains no private
members; the idle limit ends the session; a return path like `//evil.example` falls back to `/`. Where a test
Keycloak exists, use `tests/e2e/run_e2e.py` as the reference for how to drive it; don't run that script from the
app repo.

### 4. Write and validate the request
Copy `assets/client-request.example.json` to the app repo (for example `deploy/idp/client-request.<env>.json`) and fill
it from step 2: exact URIs built from the base URL and the routes you implemented.
```bash
python3 <skill>/scripts/validate-client-request.py deploy/idp/client-request.prod.json --strict
python3 <skill>/scripts/validate-client-request.py deploy/idp/client-request.prod.json --emit-client -   # what gets registered
```
Fix every `ERROR`. With `--strict`, warnings fail too (placeholder hosts, a URL on another origin, wildcard-DNS
services such as nip.io, single-label hosts): fix them. The operator's `add-client` treats warnings as errors by
default, so a request that passes `--strict` is what registers cleanly. `NOTE` lines (choosing `client-secret`, a
dev request) are advice and never fail. Every URL needs a DNS name; IP addresses are refused in
every form, and must be ASCII (punycode for IDNs). `localhost` is accepted only with `"dev_request": true`.
Keycloak's own client ids (`account`, `account-console`, `admin-cli`, `broker`, `realm-management`,
`security-admin-console`, any `*-realm`) are refused here and by the operator's `kcstig.py add-client`. The
operator records your team as the client's owner. A later change is a new request with the same `client_id` from
the same contact, which the operator confirms with you through a second channel and applies with `--update`. Never put a secret or private key in the file: fields named like
secrets are refused, and `notes`, `name` and `contact` are scanned for credential-looking values (PEM blocks, JWTs,
tokens, `password: ...`, long random strings). The scan catches common shapes, not every secret.

### 5. Report back to the human
- What changed in the app (files, routes, config variables, tests and their results).
- The request file path(s), and the operator checklist from `references/operator-handoff.md`: what to send, what
  to expect back, and how to receive a secret **out of band** (never chat or email).
- The configuration still needed once the operator replies (`OIDC_ISSUER`, the CA bundle, the secret file).
- The STIG split from `references/stig-inheritance.md`: inherited rules, shared rules the app now meets (say how),
  and app-owned rules that are still open. Cite rule IDs individually, as written there, never as ranges.

## Hard rules
- Never weaken: no wildcard redirect URIs, no implicit or password grant, no disabled TLS verification, no tokens
  in `localStorage`, no app session longer than the IdP's limits.
- No secrets, private keys, real issuer URLs or internal hostnames in the repository or the request's `notes`.
- Don't add a second way to sign in (local accounts, API keys for humans, "break-glass" forms). Machine clients
  need their own registration (client credentials or mTLS). Raise it with the human; it is out of this request
  format's scope.

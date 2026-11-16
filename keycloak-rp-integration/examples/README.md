# Example relying parties

Three minimal apps with the same routes and configuration. Each implements `references/integration.md` in full:
authorization code + PKCE S256 + nonce, `private_key_jwt` or a client secret from a file, ID-token and access-token
validation, roles from `resource_access.<client_id>.roles`, server-side idle and absolute limits, a hardened
session cookie, RP-initiated and back-channel logout, and a public JWKS endpoint.

| Dir | Stack |
|---|---|
| `node-express/` | Node >= 20, Express 5, `openid-client` 6, `jose` 6 |
| `python-flask/` | Python >= 3.10, Flask 3, Authlib 1.9, `joserfc` |
| `go/` | Go, `net/http`, `coreos/go-oidc/v3`, `x/oauth2`, `go-jose/v4` |

`../tests/e2e/run_e2e.py` runs all three, with both authentication methods, against a real Keycloak 26.8.2 (see
`.github/workflows/keycloak-rp-integration.yml`).

The session and back-channel stores are in memory, so these are single-replica examples. Use Redis or a database
when you run more than one replica.

## Routes

| Route | Purpose | In `client-request.json` |
|---|---|---|
| `GET /login` | Start the code flow | |
| `GET /oauth2/callback` | Code exchange and token validation | `redirect_uris` |
| `GET /me` | The signed-in user, roles and `previousLogin` (401 without a session) | |
| `GET /approve` | Example of a role-gated function (`approver`, else 403) | `roles` |
| `GET /logout` | RP-initiated logout via `end_session_endpoint` | |
| `GET /logged-out` | Explicit logged-off page | `post_logout_redirect_uris` |
| `POST /oauth2/backchannel-logout` | Back-channel logout | `backchannel_logout_url` |
| `GET /.well-known/jwks.json` | The app's public key(s) for `private_key_jwt` | `jwks_url` |

## Configuration

| Variable | Meaning |
|---|---|
| `OIDC_ISSUER` | From the operator, e.g. `https://idp.example.mil/realms/<realm>` |
| `OIDC_CLIENT_ID` | `client_id` from the request |
| `APP_BASE_URL` | Public base URL (`root_url`). Every external URL is built from it |
| `OIDC_PRIVATE_KEY_FILE` + `OIDC_KEY_ID` | `client-jwt`: PKCS#8 RSA private key (PEM) and its `kid` |
| `OIDC_CLIENT_SECRET_FILE` | `client-secret`: file holding the secret (used when no private key is set) |
| `SESSION_SECRET_FILE` | Node/Python: file with a random string that signs the session cookie |
| `SESSION_IDLE_MINUTES` / `SESSION_MAX_HOURS` | Default 15 / 8. Keep them at or below the realm's values (10 for admin apps) |
| `TRUST_PROXY` | `1` only behind your own proxy that overwrites `X-Forwarded-*` (Node/Python; Go relies on `APP_BASE_URL` only) |
| `OIDC_CA_FILE` (Go), `NODE_EXTRA_CA_CERTS` (Node), `REQUESTS_CA_BUNDLE` (Python) | The IdP's CA bundle, when it chains to a private or DoD root |
| `HOST` / `PORT` | Listen address. Default `127.0.0.1:3000`; put a TLS proxy in front |

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /run/secrets/client-key.pem
head -c 32 /dev/urandom | base64 > /run/secrets/session-secret
export OIDC_ISSUER=https://idp.example.mil/realms/<realm> OIDC_CLIENT_ID=myapp-web APP_BASE_URL=https://myapp.example.mil \
       OIDC_PRIVATE_KEY_FILE=/run/secrets/client-key.pem OIDC_KEY_ID=myapp-2026-01 SESSION_SECRET_FILE=/run/secrets/session-secret
(cd node-express && npm ci && node app.mjs)
(cd python-flask && pip install -r requirements.txt && python app.py)
(cd go && go build -o keycloak-rp . && ./keycloak-rp)
```

The session cookie is `Secure` and `__Host-` prefixed whenever `APP_BASE_URL` is https, which is always the case
outside a `localhost` dev setup.

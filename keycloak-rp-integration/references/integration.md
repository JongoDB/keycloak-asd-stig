# Integrating an app with the STIG-hardened Keycloak (OIDC relying party)

The IdP is run by someone else (the **operator**). You build the app side and send the operator a client request
(`client-request.json`). The operator registers the client and gives you back the issuer URL, and a client secret
if you chose one. This file covers what the app must do. The full, runnable versions of the snippets below are in
`../examples/` (Node/Express, Python/Flask, Go). Each was tested end to end against Keycloak 26.8.2 by
`../tests/e2e/run_e2e.py` with both client authentication methods.

Placeholders used throughout: issuer `https://idp.example.mil/realms/<realm>`, app `https://myapp.example.mil`.
The operator gives you the real issuer. Never guess it, and never copy one from another project.

## Contents
1. What the IdP enforces, and what that means for the app
2. The flow: authorization code + PKCE S256, nothing else
3. Client authentication: `private_key_jwt` (preferred) or a client secret
4. Validating tokens
5. Roles
6. Sessions and timeouts
7. Logout: RP-initiated and back-channel
8. Banner, consent, CAC: the IdP's job, not the app's
9. Behind a reverse proxy: `TRUST_PROXY` and forwarded headers
10. Snippets: Node, Python, Go
11. Checklist before you send the request

## 1. What the IdP enforces

The operator's realm applies these to every client. You cannot change them through the request, and the app
must not try to work around them:

| IdP setting (STIG default) | Value | Consequence for the app |
|---|---|---|
| Grant types | Authorization code only. PKCE `S256` is required. Implicit, password (ROPC), device and CIBA grants are off | Use the code flow with PKCE. A request without `code_challenge` fails |
| `fullScopeAllowed` | false | Tokens carry only **this client's** roles |
| SSO idle timeout | 15 min (10 min for `privileged` clients) | The IdP session ends after this long without IdP activity |
| SSO max lifespan | 8 h | The user signs in again after this, whatever they do |
| Access token lifetime | 5 min | Don't cache authorization decisions on a token past `exp` |
| Refresh tokens | single use (rotation), no `offline_access` | Store the newest one; `invalid_grant` means sign in again |
| Concurrent sessions | 3 per user; a 4th sign-in is refused | Tell users to log off, not just close the tab |
| Lockout | 3 failures in 15 min | The IdP handles it. Never build your own password retry UI |

An organization may set stricter values. Ask the operator for the realm's actual numbers and configure the app
to be equal or stricter (section 6).

## 2. The flow

- **Authorization code flow with PKCE, method `S256`**, plus `state` and `nonce` on every request. Use your
  library's built-in support (all three examples do).
- **Never** the implicit flow (`response_type=token` or `id_token`), the password grant, or tokens in URL
  fragments. The IdP rejects them, and any code path that tries them is a finding in itself.
- `scope=openid`. Keycloak's default scopes add `profile`, `email` and `roles`. Don't ask for `offline_access`:
  it is removed from the realm.
- Server-side apps are **confidential clients**. A single-page app should use a backend-for-frontend: the browser
  holds only a session cookie and the backend holds the tokens. That is the only client type this request format
  covers.
- The redirect URI you send in the request must match a registered URI **exactly**: scheme, host, port, path and
  query. Build it from your configured public base URL, never from the request's `Host` header.

## 3. Client authentication

### Preferred: `private_key_jwt` (`"auth": "client-jwt"`)

The app signs a short JWT with its private key for each token request. Keycloak verifies it with your public key,
which it fetches from `jwks_url`. No shared secret exists, so nothing secret has to be delivered or rotated
by hand.

Generate the key once per environment, store it as a secret (Kubernetes Secret, Vault and similar, mounted as a
file with mode 0400), and never commit it:

```bash
(umask 077; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out client-key.pem)   # PKCS#8 PEM, 0600 from birth
chmod 0400 client-key.pem
KID=$(openssl pkey -in client-key.pem -pubout -outform DER | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=' | cut -c1-16)
```

Serve the **public** half at `jwks_url` (for example `https://myapp.example.mil/.well-known/jwks.json`), as
`{"keys":[{"kty":"RSA","n":"...","e":"AQAB","kid":"<KID>","alg":"RS256","use":"sig"}]}`. The examples derive it
from the private key at start-up. Rules:

- Publish public keys only. A test should assert that no key in the response has a `d` member.
- The endpoint must be reachable **from the IdP** over https with a certificate the IdP trusts. In split
  networks, tell the operator where it is served.
- The assertion's header `kid` must match a key in the JWKS. Claims: `iss` = `sub` = client_id, `aud` = the token
  endpoint URL, a fresh `jti`, and `exp` 60 seconds or less ahead.
- **Rotation:** publish the new key next to the old one, wait for the IdP's JWKS cache to refresh (ask the
  operator, or have them use "Reload keys" on the client), switch signing to the new key, then remove the old
  one.
- RS256, PS256 and ES256 are FIPS-approved. Don't use EdDSA if the IdP runs in strict FIPS mode.

### Acceptable: client secret (`"auth": "client-secret"`)

- The operator generates the secret and delivers it **out of band** (see `operator-handoff.md`). Never put it in
  the request, a chat, an email, a ticket or a commit.
- The app reads it from a file (`OIDC_CLIENT_SECRET_FILE`, a mounted secret) or, failing that, from an
  environment variable injected by the platform's secret store. Strip a trailing newline. If you must stage it in a
  file by hand, create the file private from the start: `(umask 077; cat > client-secret)`, not `chmod` afterwards.
- Don't log it, put it in an image layer, or put it in `.env` files that are committed or baked into images.
- Send it with `client_secret_basic` (the HTTP Basic header) or `client_secret_post`. Both are accepted.
- Rotation: the operator regenerates the secret, and both sides switch during an agreed window. The old secret
  stops working immediately.

## 4. Validating tokens

**The ID token** (always, on every login). The libraries in the examples do all of these when used as shown:

| Check | Why |
|---|---|
| Signature against the IdP's JWKS (`jwks_uri` from discovery), RS256/PS256/ES256 only, never `alg: none` | Authenticity |
| `iss` equals the issuer exactly | Wrong-IdP and mix-up attacks |
| `aud` contains your client_id (and `azp` equals it if present) | Token issued to another app |
| `exp` in the future, `iat` sensible (allow at most 2 minutes of clock skew) | Replay |
| `nonce` equals the value you stored for this login | Code or ID-token injection |
| `state` equals the stored value (callback, before the code exchange) | CSRF on the callback |

Discovery: `<issuer>/.well-known/openid-configuration`. Cache the JWKS, and refetch it **only** when a token carries
an unknown `kid` (the IdP rotates keys), at most once a minute. Refetching on every failed verification lets anyone
with a garbage token make the app hammer the IdP. `jose.createRemoteJWKSet` (Node) and go-oidc's remote key set do
this already; the Python example shows it by hand.

**The access token**, if you read roles from it (section 5) or call APIs with it: verify the signature, `iss` and
`exp` the same way, and require `azp` to equal your client_id. APIs that accept bearer tokens validate them the
same way, with their own audience.

**Trust store:** the IdP's TLS certificate usually chains to a DoD or other private root that public trust
stores don't include. Add the operator-supplied CA bundle to the app's trust: `NODE_EXTRA_CA_CERTS` for Node,
`REQUESTS_CA_BUNDLE` for Python requests and Authlib, or a custom `RootCAs` in Go (`OIDC_CA_FILE` in the
example). Never turn verification off.

## 5. Roles

- Your client's roles are the `roles` list in your request. The operator creates them and assigns them to people.
- Keycloak puts them in the **access token** at `resource_access.<client_id>.roles`. The default `roles` scope
  does not put them in the ID token, so read them from the verified access token at login and store them in the
  server-side session.
- Enforce authorization **on every request**, server-side, for every function and object (V-222425, V-222429).
  Hiding a button is not authorization.
- Missing role: return 403 and log it. Missing session: return 401 or redirect to `/login`.
- Role changes take effect at the next login. If a change must apply sooner, shorten the app session or refresh
  the token (section 6).
- Don't map the IdP's realm roles or groups into app permissions unless the operator agrees. Client roles are
  the contract.

## 6. Sessions and timeouts

The IdP's limits are a ceiling for the app, never a floor. Its sessions must not outlive the IdP's:

| App setting | Value | STIG |
|---|---|---|
| Local idle timeout | at most 15 min (at most 10 min for admin functions, or register a separate `privileged` client) | V-222389, V-222390 |
| Absolute session lifetime | at most the SSO max lifespan (8 h by default) | V-222520 |
| Session cookie | `Secure`, `HttpOnly`, `SameSite=Lax` (or `Strict`), no `Expires` or `Max-Age`, `__Host-` prefix, `Path=/` | V-222575, V-222576, V-222578 |
| Session ID | system-generated and random, issued fresh after login (fixation), never reused, never in URLs | V-222579, V-222581, V-222582 |
| Session lifecycle audit | log creation, destruction, timeout and renewal, with user and IdP `sid` | V-222441, V-222442, V-222443, V-222445 |

- Enforce idle and absolute limits **server-side** on every request (the examples keep `lastSeen` and
  `loginAt`). A JavaScript timer alone is not enforcement.
- Keep tokens server-side. Don't put tokens in `localStorage`, `sessionStorage` or non-HttpOnly cookies.
- The IdP's idle clock only moves on IdP traffic. If your app session must end when the IdP session idles out (for
  example, logout in another app should be reflected within minutes even if back-channel delivery fails), refresh
  the token every few minutes while the user is active, and end the local session on `invalid_grant`. That is what
  the IdP skill's oauth2-proxy gateway does with a one-minute refresh.
- **Bound what an anonymous visitor can create.** Every `/login` stores state (PKCE verifier, nonce) before anyone
  is authenticated. Expire it (the examples use 10 minutes), sweep sessions that idled out but were never revisited,
  and cap the total (`MAX_SESSIONS`, answered with 503), or a script that requests `/login` in a loop fills memory.
  Give logins in progress their own, much smaller budget (`MAX_PENDING_LOGINS` starts per 10 minutes, 503) and a
  per-client-IP limit (`LOGIN_RATE_PER_IP`, 429 with `Retry-After`), so one client cannot use up the budget for
  everyone. Behind a proxy, the per-IP limit needs the real client IP (section 9), or every user shares one
  budget. A shared store needs the same TTLs and counters.
- **Return-to-page after login without an open redirect.** If you send users back to the page they asked for,
  store that path **server-side** in the login-in-progress state, never in a query parameter you echo back
  unchecked. Accept only a relative path that starts with exactly one `/`: reject `//host`, `/\host`, anything
  with a scheme (`https:`, `javascript:`), a backslash or a control character, and fall back to `/`. After the
  callback, redirect to that stored path. Don't build it from `Referer`.
  ```python
  def safe_return_path(p):
      return p if isinstance(p, str) and p.startswith("/") and not p.startswith(("//", "/\\")) \
          and "\\" not in p and p.isprintable() and ":" not in p.split("?", 1)[0] else "/"
  ```
- For sensitive transactions your organization defines, force re-authentication with `prompt=login` or
  `max_age=0` and check `auth_time` in the new ID token (V-222520).
- Show the date and time of the user's previous logon after sign-in (V-222437). The hardened realm provides it as
  the `previous_login` ID-token claim (UTC).

## 7. Logout

**RP-initiated logout** (the visible "Log off" control, V-222391):

0. Make it a **POST** with CSRF protection: a form button, not a link. Check that `Origin` (or, if absent,
   `Referer`) is your app's own origin, or use your framework's CSRF token. A `GET /logout` lets any page log your
   users out with an `<img>` tag; the examples answer it with 404/405. `SameSite=Lax` alone doesn't cover it: Lax
   cookies are still sent on top-level navigations.
1. Destroy the local session server-side and clear the cookie.
2. Redirect (`303 See Other`) to the IdP's `end_session_endpoint` with `id_token_hint=<the ID token>` and
   `post_logout_redirect_uri=<an exact registered post_logout_redirect_uri>`. This ends the IdP session too.
3. Show an explicit "you have been logged off" page there (V-222392).

**Back-channel logout** (`backchannel_logout_url`, V-222568, V-222388). Keycloak POSTs
`logout_token=<JWT>` (form-encoded) to your endpoint when the SSO session ends: logout from another app,
admin sign-out, or an account being disabled. The call comes from the IdP's server and carries no user cookie, so:

- Remember the mapping from the ID token's `sid` **and** `sub` to your session IDs at login, in a store every
  replica can reach (Redis or a database; the examples use memory).
- Validate the logout token:
  - signature (JWKS), `iss`, and `aud` equal to your client_id;
  - the JOSE header `typ` is `logout+jwt`, and a `typ` claim, if present, is `Logout` (Keycloak sends both).
    This stops an ID or access token, which are signed by the same keys, from being replayed as a logout token;
  - an `events` member containing `http://schemas.openid.net/event/backchannel-logout`;
  - `iat` no more than 60 seconds in the future and no more than 2 minutes old; `exp` not passed;
  - `sid` or `sub` present, and **no** `nonce`. Optionally reject a replayed `jti`.
- With `sid`, destroy the local sessions of that IdP session. With only `sub`, destroy **every** session of that
  user. Never let a missing `sid` match sessions whose stored `sid` is also missing. Return `200` with
  `Cache-Control: no-store`, or `400` for an invalid token.
- The endpoint must be reachable from the IdP, must be exempt from CSRF middleware (it authenticates with the
  token instead) and must not require a session.

## 8. The IdP's job, not the app's

- **DoD Notice and Consent banner:** the IdP shows it on its login pages and records acceptance (V-222434,
  V-222435, V-222436). The app must not add its own copy to the login path. It does need one if it has **other**
  pages reachable before sign-in, such as a public landing page with a "log in" button.
- **CAC/PIV:** the card is read by the IdP over mutual TLS. CAC users arrive at the app as ordinary OIDC users: a
  `sub`, `preferred_username` and claims. The app needs **no** client-certificate handling, no
  `ssl_verify_client`, no reading of `X-SSL-Client-Cert` headers, and no PKI code. Don't make the app's ingress
  request client certificates: browsers will prompt for a card twice. The IdP may also allow password + MFA for
  people without cards. The app cannot tell the two apart and should not need to.
- **Password rules, lockout, MFA, account inactivity, the 72-hour temporary-account disable:** all at the IdP. The
  app has no passwords. Remove any local login form, or the inheritance claims stop holding.
- **Identity:** use `sub` (a stable UUID) as the user key. Usernames can change, and CAC usernames depend on the
  realm's mapping (UPN, EDIPI and so on).

## 9. Behind a reverse proxy

Most apps run behind a TLS-terminating proxy or ingress. Two things go wrong:

- **Callback URLs and cookie flags:** the app sees `http://` and an internal host, builds the wrong redirect URI,
  and refuses `Secure` cookies. Fix it by building every external URL from configuration (`APP_BASE_URL`, equal to
  `root_url` in the request). All three examples do. Only rely on forwarded headers when the proxy is yours.
- **`TRUST_PROXY=1`** (the examples' switch) trusts **one** hop of `X-Forwarded-Proto`, `X-Forwarded-Host` and
  `X-Forwarded-For`. This is Express `trust proxy` and Werkzeug `ProxyFix(x_for=1, x_proto=1, x_host=1)`; Go uses
  `APP_BASE_URL` only. Enable it only when:
  - the app is reachable **only** through that proxy (it listens on loopback or a private network; NetworkPolicy
    or security group), and
  - the proxy **overwrites**, rather than appends to, the `X-Forwarded-*` headers it receives.

  Otherwise anyone can forge their client IP in your audit log, or the scheme your cookie logic trusts.
- Audit records should carry the original client IP (V-222448), so log the forwarded IP only under those
  conditions.
- Keep TLS from the proxy to the app where the platform allows it (V-222596). At minimum, the hop must stay inside
  the accredited boundary.

## 10. Snippets

These are the core of each example, trimmed. Use the full files in `../examples/` as the starting point. They also
cover idle enforcement, back-channel logout, the JWKS endpoint and error handling.

### Node.js / Express: `openid-client` v6 + `jose`

```js
import * as client from 'openid-client';
import * as jose from 'jose';

const key = await jose.importPKCS8(fs.readFileSync(process.env.OIDC_PRIVATE_KEY_FILE, 'utf8'), 'RS256');
const config = await client.discovery(new URL(process.env.OIDC_ISSUER), process.env.OIDC_CLIENT_ID, undefined,
  client.PrivateKeyJwt({ key, kid: process.env.OIDC_KEY_ID }));      // or client.ClientSecretBasic(secretFromFile)

// GET /login
const verifier = client.randomPKCECodeVerifier();
req.session.oidc = { verifier, nonce: client.randomNonce(), state: client.randomState() };
res.redirect(client.buildAuthorizationUrl(config, {
  redirect_uri: `${BASE}/oauth2/callback`, scope: 'openid', state: req.session.oidc.state, nonce: req.session.oidc.nonce,
  code_challenge: await client.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256' }).href);

// GET /oauth2/callback: checks state and PKCE; validates the ID token's signature, iss, aud, exp and nonce
const tokens = await client.authorizationCodeGrant(config, new URL(req.originalUrl, BASE), {
  pkceCodeVerifier: o.verifier, expectedNonce: o.nonce, expectedState: o.state, idTokenExpected: true });
const claims = tokens.claims();
const { payload: at } = await jose.jwtVerify(tokens.access_token,
  jose.createRemoteJWKSet(new URL(config.serverMetadata().jwks_uri)), { issuer: config.serverMetadata().issuer });
if (at.azp !== CLIENT_ID) throw new Error('access token not issued to this client');
const roles = at.resource_access?.[CLIENT_ID]?.roles ?? [];

// POST /logout (same-origin only), after destroying the local session
const src = req.get('origin') ?? req.get('referer');   // absent or unparsable: refuse (never resolve it against BASE)
let sameOrigin = false;
try { sameOrigin = !!src && new URL(src).origin === new URL(BASE).origin; } catch {}
if (!sameOrigin) return res.sendStatus(403);
res.redirect(303, client.buildEndSessionUrl(config, { id_token_hint: idToken, post_logout_redirect_uri: `${BASE}/logged-out` }).href);
```

### Python / Flask: Authlib

```python
from authlib.integrations.flask_client import OAuth
from authlib.oauth2.rfc7523 import PrivateKeyJWT
from joserfc.jwk import RSAKey

key = RSAKey.import_key(open(os.environ["OIDC_PRIVATE_KEY_FILE"]).read(), {"kid": KID})
oauth = OAuth(app)
oauth.register("idp", client_id=CLIENT_ID, client_secret=key,           # or the secret read from a file
               server_metadata_url=ISSUER + "/.well-known/openid-configuration",
               client_kwargs={"scope": "openid", "code_challenge_method": "S256",
                              "token_endpoint_auth_method": "private_key_jwt"},
               client_auth_methods=[PrivateKeyJWT(headers={"kid": KID})])

@app.get("/login")
def login():                       # Authlib adds state, nonce and the S256 challenge
    return oauth.idp.authorize_redirect(BASE + "/oauth2/callback")

@app.get("/oauth2/callback")
def callback():                    # validates state and the ID token's signature, iss, aud, exp and nonce
    token = oauth.idp.authorize_access_token()
    claims = token["userinfo"]
    at = verify_jwt(token["access_token"], azp=CLIENT_ID)        # joserfc + the IdP JWKS; see the example
    roles = at.get("resource_access", {}).get(CLIENT_ID, {}).get("roles", [])
```

### Go: `coreos/go-oidc` v3 + `x/oauth2`

```go
provider, err := oidc.NewProvider(ctx, issuer)
if err != nil {
	log.Fatal(err)
}
conf := oauth2.Config{ClientID: clientID, Endpoint: provider.Endpoint(), RedirectURL: base + "/oauth2/callback",
	Scopes: []string{oidc.ScopeOpenID}}
conf.Endpoint.AuthStyle = oauth2.AuthStyleInParams // private_key_jwt: client_id in the body, no Basic header
idv := provider.Verifier(&oidc.Config{ClientID: clientID})         // signature, iss, aud, exp
atv := provider.Verifier(&oidc.Config{SkipClientIDCheck: true})     // access token: azp is checked below

// /login
verifier := oauth2.GenerateVerifier()
http.Redirect(w, r, conf.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)

// /oauth2/callback, after the state check. Every failure ends the request: fail closed.
assertion, err := signedAssertion() // go-jose: iss=sub=client_id, aud=token URL, jti, exp <= 60 s
if err != nil {
	http.Error(w, "sign-in failed", http.StatusInternalServerError)
	return
}
tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(verifier),
	oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
	oauth2.SetAuthURLParam("client_assertion", assertion))
if err != nil {
	http.Error(w, "sign-in failed", http.StatusBadRequest)
	return
}
rawID, ok := tok.Extra("id_token").(string)
if !ok {
	http.Error(w, "sign-in failed", http.StatusBadRequest)
	return
}
idt, err := idv.Verify(ctx, rawID)
if err != nil || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(nonce)) != 1 { // go-oidc does not check nonce
	http.Error(w, "sign-in failed", http.StatusBadRequest)
	return
}
att, err := atv.Verify(ctx, tok.AccessToken)
var at struct {
	Azp            string                         `json:"azp"`
	ResourceAccess map[string]struct{ Roles []string } `json:"resource_access"`
}
if err != nil || att.Claims(&at) != nil || at.Azp != clientID || att.Subject != idt.Subject {
	http.Error(w, "sign-in failed", http.StatusBadRequest)
	return
}
roles := at.ResourceAccess[clientID].Roles
```

## 11. Before you send the request

- [ ] Code flow + PKCE S256 + state + nonce; no implicit, password or device code paths.
- [ ] ID token fully validated; roles read from the verified access token; authorization on every request.
- [ ] Idle at most 15 min (10 for admin), absolute at most 8 h, server-side; the cookie is Secure, HttpOnly,
      SameSite and non-persistent.
- [ ] Log off is a same-origin POST that goes to `end_session_endpoint` and lands on a logged-off page; the
      back-channel endpoint checks `typ`, `events`, `iat` and the signature, and kills sessions by `sid` (or every
      session of `sub`) across replicas.
- [ ] Any return-to-page path is stored server-side and only ever a single-`/` relative path.
- [ ] Pre-login state expires and the session store is capped.
- [ ] `previous_login` shown after sign-in.
- [ ] No local login form, no secrets in git, and no tokens or secrets in logs.
- [ ] `client-jwt`: JWKS served over https at the URL in the request, reachable from the IdP, public keys only.
- [ ] `python3 scripts/validate-client-request.py --strict client-request.json` passes.

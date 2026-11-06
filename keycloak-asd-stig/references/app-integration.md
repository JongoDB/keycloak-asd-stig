# Integrating a relying application (how one Keycloak realm scales across solutions)

Each new solution = one entry in `clients` (or its own realm/profile) + an inheritance statement.

## Steps for a new solution
1. Add the client to the profile (`oidc-confidential` for server apps, `oidc-public` for SPAs/mobile, `saml` for
   legacy). Exact redirect URIs only - wildcards are refused by the generator.
2. `kcstig.py apply --profile p.json` (idempotent) and `kcstig.py verify ...`.
3. `kcstig.py inherit --profile p.json --app <solution>` -> `<solution>-stig-inheritance.md`: the list of ASD
   rules the app can mark as inherited (attach the Keycloak checklist as evidence), shared ones, and the rest.
4. Implement the shared obligations below in the app and test them in the app's own ASD checklist.

## Shared obligations the IdP cannot meet for the app
| STIG | What the app must do |
|---|---|
| V-222389 / V-222390 | Local session idle <= 15 min (<= 10 min for admin functions); do not keep users alive with silent refresh beyond that |
| V-222391 / V-222392 | Visible logoff -> RP-initiated logout (`end_session_endpoint` with `id_token_hint`); show a logged-off confirmation |
| V-222578 / V-222575 / V-222576 | Session cookie: Secure, HttpOnly, SameSite, no Expires/Max-Age |
| V-222437 | Show the `previous_login` ID-token claim (date/time of last successful logon) after sign-in |
| V-222425 / V-222429 | Enforce authorization on every request from token roles; `fullScopeAllowed=false` limits roles to the client's own |
| V-222520 | Ask for `prompt=login` or `max_age=0` before sensitive transactions defined by the organization |
| V-222568 | Implement back-channel logout (`backchannel_logout_url`): drop the local session when Keycloak ends it |
| V-222602 / V-222603 / V-222607 ... | Input validation, XSS, CSRF, injection - the app's own code |

## Client library settings (OIDC)
- Authorization code + PKCE S256 (enforced by the `asd-stig` client policy; implicit and password grants are
  rejected server-side).
- Validate `iss`, `aud`, `exp`, `nonce`, signature (RS256 or PS256; FIPS-approved).
- Prefer `client-jwt` (private_key_jwt) or `client-x509` (mTLS) over shared secrets for confidential clients.
- Access tokens live 5 minutes; refresh tokens are single use (rotation) - handle `invalid_grant` by
  re-authenticating.

## SAML clients
Signed responses and assertions, encrypted assertions (`saml.encrypt=true`, needs the SP's encryption cert in
`encryption_cert`), RSA-SHA256, persistent NameID, assertion lifespan 300 s. Keycloak always emits
`NotBefore`/`NotOnOrAfter` (V-222400/403/404).

## One realm or many?
- One realm per *mission/user population* with many clients is simplest: one CAC mapping, one banner, one
  audit trail; every client inherits the same controls.
- Separate realms when user populations, classification or ATO boundaries differ. Generate one profile per
  realm; the admin realm hardening (`--harden-master`) is done once per Keycloak deployment.

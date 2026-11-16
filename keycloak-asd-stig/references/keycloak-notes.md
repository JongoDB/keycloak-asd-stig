# Keycloak 26.8.2 facts verified while building this skill

Things that are easy to get wrong and silently break compliance. Re-check them after upgrades.

| Topic | Verified behaviour | Consequence |
|---|---|---|
| `https-client-auth`, `log-mdc-enabled`, `https-management-client-auth`, `spi-x509cert-lookup--provider` | **Build-time** options | Put them in the Dockerfile (`KC_*` env before `kc.sh build`); in keycloak.conf they are ignored and the server refuses to start with `--optimized` |
| Read-only root FS | Keycloak writes `data/keycloak-truststore.p12` at start | tmpfs on `/opt/keycloak/data` |
| keycloak.conf `${VAR}` | Unset variables are an error | Use `${VAR:default}` |
| Workflows feature | Enabled by default; REST `/admin/realms/{r}/workflows` | Used for V-222409/V-222411 |
| Workflow condition | `has-user-attribute(key:value)`; `key,value` is **accepted but never matches**; `not ...` works | Always use colon form |
| Workflow triggers | `on: "user-created or user-authenticated"` + `concurrency.restart-in-progress: "true"` restarts the timer at each logon (tested) | One workflow implements "35 days since last logon" |
| Workflow runner | `spi-events-listener--workflow-event-listener--step-runner-task-interval` in **seconds**, default 12 h | Set 900 so a 72 h temp account is not alive for 84 h |
| Client policy `reject-ropc-grant` | Empty configuration -> NullPointerException on every client create/update | Always pass `{"auto-configure":"true"}` |
| Admin REST API | Tokens need the admin-API audience from client scope `kc-admin-api` | Add that default scope to automation service accounts or every call is 401 |
| Default password hash | argon2 (not FIPS approved) | Policy sets `hashAlgorithm(pbkdf2-sha512) and hashIterations(210000)` |
| FIPS | Needs bc-fips, bctls-fips, bcutil-fips **and bcpkix-fips** in providers; `serverinfo.cryptoInfo.cryptoProvider` becomes `FIPS1402Provider` | Missing bcpkix-fips -> `NoClassDefFoundError org/bouncycastle/cert/CertIOException` |
| X.509 + OCSP + CRL | Both are evaluated on each login; `ocsp-fail-open` only skips OCSP | Safe to enable only with CRL on |
| Login page IDs | `data-page-id="login-login-x509-info"` (no `.ftl`) | Used by the banner script and e2e tests |
| Cookies | `KEYCLOAK_IDENTITY` is a browser-session cookie without remember-me; `KEYCLOAK_SESSION` carries an expiry but is only a status hint for JS adapters | V-222578 judged on `KEYCLOAK_IDENTITY` |
| Event listener SPI | A new `KeycloakSession` from `runJobInTransaction` must `getContext().setRealm(realm)` before user lookups | Otherwise "Session not bound to a realm" breaks the login |
| Offline tokens | Default role grants `offline_access`; offline sessions ignore the SSO idle limit | Removed from default roles and default optional scopes |
| Docker Hub | Anonymous pulls rate-limited (429) | Use a registry mirror (e.g. `mirror.gcr.io/library/postgres:17`) |
| TLS client-auth trust | `truststore-paths` is **merged with the ~140 public CAs of the JVM**: the server advertises and accepts client certificates from DigiCert, Let's Encrypt, ... | Set `https-trust-store-file` to a DoD-only PKCS#12 (`client-ca.p12`, built by pki-init with `openssl pkcs12 -jdktrust`). Verify with `openssl s_client` "Acceptable client certificate CA names" (verify does this live) |
| `x509-cert-auth.casubjectdn` | Matched against the **trust anchor (root)** of the validated path, not the issuing CA; empty value is logged as deprecated | Pin the DoD root DNs (RFC 2253): `CN=DoD Root CA 3,OU=PKI,OU=DoD,O=U.S. Government,C=US`, ... |
| CRL files | Every configured CRL is evaluated on every login; a CRL whose issuer is not trusted throws `crlSignatureCertificates is null` and **every** login fails | pki-sync only installs CRLs whose signature verifies against the trust store |
| CRL performance | Infinispan CRL cache works (parsing is cached), but `CRLUtils.check` re-verifies the signature of EVERY listed CRL on every login: with ~140 MB of DoD CRLs non-FIPS 0.14 s/login, strict FIPS 4-5 s/login, 3.5-4.9 GiB memory | `stig-x509-client-username-form` checks only the issuing CA's CRL and verifies each CRL once per file version: ~0.06 s/login in strict FIPS (cac-pki.md) |
| BC-FIPS native code | BC-FIPS 2.1 extracts a JNI library into /tmp and maps it executable: fails on a `noexec` /tmp and Keycloak refuses to start | `JAVA_OPTS_APPEND=-Dorg.bouncycastle.native.cpu_variant=java` (baked into the image) |
| FIPS strict + PKCS#12 | Strict mode accepted the PKCS#12 client trust store and the DB created by the non-FIPS image (existing realms/keys) | Upgrade path non-FIPS -> FIPS works in place |
| Bootstrap admin env on restart | Restarting with `KC_BOOTSTRAP_ADMIN_*` still set does **not** recreate the temporary admin once the admin realm exists | Still remove the variables after the first apply |
| Recovery | `kc.sh bootstrap-admin service --client-id X --client-secret:env=VAR --optimized` against the same DB creates a temporary admin client (`is_temporary_admin=true`) | apply `--remove-bootstrap-admin` deletes temporary admin users **and** clients |
| oauth2-proxy (gateway) | Header injection can only read session fields (user, email, groups, preferred_username, tokens), not arbitrary claims; its "email" field holds the user-ID claim; the alpha-config converter emits `insecureSkipNonce: true`; `backendLogoutURL` is a provider field in alpha config | Gateway forwards `X-Forwarded-Id-Token` for `previous_login`, sets nonce validation on |
| Clustering | `cache-stack=jdbc-ping` (baked) clusters through the database on any runtime; `status.podIP` bind address not needed | Allow 7800/57800 between replicas |
| Upgrade 26.7 -> 26.8 | DB migrates in place, workflows and their schedules survive; but service accounts created before 26.8 lack the new `kc-admin-api` audience and get 401 from the admin API | One-time recovery with `kc.sh bootstrap-admin service` (operations.md section 7) |

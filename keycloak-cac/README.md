# keycloak-cac: a single DoD CAC/PIV identity provider image

One container image that you deploy and configure with environment variables. It provides:
- **Keycloak 26.8.2 hardened to the DISA ASD STIG V6R4**, configured by the image itself at startup.
- **Login with a CAC or PIV card.** The DoD PKI trust anchors are baked in at build time. A bundle you drop in yourself works for offline builds.
- **Revocation checking with CRL and OCSP.** It works online or air-gapped, and the CRLs stay fresh.
- **Admin access only with an Alt Token.** Admin passwords are disabled, and the bootstrap admin is removed once the image has configured itself.
- **The STIG session rules**: a 15/10-minute idle timeout, a 3-strike lockout, the DoD banner, a concurrent-session limit, auditing and previous-logon display.

Every application then uses it as its OpenID Connect provider:

```
issuer:  https://<CAC_PUBLIC_URL>/realms/<CAC_REALM>        (discovery: <issuer>/.well-known/openid-configuration)
```

There are no sidecars, init containers or jobs. Run more replicas for high availability: they cluster through the database, and each one applies the realm configuration idempotently.

> The image does **not** act as a certificate authority. It *trusts* the DoD CAs and checks each card against them. The only CA it ever creates is the throwaway mock-CAC CA in lab mode.

## Quick start (lab, no card needed)

```bash
docker build -f keycloak-cac/Containerfile -t keycloak-cac:26.8.2 .          # from the repository root
docker compose -f keycloak-cac/deploy/compose/compose.lab.yaml up -d
docker compose -f keycloak-cac/deploy/compose/compose.lab.yaml cp keycloak:/opt/keycloak/data/cac/lab/users ./lab-cards
```

Import `lab-cards/doe.john.p12` (password `changeit`) into a browser and open `https://localhost:8443/realms/dod-cac/account`.
- `revoked.p12` is refused because its certificate is revoked.
- `unmapped.p12` is refused because no account is mapped to it.
- `admin.alt.p12` is the Alt Token that can open `/admin`.

**If a card login says "Invalid username or password":**
- If the logs show a `LOGIN_ERROR` with no `user_not_found` and no X.509 lines, the browser didn't send a certificate. Browsers remember a client-certificate choice per address, so after switching servers on the same address, fully quit Chrome (Cmd-Q) and retry in a new private window.
- If the logs show `user_not_found`, the mapped value doesn't match the card. That event's `username="..."` is what the card actually holds.

To use your real CAC in the lab, set `CAC_LAB_TRUST_DOD=true` and `CAC_USERS=your.name=<your card's UPN>`. The username needs at least 3 characters. The container then also downloads the DoD CRLs (from crl.disa.mil, about 140 MB) and needs about 5 GB of memory. The mock cards keep working alongside your card.

## Production

**Step-by-step instructions for every platform** are in **[DEPLOY.md](DEPLOY.md)**: building (standard, FIPS, multi-arch, offline), pushing to Azure Container Registry, AWS ECR, GHCR, Google Artifact Registry, Harbor, Iron Bank or an air-gapped site, and running on Docker, Podman (including Quadlet/systemd), Kubernetes, Helm, OpenShift, AKS, Azure Container Instances, ECS/Fargate, EKS or GKE.

The short version for one host:

```bash
cd keycloak-cac/deploy/compose && cp keycloak-cac.env.example keycloak-cac.env    # edit it
mkdir -p tls secrets clients     # tls/tls.crt + tls.key, secrets/{db_password,bootstrap_admin_password,automation_secret}
sudo chown root:1000 tls/* secrets/* && sudo chmod 0440 tls/* secrets/*   # one file each, read by the service's uid/gid 1000:1000
docker compose up -d             # podman compose works too; --scale keycloak=2 for HA
```

| Runtime | File |
|---|---|
| Docker / Podman Compose | `deploy/compose/compose.yaml` (+ `compose.airgap.yaml` for offline CRLs) |
| Kubernetes with Helm | `deploy/helm/keycloak-cac` (`values-airgap.yaml` for closed networks) |
| Kubernetes without Helm | `deploy/k8s/keycloak-cac-airgap.yaml` |
| AWS ECS / Fargate | `deploy/ecs/task-definition.json` (with an NLB TCP listener: 443 to 8443) |

**CAC needs TLS to reach Keycloak unbroken.** Use one of these:
- Expose port 8443 directly.
- Use a Layer-4/TCP passthrough load balancer (an NLB, MetalLB, or HAProxy in TCP mode).
- Build with `X509_LOOKUP=nginx` (or haproxy, apache, envoy), so that a proxy verifies the card and forwards it in a header. Keycloak then believes that header, so the proxy must authenticate with a TLS client certificate (`CAC_EDGE_PROXY_CA_FILE`; the image refuses to start without it) and be the only thing that can reach Keycloak: no published port (`compose.edge.yaml`), or the chart's `edge.proxyFrom` NetworkPolicy. Use a proxy dedicated to Keycloak that overwrites the header on every request. A shared ingress controller is not acceptable, because any tenant's Ingress could set the header.

An L7 ingress or ALB that decrypts traffic and forwards nothing breaks CAC login.

### Registering an application

Add one JSON file per application to `CAC_CLIENTS_DIR`. A Kubernetes ConfigMap works, or you can use `clients:` in the Helm values or `CAC_CLIENTS_JSON`. Restart the pods, or let the next rollout pick it up.

```json
{"client_id": "payroll", "type": "oidc-confidential", "auth": "client-jwt",
 "jwks_url": "https://payroll.example.mil/.well-known/jwks.json",
 "redirect_uris": ["https://payroll.example.mil/oauth2/callback"],
 "post_logout_redirect_uris": ["https://payroll.example.mil/"],
 "backchannel_logout_url": "https://payroll.example.mil/oauth2/backchannel-logout",
 "roles": ["payroll-user", "payroll-approver"]}
```

The fields are documented in `keycloak-asd-stig/references/profile.md` under clients. If an application can't enforce the STIG session rules itself, put the skill's hardened oauth2-proxy gateway in front of it (`kcstig.py gateway`).

## Environment
<!-- env-start -->

| Variable | Default | Meaning |
|---|---|---|
| `CAC_PUBLIC_URL` | *(required)* | Public base URL, for example `https://sso.example.mil`. It sets `KC_HOSTNAME`. |
| `CAC_REALM` (alias `KC_REALM_NAME`) | `dod-cac` | The realm that applications use. |
| `CAC_REALM_DISPLAY_NAME` | realm name | Title shown on the login page. |
| `CAC_USERNAME_SOURCE` (alias `CAC_USERNAME_ATTRIBUTE`) | `upn` | Which part of the certificate identifies the person. The options are listed under "Username sources" below. `SERIALNUMBER` is refused because it changes every time a card is reissued. |
| `CRL_MODE` | `online` (`file` in lab mode) | `online`: download the DoD CRLs and refresh them, plus OCSP. `file` (alias `OFFLINE`): CRLs from `CAC_CRL_DIR`. `ocsp`: OCSP only. `none`: no revocation checking, accepted only with `CAC_LAB_MODE=true`. |
| `CAC_CRL_DIR` | `/crl` | File mode: a directory of `*.crl` files. Each one is signature-checked against the anchors before use. |
| `CAC_CRL_REFRESH_SECONDS` | `21600` | How often CRLs are re-fetched or re-read. After each refresh, every node's CRL cache is cleared. |
| `CAC_OCSP` | on for `online`/`ocsp` | Checks OCSP in addition to CRLs. The `ocsp` mode fails closed. |
| `CAC_OCSP_RESPONDER_URI` | *(from the certificate)* | Overrides the responder, for example a local OCSP repeater. |
| `CAC_ADMINS` | | Alt Token administrators, as `user=<Alt Token UPN>,...`. With this set, the admin realm is hardened and the bootstrap admin is deleted. |
| `CAC_ADMINS_JSON` / `CAC_ADMINS_DIR` | | Full admin records (email, names and so on). |
| `CAC_USERS` | | Card holders, as `user=<value of the username source>,...`. |
| `CAC_USERS_JSON` / `CAC_USERS_DIR` | | Full user records, including `client_roles`. |
| `CAC_CLIENTS_DIR` / `CAC_CLIENTS_JSON` | | Relying applications (see above). |
| `CAC_AUTH_MODE` | `cac` | `cac` (card only) or `cac_or_mfa` (card, or password plus OTP/WebAuthn). |
| `CAC_CERT_POLICIES` | | Required certificate policy OIDs, comma separated (for example the DoD medium-hardware policy). |
| `CAC_PROFILE_JSON` / `CAC_PROFILE_FILE` | | A JSON overlay for any kcstig profile field, for example `{"sessions":{"max_hours":10}}`. Values weaker than the STIG are logged as warnings. |
| `CAC_AUTOMATION_SECRET` (`_FILE`) | *(required)* | Secret of the admin-API service account that applies the realm. Use 24 or more characters and keep it the same across restarts. |
| `KC_BOOTSTRAP_ADMIN_USERNAME` / `_PASSWORD` (`_FILE`) | | Used for the first start only. |
| `KC_HTTPS_CERTIFICATE_FILE` / `_KEY_FILE` | *(required)* | Server certificate (PEM, chain included), or `CAC_TLS_CERT_PEM` / `CAC_TLS_KEY_PEM` as environment variables. |
| `KC_DB_URL`, `KC_DB_USERNAME`, `KC_DB_PASSWORD` (`_FILE`) | | PostgreSQL. Use `sslmode=verify-full` in production. |
| `CAC_TRUST_ANCHORS_DIR` | | **Replaces** the baked DoD bundle with these zip, p7b or PEM files. |
| `CAC_EXTRA_ANCHORS_DIR` | | **Adds** CAs, for example ECA or a partner PKI. Their fingerprints are logged. |
| `CAC_APPLY` | `true` | `false` leaves the realm alone, which suits GitOps-managed realms. |
| `CAC_EDGE_PROXY_CA_FILE` | | Edge images only (`X509_LOOKUP` other than `default`): the CA that issued the verifying proxy's TLS client certificate. The listener then **requires** a client certificate from that CA (edge builds bake `https-client-auth=required`) and trusts it for that hop only; cards are still checked against the DoD anchors. It must be a **dedicated** CA that issues the proxy's certificate and nothing else, because anything it signs can speak for any card. Such an image refuses to start without it, or without `CAC_EDGE_PROXY_CERT_FILE`. See `deploy/compose/compose.edge.yaml` and the chart's `edge:` values. |
| `CAC_EDGE_PROXY_CERT_FILE` | | Edge images only: pin the proxy's own client certificate instead of a CA. The listener then accepts exactly that certificate (the startup log prints its SHA-256), and it takes precedence over `CAC_EDGE_PROXY_CA_FILE`. |
| `STIG_PUBLIC_PATHS` | | Network allowlist of raw paths (`stig-extensions` PublicPathAllowlistFilter). Comma separated; an entry ending in `/` is a prefix, anything else is exact. For network clients, a raw path with `%`, `;`, `\`, `//`, a `.` or `..` segment, whitespace, a control character or non-ASCII is refused (404), and so is anything not listed. Example for one realm: `/realms/r,/realms/r/,/admin/r/,/admin/realms/r/,/admin/serverinfo,/resources/`. The master realm and any unlisted realm are then unreachable from the network. Needs `STIG_TRUSTED_SOURCES`. |
| `STIG_TRUSTED_SOURCES` | | TCP peer IPs that bypass the allowlist, for example `127.0.0.1` and the host's Docker network gateway. Forwarded headers are never trusted. Set it together with `STIG_PUBLIC_PATHS`, or the container refuses to start. **Migration:** the earlier `STIG_ADMIN_REALM_ALLOWED_SOURCES` is retired, and setting it now stops the container with a message naming these two variables. |
| `CAC_LAB_MODE` | `false` | Generates a mock CAC PKI and a self-issued server certificate, and allows `CRL_MODE=none` and dev databases. |
| `CAC_LAB_TRUST_DOD` | `false` | Lab mode: also trusts the baked DoD bundle, so a real card works. |
| `KC_HTTP_RELATIVE_PATH`, `KC_DB` | `/`, `postgres` | Keycloak build-time options. A different value at run time triggers an automatic rebuild at startup, which is slower and needs a writable `/opt/keycloak/lib`. For production, use the build argument instead. |
| `HTTPS_PROXY`, `NO_PROXY`, `CURL_CA_BUNDLE` | | Egress proxy settings for CRL downloads. |
| any `KC_*` | | Every Keycloak option still works. |

Every `*_PASSWORD`, `*_SECRET`, `*_USERNAME` and `*_TOKEN` variable also accepts `_FILE` pointing to a file. That suits Docker or Podman secrets, Kubernetes Secret volumes and Vault Agent.
<!-- env-end -->

### Username sources

| `CAC_USERNAME_SOURCE` | Certificate field | Account attribute | Notes |
|---|---|---|---|
| `upn` | SAN otherName UPN, for example `1234567890123456@mil` | `cac_upn` | The DoD standard. Copy it exactly: contractor and newer cards have 16 digits. |
| `edipi` | 10-digit DoD ID at the end of the subject CN | `cac_edipi` | Easiest to provision, since people know their DoD ID. |
| `cn` | Subject common name | `cac_cn` | |
| `subject-dn` | Full subject DN | `cac_subject_dn` | |

Users can't edit these attributes, so nobody can map someone else's card to their own account. Alt Tokens always map by UPN.

## Build arguments

```bash
docker build -f keycloak-cac/Containerfile -t keycloak-cac:26.8.2 .                       # downloads the DoD bundle
docker build -f keycloak-cac/Containerfile --build-arg PKI_FETCH=false -t keycloak-cac .  # offline: bundle in keycloak-cac/certs/
```

These are listed at the top of the `Containerfile`:
- `KEYCLOAK_IMAGE`: Iron Bank or Red Hat build of Keycloak 26.x bases work too.
- `PKI_BUNDLE_URLS`: for example, add the ECA bundle.
- `PKI_FETCH`, `PKI_REQUIRE_MANIFEST`, `PKI_KEEP_EXPIRED`, `PKI_REFRESH`.
- `KC_DB`, `KC_HTTP_RELATIVE_PATH`, `X509_LOOKUP`.
- `FIPS`: put the BC-FIPS jars in `keycloak-cac/fips/`.

How the build handles the trust anchors:
- **Bundle check:** the build verifies the DISA bundle's signed SHA-256 manifest and refuses a tampered bundle.
- **What it keeps:** CA certificates only. Expired CAs are dropped, because their stale CRLs would block every login.
- **Where the list goes:** the result is printed during the build and stored in `/opt/keycloak-cac/pki/anchors.txt`. Compare the DoD Root CA fingerprints with the values DISA publishes.
- **Refreshing:** rebuild when DISA publishes a new bundle (`--build-arg PKI_REFRESH=$(date +%F)`).
- **Behind a TLS-inspecting egress proxy:** put the proxy's CA in `keycloak-cac/certs/build-trust/`. It's trusted only for the download.

A fully air-gapped build host still needs a UBI package mirror for the tools stage. Alternatively, build on a connected host and move the image.

## What happens at startup

1. `*_FILE` secrets are read, and the configuration is validated. The container refuses to start on any setting weaker than the STIG allows: a missing certificate, `CRL_MODE=none` outside lab mode, a serial-number mapping, a dev database or a missing automation secret.
2. Trust anchors are set up from the baked bundle, a mounted directory or the lab PKI. The container builds `client-ca.p12` from these anchors **only**, so public CAs can never authenticate a client (V-222584), and pins the root DNs.
3. CRLs come from a local directory (`file`), or start downloading in the background (`online`). Card logins fail closed until they arrive.
4. Keycloak starts as PID 1.
5. A worker waits for Keycloak, then applies the STIG realm: flows, timeouts, lockout, banner, users, clients, the Alt Token admin realm, and the automation account. It then deletes the bootstrap admin. If the apply fails three times, it stops the container (fail secure).
6. The same worker refreshes CRLs every `CAC_CRL_REFRESH_SECONDS` and clears Keycloak's CRL cache cluster-wide.

Keycloak otherwise keeps a CRL until its `nextUpdate`, about 7 days for DoD CRLs.

**Readiness** (`cac-entrypoint.sh health`, used by the image `HEALTHCHECK` and the Helm probes) means three things: Keycloak is ready, the realm is applied, and revocation data is loaded.

## Verification

All of these were run against this image. The black-box suite is `keycloak-asd-stig/scripts/e2e_check.py`: banner, card login, revoked, unmapped and rogue-CA cards, session limit, logout, cookies, refresh-token rotation, `previous_login`, and the Alt Token admin.

| Setup | Result |
|---|---|
| Lab: one container plus PostgreSQL | 13/13 e2e, rogue-CA card refused at TLS, full STIG verify |
| Production shape, air-gapped: mounted anchors and CRLs, secrets as files, EDIPI mapping, read-only root | 14/14 |
| `KC_HTTP_RELATIVE_PATH=/auth` set at run time (automatic rebuild) | issuer `https://host/auth/realms/dod-cac`; 11/12 e2e |
| Two replicas started together on one database (jdbc-ping cluster, concurrent apply) | 9/9 against each replica |
| Helm chart pod spec through `podman kube play` (ConfigMap CRLs, read-only root, restricted security context) | 13/13 |
| ECS shape: secrets and certificate in env vars, tmpfs data | 8/8 |
| Online: baked DoD bundle, live download of all 17 DoD CRLs, CRL cache clear | passed; the TLS handshake requests only DoD CAs (45 names) |
| Offline drop-in build, and a tampered bundle | same 45 anchors; the tampered bundle is refused |
| Wrong automation secret after hardening | container stops (fail secure) |
| **Strict FIPS** build (`FIPS=true`): BCFKS stores converted at startup | 14/14; `server.fips` passes (`Fips1402StrictCryptoProvider`) |
| Arbitrary UID (OpenShift style: random UID, group 0, read-only root) | healthy; realm applied |
| **Live DoD CAC** (DOD ID CA-80, 16-digit UPN) in lab mode with DoD trust, live CRLs and OCSP, on Docker Desktop for Mac | login succeeded |
| Lab mode plus DoD trust: mock CA and DoD anchors, mock CRL plus all 17 DoD CRLs | 11/11 with mock cards; 4.3 GiB memory with the DoD CRLs loaded |

On the `/auth` run, the one failure was `previous_login`. That run used Keycloak's built-in admin-console client, which doesn't carry the `stig-claims` scope. The check passed in the runs that used registered clients.

`kcstig.py verify` on the lab realm, standard build: 49 pass. The only failing check is `server.fips`, which accounts for all 6 Open rules. The FIPS build passes `server.fips`.

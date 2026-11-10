# Deploying keycloak-cac

You build the image once, push it to the registry you use, and run the same image everywhere. Only the wrapper changes from one runtime to the next.

Each section says what was tested and what wasn't. "Tested" means it was run against this image, with the e2e suite passing, as listed in [README.md](README.md#verification).

- [1. What every deployment needs](#1-what-every-deployment-needs)
- [2. Build](#2-build) (standard, FIPS, multi-arch, offline)
- [3. Push to a registry](#3-push-to-a-registry): Azure Container Registry, AWS ECR, GHCR, Google Artifact Registry, Harbor, Iron Bank, air-gapped
- [4. Docker](#4-docker) · [5. Podman](#5-podman) · [6. Kubernetes (kubectl)](#6-kubernetes-kubectl) · [7. Helm](#7-helm) · [8. OpenShift](#8-openshift)
- [9. Azure](#9-azure): AKS, Container Instances, Container Apps · [10. AWS](#10-aws): ECS/Fargate, EKS · [11. Google Cloud](#11-google-cloud)
- [12. After deploying](#12-after-deploying) · [13. Operations](#13-operations)

## 1. What every deployment needs

| Item | Notes |
|---|---|
| **PostgreSQL 13 or later** | Holds all state. Use `sslmode=verify-full` in production. In strict FIPS mode, the database password must be at least 14 characters. |
| **Server certificate** for the public host name | PEM with the chain. Mount it as files (`KC_HTTPS_CERTIFICATE_FILE`/`_KEY_FILE`), or pass it as env vars (`CAC_TLS_CERT_PEM`/`CAC_TLS_KEY_PEM`). |
| **Three secrets** | The DB password; the bootstrap admin password (used on first start only); `CAC_AUTOMATION_SECRET` (24+ characters, kept stable). Passing them as `*_FILE` is preferred. |
| **TLS passthrough to port 8443** | Browsers must complete TLS with Keycloak itself, because the card signs that handshake. Use a direct port, an L4/TCP load balancer, or an OpenShift passthrough route. An L7 proxy that decrypts traffic breaks CAC login unless you build with `X509_LOOKUP` and the proxy verifies the card (see the README). |
| **Revocation path** | `CRL_MODE=online` needs outbound access to `crl.disa.mil` (HTTP) and `ocsp.disa.mil`. `CRL_MODE=file` needs a CRL directory that something keeps fresh. |
| **Memory** | 8 GiB limit per replica with all DoD CRLs. 4.3 to 4.9 GiB was measured; about 0.6 GiB without CRLs. |
| **Configuration** | `CAC_PUBLIC_URL`, `CAC_REALM`, `CAC_ADMINS`, `CAC_USERS`, and app clients. The full list is in [README.md](README.md#environment). |

Generate the secrets on any machine:

```bash
mkdir -p secrets && openssl rand -hex 24 > secrets/db_password && openssl rand -hex 24 > secrets/bootstrap_admin_password && openssl rand -hex 32 > secrets/automation_secret
```

## 2. Build

Run these from the repository root. The build context is the root folder.

```bash
docker build -f keycloak-cac/Containerfile -t keycloak-cac:26.8.2 .                                  # standard
docker build -f keycloak-cac/Containerfile --build-arg FIPS=true -t keycloak-cac:26.8.2-fips .       # strict FIPS
podman build -f keycloak-cac/Containerfile -t keycloak-cac:26.8.2 .                                  # podman / buildah: same arguments
```

- **FIPS** (`FIPS=true`, strict by default):
  - The build adds the Bouncy Castle FIPS jars. Their SHA-256 hashes are pinned in `keycloak-cac/fips/fips-jars.sha256`.
  - At startup, the image converts the server certificate and the client trust store to BCFKS, because strict mode accepts nothing else.
  - Every password must be at least 14 characters.
  - The result runs FIPS-approved algorithms only. A *validated* configuration also needs a FIPS-enabled host (RHEL 9: `fips-mode-setup --enable`).
  - Expect slower card logins with large CRL sets: v1 measured 4 to 5 s per login with all DoD CRLs. If you can, list only the CRLs of the CAs that issue your users' cards.
  - Tested: 14/14 e2e, and `server.fips` passes (`Fips1402StrictCryptoProvider`).
- **Iron Bank or Red Hat base:** pass `--build-arg KEYCLOAK_IMAGE=registry1.dso.mil/ironbank/opensource/keycloak/keycloak:<26.x tag>` (after `docker login registry1.dso.mil`). For Red Hat build of Keycloak, use `registry.redhat.io/rhbk/keycloak-rhel9:26`. Not tested here, because those registries need credentials.
- **Multi-arch** (Apple Silicon, Graviton): `docker buildx build --platform linux/amd64,linux/arm64 -f keycloak-cac/Containerfile -t <registry>/keycloak-cac:26.8.2 --push .`. arm64 hasn't been run end to end here (only amd64 was built and tested).
- **Offline build:** put the DISA zip in `keycloak-cac/certs/` and the BC-FIPS jars in `keycloak-cac/fips/`, then pass `--build-arg PKI_FETCH=false`. The tools stage still needs a UBI package mirror, so building on a connected machine and moving the image (section 3) is simpler.
- **Behind a TLS-inspecting proxy:** put the proxy's CA in `keycloak-cac/certs/build-trust/` and pass `--build-arg HTTPS_PROXY=...`.
- **Rebuild when DISA publishes a new bundle:** `--build-arg PKI_REFRESH=$(date +%F)` forces a fresh download.

## 3. Push to a registry

In every case: tag, log in, push. The image name used below is `keycloak-cac:26.8.2`.

**Azure Container Registry** (Azure Government: the registry ends in `.azurecr.us`):
```bash
az login && az acr login --name myregistry
docker tag keycloak-cac:26.8.2 myregistry.azurecr.io/iam/keycloak-cac:26.8.2
docker push myregistry.azurecr.io/iam/keycloak-cac:26.8.2
```
Alternatively, build inside Azure with no local Docker: `az acr build -r myregistry -t iam/keycloak-cac:26.8.2 -f keycloak-cac/Containerfile .`

**AWS ECR** (GovCloud: `us-gov-west-1`, with ARNs under `arn:aws-us-gov`):
```bash
aws ecr create-repository --repository-name iam/keycloak-cac
aws ecr get-login-password --region us-gov-west-1 | docker login --username AWS --password-stdin 111122223333.dkr.ecr.us-gov-west-1.amazonaws.com
docker tag keycloak-cac:26.8.2 111122223333.dkr.ecr.us-gov-west-1.amazonaws.com/iam/keycloak-cac:26.8.2
docker push 111122223333.dkr.ecr.us-gov-west-1.amazonaws.com/iam/keycloak-cac:26.8.2
```

**GitHub Container Registry:**
```bash
echo "$GITHUB_TOKEN" | docker login ghcr.io -u <github-user> --password-stdin   # token with write:packages
docker tag keycloak-cac:26.8.2 ghcr.io/<owner>/keycloak-cac:26.8.2 && docker push ghcr.io/<owner>/keycloak-cac:26.8.2
```
Packages start out private. Keep this one private.

**Built by CI:** `.github/workflows/keycloak-cac-image.yml` builds the standard and strict-FIPS images on every pull
request, and on `main` pushes them to `ghcr.io/<owner>/keycloak-cac` (`26.8.2`, `26.8.2-fips`, `sha-<commit>[-fips]`)
with an SPDX SBOM and SLSA provenance attached in the registry, plus a syft SBOM as a job artifact. The job summary
prints the digest: deploy `ghcr.io/<owner>/keycloak-cac@sha256:...`, never a tag. A host pulls it with a token that
has `read:packages` only.

**Google Artifact Registry:**
```bash
gcloud auth configure-docker us-east4-docker.pkg.dev
docker tag keycloak-cac:26.8.2 us-east4-docker.pkg.dev/<project>/iam/keycloak-cac:26.8.2 && docker push us-east4-docker.pkg.dev/<project>/iam/keycloak-cac:26.8.2
```

**Harbor, Nexus, Artifactory, or a self-hosted registry:** `docker login registry.example.mil`, then tag and push. With Podman, use `podman login`/`podman push`, which take the same arguments.

**Air-gapped / sneakernet:**
```bash
docker save keycloak-cac:26.8.2 | gzip > keycloak-cac-26.8.2.tar.gz      # connected side
docker load < keycloak-cac-26.8.2.tar.gz                                  # disconnected side (podman load works too)
```

**SBOM and signature** (recommended for ATO evidence):
```bash
syft <registry>/iam/keycloak-cac:26.8.2 -o spdx-json > keycloak-cac.spdx.json
cosign sign --key cosign.key --tlog-upload=false <registry>/iam/keycloak-cac@<digest>
```
`--tlog-upload=false` keeps the signature out of the public Rekor log.

## 4. Docker

**Lab (no card needed):**
```bash
docker compose -f keycloak-cac/deploy/compose/compose.lab.yaml up -d
```
Mock cards: `docker compose -f keycloak-cac/deploy/compose/compose.lab.yaml cp keycloak:/opt/keycloak/data/cac/lab/users ./lab-cards`. To also use a real card, add an override file with `CAC_LAB_TRUST_DOD: "true"` and `CAC_USERS: "your.name=<UPN>"` (see the README). Tested, including with a live DoD CAC on Docker Desktop for Mac.

**Single host, production shape:**
```bash
cd keycloak-cac/deploy/compose
cp keycloak-cac.env.example keycloak-cac.env        # edit: CAC_PUBLIC_URL, KC_DB_URL, CAC_ADMINS, CAC_USERS...
mkdir -p tls secrets clients                        # tls/tls.crt + tls.key; secrets/ (section 1); clients/<app>.json
docker compose up -d                                # HA on one host: docker compose up -d --scale keycloak=2
docker compose -f compose.yaml -f compose.airgap.yaml up -d   # air-gapped: CRLs from ./crl
```
Tested: two replicas at once, plus the air-gapped variant.

**Plain `docker run`** (equivalent):
```bash
docker run -d --name keycloak-cac --restart unless-stopped -p 443:8443 --read-only --tmpfs /tmp \
  -v kc-data:/opt/keycloak/data -v $PWD/tls:/tls:ro -v $PWD/clients:/clients:ro \
  -v $PWD/secrets/db_password:/run/secrets/db_password:ro -v $PWD/secrets/automation_secret:/run/secrets/automation_secret:ro \
  -v $PWD/secrets/bootstrap_admin_password:/run/secrets/bootstrap_admin_password:ro \
  -e CAC_PUBLIC_URL=https://sso.example.mil -e CAC_ADMINS=smith.alex.adm=3456789012.alt@mil \
  -e KC_HTTPS_CERTIFICATE_FILE=/tls/tls.crt -e KC_HTTPS_CERTIFICATE_KEY_FILE=/tls/tls.key \
  -e KC_DB_URL='jdbc:postgresql://db.example.mil/keycloak?sslmode=verify-full' -e KC_DB_USERNAME=keycloak \
  -e KC_DB_PASSWORD_FILE=/run/secrets/db_password -e KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD_FILE=/run/secrets/bootstrap_admin_password \
  -e CAC_AUTOMATION_SECRET_FILE=/run/secrets/automation_secret -e CAC_CLIENTS_DIR=/clients \
  myregistry.azurecr.io/iam/keycloak-cac:26.8.2
```

## 5. Podman

Compose files work as they are: `podman compose -f ... up -d` (Podman 4.7 or later, or `podman-compose`).

Podman-specific notes:
- **Rootless and port 443:** publish `8443:8443` and point the load balancer at it, or allow low ports (`sysctl net.ipv4.ip_unprivileged_port_start=443`).
- **SELinux hosts** (RHEL): add `:Z` to bind mounts, for example `-v ./tls:/tls:ro,Z`.
- **Podman secrets** instead of files:
  ```bash
  podman secret create kc_db_password secrets/db_password
  podman secret create kc_automation secrets/automation_secret
  podman run -d --name keycloak-cac -p 8443:8443 --read-only --tmpfs /tmp -v kc-data:/opt/keycloak/data \
    --secret kc_db_password,target=/run/secrets/db_password --secret kc_automation,target=/run/secrets/automation_secret \
    ...same -e flags as the docker run above... registry.example.mil/iam/keycloak-cac:26.8.2
  ```
- **systemd with Quadlet** (start at boot, restart on failure): save the following as `/etc/containers/systemd/keycloak-cac.container`, then run `systemctl daemon-reload && systemctl start keycloak-cac`.
  ```ini
  [Container]
  Image=registry.example.mil/iam/keycloak-cac:26.8.2
  PublishPort=443:8443
  ReadOnly=true
  Tmpfs=/tmp
  Volume=kc-data:/opt/keycloak/data
  Volume=/etc/keycloak-cac/tls:/tls:ro,Z
  Volume=/etc/keycloak-cac/clients:/clients:ro,Z
  Secret=kc_db_password,target=/run/secrets/db_password
  Secret=kc_bootstrap,target=/run/secrets/bootstrap_admin_password
  Secret=kc_automation,target=/run/secrets/automation_secret
  EnvironmentFile=/etc/keycloak-cac/keycloak-cac.env
  Environment=KC_HTTPS_CERTIFICATE_FILE=/tls/tls.crt KC_HTTPS_CERTIFICATE_KEY_FILE=/tls/tls.key CAC_CLIENTS_DIR=/clients
  Environment=KC_DB_PASSWORD_FILE=/run/secrets/db_password KC_BOOTSTRAP_ADMIN_PASSWORD_FILE=/run/secrets/bootstrap_admin_password
  Environment=CAC_AUTOMATION_SECRET_FILE=/run/secrets/automation_secret
  HealthCmd=/opt/keycloak-cac/bin/cac-entrypoint.sh health
  [Service]
  Restart=always
  [Install]
  WantedBy=multi-user.target
  ```
- **Kubernetes YAML on Podman:** `helm template ... > app.yaml && podman kube play app.yaml`. Tested: the chart's pod spec passed 13/13.

Podman's health checks run on systemd timers, so on a host without systemd they never fire. This has no effect on how the container works.

## 6. Kubernetes (kubectl)

```bash
kubectl create namespace iam
kubectl label namespace iam pod-security.kubernetes.io/enforce=restricted
kubectl -n iam create secret tls keycloak-cac-tls --cert=tls.crt --key=tls.key
kubectl -n iam create secret generic keycloak-cac-db --from-file=password=secrets/db_password
kubectl -n iam create secret generic keycloak-cac-bootstrap --from-file=password=secrets/bootstrap_admin_password
kubectl -n iam create secret generic keycloak-cac-automation --from-file=secret=secrets/automation_secret
```

**Online cluster:** render the chart once and apply the result, which gives you plain manifests you can commit:
```bash
helm template iam keycloak-cac/deploy/helm/keycloak-cac -f my-values.yaml > keycloak-cac.yaml
kubectl -n iam apply -f keycloak-cac.yaml
```
**Air-gapped cluster:** `keycloak-cac/deploy/k8s/keycloak-cac-airgap.yaml` is already rendered, with CRLs from the `dod-crls` PVC. Edit the lines marked `EDIT`, then `kubectl -n iam apply -f ...`.

The Service is `type: LoadBalancer`, an L4 load balancer that passes TLS through, which is what CAC needs. On bare metal, use MetalLB or a NodePort behind an L4 load balancer. Don't put an Ingress that terminates TLS in front of it.

Tested: the manifests passed server-side dry-runs with Pod Security `restricted`, and ran under `podman kube play`. Not tested here on a full cluster.

## 7. Helm

```bash
cat > my-values.yaml <<'EOF'
image: {repository: myregistry.azurecr.io/iam/keycloak-cac, tag: "26.8.2"}
publicUrl: https://sso.example.mil
realm: dod-cac
admins: "smith.alex.adm=3456789012.alt@mil"
users: "doe.john=1234567890123456@mil"
db: {url: "jdbc:postgresql://pg.iam.svc:5432/keycloak?sslmode=verify-full", username: keycloak}
clients:
  payroll: {client_id: payroll, type: oidc-public, redirect_uris: ["https://payroll.example.mil/cb"],
            post_logout_redirect_uris: ["https://payroll.example.mil/"]}
EOF
helm install iam keycloak-cac/deploy/helm/keycloak-cac -n iam -f my-values.yaml         # secrets: section 6
helm upgrade iam keycloak-cac/deploy/helm/keycloak-cac -n iam -f my-values.yaml         # new app, image, settings
```

- **Air-gapped:** add `-f keycloak-cac/deploy/helm/keycloak-cac/values-airgap.yaml` and point `crl.volume` at your CRL volume.
- **More apps:** add entries under `clients:` and run `helm upgrade`. The pods restart and register the new clients.
- **Extra CAs** (ECA, partners): use `extraAnchors:`.
- **Any other profile field:** use `profileOverlay:`.

## 8. OpenShift

Use the Helm chart, or the rendered manifest, with these changes:
- **Security context:** OpenShift's `restricted-v2` SCC assigns its own UID, so set `podSecurityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}`. The image runs under any UID in group 0. Tested here with a random UID, a read-only root and a tmpfs data directory.
- **TLS passthrough route** (instead of the LoadBalancer):
  ```bash
  oc -n iam create route passthrough keycloak-cac --service=iam-keycloak-cac --hostname=sso.apps.example.mil --port=https
  ```
  Set `service.type: ClusterIP`.

Not tested on a real OpenShift cluster.

## 9. Azure

**AKS** (Azure Kubernetes Service):
```bash
az aks update -g rg-iam -n aks-iam --attach-acr myregistry           # let AKS pull from ACR
```
Then follow sections 6 and 7. The `LoadBalancer` Service gets an Azure Standard Load Balancer, which is L4 passthrough and fine for CAC. Add the annotation `service.beta.kubernetes.io/azure-load-balancer-internal: "true"` for an internal-only address.
- **Database:** Azure Database for PostgreSQL – Flexible Server. Download its root CA, mount it, and use `?sslmode=verify-full&sslrootcert=/path/ca.pem`.
- **Secrets:** Azure Key Vault through the Secrets Store CSI driver. Mount the secrets as files and point the `*_FILE` variables at them.
- **Application Gateway / Front Door:** both terminate TLS (they're L7). CAC through them needs their mutual-TLS feature plus a matching `X509_LOOKUP` build. That combination is untested, so prefer the L4 load balancer.

**Azure Container Instances** (one container, public IP, TCP straight through):
```bash
az container create -g rg-iam -n keycloak-cac --image myregistry.azurecr.io/iam/keycloak-cac:26.8.2 \
  --registry-login-server myregistry.azurecr.io --registry-username <user> --registry-password <pw> \
  --cpu 2 --memory 8 --ports 8443 --ip-address Public --dns-name-label sso-example \
  --environment-variables CAC_PUBLIC_URL=https://sso-example.<region>.azurecontainer.io:8443 KC_DB_URL='jdbc:postgresql://...' KC_DB_USERNAME=keycloak KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap \
  --secure-environment-variables KC_DB_PASSWORD=... KC_BOOTSTRAP_ADMIN_PASSWORD=... CAC_AUTOMATION_SECRET=... CAC_TLS_CERT_PEM="$(cat tls.crt)" CAC_TLS_KEY_PEM="$(cat tls.key)"
```
ACI can't mount secrets as individual files, so the certificate goes in env vars (`CAC_TLS_*_PEM`, the same pattern as the tested ECS run).

**Azure Container Apps:** its HTTP ingress terminates TLS. TCP ingress, which CAC needs, requires an environment with a custom VNet: set ingress to `tcp`, target port 8443, exposed port 443. Not tested.

## 10. AWS

**ECS / Fargate:** `keycloak-cac/deploy/ecs/task-definition.json` (2 vCPU, 8 GiB, read-only root, secrets from Secrets Manager and SSM).
```bash
aws ecs register-task-definition --cli-input-json file://keycloak-cac/deploy/ecs/task-definition.json
```
Put a **Network Load Balancer** in front, with a TCP listener on 443 forwarding to the target group on TCP 8443. Don't use an ALB, which terminates TLS. Use RDS for PostgreSQL with the RDS CA bundle for `verify-full`. For HA, set the service's desired count to 2 or more; the tasks cluster through the database, and the security group must allow port 7800 between tasks.

Tested: the same env-only shape run locally passed 8/8. Not tested on AWS itself.

**EKS:** sections 6 and 7, plus these Service annotations for an NLB through the AWS Load Balancer Controller:
```yaml
service:
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: external
    service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: ip
    service.beta.kubernetes.io/aws-load-balancer-scheme: internet-facing   # or internal
```

## 11. Google Cloud

**GKE:** sections 6 and 7. A `LoadBalancer` Service gets a passthrough Network Load Balancer by default. Use Cloud SQL for PostgreSQL. Not tested.

**Cloud Run:** its front end terminates TLS and offers no client-certificate passthrough, so it isn't suitable for CAC.

## 12. After deploying

```bash
curl -s https://sso.example.mil/realms/dod-cac/.well-known/openid-configuration | head -c 300   # issuer for your apps
docker logs keycloak-cac 2>&1 | grep keycloak-cac          # or kubectl logs ...: expect "STIG realm applied"
```
- **Readiness:** the `health` probe reports ready only after the realm is applied and the CRLs are loaded.
- **Evidence:** run `kcstig.py verify` against the live URL, from any machine that has the skill:
  ```bash
  KC_CLIENT_ID=stig-automation KC_CLIENT_SECRET_FILE=secrets/automation_secret \
    python3 keycloak-asd-stig/scripts/kcstig.py verify --profile <rendered profile> --live-url https://sso.example.mil --out reports
  ```
  The container writes its rendered profile to `/opt/keycloak/data/cac/profile.json`.
- **First card login:** this is the real check. If it fails, see the README's troubleshooting section.

## 13. Operations

- **New app:** add its client JSON, then restart or roll out. Apps point at `<CAC_PUBLIC_URL>/realms/<CAC_REALM>`.
- **DoD PKI updates:** rebuild the image (`PKI_REFRESH=$(date +%F)`) and roll it out. CRLs refresh themselves (`online`) or come from your CRL volume (`file`).
- **Upgrades:** build on a new `KEYCLOAK_IMAGE` tag, test in lab mode, then roll it out. The realm is re-applied on every start.
- **Rotating the automation secret:**
  1. Set the new secret on the `stig-automation` client in Keycloak (master realm, Clients, stig-automation, Credentials).
  2. Update your secret store.
  3. Restart.

  If you change the secret store first, the container can no longer log in, and it stops (fail secure).
- **Lost admin access:** see `keycloak-asd-stig/references/operations.md` §1.

# Runtime-agnostic deployment (Docker, Podman, Kubernetes, Helm, OpenShift, systemd)

One pattern, the same two images and the same env everywhere:

```
            +-------------------------+     shared volume /pki      +---------------------------+
 pki-init   | kcstig-tools pki-init   | --> truststore/ crl/        | keycloak-stig (Keycloak)  |
 (once)     +-------------------------+     client-ca.p12           |  env-only config (KC_*)   |
 pki-refresh| kcstig-tools pki-refresh| --> (every 6 h, atomic)  -> |  secrets via *_FILE        |
 (sidecar)  +-------------------------+                             +---------------------------+
 apply job  | kcstig-tools apply      | --> Admin REST (idempotent, service account / bootstrap fallback)
 verify cron| kcstig-tools verify     | --> report + .ckl/.cklb, exit 1 on drift (--strict)
```

## Contents
1. Build the images (base image choice, FIPS, edge variant, SBOM, signing)
2. Runtime configuration (env + secret files)
3. PKI volume (init + refresh)
4. Apply / verify jobs
5. Reference deployments: Compose, Helm, podman kube play
6. CAC ingress modes
7. High availability
8. Sizing (measured)
9. What was tested

## 1. Images
```
scripts/build_images.sh --engine docker|podman|buildah --registry REG --tag 26.8.2-stig \
   --base-image <BASE> [--fips] [--x509-lookup nginx] --push --sbom --sign cosign.key
```
- `BASE`: `registry1.dso.mil/ironbank/opensource/keycloak/keycloak:<tag>` (Iron Bank, preferred for DoD ATO),
  `registry.redhat.io/rhbk/keycloak-rhel9:26.x` (Red Hat build of Keycloak, vendor support - V-222658), or upstream
  `quay.io/keycloak/keycloak:26.8.2` (community). Both registries need credentials (docker/podman login).
  The extension jar is compiled against the chosen base image automatically.
- `--fips`: bakes `--features=fips --fips-mode=strict` + bc-fips, bctls-fips, bcutil-fips, **bcpkix-fips**
  (`FIPS_JAR_DIR=<dir>` for air-gapped builds). Run on a FIPS-mode host for a validated configuration.
- `--x509-lookup nginx|haproxy|apache|envoy`: image for edge-verify ingress (build-time Keycloak option); tag gets
  a `-nginx` suffix.
- `--sbom`: SPDX JSON per image (syft). `--sign KEY|keyless`: cosign signature + SBOM attestation. Key-based signing
  does **not** upload to the public Rekor log unless `SIGN_TLOG=true` (image digests of DoD systems should not be
  public). Verify: `cosign verify --key cosign.pub --insecure-ignore-tlog=true <ref>`.
- `dist/keycloak-stig-image.env` lists the runtime defaults baked into the image: keep it next to your deployment
  config so `kcstig.py verify --deploy-dir` sees them.
- Enforce signatures at admission (Kyverno `verifyImages`, Sigstore policy-controller, OpenShift image policy).

## 2. Runtime configuration
`assets/deploy/runtime.env.example` is the complete list. Everything is `KC_*` env; the image entrypoint turns
`KC_<NAME>_FILE=/path` into `KC_<NAME>` for names ending in PASSWORD, SECRET, USERNAME or TOKEN (Docker/Podman
secrets, Kubernetes Secret volumes, Vault agent, systemd credentials). Keycloak's own `*_FILE` options
(`KC_HTTPS_CERTIFICATE_FILE`, `KC_HTTPS_CERTIFICATE_KEY_FILE`, ...) are left alone.
Logs are JSON on stdout by default (any platform collector); add `KC_LOG=console,syslog` for direct syslog.

## 3. PKI volume
`kcstig-tools pki-init` / `pki-refresh` fill `/pki` (mounted in Keycloak at `/opt/keycloak/conf/pki`, read-only):
`truststore/*.pem`, `crl/*.crl`, `client-ca.p12` (DoD-only TLS client-auth trust store, used through
`KC_HTTPS_TRUST_STORE_FILE`) and `ca-subject-dns.txt` (root DNs for `x509.ca_subject_dns`).
- `PKI_SOURCE=dod`: download and verify the official DISA bundle and CRLs (needs dl.dod.cyber.mil, crl.disa.mil).
- `PKI_SOURCE=dir:/seed`: air-gapped. Seed = `truststore/` + `crl/` subfolders, or flat `*.pem|*.crt` + `*.crl`
  (flat works for ConfigMaps/Secrets). CRLs that do not verify against the trust store are refused
  (`STIG-CRL-UNTRUSTED`) - one untrusted CRL in the list makes **every** login fail in Keycloak.
- Refresh writes files atomically (rename) and logs `STIG-CRL-STALE` when a CRL expires within 24 h.
- Per-pod `emptyDir` in Kubernetes: no ReadWriteMany storage needed.
- Profile: `"crl_files": ["pki/crl/DODIDCA_71.crl", ...]` (paths relative to /opt/keycloak/conf).

## 4. Jobs
`kcstig-tools apply --wait 900 --harden-master --remove-bootstrap-admin --automation-secret-file /run/secrets/automation/secret`
- Logs in with the automation service account; on the very first run (account not yet created) it falls back to
  the bootstrap admin. The automation secret comes from your secret manager (`--automation-secret-file`), so no job
  needs permission to write secrets; changing the file rotates the client secret on the next run.
- Per-service clients: every `*.json` in `STIG_CLIENTS_DIR` (`/etc/kcstig/clients.d`) is merged into the profile.
  Services own their client file (ConfigMap); the Helm chart projects `stig.clientConfigMaps` into that directory.
- `kcstig-tools verify --live-url ... --strict` (nightly): non-zero exit on drift; report printed to the log.

## 5. Reference deployments
- **Compose** (`assets/deploy/compose/`): `docker compose up -d` or `podman compose up -d`. Lab overrides in
  `examples/` (edge proxy, two replicas).
- **Helm** (`assets/deploy/helm/keycloak-stig`): Deployment (pki-init init container, pki-refresh sidecar,
  Keycloak), Service, post-install/upgrade apply Job, verify CronJob, NetworkPolicy, PDB, optional ingress-nginx
  Ingress for edge mode. Pod Security `restricted` compliant. Values: `pki.sidecar: container|native|none`
  (native = K8s >= 1.29 init sidecar), `probes.type: http|tcp`, `ingress.mode: passthrough|edge`.
- **podman kube play / Quadlet `.kube`**: render the chart (`helm template ... --set probes.type=tcp`), pass ConfigMaps
  with `--configmap`. Podman limitations met in testing: no projected volumes (use one ConfigMap), no
  `status.podIP` env, no native sidecars, ConfigMap `items.path` cannot create subfolders (use the flat seed),
  HTTP probes run `curl` inside the image (UBI-micro has none - use tcp).

## 6. CAC ingress modes
- **passthrough** (default, simplest): L4 TCP to Keycloak (LoadBalancer/NodePort, ingress-nginx
  `ssl-passthrough`, Gateway API `TLSRoute`, F5 fastL4). Keycloak terminates TLS and reads the CAC itself.
- **edge**: the proxy terminates TLS, verifies the CAC against the DoD anchors and forwards it in a header
  (`assets/deploy/proxy/nginx-edge-verify.conf`, `keycloak-edge-verify.env`, Helm `ingress.mode=edge`). Forward the
  certificate **only when the proxy verified it** (`map $ssl_client_verify ... SUCCESS`); nginx's optional mode
  still has unverified certificates. Keycloak re-validates the chain (trust-proxy-verification=false) and pins the
  DoD roots (`x509.ca_subject_dns`): a deliberately broken proxy that forwarded a rogue certificate was still
  refused. Requires the `-nginx` image variant.

## 7. High availability
Replicas cluster through the database (`KC_CACHE_STACK=jdbc-ping`, baked into the image): no multicast, DNS or
Kubernetes API needed; allow TCP 7800/57800 between replicas (the chart's NetworkPolicy does). Two replicas behind a
round-robin proxy (no sticky sessions) passed the full e2e suite: brute-force counting, session limits, OTP replay
protection and logout are cluster-wide.

## 8. Sizing (measured, Keycloak 26.8.2)
| Scenario | Memory | CAC login |
|---|---|---|
| Idle, test PKI | ~0.6 GiB | 0.03-0.1 s |
| 18 CRLs (DoD ID + derived PIV, ~140 MB, 600k entries/CA), non-FIPS | ~4.9 GiB | first 7.7 s, then 0.14 s |
| same, strict FIPS (BC-FIPS pure Java) | ~3.5-3.9 GiB | first 10-11 s, then **4.3-5.3 s every login** |
Guidance: container limit >= 8 GiB with the full DoD CRL set (Helm default); warm each pod with one CAC login
before adding it to the load balancer; in strict FIPS list only the CRLs of the DoD ID CAs that issue your users'
certificates (latency scales with the total CRL size) and rate-limit logins at the proxy.

## 9. What was tested (this skill's lab, Keycloak 26.8.2)
| Topology | Result |
|---|---|
| Single container, env-only config, DoD-only client trust store | e2e 20/20 |
| Behind nginx edge-verify proxy | e2e 20/20; rogue CA cert refused (also with a deliberately broken proxy) |
| 2 replicas behind round-robin proxy (jdbc-ping) | e2e 20/20, requests split 30/30 |
| Helm-rendered manifests executed with podman kube play (init container, sidecar, Secrets, ConfigMaps, apply Job pod) | e2e 20/20 |
| Helm chart on a real kube-apiserver 1.33.3, Pod Security `restricted` enforce+warn | all objects accepted (server dry-run); privileged control rejected |
| Strict FIPS image (`Fips1402StrictCryptoProvider`, Approved Mode) | e2e 20/20; verify 57 pass / 0 fail / 0 Open findings |
| Upgrade 26.7.5 -> 26.8.2 in place (same DB), apply re-run | e2e 20/20 before and after; workflows preserved; one-time admin-API audience recovery (operations.md 7) |
| Images built with docker and podman; pushed, SBOM, cosign sign + attest + verify | pass |
| oauth2-proxy gateway (see gateway.md) | 6/6 + idle-timeout test |
Not tested here: a full Kubernetes cluster (kind could not start nested containers in the build sandbox), Iron Bank /
RHBK base images (registry credentials), real CAC hardware, FIPS on a FIPS-enabled host kernel, ingress-nginx itself.

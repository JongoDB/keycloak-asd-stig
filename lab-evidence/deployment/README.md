# Deployment test evidence (Keycloak 26.8.2, lab PKI + real DoD PKI bundle/CRLs)

| Topology | e2e (behavioural) | verify |
|---|---|---|
| Env-only container, DoD-only client trust store | 20/20 | - |
| nginx edge-verify proxy (`-nginx` image) | 20/20, rogue-CA cert refused (also through a deliberately broken proxy) | - |
| 2 replicas, round-robin, jdbc-ping | 20/20 (requests 30/30 per node) | - |
| Helm chart manifests run with podman kube play (+ apply Job pod) | 20/20 | helm-manifests-verify-report.md: 56 pass, 1 fail (FIPS, non-FIPS image), 3 manual |
| Helm chart on kube-apiserver 1.33.3, Pod Security restricted | server dry-run: all objects accepted; privileged pod rejected | - |
| Strict FIPS image (Fips1402StrictCryptoProvider) | 20/20 | strict-fips-verify-report.md: 57 pass, 0 fail, **0 Open** |
| oauth2-proxy gateway | 6/6 + idle-timeout enforcement | - |
| Upgrade 26.7.5 -> 26.8.2 in place (same DB), apply re-run | 20/20 before and after | clean (FIPS item expected on non-FIPS image); workflows preserved; one-time admin-API audience recovery |

Measured with the full DoD ID + derived-PIV CRL set (18 files, ~139 MB): 3.5-4.9 GiB memory; CAC login 0.14 s
(non-FIPS, after a 7.7 s first load) vs 4.3-5.3 s every login in strict FIPS.

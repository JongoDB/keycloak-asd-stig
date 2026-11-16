# CAC / PKI design for Keycloak (ASD STIG V-222524/525/550/552/553/584, V-222523 Alt Token)

## How a CAC login works in this profile
1. Keycloak listens on HTTPS with `https-client-auth=request` (**build-time option** in 26.x - it lives in the
   Dockerfile as `KC_HTTPS_CLIENT_AUTH`, not in keycloak.conf). The browser offers the CAC authentication
   certificate; ActivClient/the OS prompts for the PIN (the card itself locks after 3 bad PINs).
2. JSSE builds the path to an anchor in the **TLS client-auth trust store** (`https-trust-store-file` =
   `client-ca.p12`, DoD roots + intermediates only, built by pki-init). Do not rely on `truststore-paths` for this:
   it is merged with the JVM's public CAs (verified). Bad path = handshake refused (rogue-CA test in e2e_check).
3. The `auth-x509-client-username-form` authenticator then:
   - checks validity dates, KeyUsage `digitalSignature`, optional EKU / certificate-policy OIDs, and the trust
     anchor DN pins (`x509.ca_subject_dns` = DoD root DNs; Keycloak compares the **root**, not the issuing CA);
   - checks revocation: **CRL from the local cache** (`x509-cert-auth.crl-relative-path`, files under
     `/opt/keycloak/conf/crl`, `##`-separated) **and** OCSP (AIA URL or `ocsp_responder_uri`). Both run on
     every login; `ocsp-fail-open` is set only when CRL checking is on, so an unreachable responder never
     skips revocation (V-222553). `x509-cert-auth-crl-abort-if-non-updated=true` refuses stale CRLs. With
     `stig-x509-client-username-form` (stig-extensions.jar) the CRL step checks the card against its issuing CA's
     CRL **and the issuing CA against its root's CRL**, and verifies a CRL's signature once per file version, not on
     every login (see "Card login latency" below);
   - extracts the **UPN from SAN otherName** (`1234567890@mil` = EDIPI@mil) and finds the ONE user whose
     admin-only attribute `cac_upn` equals it. Users cannot edit that attribute (user profile permissions
     edit=[admin]), so nobody can map someone else's card to their account (V-222552, V-222522).
     Real-card notes: store the Principal Name exactly as it is on the card. Contractor and newer CACs use
     16 digits (EDIPI + 6-digit suffix, `1234567890123456@mil`), not the 10-digit EDIPI from the CN. A
     mismatch shows as `LOGIN_ERROR error="invalid_user_credentials"` with `username="<card UPN>"`, so read
     the right value there. Real CACs also carry other SAN otherNames (FASC-N, an OCTET STRING) that make
     Keycloak log `Failed to parse subjectAltName ... DEROctetString`. That message is harmless; the UPN still
     resolves (seen on a live DOD ID CA-80 contractor card, Keycloak 26.8.2).
4. The confirmation page shows certificate subject + target account (banner is shown first).

Verified in the lab: valid card -> code; revoked card -> "Certificate revoked or incorrect"; unmapped card ->
"Invalid user"; everyday CAC -> rejected by the admin realm.

## Production PKI
- `scripts/fetch_dod_pki.sh <dir>` downloads the official DISA bundle
  (`unclass-certificates_pkcs7_DoD.zip`), verifies the CMS-signed SHA-256 manifest, writes one PEM per CA to
  `conf/truststore/`, prints each CA's SHA-256 fingerprint (compare DoD Root CA 3/4/5/6 against the values
  published by DISA on first use). Trust is **only what issues login certificates**: the `DOD ID CA-nn` and
  `DOD DERILITY CA-n` CAs (`LOGIN_CAS`; keycloak-cac: `CAC_LOGIN_CAS`) and the roots that issued them. DOD EMAIL and
  DOD SW CA certificates are not login credentials and are not trusted for client authentication. It then downloads
  and signature-verifies the CRL of every trusted issuing CA **and of each root that issued one** (the issuing CA's
  own status; names from the CA certificate's CRL distribution point, e.g. `DODROOTCA6.crl`) and prints the
  `crl_files` profile fragment. Revocation coverage equals trust: `stig-x509-client-username-form` refuses a card when
  its issuer's or its root's CRL is missing, `kcstig verify` fails `pki.crl_coverage` for every uncovered CA, and the
  keycloak-cac image logs `STIG-CRL-COVERAGE-GAP` after each refresh.
- Size (Nov 2026): 17 issuing-CA CRLs + 2 root CRLs, ~145 MB (one CA had 600k entries). Only the card's issuer's CRL
  and its root's are used per login, so login time does not grow with the total. Heap: see deployment.md sizing, and
  schedule `fetch_dod_pki.sh <dir> --crl-only` daily (cron/systemd timer). Keep the previous file if a
  download fails - the script never deletes a cached CRL.
- crl.disa.mil can be unreachable from commercial networks; inside DoD networks it is normally reachable.
  SIPRNet without root access: V-222553 is N/A per its check text.
- Federal PIV from other agencies (V-222557/558): add the Federal Common Policy CA G2 bridge certs to the
  trust store and their CRLs to `crl_files`.
- ECA certificates: add the ECA roots only if non-DoD ECA holders are in scope.

## Certificate policy OIDs (optional hardening)
`x509.certificate_policies` restricts which certificate types are accepted (mode `Any`). Take the OIDs from the
current *X.509 Certificate Policy for the United States Department of Defense* - do not copy lists from blogs.
Typical CAC/PIV authentication policies are in the `2.16.840.1.101.2.1.11.*` arc (e.g. id-US-dod-mediumHardware,
PIV-Auth variants). Wrong OIDs lock everybody out, so test with a real card before enforcing.

## Alt Token for administrators (V-222523, V-222527)
The STIG check has the admin log on with the CAC and confirms they **cannot** do admin work, then with the
Alt Token and confirms they can. This profile implements it with a separate admin realm flow whose X.509
authenticator maps through a different admin-only attribute, `alt_token_upn`. Map only Alt Token UPNs there.
`admin.mfa=webauthn` (password + FIDO2 hardware key) is offered for organisations whose ISSO accepts a
hardware authenticator as the Alt Token; `admin.mfa=otp` is lab-only and is reported as needing review.

## Behind a reverse proxy / load balancer
(Tested: `assets/deploy/proxy/nginx-edge-verify.conf`, image built with `--x509-lookup nginx`; see deployment.md.)
If TLS terminates at nginx/HAProxy/F5, the proxy must request the client cert, validate it against the same
DoD trust store and pass it in a header. Then set in keycloak.conf:
```
proxy-headers=xforwarded
spi-x509cert-lookup--provider=nginx         # or haproxy, apache, envoy
spi-x509cert-lookup--nginx--ssl-client-cert=SSL_CLIENT_CERT
spi-x509cert-lookup--nginx--ssl-cert-chain-prefix=CERT_CHAIN
spi-x509cert-lookup--nginx--certificate-chain-length=10
spi-x509cert-lookup--nginx--trust-proxy-verification=false   # keep false: Keycloak re-validates
```
Strip any client-supplied copy of that header at the proxy, and restrict Keycloak's port to the proxy only.

## Card login latency: only the issuing CA's CRL is checked (stig-extensions)
Keycloak 26.8.2 caches parsed CRLs, but `CertificateValidator.checkRevocationStatusUsingCRL` runs `CRLUtils.check`
on **every** configured CRL on **every** login, and `CRLUtils.check` re-verifies each CRL's signature. In strict
FIPS (BC-FIPS, pure Java) that re-encodes and hashes all ~140 MB of DoD CRLs per login: 5.1-6.1 s on a 2.6 GHz
Xeon (measured: 5.1 s signature checks + 0.4 s `isRevoked` scans), although only the issuing CA's CRL can list the card.

`stig-x509-client-username-form` replaces that one step (`IssuerCrlCheck`), with the same files,
`crl-abort-if-non-updated` and `isRevoked`:
- **What is checked:** the card against the CRL(s) of its issuing CA, and the issuing CA's certificate (the
  truststore certificate whose key verifies the card) against the CRL(s) of its root. Keycloak checks neither the
  intermediate nor uses only the relevant CRLs.
- **Fail closed:** a card is refused when its issuer's or the root's CRL is missing (`STIG-CRL-NO-ISSUER-CRL`),
  unreadable, or rejected. Rejected: delta CRLs, a partitioned or indirect `issuingDistributionPoint`, a scope that
  does not cover the certificate, unsupported critical extensions, a `thisUpdate` more than 5 minutes ahead.
- **Signers:** CRL signatures are verified against **truststore** certificates of the CRL issuer only, never against
  certificates the client presents.
- **Once per file version:** (file key, size, mtime, ctime) and signer key; the check verifies on a throw-away parse,
  so the cached CRL stays lazily parsed and small. Only the CRLs a login needs are verified on the request path.
- **Availability:** an unreadable or rejected CRL of **another** issuer logs `STIG-CRL-UNREADABLE` (at most once a
  minute per file) and does not refuse anyone else's login.
- **Refresh without blocking:** a background job (every 30 s, `-Dstig.crl.prewarm.seconds`, and whenever a login sees
  a changed file) re-reads and verifies changed files and evicts files no realm lists any more. Locks are per file;
  while one file is re-read, logins keep using its previous verified version. `crl-fetch` and `crl-sync` leave
  unchanged files untouched, so an unchanged CRL is never re-verified.

Measured on the same Xeon: about 0.06 s per login for the CRL step. A refreshed file is used by the next login even
before `clear-crl-cache` runs. Everything else (trust, dates, key usage, policy, CA pins, OCSP) is Keycloak's
validator, unchanged. CRL distribution points and http/ldap CRL paths are left to Keycloak's own code.

## Keycloak caches CRLs until their nextUpdate (verified 26.8.2)
Keycloak's CRL storage keeps each loaded CRL until the CRL's own `nextUpdate` (`cacheTime` only extends it),
about 7 days for DoD CRLs. Refreshing the files on disk is therefore not enough: newly revoked cards would still
pass the CRL check until then (OCSP, when reachable, still catches them). After every refresh call
`POST /admin/realms/<realm>/clear-crl-cache` (cluster-wide). The `keycloak-cac` image does this automatically
after each refresh; the v1 `pki-refresh` sidecar does NOT, so with v1 schedule that call yourself (the
automation service account can make it) or rely on OCSP for timely revocation.

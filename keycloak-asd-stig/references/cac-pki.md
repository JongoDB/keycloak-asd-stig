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
     skips revocation (V-222553). `x509-cert-auth-crl-abort-if-non-updated=true` refuses stale CRLs;
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
  published by DISA on first use), downloads and signature-verifies the CRL of every `DOD ID CA-nn` and
  `DOD DERILITY CA-n` (derived PIV) and prints the `crl_files` profile fragment.
- Size: the DoD ID CRLs total ~140 MB (one CA had 600k entries in Nov 2026). Give Keycloak >= 2 GB heap and
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

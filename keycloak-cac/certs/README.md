# Offline trust-anchor drop-in

Put DoD/Federal PKI bundles here to build without network access (they replace the download):

- the DISA zip as downloaded from https://public.cyber.mil/pki-pke/tools-configuration-files/
  (e.g. `unclass-certificates_pkcs7_DoD.zip`; its signed SHA-256 manifest is verified), or
- `*.p7b` / `*.p7c` (PKCS#7, DER or PEM), or `*.pem` / `*.crt` / `*.cer` / `*.der` CA certificates.

Only CA certificates are kept; expired CAs are left out. The result is printed during the build and stored in the
image at `/opt/keycloak-cac/pki/anchors.txt` (subject, SHA-256 fingerprint, expiry): compare the DoD Root CA
fingerprints with the values DISA publishes before first use.

`build-trust/*.crt` is different: the CA of a TLS-inspecting egress proxy, trusted only to DOWNLOAD the bundle
during the build. It is never trusted for CAC logins.

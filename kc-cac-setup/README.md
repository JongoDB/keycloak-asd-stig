# Live CAC test on your own machine

## One command
```
bash kc-cac-setup.sh
```
`kc-cac-setup.sh` is self-contained: it carries the whole `keycloak-asd-stig` toolkit (scripts, theme, prebuilt STIG
extension, Containerfiles, Compose stack). It needs only **bash** and **Docker** (Desktop or Engine with
`docker compose`) or **Podman** (it starts Podman's API socket itself, or uses `podman-compose` if installed).
OpenSSL, Python, the DoD PKI download, PostgreSQL and Keycloak all run in containers.

It asks for your certificate's UPN (`1234567890@mil`). To find it: certificate manager -> your **Authentication**
certificate -> Details -> Subject Alternative Name -> "Principal Name". Copy it exactly: on many cards
(contractors, newer issuance) it is 16 digits (EDIPI + 6-digit suffix, `1234567890123456@mil`), not the 10 digits
at the end of your name. Then it:
1. builds `keycloak-stig` and `kcstig-tools` (first run pulls about 1.5 GB);
2. creates the HTTPS/DB certificates for `localhost` (throw-away lab CA, so expect one browser warning);
3. downloads and verifies the official DoD PKI bundle and the DoD ID CA CRLs (dl.dod.cyber.mil, crl.disa.mil);
4. starts PostgreSQL (TLS), the PKI sidecars and Keycloak, and runs the STIG apply job (CAC-only realm `cactest`,
   your UPN mapped to a test account);
5. runs the STIG verification and the NIST SP 800-53 Rev 5 crosswalk into `~/kc-cac-test/reports`;
6. prints what to do next.

Options: `--upn 1234567890@mil`, `--user name`, `--port 8443`, `--dir PATH`, `--all-cas` (also email and
derived-PIV CA CRLs), `--verify` (re-run the evidence), `--down` (remove everything), `--lab-pki` (self-test with
generated test cards, no CAC needed).

## Log in
Open `https://localhost:8443/realms/cactest/account` (a private window is best). Accept the warning for the lab
server certificate. Pick your CAC **Authentication** certificate, enter your PIN, read the DoD banner and select OK,
then select Continue.

What to try:
- No card: no access (CAC-only realm).
- Idle 15+ minutes, then click: you must log in again.
- Log out: the next visit asks for the card again.
- `https://localhost:8443/admin/` with your everyday CAC: refused (admins need an Alt Token, V-222523).

Your card presents only its public certificate and signs the TLS handshake. The private key never leaves the card,
and nothing is exposed beyond `localhost`.

## If the card is refused
- **No certificate prompt:** run `docker compose -p kccac logs pki-init` in `~/kc-cac-test/stack`. It should list
  the DoD anchors.
- **"Invalid username or password" / "Invalid user":** the UPN you entered does not match the certificate's
  Principal Name. The real one is in the log: `docker compose -p kccac logs keycloak | grep LOGIN_ERROR` shows
  `username="<UPN from the card>"`. Re-run with `bash kc-cac-setup.sh --upn <that value>` (reruns are safe).
- **`Failed to parse subjectAltName ... DEROctetString` in the log:** harmless. DoD CACs carry other SAN
  entries (e.g. FASC-N) that Keycloak's parser skips; the UPN is still read.
- **"Certificate revoked or incorrect":** your issuing DOD ID CA's CRL could not be downloaded or is stale. Check
  `~/kc-cac-test/pki.log`.
- **Slow first login (seconds):** the DoD CRLs are being loaded. Later logins are fast.
- **Diagnose:** `docker compose -p kccac logs keycloak | grep -iE 'x509|certificate' | tail`.

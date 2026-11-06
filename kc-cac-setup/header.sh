#!/usr/bin/env bash
# kc-cac-setup.sh - stand up the ASD STIG-hardened Keycloak on THIS machine and log in with your real CAC.
#
#   bash kc-cac-setup.sh                      # interactive: asks for your certificate's UPN
#   bash kc-cac-setup.sh --upn 1234567890@mil --user doe.john
#   bash kc-cac-setup.sh --verify             # re-run the STIG verification + NIST crosswalk
#   bash kc-cac-setup.sh --down               # stop and delete everything this script created
#   bash kc-cac-setup.sh --ca-bundle corp.pem # network does TLS inspection: trust its CA for the downloads
#
# Needs only: bash + Docker (Desktop or Engine, with "docker compose") or Podman (with "podman compose").
# Everything else (OpenSSL, Python, the DoD PKI download, Keycloak) runs in containers built by this script.
# Network: pulls quay.io/keycloak/keycloak, registry.access.redhat.com/ubi9/python-312, docker.io/library/postgres;
# downloads the DoD PKI bundle from dl.dod.cyber.mil and CRLs from crl.disa.mil.
# Exposure: only https://localhost:<port> on this machine. Your card presents its public certificate and signs the
# TLS handshake; the private key never leaves the card.
set -euo pipefail
# Compatible with macOS /bin/bash 3.2: no empty-array expansion under set -u, no bash 4 features.

DIR="${KC_CAC_DIR:-$HOME/kc-cac-test}"
PORT=8443; UPN=""; USERNAME=""; MODE=up; LAB_PKI=false; CA_FILTER="DOD ID CA"; CA_BUNDLE="${CURL_CA_BUNDLE:-${SSL_CERT_FILE:-}}"
while [ $# -gt 0 ]; do case "$1" in
  --upn) UPN=$2; shift;; --user) USERNAME=$2; shift;; --port) PORT=$2; shift;; --dir) DIR=$2; shift;;
  --all-cas) CA_FILTER="DOD (ID|DERILITY|EMAIL) CA";; --verify) MODE=verify;; --down) MODE=down;;
  --ca-bundle) CA_BUNDLE=$2; shift;;   # TLS-inspecting proxy/firewall: PEM with its CA (plus public roots)
  --lab-pki) LAB_PKI=true;;   # self-test without a card: trust a generated test CA instead of the DoD PKI
  -h|--help) sed -n '2,15p' "$0"; exit 0;; *) echo "unknown option $1 (see --help)"; exit 2;; esac; shift; done

# Never exit silently: report the line and command that failed.
trap 'rc=$?; printf "\n\033[1;31mERROR (exit %s) at line %s: %s\033[0m\nRe-run is safe. Full logs are in %s\n" "$rc" "$LINENO" "$BASH_COMMAND" "$DIR" >&2' ERR
say()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
die()  { printf '\n\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# ---- container engine --------------------------------------------------------------------------
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && ! docker info 2>/dev/null | grep -qi podman; then
  ENGINE=docker; COMPOSE="docker compose"
  $COMPOSE version >/dev/null 2>&1 || die "Docker found but the compose plugin is missing (install docker-compose-plugin / Docker Desktop)."
elif command -v podman >/dev/null 2>&1; then
  ENGINE=podman
  if command -v podman-compose >/dev/null 2>&1; then COMPOSE="podman-compose"
  else
    # 'podman compose' delegates to docker-compose, which talks to the Podman API socket: make sure it runs.
    if [ "$(id -u)" = 0 ]; then SOCK=/run/podman/podman.sock; else SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"; fi
    if [ ! -S "$SOCK" ]; then
      systemctl --user start podman.socket >/dev/null 2>&1 || systemctl start podman.socket >/dev/null 2>&1 || true
      [ -S "$SOCK" ] || { mkdir -p "$(dirname "$SOCK")"; (podman system service --time=0 "unix://$SOCK" >/dev/null 2>&1 &); sleep 3; }
    fi
    [ -S "$SOCK" ] || die "could not start the Podman API socket ($SOCK). Install podman-compose or run: systemctl --user enable --now podman.socket"
    export DOCKER_HOST="unix://$SOCK"; COMPOSE="podman compose"
  fi
  $COMPOSE version >/dev/null 2>&1 || die "'$COMPOSE' is not available. Install podman-compose (pip install podman-compose) or docker-compose."
else die "Docker (running) or Podman is required. Install Docker Desktop / Docker Engine or Podman and retry."; fi
echo "container engine: $ENGINE ($COMPOSE)"
P="$COMPOSE -p kccac"
TOOLS=localhost/kcstig-tools:26.8.2-stig
KCIMG=localhost/keycloak-stig:26.8.2-stig
# Podman (and Docker with client proxy config) copy the host's HTTP(S)_PROXY into containers; keep it for the
# DoD PKI download but never route the stack's own service names through it.
NP="keycloak,db,ocsp,localhost,127.0.0.1,${NO_PROXY:-${no_proxy:-}}"
NOPROXY=(-e "NO_PROXY=$NP" -e "no_proxy=$NP")
tools() { $ENGINE run --rm "${NOPROXY[@]}" --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$DIR:/work" -w /work --entrypoint "$1" "$TOOLS" "${@:2}"; }

if [ "$MODE" = down ]; then
  [ -d "$DIR/stack" ] && (cd "$DIR/stack" && $P down -v --remove-orphans) || true
  echo "Stopped and removed containers/volumes. Delete $DIR to remove the files too."; exit 0
fi

verify() {
  say "STIG verification (configuration + live TLS) and NIST SP 800-53 Rev 5 crosswalk"
  local net; net=$($ENGINE network ls --format '{{.Name}}' | grep -E '^kccac[_-]frontend$' | head -1)
  $ENGINE run --rm "${NOPROXY[@]}" --network "$net" --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$DIR/stack:/stack:ro" -v "$DIR/reports:/reports" \
    -e KC_CACERT=/stack/tls/ca.crt -e KC_CLIENT_ID=stig-automation -e KC_CLIENT_SECRET_FILE=/stack/secrets/automation_secret \
    -e STIG_CLIENTS_DIR=/stack/clients.d --entrypoint sh "$TOOLS" -c \
    "python3 /opt/kcstig/scripts/kcstig.py verify --profile /stack/profile.json --url https://keycloak:8443 --live-url https://keycloak:8443 --deploy-dir /stack --out /reports 2>&1 | grep -v 'WARNING profile'; \
     [ -f /reports/cactest-asd-stig-results.json ] && python3 /opt/kcstig/scripts/kcstig.py crosswalk --results /reports/cactest-asd-stig-results.json --out /reports"
  echo "Reports: $DIR/reports (cactest-asd-stig-report.md, .ckl, .cklb, asd-stig-v6r4-to-nist-800-53r5.md/.csv)"
}
if [ "$MODE" = verify ]; then verify; exit 0; fi

# ---- inputs ------------------------------------------------------------------------------------
if ! $LAB_PKI && [ -z "$UPN" ]; then
  cat <<'EOT'

Your CAC authentication certificate's UPN is needed to map the card to your test account.
Find it in the browser: certificate manager -> your *Authentication* certificate (not "Email Signature")
-> Details -> Subject Alternative Name -> "Principal Name", e.g. 1234567890@mil
(macOS: Keychain Access -> the certificate whose name ends in your EDIPI -> Subject Alternative Name.)
Copy it exactly: on many cards (contractors, newer issuance) it is 16 digits, the EDIPI plus a 6-digit
suffix (1234567890123456@mil), so it is NOT always the 10 digits at the end of your name.
EOT
  read -r -p "UPN (EDIPI@mil): " UPN
fi
$LAB_PKI && UPN="${UPN:-1234567890@mil}"
[[ "$UPN" =~ ^[^[:space:]@]+@[^[:space:]@]+$ ]] || die "That does not look like a UPN (expected something like 1234567890@mil)."
USERNAME="${USERNAME:-cac.$(echo "${UPN%@*}" | tr -cd '0-9a-zA-Z' | cut -c1-20)}"

# ---- unpack toolkit ----------------------------------------------------------------------------
say "Unpacking toolkit into $DIR"
mkdir -p "$DIR"/{reports,stack}
LINE=$(awk '/^__PAYLOAD_BELOW__$/{print NR + 1; exit 0;}' "$0")
tail -n +"$LINE" "$0" | base64 -d 2>/dev/null | tar -xz -C "$DIR" || tail -n +"$LINE" "$0" | base64 -D | tar -xz -C "$DIR"
SK="$DIR/keycloak-asd-stig"
chmod -R u+rwX,go+rX "$DIR"
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = Enforcing ]; then
  chcon -R -t container_file_t "$DIR" 2>/dev/null || echo "SELinux enforcing: if containers cannot read files, run: chcon -R -t container_file_t $DIR"
fi

# ---- images ------------------------------------------------------------------------------------
say "Building images with $ENGINE (first run pulls ~1.5 GB; a few minutes)"
(cd "$DIR" && STIG_PREBUILT_JAR=1 "$SK/scripts/build_images.sh" --engine "$ENGINE" --out "$DIR/dist") >"$DIR/build.log" 2>&1 \
  || { tail -30 "$DIR/build.log"; die "image build failed (full log: $DIR/build.log)"; }
echo "images: $KCIMG  $TOOLS"

# ---- certificates ------------------------------------------------------------------------------
S="$DIR/stack"
cp -r "$SK/assets/deploy/compose/." "$S/"
mkdir -p "$S"/{secrets,tls,db-ca,db-tls,clients.d,pki-seed}
say "Server and database TLS certificates (throw-away lab CA, valid for localhost)"
# Re-runs keep the existing lab CA/server certificate: a running Keycloak keeps serving the old one, and the
# database and realm already trust it.
if [ ! -s "$DIR/labpki/conf/tls/server.crt" ] || [ ! -s "$DIR/labpki/ca/root.crt" ]; then
  rm -rf "$DIR/labpki"
  tools /opt/kcstig/scripts/make_test_pki.sh /work/labpki "localhost,keycloak,db" >"$DIR/certs.log" 2>&1 \
    || { tail -15 "$DIR/certs.log"; die "certificate generation failed (log: $DIR/certs.log)"; }
else echo "reusing the lab certificates from the previous run"; fi
cp "$DIR/labpki/conf/tls/server.crt" "$S/tls/tls.crt"; cp "$DIR/labpki/conf/tls/server.key" "$S/tls/tls.key"
cat "$DIR/labpki/ca/root.crt" "$DIR/labpki/ca/idca.crt" > "$S/tls/ca.crt"; cp "$S/tls/ca.crt" "$S/db-ca/ca.crt"
cp "$DIR/labpki/conf/tls/db.crt" "$S/db-tls/tls.crt"; cp "$DIR/labpki/conf/tls/db.key" "$S/db-tls/tls.key"

if $LAB_PKI; then
  say "LAB MODE: trusting the generated test CA (no real CAC needed)"
  mkdir -p "$S/pki-seed/truststore" "$S/pki-seed/crl"
  cp "$DIR"/labpki/conf/truststore/*.pem "$S/pki-seed/truststore/"; cp "$DIR"/labpki/conf/crl/*.crl "$S/pki-seed/crl/"
  CRLS="[$(cd "$S/pki-seed/crl" && ls *.crl | sed 's|^\(.*\)$|"pki/crl/\1"|' | paste -sd, -)]"
  ROOTS='["CN=TEST DoD Root CA 99,OU=PKI,OU=DoD,O=U.S. Government,C=US"]'
else
  say "Downloading and verifying the official DoD PKI bundle and CRLs ($CA_FILTER)"
  mkdir -p "$S/pki-seed/truststore" "$S/pki-seed/crl"
  CAOPT=()
  if [ -n "$CA_BUNDLE" ]; then
    [ -r "$CA_BUNDLE" ] || die "--ca-bundle $CA_BUNDLE is not readable"
    cp "$CA_BUNDLE" "$DIR/ca-bundle.pem"; chmod 644 "$DIR/ca-bundle.pem"
    CAOPT=(-v "$DIR/ca-bundle.pem:/etc/kcstig-ca.pem:ro" -e CURL_CA_BUNDLE=/etc/kcstig-ca.pem)
  fi
  $ENGINE run --rm "${NOPROXY[@]}" ${CAOPT[@]+"${CAOPT[@]}"} --user "$(id -u):$(id -g)" -e HOME=/tmp -e TS_DIR=/out/truststore -e CRL_DIR=/out/crl -e CRL_PREFIX=pki/crl \
    -e INCLUDE_CAS="$CA_FILTER" -v "$S/pki-seed:/out" --entrypoint /opt/kcstig/scripts/fetch_dod_pki.sh "$TOOLS" /out > "$DIR/pki.log" 2>&1 \
    || { tail -20 "$DIR/pki.log"; grep -q 'certificate' "$DIR/pki.log" && echo "TLS inspection on this network? Re-run with --ca-bundle <your proxy CA PEM>."
         die "DoD PKI download failed (needs dl.dod.cyber.mil and crl.disa.mil; log: $DIR/pki.log)"; }
  grep -E 'integrity|trust store' "$DIR/pki.log" || true
  N=$(ls "$S/pki-seed/crl" | wc -l | tr -d ' ')
  [ "$N" -gt 0 ] || die "no DoD CRLs could be downloaded (crl.disa.mil unreachable?). Log: $DIR/pki.log"
  W=$(grep -c WARN "$DIR/pki.log" || true)
  echo "$N CRLs cached$( [ "${W:-0}" -gt 0 ] && echo " ($W CRLs unavailable - normal for retired CAs; see $DIR/pki.log)")"
  CRLS=$(grep -o '"crl_files": \[.*\]' "$DIR/pki.log" | tail -1 | sed 's/"crl_files": //')
  ROOTS=$(grep -o '"ca_subject_dns": \[[^]]*\]' "$DIR/pki.log" | tail -1 | sed 's/"ca_subject_dns": //')
  [ -n "$ROOTS" ] || ROOTS='["CN=DoD Root CA 3,OU=PKI,OU=DoD,O=U.S. Government,C=US","CN=DoD Root CA 4,OU=PKI,OU=DoD,O=U.S. Government,C=US","CN=DoD Root CA 5,OU=PKI,OU=DoD,O=U.S. Government,C=US","CN=DoD Root CA 6,OU=PKI,OU=DoD,O=U.S. Government,C=US"]'
fi
rm -rf "$S/pki-seed/conf" 2>/dev/null || true

# ---- secrets, runtime env, profile -------------------------------------------------------------
rnd() { $ENGINE run --rm --entrypoint python3 "$TOOLS" -c "import secrets;print(secrets.token_$1($2),end='')"; }
# Re-runs keep existing secrets: the database volume was initialised with them.
[ -s "$S/secrets/db_password" ] || rnd hex 24 > "$S/secrets/db_password"
[ -s "$S/secrets/bootstrap_admin_password" ] || rnd urlsafe 24 > "$S/secrets/bootstrap_admin_password"
[ -s "$S/secrets/automation_secret" ] || rnd hex 32 > "$S/secrets/automation_secret"
if [ -s "$DIR/lab-admin-temporary-password.txt" ]; then ADMIN_PW=$(cat "$DIR/lab-admin-temporary-password.txt"); else ADMIN_PW="Lab-$(rnd urlsafe 18)-9x"; fi
chmod 644 "$S"/secrets/* "$S"/tls/* "$S"/db-tls/* "$S"/db-ca/*
sed -e "s|^KC_HOSTNAME=.*|KC_HOSTNAME=https://localhost:$PORT|" -e "s|^KC_HOSTNAME_ADMIN=.*|KC_HOSTNAME_ADMIN=https://localhost:$PORT|" \
  "$S/runtime.env.example" > "$S/runtime.env"
cp "$DIR/dist/keycloak-stig-image.env" "$S/" 2>/dev/null || true
cat > "$S/profile.json" <<EOF
{
  "keycloak": {"url": "https://keycloak:8443", "admin_realm": "master"},
  "realm": {"name": "cactest", "display_name": "CAC Test"},
  "auth_mode": "cac",
  "x509": {"crl_files": $CRLS, "ca_subject_dns": $ROOTS},
  "users": [{"username": "$USERNAME", "email": "$USERNAME@example.mil", "firstName": "CAC", "lastName": "Tester", "cac_upn": "$UPN"}],
  "admin": {"mfa": "otp", "users": [{"username": "lab.admin", "email": "lab.admin@example.mil", "firstName": "Lab", "lastName": "Admin",
            "temporary_password": "$ADMIN_PW"}]}
}
EOF
cat > "$S/clients.d/cac-demo.json" <<EOF
{"client_id": "cac-demo", "type": "oidc-public", "redirect_uris": ["https://localhost:$PORT/realms/cactest/account/"],
 "post_logout_redirect_uris": ["https://localhost:$PORT/realms/cactest/account/"]}
EOF
echo "$ADMIN_PW" > "$DIR/lab-admin-temporary-password.txt"; chmod 600 "$DIR/lab-admin-temporary-password.txt" 2>/dev/null || true

# ---- start ------------------------------------------------------------------------------------
say "Starting PostgreSQL (TLS), PKI init/refresh, Keycloak and the STIG apply job"
cd "$S"
export KC_PUBLISH=$PORT PKI_SOURCE=dir:/seed KEYCLOAK_IMAGE=$KCIMG TOOLS_IMAGE=$TOOLS
if [ "$ENGINE" = podman ]; then
  # Podman runs healthchecks from systemd timers; without systemd (some VMs/containers) they never fire and
  # compose would wait forever for "healthy". Trigger them ourselves while we wait.
  ( for i in $(seq 1 360); do for c in $(podman ps --filter name=kccac --format '{{.Names}}'); do
      podman healthcheck run "$c" >/dev/null 2>&1 || true; done; sleep 5; done ) & HC_PID=$!
  trap 'kill $HC_PID 2>/dev/null || true' EXIT
fi
$P up -d >/dev/null 2>&1 || { $P up -d; die "compose up failed"; }
printf 'waiting for the apply job '
for i in $(seq 1 180); do
  cid=$($ENGINE ps -a --filter name=kccac --format '{{.Names}}' | grep -E 'kcstig-apply' | head -1)
  st=$([ -n "$cid" ] && $ENGINE inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$cid" 2>/dev/null || true)
  case "$st" in "exited 0") echo " done"; break;; exited*) echo; $P logs kcstig-apply | tail -30; die "apply job failed";; esac
  printf '.'; sleep 5
done
$P logs kcstig-apply 2>/dev/null | grep -E '^.*\| *(== |  (created|flow|client|user|bootstrap|automation))' | sed 's/^[^|]*| //' | head -30

verify || true

cat <<EOT

$(printf '\033[1;32m')Ready.$(printf '\033[0m') Everything runs only on https://localhost:$PORT

1. Insert your CAC, then open (a private/incognito window is best):
     https://localhost:$PORT/realms/cactest/account
2. Accept the warning for the lab server certificate (it is not the DoD PKI).
3. Choose your CAC *Authentication* certificate, enter your PIN, read the DoD banner, select OK,
   then Continue on the "You will be logged in as $USERNAME" page.

Things to try
 - No card / a different card: no access (CAC-only realm).
 - Idle 15+ minutes, then click: you must log in again.  Log out: the next visit asks for the card again.
 - Admin console https://localhost:$PORT/admin/ with your CAC: refused (admins need an Alt Token).
   Lab-only admin login: lab.admin / password in $DIR/lab-admin-temporary-password.txt (forces change + OTP).

Evidence:   $DIR/reports      (re-run: bash $0 --verify)
Logs:       cd $S && $P logs -f keycloak
Tear down:  bash $0 --down
If the card is refused: cd $S && $P logs keycloak | grep -iE 'x509|certificate' | tail
"Invalid username or password" = the UPN does not match. Read the card's real UPN from the log line
  type="LOGIN_ERROR" ... username="<this>"   then: bash $0 --upn <this>
("Failed to parse subjectAltName ... DEROctetString" lines are harmless: other SAN entries such as FASC-N.)
EOT
exit 0
__PAYLOAD_BELOW__

#!/bin/bash
# keycloak-cac entrypoint: one container = DoD CAC/PIV identity provider hardened to the DISA ASD STIG V6R4.
#   1. secrets from *_FILE      2. trust anchors (baked DoD bundle | mounted | lab mock PKI)
#   3. CRLs (online | file | ocsp | none)   4. start Keycloak   5. apply the STIG realm from env (idempotent)
#   6. keep CRLs fresh and tell Keycloak to drop its CRL cache after every refresh
# Everything is configured with environment variables: see /opt/keycloak-cac/README.md or `--help`.
set -euo pipefail
KCB=/opt/keycloak/bin; TOOLS=/opt/keycloak-cac/bin
export CAC_PKI_DIR="${CAC_PKI_DIR:-/opt/keycloak/data/cac}"; D="$CAC_PKI_DIR"
BAKED=/opt/keycloak-cac/pki
log() { echo "keycloak-cac: $*" >&2; }
die() { log "ERROR $*"; exit 1; }
truthy() { case "${1,,}" in 1|true|yes|on) return 0;; *) return 1;; esac; }
[ "${1:-}" = "--help" ] && { sed -n '/<!-- env-start -->/,/<!-- env-end -->/p' /opt/keycloak-cac/README.md | grep -v '^<!--'; exit 0; }
[ "${1:-}" = "health" ] && exec python3 "$TOOLS/cac-health.py"

# ---- 1. secrets: KC_X_FILE / CAC_X_FILE -> KC_X / CAC_X for secret-like names (paths such as
#         KC_HTTPS_CERTIFICATE_FILE are Keycloak options and are left alone)
for var in $(compgen -e | grep -E '^(KC|CAC)_[A-Z0-9_]*(PASSWORD|SECRET|USERNAME|TOKEN)_FILE$' || true); do
  f="${!var}"; [ -r "$f" ] || die "$var points to unreadable $f"
  export "${var%_FILE}"="$(cat "$f")"; unset "$var"
done
LAB=false; truthy "${CAC_LAB_MODE:-false}" && LAB=true
$LAB && log "!!! LAB MODE: mock CAC PKI / relaxed checks allowed. Never use in production. !!!"
mkdir -p "$D"

# ---- database and build-time options
case "${KC_DB:-postgres}" in
  cockroach*) die "KC_DB=${KC_DB}: CockroachDB is not supported by Keycloak 26. Use postgres (or dev-file in lab mode).";;
  dev-file|dev-mem) $LAB || die "KC_DB=${KC_DB} is a development store (no backups, single node). Only with CAC_LAB_MODE=true.";;
esac
OPTIMIZED=--optimized
while IFS='=' read -r k v; do
  [ -n "$k" ] || continue
  [ -n "${!k:-}" ] || export "$k=$v"   # an automatic re-build must reproduce every baked option it is not told to change
  if [ -n "${!k:-}" ] && [ "${!k}" != "$v" ]; then
    log "build-time option $k=${!k} differs from the image ($v): starting with an automatic re-build (slower start;"
    log "  for production build the image with that value instead, see README 'Build arguments')"; OPTIMIZED=""
  fi
done < /opt/keycloak-cac/build-options.env
REL="${KC_HTTP_RELATIVE_PATH:-/}"; REL="${REL%/}"
[ -n "${CAC_PUBLIC_URL:-}" ] && [ -z "${KC_HOSTNAME:-}" ] && export KC_HOSTNAME="$CAC_PUBLIC_URL"
if [ -z "${KC_HOSTNAME:-}" ]; then
  $LAB && export KC_HOSTNAME="https://localhost:${KC_HTTPS_PORT:-8443}${REL}" || die "set CAC_PUBLIC_URL (or KC_HOSTNAME), e.g. https://sso.example.mil"
fi
python3 "$TOOLS/cac-config.py" check

# ---- 2. trust anchors -> $D/anchors (+ client-ca.p12 with ONLY these anchors for TLS client auth)
rm -rf "$D/anchors.new"; mkdir -p "$D/anchors.new"
if [ -n "${CAC_TRUST_ANCHORS_DIR:-}" ]; then
  log "trust anchors: REPLACING the baked DoD bundle with $CAC_TRUST_ANCHORS_DIR"
  "$TOOLS/cac-pki.sh" bundle "$D/src" "$CAC_TRUST_ANCHORS_DIR" && cp "$D/src/anchors/"*.pem "$D/anchors.new/"
elif $LAB && ! truthy "${CAC_LAB_TRUST_DOD:-false}"; then
  if [ ! -f "$D/lab/ca/idca.crt" ]; then
    host=$(echo "$KC_HOSTNAME" | sed -E 's#^https?://##; s#[:/].*$##')
    log "lab: generating the mock CAC PKI (test root, issuing CA, users, revoked + rogue cards) for $host"
    (OCSP_URL=http://127.0.0.1:1/ocsp /opt/kcstig/scripts/make_test_pki.sh "$D/lab" "$host,localhost" >/dev/null)
  fi
  cp "$D/lab/conf/truststore/"*.pem "$D/anchors.new/"
else
  cp "$BAKED/anchors/"*.pem "$D/anchors.new/"
  log "trust anchors: $(ls "$D/anchors.new" | wc -l) from the image ($(cat "$BAKED/source.txt"))"
fi
if $LAB && truthy "${CAC_LAB_TRUST_DOD:-false}" && [ -z "${CAC_TRUST_ANCHORS_DIR:-}" ]; then cp "$BAKED/anchors/"*.pem "$D/anchors.new/"; fi
if [ -n "${CAC_EXTRA_ANCHORS_DIR:-}" ]; then
  "$TOOLS/cac-pki.sh" bundle "$D/extra" "$CAC_EXTRA_ANCHORS_DIR" && cp "$D/extra/anchors/"*.pem "$D/anchors.new/"
  log "trust anchors: added $(ls "$D/extra/anchors" | wc -l) from $CAC_EXTRA_ANCHORS_DIR:"; sed 's/^/  /' "$D/extra/anchors.txt" >&2
fi
rm -rf "$D/anchors"; mv "$D/anchors.new" "$D/anchors"
export PKI_P12_PASSWORD="${CAC_CLIENT_CA_PASSWORD:-cac-anchors}"
"$TOOLS/cac-pki.sh" compile "$D/anchors" "$D"
export KC_TRUSTSTORE_PATHS="$D/anchors" KC_HTTPS_TRUST_STORE_FILE="$D/client-ca.p12" KC_HTTPS_TRUST_STORE_PASSWORD="$PKI_P12_PASSWORD"
log "trust anchors ready: $(ls "$D/anchors" | wc -l) CAs, pinned roots: $(tr '\n' ';' < "$D/ca-subject-dns.txt")"

# ---- server TLS certificate
if [ -n "${CAC_TLS_CERT_PEM:-}" ]; then   # platforms that inject secrets as env only (ECS, some PaaS)
  [ -n "${CAC_TLS_KEY_PEM:-}" ] || die "CAC_TLS_CERT_PEM is set but CAC_TLS_KEY_PEM is not"
  mkdir -p "$D/tls"; ( umask 077; printf '%s\n' "$CAC_TLS_CERT_PEM" > "$D/tls/tls.crt"; printf '%s\n' "$CAC_TLS_KEY_PEM" > "$D/tls/tls.key" )
  unset CAC_TLS_KEY_PEM; export KC_HTTPS_CERTIFICATE_FILE="$D/tls/tls.crt" KC_HTTPS_CERTIFICATE_KEY_FILE="$D/tls/tls.key"
fi
if [ -z "${KC_HTTPS_CERTIFICATE_FILE:-}" ]; then
  $LAB || die "mount the server certificate: KC_HTTPS_CERTIFICATE_FILE and KC_HTTPS_CERTIFICATE_KEY_FILE (PEM, chain included)"
  if [ -f "$D/lab/conf/tls/server.crt" ]; then
    export KC_HTTPS_CERTIFICATE_FILE="$D/lab/conf/tls/server.crt" KC_HTTPS_CERTIFICATE_KEY_FILE="$D/lab/conf/tls/server.key"
  else
    mkdir -p "$D/tls"; [ -f "$D/tls/server.crt" ] || openssl req -x509 -newkey rsa:3072 -nodes -days 30 -sha256 \
      -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" -keyout "$D/tls/server.key" -out "$D/tls/server.crt" 2>/dev/null
    export KC_HTTPS_CERTIFICATE_FILE="$D/tls/server.crt" KC_HTTPS_CERTIFICATE_KEY_FILE="$D/tls/server.key"
  fi
  log "lab: self-issued server certificate $KC_HTTPS_CERTIFICATE_FILE (browsers will warn)"
fi

# ---- 3. revocation data
MODE="${CRL_MODE:-}"; [ -z "$MODE" ] && { $LAB && MODE=file || MODE=online; }
MODE="${MODE,,}"; case "$MODE" in offline|local) MODE=file;; disabled|off) MODE=none;; esac; export CRL_MODE="$MODE"
mkdir -p "$D/crl"
CRL_SRC="${CAC_CRL_DIR:-/crl}"; $LAB && [ -z "${CAC_CRL_DIR:-}" ] && [ -d "$D/lab/conf/crl" ] && CRL_SRC="$D/lab/conf/crl"
crl_refresh() {
  case "$MODE" in
    online) "$TOOLS/cac-pki.sh" crl-fetch "$D/anchors" "$D/crl";;
    file)   "$TOOLS/cac-pki.sh" crl-sync "$CRL_SRC" "$D/anchors" "$D/crl";;
  esac
  "$TOOLS/cac-pki.sh" crl-health "$D/crl" || true
}
case "$MODE" in
  file)   crl_refresh ;;                       # local: fast, needed before the profile is rendered
  online) log "CRLs: downloading $(wc -l < "$D/crl-names.txt") DoD CRLs in the background (CAC logins fail closed until they arrive)";;
  ocsp)   log "WARN CRL_MODE=ocsp: no local CRL cache (V-222553 asks for one); every login depends on the OCSP responder";;
  none)   log "!!! CRL_MODE=none: certificate revocation is NOT checked (lab only) !!!";;
esac

# ---- validate everything before Keycloak starts (fail fast, fail secure)
for f in "$KC_HTTPS_CERTIFICATE_FILE" "$KC_HTTPS_CERTIFICATE_KEY_FILE"; do [ -r "$f" ] || die "cannot read $f"; done
automation_secret() {
  if [ -n "${CAC_AUTOMATION_SECRET:-}" ]; then printf %s "$CAC_AUTOMATION_SECRET"
  elif $LAB; then printf 'cac-lab-automation:%s' "${KC_BOOTSTRAP_ADMIN_PASSWORD:-}" | sha256sum | cut -c1-48
  else return 1; fi
}
if truthy "${CAC_APPLY:-true}"; then
  python3 "$TOOLS/cac-config.py" profile "$D/profile.json" || die "configuration rejected (see above)"
  ( umask 077; automation_secret > "$D/.automation-secret" ) || { rm -f "$D/.automation-secret"
    die "set CAC_AUTOMATION_SECRET[_FILE]: the secret of the admin-API service account that applies the STIG realm (any long random string; keep it the same across restarts)"; }
  [ "$(wc -c < "$D/.automation-secret")" -ge 24 ] || die "CAC_AUTOMATION_SECRET must be at least 24 characters"
fi

export JAVA_OPTS_APPEND="${JAVA_OPTS_APPEND:--Dorg.bouncycastle.native.cpu_variant=java}"
KC_PID=$$   # Keycloak is exec'd below and keeps this PID (PID 1 in a container: signals and graceful shutdown work)

# ---- 5. apply the STIG realm (idempotent; every replica may run it)
apply() {
  python3 "$TOOLS/cac-config.py" wait-ready "${CAC_START_TIMEOUT:-600}"
  local sf="$D/.automation-secret" args=()
  export KC_CLIENT_ID=stig-automation KC_CLIENT_SECRET="$(cat "$sf")" KC_ADMIN_USER="${KC_BOOTSTRAP_ADMIN_USERNAME:-}" \
         KC_ADMIN_PASSWORD="${KC_BOOTSTRAP_ADMIN_PASSWORD:-}" KCSTIG_LOOPBACK_NOVERIFY=1 STIG_CLIENTS_DIR="${CAC_CLIENTS_DIR:-}"
  if python3 -c "import json,sys; sys.exit(0 if json.load(open('$D/profile.json'))['admin']['users'] else 1)"; then
    args=(--harden-master --remove-bootstrap-admin --automation-secret-file "$sf")
  else
    log "WARN no CAC_ADMINS: the admin realm is NOT hardened (no Alt Token admins) and the bootstrap admin is kept."
  fi
  local i
  for i in 1 2 3; do
    if python3 /opt/kcstig/scripts/kcstig.py apply --profile "$D/profile.json" ${args[@]+"${args[@]}"} --secret-out /dev/null; then
      date -u +%FT%TZ > "$D/.applied"; log "STIG realm applied: ${KC_HOSTNAME}/realms/$(python3 -c "import json;print(json.load(open('$D/profile.json'))['realm']['name'])")"; return 0; fi
    log "apply attempt $i failed; retrying"; sleep $((RANDOM % 10 + 5))
  done
  return 1
}
crl_loop() {
  [ "$MODE" = online ] && { crl_refresh; python3 "$TOOLS/cac-config.py" clear-crl-cache || true; touch "$D/.crl-loaded"; }
  [ "$MODE" != online ] && touch "$D/.crl-loaded"
  [ "$MODE" = online ] || [ "$MODE" = file ] || return 0
  while sleep "${CAC_CRL_REFRESH_SECONDS:-21600}"; do
    crl_refresh || log "WARN CRL refresh failed; keeping cached CRLs"
    python3 "$TOOLS/cac-config.py" clear-crl-cache || log "WARN could not clear Keycloak's CRL cache"
  done
}
# ---- 5./6. worker: apply the realm once Keycloak is ready, then keep revocation data fresh
rm -f "$D/.applied" "$D/.crl-loaded"
if truthy "${CAC_APPLY:-true}"; then
  ( if apply; then crl_loop; else log "ERROR STIG apply failed: stopping (fail secure)"; kill -TERM $KC_PID; fi ) </dev/null &
else
  log "CAC_APPLY=false: realm configuration left as it is"; date -u +%FT%TZ > "$D/.applied"; ( crl_loop ) </dev/null &
fi

# ---- 4. Keycloak
exec "$KCB/kc.sh" start $OPTIMIZED

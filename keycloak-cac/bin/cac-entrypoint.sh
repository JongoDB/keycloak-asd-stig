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
# ---- edge mode: an image built with X509_LOOKUP=nginx|haproxy|apache|envoy takes the client certificate from a
#      request HEADER. Network isolation alone is not enough (a shared ingress controller lets any tenant's Ingress
#      set that header), so the proxy must authenticate itself with a TLS client certificate issued by
#      CAC_EDGE_PROXY_CA_FILE: Keycloak's listener then requires one (KC_HTTPS_CLIENT_AUTH=required, baked into
#      edge builds) and trusts that CA ONLY for the TLS hop. Cards are still validated against the DoD anchors.
#      The CA must be DEDICATED: it issues the proxy's client certificate and nothing else, because every
#      certificate it issues can speak for any card. CAC_EDGE_PROXY_CERT_FILE pins the proxy's own certificate
#      instead (the trust store then holds exactly that certificate: nothing else from any CA is accepted).
LOOKUP="${KC_SPI_X509CERT_LOOKUP__PROVIDER:-default}"
if [ "$LOOKUP" != default ]; then
  [ "${KC_HTTPS_CLIENT_AUTH:-}" = required ] || die "X509_LOOKUP=$LOOKUP needs an image built with KC_HTTPS_CLIENT_AUTH=required (rebuild with this Containerfile)"
  [ -n "${CAC_EDGE_PROXY_CA_FILE:-}${CAC_EDGE_PROXY_CERT_FILE:-}" ] || die "this image reads the client certificate from a header (X509_LOOKUP=$LOOKUP): set CAC_EDGE_PROXY_CA_FILE to the CA that issued the verifying proxy's TLS client certificate. Keycloak then accepts connections from that proxy only. Use a proxy dedicated to Keycloak that overwrites the header on every request. Without a proxy, use the default (passthrough) image."
  for v in CAC_EDGE_PROXY_CA_FILE CAC_EDGE_PROXY_CERT_FILE; do
    [ -z "${!v:-}" ] || [ -r "${!v}" ] || die "$v=${!v} is not readable"; done
elif [ -n "${CAC_EDGE_PROXY_CA_FILE:-}${CAC_EDGE_PROXY_CERT_FILE:-}" ]; then
  log "WARN CAC_EDGE_PROXY_CA_FILE/CAC_EDGE_PROXY_CERT_FILE have no effect: this image reads the card from its own TLS handshake (passthrough)"
fi
# ---- network path allowlist (stig-extensions PublicPathAllowlistFilter): both variables or neither. A half
#      configuration, or the retired STIG_ADMIN_REALM_ALLOWED_SOURCES alone, would silently leave the filter off.
# >>> allowlist-config
if [ -n "${STIG_ADMIN_REALM_ALLOWED_SOURCES:-}" ] && { [ -z "${STIG_PUBLIC_PATHS:-}" ] || [ -z "${STIG_TRUSTED_SOURCES:-}" ]; }; then
  die "STIG_ADMIN_REALM_ALLOWED_SOURCES was replaced: set STIG_TRUSTED_SOURCES (the same addresses) and STIG_PUBLIC_PATHS (the paths network clients may use, e.g. /realms/<realm>,/realms/<realm>/,/admin/<realm>/,/admin/realms/<realm>/,/admin/serverinfo,/resources/). Without them the admin realm would be reachable from the network."
fi
if [ -n "${STIG_PUBLIC_PATHS:-}" ] && [ -z "${STIG_TRUSTED_SOURCES:-}" ]; then
  die "STIG_PUBLIC_PATHS is set but STIG_TRUSTED_SOURCES is not: the allowlist filter needs both (it would stay off)"
fi
if [ -z "${STIG_PUBLIC_PATHS:-}" ] && [ -n "${STIG_TRUSTED_SOURCES:-}" ]; then
  die "STIG_TRUSTED_SOURCES is set but STIG_PUBLIC_PATHS is not: the allowlist filter needs both (it would stay off)"
fi
# <<< allowlist-config
REL="${KC_HTTP_RELATIVE_PATH:-/}"; REL="${REL%/}"
[ -n "${CAC_PUBLIC_URL:-}" ] && [ -z "${KC_HOSTNAME:-}" ] && export KC_HOSTNAME="$CAC_PUBLIC_URL"
if [ -z "${KC_HOSTNAME:-}" ]; then
  $LAB && export KC_HOSTNAME="https://localhost:${KC_HTTPS_PORT:-8443}${REL}" || die "set CAC_PUBLIC_URL (or KC_HOSTNAME), e.g. https://sso.example.mil"
fi
python3 "$TOOLS/cac-config.py" check

# The baked DoD bundle holds every DoD CA; only the issuers of login certificates (CAC_LOGIN_CAS, default DOD ID and
# DERILITY CAs) and their roots are trusted for card login. Explicit CAC_TRUST_ANCHORS_DIR / CAC_EXTRA_ANCHORS_DIR are not narrowed.
baked_login_anchors() { # dest-dir
  rm -rf "$D/anchors.baked"; mkdir -p "$D/anchors.baked"; cp "$BAKED/anchors/"*.pem "$D/anchors.baked/"
  "$TOOLS/cac-pki.sh" narrow "$D/anchors.baked" && cp "$D/anchors.baked/"*.pem "$1/"; rm -rf "$D/anchors.baked"
}
# ---- 2. trust anchors -> $D/anchors (+ client-ca.p12 with ONLY these anchors for TLS client auth)
rm -rf "$D/anchors.new"; mkdir -p "$D/anchors.new"
if [ -n "${CAC_TRUST_ANCHORS_DIR:-}" ]; then
  log "trust anchors: REPLACING the baked DoD bundle with $CAC_TRUST_ANCHORS_DIR"
  "$TOOLS/cac-pki.sh" bundle "$D/src" "$CAC_TRUST_ANCHORS_DIR" && cp "$D/src/anchors/"*.pem "$D/anchors.new/"
elif $LAB; then
  if [ ! -f "$D/lab/ca/idca.crt" ]; then
    host=$(echo "$KC_HOSTNAME" | sed -E 's#^https?://##; s#[:/].*$##')
    log "lab: generating the mock CAC PKI (test root, issuing CA, users, revoked + rogue cards) for $host"
    (OCSP_URL=http://127.0.0.1:1/ocsp /opt/kcstig/scripts/make_test_pki.sh "$D/lab" "$host,localhost" >/dev/null)
  fi
  cp "$D/lab/conf/truststore/"*.pem "$D/anchors.new/"
else
  baked_login_anchors "$D/anchors.new"
  log "trust anchors: $(ls "$D/anchors.new" | wc -l) from the image ($(cat "$BAKED/source.txt")), login CAs only"
fi
if $LAB && truthy "${CAC_LAB_TRUST_DOD:-false}" && [ -z "${CAC_TRUST_ANCHORS_DIR:-}" ]; then baked_login_anchors "$D/anchors.new"; fi
if [ -n "${CAC_EXTRA_ANCHORS_DIR:-}" ]; then
  "$TOOLS/cac-pki.sh" bundle "$D/extra" "$CAC_EXTRA_ANCHORS_DIR" && cp "$D/extra/anchors/"*.pem "$D/anchors.new/"
  log "trust anchors: added $(ls "$D/extra/anchors" | wc -l) from $CAC_EXTRA_ANCHORS_DIR:"; sed 's/^/  /' "$D/extra/anchors.txt" >&2
fi
rm -rf "$D/anchors"; mv "$D/anchors.new" "$D/anchors"
export PKI_P12_PASSWORD="${CAC_CLIENT_CA_PASSWORD:-cac-anchors}"
"$TOOLS/cac-pki.sh" compile "$D/anchors" "$D"
export KC_TRUSTSTORE_PATHS="$D/anchors" KC_HTTPS_TRUST_STORE_FILE="$D/client-ca.p12" KC_HTTPS_TRUST_STORE_PASSWORD="$PKI_P12_PASSWORD"
log "trust anchors ready: $(ls "$D/anchors" | wc -l) CAs, pinned roots: $(tr '\n' ';' < "$D/ca-subject-dns.txt")"

# ---- edge mode: the TLS listener trusts the proxy's CA and a per-start loopback CA (for this container's own admin
#      calls), nothing else. The loopback CA's key never leaves the container's data directory and changes each start.
if [ "$LOOKUP" != default ]; then
  E="$D/edge"; rm -rf "$E"; mkdir -p "$E/trust"; chmod 700 "$E"
  if [ -n "${CAC_EDGE_PROXY_CERT_FILE:-}" ]; then   # pin: exactly the proxy's certificate is a trust anchor
    openssl x509 -in "$CAC_EDGE_PROXY_CERT_FILE" -noout >/dev/null 2>&1 || die "CAC_EDGE_PROXY_CERT_FILE is not a PEM certificate"
    cp "$CAC_EDGE_PROXY_CERT_FILE" "$E/trust/proxy-ca.pem"
    [ -z "${CAC_EDGE_PROXY_CA_FILE:-}" ] || log "WARN both set: CAC_EDGE_PROXY_CERT_FILE (pin) wins; CAC_EDGE_PROXY_CA_FILE is ignored"
  else
    openssl x509 -in "$CAC_EDGE_PROXY_CA_FILE" -noout -ext basicConstraints 2>/dev/null | grep -q 'CA:TRUE' \
      || die "CAC_EDGE_PROXY_CA_FILE must be a CA certificate (basicConstraints CA:TRUE)"
    cp "$CAC_EDGE_PROXY_CA_FILE" "$E/trust/proxy-ca.pem"
  fi
  ( umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -sha256 -subj "/CN=keycloak-cac loopback CA" \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -keyout "$E/loopback-ca.key" -out "$E/trust/loopback-ca.pem" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=keycloak-cac loopback" -keyout "$E/loopback.key" -out "$E/loopback.csr" 2>/dev/null
    printf 'extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n' > "$E/ext.cnf"
    openssl x509 -req -in "$E/loopback.csr" -CA "$E/trust/loopback-ca.pem" -CAkey "$E/loopback-ca.key" -CAcreateserial -days 30 -sha256 \
      -extfile "$E/ext.cnf" -out "$E/loopback.crt" 2>/dev/null
    rm -f "$E/loopback-ca.key" "$E/loopback.csr" "$E/ext.cnf" ) || die "could not create the loopback client certificate"
  "$TOOLS/cac-pki.sh" compile "$E/trust" "$E"
  export KC_HTTPS_TRUST_STORE_FILE="$E/client-ca.p12" KCSTIG_CLIENT_CERT="$E/loopback.crt" KCSTIG_CLIENT_KEY="$E/loopback.key"
  log "edge mode: listener requires the proxy's client certificate ($([ -n "${CAC_EDGE_PROXY_CERT_FILE:-}" ] && echo "pinned" || echo "from CA") $(openssl x509 -in "$E/trust/proxy-ca.pem" -noout -subject -nameopt RFC2253), sha256 $(openssl x509 -in "$E/trust/proxy-ca.pem" -noout -fingerprint -sha256 | cut -d= -f2)); card header via $LOOKUP"
fi

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

# ---- strict FIPS: Keycloak accepts only BCFKS key/trust stores (no PEM, no PKCS#12) -> convert with BC-FIPS
if [ "${KC_FIPS_MODE:-}" = strict ]; then
  # BC-FIPS approved mode rejects passwords under 112 bits (14 characters), e.g. for the database SCRAM login
  for v in KC_DB_PASSWORD KC_BOOTSTRAP_ADMIN_PASSWORD; do
    val="${!v:-}"; if [ -n "$val" ] && [ "${#val}" -lt 14 ]; then die "strict FIPS: $v must be at least 14 characters (112 bits)"; fi
  done
  BCJAR=$(ls /opt/keycloak/providers/bc-fips-*.jar 2>/dev/null | head -1); [ -n "$BCJAR" ] || die "strict FIPS but no bc-fips jar in the image"
  to_bcfks() { # src.p12 srcpass dst.bcfks dstpass [key-alias: the key gets the store password, as Keycloak expects]
    local k=(); [ -n "${5:-}" ] && k=(-srcalias "$5" -destalias "$5" -srckeypass "$2" -destkeypass "$4")
    rm -f "$3"; keytool -importkeystore -noprompt -srckeystore "$1" -srcstoretype PKCS12 -srcstorepass "$2" \
      -destkeystore "$3" -deststoretype BCFKS -deststorepass "$4" ${k[@]+"${k[@]}"} -providername BCFIPS \
      -J-Dorg.bouncycastle.native.cpu_variant=java \
      -providerclass org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider -providerpath "$BCJAR" >/dev/null 2>&1 \
      || die "could not convert $1 to BCFKS"
  }
  mkdir -p "$D/fips"; KSP=$(openssl rand -hex 24); TMPP=$(openssl rand -hex 24)
  ( umask 077; openssl pkcs12 -export -inkey "$KC_HTTPS_CERTIFICATE_KEY_FILE" -in "$KC_HTTPS_CERTIFICATE_FILE" -name server \
      -passout "pass:$TMPP" -out "$D/fips/server.p12" ) || die "cannot read the server certificate/key"
  to_bcfks "$D/fips/server.p12" "$TMPP" "$D/fips/server.bcfks" "$KSP" server; rm -f "$D/fips/server.p12"
  to_bcfks "$KC_HTTPS_TRUST_STORE_FILE" "$PKI_P12_PASSWORD" "$D/fips/client-ca.bcfks" "$KSP"   # DoD anchors, or the proxy CA in edge mode
  # Keep the PEM paths for validation above; Keycloak itself gets the BCFKS stores only.
  PEM_CERT="$KC_HTTPS_CERTIFICATE_FILE"; PEM_KEY="$KC_HTTPS_CERTIFICATE_KEY_FILE"; unset KC_HTTPS_CERTIFICATE_FILE KC_HTTPS_CERTIFICATE_KEY_FILE
  export KC_HTTPS_KEY_STORE_FILE="$D/fips/server.bcfks" KC_HTTPS_KEY_STORE_PASSWORD="$KSP" KC_HTTPS_KEY_STORE_TYPE=bcfks \
         KC_HTTPS_TRUST_STORE_FILE="$D/fips/client-ca.bcfks" KC_HTTPS_TRUST_STORE_PASSWORD="$KSP" KC_HTTPS_TRUST_STORE_TYPE=bcfks
  log "strict FIPS: server key store and TLS client trust store converted to BCFKS"
fi

# ---- 3. revocation data
MODE="${CRL_MODE:-}"
if [ -z "$MODE" ]; then   # lab: the mock CA's CRL; lab + real cards: DoD CRLs too (online)
  if $LAB && ! truthy "${CAC_LAB_TRUST_DOD:-false}"; then MODE=file; else MODE=online; fi
fi
MODE="${MODE,,}"; case "$MODE" in offline|local) MODE=file;; disabled|off) MODE=none;; esac; export CRL_MODE="$MODE"
mkdir -p "$D/crl"
crl_missing() { [ -f "$D/.crl-required" ] || return 0; while read -r n; do [ -z "$n" ] || [ -s "$D/crl/$n" ] || echo "$n"; done < "$D/.crl-required"; }
# A data directory that survived a restart or an image upgrade may hold CRLs of CAs that are no longer anchors;
# a single one makes Keycloak refuse every card. Remove them before Keycloak (or the profile) sees the directory.
"$TOOLS/cac-pki.sh" crl-prune "$D/crl" "$D/anchors"
CRL_SRC="${CAC_CRL_DIR:-/crl}"; $LAB && [ -z "${CAC_CRL_DIR:-}" ] && [ -d "$D/lab/conf/crl" ] && CRL_SRC="$D/lab/conf/crl"
# Online mode: the CRLs this deployment must hold before it reports ready (cac-health.py), one file name per line.
# Until every one is installed, card sign-in for that CA fails closed and the container is NOT healthy.
rm -f "$D/.crl-required"
if [ "$MODE" = online ]; then cp "$D/crl-names.txt" "$D/.crl-required"; fi
# CAC_CRL_CACHE_DIR (online mode): a persistent directory holding the last good CRLs. A new container installs them
# BEFORE Keycloak starts - through crl-sync, so only CRLs whose signature verifies against the CURRENT anchors are
# installed (a retired CA's CRL never comes back) - and every refresh writes the expected ones back. CRLs are public;
# a stale one (past nextUpdate) still fails closed for its CA until the refresh replaces it.
CACHE="${CAC_CRL_CACHE_DIR:-}"
if [ -n "$CACHE" ]; then
  [ "$MODE" = online ] || die "CAC_CRL_CACHE_DIR is for CRL_MODE=online only (file mode reads CAC_CRL_DIR)"
  [ -d "$CACHE" ] && [ -w "$CACHE" ] || die "CAC_CRL_CACHE_DIR=$CACHE is not a writable directory (owner 1000, see README)"
  "$TOOLS/cac-pki.sh" crl-sync "$CACHE" "$D/anchors" "$D/crl"
  log "CRLs: $(crl_missing | wc -l) of $(wc -l < "$D/.crl-required") expected still missing after installing the cache"
fi
crl_refresh() {
  case "$MODE" in
    online) "$TOOLS/cac-pki.sh" crl-fetch "$D/anchors" "$D/crl"
            [ -z "$CACHE" ] || "$TOOLS/cac-pki.sh" crl-save "$D/crl" "$CACHE" "$D/crl-names.txt" || log "WARN could not update the CRL cache $CACHE";;
    file)   "$TOOLS/cac-pki.sh" crl-sync "$CRL_SRC" "$D/anchors" "$D/crl";;
  esac
  "$TOOLS/cac-pki.sh" crl-health "$D/crl" || true
  "$TOOLS/cac-pki.sh" crl-coverage "$D/anchors" "$D/crl" || true   # logs STIG-CRL-COVERAGE-GAP per uncovered CA
}
# lab PKI's own CRL is always installed, so mock cards keep working next to real ones
if $LAB && [ -d "$D/lab/conf/crl" ] && [ "$MODE" != file ]; then "$TOOLS/cac-pki.sh" crl-sync "$D/lab/conf/crl" "$D/anchors" "$D/crl"; fi
case "$MODE" in
  file)   crl_refresh ;;                       # local: fast, needed before the profile is rendered
  online) log "CRLs: downloading $(wc -l < "$D/crl-names.txt") DoD CRLs in the background (CAC logins fail closed, and the container is not ready, until every one is installed)";;
  ocsp)   log "WARN CRL_MODE=ocsp: no local CRL cache (V-222553 asks for one); every login depends on the OCSP responder";;
  none)   log "!!! CRL_MODE=none: certificate revocation is NOT checked (lab only) !!!";;
esac

# ---- validate everything before Keycloak starts (fail fast, fail secure)
for f in "${PEM_CERT:-${KC_HTTPS_CERTIFICATE_FILE:-}}" "${PEM_KEY:-${KC_HTTPS_CERTIFICATE_KEY_FILE:-}}"; do [ -r "$f" ] || die "cannot read server certificate/key $f"; done
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
crl_next_wait() { # online: while any expected CRL is missing, retry every CAC_CRL_RETRY_SECONDS, not every 6 h
  local m; m=$(crl_missing | tr '\n' ' ')
  if [ -n "$m" ]; then log "STIG-CRL-INCOMPLETE not ready, CRLs missing: $m"; echo "${CAC_CRL_RETRY_SECONDS:-60}"
  else echo "${CAC_CRL_REFRESH_SECONDS:-21600}"; fi
}
crl_loop() {
  [ "$MODE" = online ] && { crl_refresh; python3 "$TOOLS/cac-config.py" sync-crl-list || log "WARN could not update the CRL list"
                           python3 "$TOOLS/cac-config.py" clear-crl-cache || true; touch "$D/.crl-loaded"; }
  [ "$MODE" != online ] && touch "$D/.crl-loaded"
  [ "$MODE" = online ] || [ "$MODE" = file ] || return 0
  while sleep "$(crl_next_wait)"; do
    crl_refresh || log "WARN CRL refresh failed; keeping cached CRLs"
    [ "$MODE" = online ] && { python3 "$TOOLS/cac-config.py" sync-crl-list || log "WARN could not update the CRL list"; }
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

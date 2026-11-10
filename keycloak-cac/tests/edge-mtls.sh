#!/usr/bin/env bash
# Behavioural test of edge mode: an X509_LOOKUP=nginx image must
#   1. refuse to start without CAC_EDGE_PROXY_CA_FILE,
#   2. with it, refuse TLS connections that present no client certificate or one from another CA,
#   3. accept the proxy's certificate, and still apply its own realm (its loopback certificate works).
# Lab mode (mock PKI, dev-file database): no secrets, nothing published beyond 127.0.0.1.
#   keycloak-cac/tests/edge-mtls.sh [image]     (builds keycloak-cac:edge-test from the repo root when no image is given)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; IMG="${1:-}"; PORT="${EDGE_TEST_PORT:-18443}"
ENGINE="${ENGINE:-docker}"
if [ -z "$IMG" ]; then IMG=keycloak-cac:edge-test; $ENGINE build -q -f "$ROOT/keycloak-cac/Containerfile" --build-arg X509_LOOKUP=nginx -t "$IMG" "$ROOT" >/dev/null; fi
T="$(mktemp -d)"; NAME="kcc-edge-test-$$"
cleanup() { $ENGINE rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$T"; }; trap cleanup EXIT
fail=0; pass() { echo "PASS $*"; }; bad() { echo "FAIL $*"; fail=1; }
mkca() { openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=$1" \
           -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -keyout "$T/$1.key" -out "$T/$1.crt" 2>/dev/null; }
mkcert() { openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -keyout "$T/$1.key" -out "$T/$1.csr" 2>/dev/null
           printf 'extendedKeyUsage=clientAuth\n' > "$T/ext"
           openssl x509 -req -in "$T/$1.csr" -CA "$T/$2.crt" -CAkey "$T/$2.key" -CAcreateserial -days 2 -extfile "$T/ext" -out "$T/$1.crt" 2>/dev/null; }
mkca proxy-ca; mkca rogue-ca; mkcert proxy proxy-ca; mkcert rogue rogue-ca; chmod 644 "$T"/*

LAB=(-e CAC_LAB_MODE=true -e KC_DB=dev-file -e KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap -e KC_BOOTSTRAP_ADMIN_PASSWORD=edge-test-bootstrap-pw)
$ENGINE run -d --name "$NAME" "${LAB[@]}" "$IMG" >/dev/null
for i in $(seq 1 24); do $ENGINE inspect -f '{{.State.Running}}' "$NAME" | grep -q false && break; sleep 5; done
out=$($ENGINE logs "$NAME" 2>&1); running=$($ENGINE inspect -f '{{.State.Running}}' "$NAME"); $ENGINE rm -f "$NAME" >/dev/null
[ "$running" = false ] && echo "$out" | grep -q "CAC_EDGE_PROXY_CA_FILE" && pass "refuses to start without the proxy CA" \
  || bad "started without CAC_EDGE_PROXY_CA_FILE: $(echo "$out" | tail -2)"

$ENGINE run -d --name "$NAME" -p "127.0.0.1:$PORT:8443" -v "$T:/pki:ro" -e CAC_EDGE_PROXY_CA_FILE=/pki/proxy-ca.crt "${LAB[@]}" "$IMG" >/dev/null
for i in $(seq 1 120); do
  $ENGINE exec "$NAME" /opt/keycloak-cac/bin/cac-entrypoint.sh health >/dev/null 2>&1 && break
  $ENGINE inspect -f '{{.State.Running}}' "$NAME" | grep -q true || { $ENGINE logs "$NAME" 2>&1 | tail -20; bad "container stopped"; exit 1; }
  sleep 5
done
$ENGINE exec "$NAME" /opt/keycloak-cac/bin/cac-entrypoint.sh health >/dev/null 2>&1 \
  && pass "ready with the realm applied (in-container admin calls use the loopback certificate)" || bad "never became ready: $($ENGINE logs "$NAME" 2>&1 | grep keycloak-cac | tail -3)"
U="https://127.0.0.1:$PORT/realms/master/.well-known/openid-configuration"
code() { curl -sk -o /dev/null -w '%{http_code}' "$@" "$U" 2>/dev/null || true; }
c=$(code); [ "$c" = 000 ] && pass "no client certificate: TLS refused" || bad "no client certificate: HTTP $c"
c=$(code --cert "$T/rogue.crt" --key "$T/rogue.key"); [ "$c" = 000 ] && pass "certificate from another CA: TLS refused" || bad "rogue CA: HTTP $c"
c=$(code --cert "$T/proxy.crt" --key "$T/proxy.key"); [ "$c" = 200 ] && pass "proxy certificate: HTTP 200" || bad "proxy certificate: HTTP $c"
exit $fail

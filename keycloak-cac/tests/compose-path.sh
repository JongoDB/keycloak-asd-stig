#!/usr/bin/env bash
# The production compose file as documented: secrets as single files owned root:1000, mode 0440, the service running
# as 1000:1000, read-only root. Lab mode (mock PKI) and a throwaway PostgreSQL make it self-contained; the point is
# that Keycloak can read every secret and the realm gets applied. Needs docker compose and sudo (to chown root:1000).
#   keycloak-cac/tests/compose-path.sh <image>
set -euo pipefail
IMG="${1:?image}"; ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; PORT="${COMPOSE_TEST_PORT:-18444}"
W="$(mktemp -d)"; chmod 755 "$W"; P="kcc-compose-test-$$"
cleanup() { (cd "$W" && KEYCLOAK_CAC_IMAGE="$IMG" CAC_PORT=$PORT docker compose -p "$P" -f compose.yaml -f test.override.yaml down -v >/dev/null 2>&1) || true; sudo rm -rf "$W"; }
trap cleanup EXIT
cp "$ROOT/keycloak-cac/deploy/compose/compose.yaml" "$W/"; cd "$W"; mkdir -p tls secrets clients
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=localhost" -addext subjectAltName=DNS:localhost \
  -keyout tls/tls.key -out tls/tls.crt 2>/dev/null
for s in db_password bootstrap_admin_password; do openssl rand -hex 24 | tr -d '\n' > secrets/$s; done
openssl rand -hex 32 | tr -d '\n' > secrets/automation_secret
sudo chown root:1000 tls/* secrets/*; sudo chmod 0440 tls/* secrets/*      # exactly what README tells operators
cat > keycloak-cac.env <<E
CAC_LAB_MODE=true
CAC_PUBLIC_URL=https://localhost:$PORT
KC_DB_URL=jdbc:postgresql://db:5432/keycloak
KC_DB_USERNAME=keycloak
KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap
E
cat > test.override.yaml <<'E'
services:
  db:
    image: mirror.gcr.io/library/postgres:17
    environment: {POSTGRES_DB: keycloak, POSTGRES_USER: keycloak, POSTGRES_PASSWORD_FILE: /run/secrets/db_password}
    secrets: [db_password]
    user: "0:0"   # the official image drops to postgres itself; it must read the 0440 root:1000 file as root first
    healthcheck: {test: ["CMD-SHELL", "pg_isready -U keycloak"], interval: 5s, retries: 30}
  keycloak:
    depends_on: {db: {condition: service_healthy}}
E
export KEYCLOAK_CAC_IMAGE="$IMG" CAC_PORT=$PORT
docker compose -p "$P" -f compose.yaml -f test.override.yaml up -d >/dev/null
C=$(docker compose -p "$P" -f compose.yaml -f test.override.yaml ps -q keycloak)
for i in $(seq 1 120); do
  st=$(docker inspect -f '{{.State.Health.Status}} {{.State.Running}}' "$C"); [ "${st%% *}" = healthy ] && break
  [ "${st##* }" = true ] || break; sleep 5
done
fail=0
[ "$(docker inspect -f '{{.Config.User}}' "$C")" = "1000:1000" ] && echo "PASS runs as 1000:1000" || { echo "FAIL user"; fail=1; }
docker exec "$C" sh -c 'for f in /run/secrets/*; do [ -r "$f" ] || exit 1; done' && echo "PASS every root:1000 0440 secret is readable" || { echo "FAIL unreadable secret"; fail=1; }
if [ "${st%% *}" = healthy ]; then echo "PASS healthy: realm applied, revocation data loaded"; else echo "FAIL not healthy ($st)"; docker logs "$C" 2>&1 | grep -E "^keycloak-cac|ERROR" | tail -5; fail=1; fi
code=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:$PORT/realms/dod-cac/.well-known/openid-configuration" || true)
[ "$code" = 200 ] && echo "PASS issuer serves over TLS" || { echo "FAIL issuer HTTP $code"; fail=1; }
exit $fail

#!/usr/bin/env bash
# stig-accounts in a passkey realm (U1-U5, U7) on the image, with a software authenticator for the set-up links:
#   per-realm set-up actions (operator-only master-realm attribute), organization domains and allow-list, the realm
#   denylist, onBehalfOf recorded as asserted, recovery (passkeys removed, sessions ended, a new link), reactivation of
#   an account the inactivity workflow disabled (and that workflow restarted), and the main realm left as it was.
# Lab mode (mock PKI, dev-file database), published on 127.0.0.1 only; a local SMTP sink takes the mail.
#   keycloak-cac/tests/accounts-public.sh <image>
set -euo pipefail
IMG="${1:?image}"; ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${ACCOUNTS_TEST_PORT:-18451}"; SMTP="${ACCOUNTS_TEST_SMTP_PORT:-18527}"
T="$(mktemp -d)"; NAME="kcc-accounts-$$"; PW="passkey-test-bootstrap-$$-$RANDOM"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; [ -n "${SINK:-}" ] && kill "$SINK" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
mkdir -p "$T/extra" "$T/clients" "$T/mail"
cat > "$T/extra/60-public.json" <<'EOF'
{"realm": {"name": "public", "display_name": "Public"}, "auth_mode": "passkey"}
EOF
chmod -R a+rX "$T"
python3 "$ROOT/keycloak-cac/tests/lib/mailsink.py" "$SMTP" "$T/mail" & SINK=$!
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8443" --add-host host.docker.internal:host-gateway \
  -e CAC_LAB_MODE=true -e KC_DB=dev-file -e CAC_AUTH_MODE=cac_or_mfa -e CAC_LOCKOUT=temporary \
  -e CAC_PUBLIC_URL="https://localhost:$PORT" -e KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap -e KC_BOOTSTRAP_ADMIN_PASSWORD="$PW" \
  -e CAC_EXTRA_REALM_PROFILES=/extra -e CAC_CLIENTS_DIR=/clients \
  -e KC_SPI_EVENTS_LISTENER__WORKFLOW_EVENT_LISTENER__STEP_RUNNER_TASK_INTERVAL=3 \
  -v "$T/extra:/extra:ro" -v "$T/clients:/clients:ro" "$IMG" >/dev/null
wait_up() {
  for i in $(seq 1 120); do
    docker exec "$NAME" /opt/keycloak-cac/bin/cac-entrypoint.sh health >/dev/null 2>&1 && return 0
    docker inspect -f '{{.State.Running}}' "$NAME" | grep -q true || { docker logs "$NAME" 2>&1 | tail -30; echo "FAIL container stopped"; exit 1; }
    sleep 5
  done
  docker logs "$NAME" 2>&1 | tail -30; echo "FAIL not healthy"; exit 1
}
wait_up
docker exec "$NAME" cat /opt/keycloak/data/cac/lab/ca/root.crt > "$T/root.crt"
LAB_BOOTSTRAP_PW="$PW" python3 "$ROOT/keycloak-cac/tests/lib/accounts_public_test.py" --name "$NAME" --port "$PORT" \
  --smtp-host host.docker.internal --smtp-port "$SMTP" --dir "$T" --realm public

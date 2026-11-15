#!/usr/bin/env bash
# A passkey realm applied by the image beside the main realm (CAC_EXTRA_REALM_PROFILES, auth_mode=passkey), driven
# with a software authenticator (tests/lib/softauthn.py) - registration and sign-in exactly as a browser posts them:
#   - both realms applied on start; the extra realm gets only its own clients; kcstig verify passes its passkey checks;
#   - an invitation (VERIFY_EMAIL + the DoD notice as terms + passkey registration) verifies the address and stores
#     an ES256 credential; RS256 registers; an algorithm outside the policy (Ed25519) is refused;
#   - sign-in: username + passkey and the discoverable "Sign in with passkey" button give a code; no user
#     verification (checked by the SERVER), a bad signature, a backwards counter, another device, a username alone:
#     no code; the direct grant is denied;
#   - an organization invitation link (even with PKCE added) creates no account: the registration flow denies;
#   - drift is undone by a restart: both realms are re-applied;
#   - a stored credential outside the policy (an Ed25519 credential registered under a looser policy) fails verify.
# Lab mode (mock PKI, dev-file database), published on 127.0.0.1 only; a local SMTP sink takes the mail.
#   keycloak-cac/tests/passkey-realm.sh <image>
set -euo pipefail
IMG="${1:?image}"; ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${PASSKEY_TEST_PORT:-18447}"; SMTP="${PASSKEY_TEST_SMTP_PORT:-18525}"
T="$(mktemp -d)"; NAME="kcc-passkey-$$"; PW="passkey-test-bootstrap-$$-$RANDOM"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; [ -n "${SINK:-}" ] && kill "$SINK" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
mkdir -p "$T/extra" "$T/clients/partners" "$T/mail"
cat > "$T/extra/50-partners.json" <<'EOF'
{"realm": {"name": "partners", "display_name": "Partners"}, "auth_mode": "passkey"}
EOF
cat > "$T/clients/partners/partner-app.json" <<'EOF'
{"client_id": "partner-app", "type": "oidc-confidential", "auth": "client-secret", "redirect_uris": ["https://app.example/cb"],
 "post_logout_redirect_uris": ["https://app.example/out"], "roles": ["VENDOR", "FACTORY_READER"]}
EOF
cat > "$T/clients/main-app.json" <<'EOF'
{"client_id": "main-app", "type": "oidc-confidential", "auth": "client-secret", "redirect_uris": ["https://main.example/cb"],
 "post_logout_redirect_uris": ["https://main.example/out"]}
EOF
chmod -R a+rX "$T"
python3 "$ROOT/keycloak-cac/tests/lib/mailsink.py" "$SMTP" "$T/mail" & SINK=$!
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8443" --add-host host.docker.internal:host-gateway \
  -e CAC_LAB_MODE=true -e KC_DB=dev-file -e CAC_AUTH_MODE=cac_or_mfa -e CAC_LOCKOUT=temporary \
  -e CAC_PUBLIC_URL="https://localhost:$PORT" -e KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap -e KC_BOOTSTRAP_ADMIN_PASSWORD="$PW" \
  -e CAC_EXTRA_REALM_PROFILES=/extra -e CAC_CLIENTS_DIR=/clients \
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
docker exec "$NAME" cat /opt/keycloak/data/cac/extra/partners.json > "$T/partners-profile.json"
LAB_BOOTSTRAP_PW="$PW" python3 "$ROOT/keycloak-cac/tests/lib/passkey_realm_test.py" --name "$NAME" --port "$PORT" \
  --smtp-host host.docker.internal --smtp-port "$SMTP" --dir "$T"

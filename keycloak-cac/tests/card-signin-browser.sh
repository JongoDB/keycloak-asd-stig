#!/usr/bin/env bash
# The card sign-in page in a real browser (card_signin_browser.py): the exact labels, the spacing at 1440 and 360 px,
# and the blocked message only on a real connection error - never during a slow certificate pick.
# Lab mode (mock PKI, dev-file database), STIG_CARD_PORT=8444, no published port: the browser runs in the container's
# network namespace (the Playwright image, pinned by digest, for the browsers; the Python package from
# playwright-requirements.txt, pinned by hash), as onboarding_lab.sh runs its tests.
#   keycloak-cac/tests/card-signin-browser.sh <image> [screenshot dir] [screenshot name tag]
set -euo pipefail
IMG="${1:?image}"; SHOTS="${2:-}"; TAG="${3:-}"; ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PW="${PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright/python:v1.49.1-noble@sha256:42e251ec3238672c931be6c3565ff279690ae072c3e22058128d0412494f6866}"
T="$(mktemp -d)"; NAME="kcc-card-signin-$$"; SECRET="$(openssl rand -hex 24)"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$T"; }; trap cleanup EXIT
docker run -d --name "$NAME" -e CAC_LAB_MODE=true -e KC_DB=dev-file -e CAC_AUTH_MODE=cac_or_mfa -e STIG_CARD_PORT=8444 \
  -e CAC_PUBLIC_URL="https://localhost:8443" -e KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -hex 16)" -e CAC_AUTOMATION_SECRET="$SECRET" "$IMG" >/dev/null
for i in $(seq 1 120); do
  docker exec "$NAME" /opt/keycloak-cac/bin/cac-entrypoint.sh health >/dev/null 2>&1 && break
  docker inspect -f '{{.State.Running}}' "$NAME" | grep -q true || { docker logs "$NAME" 2>&1 | tail -20; echo "FAIL container stopped"; exit 1; }
  sleep 5
done
# the present-card page (an invite naming a card; reached through an identity provider, not set up here): the same
# label, and the same [hidden] rule and no-timeout probe as the card sign-in page - read from the image's own jar
docker cp "$NAME:/opt/keycloak/providers/stig-extensions.jar" "$T/ext.jar" >/dev/null
python3 - "$T/ext.jar" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1]); msgs = z.read("theme-resources/messages/messages_en.properties").decode()
res = []
def check(n, ok): res.append(ok); print("%s  %-100s" % ("PASS" if ok else "FAIL", n))
check("[present-card] the card button reads exactly \"Sign in with CAC/PIV\"", "\nstigPresentCardUse=Sign in with CAC/PIV\n" in msgs)
check("[card-signin] the card button reads exactly \"Sign in with CAC/PIV\"", "\nstigCardSignInUse=Sign in with CAC/PIV\n" in msgs)
for t in ("stig-present-card.ftl", "stig-card-signin.ftl"):
    f = z.read("theme-resources/templates/" + t).decode()
    check("[%s] [hidden] beats the theme's alert display; no timeout aborts the probe; a still-waiting note" % t,
          "#stig-card-blocked[hidden]" in f and "display: none !important" in f and "ac.abort(); }, 10000" not in f
          and 'id="stig-card-wait"' in f)
sys.exit(0 if all(res) else 1)
PY
L=/opt/keycloak/data/cac/lab
for f in ca/root.crt users/doe.john.crt users/doe.john.key; do docker exec "$NAME" cat "$L/$f" > "$T/$(basename "$f")"; done
chmod 0644 "$T"/*; chmod 0755 "$T"
MS=(); SA=()
if [ -n "$SHOTS" ]; then mkdir -p "$SHOTS"; chmod 0777 "$SHOTS"; MS=(-v "$(cd "$SHOTS" && pwd):/shots"); SA=(--shots /shots --tag "$TAG"); fi
docker run --rm --network "container:$NAME" -e AUTOMATION_SECRET="$SECRET" -v "$ROOT/keycloak-cac/tests:/tests:ro" \
  -v "$ROOT/keycloak-asd-stig/scripts:/kas:ro" -v "$T:/t:ro" "${MS[@]}" "$PW" \
  sh -c 'pip install -q --break-system-packages --require-hashes -r /tests/playwright-requirements.txt >/dev/null &&
         exec python3 -I /tests/card_signin_browser.py --cacert /t/root.crt --certs /t --skill-scripts /kas "$@"' sh "${SA[@]}"

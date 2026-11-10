#!/usr/bin/env bash
# A card is not refused because someone typed wrong passwords for its holder (stig-x509-client-username-form):
#   1. three wrong passwords on the public form lock the holder (temporary lockout, CAC_LOCKOUT=temporary);
#   2. a fourth attempt is refused BY THE LOCK (Keycloak's own event: error="user_temporarily_disabled");
#   3. the holder's valid card still signs in (an authorization code comes back);
#   4. a REVOKED card is still refused (the change touches lockout only).
# Lab mode (mock PKI, dev-file database), published on 127.0.0.1 only.
#   keycloak-cac/tests/card-lockout.sh <image>
set -euo pipefail
IMG="${1:?image}"; ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; PORT="${CARD_TEST_PORT:-18445}"
T="$(mktemp -d)"; NAME="kcc-card-lockout-$$"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$T"; }; trap cleanup EXIT
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8443" -e CAC_LAB_MODE=true -e KC_DB=dev-file -e CAC_AUTH_MODE=cac_or_mfa \
  -e CAC_LOCKOUT=temporary -e CAC_PUBLIC_URL="https://localhost:$PORT" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap -e KC_BOOTSTRAP_ADMIN_PASSWORD=card-test-bootstrap-pw "$IMG" >/dev/null
for i in $(seq 1 120); do
  docker exec "$NAME" /opt/keycloak-cac/bin/cac-entrypoint.sh health >/dev/null 2>&1 && break
  docker inspect -f '{{.State.Running}}' "$NAME" | grep -q true || { docker logs "$NAME" 2>&1 | tail -20; echo "FAIL container stopped"; exit 1; }
  sleep 5
done
L=/opt/keycloak/data/cac/lab
for f in ca/root.crt users/doe.john.crt users/doe.john.key users/revoked.crt users/revoked.key; do
  docker exec "$NAME" cat "$L/$f" > "$T/$(basename "$f")"
done
python3 - "$ROOT/keycloak-asd-stig/scripts" "$T" "$PORT" "$NAME" <<'PY'
import argparse, subprocess, sys, time, uuid
sys.path.insert(0, sys.argv[1]); import e2e_check as E
T, PORT, NAME = sys.argv[2], sys.argv[3], sys.argv[4]
BASE = "https://localhost:%s" % PORT; RED = BASE + "/realms/dod-cac/account/"
fl = E.Flow(argparse.Namespace(url=BASE, realm="dod-cac", client="account-console", redirect=RED, admin_url=None, client_secret=None, cacert=T + "/root.crt"))
res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s %-70s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)
def wrong(user):
    b = E.Browser(T + "/root.crt"); url, _ = fl.auth_url(); k, u, p = b.go(url, None, RED)
    act, f = E.form(p, "kc-form-login"); f.update({"username": user, "password": "wrong-" + uuid.uuid4().hex}); b.go(act, f, RED)
since = int(time.time())
for _ in range(4):
    wrong("doe.john")
time.sleep(2)
logs = subprocess.run(["docker", "logs", "--since", str(since), NAME], capture_output=True, text=True)
logs = logs.stdout + logs.stderr
check("wrong passwords lock the holder (event user_temporarily_disabled)", "user_temporarily_disabled" in logs and "doe.john" in logs)
b, final, seen, banner, ver = E.cac_login(fl, T + "/doe.john.crt", T + "/doe.john.key")
check("... and the holder's valid card still signs in", bool(final and "code=" in final), "pages=%s" % seen)
b, final, seen, banner, ver = E.cac_login(fl, T + "/revoked.crt", T + "/revoked.key")
check("a revoked card is still refused", not (final and "code=" in final), "pages=%s" % seen)
sys.exit(0 if all(res) else 1)
PY

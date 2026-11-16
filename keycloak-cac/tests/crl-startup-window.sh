#!/usr/bin/env bash
# The start-up window of a hardened, online-mode deployment, as on a production host:
#   PostgreSQL (the realm survives restarts), user 1000:1000, read-only root, /tmp and /opt/keycloak/data on tmpfs,
#   cap_drop ALL, no-new-privileges; /opt/keycloak/conf/cac is the image's symlink to /opt/keycloak/data/cac.
# After a restart the data tmpfs is empty, Keycloak is up and the realm lists every CRL BEFORE crl-fetch has
# downloaded them (slowly, from a mirror sidecar). The stig authenticator must:
#   1. report the not-yet-installed CRLs as STIG-CRL-MISSING (a warning), never as STIG-CRL-UNREADABLE;
#   2. stop reporting once the CRLs are installed - no restart, no cache clear;
#   3. sign a valid card in and refuse a revoked one afterwards.
#   keycloak-cac/tests/crl-startup-window.sh <image> [dir with the DoD CRLs]   (default: download them from crl.disa.mil)
set -euo pipefail
IMG="${1:?image}"; SRC="${2:-}"; ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; PORT="${CRL_WINDOW_PORT:-18473}"
T="$(mktemp -d)"; N="kcc-crlwin-$$"; NET="$N-net"
cleanup() { docker rm -f "$N" "$N-db" "$N-mirror" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$T"; }
trap cleanup EXIT
mkdir -p "$T/mirror" "$T/cards"
if [ -n "$SRC" ]; then cp "$SRC"/*.crl "$T/mirror/"
else
  # the CRLs the image will ask for: the baked anchors, narrowed the way the entrypoint does it
  docker run --rm --entrypoint bash -v "$T/mirror:/out" "$IMG" -c 'mkdir -p /tmp/a /tmp/o && cp /opt/keycloak-cac/pki/anchors/*.pem /tmp/a/ &&
    /opt/keycloak-cac/bin/cac-pki.sh narrow /tmp/a >/dev/null 2>&1 && /opt/keycloak-cac/bin/cac-pki.sh compile /tmp/a /tmp/o >/dev/null 2>&1 && cat /tmp/o/crl-names.txt' > "$T/names.txt"
  while read -r n; do curl -fsS --retry 2 -m 180 -o "$T/mirror/$n" "http://crl.disa.mil/crl/$n" || { echo "SKIP crl.disa.mil not reachable ($n); pass a CRL directory instead"; exit 0; }; done < "$T/names.txt"
fi
chmod -R a+rX "$T/mirror"
docker network create "$NET" >/dev/null
docker run -d --name "$N-db" --network "$NET" -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD=crl-window-db-password docker.io/library/postgres:17 >/dev/null
# a slow mirror: 3 s per file, so the window lasts about a minute
docker run -d --name "$N-mirror" --network "$NET" -v "$T/mirror:/srv:ro" --entrypoint python3 docker.io/library/python:3.12-slim -c '
import http.server, time
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(s, *a, **k): super().__init__(*a, directory="/srv", **k)
    def do_GET(s): time.sleep(3); super().do_GET()
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()' >/dev/null
for i in $(seq 1 30); do docker exec "$N-db" pg_isready -U keycloak >/dev/null 2>&1 && break; sleep 2; done
docker run -d --name "$N" --network "$NET" --user 1000:1000 --read-only --tmpfs /tmp \
  --tmpfs /opt/keycloak/data:uid=1000,gid=1000,mode=0755 --cap-drop ALL --security-opt no-new-privileges:true \
  -p "127.0.0.1:$PORT:8443" -e CAC_LAB_MODE=true -e CAC_LAB_TRUST_DOD=true -e CAC_AUTH_MODE=cac_or_mfa \
  -e CRL_MODE=online -e CRL_BASE="http://$N-mirror:8080" -e CAC_OCSP=false \
  -e KC_DB_URL="jdbc:postgresql://$N-db/keycloak" -e KC_DB_USERNAME=keycloak -e KC_DB_PASSWORD=crl-window-db-password \
  -e CAC_PUBLIC_URL="https://localhost:$PORT" -e KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=crl-window-bootstrap-pw "$IMG" >/dev/null
wait_for() { for i in $(seq 1 120); do docker logs --since "$1" "$N" 2>&1 | grep -q "$2" && return 0; docker inspect -f '{{.State.Running}}' "$N" | grep -q true || return 1; sleep 3; done; return 1; }
wait_for 2000-01-01T00:00:00Z "CRL list" || { docker logs "$N" 2>&1 | tail -20; echo "FAIL first start"; exit 1; }
# restart: the data tmpfs is wiped, the realm (in PostgreSQL) already lists every CRL
T0=$(date -u +%FT%TZ); docker restart "$N" >/dev/null
wait_for "$T0" "CRLs refreshed" || { docker logs --since "$T0" "$N" 2>&1 | tail -20; echo "FAIL no CRL refresh after restart"; exit 1; }
T1=$(date -u +%FT%TZ); sleep 45
L=/opt/keycloak/data/cac/lab
for f in ca/root.crt users/doe.john.crt users/doe.john.key users/revoked.crt users/revoked.key; do docker exec "$N" cat "$L/$f" > "$T/cards/$(basename "$f")"; done
python3 - "$ROOT/keycloak-asd-stig/scripts" "$T/cards" "$PORT" "$N" "$T0" "$T1" <<'PY'
import argparse, subprocess, sys
sys.path.insert(0, sys.argv[1]); import e2e_check as E
C, PORT, N, T0, T1 = sys.argv[2:7]
logs = lambda since, until=None: (lambda r: r.stdout + r.stderr)(subprocess.run(["docker", "logs", "--since", since] + (["--until", until] if until else []) + [N], capture_output=True, text=True))
window, after = logs(T0, T1), logs(T1)
res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s %-80s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)
check("the start-up window reports not-yet-installed CRLs as STIG-CRL-MISSING", "STIG-CRL-MISSING" in window, "%d lines" % window.count("STIG-CRL-MISSING"))
check("... and never as STIG-CRL-UNREADABLE", "STIG-CRL-UNREADABLE" not in window + after, "%d lines" % (window + after).count("STIG-CRL-UNREADABLE"))
check("once the CRLs are installed, nothing more is reported (45 s)", "STIG-CRL-MISSING" not in after, "%d lines" % after.count("STIG-CRL-MISSING"))
check("CRL coverage complete after the refresh", "every trusted issuing CA and its root has a CRL" in window + after)
BASE = "https://localhost:%s" % PORT; RED = BASE + "/realms/dod-cac/account/"
fl = E.Flow(argparse.Namespace(url=BASE, realm="dod-cac", client="account-console", redirect=RED, admin_url=None, client_secret=None, cacert=C + "/root.crt"))
def signs_in(u):
    b, final, seen, banner, ver = E.cac_login(fl, "%s/%s.crt" % (C, u), "%s/%s.key" % (C, u)); return bool(final and "code=" in final)
check("a valid card signs in after the window", signs_in("doe.john"))
check("a revoked card is refused", not signs_in("revoked"))
sys.exit(0 if all(res) else 1)
PY

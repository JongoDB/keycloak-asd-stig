#!/usr/bin/env bash
# A restarted container never reports healthy without its CRLs, and with CAC_CRL_CACHE_DIR it has them from the start.
# Hardened online deployment as on the single-VM host: PostgreSQL, user 1000:1000, read-only root, tmpfs data, a cache
# volume, CRLs from a slow mirror sidecar standing in for crl.disa.mil.
#   1. first start, empty cache: health is never "ready" while an expected CRL is missing; the cache fills;
#   2. restart with the CRL source DOWN: the CRLs come from the cache before Keycloak starts - every expected CRL is
#      installed at the first health check that passes, no STIG-CRL-MISSING is logged, and a card still signs in;
#   2b. restart with a SLOW source (every refresh takes minutes): ready as soon as the cache installed every expected
#      CRL and the realm is applied - not after the first refresh, which still runs (and completes) afterwards;
#   2c. the same with CAC_APPLY=false (a new container on the same database): nothing re-rendered the realm's CRL list,
#      so readiness still waits for the first refresh (and its sync-crl-list) - no shortcut;
#   3. restart with an EMPTY cache and the source down: never healthy, health names the missing CRLs; once the source is
#      back the retry (CAC_CRL_RETRY_SECONDS) installs them and it becomes healthy;
#   4. one CRL PERMANENTLY unavailable: not ready during CAC_CRL_READY_GRACE (naming it), then ready DEGRADED (still
#      naming it) - an outage of one CRL does not take every sign-in down - while a card whose issuer's CRL is missing
#      is still refused (fail closed). The missing DoD CRL has no lab card, so the card half uses the lab CA's CRL.
#   keycloak-cac/tests/crl-restart-ready.sh <image> [dir with the DoD CRLs]   (default: download them from crl.disa.mil)
set -euo pipefail
IMG="${1:?image}"; SRC="${2:-}"; ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; PORT="${CRL_RESTART_PORT:-18474}"
GRACE=180; T="$(mktemp -d)"; N="kcc-crlrst-$$"; NET="$N-net"; VOL="$N-cache"
cleanup() { docker rm -f "$N" "$N-db" "$N-mirror" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true
            docker volume rm "$VOL" >/dev/null 2>&1 || true; rm -rf "$T"; }
trap cleanup EXIT
mkdir -p "$T/mirror" "$T/cards"
docker run --rm --entrypoint bash "$IMG" -c 'mkdir -p /tmp/a /tmp/o && cp /opt/keycloak-cac/pki/anchors/*.pem /tmp/a/ &&
  /opt/keycloak-cac/bin/cac-pki.sh narrow /tmp/a >/dev/null 2>&1 && /opt/keycloak-cac/bin/cac-pki.sh compile /tmp/a /tmp/o >/dev/null 2>&1 && cat /tmp/o/crl-names.txt' > "$T/names.txt"
if [ -n "$SRC" ]; then cp "$SRC"/*.crl "$T/mirror/"
else
  while read -r n; do curl -fsS --retry 2 -m 180 -o "$T/mirror/$n" "http://crl.disa.mil/crl/$n" || { echo "SKIP crl.disa.mil not reachable ($n); pass a CRL directory instead"; exit 0; }; done < "$T/names.txt"
fi
chmod -R a+rX "$T/mirror"; EXPECTED=$(wc -l < "$T/names.txt" | tr -d " ")
docker network create "$NET" >/dev/null
docker volume create "$VOL" >/dev/null
docker run --rm --user 0 -v "$VOL:/c" --entrypoint bash "$IMG" -c 'chown 1000:1000 /c && chmod 0750 /c'
docker run -d --name "$N-db" --network "$NET" -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD=crl-restart-db-password docker.io/library/postgres:17 >/dev/null
mirror() { # start the slow mirror (${1:-2} s per file)
  docker rm -f "$N-mirror" >/dev/null 2>&1 || true
  docker run -d --name "$N-mirror" --network "$NET" -v "$T/mirror:/srv:ro" --entrypoint python3 docker.io/library/python:3.12-slim -c '
import http.server, sys, time
DELAY = float(sys.argv[1])
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(s, *a, **k): super().__init__(*a, directory="/srv", **k)
    def do_GET(s): time.sleep(DELAY); super().do_GET()
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()' "${1:-2}" >/dev/null
}
mirror
for i in $(seq 1 30); do docker exec "$N-db" pg_isready -U keycloak >/dev/null 2>&1 && break; sleep 2; done
run_kc() { # [extra docker run args]
docker run -d --name "$N" --network "$NET" --user 1000:1000 --read-only --tmpfs /tmp \
  --tmpfs /opt/keycloak/data:uid=1000,gid=1000,mode=0750 --cap-drop ALL --security-opt no-new-privileges:true \
  -v "$VOL:/crl-cache" -e CAC_CRL_CACHE_DIR=/crl-cache -e CAC_CRL_RETRY_SECONDS=10 -e CAC_CRL_READY_GRACE=$GRACE \
  -p "127.0.0.1:$PORT:8443" -e CAC_LAB_MODE=true -e CAC_LAB_TRUST_DOD=true -e CAC_AUTH_MODE=cac_or_mfa \
  -e CRL_MODE=online -e CRL_BASE="http://$N-mirror:8080" -e CAC_OCSP=false \
  -e KC_DB_URL="jdbc:postgresql://$N-db/keycloak" -e KC_DB_USERNAME=keycloak -e KC_DB_PASSWORD=crl-restart-db-password \
  -e CAC_PUBLIC_URL="https://localhost:$PORT" -e KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=crl-restart-bootstrap-pw "$@" "$IMG" >/dev/null
}
run_kc

# (no `producer | grep -q` on big output: with pipefail, grep -q exiting first makes the producer's SIGPIPE a failure)
res=(); check() { res+=("$2"); printf '%s %-96s %s\n' "$([ "$2" = 1 ] && echo PASS || echo FAIL)" "$1" "${3:-}"; }
# One exec per sample: health first, then the CRLs present. CRLs are only ever added during these phases, so "ready"
# followed by a count below EXPECTED means the container reported ready while a CRL was missing.
sample() {
  docker exec "$N" bash -c 'h=$(/opt/keycloak-cac/bin/cac-entrypoint.sh health 2>&1); r=$?; c=0
    while read -r n; do [ -s /opt/keycloak/data/cac/crl/$n ] && c=$((c+1)); done < /opt/keycloak/data/cac/crl-names.txt 2>/dev/null
    echo "$r $c $h"' 2>/dev/null || echo "9 0 not running"
}
# watch <seconds>: poll until ready; sets READY_AT (count at the first ready sample, or empty), BAD (ready + missing), LAST
watch() {
  READY_AT=""; BAD=0; LAST=""
  for i in $(seq 1 "$1"); do
    s=$(sample); LAST="$s"; r=${s%% *}; rest=${s#* }; c=${rest%% *}
    if [ "$r" = 0 ]; then READY_AT=$c; [ "$c" -ge "$EXPECTED" ] || BAD=1; return 0; fi
    docker inspect -f '{{.State.Running}}' "$N" 2>/dev/null | grep -q true || { sleep 2; continue; }
    sleep 2
  done
}

# the lab PKI is regenerated on every start: fetch its cards, then "<valid signs in 1|0> <revoked refused 1|0>"
try_cards() {
  local f
  for f in ca/root.crt users/doe.john.crt users/doe.john.key users/revoked.crt users/revoked.key; do
    docker exec "$N" cat "/opt/keycloak/data/cac/lab/$f" > "$T/cards/$(basename "$f")"; done
  python3 - "$ROOT/keycloak-asd-stig/scripts" "$T/cards" "$PORT" <<'PY'
import argparse, sys
sys.path.insert(0, sys.argv[1]); import e2e_check as E
C, PORT = sys.argv[2], sys.argv[3]
BASE = "https://localhost:%s" % PORT; RED = BASE + "/realms/dod-cac/account/"
fl = E.Flow(argparse.Namespace(url=BASE, realm="dod-cac", client="account-console", redirect=RED, admin_url=None, client_secret=None, cacert=C + "/root.crt"))
def signs_in(u):
    b, final, seen, banner, ver = E.cac_login(fl, "%s/%s.crt" % (C, u), "%s/%s.key" % (C, u)); return bool(final and "code=" in final)
print("%d %d" % (signs_in("doe.john"), not signs_in("revoked")))
PY
}

# 1. first start, empty cache
watch 300
check "first start: healthy" "$([ -n "$READY_AT" ] && echo 1 || echo 0)" "${LAST:0:120}"
check "first start: never ready while a CRL was missing ($EXPECTED expected)" "$([ -n "$READY_AT" ] && [ $BAD = 0 ] && echo 1 || echo 0)" "ready with ${READY_AT:-?}"
held=$(docker run --rm -v "$VOL:/c:ro" --entrypoint bash "$IMG" -c 'ls /c/*.crl 2>/dev/null | wc -l' | tr -d ' ')
check "first start: the cache holds every expected CRL" "$([ "${held:-0}" -eq "$EXPECTED" ] && echo 1 || echo 0)" "$held of $EXPECTED"

# 2. restart with the CRL source down: CRLs from the cache, before Keycloak starts
docker rm -f "$N-mirror" >/dev/null
# counted over the whole log, not with --since: Docker Desktop's VM clock can lag the host's
M0=$(docker logs "$N" 2>&1 | grep -c STIG-CRL-MISSING || true); docker restart "$N" >/dev/null
watch 300
check "restart, source down: healthy" "$([ -n "$READY_AT" ] && echo 1 || echo 0)" "${LAST:0:120}"
check "restart, source down: every expected CRL installed when first ready" "$([ -n "$READY_AT" ] && [ $BAD = 0 ] && echo 1 || echo 0)" "ready with ${READY_AT:-?}"
L=$(docker logs "$N" 2>&1)
check "restart: the cache was installed before Keycloak started (0 missing)" "$(grep -qF ": 0 of $EXPECTED expected still missing after installing the cache" <<<"$L" && echo 1 || echo 0)"
sleep 40; M1=$(docker logs "$N" 2>&1 | grep -c STIG-CRL-MISSING || true)
check "restart: no STIG-CRL-MISSING (the start-up window does not open)" "$([ "$M1" -eq "$M0" ] && echo 1 || echo 0)" "$((M1 - M0)) new lines"
cards=$(try_cards)
check "restart: a valid card signs in" "${cards%% *}"
check "restart: a revoked card is refused" "${cards##* }"

# 2b. a slow source (8 s per file, ~19 x 8 s per refresh): ready from the cache, before the first refresh completes
mirror 8
R0=$(docker logs "$N" 2>&1 | grep -c "CRLs refreshed:" || true); docker restart "$N" >/dev/null; S0=$(date +%s)
watch 300; S1=$(date +%s); R1=$(docker logs "$N" 2>&1 | grep -c "CRLs refreshed:" || true)
check "slow source: healthy, every expected CRL installed when first ready" "$([ -n "$READY_AT" ] && [ $BAD = 0 ] && echo 1 || echo 0)" "after $((S1 - S0))s: ${LAST:0:100}"
check "slow source: ready BEFORE the first refresh completed (it does not gate readiness)" \
  "$([ -n "$READY_AT" ] && [ "$R1" -eq "$R0" ] && grep -qF "ready without waiting for the first refresh" <<<"$(docker logs "$N" 2>&1)" && echo 1 || echo 0)" "refreshes logged before/at ready: $R0/$R1"
for i in $(seq 1 150); do R2=$(docker logs "$N" 2>&1 | grep -c "CRLs refreshed:" || true); [ "$R2" -gt "$R1" ] && break; sleep 2; done
check "slow source: ... and that refresh still completes after ready (0 failed)" \
  "$([ "$R2" -gt "$R1" ] && grep "CRLs refreshed:" <<<"$(docker logs "$N" 2>&1)" | tail -1 | grep -q " 0 failed" && echo 1 || echo 0)" "$(docker logs "$N" 2>&1 | grep "CRLs refreshed:" | tail -1 | cut -c1-90)"
s=$(sample)
check "slow source: still ready, every CRL installed, after the refresh" "$([ "${s%% *}" = 0 ] && echo 1 || echo 0)" "${s:0:100}"

# 2c. CAC_APPLY=false, slow source still up, full cache: NOT ready before the first refresh completed
docker rm -f "$N" >/dev/null; run_kc -e CAC_APPLY=false; S0=$(date +%s)
watch 20   # ~60 s: the shortcut made the normal container ready in ~25 s; the refresh takes ~150 s
check "CAC_APPLY=false: no shortcut - not ready while the first refresh runs" \
  "$([ -z "$READY_AT" ] && ! grep -qF "ready without waiting for the first refresh" <<<"$(docker logs "$N" 2>&1)" && echo 1 || echo 0)" "${LAST:0:100}"
watch 300; S1=$(date +%s)
check "CAC_APPLY=false: ready once the first refresh completed" \
  "$([ -n "$READY_AT" ] && [ $BAD = 0 ] && grep -q "CRLs refreshed:" <<<"$(docker logs "$N" 2>&1)" && echo 1 || echo 0)" "after $((S1 - S0))s: ${LAST:0:90}"
docker rm -f "$N" >/dev/null; run_kc; watch 300   # back to the normal container (CAC_APPLY=true) for what follows
check "back to CAC_APPLY=true: healthy" "$([ -n "$READY_AT" ] && echo 1 || echo 0)" "${LAST:0:100}"
docker rm -f "$N-mirror" >/dev/null

# 3. restart with an EMPTY cache and the source down: never healthy; source back -> healthy, all CRLs
docker run --rm --user 0 -v "$VOL:/c" --entrypoint bash "$IMG" -c 'rm -f /c/*.crl'
docker restart "$N" >/dev/null
watch 20
check "empty cache, source down: NOT healthy" "$([ -z "$READY_AT" ] && echo 1 || echo 0)" "${LAST:0:120}"
check "empty cache, source down: health names the missing CRLs" "$(grep -q "CRLs not installed" <<<"$LAST" && echo 1 || echo 0)"
mirror
watch 300
check "source back: healthy after the retry" "$([ -n "$READY_AT" ] && echo 1 || echo 0)" "${LAST:0:120}"
check "source back: every expected CRL installed when first ready" "$([ -n "$READY_AT" ] && [ $BAD = 0 ] && echo 1 || echo 0)" "ready with ${READY_AT:-?}"
check "STIG-CRL-INCOMPLETE logged while CRLs were missing" "$(docker logs "$N" 2>&1 | grep -c STIG-CRL-INCOMPLETE | grep -qv '^0$' && echo 1 || echo 0)"

# 4. DODIDCA_70.crl permanently unavailable (gone from the source and the cache)
rm -f "$T/mirror/DODIDCA_70.crl"
docker run --rm --user 0 -v "$VOL:/c" --entrypoint bash "$IMG" -c 'rm -f /c/DODIDCA_70.crl'
docker restart "$N" >/dev/null; S0=$(date +%s); early=""
for i in $(seq 1 40); do s=$(sample); case "$s" in "1 "*DODIDCA_70.crl*) early="$s"; break;; esac; sleep 2; done
check "one CRL unavailable: not ready within the grace, naming it" "$([ -n "$early" ] && echo 1 || echo 0)" "${early:0:120}"
watch 300; S1=$(date +%s)
check "one CRL unavailable: ready DEGRADED after the ${GRACE}s grace (not out of service)" \
  "$([ -n "$READY_AT" ] && [ $((S1 - S0)) -ge $((GRACE - 15)) ] && grep -q "ready DEGRADED: 1 of $EXPECTED CRLs not installed: DODIDCA_70.crl" <<<"$LAST" && echo 1 || echo 0)" "after $((S1 - S0))s: ${LAST:0:110}"
n70=$(docker logs "$N" 2>&1 | grep STIG-CRL-INCOMPLETE | grep -c DODIDCA_70.crl || true)
check "... and keeps naming it while it retries (STIG-CRL-INCOMPLETE ... DODIDCA_70.crl)" "$([ "${n70:-0}" -gt 0 ] && echo 1 || echo 0)" "$n70 lines"
cards=$(try_cards)
check "ready DEGRADED: a valid card still signs in (its issuer's CRL is there)" "${cards%% *}"
# a card whose issuer's CRL is missing is refused: the lab issuing CA's CRL taken away (no DoD test card exists)
docker exec "$N" sh -c 'rm -f /opt/keycloak/data/cac/crl/test-id-ca.crl'; sleep 35
cards=$(try_cards)
check "ready DEGRADED: a card whose issuer's CRL is missing is refused (fail closed)" "$([ "${cards%% *}" = 0 ] && echo 1 || echo 0)"
s=$(sample)
check "... while the container still reports ready" "$([ "${s%% *}" = 0 ] && echo 1 || echo 0)" "${s:0:100}"

for r in "${res[@]}"; do [ "$r" = 1 ] || { docker logs "$N" 2>&1 | grep -E "^keycloak-cac|^cac-pki|ERROR" | tail -15; exit 1; }; done
echo "all ${#res[@]} checks passed"

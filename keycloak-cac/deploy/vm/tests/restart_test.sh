#!/bin/sh
# host/restart.sh (idp-restart): checks before it changes anything, derives the images.lock keycloak line from
# `docker image inspect` of the new tag (never the old image's ID with the new tag), recreates, waits for healthy and
# refuses a container that runs another image. Runs as root in a scratch directory with stubbed docker / idp-admin.py /
# idp-egress - it never touches /srv/idp or the running stack.
#   sudo sh restart_test.sh <path to restart.sh>
set -u
H=${1:?usage: restart_test.sh <restart.sh>}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
PASS=0; FAIL=0; ok() { PASS=$((PASS+1)); echo "PASS  $1"; }; no() { FAIL=$((FAIL+1)); echo "FAIL  $1"; }
mkdir -p "$W/srv/compose" "$W/bin"; touch "$W/srv/compose/compose.yaml"
OLDID=sha256:1111111111111111111111111111111111111111111111111111111111111111
NEWID=sha256:2222222222222222222222222222222222222222222222222222222222222222
PGD=docker.io/library/postgres@sha256:3333333333333333333333333333333333333333333333333333333333333333
# docker stub: two local images; the container runs whatever was last "up"/"restart"ed ($W/running), healthy at once
cat > "$W/bin/docker" <<EOF
#!/bin/sh
echo "docker \$*" >> "$W/calls"
case "\$*" in
  "image inspect -f {{.Id}} idp/keycloak-cac:26.8.2-fips-aaaaaaa") echo $OLDID;;
  "image inspect -f {{.Id}} idp/keycloak-cac:26.8.2-fips-bbbbbbb") echo $NEWID;;
  "image inspect -f {{.Id}} "*) echo "Error: No such image" >&2; exit 1;;
  "image inspect -f {{index .Config.Labels \"org.opencontainers.image.revision\"}} idp/keycloak-cac:26.8.2-fips-bbbbbbb") echo bbbbbbbcafe;;
  "image inspect -f "*) echo "<no value>";;
  compose*" up -d --no-deps keycloak") sed -n 's/^KEYCLOAK_IMAGE=//p' "$W/srv/compose/.env" > "$W/running";;
  compose*" restart keycloak") : ;;
  "inspect -f {{.Image}} "*) case "\$(cat "$W/running")" in *bbbbbbb) echo \${STUB_RUN_ID:-$NEWID};; *) echo $OLDID;; esac;;
  "inspect -f "*Health.Status*) echo \${STUB_HEALTH:-healthy};;
  "inspect -f {{.State.Running}} "*) echo true;;
  "inspect -f "*Health.Log*) echo "\${STUB_HEALTH_OUT:-not ready: 2 of 20 CRLs not installed: DODIDCA_70.crl DODROOTCA6.crl}";;
  exec*) echo 20;;
esac
EOF
printf '#!/bin/sh\necho "adm $*" >> %s/calls; [ -z "${STUB_DRIFT:-}" ] || { echo "DRIFT app-a"; exit 1; }; echo "no drift"\n' "$W" > "$W/bin/adm"
printf '#!/bin/sh\necho "egress $*" >> %s/calls; [ -z "${STUB_NOEGRESS:-}" ] || exit 1\n' "$W" > "$W/bin/egress"
chmod +x "$W/bin/docker" "$W/bin/adm" "$W/bin/egress"
reset() {
  rm -f "$W/calls" "$W"/srv/compose/*.prev-* "$W"/srv/compose/.env.prev-*; echo idp/keycloak-cac:26.8.2-fips-aaaaaaa > "$W/running"
  printf 'KEYCLOAK_IMAGE=idp/keycloak-cac:26.8.2-fips-aaaaaaa\nPOSTGRES_IMAGE=%s\n' "$PGD" > "$W/srv/compose/.env"
  printf '# image IDs (content digests) in use, written 2026-01-01T00:00:00Z\nkeycloak-asd-stig commit: aaaaaaa0000\nidp/keycloak-cac:26.8.2-fips-aaaaaaa %s\n%s\n' "$OLDID" "$PGD" > "$W/srv/compose/images.lock"
}
run() { PATH="$W/bin:$PATH" IDP_SRV="$W/srv" IDP_ADMIN="$W/bin/adm" IDP_EGRESS="$W/bin/egress" IDP_RESTART_TIMEOUT=10 sh "$H" "$@" 2>"$W/err"; }

reset; run; rc=$?
[ $rc -eq 0 ] && grep -q "compose .* restart keycloak" "$W/calls" && ! grep -q " up -d" "$W/calls" && ok "plain restart: compose restart, healthy, exit 0" || no "plain restart (rc=$rc) $(cat "$W/err")"
[ "$(stat -c '%u:%g %a' "$W/srv/crl-cache")" = "1000:1000 750" ] && ok "crl-cache ensured 1000:1000 0750" || no "crl-cache $(stat -c '%u:%g %a' "$W/srv/crl-cache" 2>&1)"
head -1 "$W/calls" | grep -q "^egress --check" && sed -n 2p "$W/calls" | grep -q "^adm check-clients" && ok "egress check, then check-clients, before docker" || no "order: $(head -3 "$W/calls" | tr '\n' '|')"
! grep -q "systemctl" "$W/calls" && ok "idp-egress.service is never restarted" || no "systemctl called"

reset; run --image idp/keycloak-cac:26.8.2-fips-bbbbbbb; rc=$?
L="$W/srv/compose/images.lock"
[ $rc -eq 0 ] && grep -q "compose .* up -d --no-deps keycloak" "$W/calls" && ok "--image: recreated, healthy, exit 0" || no "--image (rc=$rc) $(cat "$W/err")"
grep -qx "KEYCLOAK_IMAGE=idp/keycloak-cac:26.8.2-fips-bbbbbbb" "$W/srv/compose/.env" && grep -qx "POSTGRES_IMAGE=$PGD" "$W/srv/compose/.env" && ok "--image: .env names the new tag, PostgreSQL untouched" || no ".env: $(cat "$W/srv/compose/.env")"
grep -qx "idp/keycloak-cac:26.8.2-fips-bbbbbbb $NEWID" "$L" && ok "--image: lock pairs the NEW tag with the NEW tag's own image ID" || no "lock: $(cat "$L")"
! grep -q "$OLDID" "$L" && ! grep -q "fips-aaaaaaa" "$L" && [ "$(grep -c keycloak-cac "$L")" = 1 ] && ok "--image: no old keycloak line or ID left" || no "lock stale: $(cat "$L")"
! grep -q ROLLBACK "$W/err" && ok "--image, healthy: no rollback line" || no "--image healthy printed ROLLBACK"
grep -qx "$PGD" "$L" && grep -qx "keycloak-asd-stig commit: bbbbbbbcafe" "$L" && ok "--image: PostgreSQL digest kept, commit line from the image's revision label" || no "lock rest: $(cat "$L")"

reset; run --image idp/keycloak-cac:nope; rc=$?
[ $rc -ne 0 ] && grep -qx "KEYCLOAK_IMAGE=idp/keycloak-cac:26.8.2-fips-aaaaaaa" "$W/srv/compose/.env" && grep -q "$OLDID" "$W/srv/compose/images.lock" \
  && ! grep -q "compose" "$W/calls" && ok "unknown tag: refused, .env and lock unchanged, nothing restarted" || no "unknown tag (rc=$rc)"

reset; STUB_RUN_ID=$OLDID run --image idp/keycloak-cac:26.8.2-fips-bbbbbbb; rc=$?
[ $rc -ne 0 ] && grep -q "runs $OLDID" "$W/err" && ok "container runs another image than the lock names: exit 1" || no "image mismatch (rc=$rc) $(cat "$W/err")"

reset; STUB_DRIFT=1 run; rc=$?
[ $rc -ne 0 ] && ! grep -q "compose" "$W/calls" && ok "check-clients drift: refused, nothing restarted" || no "drift (rc=$rc)"
reset; STUB_NOEGRESS=1 run; rc=$?
[ $rc -ne 0 ] && ! grep -q "compose\|adm" "$W/calls" && grep -q "never restart idp-egress.service" "$W/err" && ok "egress rules missing: refused, points at 'sudo idp-egress'" || no "egress (rc=$rc)"

reset; STUB_HEALTH=unhealthy run; rc=$?
[ $rc -ne 0 ] && grep -q "not healthy after" "$W/err" && grep -q "CRLs not installed" "$W/err" && ok "never healthy (CRLs missing): exit 1 with the health output" || no "unhealthy (rc=$rc) $(cat "$W/err")"
grep -q "only the cards of" "$W/err" && grep -q "Do not roll back a good image" "$W/err" && ok "timeout: says sign-in may be serving and only the missing CAs' cards are refused" || no "timeout note"
! grep -q ROLLBACK "$W/err" && [ -z "$(ls "$W"/srv/compose/*.prev-* "$W"/srv/compose/.env.prev-* 2>/dev/null)" ] && ok "plain restart failing: no .prev copies, no rollback line (nothing was swapped)" || no "plain restart rollback"

# an unhealthy NEW image: the previous .env / images.lock are kept as .prev-<ts> and the rollback is printed
reset; STUB_HEALTH=unhealthy run --image idp/keycloak-cac:26.8.2-fips-bbbbbbb; rc=$?
PE=$(ls "$W"/srv/compose/.env.prev-* 2>/dev/null); PL=$(ls "$W"/srv/compose/images.lock.prev-* 2>/dev/null)
[ $rc -ne 0 ] && [ -n "$PE" ] && [ -n "$PL" ] && grep -qx "KEYCLOAK_IMAGE=idp/keycloak-cac:26.8.2-fips-aaaaaaa" "$PE" && grep -q "fips-aaaaaaa $OLDID" "$PL" \
  && ok "--image, unhealthy: .env.prev-<ts> and images.lock.prev-<ts> hold the previous pair" || no "--image unhealthy prev (rc=$rc): $PE $PL"
grep "ROLLBACK" "$W/err" | grep -qF "ROLLBACK (only if the image itself is at fault): cp -p $PE $W/srv/compose/.env && cp -p $PL $W/srv/compose/images.lock && docker compose" \
  && grep "ROLLBACK" "$W/err" | grep -q "up -d --no-deps keycloak" && grep "ROLLBACK" "$W/err" | grep -q "idp-restart --image idp/keycloak-cac:26.8.2-fips-aaaaaaa" \
  && [ "$(grep -c ROLLBACK "$W/err")" = 1 ] && ok "--image, unhealthy: one rollback line (cp -p both .prev files + up -d, or idp-restart --image <old tag>)" || no "rollback line: $(grep ROLLBACK "$W/err")"
# ...and it works: applying the printed copies restores the previous pair exactly
(cd / && cp -p "$PE" "$W/srv/compose/.env" && cp -p "$PL" "$W/srv/compose/images.lock")
grep -qx "KEYCLOAK_IMAGE=idp/keycloak-cac:26.8.2-fips-aaaaaaa" "$W/srv/compose/.env" && grep -qx "idp/keycloak-cac:26.8.2-fips-aaaaaaa $OLDID" "$W/srv/compose/images.lock" \
  && ok "the rollback copies restore the previous tag with its own ID" || no "rollback restore"
reset; STUB_RUN_ID=$OLDID run --image idp/keycloak-cac:26.8.2-fips-bbbbbbb; rc=$?
[ $rc -ne 0 ] && grep -q ROLLBACK "$W/err" && ok "--image, container runs another image: rollback printed too" || no "mismatch rollback"

# the .prev copies are pruned to the last 5 of each
reset; for t in 20260101T000001Z 20260101T000002Z 20260101T000003Z 20260101T000004Z 20260101T000005Z 20260101T000006Z 20260101T000007Z; do
  echo old > "$W/srv/compose/.env.prev-$t"; echo old > "$W/srv/compose/images.lock.prev-$t"; done
run --image idp/keycloak-cac:26.8.2-fips-bbbbbbb; rc=$?
ne=$(ls "$W"/srv/compose/.env.prev-* | wc -l); nl=$(ls "$W"/srv/compose/images.lock.prev-* | wc -l)
[ $rc -eq 0 ] && [ "$ne" -eq 5 ] && [ "$nl" -eq 5 ] && [ ! -e "$W/srv/compose/.env.prev-20260101T000003Z" ] && [ -e "$W/srv/compose/.env.prev-20260101T000004Z" ] \
  && grep -qx "KEYCLOAK_IMAGE=idp/keycloak-cac:26.8.2-fips-aaaaaaa" "$(ls "$W"/srv/compose/.env.prev-* | sort | tail -1)" \
  && ok ".prev copies pruned to the last 5 of each; the newest is the pair just replaced" || no "prune: $ne $nl $(ls -A "$W/srv/compose")"

# healthy but DEGRADED (past CAC_CRL_READY_GRACE, a CRL still missing): waits for the full set, then warns, exit 0
reset; STUB_HEALTH_OUT="ready DEGRADED: 1 of 20 CRLs not installed: DODIDCA_70.crl - cards of those CAs are refused until they arrive" \
  run --image idp/keycloak-cac:26.8.2-fips-bbbbbbb; rc=$?
[ $rc -eq 0 ] && grep -q "WARN healthy but DEGRADED after 10s" "$W/err" && grep -q "DODIDCA_70.crl" "$W/err" && grep -q "do not roll back" "$W/err" \
  && ! grep -q ROLLBACK "$W/err" && ok "healthy DEGRADED (a CRL source outage): waited the full timeout, names the CRL, exit 0, no rollback" || no "degraded (rc=$rc) $(cat "$W/err")"

echo; echo "$PASS passed, $FAIL failed"; [ $FAIL -eq 0 ]

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
  "inspect -f "*Health.Log*) echo "not ready: 2 of 20 CRLs not installed: DODIDCA_70.crl DODROOTCA6.crl";;
  exec*) echo 20;;
esac
EOF
printf '#!/bin/sh\necho "adm $*" >> %s/calls; [ -z "${STUB_DRIFT:-}" ] || { echo "DRIFT app-a"; exit 1; }; echo "no drift"\n' "$W" > "$W/bin/adm"
printf '#!/bin/sh\necho "egress $*" >> %s/calls; [ -z "${STUB_NOEGRESS:-}" ] || exit 1\n' "$W" > "$W/bin/egress"
chmod +x "$W/bin/docker" "$W/bin/adm" "$W/bin/egress"
reset() {
  rm -f "$W/calls"; echo idp/keycloak-cac:26.8.2-fips-aaaaaaa > "$W/running"
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

echo; echo "$PASS passed, $FAIL failed"; [ $FAIL -eq 0 ]

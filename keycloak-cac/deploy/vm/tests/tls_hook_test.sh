#!/bin/sh
# host/tls-deploy-hook.sh restarts Keycloak only when check-clients reports no drift; otherwise it installs the
# certificate, does NOT restart, alerts, and exits 1. Runs as root (install -o root -g 1000) in a scratch directory
# with stubbed docker / idp-admin.py / idp-alert - it never touches /srv/idp or the running stack.
#   sudo sh tls_hook_test.sh <path to tls-deploy-hook.sh>
set -u
H=${1:?usage: tls_hook_test.sh <tls-deploy-hook.sh>}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
PASS=0; FAIL=0; ok() { PASS=$((PASS+1)); echo "PASS  $1"; }; no() { FAIL=$((FAIL+1)); echo "FAIL  $1"; }
mkdir -p "$W/srv/tls" "$W/srv/compose" "$W/live" "$W/bin"; touch "$W/srv/compose/compose.yaml" "$W/srv/compose/.env"
echo CERT > "$W/live/fullchain.pem"; echo KEY > "$W/live/privkey.pem"
printf '#!/bin/sh\necho "docker $*" >> %s/calls\n' "$W" > "$W/bin/docker"
printf '#!/bin/sh\necho "alert $*" >> %s/calls; cat >> %s/alert-body\n' "$W" "$W" > "$W/bin/alert"
chmod +x "$W/bin/docker" "$W/bin/alert"
run() {  # run <check-clients exit code> <its output>
  rm -f "$W/calls" "$W/alert-body" "$W/srv/tls/tls.crt" "$W/srv/tls/tls.key"
  printf '#!/bin/sh\necho "%s"\nexit %s\n' "$2" "$1" > "$W/bin/adm"; chmod +x "$W/bin/adm"
  PATH="$W/bin:$PATH" RENEWED_LINEAGE="$W/live" IDP_SRV="$W/srv" IDP_ADMIN="$W/bin/adm" IDP_ALERT="$W/bin/alert" sh "$H" 2>/dev/null
}
run 0 "check-clients: no drift"; rc=$?
[ $rc -eq 0 ] && grep -q "docker compose .* restart keycloak" "$W/calls" && ! grep -q alert "$W/calls" \
  && ok "no drift: certificate installed, Keycloak restarted, no alert" || no "no drift (rc=$rc)"
[ "$(cat "$W/srv/tls/tls.crt")" = CERT ] && [ "$(stat -c %a "$W/srv/tls/tls.key")" = 440 ] && ok "certificate and key installed (0440)" || no "install"
run 1 "DRIFT app-a: live differs from its host file"; rc=$?
[ $rc -eq 1 ] && ! grep -q "restart" "$W/calls" && grep -q "alert idp-tls -" "$W/calls" && grep -q "NOT restarted" "$W/alert-body" \
  && grep -q "DRIFT app-a" "$W/alert-body" && ok "drift: NO restart, alert carries the drift lines, exit 1" || no "drift (rc=$rc)"
[ "$(cat "$W/srv/tls/tls.crt")" = CERT ] && ok "drift: the renewed certificate is still installed" || no "drift: certificate"
run 2 "usage: idp-admin.py ... invalid choice: 'check-clients'"; rc=$?
[ $rc -eq 1 ] && ! grep -q "restart" "$W/calls" && grep -q "alert idp-tls -" "$W/calls" && ok "check-clients cannot run (old helper): NO restart, alert" || no "check fails (rc=$rc)"
rm -f "$W/calls"; PATH="$W/bin:$PATH" RENEWED_LINEAGE="$W/live" IDP_SRV="$W/srv" IDP_ADMIN="$W/bin/adm" IDP_ALERT="$W/bin/alert" IDP_NO_RESTART=1 sh "$H"
[ $? -eq 0 ] && [ ! -f "$W/calls" ] && ok "IDP_NO_RESTART (setup-host): installs only, no check, no restart" || no "IDP_NO_RESTART"
echo; echo "$PASS passed, $FAIL failed"; [ $FAIL -eq 0 ]

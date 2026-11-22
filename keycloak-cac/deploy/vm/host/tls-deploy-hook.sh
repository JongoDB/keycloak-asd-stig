#!/bin/sh
# certbot deploy hook: install the renewed certificate for Keycloak (root:1000 0440) and restart Keycloak, because
# the strict-FIPS image converts the certificate to BCFKS at start (Keycloak's own hourly reload does not apply).
set -eu
# IDP_SRV / IDP_ADMIN / IDP_ALERT exist for tests/tls_hook_test.sh only; certbot never sets them.
S="${IDP_SRV:-/srv/idp}"; ADM="${IDP_ADMIN:-/usr/local/sbin/idp-admin.py}"; ALERT="${IDP_ALERT:-/usr/local/sbin/idp-alert}"
L="${RENEWED_LINEAGE:?}"; T=$S/tls
install -o root -g 1000 -m 0440 "$L/fullchain.pem" "$T/tls.crt.new" && mv -f "$T/tls.crt.new" "$T/tls.crt"
install -o root -g 1000 -m 0440 "$L/privkey.pem" "$T/tls.key.new" && mv -f "$T/tls.key.new" "$T/tls.key"
# A restart re-applies every /srv/idp/clients/*.json over the live clients (a stale file has broken production sign-in
# before). So restart only when check-clients finds no drift. On drift - or if the check cannot run - the new
# certificate stays installed but Keycloak keeps serving the previous one (renewal runs ~30 days before expiry), and
# the operator is alerted to fix the drift and restart by hand (README, "TLS certificate").
if [ -z "${IDP_NO_RESTART:-}" ] && [ -f "$S/compose/compose.yaml" ]; then
  if out=$("$ADM" check-clients 2>&1); then
    docker compose -f "$S/compose/compose.yaml" --env-file "$S/compose/.env" restart keycloak
  else
    msg="idp-tls: the renewed certificate for $(basename "$L") is installed, but Keycloak was NOT restarted: check-clients reported drift or could not run (below). Keycloak keeps serving the previous certificate. Fix the drift (docs/vm-accounts.md, add-client), confirm 'sudo idp-admin.py check-clients' says no drift, then: docker compose -f /srv/idp/compose/compose.yaml --env-file /srv/idp/compose/.env restart keycloak"
    logger -t idp-tls "$msg" 2>/dev/null || true
    printf '%s\n\n%s\n' "$msg" "$out" | "$ALERT" idp-tls - >/dev/null 2>&1 || logger -t idp-tls "alert mail could not be sent"
    printf '%s\n%s\n' "$msg" "$out" >&2
    exit 1
  fi
fi

#!/usr/bin/env bash
# Black-box checks of the live IdP WITHOUT a card, run ON the VM as root. Creates dedicated test users (passwords
# generated here, never printed), runs the checks in a throwaway container of the deployed image, then DISABLES
# the users. Card checks (CAC login, revoked/unmapped card, Alt Token) need a real card.
#   sudo E2E_CLIENT=<client id> E2E_REDIRECT=<its registered redirect URI> [E2E_ROLE=<client role>] ./run-e2e.sh [out-dir]
# The client must exist (a confidential client-secret client) and E2E_REDIRECT must be one of its redirect URIs.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; O="${1:-/root/idp-e2e}"; S=/srv/idp
. <(grep -E '^(CAC_REALM|CAC_PUBLIC_URL)=' $S/config/keycloak-cac.env)
IMG=$(grep -E "^KEYCLOAK_(ADMIN_)?IMAGE=" $S/compose/.env | head -1 | cut -d= -f2)
CLIENT="${E2E_CLIENT:?set E2E_CLIENT}"; REDIRECT="${E2E_REDIRECT:?set E2E_REDIRECT}"; ROLE="${E2E_ROLE:-student}"
rm -rf "$O"; mkdir -p "$O/s"; chmod 700 "$O/s"; cp "$HERE"/*.py "$O/"
pw() { ( umask 077; printf 'Aa1!%s' "$(openssl rand -hex 12)" > "$O/s/$1" ); }
pw pw.temp; pw pw.new; pw lock.pw; pw sess.temp; pw sess.new
idp-admin.py client-secret $CLIENT > "$O/s/client_secret"
STAMP=$(date +%H%M%S)
U_PW=e2e.pw.$STAMP; U_LOCK=e2e.lock.$STAMP; U_SESS=e2e.sess.$STAMP; U_HDR=e2e.hdr.$STAMP
idp-admin.py user-create-pw $U_PW   $U_PW@e2e.invalid   E2E Password $CLIENT:$ROLE --temp-password-file "$O/s/pw.temp" --temporary
idp-admin.py user-create-pw $U_LOCK $U_LOCK@e2e.invalid E2E Lockout  $CLIENT:$ROLE --temp-password-file "$O/s/lock.pw"
idp-admin.py user-create-pw $U_SESS $U_SESS@e2e.invalid E2E Sessions $CLIENT:$ROLE --temp-password-file "$O/s/sess.temp" --temporary
idp-admin.py user-create-cac $U_HDR 1234567890 $U_HDR@e2e.invalid E2E Header $CLIENT:$ROLE
# a certificate that WOULD map to $U_HDR (CN ends in its EDIPI) - only ever sent as a forged header
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj "/CN=TEST.HEADER.E.1234567890" \
  -keyout "$O/s/forged.key" -out "$O/forged.crt" 2>/dev/null
chown -R 1000:1000 "$O"
RUN=(docker run --rm --network host --user 1000:1000 --read-only --tmpfs /tmp --entrypoint python3
     --add-host "$(echo "$CAC_PUBLIC_URL" | sed 's#https://##')":127.0.0.1 -v "$O":/e "$IMG")
CA=/etc/pki/tls/certs/ca-bundle.crt
set +e
{
echo "== e2e_check.py (keycloak-asd-stig, pinned image) - password+TOTP path, lockout, banner"
"${RUN[@]}" /opt/kcstig/scripts/e2e_check.py --url "$CAC_PUBLIC_URL" --realm "$CAC_REALM" --client $CLIENT --redirect $REDIRECT \
   --client-secret "$(cat "$O/s/client_secret")" --cacert $CA \
   --pw-user $U_PW --pw-temp-password "$(cat "$O/s/pw.temp")" --pw-new-password "$(cat "$O/s/pw.new")" \
   --lockout-user $U_LOCK --lockout-password "$(cat "$O/s/lock.pw")"
echo; echo "== pw_session_limit.py - concurrent session limit on the password+TOTP path"
"${RUN[@]}" /e/pw_session_limit.py --url "$CAC_PUBLIC_URL" --realm "$CAC_REALM" --client $CLIENT --redirect $REDIRECT --cacert $CA \
   --client-secret-file /e/s/client_secret --user $U_SESS --temp-password-file /e/s/sess.temp --new-password-file /e/s/sess.new --limit 3
echo; echo "== forged_header_check.py - a client-certificate header must never sign anyone in"
"${RUN[@]}" /e/forged_header_check.py --url "$CAC_PUBLIC_URL" --direct "$CAC_PUBLIC_URL" --realm "$CAC_REALM" \
   --client $CLIENT --redirect $REDIRECT --cacert $CA --forged-cert /e/forged.crt
} 2>&1 | sed -E 's/(client-secret|password)[= ][^ ]+/\1 <redacted>/g' | tee "$O/e2e-results.txt"
set -e
for u in $U_PW $U_LOCK $U_SESS $U_HDR; do idp-admin.py user-enable $u false; done
rm -rf "$O/s"
echo "test users disabled: $U_PW $U_LOCK $U_SESS $U_HDR"

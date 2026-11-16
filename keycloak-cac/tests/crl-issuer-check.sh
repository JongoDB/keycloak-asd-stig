#!/usr/bin/env bash
# Drives stig-x509-client-username-form end to end (lab mode, OCSP off, so the local CRL check alone decides):
#   1. a valid card signs in and a revoked card is refused;
#   2. the CRL file is swapped (as crl-sync / crl-fetch do) to revoke the valid card: the NEXT sign-in refuses it,
#      with no clear-crl-cache call (IssuerCrlCheck keys its cache on the file version);
#   3. the ROOT's CRL revokes the issuing CA: every card of that CA is refused (intermediate revocation, V-222550);
#   4. the root CRL is restored: a card of that CA signs in again.
# Keycloak's own CRL step is switched off by this authenticator, so if IssuerCrlCheck were not called, 1-3 would fail.
#   keycloak-cac/tests/crl-issuer-check.sh <image>
set -euo pipefail
IMG="${1:?image}"; ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; PORT="${CRL_TEST_PORT:-18462}"
T="$(mktemp -d)"; NAME="kcc-crl-issuer-$$"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$T"; }; trap cleanup EXIT
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8443" -e CAC_LAB_MODE=true -e KC_DB=dev-file -e CAC_OCSP=false \
  -e CAC_PUBLIC_URL="https://localhost:$PORT" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap -e KC_BOOTSTRAP_ADMIN_PASSWORD=crl-issuer-bootstrap-pw "$IMG" >/dev/null
for i in $(seq 1 120); do
  docker exec "$NAME" /opt/keycloak-cac/bin/cac-entrypoint.sh health >/dev/null 2>&1 && break
  docker inspect -f '{{.State.Running}}' "$NAME" | grep -q true || { docker logs "$NAME" 2>&1 | tail -20; echo "FAIL container stopped"; exit 1; }
  sleep 5
done
L=/opt/keycloak/data/cac/lab
for f in ca/root.crt users/doe.john.crt users/doe.john.key users/roe.jane.crt users/roe.jane.key users/revoked.crt users/revoked.key; do
  docker exec "$NAME" cat "$L/$f" > "$T/$(basename "$f")"
done
python3 - "$ROOT/keycloak-asd-stig/scripts" "$T" "$PORT" "$NAME" <<'PY'
import argparse, subprocess, sys
sys.path.insert(0, sys.argv[1]); import e2e_check as E
T, PORT, NAME = sys.argv[2], sys.argv[3], sys.argv[4]
BASE = "https://localhost:%s" % PORT; RED = BASE + "/realms/dod-cac/account/"
fl = E.Flow(argparse.Namespace(url=BASE, realm="dod-cac", client="account-console", redirect=RED, admin_url=None, client_secret=None, cacert=T + "/root.crt"))
L = "/opt/keycloak/data/cac/lab"
res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s %-78s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)
def signs_in(user):
    b, final, seen, banner, ver = E.cac_login(fl, "%s/%s.crt" % (T, user), "%s/%s.key" % (T, user))
    return bool(final and "code=" in final)
def sh(cmd):
    subprocess.run(["docker", "exec", NAME, "bash", "-c", "export SAN=x UPN=x EMAIL=x OCSP_URL=x; cd %s && %s" % (L, cmd)], check=True, capture_output=True)
def install(src, name):
    sh("cp %s /opt/keycloak/data/cac/crl/.%s.new && mv -f /opt/keycloak/data/cac/crl/.%s.new /opt/keycloak/data/cac/crl/%s" % (src, name, name, name))
check("valid card signs in", signs_in("doe.john"))
check("revoked card is refused", not signs_in("revoked"))
sh("openssl ca -config ca/openssl.cnf -cert ca/idca.crt -keyfile ca/idca.key -revoke users/doe.john.crt -crl_reason keyCompromise"
   " && openssl ca -config ca/openssl.cnf -cert ca/idca.crt -keyfile ca/idca.key -gencrl -out /tmp/id.crl")
install("/tmp/id.crl", "test-id-ca.crl")
check("after the issuing CA's CRL is swapped, the newly revoked card is refused", not signs_in("doe.john"))
check("... and another card of that CA still signs in", signs_in("roe.jane"))
sh("cp conf/crl/test-root-ca.crl /tmp/root-ok.crl && openssl ca -config ca/openssl.cnf -name rootca -cert ca/root.crt -keyfile ca/root.key"
   " -revoke ca/idca.crt -crl_reason cACompromise && openssl ca -config ca/openssl.cnf -name rootca -cert ca/root.crt -keyfile ca/root.key -gencrl -out /tmp/root.crl")
install("/tmp/root.crl", "test-root-ca.crl")
check("root CRL revokes the issuing CA: its valid card is refused", not signs_in("roe.jane"))
install("/tmp/root-ok.crl", "test-root-ca.crl")
check("root CRL restored: the card signs in again", signs_in("roe.jane"))
logs = subprocess.run(["docker", "logs", NAME], capture_output=True, text=True); logs = logs.stdout + logs.stderr
check("no clear-crl-cache was needed (file mode never calls it)", "clear-crl-cache" not in logs)
check("refusals came from the issuer-scoped check", "Certificate has been revoked" in logs)
sys.exit(0 if all(res) else 1)
PY

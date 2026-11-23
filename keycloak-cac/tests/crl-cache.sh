#!/usr/bin/env bash
# CAC_CRL_CACHE_DIR and readiness, offline (no Keycloak):
#   crl-save keeps exactly the expected, installed CRLs in the cache (no lab or retired-CA CRL, nothing half-written);
#   a new container's crl-sync from the cache installs only CRLs that verify against the CURRENT anchors;
#   cac-health.py is not ready while any expected CRL is missing, names it, and CAC_READY_REQUIRES_CRLS=false lifts only that.
set -euo pipefail
B="$(cd "$(dirname "$0")/../bin" && pwd)"; PKI="$B/cac-pki.sh"; T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT; cd "$T"
mkdir anchors crl cache newcrl data data/crl; fail=0
pass() { echo "PASS $1"; }; no() { echo "FAIL $1"; fail=1; }
for ca in DODIDCA_70 DODROOTCA6 RETIRED LAB; do
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=$ca" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -keyout $ca.key -out $ca.pem 2>/dev/null
  : > index.txt; echo 01 > crlnum
  printf '[ca]\ndefault_ca=c\n[c]\ndatabase=index.txt\ncrlnumber=crlnum\ndefault_md=sha256\ndefault_crl_days=1\n' > ca.cnf
  openssl ca -config ca.cnf -gencrl -keyfile $ca.key -cert $ca.pem -out $ca.crl.pem 2>/dev/null
  openssl crl -in $ca.crl.pem -outform DER -out crl/$ca.crl
done
cp DODIDCA_70.pem DODROOTCA6.pem LAB.pem anchors/
printf 'DODIDCA_70.crl\nDODROOTCA6.crl\n' > names.txt

# 1. save: the expected CRLs only; a stale cache entry (retired CA, no longer expected) is removed
cp crl/RETIRED.crl cache/RETIRED.crl; touch cache/.DODIDCA_70.crl.new
bash "$PKI" crl-save crl cache names.txt 2>/dev/null
[ "$(cd cache && ls -A | sort | tr '\n' ' ')" = "DODIDCA_70.crl DODROOTCA6.crl " ] \
  && pass "crl-save: the cache holds exactly the expected installed CRLs" || no "crl-save: $(ls -A cache)"
[ "$(sha256sum < crl/DODIDCA_70.crl)" = "$(sha256sum < cache/DODIDCA_70.crl)" ] && pass "crl-save: byte-identical copy" || no "crl-save copy"
bash "$PKI" crl-save crl cache names.txt 2>&1 | grep -q ": 0 written, 0 removed, 2 held" \
  && pass "crl-save again: unchanged CRLs are not rewritten (no diffutils in the image: compared by SHA-256)" || no "crl-save rewrote unchanged files"
rm crl/DODROOTCA6.crl; bash "$PKI" crl-save crl cache names.txt 2>/dev/null
[ ! -e cache/DODROOTCA6.crl ] && pass "crl-save: a CRL pruned from the live directory leaves the cache too" || no "crl-save kept a pruned CRL"
cp DODROOTCA6.crl.pem crl/DODROOTCA6.crl; bash "$PKI" crl-save crl cache names.txt 2>/dev/null

# 2. a new container: install from the cache, anchors changed since (DODROOTCA6 retired from the image)
mkdir anchors2; cp DODIDCA_70.pem anchors2/
bash "$PKI" crl-sync cache anchors2 newcrl 2>/dev/null
[ -f newcrl/DODIDCA_70.crl ] && [ ! -e newcrl/DODROOTCA6.crl ] \
  && pass "crl-sync from the cache: only CRLs of CURRENT anchors are installed" || no "crl-sync: $(ls newcrl)"

# 3. readiness: .applied/.crl-loaded set, Keycloak itself unreachable here - so a CRL failure must be reported FIRST
D=data; touch $D/.applied $D/.crl-loaded; cp names.txt $D/.crl-required; cp crl/DODIDCA_70.crl $D/crl/
health() { CAC_PKI_DIR=$D KC_HTTP_MANAGEMENT_PORT=1 python3 "$B/cac-health.py"; }
out=$(health) && no "health ready with a CRL missing" || true
echo "$out" | grep -q "not ready: 1 of 2 CRLs not installed: DODROOTCA6.crl" && pass "health: not ready, names the missing CRL" || no "health: $out"
: > $D/crl/DODROOTCA6.crl; out=$(health) || true
echo "$out" | grep -q "DODROOTCA6.crl" && pass "health: an empty (half-written) CRL counts as missing" || no "health empty: $out"
cp crl/DODROOTCA6.crl $D/crl/; out=$(health) || true
echo "$out" | grep -q "CRLs not installed" && no "health still reports CRLs: $out" || pass "health: every expected CRL installed -> the CRL condition passes (then Keycloak's own readiness is asked)"
rm $D/crl/DODROOTCA6.crl; out=$(CAC_READY_REQUIRES_CRLS=false health) || true
echo "$out" | grep -q "CRLs not installed" && no "CAC_READY_REQUIRES_CRLS=false: $out" || pass "CAC_READY_REQUIRES_CRLS=false: a missing CRL no longer blocks readiness"
rm $D/.crl-required; out=$(health) || true
echo "$out" | grep -q "CRLs not installed" && no "no .crl-required (file/ocsp mode): $out" || pass "no .crl-required (file, ocsp, none modes): unchanged behavior"
exit $fail

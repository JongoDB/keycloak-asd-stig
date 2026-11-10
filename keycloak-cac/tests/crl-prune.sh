#!/usr/bin/env bash
# A CRL whose issuer is no longer a trust anchor must be removed (Keycloak refuses EVERY card while one is configured):
# crl-prune, and crl-sync/crl-fetch through it, keep CRLs of current anchors and delete the rest.
set -euo pipefail
PKI="$(cd "$(dirname "$0")/../bin" && pwd)/cac-pki.sh"; T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT; cd "$T"
mkdir anchors crl src; fail=0
for ca in kept retired; do
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=$ca" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -keyout $ca.key -out $ca.pem 2>/dev/null
  : > index.txt; echo 01 > crlnum
  printf '[ca]\ndefault_ca=c\n[c]\ndatabase=index.txt\ncrlnumber=crlnum\ndefault_md=sha256\ndefault_crl_days=1\n' > ca.cnf
  openssl ca -config ca.cnf -gencrl -keyfile $ca.key -cert $ca.pem -out $ca.crl.pem 2>/dev/null
  openssl crl -in $ca.crl.pem -outform DER -out crl/$ca.crl
done
cp kept.pem anchors/kept.pem
bash "$PKI" crl-prune crl anchors 2>/dev/null
[ -f crl/kept.crl ] && [ ! -e crl/retired.crl ] && echo "PASS crl-prune removes the retired CA's CRL, keeps the anchor's" || { echo "FAIL crl-prune: $(ls crl)"; fail=1; }
cp retired.crl.pem crl/retired.crl; cp kept.crl.pem src/kept.crl
bash "$PKI" crl-sync src anchors crl 2>/dev/null
[ -f crl/kept.crl ] && [ ! -e crl/retired.crl ] && echo "PASS crl-sync leaves no CRL from a non-anchor behind" || { echo "FAIL crl-sync: $(ls crl)"; fail=1; }
exit $fail

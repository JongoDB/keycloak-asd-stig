#!/usr/bin/env bash
# Builds a throw-away CAC-like PKI for lab testing of the ASD STIG Keycloak profile.
# NEVER use in production - production trusts only DoD PKI (scripts/fetch_dod_pki.sh).
#
# Usage: make_test_pki.sh <out-dir> [server-hostnames comma-separated]
# Produces (relative to <out-dir>):
#   conf/tls/server.{crt,key}   Keycloak HTTPS cert (chain included)
#   conf/tls/db.{crt,key}       PostgreSQL TLS cert;  conf/tls/db-ca.crt  trust anchor for the DB link
#   conf/truststore/*.pem       TEST root + issuing CA (what Keycloak trusts for client certs)
#   conf/crl/test-id-ca.crl     CRL of the issuing CA (one revoked user)
#   conf/crl/test-root-ca.crl   CRL of the root (status of the issuing CA)
#   ocsp/                       index + signer for `openssl ocsp` responder
#   users/<name>.{pem,key,p12}  CAC-like user certs (UPN SAN = EDIPI@mil), alt token, revoked
set -euo pipefail
OUT="${1:?out dir}"; HOSTS="${2:-localhost,keycloak,sso.example.mil}"
OCSP_URL="${OCSP_URL:-http://ocsp:2560}"
rm -rf "$OUT"/ca "$OUT"/ocsp "$OUT"/users "$OUT"/rogue "$OUT"/conf   # always start clean (re-runs would reuse serials)
mkdir -p "$OUT"/{ca,conf/tls,conf/truststore,conf/crl,ocsp,users}
cd "$OUT"
DAYS=825
export SAN="DNS:placeholder" UPN="placeholder" EMAIL="placeholder@invalid"  # openssl parses every section

cat > ca/openssl.cnf <<EOF
[ ca ]
default_ca = idca
[ idca ]
dir = ./ca
database = \$dir/index.txt
new_certs_dir = \$dir
serial = \$dir/serial
crlnumber = \$dir/crlnumber
default_md = sha256
default_days = $DAYS
default_crl_days = 30
policy = anything
copy_extensions = none
unique_subject = no
[ rootca ]
dir = ./ca/rootdb
database = \$dir/index.txt
new_certs_dir = \$dir
serial = \$dir/serial
crlnumber = \$dir/crlnumber
default_md = sha256
default_crl_days = 30
policy = anything
[ anything ]
countryName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
[ v3_root ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ v3_ica ]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
certificatePolicies = 2.16.840.1.101.2.1.11.39,2.16.840.1.101.2.1.11.42
crlDistributionPoints = URI:http://crl.test.invalid/TESTROOTCA99.crl
[ v3_server ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = \${ENV::SAN}
authorityKeyIdentifier = keyid
[ v3_cac_auth ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
certificatePolicies = 2.16.840.1.101.2.1.11.42
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN},email:\${ENV::EMAIL}
crlDistributionPoints = URI:http://crl.test.invalid/TESTIDCA_99.crl
authorityInfoAccess = OCSP;URI:$OCSP_URL
authorityKeyIdentifier = keyid
[ v3_ocsp ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,OCSPSigning
noCheck = ignored
EOF
touch ca/index.txt; echo 1000 > ca/serial; echo 1000 > ca/crlnumber

# Root
openssl req -x509 -newkey rsa:3072 -nodes -keyout ca/root.key -out ca/root.crt -days 3650 -sha256 \
  -subj "/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=TEST DoD Root CA 99" -config ca/openssl.cnf -extensions v3_root 2>/dev/null
# Issuing CA (signed by root)
openssl req -new -newkey rsa:3072 -nodes -keyout ca/idca.key -out ca/idca.csr \
  -subj "/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=TEST DOD ID CA-99" 2>/dev/null
openssl x509 -req -in ca/idca.csr -CA ca/root.crt -CAkey ca/root.key -CAcreateserial -out ca/idca.crt -days 3000 -sha256 \
  -extfile ca/openssl.cnf -extensions v3_ica 2>/dev/null

issue() { # name subject extension [env...]
  local n=$1 subj=$2 ext=$3
  openssl req -new -newkey rsa:2048 -nodes -keyout "$n.key" -out "$n.csr" -subj "$subj" 2>/dev/null
  openssl ca -batch -config ca/openssl.cnf -cert ca/idca.crt -keyfile ca/idca.key -in "$n.csr" -out "$n.crt" \
    -extensions "$ext" -notext 2>/dev/null
  rm -f "$n.csr"
}

SAN="$(echo "$HOSTS" | tr ',' '\n' | sed 's/^/DNS:/' | paste -sd, -)" UPN=x EMAIL=x \
  issue conf/tls/server "/C=US/O=U.S. Government/OU=DoD/CN=$(echo "$HOSTS" | cut -d, -f1)" v3_server
cat ca/idca.crt >> conf/tls/server.crt
SAN="DNS:db,DNS:localhost" UPN=x EMAIL=x issue conf/tls/db "/C=US/O=U.S. Government/CN=db" v3_server
cat ca/root.crt ca/idca.crt > conf/tls/db-ca.crt
cp ca/root.crt conf/truststore/test-dod-root-ca-99.pem
cp ca/idca.crt conf/truststore/test-dod-id-ca-99.pem

user() { # file CN UPN email
  SAN=x UPN="$3" EMAIL="$4" issue "users/$1" "/C=US/O=U.S. Government/OU=DoD/OU=PKI/OU=USA/CN=$2" v3_cac_auth
  cat ca/idca.crt > "users/$1.chain.pem"
  openssl pkcs12 -export -inkey "users/$1.key" -in "users/$1.crt" -certfile ca/idca.crt -out "users/$1.p12" -passout pass:changeit 2>/dev/null
}
user doe.john   "DOE.JOHN.Q.1234567890"       "1234567890@mil"       "john.doe@test.mil"
user roe.jane   "ROE.JANE.A.2345678901"       "2345678901@mil"       "jane.roe@test.mil"
user admin.alt  "SMITH.ALEX.B.3456789012.ALT" "3456789012.alt@mil"   "alex.smith@test.mil"
user revoked    "REVOKED.RAY.C.9999999999"    "9999999999@mil"       "ray.revoked@test.mil"
user unmapped   "NOBODY.NED.D.8888888888"     "8888888888@mil"       "ned.nobody@test.mil"

# Rogue CA (NOT in the trust store) issuing a certificate with a real user's UPN: must be rejected (V-222584)
mkdir -p rogue && openssl req -x509 -newkey rsa:2048 -nodes -keyout rogue/ca.key -out rogue/ca.crt -days 825 \
  -subj "/C=US/O=Rogue Corp/CN=Rogue Issuing CA" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -keyout users/rogue.doe.key -out rogue/u.csr -subj "/C=US/O=U.S. Government/OU=DoD/CN=DOE.JOHN.Q.1234567890" 2>/dev/null
printf 'keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=otherName:1.3.6.1.4.1.311.20.2.3;UTF8:1234567890@mil\n' > rogue/ext
openssl x509 -req -in rogue/u.csr -CA rogue/ca.crt -CAkey rogue/ca.key -CAcreateserial -days 365 -sha256 -extfile rogue/ext -out users/rogue.doe.crt 2>/dev/null

# revoke one cert, publish CRL
openssl ca -config ca/openssl.cnf -cert ca/idca.crt -keyfile ca/idca.key -revoke users/revoked.crt -crl_reason keyCompromise 2>/dev/null
openssl ca -config ca/openssl.cnf -cert ca/idca.crt -keyfile ca/idca.key -gencrl -out conf/crl/test-id-ca.crl 2>/dev/null
# the root's CRL: the issuing CA's own revocation status is checked too (V-222550)
mkdir -p ca/rootdb && touch ca/rootdb/index.txt && echo 1000 > ca/rootdb/crlnumber
openssl ca -config ca/openssl.cnf -name rootca -cert ca/root.crt -keyfile ca/root.key -gencrl -out conf/crl/test-root-ca.crl 2>/dev/null

# OCSP signer for the issuing CA
SAN=x UPN=x EMAIL=x issue ocsp/signer "/C=US/O=U.S. Government/CN=TEST DOD ID CA-99 OCSP" v3_ocsp
cp ca/index.txt ocsp/index.txt; cp ca/idca.crt ocsp/ca.crt; cat ca/root.crt ca/idca.crt > ocsp/chain.pem

chmod 0644 conf/tls/*.crt conf/truststore/*.pem conf/crl/*
chmod 0640 conf/tls/*.key users/*.key
echo "test PKI ready in $OUT"
for f in users/*.crt; do printf '  %-22s %s\n' "$(basename "$f")" "$(openssl x509 -in "$f" -noout -ext subjectAltName 2>/dev/null | tail -1 | sed 's/^ *//')"; done

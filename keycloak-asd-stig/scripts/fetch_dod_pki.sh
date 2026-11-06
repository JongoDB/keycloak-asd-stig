#!/usr/bin/env bash
# Build the Keycloak trust store and CRL cache from the official DoD PKI bundle (V-222550, V-222553, V-222584).
#
# Usage: fetch_dod_pki.sh <out-dir> [--crl-only]
#   <out-dir>/conf/truststore/*.pem   one PEM per DoD root/intermediate (point truststore-paths here)
#   <out-dir>/conf/crl/DODIDCA_NN.crl CRLs for the DoD ID CAs that issue CAC authentication certificates
#   prints the "crl_files" JSON fragment for the kcstig profile
# Re-run with --crl-only from cron/systemd at least daily (V-222553); Keycloak re-reads CRL files.
# Environment: DOD_PKI_ZIP_URL, CRL_BASE (default http://crl.disa.mil/crl), INCLUDE_CAS regex (default "DOD (ID|DERILITY) CA")
set -euo pipefail
OUT="${1:?out dir}"; MODE="${2:-}"
ZIP_URL="${DOD_PKI_ZIP_URL:-https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip}"
CRL_BASE="${CRL_BASE:-http://crl.disa.mil/crl}"
INCLUDE="${INCLUDE_CAS:-DOD (ID|DERILITY) CA}"
TS="${TS_DIR:-$OUT/conf/truststore}"; CRLD="${CRL_DIR:-$OUT/conf/crl}"   # flat volume: TS_DIR=$OUT/truststore CRL_DIR=$OUT/crl
PFX="${CRL_PREFIX:-crl}"   # how crl_files are written in the profile (relative to /opt/keycloak/conf), e.g. pki/crl
mkdir -p "$TS" "$CRLD"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

if [ "$MODE" != "--crl-only" ]; then
  curl -fsSL --retry 4 -o "$WORK/dod.zip" "$ZIP_URL"
  unzip -q "$WORK/dod.zip" -d "$WORK/z"
  D="$(dirname "$(find "$WORK/z" -name '*.sha256' | head -1)")"
  # The bundle ships a CMS-signed SHA-256 manifest. Extract it and check every listed file.
  # (Its signature chains to the DoD roots inside the same bundle, so it proves integrity, not origin:
  #  compare the DoD Root CA fingerprints with the values DISA publishes before first use.)
  M="$(find "$D" -name '*.sha256' | head -1)"
  # DISA signs this manifest with SHA-1. RHEL/UBI crypto policies reject SHA-1 signatures, so allow it for this one
  # verification only (scoped OpenSSL config; the container's system policy is unchanged).
  printf 'openssl_conf = oi\n[oi]\nalg_section = ap\n[ap]\nrh-allow-sha1-signatures = yes\n' > "$WORK/sha1.cnf"
  openssl cms -verify -noverify -inform DER -in "$M" -out "$WORK/manifest.txt" 2>/dev/null \
    || OPENSSL_CONF="$WORK/sha1.cnf" openssl cms -verify -noverify -inform DER -in "$M" -out "$WORK/manifest.txt" 2>/dev/null \
    || openssl smime -verify -noverify -inform DER -in "$M" -out "$WORK/manifest.txt" 2>/dev/null \
    || { echo "could not verify the bundle's signed SHA-256 manifest" >&2; exit 1; }
  (cd "$D" && tr -d '\r' < "$WORK/manifest.txt" | grep -E '^[0-9a-f]{64}  ' | sha256sum -c --quiet)
  echo "bundle integrity: $(grep -cE '^[0-9a-f]{64}  ' "$WORK/manifest.txt") files match the signed SHA-256 manifest"
  P7="$(find "$D" -name '*_DoD.der.p7b' | head -1)"
  openssl pkcs7 -inform DER -in "$P7" -print_certs -out "$WORK/all.pem"
  mkdir -p "$WORK/ts"
  awk -v dir="$WORK/ts" '/BEGIN CERT/{n++; f=sprintf("%s/dod-%02d.pem",dir,n); on=1} on{print > f} /END CERT/{on=0; close(f)}' "$WORK/all.pem"
  for f in "$WORK/ts/"*.pem; do
    cn="$(openssl x509 -in "$f" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= *//p')"
    printf '  %-22s sha256=%s\n' "$cn" "$(openssl x509 -in "$f" -noout -fingerprint -sha256 | cut -d= -f2)"
    mv "$f" "$WORK/ts/$(echo "$cn" | tr ' ' '_' | tr -cd 'A-Za-z0-9_.-').pem.named"
  done
  # replace the trust store contents only after everything verified
  rm -f "$TS/"*.pem; for f in "$WORK/ts/"*.named; do cp "$f" "$TS/$(basename "${f%.named}")"; done
  echo "trust store: $(ls "$TS" | wc -l) DoD CA certificates in $TS (bundle $(basename "$D"))"
fi

files=()
for f in "$TS/"*.pem; do
  cn="$(openssl x509 -in "$f" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= *//p')"
  echo "$cn" | grep -Eq "$INCLUDE" || continue
  name="$(echo "$cn" | sed -E 's/^DOD ([A-Z]+) CA-([0-9]+)$/DOD\1CA_\2/')"
  if curl -fsSL --retry 3 -m 120 -o "$WORK/$name.crl" "$CRL_BASE/$name.crl"; then
    # accept DER or PEM; verify the CRL signature against its issuing CA before installing it
    fmt=DER; openssl crl -inform DER -in "$WORK/$name.crl" -noout 2>/dev/null || fmt=PEM
    if openssl crl -inform $fmt -in "$WORK/$name.crl" -CAfile "$f" -noout 2>&1 | grep -q 'verify OK'; then
      cp "$WORK/$name.crl" "$CRLD/.$name.crl.new" && mv -f "$CRLD/.$name.crl.new" "$CRLD/$name.crl"   # atomic rename
      files+=("\"$PFX/$name.crl\"")
    else
      echo "WARN signature check failed for $name.crl - not installed" >&2
    fi
  else
    echo "WARN could not download $CRL_BASE/$name.crl (keeping any cached copy)" >&2
    [ -f "$CRLD/$name.crl" ] && files+=("\"$PFX/$name.crl\"")
  fi
done
echo "profile fragment:  \"crl_files\": [$(IFS=,; echo "${files[*]-}")]"
roots=()
for f in "$TS/"*.pem; do
  s=$(openssl x509 -in "$f" -noout -subject -nameopt RFC2253 | sed 's/^subject=//'); i=$(openssl x509 -in "$f" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')
  [ "$s" = "$i" ] && roots+=("\"$s\"")
done
echo "profile fragment:  \"ca_subject_dns\": [$(IFS=,; echo "${roots[*]-}")]   (trust-anchor pinning, V-222584)"

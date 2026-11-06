#!/bin/bash
# kcstig-tools <command>
#   pki-init      populate $PKI_DIR/{truststore,crl} once (init container / pre-start job)
#   pki-refresh   pki-init, then refresh CRLs every $PKI_REFRESH_SECONDS forever (sidecar)
#   apply|verify|render|inherit|lookup   -> kcstig.py   (profile at $STIG_PROFILE, default /etc/kcstig/profile.json)
#   e2e           -> e2e_check.py
#   help
# PKI_SOURCE: dod (download + verify official DISA bundle; needs dl.dod.cyber.mil and crl.disa.mil)
#             dir:/path (air-gapped: copy <path>/truststore/*.pem and <path>/crl/*.crl from a mounted, pre-fetched bundle)
set -euo pipefail
S=/opt/kcstig/scripts
PKI_DIR="${PKI_DIR:-/pki}"
for var in $(compgen -e | grep -E '^(KC|STIG)_[A-Z0-9_]*(PASSWORD|SECRET|USERNAME|TOKEN)_FILE$' || true); do   # *_FILE secrets
  case "$var" in KC_CLIENT_SECRET_FILE|KC_ADMIN_PASSWORD_FILE) continue;; esac  # kcstig.py reads these itself
  export "${var%_FILE}"="$(cat "${!var}")"
done

crl_health() {   # warn (and exit non-zero) when a CRL expires within 24h: Keycloak would then refuse logins
  local bad=0 now; now=$(date +%s)
  for f in "$PKI_DIR"/crl/*.crl; do
    [ -e "$f" ] || continue
    nu=$(openssl crl -inform DER -in "$f" -noout -nextupdate 2>/dev/null || openssl crl -in "$f" -noout -nextupdate 2>/dev/null)
    nu=$(date -d "${nu#nextUpdate=}" +%s 2>/dev/null || echo 0)
    if [ $((nu - now)) -lt 86400 ]; then echo "STIG-CRL-STALE $(basename "$f") nextUpdate=$(date -u -d @"$nu" +%FT%TZ)" >&2; bad=1; fi
  done
  return $bad
}

pki_sync() {   # $1 = full|crl
  mkdir -p "$PKI_DIR/truststore" "$PKI_DIR/crl"
  case "$PKI_SOURCE" in
    dod)
      TS_DIR="$PKI_DIR/truststore" CRL_DIR="$PKI_DIR/crl" "$S/fetch_dod_pki.sh" "$PKI_DIR" $([ "$1" = crl ] && echo --crl-only) ;;
    dir:*)
      # Layouts: <src>/truststore/*.pem + <src>/crl/*.crl, or flat <src>/*.pem|*.crt + <src>/*.crl
      # (flat suits ConfigMaps/Secrets, whose keys cannot contain '/').
      src="${PKI_SOURCE#dir:}"
      if [ -d "$src/truststore" ]; then ts_src=("$src"/truststore/*.pem); crl_src=("$src"/crl/*.crl)
      else shopt -s nullglob; ts_src=("$src"/*.pem "$src"/*.crt); crl_src=("$src"/*.crl); shopt -u nullglob; fi
      if [ "$1" = full ]; then
        rm -f "$PKI_DIR"/truststore/*.pem
        for f in "${ts_src[@]}"; do b=$(basename "$f"); cp "$f" "$PKI_DIR/truststore/${b%.*}.pem"; done
      fi
      # Install a CRL only if its signature verifies against an anchor in the trust store: Keycloak evaluates
      # every configured CRL on every login, and one whose issuer it does not trust makes ALL logins fail.
      cat "$PKI_DIR"/truststore/*.pem > "$PKI_DIR/.anchors-check.pem" 2>/dev/null
      for f in "${crl_src[@]}"; do [ -e "$f" ] || continue
        fmt=DER; openssl crl -inform DER -in "$f" -noout 2>/dev/null || fmt=PEM
        if openssl crl -inform $fmt -in "$f" -CAfile "$PKI_DIR/.anchors-check.pem" -noout 2>&1 | grep -q 'verify OK'; then
          cp "$f" "$PKI_DIR/crl/.$(basename "$f").new" && mv -f "$PKI_DIR/crl/.$(basename "$f").new" "$PKI_DIR/crl/$(basename "$f")"
        else
          echo "STIG-CRL-UNTRUSTED $(basename "$f"): issuer not in trust store or bad signature - NOT installed" >&2
        fi
      done; rm -f "$PKI_DIR/.anchors-check.pem"
      echo "pki: $(ls "$PKI_DIR/truststore" | wc -l) trust anchors, $(ls "$PKI_DIR/crl" | wc -l) CRLs from $src" ;;
    *) echo "unknown PKI_SOURCE=$PKI_SOURCE (dod | dir:/path)" >&2; exit 2 ;;
  esac
  # TLS client-auth trust store with ONLY these anchors. truststore-paths is merged with the JVM's public CA list,
  # so Keycloak's https-trust-store-file must point here (V-222584). -jdktrust marks the entries as Java trusted certs.
  cat "$PKI_DIR"/truststore/*.pem > "$PKI_DIR/.anchors.pem"
  openssl pkcs12 -export -nokeys -in "$PKI_DIR/.anchors.pem" -jdktrust anyExtendedKeyUsage \
    -passout "pass:${PKI_P12_PASSWORD:-dod-anchors}" -out "$PKI_DIR/.client-ca.p12.new" && mv -f "$PKI_DIR/.client-ca.p12.new" "$PKI_DIR/client-ca.p12"
  # Root (trust anchor) DNs for x509.ca_subject_dns. Keycloak matches the ANCHOR of the validated path,
  # not the issuing CA (verified 26.8.2), so only self-signed certificates are listed.
  for f in "$PKI_DIR"/truststore/*.pem; do
    s=$(openssl x509 -in "$f" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
    i=$(openssl x509 -in "$f" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')
    [ "$s" = "$i" ] && echo "$s"
  done > "$PKI_DIR/ca-subject-dns.txt"
  rm -f "$PKI_DIR/.anchors.pem"
  chmod -R a+rX "$PKI_DIR" 2>/dev/null || true
  crl_health || true
  date -u +%FT%TZ > "$PKI_DIR/.last-sync"
}

cmd="${1:-help}"; shift || true
case "$cmd" in
  pki-init)    pki_sync full; [ -n "$(ls -A "$PKI_DIR/truststore")" ] || { echo "pki-init: empty trust store" >&2; exit 1; } ;;
  pki-refresh) pki_sync full
               while true; do sleep "${PKI_REFRESH_SECONDS:-21600}"; pki_sync crl || echo "pki-refresh: sync failed, keeping cached CRLs" >&2; done ;;
  apply|verify|render|inherit|lookup)
               if [ "$cmd" = lookup ]; then exec python3 "$S/kcstig.py" lookup "$@"; fi
               exec python3 "$S/kcstig.py" "$cmd" --profile "${STIG_PROFILE:-/etc/kcstig/profile.json}" "$@" ;;
  e2e)         exec python3 "$S/e2e_check.py" "$@" ;;
  gateway)     exec python3 "$S/kcstig.py" gateway --profile "${STIG_PROFILE:-/etc/kcstig/profile.json}" "$@" ;;
  crl-health)  crl_health ;;
  *)           sed -n '2,12p' "$0" ;;
esac

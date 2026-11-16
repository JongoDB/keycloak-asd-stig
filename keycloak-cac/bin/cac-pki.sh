#!/bin/bash
# cac-pki.sh - trust anchors and CRLs for the keycloak-cac image.
#
#   cac-pki.sh bundle  <out-dir> [drop-in-dir]   BUILD: DoD/Federal bundles -> <out-dir>/anchors/*.pem + anchors.txt
#                                                 drop-in-dir with *.zip|*.p7b|*.p7c|*.pem|*.crt|*.cer|*.der wins
#                                                 (offline builds); otherwise downloads $PKI_BUNDLE_URLS.
#   cac-pki.sh compile <anchors-dir> <out-dir>    client-ca.p12 (DoD-only client trust store), ca-subject-dns.txt,
#                                                 crl-names.txt (CRL file names the issuing CAs publish)
#   cac-pki.sh crl-fetch <anchors-dir> <crl-dir>  download + signature-check the CRLs of the issuing CAs (online mode)
#   cac-pki.sh crl-sync  <src-dir> <anchors-dir> <crl-dir>   copy signature-checked CRLs from a mounted dir (air-gapped)
#   cac-pki.sh crl-prune <crl-dir> <anchors-dir>  delete CRLs whose issuer is no longer an anchor (also after fetch/sync)
#   cac-pki.sh crl-health <crl-dir>               exit 1 if a CRL expires within 24h
#   cac-pki.sh crl-coverage <anchors-dir> <crl-dir>  exit 1 if a trusted issuing CA or its root has no CRL
#   cac-pki.sh narrow <anchors-dir>               keep only the issuing CAs of login certificates ($CAC_LOGIN_CAS) and their roots
#
# Every anchor must be a CA certificate. A zip that ships a signed SHA-256 manifest (the DISA bundles do) must verify.
# Never adds anything to the JVM cacerts: client certificates are checked against client-ca.p12 only (V-222584).
set -euo pipefail
DOD_ZIP=https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip
URLS="${PKI_BUNDLE_URLS:-$DOD_ZIP}"
CRL_BASE="${CRL_BASE:-http://crl.disa.mil/crl}"
# Revocation coverage must equal trust: every ISSUING CA among the anchors (not self-signed) gets its CRL, because
# stig-x509-client-username-form refuses a card whose issuer has no CRL. CRL_INCLUDE_CAS (an ERE on the CA's CN) only
# narrows that, and every CA it leaves out is a coverage gap: crl-coverage and kcstig verify (pki.crl_coverage) report it.
INCLUDE="${CRL_INCLUDE_CAS:-}"
# CAs whose certificates may sign in: CAC/PIV authentication certificates come from DOD ID CA-n and DOD DERILITY CA-n.
# DOD EMAIL (signature/encryption) and DOD SW (software) CA certificates are not login credentials, so they are not
# trusted for TLS client authentication at all - which also keeps the CRL set to what login needs (~141 MB, not ~296 MB).
LOGIN_CAS="${CAC_LOGIN_CAS:-^DOD (ID|DERILITY) CA-[0-9]+$}"
log() { echo "cac-pki: $*" >&2; }
die() { log "ERROR $*"; exit 1; }
cn_of() { openssl x509 -in "$1" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= *//p' | head -1; }
dn_of() { openssl x509 -in "$1" -noout -"$2" -nameopt RFC2253 | sed "s/^$2=//"; }
fp_of() { openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d :; }

split_pem() { # file.pem outdir prefix  -> one file per certificate
  awk -v d="$2" -v p="$3" '/BEGIN CERT/{n++; f=sprintf("%s/%s-%03d.crt",d,p,n); on=1} on{print > f} /END CERT/{on=0; close(f)}' "$1"
}

verify_zip_manifest() { # unzipped-dir -> 0 ok / 1 bad / 2 no manifest
  local m; m=$(find "$1" -name '*.sha256' | head -1); [ -n "$m" ] || return 2
  local t; t=$(mktemp -d)
  # DISA signs the manifest with SHA-1; RHEL crypto policy rejects SHA-1 signatures, so allow it for this check only.
  printf 'openssl_conf = oi\n[oi]\nalg_section = ap\n[ap]\nrh-allow-sha1-signatures = yes\n' > "$t/sha1.cnf"
  openssl cms -verify -noverify -inform DER -in "$m" -out "$t/m.txt" 2>/dev/null \
    || OPENSSL_CONF="$t/sha1.cnf" openssl cms -verify -noverify -inform DER -in "$m" -out "$t/m.txt" 2>/dev/null \
    || { rm -rf "$t"; return 1; }
  (cd "$(dirname "$m")" && tr -d '\r' < "$t/m.txt" | grep -E '^[0-9a-f]{64}  ' | sha256sum -c --quiet) || { rm -rf "$t"; return 1; }
  log "$(basename "$(dirname "$m")"): $(grep -cE '^[0-9a-f]{64}  ' "$t/m.txt") files match the bundle's signed SHA-256 manifest"
  rm -rf "$t"
}

extract() { # input-file workdir -> certificates as *.crt in workdir/certs
  local f="$1" w="$2" b; b=$(basename "$f"); mkdir -p "$w/certs"
  case "${b,,}" in
    *.zip)
      local z="$w/z-$b"; mkdir -p "$z"
      if command -v unzip >/dev/null; then unzip -q -o "$f" -d "$z"; else python3 -m zipfile -e "$f" "$z"; fi
      verify_zip_manifest "$z" && : || case $? in
        1) die "$b: signed SHA-256 manifest does not verify - refusing this bundle";;
        2) [ "${PKI_REQUIRE_MANIFEST:-true}" = true ] && die "$b: no signed manifest (set PKI_REQUIRE_MANIFEST=false only for bundles you verified yourself)"
           log "WARN $b has no signed manifest (PKI_REQUIRE_MANIFEST=false)";;
      esac
      # DISA zips carry the same certificates in several encodings; take the DER PKCS#7 when present.
      local p7; p7=$(find "$z" -iname '*.der.p7b' | sort)
      [ -n "$p7" ] || p7=$(find "$z" -iname '*.p7b' -o -iname '*.p7c' | sort)
      for x in $p7; do extract "$x" "$w"; done
      for x in $(find "$z" -iname '*.pem' -o -iname '*.crt' -o -iname '*.cer'); do [ -n "$p7" ] || extract "$x" "$w"; done ;;
    *.p7b|*.p7c)
      openssl pkcs7 -inform DER -in "$f" -print_certs -out "$w/p7.pem" 2>/dev/null \
        || openssl pkcs7 -inform PEM -in "$f" -print_certs -out "$w/p7.pem" || die "$b: not a PKCS#7 bundle"
      split_pem "$w/p7.pem" "$w/certs" "$(echo "$b" | tr -cd 'A-Za-z0-9')" ;;
    *.pem|*.crt|*.cer|*.der)
      if grep -q 'BEGIN CERTIFICATE' "$f" 2>/dev/null; then split_pem "$f" "$w/certs" "$(echo "$b" | tr -cd 'A-Za-z0-9')"
      else openssl x509 -inform DER -in "$f" -out "$w/certs/$(echo "$b" | tr -cd 'A-Za-z0-9').crt" || die "$b: not a certificate"; fi ;;
    readme*|*.md|*.txt|.gitkeep) ;;
    *) log "skipping $b (not a certificate bundle)";;
  esac
}

cmd_bundle() {
  local out="$1" drop="${2:-}" w; w=$(mktemp -d); trap 'rm -rf "$w"' RETURN
  mkdir -p "$out/anchors"; rm -f "$out"/anchors/*.pem
  local inputs=()
  if [ -n "$drop" ] && [ -d "$drop" ]; then
    while IFS= read -r f; do inputs+=("$f"); done < <(find "$drop" -maxdepth 1 -type f \( -iname '*.zip' -o -iname '*.p7b' -o -iname '*.p7c' -o -iname '*.pem' -o -iname '*.crt' -o -iname '*.cer' -o -iname '*.der' \) | sort)
  fi
  if [ ${#inputs[@]} -gt 0 ]; then
    log "offline: using ${#inputs[@]} bundle file(s) from $drop"; echo "source: drop-in $(cd "$drop" && ls | tr '\n' ' ')" > "$out/source.txt"
  else
    [ "${PKI_FETCH:-true}" = true ] || die "no bundles in ${drop:-<none>} and PKI_FETCH=false"
    local i=0
    for u in $URLS; do i=$((i+1)); log "downloading $u"
      curl -fsSL --retry 5 --retry-delay 5 -o "$w/bundle-$i-$(basename "$u")" "$u" || die "download failed: $u (offline build: put the bundle in certs/)"
      inputs+=("$w/bundle-$i-$(basename "$u")")
    done
    echo "source: $URLS (downloaded $(date -u +%FT%TZ))" > "$out/source.txt"
  fi
  for f in "${inputs[@]}"; do extract "$f" "$w"; done
  local n=0 seen=" "
  : > "$out/anchors.txt"
  for c in "$w"/certs/*.crt; do
    [ -e "$c" ] || continue
    openssl x509 -in "$c" -noout 2>/dev/null || { log "WARN unreadable certificate $(basename "$c")"; continue; }
    local fp; fp=$(fp_of "$c"); case "$seen" in *" $fp "*) continue;; esac; seen="$seen$fp "
    if ! openssl x509 -in "$c" -noout -ext basicConstraints 2>/dev/null | grep -q 'CA:TRUE'; then
      log "skipping non-CA certificate: $(dn_of "$c" subject)"; continue; fi
    local cn name; cn=$(cn_of "$c"); name=$(echo "${cn:-ca-$fp}" | tr ' ' '_' | tr -cd 'A-Za-z0-9_.-')
    [ -e "$out/anchors/$name.pem" ] && name="$name-${fp:0:8}"
    openssl x509 -in "$c" -out "$out/anchors/$name.pem"
    local na; na=$(openssl x509 -in "$c" -noout -enddate | cut -d= -f2)
    if ! openssl x509 -in "$c" -noout -checkend 0 >/dev/null; then
      # An expired CA can no longer vouch for anything, and its last CRL is stale: with
      # crl-abort-if-non-updated Keycloak would then refuse EVERY login. Leave it out (PKI_KEEP_EXPIRED=true keeps it).
      if [ "${PKI_KEEP_EXPIRED:-false}" != true ]; then log "dropping expired anchor: $cn ($na)"; rm -f "$out/anchors/$name.pem"; continue; fi
      log "WARN keeping expired anchor: $cn ($na)"; fi
    printf '%-34s sha256=%s notAfter=%s\n' "$cn" "$fp" "$na" >> "$out/anchors.txt"; n=$((n+1))
  done
  [ "$n" -gt 0 ] || die "no CA certificates found"
  log "$n trust anchors -> $out/anchors"
}

cmd_compile() {
  local a="$1" out="$2"; mkdir -p "$out"
  ls "$a"/*.pem >/dev/null 2>&1 || die "no anchors in $a"
  cat "$a"/*.pem > "$out/.anchors.pem"
  # -jdktrust marks every entry as a Java trusted certificate; this store is ONLY used for TLS client auth.
  openssl pkcs12 -export -nokeys -in "$out/.anchors.pem" -jdktrust anyExtendedKeyUsage \
    -passout "pass:${PKI_P12_PASSWORD:-cac-anchors}" -out "$out/.client-ca.p12.new"
  mv -f "$out/.client-ca.p12.new" "$out/client-ca.p12"; rm -f "$out/.anchors.pem"
  : > "$out/ca-subject-dns.txt"
  local s
  for f in "$a"/*.pem; do
    s=$(dn_of "$f" subject); [ "$s" = "$(dn_of "$f" issuer)" ] && echo "$s" >> "$out/ca-subject-dns.txt"
  done
  crl_names "$a" log | sed 's/$/.crl/' > "$out/crl-names.txt"
}

# The CRLs revocation checking needs = what trust covers: the CRL of every ISSUING CA among the anchors (the card's
# status), and the CRL of every root that issued one of them (the issuing CA's own status, V-222550). Root CRL names
# come from the issuing CA certificate's CRL distribution point (DISA: DODROOTCA3.crl ...).
crl_names() { # anchors-dir [log] -> base names, one per line, sorted, unique
  local a="$1" f n
  for f in "$a"/*.pem; do
    n=$(crl_name_of "$f" "${2:-}") || continue; echo "$n"
    n=$(openssl x509 -in "$f" -noout -ext crlDistributionPoints 2>/dev/null | grep -o 'URI:[^ ,]*' | head -1 | sed 's#.*/##; s#\.crl$##')
    if [ -n "$n" ]; then echo "$n"
    else [ -n "${2:-}" ] && log "issuing CA \"$(cn_of "$f")\" names no CRL distribution point: supply its root's CRL in the CRL directory"; fi
  done | sort -u
}

crl_name_of() { # anchor.pem [log] -> DISA CRL base name (DOD SW CA-75 -> DODSWCA_75) of an ISSUING CA; 1 if none
  local f="$1" cn kind
  [ "$(dn_of "$f" subject)" = "$(dn_of "$f" issuer)" ] && return 1            # root: path anchor, issues CAs only
  cn=$(cn_of "$f")
  if [ -n "$INCLUDE" ] && ! echo "$cn" | grep -Eq "$INCLUDE"; then
    [ -n "${2:-}" ] && log "WARN CRL_INCLUDE_CAS leaves out issuing CA \"$cn\": its cards will be refused (STIG-CRL-NO-ISSUER-CRL)"
    return 1; fi
  if [[ "$cn" =~ ^DOD\ (.+)\ CA-([0-9]+)$ ]]; then kind="${BASH_REMATCH[1]}"; echo "DOD${kind// /}CA_${BASH_REMATCH[2]}"; return 0; fi
  [ -n "${2:-}" ] && log "issuing CA \"$cn\" has no DISA CRL name: supply its CRL in the CRL directory (crl-sync) or its cards are refused"
  return 1
}

crl_ok() { # crl anchors-pem -> installs only if the signature verifies against a trusted anchor
  local fmt=DER; openssl crl -inform DER -in "$1" -noout 2>/dev/null || fmt=PEM
  openssl crl -inform $fmt -in "$1" -CAfile "$2" -noout 2>&1 | grep -q 'verify OK'
}

# Keycloak evaluates EVERY configured CRL on every card login, and one whose issuer is not a trust anchor throws
# "crlSignatureCertificates is null": every card is then refused. A CRL left behind by a CA that is no longer an
# anchor (an image upgrade that retired it, lab files on a persisted volume) must therefore be removed, not kept.
# Caveat, a CA re-keyed under the same name: its CRLs are signed with the new key, so a cached CRL signed with the OLD
# key no longer verifies and is pruned (and the new one arrives with the next fetch; until then that CA's cards fail
# closed). While both the old and the new CA certificate are anchors, CRLs from either key verify and are kept, and
# Keycloak picks the CRL by issuer name - keep only the current CA certificate once DISA retires the old one.
cmd_crl_prune() { # crl-dir anchors-dir -> delete every *.crl that does not verify against the current anchors
  local d="$1" a="$2" w n=0; [ -d "$d" ] || return 0; w=$(mktemp -d); cat "$a"/*.pem > "$w/anchors.pem"
  for f in "$d"/*.crl; do [ -e "$f" ] || continue
    crl_ok "$f" "$w/anchors.pem" || { rm -f "$f"; n=$((n+1)); log "STIG-CRL-PRUNED $(basename "$f"): issuer is not a current trust anchor - removed"; }
  done; rm -rf "$w"; [ $n -eq 0 ] || log "CRLs pruned: $n"
}

cmd_crl_fetch() {
  local a="$1" d="$2" w n; w=$(mktemp -d); mkdir -p "$d"; cat "$a"/*.pem > "$w/anchors.pem"
  local ok=0 same=0 bad=0
  for n in $(crl_names "$a"); do
    if curl -fsSL --retry 3 -m 180 -o "$w/$n.crl" "$CRL_BASE/$n.crl" && crl_ok "$w/$n.crl" "$w/anchors.pem"; then
      # unchanged bytes: leave the installed file alone, so Keycloak does not re-read and re-verify it
      if cmp -s "$w/$n.crl" "$d/$n.crl"; then same=$((same+1)); rm -f "$w/$n.crl"
      else mv -f "$w/$n.crl" "$d/.$n.crl.new" && mv -f "$d/.$n.crl.new" "$d/$n.crl"; ok=$((ok+1)); fi   # atomic swap
    else log "WARN $n.crl: download or signature check failed - keeping cached copy"; bad=$((bad+1)); rm -f "$w/$n.crl"; fi
  done
  rm -rf "$w"; log "CRLs refreshed: $ok replaced, $same unchanged, $bad failed (from $CRL_BASE)"
  cmd_crl_prune "$d" "$a"
}

cmd_crl_sync() {
  local src="$1" a="$2" d="$3" w; w=$(mktemp -d); mkdir -p "$d"; cat "$a"/*.pem > "$w/anchors.pem"
  local ok=0
  for f in "$src"/*.crl "$src"/crl/*.crl; do
    [ -e "$f" ] || continue
    if cmp -s "$f" "$d/$(basename "$f")"; then ok=$((ok+1))   # unchanged: keep the installed file (no re-read by Keycloak)
    elif crl_ok "$f" "$w/anchors.pem"; then cp "$f" "$d/.$(basename "$f").new" && mv -f "$d/.$(basename "$f").new" "$d/$(basename "$f")"; ok=$((ok+1))
    else log "STIG-CRL-UNTRUSTED $(basename "$f"): issuer not trusted or bad signature - NOT installed"; fi
  done
  rm -rf "$w"; log "CRLs synced from $src: $ok installed"
  cmd_crl_prune "$d" "$a"
}

cmd_crl_coverage() { # anchors-dir crl-dir -> exit 1 (and STIG-CRL-COVERAGE-GAP per CA) if an issuing CA has no CRL
  local a="$1" d="$2" gaps=0 have=" " f s
  for f in "$d"/*.crl; do [ -e "$f" ] || continue
    s=$(openssl crl -inform DER -in "$f" -noout -issuer -nameopt RFC2253 2>/dev/null || openssl crl -in "$f" -noout -issuer -nameopt RFC2253 2>/dev/null || true)
    have="$have${s#issuer=}|"
  done
  local i seen=" "
  for f in "$a"/*.pem; do
    s=$(dn_of "$f" subject); i=$(dn_of "$f" issuer); [ "$s" = "$i" ] && continue
    case "$have" in *"|$s|"*|" $s|"*) ;; *) log "STIG-CRL-COVERAGE-GAP no CRL for trusted issuing CA \"$(cn_of "$f")\": its cards are refused"; gaps=$((gaps+1));; esac
    case "$seen" in *"|$i|"*) continue;; esac; seen="$seen|$i|"
    case "$have" in *"|$i|"*|" $i|"*) ;; *) log "STIG-CRL-COVERAGE-GAP no CRL for root \"$i\": the status of the CAs it issued is unknown, their cards are refused"; gaps=$((gaps+1));; esac
  done
  [ $gaps -eq 0 ] && log "CRL coverage: every trusted issuing CA and its root has a CRL" || { log "CRL coverage: $gaps CA(s) without a CRL"; return 1; }
}

cmd_narrow() { # anchors-dir -> delete issuing CAs not matching LOGIN_CAS, then roots that issued none of the rest
  local a="$1" f s i cn issuers="|" n=0
  for f in "$a"/*.pem; do
    s=$(dn_of "$f" subject); i=$(dn_of "$f" issuer); [ "$s" = "$i" ] && continue
    cn=$(cn_of "$f")
    if echo "$cn" | grep -Eq "$LOGIN_CAS"; then issuers="$issuers$i|"; else rm -f "$f"; n=$((n+1)); fi
  done
  for f in "$a"/*.pem; do
    s=$(dn_of "$f" subject); [ "$s" = "$(dn_of "$f" issuer)" ] || continue
    case "$issuers" in *"|$s|"*) ;; *) rm -f "$f"; n=$((n+1));; esac
  done
  log "trust narrowed to login CAs ($LOGIN_CAS): removed $n, kept $(ls "$a"/*.pem 2>/dev/null | wc -l)"
  ls "$a"/*.pem >/dev/null 2>&1 || die "CAC_LOGIN_CAS=$LOGIN_CAS leaves no trust anchors"
}

cmd_crl_health() {
  local bad=0 now; now=$(date +%s)
  for f in "$1"/*.crl; do [ -e "$f" ] || continue
    nu=$(openssl crl -inform DER -in "$f" -noout -nextupdate 2>/dev/null || openssl crl -in "$f" -noout -nextupdate 2>/dev/null || true)
    nu=$(date -d "${nu#nextUpdate=}" +%s 2>/dev/null || echo 0)
    [ $((nu - now)) -lt 86400 ] && { log "STIG-CRL-STALE $(basename "$f") nextUpdate=$(date -u -d @"$nu" +%FT%TZ)"; bad=1; }
  done; return $bad
}

c="${1:-}"; shift || true
case "$c" in
  bundle) cmd_bundle "$@";; compile) cmd_compile "$@";; crl-fetch) cmd_crl_fetch "$@";;
  crl-sync) cmd_crl_sync "$@";; crl-prune) cmd_crl_prune "$@";; crl-health) cmd_crl_health "$@";;
  crl-coverage) cmd_crl_coverage "$@";; narrow) cmd_narrow "$@";; *) sed -n '2,16p' "$0"; exit 2;;
esac

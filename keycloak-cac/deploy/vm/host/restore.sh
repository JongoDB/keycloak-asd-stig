#!/usr/bin/env bash
# Restore the shared IdP from an encrypted backup (see README "Backup and restore").
#   idp-restore list                          # backups in the storage account
#   idp-restore fetch <blob> <dir>            # download + decrypt + unpack into <dir> (keycloak.dump, files.tar)
#   idp-restore db <dir>                      # DESTRUCTIVE: replace the keycloak database with <dir>/keycloak.dump
# On a NEW VM: run setup-host.sh first (it creates fresh secrets), then `fetch`, put files.tar's
# srv/idp/secrets/*, srv/idp/clients/* and srv/idp/state/* back (the automation secret must match the database; the
# state holds the vetted administrators - restore it BEFORE the guard timer runs), then `db`.
# The passphrase: RESTORE_SECRET_VERSION=<id> pins one Key Vault version (only that is tried); otherwise
# /srv/idp/secrets/backup_passphrase if it decrypts the backup, else every Key Vault version (all pages), newest first -
# refused above RESTORE_MAX_VERSIONS (default 10) enabled versions unless RESTORE_FORCE=1.
set -euo pipefail
. /etc/default/idp-backup
S=/srv/idp; PASS=$S/secrets/backup_passphrase; KVSECRET=${KV_SECRET:-idp-backup-passphrase}
imds() { curl -fsS -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$1" | jq -r .access_token; }
case "${1:-}" in
  list)
    curl -fsS -H "Authorization: Bearer $(imds https://storage.azure.com/)" -H "x-ms-version: 2021-08-06" \
      "https://$STORAGE_ACCOUNT.blob.core.windows.net/backups?restype=container&comp=list" | grep -o '<Name>[^<]*</Name>' | sed 's/<[^>]*>//g';;
  fetch)
    B="${2:?blob}"; O="${3:?dir}"
    # only a name backup.sh writes: no path, no query, nothing to smuggle into the URL or the output directory
    [[ "$B" =~ ^idp-[0-9]{8}T[0-9]{6}Z\.tar\.gz\.gpg$ ]] || { echo "not a backup name (idp-YYYYMMDDTHHMMSSZ.tar.gz.gpg): $B"; exit 1; }
    mkdir -p "$O"; chmod 700 "$O"
    curl -fsS -o "$O/$B" -H "Authorization: Bearer $(imds https://storage.azure.com/)" -H "x-ms-version: 2021-08-06" \
      "https://$STORAGE_ACCOUNT.blob.core.windows.net/backups/$B"
    # decrypt to a file first, so a wrong passphrase leaves nothing half-unpacked
    try() { gpg --batch --quiet --pinentry-mode loopback --passphrase-file "$1" -o "$O/.tgz" -d "$O/$B" 2>/dev/null; }
    ok=""
    KVT=""; KVU="https://$KEY_VAULT.vault.azure.net/secrets/$KVSECRET"
    kv_try() {    # kv_try <version>: that version's value, unless it is the placeholder, decrypts the backup
      ( umask 077; curl -fsS -H "Authorization: Bearer $KVT" "$KVU/$1?api-version=7.4" \
          | jq -je 'select(.contentType != "pending") | .value' > "$O/.pass" ) && [ -s "$O/.pass" ] && try "$O/.pass"; }
    if [ -n "${RESTORE_SECRET_VERSION:-}" ]; then
      # the operator pinned a known-good version: that one and nothing else (not the host file, no other version)
      [[ "$RESTORE_SECRET_VERSION" =~ ^[0-9a-f]{32}$ ]] || { echo "RESTORE_SECRET_VERSION is a 32-hex Key Vault version id"; exit 1; }
      KVT=$(imds https://vault.azure.net)
      kv_try "$RESTORE_SECRET_VERSION" && ok="Key Vault $KVSECRET version $RESTORE_SECRET_VERSION (pinned)"
    else
      if [ -s "$PASS" ]; then try "$PASS" && ok="$PASS (on this host)"; fi
      if [ -z "$ok" ]; then
        # Key Vault: EVERY enabled version, newest first - all pages (nextLink) are listed before sorting, so versions
        # written later cannot push the real passphrase out of view. Placeholders are skipped. A version that cannot
        # be trusted can be bypassed with RESTORE_SECRET_VERSION=<known-good version id>.
        KVT=$(imds https://vault.azure.net); ALL="$O/.versions"; echo '[]' > "$ALL"
        url="$KVU/versions?api-version=7.4&maxresults=25"; pages=0
        while [ -n "$url" ]; do
          pages=$((pages + 1)); [ "$pages" -le 1000 ] || { echo "more than 1000 pages of secret versions: refusing"; exit 1; }
          page=$(curl -fsS -H "Authorization: Bearer $KVT" "$url") || { echo "cannot list the versions of $KEY_VAULT/$KVSECRET"; exit 1; }
          jq -s '.[0] + (.[1].value // [])' "$ALL" <(printf '%s' "$page") > "$ALL.n" && mv "$ALL.n" "$ALL"
          url=$(printf '%s' "$page" | jq -r '.nextLink // empty')
          case "$url" in ""|"https://$KEY_VAULT.vault.azure.net/"*) ;; *) echo "unexpected nextLink host: refusing"; exit 1;; esac
        done
        VERS=$(jq -r 'sort_by(-.attributes.created) | .[] | select(.attributes.enabled) | .id | split("/") | last' "$ALL")
        NV=$(printf '%s\n' $VERS | grep -c . || true); rm -f "$ALL"
        echo "Key Vault $KVSECRET: $NV enabled version(s) to try"
        # backup.sh escrows once; many versions mean someone with write access has been adding them - possibly to
        # bury the real passphrase. Refuse above RESTORE_MAX_VERSIONS (default 10) unless RESTORE_FORCE=1; better,
        # check the versions' creation times and pin the known-good one with RESTORE_SECRET_VERSION.
        MAXV=${RESTORE_MAX_VERSIONS:-10}
        [[ "$MAXV" =~ ^[0-9]+$ ]] || { echo "RESTORE_MAX_VERSIONS must be a whole number"; exit 1; }
        if [ "$NV" -gt "$MAXV" ]; then
          echo "WARNING: $NV enabled versions of $KEY_VAULT/$KVSECRET (more than $MAXV): the secret may have been tampered with." >&2
          echo "         List them (az keyvault secret list-versions --vault-name $KEY_VAULT -n $KVSECRET), then pin a known-good" >&2
          echo "         one with RESTORE_SECRET_VERSION=<id>, or accept trying them all with RESTORE_FORCE=1." >&2
          [ "${RESTORE_FORCE:-}" = 1 ] || exit 1
          echo "RESTORE_FORCE=1: trying all $NV" >&2
        fi
        for v in $VERS; do
          if kv_try "$v"; then ok="Key Vault $KVSECRET version $v"; break; fi
        done
      fi
    fi
    rm -f "$O/.pass"
    [ -n "$ok" ] || { rm -f "$O/.tgz"; echo "no passphrase decrypts $B (host file, then every Key Vault version tried)"; exit 1; }
    tar -C "$O" -xzf "$O/.tgz"; rm -f "$O/.tgz"; echo "decrypted with $ok"
    rm -f "$O/.pass" "$O/$B"; echo "restored into $O: $(ls "$O" | tr '\n' ' ')";;
  db)
    O="${2:?dir}"; [ -s "$O/keycloak.dump" ] || { echo "no $O/keycloak.dump"; exit 1; }
    C="docker compose -f $S/compose/compose.yaml --env-file $S/compose/.env"
    $C stop keycloak
    $C exec -T db psql -q -U keycloak -d postgres -c 'DROP DATABASE IF EXISTS keycloak WITH (FORCE)' -c 'CREATE DATABASE keycloak OWNER keycloak'
    $C exec -T db pg_restore -U keycloak -d keycloak --no-owner < "$O/keycloak.dump"
    $C start keycloak; echo "database restored; Keycloak restarting";;
  *) sed -n '2,9p' "$0"; exit 2;;
esac

#!/usr/bin/env bash
# Daily backup of the shared IdP: pg_dump (custom format) + /srv/idp configuration, secrets, client files, database
# PKI and the administrator allowlist and guard state (srv/idp/state), as ONE tarball encrypted with gpg (AES-256,
# passphrase in /srv/idp/secrets/backup_passphrase) and
# uploaded to Azure Blob Storage with the VM's managed identity (the account allows no shared keys).
# The passphrase is escrowed in Key Vault on first run so a restore onto a NEW VM is possible. Prints no secrets.
# Env: STORAGE_ACCOUNT, KEY_VAULT (from /etc/default/idp-backup).
set -euo pipefail
: "${STORAGE_ACCOUNT:?}" "${KEY_VAULT:?}"
S=/srv/idp; PASS=$S/secrets/backup_passphrase; KVSECRET=${KV_SECRET:-idp-backup-passphrase}
imds() { curl -fsS -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$1" | jq -r .access_token; }

# escrow the passphrase in Key Vault (once). The VM's identity may touch only this one secret, so azure-provision.sh
# creates it holding a placeholder (contentType "pending"): absent (404) or pending -> PUT the real passphrase.
# Escrowed already -> the escrow must BE this host's passphrase: compared in memory (never written to disk), and a
# mismatch stops the backup (exit 1, alerted). Otherwise a rebuilt VM's fresh passphrase, or a rotated one, would
# silently produce backups that the escrowed passphrase cannot decrypt.
KVT=$(imds https://vault.azure.net)
KVU="https://$KEY_VAULT.vault.azure.net/secrets/$KVSECRET?api-version=7.4"
resp=$(curl -s -w '\n%{http_code}' -H "Authorization: Bearer $KVT" "$KVU") || true
code=${resp##*$'\n'}; body=${resp%$'\n'*}; resp=""
pending=""; [ "$code" = 200 ] && pending=$(printf '%s' "$body" | jq -r '.contentType // ""')
if [ "$code" = 404 ] || [ "$pending" = pending ]; then
  body=""
  jq -Rn --rawfile v "$PASS" '{value: $v, contentType: "gpg passphrase for idp backups"}' \
    | curl -fsS -o /dev/null -X PUT -H "Authorization: Bearer $KVT" -H "Content-Type: application/json" --data-binary @- "$KVU"
  echo "idp-backup: passphrase escrowed in Key Vault $KEY_VAULT/$KVSECRET"
elif [ "$code" = 200 ]; then
  if [ "$(printf '%s' "$body" | jq -j '.value // ""')" != "$(cat "$PASS")" ]; then
    body=""
    echo "idp-backup: REFUSED - the passphrase escrowed in Key Vault $KEY_VAULT/$KVSECRET is not this host's" \
         "($PASS): a backup now could not be decrypted with the escrow. Restore the escrowed passphrase to $PASS, or" \
         "escrow this one deliberately (operator, see README 'Backup and restore'), then retry."
    exit 1
  fi
  body=""
else
  body=""; echo "idp-backup: Key Vault check failed (HTTP $code)"; exit 1
fi

STAMP=$(date -u +%Y%m%dT%H%M%SZ); W=$(mktemp -d /srv/idp/backup/run.XXXX); trap 'rm -rf "$W"' EXIT
docker compose -f $S/compose/compose.yaml --env-file $S/compose/.env exec -T db pg_dump -U keycloak -d keycloak -Fc > "$W/keycloak.dump"
[ -s "$W/keycloak.dump" ] || { echo "idp-backup: empty dump"; exit 1; }
# srv/idp/state holds the vetted-administrator allowlist (admins.json) and the guard's state: without it a restored
# host has no vetted administrator (the guard then stops and alerts rather than act on the sole administrator)
tar -C / -cf "$W/files.tar" srv/idp/config srv/idp/secrets srv/idp/clients srv/idp/pki srv/idp/compose srv/idp/state etc/letsencrypt
tar -C "$W" -czf "$W/idp.tar.gz" keycloak.dump files.tar
gpg --batch --quiet --yes --pinentry-mode loopback --passphrase-file "$PASS" --symmetric --cipher-algo AES256 \
    -o "$W/idp-$STAMP.tar.gz.gpg" "$W/idp.tar.gz"
ST=$(imds https://storage.azure.com/)
curl -fsS -o /dev/null -X PUT -H "Authorization: Bearer $ST" -H "x-ms-version: 2021-08-06" -H "x-ms-blob-type: BlockBlob" \
  -H "Content-Type: application/octet-stream" --data-binary @"$W/idp-$STAMP.tar.gz.gpg" \
  "https://$STORAGE_ACCOUNT.blob.core.windows.net/backups/idp-$STAMP.tar.gz.gpg"
echo "idp-backup: uploaded backups/idp-$STAMP.tar.gz.gpg ($(stat -c %s "$W/idp-$STAMP.tar.gz.gpg") bytes, sha256 $(sha256sum "$W/idp-$STAMP.tar.gz.gpg" | cut -c1-16)...)"

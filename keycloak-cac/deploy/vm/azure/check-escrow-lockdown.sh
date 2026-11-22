#!/usr/bin/env bash
# Install step, after the FIRST backup and the re-run of azure-provision.sh that follows it: checks that the backup
# passphrase is escrowed and that the VM's identity can no longer write it. Read-only (it changes nothing).
#   SUB=<subscription> RG=<resource group> N=<vm name> KV=<key vault> [KV_SECRET=idp-backup-passphrase] ./check-escrow-lockdown.sh
# Exit 0: escrowed, and the VM holds only the reader role on that secret. Exit 1: not yet - with what to do.
set -euo pipefail
need() { for v in "$@"; do [ -n "${!v:-}" ] || { echo "REFUSED: set $v (see the header of $0)" >&2; exit 2; }; done; }
need SUB RG N KV
command -v jq >/dev/null || { echo "REFUSED: jq is required" >&2; exit 2; }
KV_SECRET=${KV_SECRET:-idp-backup-passphrase}
az account set -s "$SUB"
PRINCIPAL=$(az vm show -g "$RG" -n "$N" --query identity.principalId -o tsv)
KV_ID=$(az keyvault show -g "$RG" -n "$KV" --query id -o tsv)
SCOPE="$KV_ID/secrets/$KV_SECRET"
ok=1
ESCROWED=$(az keyvault secret list-versions --vault-name "$KV" -n "$KV_SECRET" --query "length([?contentType!='pending'])" -o tsv)
if ! [[ "$ESCROWED" =~ ^[0-9]+$ ]] || [ "$ESCROWED" -eq 0 ]; then
  echo "NOT YET: no escrowed version of $KV/$KV_SECRET - run the first backup (sudo systemctl start idp-backup) and look for 'passphrase escrowed'"; ok=0
fi
ROLES=$(az role assignment list --assignee "$PRINCIPAL" --all --query "[?scope=='$SCOPE' || scope=='$KV_ID'].{r: roleDefinitionName, s: scope}" -o json)
has() { jq -e --arg r "$1" --arg s "$2" 'any(.[]; .r == $r and .s == $s)' <<<"$ROLES" >/dev/null; }
has "idp passphrase reader ($RG)" "$SCOPE" || { echo "NOT YET: the VM does not hold 'idp passphrase reader ($RG)' on $SCOPE"; ok=0; }
for r in "idp passphrase escrow ($RG)" "Key Vault Secrets Officer"; do
  for s in "$SCOPE" "$KV_ID"; do has "$r" "$s" && { echo "NOT YET: the VM still holds '$r' on $s (it can write the passphrase)"; ok=0; }; done
done
OTHER=$(jq -r --arg rd "idp passphrase reader ($RG)" '[.[] | select(.r != $rd)] | map("\(.r) on \(.s)") | join("; ")' <<<"$ROLES")
[ -z "$OTHER" ] || { echo "NOT YET: the VM holds other roles on the vault or the secret: $OTHER"; ok=0; }
if [ "$ok" = 1 ]; then
  echo "OK: $KV/$KV_SECRET is escrowed ($ESCROWED version(s)) and the VM can only read it"
else
  echo "-> re-run azure-provision.sh (without KEEP_PASSPHRASE_WRITE=1), then this check again"; exit 1
fi

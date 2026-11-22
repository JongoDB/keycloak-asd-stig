#!/usr/bin/env bash
# keycloak-cac on one Azure VM: the Azure resources. Idempotent: re-running creates what is missing and re-applies
# the NSG rules (use it to move the operator IP: OPERATOR_IP=<new ip> ./azure-provision.sh).
# Runs from an operator machine with `az` logged in. Prints no secrets (it creates none). Never touches any other
# resource group. Every instance name is REQUIRED (no defaults that could point at someone else's resources):
#
#   SUB=<subscription id> RG=<resource group> N=<vm name> SA=<storage account> KV=<key vault> \
#   ACME_ZONE=<acme.your-domain> ACME_NAMES="idp" OWNER=<owner tag> ./azure-provision.sh
#
# Optional: L (region, default eastus), SIZE, IMAGE, VNET_PREFIX/SUBNET_PREFIX/PRIVATE_IP (default 10.0.0.0/16,
# 10.0.1.0/24, 10.0.1.10 - egress.sh's KC_IP must match PRIVATE_IP's bridge layout only if you change compose.yaml),
# OPERATOR_IP (default: your current public address), SSH_KEY,
# BACKUP_RETENTION_DAYS (default 90: how long each backup is immutable - not even the VM, nor anyone without the
# right to change the policy, can delete or overwrite it - and is then expired), LOCK_BACKUP_IMMUTABILITY=1 (lock that
# policy: irreversible, it can then only be extended; leave unset until the retention period is settled),
# KV_SECRET (default idp-backup-passphrase: the one Key Vault secret the VM may read and write; set the same name as
# KV_SECRET in the VM's /etc/default/idp-backup if you change it), KEEP_PASSPHRASE_WRITE=1 (opt out of dropping the
# VM's write access to that secret once it is escrowed - see the Key Vault section).
set -euo pipefail
need() { for v in "$@"; do [ -n "${!v:-}" ] || { echo "REFUSED: set $v (see the header of $0)" >&2; exit 2; }; done; }
need SUB RG N SA KV ACME_ZONE ACME_NAMES OWNER
command -v jq >/dev/null || { echo "REFUSED: jq is required" >&2; exit 2; }
L=${L:-eastus}
SIZE=${SIZE:-Standard_D4s_v3}          # 4 vCPU / 16 GiB: keycloak-cac 8 GiB limit (DoD CRL set) + admin node + PostgreSQL
IMAGE=${IMAGE:-Canonical:ubuntu-24_04-lts:server:latest}
VNET_PREFIX=${VNET_PREFIX:-10.0.0.0/16}; SUBNET_PREFIX=${SUBNET_PREFIX:-10.0.1.0/24}; PRIVATE_IP=${PRIVATE_IP:-10.0.1.10}
OPERATOR_IP=${OPERATOR_IP:-$(curl -fsS https://api.ipify.org)}
SSH_KEY=${SSH_KEY:-$HOME/.ssh/$N}
BACKUP_RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-90}
KV_SECRET=${KV_SECRET:-idp-backup-passphrase}
# capped at 365: blob and container soft delete (which use the same period) allow at most 365 days
[[ "$BACKUP_RETENTION_DAYS" =~ ^[0-9]+$ ]] && [ "$BACKUP_RETENTION_DAYS" -ge 1 ] && [ "$BACKUP_RETENTION_DAYS" -le 365 ] \
  || { echo "REFUSED: BACKUP_RETENTION_DAYS is a whole number of days, 1..365" >&2; exit 2; }
TAGS=(owner="$OWNER" project=idp purpose=cac-idp)
az account set -s "$SUB"
[ -f "$SSH_KEY" ] || ssh-keygen -q -t ed25519 -N "" -C "$N" -f "$SSH_KEY"

az group show -n "$RG" >/dev/null 2>&1 || az group create -n "$RG" -l "$L" --tags "${TAGS[@]}" -o none

# NSG: 443 from the internet (sign-in, relying apps and the realm's admin console - access by realm role, MFA on
#      every sign-in; an exposure the operator must accept), 22 from the operator's /32 only. An earlier layout
#      restricted an admin node on 8444 to the operator's IP; that rule is removed below if present.
az network nsg show -g "$RG" -n "$N-nsg" >/dev/null 2>&1 || az network nsg create -g "$RG" -n "$N-nsg" -l "$L" --tags "${TAGS[@]}" -o none
rule() { az network nsg rule create -g "$RG" --nsg-name "$N-nsg" -n "$1" --priority "$2" --direction Inbound --access Allow \
           --protocol Tcp --source-address-prefixes "$3" --destination-port-ranges "$4" -o none; }
rule allow-https 100 Internet 443
# 8444: the card port (STIG_CARD_PORT) - the same Keycloak listener; the present-card step's POST goes there so that the
# browser makes a new TLS handshake and is asked for the CAC (2026-11-22)
rule allow-card-port 105 Internet 8444
rule allow-ssh-operator 110 "$OPERATOR_IP/32" 22
az network nsg rule delete -g "$RG" --nsg-name "$N-nsg" -n allow-admin-operator -o none 2>/dev/null || true

az network vnet show -g "$RG" -n "$N-vnet" >/dev/null 2>&1 || az network vnet create -g "$RG" -n "$N-vnet" -l "$L" \
  --address-prefixes "$VNET_PREFIX" --subnet-name "$N-snet" --subnet-prefixes "$SUBNET_PREFIX" --network-security-group "$N-nsg" --tags "${TAGS[@]}" -o none
az network public-ip show -g "$RG" -n "$N-pip" >/dev/null 2>&1 || az network public-ip create -g "$RG" -n "$N-pip" -l "$L" \
  --sku Standard --allocation-method Static --tags "${TAGS[@]}" -o none
az network nic show -g "$RG" -n "$N-nic" >/dev/null 2>&1 || az network nic create -g "$RG" -n "$N-nic" -l "$L" \
  --vnet-name "$N-vnet" --subnet "$N-snet" --public-ip-address "$N-pip" --private-ip-address "$PRIVATE_IP" --tags "${TAGS[@]}" -o none

# VM: non-zonal (some sizes are not available in every zone of a subscription), Trusted Launch, system identity.
if ! az vm show -g "$RG" -n "$N" >/dev/null 2>&1; then
  az vm create -g "$RG" -n "$N" -l "$L" --size "$SIZE" --image "$IMAGE" --security-type TrustedLaunch \
    --enable-secure-boot true --enable-vtpm true --nics "$N-nic" --admin-username azureuser --authentication-type ssh \
    --ssh-key-values "$SSH_KEY.pub" --os-disk-name "$N-osdisk" --os-disk-size-gb 64 --storage-sku StandardSSD_LRS \
    --data-disk-sizes-gb 64 --data-disk-caching ReadOnly --assign-identity '[system]' --computer-name "$N" \
    --tags "${TAGS[@]}" -o none
fi
PRINCIPAL=$(az vm show -g "$RG" -n "$N" --query identity.principalId -o tsv)

# Backups: private storage account (no public blob access, TLS 1.2+, no shared-key auth: identity only), container
# `backups`. Contents are also gpg-encrypted on the VM. A compromised VM must not be able to destroy its own backups:
#   - the container has a time-based immutability (WORM) policy of BACKUP_RETENTION_DAYS: no blob in it can be
#     deleted or overwritten by anyone until it is that old (lock it with LOCK_BACKUP_IMMUTABILITY=1);
#   - blob and container soft delete (BACKUP_RETENTION_DAYS) as a second net, e.g. for a container deleted by an
#     account administrator;
#   - the VM's identity holds a custom role with read, create and write only - no delete action of any kind;
#   - lifecycle management expires backups the day after their immutability ends.
if ! az storage account show -g "$RG" -n "$SA" >/dev/null 2>&1; then
  az storage account create -g "$RG" -n "$SA" -l "$L" --sku Standard_LRS --kind StorageV2 --min-tls-version TLS1_2 \
    --allow-blob-public-access false --allow-shared-key-access false --https-only true --tags "${TAGS[@]}" -o none
fi
SA_ID=$(az storage account show -g "$RG" -n "$SA" --query id -o tsv)
az storage container show --account-name "$SA" -n backups --auth-mode login >/dev/null 2>&1 || {
  az role assignment create --assignee "$(az ad signed-in-user show --query id -o tsv)" --role "Storage Blob Data Contributor" --scope "$SA_ID" -o none 2>/dev/null || true
  for i in 1 2 3 4 5 6; do az storage container create --account-name "$SA" -n backups --auth-mode login -o none 2>/dev/null && break; sleep 20; done; }
az storage account blob-service-properties update -g "$RG" --account-name "$SA" -o none \
  --enable-delete-retention true --delete-retention-days "$BACKUP_RETENTION_DAYS" \
  --enable-container-delete-retention true --container-delete-retention-days "$BACKUP_RETENTION_DAYS"
POLICY_STATE=$(az storage container immutability-policy show -g "$RG" --account-name "$SA" -c backups --query state -o tsv 2>/dev/null || true)
if [ "$POLICY_STATE" = Locked ]; then
  echo "backups: immutability policy is locked (it can only be extended: az storage container immutability-policy extend)"
else
  az storage container immutability-policy create -g "$RG" --account-name "$SA" -c backups \
    --period "$BACKUP_RETENTION_DAYS" --allow-protected-append-writes false -o none
  if [ "${LOCK_BACKUP_IMMUTABILITY:-}" = 1 ]; then
    ETAG=$(az storage container immutability-policy show -g "$RG" --account-name "$SA" -c backups --query etag -o tsv)
    az storage container immutability-policy lock -g "$RG" --account-name "$SA" -c backups --if-match "$ETAG" -o none
    echo "backups: immutability policy LOCKED at $BACKUP_RETENTION_DAYS days"
  fi
fi
az storage account management-policy create -g "$RG" --account-name "$SA" -o none --policy \
  "{\"rules\":[{\"enabled\":true,\"name\":\"expire-backups\",\"type\":\"Lifecycle\",\"definition\":{\"actions\":{\"baseBlob\":{\"delete\":{\"daysAfterModificationGreaterThan\":$((BACKUP_RETENTION_DAYS + 1))}}},\"filters\":{\"blobTypes\":[\"blockBlob\"],\"prefixMatch\":[\"backups/\"]}}}]}"
# custom_role <name> <description> <actions, space-separated> <data actions, space-separated>: a custom role assignable
# in this resource group with EXACTLY these permissions - created if missing, and reconciled (updated) if an existing
# definition of that name grants anything else or lacks something.
RG_ID=$(az group show -n "$RG" --query id -o tsv)
custom_role() {
  local name="$1" desc="$2" acts="$3" dacts="$4" id want have
  want=$(jq -cn --arg a "$acts" --arg d "$dacts" '{a: ($a | split(" ") | map(select(. != "")) | sort), d: ($d | split(" ") | map(select(. != "")) | sort)}')
  id=$(az role definition list --custom-role-only true --name "$name" --query '[0].id' -o tsv)
  if [ -n "$id" ]; then
    have=$(az role definition list --custom-role-only true --name "$name" \
      --query '[0].permissions[0].{a: actions, d: dataActions, na: notActions, nd: notDataActions}' -o json \
      | jq -c '{a: (.a // [] | sort), d: (.d // [] | sort)} + (if ((.na // []) + (.nd // [])) == [] then {} else {x: true} end)')
    [ "$have" = "$want" ] && return 0
    echo "custom role '$name': permissions differ from what this script grants - reconciling"
  fi
  az role definition "$([ -n "$id" ] && echo update || echo create)" -o none --role-definition "$(jq -n --arg n "$name" \
    --arg d "$desc" --arg s "$RG_ID" --arg id "${id##*/}" --argjson w "$want" \
    '{Name: $n, Description: $d, Actions: $w.a, NotActions: [], DataActions: $w.d, NotDataActions: [], AssignableScopes: [$s]}
     + (if $id == "" then {} else {Id: $id} end)')"
  for i in 1 2 3 4 5 6; do az role definition list --custom-role-only true --name "$name" --query '[0].id' -o tsv | grep -q . && return 0; sleep 10; done
}
# the VM's role on the container: read (restore, list), create and write - and nothing that deletes
WRITER_ROLE="idp backup writer ($RG)"
custom_role "$WRITER_ROLE" "Read, create and write blobs; no delete. The IdP VM's identity on its backups container." "" \
  "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"
az role assignment create --assignee-object-id "$PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --role "$WRITER_ROLE" --scope "$SA_ID/blobServices/default/containers/backups" -o none
# a VM provisioned by an earlier version of this script held Storage Blob Data Contributor (delete included): remove it
az role assignment delete --assignee "$PRINCIPAL" --role "Storage Blob Data Contributor" \
  --scope "$SA_ID/blobServices/default/containers/backups" -o none 2>/dev/null || true

# Key Vault (RBAC, purge protection): holds the backup passphrase, which the VM generates and escrows itself; the
# operator can read it for a restore onto a new VM. The VM's identity reaches exactly ONE secret, through a custom role
# scoped to it with get, set and read-metadata only - it can neither delete, purge, recover, back up nor restore it,
# and purge protection keeps even a deleted secret recoverable for the retention period. The role needs the secret to
# exist, so it is created here holding a placeholder (contentType "pending") that backup.sh replaces on its first run.
# Each escrow is a new version; restore.sh tries every version, newest first.
# Once the passphrase is escrowed (the secret is no longer the placeholder), a re-run leaves the VM get and
# read-metadata only, BY DEFAULT: it can then no longer write versions over the real passphrase. So re-run this script
# after the first backup (backup.sh logs "passphrase escrowed"); until then the VM holds the escrow role. Opt out
# with KEEP_PASSPHRASE_WRITE=1 (e.g. to let the VM escrow a rotated passphrase). backup.sh only ever writes while the
# secret is missing or the placeholder, so it keeps working read-only.
az keyvault show -g "$RG" -n "$KV" >/dev/null 2>&1 || az keyvault create -g "$RG" -n "$KV" -l "$L" \
  --enable-rbac-authorization true --retention-days 90 --enable-purge-protection true --tags "${TAGS[@]}" -o none
[ "$(az keyvault show -g "$RG" -n "$KV" --query properties.enablePurgeProtection -o tsv)" = true ] \
  || az keyvault update -g "$RG" -n "$KV" --enable-purge-protection true -o none      # irreversible, by design
KV_ID=$(az keyvault show -g "$RG" -n "$KV" --query id -o tsv)
az role assignment create --assignee "$(az ad signed-in-user show --query id -o tsv)" --role "Key Vault Secrets Officer" --scope "$KV_ID" -o none
if ! az keyvault secret show --vault-name "$KV" -n "$KV_SECRET" --query id -o tsv >/dev/null 2>&1; then
  for i in 1 2 3 4 5 6; do      # the operator's own assignment may take a minute to apply
    az keyvault secret set --vault-name "$KV" -n "$KV_SECRET" --value pending --content-type pending -o none 2>/dev/null && break; sleep 20
  done
fi
ESCROW_ROLE="idp passphrase escrow ($RG)"; READER_ROLE="idp passphrase reader ($RG)"
custom_role "$ESCROW_ROLE" "Get, set and read the metadata of one secret; no delete, purge, recover, backup or restore." "" \
  "Microsoft.KeyVault/vaults/secrets/getSecret/action Microsoft.KeyVault/vaults/secrets/setSecret/action Microsoft.KeyVault/vaults/secrets/readMetadata/action"
custom_role "$READER_ROLE" "Get and read the metadata of one secret; nothing else." "" \
  "Microsoft.KeyVault/vaults/secrets/getSecret/action Microsoft.KeyVault/vaults/secrets/readMetadata/action"
SECRET_SCOPE="$KV_ID/secrets/$KV_SECRET"
# escrowed = ANY version of the secret is not the placeholder (not merely the latest one: a placeholder written over a
# real passphrase must not hand the VM its write access back)
ESCROWED=$(az keyvault secret list-versions --vault-name "$KV" -n "$KV_SECRET" --query "length([?contentType!='pending'])" -o tsv)
[[ "$ESCROWED" =~ ^[0-9]+$ ]] || { echo "REFUSED: cannot list the versions of $KV/$KV_SECRET" >&2; exit 1; }
if [ "$ESCROWED" -gt 0 ] && [ "${KEEP_PASSPHRASE_WRITE:-}" != 1 ]; then
  KEEP="$READER_ROLE"; DROP="$ESCROW_ROLE"; echo "key vault: passphrase escrowed - the VM keeps read access only"
else
  KEEP="$ESCROW_ROLE"; DROP="$READER_ROLE"
  [ "$ESCROWED" -eq 0 ] && echo "key vault: passphrase NOT escrowed yet - after the first backup, re-run this script and then azure/check-escrow-lockdown.sh (install step)"
fi
az role assignment create --assignee-object-id "$PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --role "$KEEP" --scope "$SECRET_SCOPE" -o none
az role assignment delete --assignee "$PRINCIPAL" --role "$DROP" --scope "$SECRET_SCOPE" -o none 2>/dev/null || true
# assignments an earlier version of this script made (Secrets Officer: delete and purge included) are removed
az role assignment delete --assignee "$PRINCIPAL" --role "Key Vault Secrets Officer" --scope "$SECRET_SCOPE" -o none 2>/dev/null || true
az role assignment delete --assignee "$PRINCIPAL" --role "Key Vault Secrets Officer" --scope "$KV_ID" -o none 2>/dev/null || true

# ACME DNS-01 without a DNS provider token on the host: the parent zone (e.g. at Cloudflare, cloudflare-dns.sh)
# delegates $ACME_ZONE to this Azure DNS zone and CNAMEs _acme-challenge.<name>.<domain> into it. The VM's identity
# may write exactly the TXT record sets of its own names - nothing else in this zone, and nothing in the parent.
az network dns zone show -g "$RG" -n "$ACME_ZONE" >/dev/null 2>&1 || az network dns zone create -g "$RG" -n "$ACME_ZONE" --tags "${TAGS[@]}" -o none
TXT_ROLE="idp acme txt writer ($RG)"
custom_role "$TXT_ROLE" "Read and write one TXT record set; nothing else in the zone." \
  "Microsoft.Network/dnsZones/TXT/read Microsoft.Network/dnsZones/TXT/write" ""
for a in $ACME_NAMES; do
  az network dns record-set txt show -g "$RG" -z "$ACME_ZONE" -n "_acme-challenge.$a" >/dev/null 2>&1 || {
    az network dns record-set txt create -g "$RG" -z "$ACME_ZONE" -n "_acme-challenge.$a" --ttl 60 -o none
    az network dns record-set txt add-record -g "$RG" -z "$ACME_ZONE" -n "_acme-challenge.$a" -v idle -o none; }
  TXT_ID=$(az network dns record-set txt show -g "$RG" -z "$ACME_ZONE" -n "_acme-challenge.$a" --query id -o tsv)
  az role assignment create --assignee-object-id "$PRINCIPAL" --assignee-principal-type ServicePrincipal --role "$TXT_ROLE" --scope "$TXT_ID" -o none
  # an earlier version of this script granted DNS Zone Contributor here (delete included): remove it
  az role assignment delete --assignee "$PRINCIPAL" --role "DNS Zone Contributor" --scope "$TXT_ID" -o none 2>/dev/null || true
done

az vm show -d -g "$RG" -n "$N" --query "{vm:id,size:hardwareProfile.vmSize,ip:publicIps,private:privateIps,image:storageProfile.imageReference.exactVersion}" -o json

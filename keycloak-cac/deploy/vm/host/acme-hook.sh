#!/usr/bin/env bash
# certbot --manual DNS-01 hook for the shared IdP. No DNS-provider token on this host: each name's
# _acme-challenge.<name>.<domain> is a CNAME (e.g. at Cloudflare) to _acme-challenge.<name>.<ACME_ZONE> in an Azure DNS
# zone, and the VM's identity holds DNS Zone Contributor on exactly those TXT record sets. A compromised host can
# therefore change no other DNS record.
#   idp-acme-hook auth      (certbot sets CERTBOT_DOMAIN, CERTBOT_VALIDATION) -> write the TXT value, wait until served
#   idp-acme-hook cleanup                                                       -> set it back to "idle" (never delete:
#                                                                                  the role is scoped to the record set)
# Configuration: /etc/default/idp-acme (root-owned, not group/world-writable) - ACME_ZONE, ACME_RG, ACME_PARENT,
# ACME_DOMAINS, parsed as data and never sourced. The bearer token never reaches argv: it goes to curl as a header FILE in a 0700 directory.
set -euo pipefail
umask 077
CONF=/etc/default/idp-acme
[ "$(stat -c '%u' "$CONF")" = 0 ] && [ $(( 0$(stat -c '%a' "$CONF") & 022 )) = 0 ] \
  || { echo "idp-acme-hook: $CONF must be root-owned and not group/world-writable"; exit 1; }
# The config is DATA: read as KEY=value lines, never sourced, so nothing in it can execute. A key given twice is
# refused (which one would win is exactly the ambiguity an attacker wants).
ACME_ZONE=; ACME_RG=; ACME_PARENT=; ACME_DOMAINS=; declare -A SEEN=()
while IFS= read -r line || [ -n "$line" ]; do
  [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
  [[ "$line" =~ ^([A-Z_]+)=\"?([^\"]*)\"?$ ]] || { echo "idp-acme-hook: unparseable line in $CONF"; exit 1; }
  [ -z "${SEEN[${BASH_REMATCH[1]}]:-}" ] || { echo "idp-acme-hook: ${BASH_REMATCH[1]} is set twice in $CONF"; exit 1; }
  SEEN[${BASH_REMATCH[1]}]=1
  case "${BASH_REMATCH[1]}" in
    ACME_ZONE) ACME_ZONE="${BASH_REMATCH[2]}";; ACME_RG) ACME_RG="${BASH_REMATCH[2]}";;
    ACME_PARENT) ACME_PARENT="${BASH_REMATCH[2]}";; ACME_DOMAINS) ACME_DOMAINS="${BASH_REMATCH[2]}";;
  esac
done < "$CONF"
# DNS-label shape: dot-separated non-empty labels, so "..", a leading or a trailing dot are refused.
DNS='^[a-z0-9-]+(\.[a-z0-9-]+)*$'
for v in "$ACME_ZONE" "$ACME_PARENT"; do
  [[ "$v" =~ $DNS ]] || { echo "idp-acme-hook: ACME_ZONE and ACME_PARENT must be DNS-label shaped"; exit 1; }
done
# an Azure resource group name: letters (either case), digits, . _ - (parentheses are allowed by Azure, not here)
[[ "$ACME_RG" =~ ^[A-Za-z0-9._-]{1,90}$ ]] || { echo "idp-acme-hook: ACME_RG is not a resource group name"; exit 1; }
[ -n "$ACME_DOMAINS" ] || { echo "idp-acme-hook: ACME_DOMAINS is empty"; exit 1; }
for d in $ACME_DOMAINS; do [[ "$d" =~ $DNS ]] || { echo "idp-acme-hook: ACME_DOMAINS must be space-separated DNS names"; exit 1; }; done
[[ "$ACME_DOMAINS" =~ ^[a-z0-9.-]+( [a-z0-9.-]+)*$ ]] || { echo "idp-acme-hook: ACME_DOMAINS must be single-space separated"; exit 1; }

case "${1:-}" in
  auth)    VALUE="${CERTBOT_VALIDATION:?}";;
  cleanup) VALUE=idle;;
  *) sed -n '2,8p' "$0"; exit 2;;
esac
[[ "$VALUE" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "idp-acme-hook: unexpected validation value"; exit 1; }
DOMAIN="${CERTBOT_DOMAIN:?}"
[[ " $ACME_DOMAINS " == *" $DOMAIN "* ]] || { echo "idp-acme-hook: $DOMAIN is not in ACME_DOMAINS"; exit 1; }
LABEL="${DOMAIN%."$ACME_PARENT"}"
[[ "$LABEL" =~ ^[a-z0-9-]+$ ]] || { echo "idp-acme-hook: cannot derive a label from $DOMAIN"; exit 1; }
RECORD="_acme-challenge.$LABEL"

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
SUB=$(curl -fsS -H Metadata:true "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01" | jq -r .subscriptionId)
# the subscription goes into the ARM URL: it must be a GUID, nothing else
[[ "$SUB" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "idp-acme-hook: unexpected subscription id from IMDS"; exit 1; }
curl -fsS -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq -r '"Authorization: Bearer " + .access_token' > "$W/auth"
URL="https://management.azure.com/subscriptions/$SUB/resourceGroups/$ACME_RG/providers/Microsoft.Network/dnsZones/$ACME_ZONE/TXT/$RECORD?api-version=2018-05-01"
jq -n --arg v "$VALUE" '{properties: {TTL: 60, TXTRecords: [{value: [$v]}]}}' \
  | curl -fsS -o /dev/null -X PUT -H @"$W/auth" -H "Content-Type: application/json" --data-binary @- "$URL"
[ "$1" = cleanup ] && exit 0

# Wait until EVERY name server of the zone serves the new value, then let the 60 s TTL of the previous value ("idle")
# age out of resolver caches: the CA validates from several vantage points, and one stale answer fails the order.
NS=$(dig +short NS "$ACME_ZONE" @1.1.1.1)
[ -n "$NS" ] || { echo "idp-acme-hook: no NS for $ACME_ZONE"; exit 1; }
for i in $(seq 1 120); do
  ok=1; for ns in $NS; do dig +short TXT "$RECORD.$ACME_ZONE" @"$ns" | grep -q "\"$VALUE\"" || ok=0; done
  if [ $ok = 1 ]; then echo "idp-acme-hook: $RECORD live on all $(echo $NS | wc -w) name servers after ${i}s; settling 65s"; sleep 65; exit 0; fi
  sleep 1
done
echo "idp-acme-hook: $RECORD not on every name server after 120s"; exit 1

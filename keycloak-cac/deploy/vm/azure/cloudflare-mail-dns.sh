#!/usr/bin/env bash
# DNS for the IdP's outbound mail (Azure Communication Services Email, sender domain MAIL_DOMAIN): the ACS
# domain-verification TXT, SPF, the two DKIM CNAMEs and a DMARC policy. Idempotent (creates or updates by type+name+content
# family). Reads the values from Azure; the Cloudflare token is read from a file and never printed.
#   RG=<resource group> ECS=<email service> MAIL_DOMAIN=<notify.your-domain> ZONE=<your-domain> \
#   CF_TOKEN_FILE=<token file> ./cloudflare-mail-dns.sh
set -euo pipefail
RG="${RG:?set RG}"; ECS="${ECS:?set ECS (the email communication service)}"; D="${MAIL_DOMAIN:?set MAIL_DOMAIN}"
ZONE="${ZONE:?set ZONE}"
T="$(tr -d '\r\n' < "${CF_TOKEN_FILE:?set CF_TOKEN_FILE}")"
# the token never reaches a command line (ps, /proc): a header file in a 0700 directory, removed on exit
AUTHD=$(mktemp -d); chmod 700 "$AUTHD"; trap 'rm -rf "$AUTHD"' EXIT
( umask 077; printf 'Authorization: Bearer %s\n' "$T" > "$AUTHD/cf" ); T=""
api() { curl -fsS -H @"$AUTHD/cf" -H "Content-Type: application/json" "$@"; }
ZID=$(api "https://api.cloudflare.com/client/v4/zones?name=$ZONE" | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"][0]["id"])')
REC=$(az communication email domain show -g "$RG" --email-service-name "$ECS" -n "$D" --query verificationRecords -o json 2>/dev/null)
upsert() { # type name content match-prefix
  local type="$1" name="$2" content="$3" prefix="$4" rid body
  body=$(python3 -c 'import json,sys;print(json.dumps({"type":sys.argv[1],"name":sys.argv[2],"content":sys.argv[3],"ttl":3600,"proxied":False,"comment":"IdP mail (ACS)"}))' "$type" "$name" "$content")
  rid=$(api "https://api.cloudflare.com/client/v4/zones/$ZID/dns_records?type=$type&name=$name" | python3 -c 'import json,sys
r=[x for x in json.load(sys.stdin)["result"] if x["content"].strip("\"").startswith(sys.argv[1])]
print(r[0]["id"] if r else "")' "$prefix")
  if [ -n "$rid" ]; then api -X PUT "https://api.cloudflare.com/client/v4/zones/$ZID/dns_records/$rid" -d "$body" >/dev/null; echo "updated $type $name"
  else api -X POST "https://api.cloudflare.com/client/v4/zones/$ZID/dns_records" -d "$body" >/dev/null; echo "created $type $name"; fi
}
val() { python3 -c 'import json,sys;d=json.loads(sys.argv[1])[sys.argv[2]];print(d["name"]+"\t"+d["value"])' "$REC" "$1"; }
IFS=$'\t' read -r n v < <(val Domain); upsert TXT "$D" "$v" "ms-domain-verification="
IFS=$'\t' read -r n v < <(val SPF);    upsert TXT "$D" "$v" "v=spf1"
IFS=$'\t' read -r n v < <(val DKIM);   upsert CNAME "$n.$D" "$v" ""
IFS=$'\t' read -r n v < <(val DKIM2);  upsert CNAME "$n.$D" "$v" ""
upsert TXT "_dmarc.$D" "v=DMARC1; p=quarantine; adkim=s; aspf=s" "v=DMARC1"

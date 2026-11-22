#!/usr/bin/env bash
# DNS-only (not proxied) A records for the IdP, so browsers' CAC client certificates reach Keycloak's own TLS.
# Idempotent: creates or updates. Token: Zone:DNS:Edit + Zone:Zone:Read on ZONE, read from a file, never printed.
#   ZONE=<your zone> NAMES="idp" CF_TOKEN_FILE=<token file> ./cloudflare-dns.sh <public ip>
set -euo pipefail
IP="${1:?usage: ZONE=<zone> NAMES=\"idp ...\" CF_TOKEN_FILE=<file> cloudflare-dns.sh <public ip>}"
ZONE="${ZONE:?set ZONE}"; NAMES="${NAMES:?set NAMES (labels under ZONE)}"
T="$(tr -d '\r\n' < "${CF_TOKEN_FILE:?set CF_TOKEN_FILE}")"   # a trailing newline would join the bearer
# the token never reaches a command line (ps, /proc): a header file in a 0700 directory, removed on exit
AUTHD=$(mktemp -d); chmod 700 "$AUTHD"; trap 'rm -rf "$AUTHD"' EXIT
( umask 077; printf 'Authorization: Bearer %s\n' "$T" > "$AUTHD/cf" ); T=""
api() { curl -fsS -H @"$AUTHD/cf" -H "Content-Type: application/json" "$@"; }
ZID=$(api "https://api.cloudflare.com/client/v4/zones?name=$ZONE" | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"][0]["id"])')
for n in $NAMES; do
  fq="$n.$ZONE"; body=$(printf '{"type":"A","name":"%s","content":"%s","ttl":300,"proxied":false,"comment":"CAC IdP"}' "$fq" "$IP")
  rid=$(api "https://api.cloudflare.com/client/v4/zones/$ZID/dns_records?type=A&name=$fq" | python3 -c 'import json,sys;r=json.load(sys.stdin)["result"];print(r[0]["id"] if r else "")')
  if [ -n "$rid" ]; then api -X PUT "https://api.cloudflare.com/client/v4/zones/$ZID/dns_records/$rid" -d "$body" >/dev/null; echo "updated $fq -> $IP"
  else api -X POST "https://api.cloudflare.com/client/v4/zones/$ZID/dns_records" -d "$body" >/dev/null; echo "created $fq -> $IP"; fi
done

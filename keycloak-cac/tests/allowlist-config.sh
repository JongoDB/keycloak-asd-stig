#!/usr/bin/env bash
# The entrypoint refuses a half or retired allowlist configuration instead of silently leaving the filter off.
set -euo pipefail
E="$(cd "$(dirname "$0")/../bin" && pwd)/cac-entrypoint.sh"; T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
sed -n '/^# >>> allowlist-config/,/^# <<< allowlist-config/p' "$E" > "$T/snippet.sh"
fail=0
run() { # want(start|stop) label env...
  local want="$1" label="$2"; shift 2
  out=$(env -i PATH="$PATH" "$@" bash -c 'set -euo pipefail; log(){ echo "log: $*" >&2; }; die(){ log "ERROR $*"; exit 1; }; source "'"$T"'/snippet.sh"; echo started' 2>&1 || true)
  got=$(echo "$out" | grep -q "^started" && echo start || echo stop)
  [ "$got" = "$want" ] && echo "PASS $label -> $got" || { echo "FAIL $label -> $got ($out)"; fail=1; }
}
run start "nothing set (filter off, as before)"
run start "both set" STIG_PUBLIC_PATHS=/realms/r/ STIG_TRUSTED_SOURCES=127.0.0.1
run stop  "retired STIG_ADMIN_REALM_ALLOWED_SOURCES alone" STIG_ADMIN_REALM_ALLOWED_SOURCES=127.0.0.1
run stop  "retired variable + only STIG_TRUSTED_SOURCES" STIG_ADMIN_REALM_ALLOWED_SOURCES=127.0.0.1 STIG_TRUSTED_SOURCES=127.0.0.1
run start "retired variable left beside a full new configuration" STIG_ADMIN_REALM_ALLOWED_SOURCES=127.0.0.1 STIG_PUBLIC_PATHS=/realms/r/ STIG_TRUSTED_SOURCES=127.0.0.1
run stop  "STIG_PUBLIC_PATHS without STIG_TRUSTED_SOURCES" STIG_PUBLIC_PATHS=/realms/r/
run stop  "STIG_TRUSTED_SOURCES without STIG_PUBLIC_PATHS" STIG_TRUSTED_SOURCES=127.0.0.1
out=$(env -i PATH="$PATH" STIG_ADMIN_REALM_ALLOWED_SOURCES=127.0.0.1 bash -c 'log(){ echo "$*" >&2; }; die(){ log "$*"; exit 1; }; source "'"$T"'/snippet.sh"' 2>&1 || true)
echo "$out" | grep -q "STIG_TRUSTED_SOURCES" && echo "$out" | grep -q "STIG_PUBLIC_PATHS" && echo "PASS the refusal names both replacement variables" || { echo "FAIL message: $out"; fail=1; }
exit $fail

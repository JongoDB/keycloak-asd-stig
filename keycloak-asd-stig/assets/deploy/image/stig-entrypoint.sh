#!/bin/bash
# Runtime-agnostic secrets: KC_<NAME>_FILE=/path sets KC_<NAME> from the file, for secret-like names only
# (<NAME> ending in PASSWORD, SECRET, USERNAME or TOKEN). Keycloak's own *_FILE options such as
# KC_HTTPS_CERTIFICATE_FILE / KC_HTTPS_CERTIFICATE_KEY_FILE / KC_LOG_FILE are paths and are left alone.
# Works with docker/podman secrets (/run/secrets/*), Kubernetes Secret volumes, Vault agent files, systemd credentials.
set -euo pipefail
for var in $(compgen -e | grep -E '^KC_[A-Z0-9_]*(PASSWORD|SECRET|USERNAME|TOKEN)_FILE$' || true); do
  target="${var%_FILE}"; file="${!var}"
  if [ ! -r "$file" ]; then echo "stig-entrypoint: $var points to unreadable $file" >&2; exit 1; fi
  export "$target"="$(cat "$file")"; unset "$var"
done
# Wait for the PKI init container/job: refuse to start without a trust store (fail secure, V-222585).
if [ -n "${KC_TRUSTSTORE_PATHS:-}" ] && [ -z "$(ls -A "${KC_TRUSTSTORE_PATHS}" 2>/dev/null)" ] && [ "${STIG_REQUIRE_TRUSTSTORE:-true}" = "true" ]; then
  echo "stig-entrypoint: trust store ${KC_TRUSTSTORE_PATHS} is empty - run the PKI init step first" >&2; exit 1
fi
exec /opt/keycloak/bin/kc.sh "$@"

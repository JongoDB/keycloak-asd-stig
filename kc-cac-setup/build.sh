#!/usr/bin/env bash
# Assemble kc-cac-setup.sh = header + base64(tar.gz of the keycloak-asd-stig toolkit)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SK=/home/user/keycloak-asd-stig
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
tar -C "$(dirname "$SK")" -czf "$T/p.tgz" --exclude='keycloak-asd-stig/evals' --exclude='keycloak-asd-stig/scripts/dev' \
    --exclude='__pycache__' keycloak-asd-stig
{ cat "$HERE/header.sh"; base64 < "$T/p.tgz"; } > "$HERE/kc-cac-setup.sh"
chmod +x "$HERE/kc-cac-setup.sh"
bash -n "$HERE/kc-cac-setup.sh" 2>/dev/null || true
echo "built $HERE/kc-cac-setup.sh ($(du -h "$HERE/kc-cac-setup.sh" | cut -f1)), payload sha256 $(sha256sum "$T/p.tgz" | cut -c1-16)"

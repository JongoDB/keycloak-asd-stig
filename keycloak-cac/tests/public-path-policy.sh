#!/usr/bin/env bash
# Unit test of PublicPathPolicy (the network allowlist that keeps unlisted realms, master included, off the public
# listener). Needs a JDK (javac).
set -euo pipefail
X="$(cd "$(dirname "$0")/../../keycloak-asd-stig/assets/extension" && pwd)"; T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
javac --release 17 -encoding UTF-8 -d "$T" "$X/src/main/java/mil/stig/keycloak/PublicPathPolicy.java" "$X/src/test/java/mil/stig/keycloak/PublicPathPolicyTest.java"
java -cp "$T" mil.stig.keycloak.PublicPathPolicyTest

#!/usr/bin/env bash
# Unit test of AdminRealmPathMatcher (the master-realm network guard's path matcher). Needs a JDK (javac).
set -euo pipefail
X="$(cd "$(dirname "$0")/../../keycloak-asd-stig/assets/extension" && pwd)"; T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
javac --release 17 -d "$T" "$X/src/main/java/mil/stig/keycloak/AdminRealmPathMatcher.java" "$X/src/test/java/mil/stig/keycloak/AdminRealmPathMatcherTest.java"
java -cp "$T" mil.stig.keycloak.AdminRealmPathMatcherTest

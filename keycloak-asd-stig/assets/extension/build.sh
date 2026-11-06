#!/usr/bin/env bash
# Builds stig-extensions.jar against the exact Keycloak version you deploy.
# Usage: build.sh [keycloak-image]   (default quay.io/keycloak/keycloak:26.8.2)
# Needs: docker, javac 17+. Output: ./target/stig-extensions.jar
set -euo pipefail
IMG="${1:-quay.io/keycloak/keycloak:26.8.2}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"; docker rm -f stig-ext-cp >/dev/null 2>&1 || true' EXIT
docker create --name stig-ext-cp "$IMG" >/dev/null
mkdir -p "$WORK/lib"
JARS=$(docker run --rm --entrypoint bash "$IMG" -c 'find /opt/keycloak/lib/lib -name "*.jar"' \
  | grep -E '(keycloak-server-spi-|keycloak-server-spi-private-|keycloak-core-|keycloak-common-|keycloak-services-|org\.jboss\.logging\.jboss-logging-[0-9])')
for f in $JARS; do docker cp "stig-ext-cp:$f" "$WORK/lib/" >/dev/null; done
CP="$(ls "$WORK"/lib/*.jar | tr '\n' ':')"
mkdir -p "$WORK/classes" "$HERE/target"
javac --release 17 -nowarn -cp "$CP" -d "$WORK/classes" $(find "$HERE/src/main/java" -name '*.java')
cp -r "$HERE/src/main/resources/." "$WORK/classes/"
(cd "$WORK/classes" && jar cf "$HERE/target/stig-extensions.jar" .)
echo "built $HERE/target/stig-extensions.jar for $IMG"

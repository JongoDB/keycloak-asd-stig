#!/usr/bin/env bash
# Builds stig-extensions.jar against the exact Keycloak version you deploy.
# Usage: build.sh [keycloak-image]   (default quay.io/keycloak/keycloak:26.8.2)
# Needs: docker, javac 17+. Output: ./target/stig-extensions.jar
set -euo pipefail
IMG="${1:-quay.io/keycloak/keycloak:26.8.2@sha256:723b1d6e254c0fc96d5cffec860c7e0744d6a3277822b865bb538cf891575e41}"   # pinned by digest
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"; docker rm -f stig-ext-cp >/dev/null 2>&1 || true' EXIT
docker create --name stig-ext-cp "$IMG" >/dev/null
mkdir -p "$WORK/lib"
JARS=$(docker run --rm --entrypoint bash "$IMG" -c 'find /opt/keycloak/lib/lib -name "*.jar"' \
  | grep -E '(keycloak-server-spi-|keycloak-server-spi-private-|keycloak-core-|keycloak-common-|keycloak-services-|org\.jboss\.logging\.jboss-logging-[0-9]|jakarta\.ws\.rs\.jakarta\.ws\.rs-api-|io\.vertx\.vertx-core-[0-9])')
for f in $JARS; do docker cp "stig-ext-cp:$f" "$WORK/lib/" >/dev/null; done
CP="$(ls "$WORK"/lib/*.jar | tr '\n' ':')"
mkdir -p "$WORK/classes" "$HERE/target"
cp -r "$HERE/src" "$WORK/src"
if javac -version >/dev/null 2>&1; then
  javac --release 17 -encoding UTF-8 -nowarn -cp "$CP" -d "$WORK/classes" $(find "$WORK/src/main/java" -name '*.java')
  cp -r "$WORK/src/main/resources/." "$WORK/classes/"
  (cd "$WORK/classes" && jar cf "$WORK/stig-extensions.jar" .)
else    # no local JDK: the same javac in a pinned Temurin 17 container
  JDK="${JDK_IMAGE:-eclipse-temurin:17-jdk@sha256:43338b737d0f75d6883d3c4563bc66974113ca8ac296e82f39d161fb3d398f0d}"
  docker run --rm -v "$WORK:/w" -w /w --entrypoint bash "$JDK" -c \
    'javac --release 17 -encoding UTF-8 -nowarn -cp "$(ls lib/*.jar | tr "\n" ":")" -d classes $(find src/main/java -name "*.java") && cp -r src/main/resources/. classes/ && (cd classes && jar cf ../stig-extensions.jar .)'
fi
# unit tests (src/test/java, plain main() - no test framework): a failure fails the build
if [ -d "$WORK/src/test/java" ]; then
  if javac -version >/dev/null 2>&1; then
    javac --release 17 -encoding UTF-8 -nowarn -cp "$WORK/stig-extensions.jar:$CP" -d "$WORK/tclasses" $(find "$WORK/src/test/java" -name '*.java')
    for t in $(cd "$WORK/src/test/java" && find . -name '*Test.java' | sed 's#^\./##; s#\.java$##; s#/#.#g'); do
      java -cp "$WORK/tclasses:$WORK/stig-extensions.jar:$CP" "$t"
    done
  else
    docker run --rm -v "$WORK:/w" -w /w --entrypoint bash "$JDK" -c \
      'CP="stig-extensions.jar:$(ls lib/*.jar | tr "\n" ":")"; javac --release 17 -encoding UTF-8 -nowarn -cp "$CP" -d tclasses $(find src/test/java -name "*.java") && for t in $(cd src/test/java && find . -name "*Test.java" | sed "s#^\./##; s#\.java\$##; s#/#.#g"); do java -cp "tclasses:$CP" "$t" || exit 1; done'
  fi
fi
cp "$WORK/stig-extensions.jar" "$HERE/target/stig-extensions.jar"
echo "built $HERE/target/stig-extensions.jar for $IMG"

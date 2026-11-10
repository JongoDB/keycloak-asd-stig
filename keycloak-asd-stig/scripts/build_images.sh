#!/usr/bin/env bash
# Build (and optionally push, SBOM, sign) the two OCI images of the Keycloak ASD STIG deployment:
#   <registry>/keycloak-stig:<tag>        Keycloak + dod-stig theme + stig-extensions (+ BC-FIPS with --fips)
#   <registry>/kcstig-tools:<tag>         PKI init/refresh sidecar and apply/verify/e2e job
#
# Usage: build_images.sh [--engine docker|podman|buildah] [--registry REG] [--tag TAG]
#                        [--base-image IMAGE] [--fips [--fips-mode strict|non-strict]]
#                        [--x509-lookup default|nginx|haproxy|apache|envoy]
#                        [--push] [--sbom] [--sign KEYREF|keyless] [--out DIR]
# Examples:
#   build_images.sh --registry registry.example.mil/iam --base-image registry1.dso.mil/ironbank/opensource/keycloak/keycloak:26.x --fips --push --sbom --sign cosign.key
#   build_images.sh --engine podman                                  # local build only
# Needs: one engine; syft for --sbom; cosign for --sign. Verify with:
#   cosign verify --key cosign.pub --insecure-ignore-tlog=true <ref>   (drop the flag if you set SIGN_TLOG=true) The images run unchanged on Docker, Podman, Kubernetes, OpenShift.
set -euo pipefail
SK="$(cd "$(dirname "$0")/.." && pwd)"
ENGINE=""; REG="localhost"; TAG="26.8.2-stig"; BASE="quay.io/keycloak/keycloak:26.8.2@sha256:723b1d6e254c0fc96d5cffec860c7e0744d6a3277822b865bb538cf891575e41"; FIPS=false; FIPS_MODE=strict
PUSH=false; SBOM=false; SIGN=""; OUT="$PWD/dist"; LOOKUP=default
while [ $# -gt 0 ]; do case "$1" in
  --engine) ENGINE=$2; shift;; --registry) REG=$2; shift;; --tag) TAG=$2; shift;; --base-image) BASE=$2; shift;;
  --fips) FIPS=true;; --x509-lookup) LOOKUP=$2; shift;; --fips-mode) FIPS_MODE=$2; shift;; --push) PUSH=true;; --sbom) SBOM=true;; --sign) SIGN=$2; shift;;
  --out) OUT=$2; shift;; -h|--help) sed -n '2,14p' "$0"; exit 0;; *) echo "unknown arg $1" >&2; exit 2;; esac; shift; done
[ -n "$ENGINE" ] || for e in docker podman buildah; do command -v $e >/dev/null && { ENGINE=$e; break; }; done
[ -n "$ENGINE" ] || { echo "no container engine found" >&2; exit 1; }
mkdir -p "$OUT"; CTX="$(mktemp -d)"; trap 'rm -rf "$CTX"' EXIT
KC_IMG="$REG/keycloak-stig:$TAG"; [ "$LOOKUP" = default ] || KC_IMG="$KC_IMG-$LOOKUP"; TOOLS_IMG="$REG/kcstig-tools:$TAG"

# --- Keycloak image context ---
KC_VERSION_GUESS="$(echo "$BASE" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | tail -1)"
JAR="$SK/assets/extension/target/stig-extensions.jar"
# The SPI is compiled against the exact Keycloak jars of the base image.
# STIG_PREBUILT_JAR=1 uses the bundled jar (compiled for 26.8.2) - no JDK needed on the build machine
if [ "${STIG_PREBUILT_JAR:-0}" = "1" ] && [ -f "$JAR" ]; then echo "using prebuilt $JAR"
else "$SK/assets/extension/build.sh" "$BASE" >/dev/null; fi
mkdir -p "$CTX/kc/fips" "$CTX/kc/theme"
cp "$SK/assets/deploy/image/Containerfile" "$SK/assets/deploy/image/stig-entrypoint.sh" "$CTX/kc/"
cp "$JAR" "$CTX/kc/"; cp -r "$SK/assets/theme/dod-stig" "$CTX/kc/theme/"
if $FIPS; then
  for a in bc-fips:${BC_FIPS:-2.1.3} bctls-fips:${BCTLS_FIPS:-2.1.25} bcutil-fips:${BCUTIL_FIPS:-2.1.8} bcpkix-fips:${BCPKIX_FIPS:-2.1.13}; do
    n=${a%%:*}; v=${a##*:}; f="$CTX/kc/fips/$n-$v.jar"
    if [ -f "${FIPS_JAR_DIR:-/nonexistent}/$n-$v.jar" ]; then cp "$FIPS_JAR_DIR/$n-$v.jar" "$f"   # air-gapped
    else curl -fsSL --retry 6 --retry-all-errors --retry-delay 10 -o "$f" "https://repo1.maven.org/maven2/org/bouncycastle/$n/$v/$n-$v.jar"; fi
    want=$(curl -fsSL --retry 6 --retry-all-errors --retry-delay 10 "https://repo1.maven.org/maven2/org/bouncycastle/$n/$v/$n-$v.jar.sha1" 2>/dev/null || true)
    [ -z "$want" ] || [ "$(sha1sum "$f" | cut -d' ' -f1)" = "${want%% *}" ] || { echo "checksum mismatch $n-$v" >&2; exit 1; }
  done
fi
touch "$CTX/kc/fips/.keep"

# --- tools image context ---
mkdir -p "$CTX/tools/kcstig"
cp "$SK/assets/deploy/tools/Containerfile" "$SK/assets/deploy/tools/kcstig-tools.sh" "$CTX/tools/"
cp -r "$SK/scripts" "$SK/references" "$CTX/tools/kcstig/"; cp "$SK/SKILL.md" "$CTX/tools/kcstig/"
mkdir -p "$CTX/tools/kcstig/assets"; cp "$SK/assets/profile.example.json" "$CTX/tools/kcstig/assets/"
rm -rf "$CTX/tools/kcstig/scripts/dev"

build() { # context image [build-args...]
  local ctx=$1 img=$2; shift 2
  case "$ENGINE" in
    docker|podman) $ENGINE build -f "$ctx/Containerfile" -t "$img" "$@" "$ctx" ;;
    buildah)       buildah bud -f "$ctx/Containerfile" -t "$img" "$@" "$ctx" ;;
  esac
}
echo "== $ENGINE build $KC_IMG (base $BASE, fips=$FIPS)"
build "$CTX/kc" "$KC_IMG" --build-arg BASE_IMAGE="$BASE" --build-arg FIPS=$FIPS --build-arg FIPS_MODE=$FIPS_MODE --build-arg X509_LOOKUP=$LOOKUP \
  --label org.opencontainers.image.title=keycloak-stig --label org.opencontainers.image.base.name="$BASE" \
  --label mil.stig.benchmark="ASD STIG V6R4" --label mil.stig.fips=$FIPS
echo "== $ENGINE build $TOOLS_IMG"
build "$CTX/tools" "$TOOLS_IMG" --label org.opencontainers.image.title=kcstig-tools

# Evidence of the runtime defaults baked into the image (keep it with the deployment config for `verify --deploy-dir`)
case "$ENGINE" in
  docker|podman) $ENGINE inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$KC_IMG" ;;
  buildah) buildah inspect --format '{{range .OCIv1.Config.Env}}{{println .}}{{end}}' "$KC_IMG" ;;
esac | grep -E '^KC_' > "$OUT/keycloak-stig-image.env"
echo "image defaults: $OUT/keycloak-stig-image.env"

push() { case "$ENGINE" in docker|podman) $ENGINE push "$1";; buildah) buildah push "$1";; esac; }
digest() { # registry digest after push
  case "$ENGINE" in
    docker) docker inspect --format '{{index .RepoDigests 0}}' "$1" ;;
    podman) podman inspect --format '{{index .RepoDigests 0}}' "$1" ;;
    buildah) echo "$1" ;;
  esac
}
for img in "$KC_IMG" "$TOOLS_IMG"; do
  name="${img##*/}"; name="${name%%:*}"
  if $PUSH; then push "$img"; ref=$(digest "$img"); else ref="$img"; fi
  if $SBOM; then
    src=$([ "$ENGINE" = podman ] && echo "podman:$img" || echo "docker:$img"); $PUSH && src="registry:$ref"
    syft scan "$src" -o spdx-json="$OUT/$name.spdx.json" -q
    echo "SBOM: $OUT/$name.spdx.json ($(python3 -c "import json;print(len(json.load(open('$OUT/$name.spdx.json'))['packages']))" 2>/dev/null) packages)"
  fi
  if [ -n "$SIGN" ]; then
    $PUSH || { echo "--sign needs --push (signatures are stored in the registry)" >&2; exit 1; }
    # Key-based signing does NOT publish to the public Rekor transparency log unless SIGN_TLOG=true
    # (image digests of DoD systems should not land in a public log). Keyless signing always needs Rekor.
    TL="--tlog-upload=${SIGN_TLOG:-false}"
    if [ "$SIGN" = keyless ]; then cosign sign --yes "$ref"; else cosign sign --yes $TL --key "$SIGN" "$ref"; fi
    if $SBOM; then
      if [ "$SIGN" = keyless ]; then cosign attest --yes --type spdxjson --predicate "$OUT/$name.spdx.json" "$ref"
      else cosign attest --yes $TL --key "$SIGN" --type spdxjson --predicate "$OUT/$name.spdx.json" "$ref"; fi
    fi
    echo "signed $ref"
  fi
  echo "$ref" >> "$OUT/images.txt"
done
echo "done: $KC_IMG  $TOOLS_IMG  (refs in $OUT/images.txt)"

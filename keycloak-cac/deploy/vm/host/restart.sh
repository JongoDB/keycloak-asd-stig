#!/bin/sh
# idp-restart: restart Keycloak on the shared IdP host (or switch it to another local image) and wait until it is
# HEALTHY, which in online CRL mode means every expected CRL is installed (cac-health.py). Installed by setup-host.sh
# as /usr/local/sbin/idp-restart. README, "Restarting Keycloak".
#   sudo idp-restart                       restart the keycloak service, wait for healthy
#   sudo idp-restart --image <tag>         run <tag> (already built or loaded on this host): /srv/idp/compose/.env and the
#                                          keycloak line of images.lock are derived from `docker image inspect <tag>`,
#                                          never typed, then the container is recreated and checked to run that image ID
# Before anything changes: the egress rules must be in place (idp-egress --check; the unit itself is never restarted,
# that would restart dockerd) and check-clients must report no drift (a restart re-applies /srv/idp/clients).
# IDP_SRV / IDP_ADMIN / IDP_EGRESS / IDP_KC_CONTAINER exist for tests/restart_test.sh only.
set -eu
S="${IDP_SRV:-/srv/idp}"; ADM="${IDP_ADMIN:-/usr/local/sbin/idp-admin.py}"; EGRESS="${IDP_EGRESS:-/usr/local/sbin/idp-egress}"
CT="${IDP_KC_CONTAINER:-idp-keycloak-1}"; TIMEOUT="${IDP_RESTART_TIMEOUT:-900}"
log() { echo "idp-restart: $*" >&2; }
die() { log "ERROR $*"; exit 1; }
TAG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --image) TAG="${2:?--image needs a tag}"; shift 2;;
    --timeout) TIMEOUT="${2:?--timeout needs seconds}"; shift 2;;
    -h|--help) sed -n '2,12p' "$0"; exit 0;;
    *) die "unknown argument $1 (see --help)";;
  esac
done
ENVF="$S/compose/.env"; LOCK="$S/compose/images.lock"
C="docker compose --env-file $ENVF -f $S/compose/compose.yaml"
[ -f "$ENVF" ] && [ -f "$S/compose/compose.yaml" ] || die "no stack in $S/compose (run setup-host.sh first)"

"$EGRESS" --check >/dev/null || die "egress rules are not in place: run 'sudo idp-egress' (never restart idp-egress.service)"
"$ADM" check-clients || die "check-clients reported drift or could not run: a restart would re-apply /srv/idp/clients; fix that first"
install -d -o 1000 -g 1000 -m 0750 "$S/crl-cache"   # compose.yaml mounts it; a missing one would be created root-owned

if [ -n "$TAG" ]; then
  ID=$(docker image inspect -f '{{.Id}}' "$TAG") || die "no local image $TAG (build or load it first)"
  REV=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$TAG" 2>/dev/null || true)
  [ "$REV" = "<no value>" ] && REV=""
  OLD=$(sed -n 's/^KEYCLOAK_IMAGE=//p' "$ENVF")
  # keep the previous pair; from here on ANY failure prints how to put it back
  [ -f "$LOCK" ] || : > "$LOCK"
  TS=$(date -u +%Y%m%dT%H%M%SZ)
  cp -p "$ENVF" "$ENVF.prev-$TS"; cp -p "$LOCK" "$LOCK.prev-$TS"
  trap 'rc=$?; [ "$rc" -eq 0 ] || log "ROLLBACK (previous image ${OLD:-none}): cp -p $ENVF.prev-$TS $ENVF && cp -p $LOCK.prev-$TS $LOCK && $C up -d --no-deps keycloak   - or: idp-restart --image ${OLD:-<old tag>}"; exit "$rc"' EXIT
  awk -v t="$TAG" 'BEGIN{d=0} /^KEYCLOAK_IMAGE=/{print "KEYCLOAK_IMAGE=" t; d=1; next} {print} END{if(!d) print "KEYCLOAK_IMAGE=" t}' \
    "$ENVF" > "$ENVF.new" && mv -f "$ENVF.new" "$ENVF"
  # images.lock: the keycloak line is "<tag> <image ID>", both from the same inspect; the commit line from its label
  awk -v t="$TAG" -v id="$ID" -v old="$OLD" -v rev="$REV" -v now="$(date -u +%FT%TZ)" '
    /^# image IDs/ {print "# image IDs (content digests) in use, written " now; next}
    /^keycloak-asd-stig commit:/ {if (rev != "") print "keycloak-asd-stig commit: " rev; else print; next}
    ($1 == old && old != "") || $1 ~ /^idp\/keycloak-cac:/ {if (!k) print t " " id; k=1; next}
    {print}
    END {if (!k) print t " " id}' "$LOCK" > "$LOCK.new" && mv -f "$LOCK.new" "$LOCK"
  log "Keycloak image: ${OLD:-none} -> $TAG ($ID)"
  $C up -d --no-deps keycloak
else
  ID=$(docker image inspect -f '{{.Id}}' "$(sed -n 's/^KEYCLOAK_IMAGE=//p' "$ENVF")" 2>/dev/null || true)
  $C restart keycloak
fi

# healthy = Keycloak ready, realm applied, every expected CRL installed. Until then card sign-in of a CA whose CRL is
# missing is refused (fail closed); with /srv/idp/crl-cache the CRLs are normally there from the first second. Past
# CAC_CRL_READY_GRACE the image reports healthy "DEGRADED" with CRLs still missing: keep waiting for the full set, and
# if it does not arrive, say so without failing the restart (the image is fine; the CRL source is not).
last() { docker inspect -f '{{range .State.Health.Log}}{{.Output}}{{end}}' "$CT" 2>/dev/null | grep -v '^$' | tail -1; }
waited=0; st=""
while [ "$waited" -lt "$TIMEOUT" ]; do
  st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CT" 2>/dev/null || echo missing)
  if [ "$st" = healthy ]; then case "$(last)" in *DEGRADED*) ;; *) break;; esac; fi
  [ "$st" = missing ] || [ "$(docker inspect -f '{{.State.Running}}' "$CT")" = true ] || die "$CT is not running (docker logs $CT)"
  sleep 5; waited=$((waited + 5))
done
if [ "$st" != healthy ]; then
  log "$CT is not healthy after ${TIMEOUT}s (state: $st). Last health output:"
  docker inspect -f '{{range .State.Health.Log}}{{.Output}}{{end}}' "$CT" 2>/dev/null | tail -3 >&2 || true
  log "NOTE: Keycloak may already be serving sign-in; if the output above lists CRLs not installed, only the cards of"
  log "  those CAs are refused until they arrive (a CRL source outage, e.g. crl.disa.mil). Do not roll back a good image"
  log "  for that: it would come up without those CRLs too. Check 'docker logs $CT | grep STIG-CRL' first."
  exit 1
fi
RUN=$(docker inspect -f '{{.Image}}' "$CT")
[ -z "$ID" ] || [ "$RUN" = "$ID" ] || die "$CT runs $RUN, but images.lock / .env name $ID"
case "$(last)" in *DEGRADED*)
  log "WARN healthy but DEGRADED after ${TIMEOUT}s, image $RUN: $(last | sed 's/^ready DEGRADED: //')"
  log "  Sign-in works; only those CAs' cards are refused until their CRLs arrive (the container keeps retrying every"
  log "  minute, STIG-CRL-INCOMPLETE). This is a CRL-source problem, not the image: do not roll back for it."
  exit 0;;
esac
log "healthy after ${waited}s: $(docker exec "$CT" sh -c 'ls /opt/keycloak/data/cac/crl/*.crl 2>/dev/null | wc -l') CRLs installed, image $RUN"

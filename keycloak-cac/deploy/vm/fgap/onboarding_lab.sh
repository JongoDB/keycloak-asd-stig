#!/usr/bin/env bash
# Runs fgap/onboarding_lab_test.py against a THROWAWAY keycloak-cac container (lab mode: mock PKI, dev-file database,
# no published port), on any Docker host - the operator Mac included. Nothing outside the two containers it starts.
#   onboarding_lab.sh <keycloak-cac image> <keycloak-asd-stig checkout> [report file] [test script in fgap/]
# The image is the one under test (built from the keycloak-asd-stig branch with the admin-API profile). The path
# filter is configured as on the IdP host (STIG_PUBLIC_PATHS for the realm, STIG_TRUSTED_SOURCES=127.0.0.1), so the
# test's network calls (from the container's own address) meet it exactly as a browser does.
set -euo pipefail
IMG="${1:?image}"; KAS="${2:?keycloak-asd-stig checkout}"; OUT="${3:-/dev/null}"; TEST="${4:-onboarding_lab_test.py}"
HERE="$(cd "$(dirname "$0")" && pwd)"; IDP="$(cd "$HERE/.." && pwd)"
NAME="onb-lab-$$"; T="$(mktemp -d)"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$T"; }; trap cleanup EXIT
SECRET="$(openssl rand -hex 24)"; R=dod-cac
P="/realms/$R,/realms/$R/.well-known/,/realms/$R/protocol/,/realms/$R/login-actions/,/realms/$R/broker/,/realms/$R/account,/realms/$R/account/,/admin/$R/,/admin/realms/$R,/admin/realms/$R/,/admin/serverinfo,/resources/"
# STIG_CARD_PORT=8444: the present-card step posts to a second port of the same listener (the test forwards 8444 -> 8443
# inside the container's network namespace, as the host's port mapping does)
docker run -d --name "$NAME" -e CAC_LAB_MODE=true -e KC_DB=dev-file -e CAC_AUTH_MODE=cac_or_mfa -e CAC_USERNAME_SOURCE=edipi -e STIG_CARD_PORT=8444 \
  -e CAC_PUBLIC_URL="https://localhost:8443" -e KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -hex 16)" -e CAC_AUTOMATION_SECRET="$SECRET" \
  -e STIG_ALLOWLIST_ENFORCED_REALMS=$R -e STIG_PUBLIC_PATHS="$P" -e STIG_TRUSTED_SOURCES=127.0.0.1 "$IMG" >/dev/null
for i in $(seq 1 120); do
  docker exec "$NAME" /opt/keycloak-cac/bin/cac-entrypoint.sh health >/dev/null 2>&1 && break
  docker inspect -f '{{.State.Running}}' "$NAME" | grep -q true || { docker logs "$NAME" 2>&1 | tail -30; echo "FAIL container stopped"; exit 1; }
  sleep 5
done
docker exec "$NAME" cat /opt/keycloak/data/cac/lab/ca/root.crt > "$T/root.crt"
# a mock card no lab account carries (EDIPI 8888888888): the card-account test creates its account through stig-accounts
for f in unmapped.crt unmapped.key roe.jane.crt roe.jane.key revoked.crt revoked.key; do docker exec "$NAME" cat "/opt/keycloak/data/cac/lab/users/$f" > "$T/$f" 2>/dev/null || true; done
START=$(date +%s)
{
  echo "# fgap/$TEST -- throwaway keycloak-cac container, lab mode (mock PKI, dev-file DB, strict path filter as on the host)"
  echo "# image: $IMG ($(docker image inspect -f '{{.Id}}' "$IMG" | cut -c1-19)), keycloak-asd-stig: $(git -C "$KAS" rev-parse --short HEAD) ($(git -C "$KAS" rev-parse --abbrev-ref HEAD)), $(date -u +%Y-%m-%dT%H:%MZ)"
  echo "# crypto: $(docker logs "$NAME" 2>&1 | grep -oE 'BCFIPS version [^,]* (Approved|Non-Approved) Mode' | head -1 || true)"
  set +e
  # add-client's validator is the relying-party skill's own (IDP_VCR), from the same keycloak-asd-stig checkout
  docker run --rm --network "container:$NAME" -e AUTOMATION_SECRET="$SECRET" -v "$IDP:/idp:ro" -v "$KAS/keycloak-asd-stig/scripts:/kas:ro" \
    -v "$KAS/keycloak-rp-integration/scripts:/kasrp:ro" -e IDP_VCR=/kasrp/validate-client-request.py \
    -v "$T:/t:ro" python:3.12-slim sh -c 'pip install -q cryptography >/dev/null 2>&1; python3 -I /idp/fgap/'"$TEST"' --cacert /t/root.crt --skill-scripts /kas'
  RC=$?
  set -e
  # no EDIPI in the server's own output since the test started: any standalone run of exactly ten digits (a card's
  # EDIPI, as in CN=LAST.FIRST.MI.<EDIPI> or <EDIPI>@mil) - events (LOGIN_ERROR included), audit lines, everything
  docker logs --since "$START" "$NAME" 2>&1 | python3 -c '
import re, sys
pat = re.compile(r"(?<![0-9A-Za-z])[0-9]{10}(?![0-9A-Za-z])")
lines = sys.stdin.read().splitlines()
hits = [i for i, l in enumerate(lines) if pat.search(l)]
import json as _j
def show(l):
    try:
        d = _j.loads(l); l = "%s %s: %s" % (d.get("level"), d.get("loggerName"), d.get("message"))
    except ValueError:
        pass
    return pat.sub("<10 digits>", l)[:400]
print("%s  [log] no ten-digit run (an EDIPI) in the server log since the test started (%d lines scanned, LOGIN_ERROR events included)%s"
      % ("PASS" if not hits else "FAIL", len(lines), "" if not hits else ": %d line(s), e.g. %s" % (len(hits), " || ".join(show(lines[i]) for i in hits[:3]))))
sys.exit(1 if hits else 0)' || RC=1
  docker logs --since "$START" "$NAME" 2>&1 | python3 -c '
import re, sys
import json
def msg(l):
    try:
        return json.loads(l).get("message") or ""
    except ValueError:
        return l
q = [m.split("?", 1)[1] for m in map(msg, sys.stdin.read().splitlines()) if m.startswith("STIG-ADMIN-QUERY") and "?" in m]
def leaks(x):
    for tok in re.split(r"[&\s]+", x):                       # Unicode digits (\d is \p{Nd} for str patterns)
        if len(re.findall(r"\d", tok)) > 4 or (re.search(r"\d{4}", tok) and "#" not in tok):
            return True
    return bool(re.search(r"(cac_|entra_oid|entra_vouched|stig_created_by)[a-z_]*[:=](?!<concealed>)", x))
bad = [x for x in q if leaks(x)]
print("%s  [log] STIG-ADMIN-QUERY lines: no 4+ digit run, every concealed attribute masked (%d lines)%s" % ("PASS" if not bad else "FAIL", len(q),
      "" if not bad else ": e.g. " + re.sub(r"[0-9]", "9", bad[0])[:200]))
sys.exit(1 if bad else 0)' || RC=1
  docker logs --since "$START" "$NAME" 2>&1 | python3 -c '
import json, re, sys
def msg(l):
    try:
        return json.loads(l).get("message") or ""
    except ValueError:
        return l
allm = list(map(msg, sys.stdin.read().splitlines()))
r = [m for m in allm if m.startswith("STIG-REFERER ")]
acc = [m for m in allm if "/.well-known/openid-configuration HTTP" in m]
bad = [m for m in r if "?" in m.split("referer=", 1)[-1] or "#frag" in m or len(re.findall(r"\d", m.split("referer=", 1)[-1])) > 4]
lab = [m for m in r if "portal.lab.example" in m]
# correlation: the STIG-REFERER line names a client address, and the access log has the same client and path
def corr(m):
    ip = re.search(r"ip=(\S+) (\S+) (\S+)", m)
    return ip and ip.group(1) != "?" and any(a.startswith(ip.group(1) + " ") and (ip.group(2) + " " + ip.group(3) + " ") in a for a in acc)
ok = bool(lab) and not bad and all(corr(m) for m in lab)
print("%s  [log] V-222447: the Referer is recorded sanitised and correlates with the access log (STIG-REFERER: %d lines; no query, fragment or digit run), e.g. %s"
      % ("PASS" if ok else "FAIL", len(r), (bad or lab or ["(none)"])[0][:200]))
sys.exit(0 if ok else 1)' || RC=1
  # (grep -c, not -q: -q stops reading, docker logs gets SIGPIPE, and pipefail turns a match into a failure)
  if [ "$(docker logs "$NAME" 2>&1 | grep -c 'STIG-REFERER-AUDIT on')" -gt 0 ]; then echo "PASS  [log] start-up line: STIG-REFERER-AUDIT on"; else echo "FAIL  [log] no STIG-REFERER-AUDIT on line at start-up"; RC=1; fi
  # the same image with the audit switched off by a deployment variable: a WARN at start-up says so
  OFF="$NAME-off"; docker run -d --name "$OFF" -e CAC_LAB_MODE=true -e KC_DB=dev-file -e CAC_PUBLIC_URL="https://localhost:8443" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap -e KC_BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -hex 16)" -e STIG_REFERER_AUDIT=off "$IMG" >/dev/null
  for i in $(seq 1 60); do docker exec "$OFF" /opt/keycloak-cac/bin/cac-entrypoint.sh health >/dev/null 2>&1 && break; sleep 5; done
  if [ "$(docker logs "$OFF" 2>&1 | grep -E '"level":"WARN"|WARN' | grep -c 'STIG-REFERER-AUDIT OFF')" -gt 0 ]; then echo "PASS  [log] STIG_REFERER_AUDIT=off: a WARN line STIG-REFERER-AUDIT OFF at start-up"
  else echo "FAIL  [log] STIG_REFERER_AUDIT=off gave no WARN line"; RC=1; fi
  docker rm -f "$OFF" >/dev/null 2>&1 || true
  echo "info  admin queries audited by the extension (STIG-ADMIN-QUERY): $(docker logs --since "$START" "$NAME" 2>&1 | grep -c 'STIG-ADMIN-QUERY'), e.g. $(docker logs --since "$START" "$NAME" 2>&1 | grep -oE 'STIG-ADMIN-QUERY[^"]*<concealed>[^"]*' | head -1 | cut -c1-200)"
  echo
  echo "== Keycloak's audit log lines from this run (stig-extensions)"
  docker logs --since "$START" "$NAME" 2>&1 | grep -oE 'STIG-(ADMIN-API-STEP-UP-REQUIRED|ADMIN-API-PROFILE-REFUSED|ACCOUNTS[ -][A-Za-z-]*|ADMIN-NOT-ALLOWLISTED|IDP-PENDING-INVITE-BOUND|IDP-LINK-REFUSED|IDP-LINK-MISMATCH|CARD-PRESENT-[A-Z]*)[^"\\]*' \
    | sed -E 's/(user|caller)=lab\.[a-z0-9.]+/\1=<lab user>/g; s/[0-9a-f]{8}-[0-9a-f-]{27}/<id>/g' | sort | uniq -c | sort -rn | head -60
  exit $RC
} 2>&1 | tee "$OUT"

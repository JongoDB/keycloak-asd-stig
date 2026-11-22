#!/bin/sh
# Session events from the Keycloak container(s): time, node, type, client, error, username (the mapped EDIPI on a card
# refusal), certificate subject. Sign-in (LOGIN), sign-out (LOGOUT), brokered sign-in, every *_ERROR event (failed
# sign-in, failed logout, failed code or token exchange, client authentication), and the gate's own audit lines
# (STIG-ADMIN-*). Usage: idp-events [minutes, default 30]. Read-only.
M="${1:-30}"
for c in $(docker ps --format "{{.Names}}" | grep -E "^idp-keycloak"); do
  docker logs --since "${M}m" "$c" 2>&1 | C="$c" python3 -c '
import sys, json, re, os
SHOW = {"LOGIN", "LOGOUT", "IDENTITY_PROVIDER_LOGIN", "IDENTITY_PROVIDER_FIRST_LOGIN", "IDENTITY_PROVIDER_POST_LOGIN",
        "USER_DISABLED_BY_TEMPORARY_LOCKOUT", "USER_DISABLED_BY_PERMANENT_LOCKOUT"}
node = os.environ["C"].replace("idp-", "").replace("-1", "")
for l in sys.stdin:
    try: d = json.loads(l)
    except Exception: continue
    m = d.get("message", "")
    t = re.search(r"(?<![A-Za-z_])type=\"([A-Z_]+)\"", m)
    if t and (t.group(1) in SHOW or t.group(1).endswith("_ERROR")):
        print(d.get("timestamp", "")[:19], node, " ".join(re.findall(
            r"(?<![A-Za-z_])(?:type|clientId|error|username|reason|x509_cert_subject_distinguished_name)=\"[^\"]*\"", m)))
    elif m.startswith("STIG-ADMIN-"):
        print(d.get("timestamp", "")[:19], node, m[:300])
    elif d.get("level") == "ERROR" and "X509" in (d.get("loggerName", "") + m):
        print(d.get("timestamp", "")[:19], node, "ERROR", m[:300])'
done | sort

#!/usr/bin/env python3
"""Readiness: Keycloak is ready AND the STIG realm was applied AND revocation data is loaded - in online mode, EVERY
expected CRL (.crl-required, written by the entrypoint) is installed.

That last condition is bounded in time: for CAC_CRL_READY_GRACE seconds after the container started (default 240) a
missing CRL keeps it not ready, so a restart that waits for healthy does not hand card sign-in over early. After the
grace the container reports ready DEGRADED, naming the missing CRLs: one CRL that stays unavailable (a CRL-source
outage) must not take every sign-in method down by keeping all replicas out of service or having the orchestrator kill
them. The cards of those CAs stay refused (fail closed) and the worker keeps retrying (STIG-CRL-INCOMPLETE).
The grace must stay below the orchestrator's kill threshold (Helm startupProbe 600 s, ECS startPeriod 300 s + retries).
CAC_CRL_READY_GRACE=-1 never reports ready without every CRL; 0 never waits for them.
Use as an exec probe / compose healthcheck:  /opt/keycloak-cac/bin/cac-entrypoint.sh health"""
import os, ssl, sys, time, urllib.request
d = os.environ.get("CAC_PKI_DIR", "/opt/keycloak/data/cac")
try:
    grace = int(os.environ.get("CAC_CRL_READY_GRACE", "240"))
except ValueError:
    grace = 240
degraded = ""
req = os.path.join(d, ".crl-required")
if os.path.exists(req):
    names = [n.strip() for n in open(req) if n.strip()]
    missing = [n for n in names if not (os.path.isfile(os.path.join(d, "crl", n)) and os.path.getsize(os.path.join(d, "crl", n)) > 0)]
    if missing:
        what = "%d of %d CRLs not installed: %s" % (len(missing), len(names), " ".join(missing))
        try:
            age = time.time() - int(open(os.path.join(d, ".started")).read().strip())
        except (OSError, ValueError):
            age = float("inf")   # no start time: treat the grace as elapsed (never-ready would bring back the kill loop)
        if grace < 0 or age < grace:
            print("not ready: %s%s" % (what, " (ready without them after the %ds grace)" % grace if grace >= 0 else ""))
            sys.exit(1)
        degraded = " DEGRADED: %s - cards of those CAs are refused until they arrive" % what
for f in (".applied",) + (() if degraded else (".crl-loaded",)):   # past the grace the first refresh may still hang
    if not os.path.exists(os.path.join(d, f)):
        print("not ready: %s missing" % f); sys.exit(1)
rel = (os.environ.get("KC_HTTP_MANAGEMENT_RELATIVE_PATH") or os.environ.get("KC_HTTP_RELATIVE_PATH") or "/").rstrip("/")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE   # loopback only
try:
    urllib.request.urlopen("https://127.0.0.1:%s%s/health/ready" % (os.environ.get("KC_HTTP_MANAGEMENT_PORT", "9000"), rel), context=ctx, timeout=5)
except Exception as e:
    print("not ready: %s" % e); sys.exit(1)
print("ready" + degraded)

#!/usr/bin/env python3
"""Readiness: Keycloak is ready AND the STIG realm was applied AND revocation data is loaded - in online mode, EVERY
expected CRL (.crl-required, written by the entrypoint) is installed. A container that would refuse a CA's cards for want
of its CRL is not ready, so a restart procedure that waits for healthy never hands sign-in to it early.
CAC_READY_REQUIRES_CRLS=false drops that last condition (readiness only; a missing CRL still refuses its CA's cards).
Use as an exec probe / compose healthcheck:  /opt/keycloak-cac/bin/cac-entrypoint.sh health"""
import os, ssl, sys, urllib.request
d = os.environ.get("CAC_PKI_DIR", "/opt/keycloak/data/cac")
for f in (".applied", ".crl-loaded"):
    if not os.path.exists(os.path.join(d, f)):
        print("not ready: %s missing" % f); sys.exit(1)
req = os.path.join(d, ".crl-required")
strict = os.environ.get("CAC_READY_REQUIRES_CRLS", "true").strip().lower() not in ("0", "false", "no", "off")
if strict and os.path.exists(req):
    names = [n.strip() for n in open(req) if n.strip()]
    missing = [n for n in names if not (os.path.isfile(os.path.join(d, "crl", n)) and os.path.getsize(os.path.join(d, "crl", n)) > 0)]
    if missing:
        print("not ready: %d of %d CRLs not installed: %s" % (len(missing), len(names), " ".join(missing))); sys.exit(1)
rel = (os.environ.get("KC_HTTP_MANAGEMENT_RELATIVE_PATH") or os.environ.get("KC_HTTP_RELATIVE_PATH") or "/").rstrip("/")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE   # loopback only
try:
    urllib.request.urlopen("https://127.0.0.1:%s%s/health/ready" % (os.environ.get("KC_HTTP_MANAGEMENT_PORT", "9000"), rel), context=ctx, timeout=5)
except Exception as e:
    print("not ready: %s" % e); sys.exit(1)
print("ready")

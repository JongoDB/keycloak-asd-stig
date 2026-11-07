#!/usr/bin/env python3
"""Readiness: Keycloak is ready AND the STIG realm was applied AND revocation data is loaded.
Use as an exec probe / compose healthcheck:  /opt/keycloak-cac/bin/cac-entrypoint.sh health"""
import os, ssl, sys, urllib.request
d = os.environ.get("CAC_PKI_DIR", "/opt/keycloak/data/cac")
for f in (".applied", ".crl-loaded"):
    if not os.path.exists(os.path.join(d, f)):
        print("not ready: %s missing" % f); sys.exit(1)
rel = (os.environ.get("KC_HTTP_MANAGEMENT_RELATIVE_PATH") or os.environ.get("KC_HTTP_RELATIVE_PATH") or "/").rstrip("/")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE   # loopback only
try:
    urllib.request.urlopen("https://127.0.0.1:%s%s/health/ready" % (os.environ.get("KC_HTTP_MANAGEMENT_PORT", "9000"), rel), context=ctx, timeout=5)
except Exception as e:
    print("not ready: %s" % e); sys.exit(1)
print("ready")

#!/usr/bin/env bash
# The CRL list each X.509 authenticator gets (cac-config.py crl_list_for): the stig form may list only installed CRLs
# (it refuses a card whose issuer's CRL is missing); Keycloak's stock form must keep EVERY expected CRL listed, because
# it passes a card whose issuer has no CRL in the list - dropping a missing one would silently stop checking that CA.
set -euo pipefail
B="$(cd "$(dirname "$0")/../bin" && pwd)"
python3 - "$B" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("cac_config", sys.argv[1] + "/cac-config.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
res = []
def check(name, ok, got=""): res.append(ok); print("%s %-82s %s" % ("PASS" if ok else "FAIL", name, got))
expected = ["cac/crl/DODIDCA_70.crl", "cac/crl/DODIDCA_71.crl", "cac/crl/DODROOTCA6.crl"]
installed = ["cac/crl/DODIDCA_70.crl", "cac/crl/DODROOTCA6.crl", "cac/crl/test-id-ca.crl"]   # CA-71's download failed
stock = m.crl_list_for("auth-x509-client-username-form", expected, installed)
stig = m.crl_list_for("stig-x509-client-username-form", expected, installed)
check("stock form keeps the CRL that failed to download (Keycloak then fails closed)", "cac/crl/DODIDCA_71.crl" in stock, stock)
check("stock form also lists other installed CRLs (lab CA)", "cac/crl/test-id-ca.crl" in stock)
check("stock form lists every expected CRL", all(e in stock for e in expected))
check("stig form lists only installed CRLs", stig == installed, stig)
check("unknown/other providers are treated like the stock form", m.crl_list_for(None, expected, installed) == stock)
check("nothing installed, stig form: placeholder (every card refused)", m.crl_list_for("stig-x509-client-username-form", expected, []) == ["cac/crl/none.crl"])
check("nothing installed, stock form: every expected CRL", m.crl_list_for("auth-x509-client-username-form", expected, []) == expected)
sys.exit(0 if all(res) else 1)
PY

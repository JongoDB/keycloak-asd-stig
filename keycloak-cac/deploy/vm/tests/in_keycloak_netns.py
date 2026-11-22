#!/usr/bin/env python3
"""Run a test script from INSIDE the Keycloak container's network namespace (root, on the VM): the only place the
master realm answers since the path filter trusts 127.0.0.1 alone. The public host name resolves to 127.0.0.1:8443
(certificate still verified for that name).

  sudo python3 in_keycloak_netns.py <script.py> [args...]
"""
import importlib.machinery, importlib.util, runpy, socket, sys

ld = importlib.machinery.SourceFileLoader("idp_admin", "/usr/local/sbin/idp-admin.py")
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
M.enter_keycloak_netns()
_gai = socket.getaddrinfo
socket.getaddrinfo = lambda h, p, *r, **k: _gai("127.0.0.1", M.ADMIN_PORT, *r, **k) if h == M.ADMIN_HOST else _gai(h, p, *r, **k)
script = sys.argv[1]; sys.argv = sys.argv[1:]
runpy.run_path(script, run_name="__main__")

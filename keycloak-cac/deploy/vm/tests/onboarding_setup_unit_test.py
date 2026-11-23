#!/usr/bin/env python3
"""Unit test of onboarding-client-setup's refusal to take over a client something else manages. No Keycloak, no root.

A client add-client registered or adopted (attribute stig.created-by=add-client), or one a host client file declares,
belongs to that path: onboarding-client-setup must refuse it before it records or changes anything. An absent client,
or the onboarding client this tool built itself, goes ahead.

  python3 onboarding_setup_unit_test.py
"""
import argparse, contextlib, copy, importlib.machinery, importlib.util, io, json, os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("IDP_ADMIN_CONFIG", os.path.join(HERE, "fixtures", "idp-admin.test.json"))
ld = importlib.machinery.SourceFileLoader("idp_admin", os.path.join(HERE, "..", "host", "idp-admin.py"))
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)

res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s  %-96s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

class FakeKC:
    """Clients by id; records every write."""
    def __init__(self, clients=()):
        self.clients = {c["id"]: copy.deepcopy(c) for c in clients}
        self.writes = []
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        if method != "GET":
            self.writes.append((method, path)); return None
        if path.startswith("/clients?clientId="):
            cid = path.split("=", 1)[1]
            return [copy.deepcopy(c) for c in self.clients.values() if c["clientId"] == cid]
        if path.startswith("/clients/"):
            return copy.deepcopy(self.clients.get(path.split("/")[2]))
        raise AssertionError("unexpected call %s %s" % (method, path))

CID = M.ONBOARDING_CLIENT_IDS[0]
managed = {"id": "u1", "clientId": CID, "attributes": {M.MANAGED_ATTR: M.MANAGED_VAL}}
ours = {"id": "u2", "clientId": CID, "attributes": {M.ONBOARDING_PROFILE_ATTR: M.ONBOARDING_PROFILE}}

# the check itself
why = M.onboarding_takeover_refusal(FakeKC([managed]), CID, files={})
check("an existing client add-client manages (stig.created-by=add-client): refused, and says why",
      why and "add-client" in why, why)
why = M.onboarding_takeover_refusal(FakeKC(), CID, files={CID: ["/srv/idp/clients/%s.json" % CID]})
check("a client a host client file declares (even before it exists): refused, naming the file",
      why and "%s.json" % CID in why, why)
check("an absent client with no host file: goes ahead", M.onboarding_takeover_refusal(FakeKC(), CID, files={}) is None)
check("the onboarding client this tool built: goes ahead (re-running setup converges it)",
      M.onboarding_takeover_refusal(FakeKC([ours]), CID, files={}) is None)

# through the command: refused BEFORE anything is recorded or written
tmp = tempfile.mkdtemp(prefix="onb-unit-")
M.ONBOARDING_STATE = os.path.join(tmp, "onboarding.json")
M.gate_capability = lambda kc_, key: 2
M.host_client_files = lambda d=None: {}
rm = {"id": "rm", "clientId": "realm-management", "attributes": {}}
for name, clients, files in (("add-client's client", [rm, managed], {}),
                             ("a host file's client", [rm], {CID: ["/srv/idp/clients/x.json"]})):
    kc = FakeKC(clients)
    M.KC = lambda kc=kc: kc
    M.host_client_files = lambda d=None, files=files: files
    ns = argparse.Namespace(redirect_uri="https://portal.lab.example/admin/accounts/callback", origin=None, client_id=CID,
                            app=["app-a"], max_auth_age=300, require_dpop=False, operations=",".join(M.ONBOARDING_DEFAULT_OPS))
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            M.cmd_onboarding_client_setup(ns)
        r = None
    except SystemExit as e:
        r = e
    check("setup over %s: REFUSED, nothing recorded, no write to Keycloak" % name,
          isinstance(r, SystemExit) and "REFUSED" in str(r) and not os.path.exists(M.ONBOARDING_STATE) and not kc.writes,
          (str(r)[:110], kc.writes))

print("\n%d/%d passed" % (sum(res), len(res)))
raise SystemExit(0 if all(res) else 1)

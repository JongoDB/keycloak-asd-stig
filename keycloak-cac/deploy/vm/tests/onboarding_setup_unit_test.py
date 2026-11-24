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

# ---- the portal operations (reset-otp, reset-password, unlock, logout, link-cac, status): off unless listed
check("the portal operations are six, the operations ten", len(M.ONBOARDING_PORTAL_OPS) == 6 and len(M.ONBOARDING_OPERATIONS) == 10)
check("the default list names no portal operation", not set(M.ONBOARDING_DEFAULT_OPS) & set(M.ONBOARDING_PORTAL_OPS))
check("capability: no list 1, a list of legacy operations 2, any portal operation 3",
      [M.onboarding_needed_cap(None), M.onboarding_needed_cap({"operations": ["create"]}),
       M.onboarding_needed_cap({"operations": ["create", "unlock"]}), M.onboarding_needed_cap({"operations": ["status"]})] == [1, 2, 3, 3])
check("canonical order, no duplicates; exactly the four legacy ones records nothing (an unset attribute means them)",
      M.canonical_operations(["status", "create", "create"]) == (["create", "status"], ["create", "status"])
      and M.canonical_operations(["membership", "disable", "setup-email", "create"])[1] is None)
check("recorded_operations: an unset list grants the four legacy ones, never a portal one",
      M.recorded_operations({}) == list(M.ONBOARDING_LEGACY_OPS))
attrs_ = M.onboarding_attrs(300, False, ["create", "setup-email", "membership", "reset-otp", "status"])
check("the client attribute names exactly the listed operations",
      attrs_.get(M.ONBOARDING_OPS_ATTR) == "create,setup-email,membership,reset-otp,status", attrs_.get(M.ONBOARDING_OPS_ATTR))

class ShapeKC:
    """Enough of Keycloak for onboarding_problems: one client as onboarding-client-setup leaves it."""
    def __init__(self, rep):
        self.c = dict(rep, id="u9", protocolMappers=[])
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        if path.startswith("/clients?clientId="):
            return [dict(self.c)]
        if path == "/clients/u9":
            return copy.deepcopy(self.c)
        if path.endswith("/default-client-scopes"):
            return [{"name": n} for n in M.ONBOARDING_DEFAULT_SCOPES]
        if path.endswith("/optional-client-scopes"):
            return []
        if path == "/client-scopes":
            return [{"name": n, "protocolMappers": [{"name": k, "protocolMapper": v, "config": (
                {"user.session.note": "AUTH_TIME", "claim.name": "auth_time", "access.token.claim": "true"} if k == "auth_time" else {})}
                for k, v in (M.ONBOARDING_SCOPE_MAPPERS.get(n) or {}).items()]} for n in M.ONBOARDING_DEFAULT_SCOPES]
        if path.endswith("/scope-mappings"):
            return {"clientMappings": {"realm-management": {"mappings": [{"name": r} for r in M.ONBOARDING_SCOPE_ROLES]}}}
        raise AssertionError("unexpected call %s %s" % (method, path))

PORTAL = ["create", "setup-email", "membership", "reset-otp", "reset-password", "unlock", "logout", "link-cac", "status"]
want = {"redirect": "https://portal.lab.example/admin/accounts/callback", "origin": "https://portal.lab.example", "max_age": 300,
        "operations": PORTAL}
live = M.onboarding_rep(CID, want["redirect"], want["origin"], 300, False, PORTAL)
check("[shape] a live client exactly as recorded (portal operations included): no problem",
      M.onboarding_problems(ShapeKC(live), CID, want) == [], M.onboarding_problems(ShapeKC(live), CID, want))
for label, ops_live in (("one portal operation added beyond the record", PORTAL + ["disable"]),
                        ("one portal operation missing from the live client", [x for x in PORTAL if x != "unlock"]),
                        ("the attribute removed (= the four legacy ones)", None)):
    lv = M.onboarding_rep(CID, want["redirect"], want["origin"], 300, False, ops_live)
    if ops_live is None:
        lv["attributes"].pop(M.ONBOARDING_OPS_ATTR, None)
    pr = M.onboarding_problems(ShapeKC(lv), CID, want)
    check("[shape] %s: drift on %s" % (label, M.ONBOARDING_OPS_ATTR), any(M.ONBOARDING_OPS_ATTR in x for x in pr), pr)
rec_legacy = {"redirect": want["redirect"], "origin": want["origin"], "max_age": 300, "operations": ["create", "setup-email", "membership"]}
lv = M.onboarding_rep(CID, want["redirect"], want["origin"], 300, False, PORTAL)
check("[shape] a record without portal operations, a live client with them: drift (someone added them by hand)",
      any(M.ONBOARDING_OPS_ATTR in x for x in M.onboarding_problems(ShapeKC(lv), CID, rec_legacy)))

# guard: a record with portal operations on an image that states capability 2 is a violation (and --fix disables it)
M.load_onboarding = lambda: {CID: want}
for capv, viol in ((2, True), (3, False)):
    kc_ = ShapeKC(live)
    writes = []
    kc_.api_orig = kc_.api
    def api_(method, path, obj=None, ok=(200, 201, 204), ok404=False, kc_=kc_, writes=writes):
        if method == "PUT":
            writes.append(path); kc_.c.update(obj); return None
        return kc_.api_orig(method, path, obj, ok, ok404)
    kc_.api = api_
    M.gate_capability = lambda k, key, capv=capv: capv
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        v = M.onboarding_guard(kc_, True, None)
    check("[guard] portal operations recorded, image capability %d: %s" % (capv, "a violation, the client DISABLED" if viol else "clean"),
          (v == [CID] and kc_.c.get("enabled") is False) if viol else (v == [] and not writes),
          [l for l in out.getvalue().splitlines() if "DRIFT" in l][:1])

# setup: portal operations on an image stating capability 2 are refused before anything is recorded or written
kc = FakeKC([rm]); M.KC = lambda kc=kc: kc; M.host_client_files = lambda d=None: {}
M.gate_capability = lambda kc_, key: 2
if os.path.exists(M.ONBOARDING_STATE):
    os.unlink(M.ONBOARDING_STATE)
ns = argparse.Namespace(redirect_uri="https://portal.lab.example/admin/accounts/callback", origin=None, client_id=CID,
                        app=["app-a"], max_auth_age=300, require_dpop=False, operations="create,unlock")
out = io.StringIO()
try:
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        M.cmd_onboarding_client_setup(ns)
    r = None
except SystemExit as e:
    r = e
check("[setup] create,unlock on an image with capability 2: REFUSED (needs 3), nothing recorded or written",
      isinstance(r, SystemExit) and "needs 3" in str(r) and "unlock" in str(r) and not os.path.exists(M.ONBOARDING_STATE) and not kc.writes,
      str(r)[:140])
for bad in ("create,unlock-all", "status,", ""):
    ns.operations = bad
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            M.cmd_onboarding_client_setup(ns)
        r = None
    except SystemExit as e:
        r = e
    check("[setup] --operations %r: REFUSED" % bad, isinstance(r, SystemExit) and "REFUSED" in str(r), str(r)[:80])

# the config's onboarding.operations: the default of --operations, and an info line when a record differs
M._AC = dict(M._AC, onboarding={"operations": {CID: ["status", "create", "unlock"]}})
check("configured_operations: canonical order", M.configured_operations(CID) == ["create", "unlock", "status"], M.configured_operations(CID))
check("configured_operations: a client the config does not list -> None", M.configured_operations("other") is None)
check("a record matching the config: no note", M.operations_config_note(CID, {"operations": ["create", "unlock", "status"]}) is None)
note = M.operations_config_note(CID, {"operations": ["create"]})
check("a record differing from the config: an info line naming both lists and the command", note and note.startswith("info")
      and "create,unlock,status" in note and "onboarding-client-setup" in note, note)
ns.operations = None
try:
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_onboarding_client_setup(ns)
    r = None
except SystemExit as e:
    r = e
check("[setup] no --operations: the config's list is applied (here refused on capability 2, naming unlock and status)",
      isinstance(r, SystemExit) and "unlock, status" in str(r), str(r)[:140])

print("\n%d/%d passed" % (sum(res), len(res)))
raise SystemExit(0 if all(res) else 1)

#!/usr/bin/env python3
"""Unit test of the guard's containment of one account (idp-admin.contain_user), with a fake Keycloak - no live call.
Runs on the VM, or anywhere from a checkout. Review 2026-11-11 HIGH: reset_at - from which grant's
promotion checks read an account's history - must move only when the reset returned AND a re-read shows nothing left,
and the account must stay HELD whatever happens.

  sudo python3 guard_contain_unit_test.py      # on the VM
  python3 guard_contain_unit_test.py           # from a checkout
"""
import copy, importlib.machinery, importlib.util, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
# on the VM the installed copy; from a checkout, the one beside these tests (with the lab config)
ADM = "/usr/local/sbin/idp-admin.py" if os.path.exists("/usr/local/sbin/idp-admin.py") else os.path.join(HERE, "..", "host", "idp-admin.py")
if not ADM.startswith("/usr/local/"):
    os.environ.setdefault("IDP_ADMIN_CONFIG", os.path.join(HERE, "fixtures", "idp-admin.test.json"))
ld = importlib.machinery.SourceFileLoader("idp_admin", ADM)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
UID = "11111111-2222-4333-8444-555555555555"
res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s  %-84s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

class FakeKC:
    """Just enough of the admin API for contain_user: one user, its credentials and links."""
    def __init__(self):
        self.user = {"id": UID, "username": "t.unit", "enabled": True, "email": "t@x.invalid",
                     "attributes": {"cac_edipi": ["1234567890"], "entra_oid": ["oid"]}}
        self.creds = [{"id": "c1", "type": "password"}, {"id": "c2", "type": "otp"}]
        self.links = [{"identityProvider": "entra"}]
        self.calls = []
        # admin events about this user (oldest first): created by the operator's tooling, bindings included
        self.events = [{"time": 1, "operationType": "CREATE", "resourcePath": "users/%s" % UID, "authDetails": {"realmId": "MASTER"},
                        "representation": json.dumps({"attributes": {"cac_edipi": ["1234567890"], "entra_oid": ["oid"]}})}]
        self._master_id = "MASTER"       # operator_actor: realmId MASTER = the operator's tooling
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        self.calls.append((method, path))
        if path.startswith("/admin-events?"): return copy.deepcopy(self.events) if "first=0" in path else []
        if path == "/events/config": return {"adminEventsEnabled": True, "adminEventsDetailsEnabled": True}
        if method == "DELETE" and path.startswith("/users/%s/credentials/" % UID):
            self.creds = [c for c in self.creds if c["id"] != path.rsplit("/", 1)[-1]]; return None
        if method == "DELETE" and path.startswith("/users/%s/federated-identity/" % UID):
            self.links = [l for l in self.links if l["identityProvider"] != path.rsplit("/", 1)[-1]]; return None
        if path == "/users/%s" % UID:
            if method == "GET": return copy.deepcopy(self.user)
            if method == "PUT": self.user.update(copy.deepcopy(obj)); return None
        if path == "/users/%s/credentials" % UID: return copy.deepcopy(self.creds)
        if path == "/users/%s/federated-identity" % UID: return copy.deepcopy(self.links)
        if path == "/users/%s/logout" % UID: return None
        raise AssertionError("unexpected call %s %s" % (method, path))

def run(case, reset_impl, bindings_impl=None):
    kc, st = FakeKC(), {"reset_at": {UID: 1000}, "pending": {}}
    M.reset_factors = reset_impl
    M.clear_bindings = bindings_impl or (lambda kc_, u: [])
    lines, fails = M.contain_user(kc, st, UID, "unit test")
    return kc, st, lines, fails

real_reset, real_bindings = M.reset_factors, M.clear_bindings

# 1. the reset raises partway (removed the password, then failed): reset_at unchanged, held, disable + logout still ran
def partial(kc, u, why):
    kc.creds = kc.creds[1:]
    raise RuntimeError("factor reset incomplete: otp remains")
kc, st, lines, fails = run("partial", partial)
check("reset fails partway -> reset_at UNCHANGED", st["reset_at"][UID] == 1000, "%s" % st["reset_at"])
check("... the account is HELD (user-enable refuses it)", UID in st.get("guard_disabled", {}), "%s" % st.get("guard_disabled"))
check("... the remaining steps still ran: disabled, sessions ended", kc.user["enabled"] is False and ("POST", "/users/%s/logout" % UID) in kc.calls)
check("... and the failure is reported", "reset" in fails and "reset not verified" in fails, "%s" % fails)

# 2. the reset "returns" but a credential is left (the re-read disagrees): reset_at unchanged, held
kc, st, lines, fails = run("lying", lambda kc_, u, why: ["password"])
check("reset returns but the re-read finds factors left -> reset_at UNCHANGED, held", st["reset_at"][UID] == 1000
      and UID in st.get("guard_disabled", {}) and "reset not verified" in fails, "%s" % fails)

# 3. a complete, verified reset: reset_at moves, still held; the identity bindings are NEVER cleared automatically
def clean(kc, u, why):
    kc.creds, kc.links = [], []; kc.user["email"] = ""; return ["password", "otp", "link:entra", "email"]
def bindings_called(kc, u):
    raise AssertionError("contain_user must never clear identity bindings")
kc, st, lines, fails = run("ok", clean, bindings_called)
check("a complete, verified reset -> reset_at moves; held; no failure", st["reset_at"][UID] > 1000
      and UID in st.get("guard_disabled", {}) and fails == [], "%s" % fails)
check("... and the identity bindings are kept (cac_edipi, entra_oid untouched)", kc.user["attributes"].get("cac_edipi") == ["1234567890"]
      and kc.user["attributes"].get("entra_oid") == ["oid"])

# 5. the gate's capability marker (server info), read by the guard
class InfoKC:
    def __init__(self, status, body): self.status, self.body = status, body
    def req(self, method, path, *a, **k):
        assert path == "/admin/serverinfo"
        if isinstance(self.body, Exception): raise self.body
        return self.status, self.body
def info(op):
    import json as _j
    return _j.dumps({"providers": {"authenticator": {"providers": {"stig-admin-allowlist-gate": {"operationalInfo": op} if op is not None else {}}}}})
check("marker 1 -> the gate checks role extent", M.gate_enforces_roles(InfoKC(200, info({"allowlist-role-extent": "1"}))) is True)
check("marker 2 (newer) -> checks", M.gate_enforces_roles(InfoKC(200, info({"allowlist-role-extent": "2"}))) is True)
check("marker missing (older extension) -> NOT confirmed", M.gate_enforces_roles(InfoKC(200, info(None))) is False)
check("marker 0 (older) -> NOT confirmed", M.gate_enforces_roles(InfoKC(200, info({"allowlist-role-extent": "0"}))) is False)
check("marker unparseable -> NOT confirmed", M.gate_enforces_roles(InfoKC(200, info({"allowlist-role-extent": "x"}))) is False)
check("server info refused (403) -> NOT confirmed", M.gate_enforces_roles(InfoKC(403, "{}")) is False)
check("server info unreachable -> NOT confirmed", M.gate_enforces_roles(InfoKC(200, OSError("down"))) is False)

# 6. when the users an unvetted account changed are contained
R = M.containment_reason
ch = {"t": ["ACTION users/t/reset-password"]}
check("start of the unvetted period NOT proven, changes -> NOTHING contained (listed only)", R(False, True, {"t": ["x"]}, proven=False) is None)
check("not proven, over-entry, marker missing -> nothing contained", R(True, False, {"t": ["x"]}, proven=False) is None)
check("over-entry, marker missing, no changes -> contain (reason given)", R(True, False, {}) is not None)
check("over-entry, marker missing, changes -> contain", R(True, False, ch) is not None)
check("over-entry, marker present, no changes -> nothing to contain", R(True, True, {}) is None)
check("over-entry, marker present, CHANGES -> contain anyway (the gate failed)", R(True, True, ch) is not None)
check("not on the allowlist, changes -> contain (the gate failed)", R(False, True, ch) is not None)
check("not on the allowlist, no changes -> nothing to contain", R(False, True, {}) is None)

# 7. which users count as changed: from unvetted_since, users/<uuid> only, never itself
T1, T2 = "aaaaaaaa-0000-4000-8000-000000000001", "aaaaaaaa-0000-4000-8000-000000000002"
evs = [{"time": 500, "operationType": "ACTION", "resourcePath": "users/%s/reset-password" % T1},     # before since
       {"time": 2000, "operationType": "ACTION", "resourcePath": "users/%s/reset-password" % T2},
       {"time": 2001, "operationType": "UPDATE", "resourcePath": "users/%s" % UID},                    # itself
       {"time": 2002, "operationType": "CREATE", "resourcePath": "clients/xyz"},
       {"time": 2003, "operationType": "UPDATE", "resourcePath": "users/not-a-uuid"}]
real_ae, real_us = M.admin_events, M.unvetted_since
M.admin_events = lambda kc_, qy: evs
M.unvetted_since = lambda kc_, st_, uid_, e_: (1000, True)
got, proven = M.changed_users(None, {}, UID, {})
check("changed users: from the unvetted point only, users/<uuid> paths only, never itself; proven passed on", list(got) == [T2] and proven, "%s" % got)
M.unvetted_since = lambda kc_, st_, uid_, e_: (0, False)
got, proven = M.changed_users(None, {}, UID, {})
check("changed users with an unproven start: everything listed, marked NOT proven", not proven and set(got) == {T1, T2}, "%s" % got)
M.admin_events, M.unvetted_since = real_ae, real_us

# 8. a changed user is contained through contain_user (held, verified reset, bindings kept) - unless allowlisted
M.reset_factors, M.clear_bindings = clean, bindings_called
kc8, st8 = FakeKC(), {"reset_at": {}, "pending": {}}
lines8, fails8 = M.contain_changed(kc8, st8, {UID: ["ACTION users/%s/reset-password" % UID]}, {})
check("contain_changed: a changed user disabled, held, reset verified, bindings kept",
      kc8.user["enabled"] is False and UID in st8.get("guard_disabled", {}) and UID in st8["reset_at"] and fails8 == []
      and kc8.user["attributes"].get("cac_edipi") == ["1234567890"], "%s" % fails8)
def ev(t, op, path, realm, rep=None):
    e = {"time": t, "operationType": op, "resourcePath": path, "authDetails": {"realmId": realm}}
    if rep is not None: e["representation"] = json.dumps(rep)
    return e
kc9, st9 = FakeKC(), {"reset_at": {}, "pending": {}}
kc9.creds = [{"id": "p1", "type": "password", "createdDate": 50000}, {"id": "o1", "type": "otp", "createdDate": 10000}]
kc9.links = [{"identityProvider": "entra"}, {"identityProvider": "other"}]
kc9.events = [ev(1000, "CREATE", "users/%s" % UID, "MASTER", {"attributes": {"cac_edipi": ["1234567890"], "entra_oid": ["oid"]}}),
              ev(2000, "CREATE", "users/%s/federated-identity/other" % UID, "MASTER"),
              ev(49000, "ACTION", "users/%s/reset-password" % UID, "REALM"),           # an unvetted account resets its password
              ev(49500, "CREATE", "users/%s/federated-identity/entra" % UID, "REALM")]  # ... and plants a link
lines9, fails9 = M.contain_changed(kc9, st9, {UID: ["ACTION users/%s/reset-password" % UID]}, {UID: {}})
check("an ALLOWLISTED user changed by an unvetted account: sessions ended; the password and link a non-operator added removed; "
      "its OTP, the operator's link and its bindings kept; NOT disabled, not held",
      ("POST", "/users/%s/logout" % UID) in kc9.calls and [c["id"] for c in kc9.creds] == ["o1"]
      and [l["identityProvider"] for l in kc9.links] == ["other"] and kc9.user["enabled"] is True
      and kc9.user["attributes"].get("cac_edipi") == ["1234567890"] and UID not in st9.get("guard_disabled", {})
      and "ALLOWLISTED-TOUCHED" in lines9[0] and fails9 == [], "%s" % lines9)
kc9b = FakeKC(); kc9b.events = [ev(1000, "CREATE", "users/%s" % UID, "MASTER", {"attributes": {"cac_edipi": ["0000000000"]}}),
                                ev(3000, "UPDATE", "users/%s" % UID, "REALM", {"attributes": {"cac_edipi": ["1234567890"], "entra_oid": ["oid"]}})]
lines9b, _ = M.contain_changed(kc9b, {"reset_at": {}, "pending": {}}, {UID: ["UPDATE users/%s" % UID]}, {UID: {}})
check("... a binding a non-operator set on it is flagged for REVIEW and kept", "REVIEW binding cac_edipi" in lines9b[0]
      and kc9b.user["attributes"].get("cac_edipi") == ["1234567890"], "%s" % lines9b)

# 8a. binding provenance from the admin events
pk = FakeKC()
pk.events = [ev(1000, "CREATE", "users/%s" % UID, "MASTER", {"attributes": {"cac_edipi": ["1234567890"]}})]
check("binding provenance: set by the operator's tooling -> True", M.binding_provenance(pk, UID).get("cac_edipi") is True)
pk.events.append(ev(2000, "UPDATE", "users/%s" % UID, "REALM", {"attributes": {"cac_edipi": ["1234567890"], "entra_oid": ["oid"]}}))
prov = M.binding_provenance(pk, UID)
check("binding provenance: an unchanged value re-sent by someone else keeps the operator; a new one is theirs",
      prov.get("cac_edipi") is True and prov.get("entra_oid") is False, "%s" % prov)
pk.events = []
check("binding provenance: no event shows the current value -> unknown (None)", M.binding_provenance(pk, UID).get("cac_edipi") is None)

# 8b0. reset_at waits while a non-operator binding remains; reset-user releases only then (or with --clear-bindings)
M.reset_factors = clean
kcb = FakeKC(); kcb.events = [ev(3000, "UPDATE", "users/%s" % UID, "REALM", {"attributes": {"cac_edipi": ["1234567890"]}})]
stb = {"reset_at": {UID: 1000}, "pending": {}}
lb, fb = M.contain_user(kcb, stb, UID, "unit test")
check("contain_user: a clean reset with a NON-OPERATOR binding left -> reset_at UNCHANGED, held, binding kept",
      stb["reset_at"][UID] == 1000 and UID in stb.get("guard_disabled", {}) and kcb.user["attributes"].get("cac_edipi")
      and any("reset_at unchanged" in l for l in lb), "%s" % lb)
real_load, real_save = M.load_state, M.save_state
store = {"st": {"reset_at": {UID: 1000}, "pending": {}, "guard_disabled": {UID: {"at": 1, "why": "x"}}}}
M.load_state = lambda: copy.deepcopy(store["st"]); M.save_state = lambda st_: store.__setitem__("st", copy.deepcopy(st_))
kcr = FakeKC(); kcr.events = kcb.events
g1, rel1, nb1 = M.reset_user(kcr, kcr.user, False)
check("reset-user without --clear-bindings: hold NOT released, reset_at unchanged while a non-operator binding remains",
      not rel1 and "cac_edipi" in nb1 and UID in store["st"]["guard_disabled"] and store["st"]["reset_at"][UID] == 1000)
def clear_all(kc_, u):
    kc_.user["attributes"] = {}; return ["binding:cac_edipi"]
M.clear_bindings = clear_all
g2, rel2, nb2 = M.reset_user(kcr, kcr.user, True)
check("reset-user --clear-bindings: binding gone -> hold released, reset_at moves", rel2 and not nb2
      and UID not in store["st"]["guard_disabled"] and store["st"]["reset_at"][UID] > 1000)
M.load_state, M.save_state = real_load, real_save
kcp = FakeKC(); kcp.events = kcb.events; kcp.links = []; kcp.user["createdTimestamp"] = int(time.time() * 1000)
check("promotion_risks: a non-operator binding is a risk whatever reset_at says",
      any("cac_edipi is not proven to be set by the operator" in r for r in M.promotion_risks(kcp, kcp.user, {}, since=10 ** 13)))
M.clear_bindings = bindings_called

# 8b. the start of the unvetted period: never vetted -> all of its events; vetted -> after its LAST vetting. No fallback.
U1 = "bbbbbbbb-0000-4000-8000-000000000001"
check("unvetted_since: never vetted -> all of its events (0), proven", M.unvetted_since(None, {"vetted_at": {}}, U1, None) == (0, True))
check("unvetted_since: vetted at some point -> after its last vetting, proven", M.unvetted_since(None, {"vetted_at": {U1: 4000}}, U1, None) == (4000, True))

# 8d. NEEDS_REGRANT only where the deployed gate itself refuses for it (marker >= 2)
check("effective_standing: needs-regrant with gate marker 2 -> needs-regrant", M.effective_standing(M.NEEDS_REGRANT, 2) == M.NEEDS_REGRANT)
check("effective_standing: needs-regrant with marker 1, 0 (older or unconfirmed gate) -> over-entry",
      M.effective_standing(M.NEEDS_REGRANT, 1) == M.OVER_ENTRY and M.effective_standing(M.NEEDS_REGRANT, 0) == M.OVER_ENTRY)
check("effective_standing: other standings unchanged", M.effective_standing(M.OVER_ENTRY, 0) == M.OVER_ENTRY and M.effective_standing(M.VETTED, 0) == M.VETTED)

# 8c. a stale copy of the state never erases when an account was vetted
import tempfile as _tf
_d = _tf.mkdtemp(); real_state = M.STATE; M.STATE = _d + "/state.json"
M._write_json(M.STATE, {"reset_at": {}, "pending": {}, "vetted_at": {U1: 5000}})
stale = {"reset_at": {}, "pending": {"x": 1}, "vetted_at": {}}
M.save_state(stale)
check("save_state: a stale copy keeps the vetting recorded on disk (vetted_at merged, latest wins)",
      (M.load_state() or {}).get("vetted_at", {}).get(U1) == 5000 and (M.load_state() or {}).get("pending") == {"x": 1})
M.STATE = real_state

# 10. provenance unknown is untrusted; the events must be able to prove the history
pv = FakeKC()
check("untrusted_bindings: operator-set bindings are trusted", M.untrusted_bindings(pv, UID) == [])
pv.events = []
check("untrusted_bindings: unknown provenance (no event shows the value) is NOT trusted", M.untrusted_bindings(pv, UID) == ["cac_edipi", "entra_oid"])
for label, cfg in (("admin events off", {"adminEventsEnabled": False, "adminEventsDetailsEnabled": True}),
                   ("no representations", {"adminEventsEnabled": True, "adminEventsDetailsEnabled": False}),
                   ("account older than the retention", {"adminEventsEnabled": True, "adminEventsDetailsEnabled": True, "adminEventsExpiration": 60})):
    pe = FakeKC(); pe._ev_cfg = cfg; pe.user["createdTimestamp"] = int((time.time() - 3600) * 1000)
    check("binding provenance: %s -> unknown (None) even with an operator event" % label,
          set(M.binding_provenance(pe, UID).values()) == {None} and M.untrusted_bindings(pe, UID) == ["cac_edipi", "entra_oid"])
pe = FakeKC(); pe._ev_cfg = {"adminEventsEnabled": True, "adminEventsDetailsEnabled": True, "adminEventsExpiration": 86400}
pe.user["createdTimestamp"] = int(time.time() * 1000)
check("binding provenance: retention set but the account younger than it -> provable (True)", M.binding_provenance(pe, UID).get("cac_edipi") is True)

# 11. a card counts as the strong sign-in path only when the operator's tooling set the mapping
sp1 = FakeKC()
check("strong_path: operator-set card mapping -> card", M.strong_path(sp1, sp1.user) == "card")
sp2 = FakeKC(); sp2.events = [ev(5, "UPDATE", "users/%s" % UID, "REALM", {"attributes": {"cac_edipi": ["1234567890"]}})]; sp2.creds = []
check("strong_path: a card mapping someone else set -> not a strong path", M.strong_path(sp2, sp2.user) is None)
sp3 = FakeKC(); sp3.events = []; sp3.creds = []
check("strong_path: a card mapping of unknown provenance -> not a strong path", M.strong_path(sp3, sp3.user) is None)

# 12. promotion refuses while an untrusted binding remains, unless --clear-bindings
bg = FakeKC(); bg.events = []
try:
    M.binding_gate(bg, bg.user, False); refused = False
except SystemExit as ex_:
    refused = "REFUSED" in str(ex_)
check("binding_gate: an untrusted binding after the reset -> grant/promote REFUSED", refused)
M.clear_bindings = clear_all
check("binding_gate --clear-bindings: cleared, then accepted", M.binding_gate(bg, bg.user, True) == ["binding:cac_edipi"] and not bg.user["attributes"])
M.clear_bindings = bindings_called
check("binding_gate: only operator-set bindings -> nothing to do", M.binding_gate(FakeKC(), FakeKC().user, False) == [])

# 13. the gate marker: unreadable is never 0
check("gate_version: server info refused -> None (unreadable)", M.gate_version(InfoKC(403, "{}")) is None)
check("gate_version: server info unreachable -> None", M.gate_version(InfoKC(200, OSError("down"))) is None)
check("gate_version: the gate states no marker (older extension) -> 0", M.gate_version(InfoKC(200, info(None))) == 0)
check("gate_version: marker 2 -> 2", M.gate_version(InfoKC(200, info({"allowlist-role-extent": "2"}))) == 2)

# 14. the guard stops (alert, nothing contained or published) on a lost record
P = M.guard_preflight
check("preflight: allowlist file MISSING while the published allowlist names administrators -> stop", P(False, {}, "u1", True) is not None)
check("preflight: allowlist file EMPTY while published names administrators -> stop", P(True, {}, "u1", True) is not None)
check("preflight: guard state missing while there are vetted administrators -> stop", P(True, {"u1": {}}, "u1", False) is not None)
check("preflight: fresh install (nothing on disk, nothing published) -> proceed", P(False, {}, None, False) is None and P(False, {}, "", False) is None)
check("preflight: normal (file, state, published) -> proceed", P(True, {"u1": {}}, "u1", True) is None)
src2 = open(ADM).read()
g2 = src2[src2.index("def guard("):src2.index("def unvetted_since(")]
check("guard(): the preflight runs before any publish or containment; an unreadable marker turns the run to report only",
      g2.index("guard_preflight(") < g2.index("publish_allowlist(") < g2.index("contain_user(") and "fix = False" in g2[:g2.index("publish_allowlist(")])

# 15. the guard stops (alert, nothing done) when the published allowlist cannot be read - never "nothing published"
class MasterKC:
    def __init__(self, status): self.status = status
    def req(self, method, path, *a, **k):
        assert path == "/admin/realms/master"
        return self.status, "{}"
    def api(self, method, path, *a, **k):
        if path == "/clients?clientId=admin-permissions":
            return []                    # before the preflight: nothing to clean up
        raise AssertionError("the guard went past its preflight: %s %s" % (method, path))
import io as _io, contextlib as _cl
real_bm, real_sap, real_aw = M.binding_mappers, M.sync_admin_protection, M.admin_members
M.binding_mappers, M.sync_admin_protection, M.admin_members = (lambda kc_: []), (lambda kc_, a_: None), (lambda kc_: {})
for status in (403, 500):
    _err = _io.StringIO()
    with _cl.redirect_stderr(_err), _cl.redirect_stdout(_io.StringIO()):
        try:
            r_ = M.guard(MasterKC(status), True)
        except AssertionError as ex_:
            r_ = "went on: %s" % ex_
    check("guard: GET master realm -> HTTP %s: stops and alerts (STIG-ADMIN-GUARD-STOPPED), does nothing else" % status,
          r_ == M.GUARD_VIOLATION and "STIG-ADMIN-GUARD-STOPPED" in _err.getvalue(), "%s" % r_)
M.binding_mappers, M.sync_admin_protection, M.admin_members = real_bm, real_sap, real_aw

# 9. the guard's classification of an administrator against its entry = the gate's (StigAdministrators.classify)
G = {"aaaaaaaa-0000-4000-8000-0000000000aa": {"query-users", "view-users"}}
live = lambda gid: G.get(gid)
gi = "group:aaaaaaaa-0000-4000-8000-0000000000aa@query-users+view-users"
check("classify: within the snapshot -> vetted", M.classify({"query-users"}, [gi], live) == M.VETTED)
G["aaaaaaaa-0000-4000-8000-0000000000aa"] = {"query-users", "view-users", "manage-users"}
check("classify: the group carries MORE now and the user holds it -> needs-regrant (not over-entry)",
      M.classify({"query-users", "manage-users"}, [gi], live) == M.NEEDS_REGRANT)
check("classify: a role outside even the live grant -> over-entry", M.classify({"query-users", "realm-admin"}, [gi], live) == M.OVER_ENTRY)
check("classify: granted group id gone, nothing extra -> needs-regrant", M.classify({"query-users"}, ["group:gone@query-users"], live) == M.NEEDS_REGRANT)
check("classify: group by path, unknown kinds, no snapshot, no items -> refused",
      M.classify({"query-users"}, ["group:/roles/idp-admin@query-users"], live) != M.VETTED
      and M.classify({"query-users"}, ["role:query-users"], live) == M.NOT_LISTED
      and M.classify({"query-users"}, ["group:x"], live) == M.NOT_LISTED and M.classify({"query-users"}, [], live) == M.NOT_LISTED)
check("classify: the older format (bare names) still read", M.classify({"query-users"}, ["query-users"], live) == M.VETTED
      and M.classify({"realm-admin"}, ["query-users"], live) == M.OVER_ENTRY)
check("entry_items: grants publish group:<id>@<snapshot>", M.entry_items({"grants": [{"id": "g", "path": "/roles/x", "roles": ["a", "b"]}]}) == ["group:g@a+b"]
      and M.entry_items({"rm_roles": ["a"]}) == ["a"])

# 5. the guard and the containment loop use contain_user (no other writer of reset_at in them)
src = open(ADM).read()
g = src[src.index("def guard("):src.index("def unvetted_since(")]
check("guard() contains through contain_user / contain_changed and never writes reset_at itself",
      "contain_user(" in g and "contain_changed(" in g and 'st["reset_at"]' not in g)
cu = src[src.index("def contain_user("):src.index("GATE_PROVIDER")]
check("neither the guard nor the containment ever clears identity bindings (only reset-user --clear-bindings does)",
      "clear_bindings(" not in g and "clear_bindings(" not in cu)
M.reset_factors, M.clear_bindings = real_reset, real_bindings
print("\n%d/%d passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)

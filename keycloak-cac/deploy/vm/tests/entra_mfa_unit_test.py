#!/usr/bin/env python3
"""Unit test of idp-admin.py's tenant-MFA flow handling with a fake Keycloak that models authentication flows - no live
call, no root, runs anywhere.

  - migration: the live shape (conditional-user-attribute on a stored entra_amr) and an older one
    (conditional-user-role, no refusal) both become the current shape IN PLACE; after EVERY admin-API write the
    administrators' sub-flow exists, is CONDITIONAL, keeps at least one condition (a CONDITIONAL sub-flow without one is
    skipped) and still requires a second factor - never weaker, never absent;
  - drift (guard, and the re-read after setup): the WHOLE condition configuration (accept-amr exactly mfa, accept-acr
    empty, alias, tenants) and every requirement (the sub-flow, each execution) - a console edit to accept `pwd`, any
    acr, a DISABLED sub-flow or condition, an extra tenant are each reported;
  - guard --fix narrows only: requirements restored, the configuration reset to the live tenants the config also
    trusts - never a tenant added; the retired amr mapper removed and entra_amr cleared;
  - entra-mfa --remove-condition keeps the sub-flow strict.

  python3 entra_mfa_unit_test.py [--admin ../host/idp-admin.py]
"""
import argparse, contextlib, importlib.machinery, importlib.util, io, json, os, sys, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser(); ap.add_argument("--admin", default=os.path.join(HERE, "..", "host", "idp-admin.py"))
args = ap.parse_args()
os.environ.setdefault("IDP_ADMIN_CONFIG", os.path.join(HERE, "fixtures", "idp-admin.test.json"))
ld = importlib.machinery.SourceFileLoader("idp_admin", args.admin)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)

res = []
def check(n, ok, d=""):
    res.append(bool(ok)); print("%s  %-100s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

T1, T2, T3 = ("00000000-0000-4000-8000-00000000000%d" % i for i in (1, 2, 3))
SUB = M.POST_BROKER_SUB

class FakeKC:
    """Flows as Keycloak keeps them: a flow alias -> its executions (an execution may be a sub-flow, by alias)."""
    def __init__(self):
        self.flows, self.cfgs, self.n, self.mappers, self.users, self.writes = {}, {}, 0, [], {}, []
        self.watch = None                                  # called after every write
    def nid(self):
        self.n += 1; return "x%d" % self.n
    def add_flow(self, alias):
        self.flows.setdefault(alias, [])
    def add_exec(self, flow, provider=None, req="DISABLED", sub=None, cfg=None):
        e = {"id": self.nid(), "providerId": provider, "requirement": req, "sub": sub}
        if cfg is not None:
            cid = self.nid(); self.cfgs[cid] = {"id": cid, "alias": cid, "config": dict(cfg)}; e["cfg"] = cid
        if sub:
            self.add_flow(sub)
        self.flows[flow].append(e); return e
    def listing(self, alias, level=0):
        out = []
        for e in self.flows.get(alias, []):
            r = {"id": e["id"], "level": level, "requirement": e["requirement"], "index": len(out)}
            if e["sub"]:
                r.update(displayName=e["sub"], authenticationFlow=True)
            else:
                r.update(providerId=e["providerId"], displayName=e["providerId"])
            if e.get("cfg"):
                r["authenticationConfig"] = e["cfg"]
            out.append(r)
            if e["sub"]:
                out += self.listing(e["sub"], level + 1)
        return out
    def find(self, eid):
        for f, es in self.flows.items():
            for i, e in enumerate(es):
                if e["id"] == eid:
                    return f, i, e
        raise KeyError(eid)
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        u = urllib.parse.urlparse(path); p = urllib.parse.unquote(u.path); parts = p.strip("/").split("/")
        r = self._api(method, p, parts, obj, u.query)
        if r == 404:
            if ok404:
                return None
            raise SystemExit("%s %s -> 404" % (method, path))
        if method != "GET":
            self.writes.append((method, p))
            if self.watch:
                self.watch(method, p)
        return r
    def _api(self, method, p, parts, obj, query):
        if p == "/authentication/flows" and method == "GET":
            return [{"alias": a, "id": a} for a in self.flows]
        if p == "/authentication/flows" and method == "POST":
            self.add_flow(obj["alias"]); return None
        if parts[:2] == ["authentication", "flows"] and len(parts) >= 4 and parts[3] == "executions":
            alias = parts[2]
            if alias not in self.flows:
                return 404
            if method == "GET" and len(parts) == 4:
                return self.listing(alias)
            if method == "PUT" and len(parts) == 4:
                self.find(obj["id"])[2]["requirement"] = obj["requirement"]; return None
            if method == "POST" and parts[4:] == ["execution"]:
                self.add_exec(alias, obj["provider"]); return None
            if method == "POST" and parts[4:] == ["flow"]:
                self.add_exec(alias, sub=obj["alias"]); return None
        if parts[:2] == ["authentication", "executions"]:
            f, i, e = self.find(parts[2])
            if method == "DELETE" and len(parts) == 3:
                self.flows[f].pop(i); return None
            if parts[3:] == ["raise-priority"]:
                if i > 0:
                    self.flows[f][i - 1], self.flows[f][i] = self.flows[f][i], self.flows[f][i - 1]
                return None
            if parts[3:] == ["config"] and method == "POST":
                cid = self.nid(); self.cfgs[cid] = {"id": cid, "alias": obj["alias"], "config": dict(obj["config"])}; e["cfg"] = cid; return None
        if parts[:2] == ["authentication", "config"]:
            if method == "GET":
                return json.loads(json.dumps(self.cfgs[parts[2]]))
            if method == "PUT":
                self.cfgs[parts[2]] = json.loads(json.dumps(obj)); return None
        if p == "/identity-provider/instances/entra":
            return {"alias": "entra", "config": {}}
        if p == "/identity-provider/instances/entra/mappers":
            return [dict(m) for m in self.mappers]
        if parts[:4] == ["identity-provider", "instances", "entra", "mappers"] and method == "DELETE":
            self.mappers = [m for m in self.mappers if m["id"] != parts[4]]; return None
        if p == "/identity-provider/instances":
            return [{"alias": "entra"}]
        if p == "/users":
            q_ = dict(urllib.parse.parse_qsl(query)); first = int(q_.get("first", 0)); mx = int(q_.get("max", 100))
            return [json.loads(json.dumps(u)) for u in list(self.users.values())[first:first + mx]]
        return 404
    def req(self, method, path, body=None, headers=None):
        if "/stig-bindings/users/" in path:
            uid = path.rsplit("/", 1)[1]; b = json.loads(body)
            if not __import__("re").fullmatch(r"[a-z0-9 _-]{1,40}", b.get("reason", "x")):     # the endpoint's own rule
                return 400, '{"error":"reason must be 1-40 of a-z 0-9 space _ -"}'
            for k in b.get("remove", []):
                (self.users[uid].get("attributes") or {}).pop(k, None)
            self.writes.append(("POST", "stig-bindings")); return 200, "{}"
        return 404, ""

def sub_state(kc):
    """(present, requirement, conditions, second factor required) of the administrators' sub-flow."""
    top = [e for e in kc.flows.get(M.POST_BROKER, []) if e["sub"] == SUB]
    if not top:
        return (False, None, [], False)
    kids = kc.flows.get(SUB, [])
    conds = [e["providerId"] for e in kids if (e["providerId"] or "").startswith("conditional-") and e["requirement"] != "DISABLED"]
    second = any(e["providerId"] in ("stig-admin-second-factor-required", "auth-otp-form") and e["requirement"] == "REQUIRED" for e in kids)
    return (True, top[0]["requirement"], conds, second)

def strict(st):
    return st[0] and st[1] == "CONDITIONAL" and len(st[2]) >= 1 and st[3]

def watched(kc):
    bad = []
    def w(method, p):
        st = sub_state(kc)
        if not strict(st):
            bad.append((method, p, st))
    kc.watch = w
    return bad

def base_realm(kids):
    kc = FakeKC(); kc.add_flow(M.POST_BROKER)
    kc.add_exec(M.POST_BROKER, sub=SUB, req="CONDITIONAL")
    for prov, req, cfg in kids:
        kc.add_exec(SUB, prov, req, cfg=cfg)
    kc.add_exec(M.POST_BROKER, "idp-require-admin-attribute-match", "REQUIRED", cfg=M.binding_cfg("entra", T1))
    kc.add_exec(M.POST_BROKER, "user-session-limits", "REQUIRED", cfg={"userRealmLimit": "3"})
    return kc

def quiet(fn, *a):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        try:
            return fn(*a), out.getvalue()
        except (SystemExit, RuntimeError) as e:
            return e, out.getvalue()

LIVE = [("conditional-stig-administrator", "REQUIRED", None),
        ("conditional-user-attribute", "REQUIRED", {"attribute_name": "entra_amr", "attribute_expected_value": "mfa", "not": "true"}),
        ("stig-admin-second-factor-required", "REQUIRED", None), ("auth-otp-form", "REQUIRED", None)]
OLDER = [("conditional-user-role", "REQUIRED", {"condUserRole": "realm-management.realm-admin"}), ("auth-otp-form", "REQUIRED", None)]

# ---- migration, never weaker
for name, kids in (("the live shape (cua on a stored entra_amr)", LIVE), ("an older shape (conditional-user-role, no refusal)", OLDER)):
    kc = base_realm(kids); bad = watched(kc)
    r, out = quiet(M.post_broker_flow, kc, "entra", T1, [T1])
    shape = [(e["providerId"], e["requirement"]) for e in kc.flows[SUB]]
    check("migrate %s: ends in the current shape, every execution REQUIRED" % name,
          not isinstance(r, BaseException) and shape == M.POST_BROKER_SUB_REQ, (r if isinstance(r, BaseException) else "", shape))
    check("... after EVERY write the sub-flow exists, is CONDITIONAL, keeps a condition and requires a second factor",
          not bad and len(kc.writes) > 0, bad[:2] or "%d writes" % len(kc.writes))
    check("... and the condition trusts exactly the given tenant, amr mfa, no acr", M.idp_mfa_drift(kc, "entra", [T1]) == [],
          M.idp_mfa_drift(kc, "entra", [T1]))
    w0 = len(kc.writes); quiet(M.post_broker_flow, kc, "entra", T1, [T1])
    check("... a re-run changes nothing structural (no execution added or deleted)",
          not any(m in ("DELETE",) or p.endswith("/execution") for m, p in kc.writes[w0:]), kc.writes[w0:])

# ---- drift: the WHOLE configuration and every requirement
def current(tenants=(T1,)):
    kc = base_realm(LIVE); quiet(M.post_broker_flow, kc, "entra", T1, list(tenants)); kc.writes.clear(); return kc
def cond(kc):
    return [e for e in kc.flows[SUB] if e["providerId"] == M.IDP_MFA_COND][0]
def edit_cfg(kc, **kv):
    c = kc.cfgs[cond(kc)["cfg"]]["config"]
    for k, v in kv.items():
        if v is None:
            c.pop(k, None)
        else:
            c[k] = v
kc = current()
check("drift: none for the intended shape and configuration", M.idp_mfa_drift(kc, "entra", [T1]) == [], M.idp_mfa_drift(kc, "entra", [T1]))
cases = [("accept-amr edited to pwd (one factor would pass)", lambda k: edit_cfg(k, **{"stig.idp-mfa.accept-amr": "pwd"})),
         ("accept-amr widened to mfa,pwd", lambda k: edit_cfg(k, **{"stig.idp-mfa.accept-amr": "mfa,pwd"})),
         ("accept-acr set to c1", lambda k: edit_cfg(k, **{"stig.idp-mfa.accept-acr": "c1"})),
         ("an extra trusted tenant", lambda k: edit_cfg(k, **{"stig.idp-mfa.trusted-tenants": T1 + "##" + T2})),
         ("another provider alias", lambda k: edit_cfg(k, **{"stig.idp-mfa.idp-alias": "corp"})),
         ("the sub-flow DISABLED", lambda k: k.flows[M.POST_BROKER][0].update(requirement="DISABLED")),
         ("the sub-flow REQUIRED instead of CONDITIONAL", lambda k: k.flows[M.POST_BROKER][0].update(requirement="REQUIRED")),
         ("conditional-stig-administrator DISABLED", lambda k: k.flows[SUB][0].update(requirement="DISABLED")),
         ("the gate DISABLED", lambda k: k.flows[SUB][2].update(requirement="DISABLED")),
         ("the OTP form ALTERNATIVE", lambda k: k.flows[SUB][3].update(requirement="ALTERNATIVE"))]
for name, mut in cases:
    kc = current(); mut(kc); d = M.idp_mfa_drift(kc, "entra", [T1])
    check("drift reported: %s" % name, bool(d), d[:1])
kc = current(); edit_cfg(kc, **{"stig.idp-mfa.accept-amr": None, "stig.idp-mfa.accept-acr": None})
check("drift: absent accept-amr / accept-acr read as the extension's defaults (mfa, none): no drift",
      M.idp_mfa_drift(kc, "entra", [T1]) == [], M.idp_mfa_drift(kc, "entra", [T1]))

# ---- guard --fix narrows only
for name, mut in cases:
    kc = current(); mut(kc)
    done = M.fix_idp_mfa(kc, "entra", [T1])
    if "alias" in name:     # trust from another provider's name: narrowed to NOTHING (never re-trusted by the fix)
        check("fix: %s -> trust switched off (alias entra, no tenant); drift left for entra-mfa" % name,
              M.live_idp_mfa(kc) == ("entra", []) and M.idp_mfa_drift(kc, "entra", []) == [], (done, M.live_idp_mfa(kc)))
        continue
    check("fix: %s -> back to intended" % name, M.idp_mfa_drift(kc, "entra", [T1]) == [] and done, (done, M.idp_mfa_drift(kc, "entra", [T1])))
kc = current(tenants=(T1, T2))
done = M.fix_idp_mfa(kc, "entra", [T1, T3])
check("fix: live trusts T1+T2, config T1+T3 -> narrowed to T1 (T2 dropped, T3 NOT added)", M.live_idp_mfa(kc) == ("entra", [T1]), (done, M.live_idp_mfa(kc)))
kc = current(tenants=())
done = M.fix_idp_mfa(kc, "entra", [T1])
check("fix: live trusts nobody, config T1 -> left trusting nobody (never widened), drift still reported",
      M.live_idp_mfa(kc) == ("entra", []) and M.idp_mfa_drift(kc, "entra", [T1]) != [], (done, M.live_idp_mfa(kc)))

# ---- guard's report and fix: amr mapper, stale entra_amr
kc = current()
kc.mappers = [{"id": "m1", "name": M.AMR_MAPPER, "config": {"claim": "amr", "user.attribute": "entra_amr"}}]
kc.users = {"u1": {"id": "u1", "username": "a.b", "attributes": {"entra_amr": ["pwd", "mfa"]}}, "u2": {"id": "u2", "username": "c.d", "attributes": {}}}
M._AC = dict(M._AC, entra=dict(M._AC.get("entra") or {}, mfaTrustedTenants=[T1]))
rep = M.entra_mfa_report(kc)
check("report: the retired mapper and a stored entra_amr are each drift", sum("STIG-IDP-MFA-DRIFT" in x for x in rep) == 2, rep)
rep = M.entra_mfa_report(kc, True)
check("--fix: mapper removed, entra_amr cleared (server-side bindings), nothing left",
      not kc.mappers and not kc.users["u1"]["attributes"].get("entra_amr") and not any(x.startswith("STIG-IDP-MFA-DRIFT still") for x in rep), rep)
kc.cfgs[cond(kc)["cfg"]]["config"]["stig.idp-mfa.accept-amr"] = "pwd"
rep = M.entra_mfa_report(kc, True)
check("--fix: accept-amr pwd reset to mfa and reported as fixed", M.idp_mfa_drift(kc, "entra", [T1]) == [] and any("fixed" in x for x in rep), rep)

# ---- --remove-condition stays strict
kc = current(); bad = watched(kc)
M.KC = lambda: kc
r, out = quiet(M.cmd_entra_mfa, argparse.Namespace(show=False, off=False, trust_tenant=[], remove_condition=True))
check("--remove-condition: the condition gone; the sub-flow still CONDITIONAL with the administrator condition and both factors",
      [e["providerId"] for e in kc.flows[SUB]] == ["conditional-stig-administrator", "stig-admin-second-factor-required", "auth-otp-form"]
      and not bad, (out.strip()[-120:], bad))

print("\n%d/%d passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)

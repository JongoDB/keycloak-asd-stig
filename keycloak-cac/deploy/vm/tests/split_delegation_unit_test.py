#!/usr/bin/env python3
"""Unit test of idp-admin.py's split delegation with a fake Keycloak - no live call, no root, runs anywhere.

What it proves:
  - the matrix in APP_DELEGATIONS: app-a's administrator writes the 6 app-a role groups and partner-reader, never
    partner-lead, partner-auditor, contractor or the bare tree root; the reader delegate writes partner-reader only; a
    group nobody lists (a role added later) is the user managers' alone;
  - from the state live today (one tree-wide permission holding manage-membership), sync_delegations writes every
    group's own write permission BEFORE the tree permission loses manage-membership, and adds a new delegation to
    the tree's aggregate only AFTER that - the migration never widens anyone and never removes a group app-a's
    administrator is listed for;
  - a converged realm gets no write (idempotent); a write permission of a group that left the tree is deleted;
  - it refuses to use a same-named policy that matches anything else, and never writes a permission with no
    resources (which Keycloak reads as ALL groups);
  - delegation-rollback returns app-a's administrator to exactly its earlier grant, removes and disables the reader
    delegate first, and is refused once a partner role group exists;
  - fgap/app_admin_fgap.py setup grants no write and refuses (before any write) an unsplit, partially split or
    drifted realm, or a new role group roles-setup has not covered;
  - ensure_delegate_client: only a listed delegation, https JWKS only, and a service account holding any role is refused;
  - the delegates are reserved client ids (add-client cannot register or adopt them, client-delete refuses them);
  - the per-application user manager (/roles/app-a-user-manager): writes every app-a role
    group but never the bare root, sees the app-a tree, and reaches nothing in another application's tree.
The behaviour against a real Keycloak is fgap/split_delegation_test.py.

  python3 split_delegation_unit_test.py [--admin ../host/idp-admin.py]
"""
import argparse, contextlib, copy, importlib.machinery, importlib.util, io, os, sys, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser(); ap.add_argument("--admin", default=os.path.join(HERE, "..", "host", "idp-admin.py"))
a = ap.parse_args()
os.environ.setdefault("IDP_ADMIN_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures", "idp-admin.test.json"))   # the lab/unit config; on a host the real one is used
ld = importlib.machinery.SourceFileLoader("idp_admin", a.admin)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
# the lab config's application shape (tests/fixtures/idp-admin.test.json)
APP_A_ROLES = tuple(g for g in M.APP_DELEGATIONS["app-a"]["app-a-admin"] if g != "partner-reader")
APP_BC_CLIENTS = tuple(c for c in M.APP_CLIENTS if c != "app-a" and c in M.APP_USER_MANAGERS)
APP_BC_ROLES = {"app-b": ("owner", "maintainer", "reviewer", "member"), "app-c": ("lead", "analyst", "auditor", "reader")}   # fixtures/clients

res = []
def check(n, ok, d=""):
    res.append(bool(ok)); print("%s  %-96s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

APP = "app-a"
APP_A = list(APP_A_ROLES)
REVIEW = ["partner-lead", "partner-auditor", "partner-reader", "contractor"]
BASE = "/clients/AP/authz/resource-server"

class Exit(Exception):
    pass

class FakeKC:
    """Just enough of the admin API for sync_delegations / ensure_delegate_client: groups, clients, and the
    admin-permissions resource server's group/client/aggregate policies and scope permissions."""
    def __init__(self, roles=APP_A, delegates=("app-a-admin",)):
        self.n, self.log = 0, []
        self.groups = {}
        for p in ["/roles/idp-user-manager", "/" + APP] + ["/roles/%s-user-manager" % x for x in M.APP_USER_MANAGERS] + ["/%s/%s" % (APP, r) for r in roles]:
            self.add_group(p)
        self.clients = {"admin-permissions": {"id": "AP", "clientId": "admin-permissions"},
                        "realm-management": {"id": "RMC", "clientId": "realm-management"}}
        self.admin_carriers = set()       # group ids that carry a realm-management role (directly or by composite)
        for c in delegates:
            self.add_client(c)
        self.policies, self.perms = {}, {}
        self.sa_roles = {}
    def nid(self, k):
        self.n += 1; return "%s-%04d" % (k, self.n)
    def add_group(self, path):
        g = {"id": self.nid("g"), "path": path, "name": path.rsplit("/", 1)[-1]}; self.groups[g["id"]] = g; return g
    def add_client(self, cid):
        self.clients[cid] = {"id": self.nid("c"), "clientId": cid, "attributes": {}}
    def tree(self, app=APP):
        return [g for g in self.groups.values() if g["path"] == "/" + app or g["path"].startswith("/%s/" % app)]
    def by_name(self, store, name):
        return [copy.deepcopy(x) for x in store.values() if name in x["name"]]       # Keycloak's name filter is "contains"
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        u = urllib.parse.urlparse(path); qs = dict(urllib.parse.parse_qsl(u.query)); p = u.path
        if method != "GET":
            self.log.append((method, p, copy.deepcopy(obj)))
        if p == "/clients" and method == "GET":
            c = self.clients.get(qs.get("clientId")); return [copy.deepcopy(c)] if c else []
        if p == "/clients" and method == "POST":
            self.clients[obj["clientId"]] = dict(copy.deepcopy(obj), id=self.nid("c")); return None
        if p.startswith("/group-by-path/"):
            path_ = "/" + urllib.parse.unquote(p[len("/group-by-path/"):])
            g = [x for x in self.groups.values() if x["path"] == path_]
            if g: return copy.deepcopy(g[0])
            if ok404: return None
            raise Exit("404 %s" % p)
        if p == "/client-scopes":
            return []
        for c in self.clients.values():
            cp = "/clients/%s" % c["id"]
            if p == cp and method == "GET": return copy.deepcopy(c)
            if p == cp and method == "PUT":
                # as Keycloak's RepresentationToModel.updateClientProperties: attributes present are SET, absent ones KEPT
                new = copy.deepcopy(obj); new["attributes"] = dict(c.get("attributes") or {}, **(obj.get("attributes") or {}))
                self.clients[c["clientId"]] = new; return None
            if p == cp + "/client-secret/rotated" and method == "DELETE":
                (c.get("attributes") or {}).pop("client.secret.rotated", None); return None
            if p == cp + "/default-client-scopes": return []
            if p == cp + "/client-secret" and method == "POST":
                c["secret_gen"] = c.get("secret_gen", 0) + 1
                c.setdefault("attributes", {})["client.secret.rotated"] = "old"       # Keycloak keeps the previous one
                return {"value": "x"}
            if p == cp + "/service-account-user": return {"id": "sa-" + c["id"]}
        if p.startswith("/groups/") and p.endswith("/role-mappings/clients/RMC/composite"):
            return [{"name": "manage-users"}] if p.split("/")[2] in self.admin_carriers else []
        if p.startswith("/users/sa-") and p.endswith("/role-mappings"):
            return self.sa_roles.get(p.split("/")[2][3:], {"realmMappings": [{"name": "default-roles-x"}]})
        if not p.startswith(BASE):
            raise AssertionError("unexpected call %s %s" % (method, path))
        r = p[len(BASE):]
        if r == "/policy" and method == "GET":
            return self.by_name(self.policies, qs.get("name", ""))
        if r == "/permission" and method == "GET":
            if "name" in qs: return self.by_name(self.perms, qs["name"])
            first, mx = int(qs.get("first", 0)), int(qs.get("max", 100))
            return [copy.deepcopy(x) for x in list(self.perms.values())[first:first + mx]]
        kinds = ("group", "client", "aggregate")
        for k in kinds:
            if r == "/policy/" + k and method == "POST":
                pid = self.nid("pol"); self.policies[pid] = dict(copy.deepcopy(obj), id=pid, type=k); return None
            if r.startswith("/policy/%s/" % k):
                pid = r.split("/")[3]
                if method == "GET": return copy.deepcopy(self.policies[pid])
                if method == "PUT": self.policies[pid] = dict(copy.deepcopy(obj), id=pid, type=k); return None
        if r.startswith("/policy/") and r.endswith("/associatedPolicies"):
            x = r.split("/")[2]
            ids = (self.policies.get(x) or self.perms.get(x))["policies"]
            return [copy.deepcopy(self.policies[i]) for i in ids]
        if r == "/permission/scope" and method == "POST":
            pid = self.nid("perm"); self.perms[pid] = dict(copy.deepcopy(obj), id=pid); return None
        if r.startswith("/permission/scope/") and method == "PUT":
            pid = r.split("/")[3]; self.perms[pid] = dict(copy.deepcopy(obj), id=pid); return None
        if r.startswith("/permission/") and r.endswith("/resources"):
            return [{"name": g} for g in self.perms[r.split("/")[2]]["resources"]]
        if r.startswith("/permission/") and r.endswith("/scopes"):
            return [{"name": s} for s in self.perms[r.split("/")[2]]["scopes"]]
        if r.startswith("/policy/") and r.count("/") == 2 and method == "DELETE":
            del self.policies[r.split("/")[2]]; return None
        if r.startswith("/permission/") and method == "DELETE":
            del self.perms[r.split("/")[2]]; return None
        raise AssertionError("unexpected call %s %s" % (method, path))
    # what the realm grants, computed from the fake's permissions as Keycloak does: unanimous across permissions
    def policy_grants(self, pid, who):
        p = self.policies[pid]
        if p["type"] == "group": return self.groups[p["groups"][0]["id"]]["path"] == "/roles/" + who
        if p["type"] == "client": return [c for c in self.clients.values() if c["id"] in p["clients"]][0]["clientId"] == who
        return any(self.policy_grants(x, who) for x in p["policies"])        # AFFIRMATIVE aggregate
    def may(self, who, gid, scope):
        ps = [x for x in self.perms.values() if gid in x["resources"] and scope in x["scopes"]]
        return bool(ps) and all(all(self.policy_grants(pol, who) for pol in x["policies"]) for x in ps)

def legacy(kc):
    """The state live today: ONE tree-wide permission with manage-membership, aggregate of the user managers and
    app-a's administrator (written by the earlier roles-setup and fgap/app_admin_fgap.py setup)."""
    um = M.ensure_um_policy(kc, BASE); fa = M.ensure_delegate_policy(kc, BASE, "app-a-admin")
    agg = M.ensure_aggregate(kc, BASE, "delegates of /" + APP, [um, fa])
    M.ensure_group_permission(kc, BASE, "delegated: /" + APP, [g["id"] for g in kc.tree()], M.SCOPES_MEMBERS, agg)
    kc.log = []

def sync(kc):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        M.sync_delegations(kc, kc.tree())
    return out.getvalue()

def gpath(kc, path):
    return [g for g in kc.groups.values() if g["path"] == path][0]["id"]

def raises(fn, exc=(RuntimeError, SystemExit, Exit)):
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            fn()
    except exc as e:
        return str(e) or True
    return False

# 1. the matrix as declared
fa_set, rd_set = set(M.APP_DELEGATIONS[APP]["app-a-admin"]), set(M.APP_DELEGATIONS[APP]["app-a-reader-delegate"])
check("app-a's administrator: exactly the 6 app-a roles + partner-reader", fa_set == set(APP_A) | {"partner-reader"}, sorted(fa_set))
check("... never partner-lead, partner-auditor, contractor or the tree root", not fa_set & {"partner-lead", "partner-auditor", "contractor", ""})
import json
cf = [r for r in json.load(open(os.path.join(HERE, "fixtures", "clients", "app-a.json")))["roles"] if r not in REVIEW]
check("the config's app-a roles equal the app-a roles in fixtures/clients/app-a.json", sorted(cf) == sorted(APP_A), "%s" % sorted(set(cf) ^ set(APP_A)))
check("the reader delegate: partner-reader and nothing else", rd_set == {"partner-reader"}, sorted(rd_set))
check("partner-lead / partner-auditor / contractor: no delegate writes them", all(not M.membership_writers(APP, g) for g in ("partner-lead", "partner-auditor", "contractor")))
check("a role added later (unlisted) has no delegate writer: fails closed", M.membership_writers(APP, "partner-superlead") == [])
check("other applications' trees have no delegate writer", M.membership_writers("app-b", "owner") == [])
check("the delegate scopes on the tree never include a write", "manage-membership" not in M.TREE_SCOPES and "manage-members" not in M.TREE_SCOPES, M.TREE_SCOPES)
check("the user managers hold exactly view, view-members, manage-membership, manage-membership-of-members",
      sorted(M.SCOPES_MEMBERS) == sorted(["view", "view-members", "manage-membership", "manage-membership-of-members"]))

# 2. migration from the live state, app-a roles only (the live order: the split lands before the partner roles)
kc = FakeKC(); legacy(kc)
ou, adm_g, root = gpath(kc, "/%s/viewer" % APP), gpath(kc, "/%s/administrator" % APP), gpath(kc, "/" + APP)
check("[legacy] app-a's administrator writes the bare tree root (the earlier, wider grant)", kc.may("app-a-admin", root, "manage-membership"))
# replay the writes one at a time and evaluate the grants after each
snap = FakeKC(); legacy(snap)
kc.log = []; sync(kc)
writes = list(kc.log)
check("the migration writes something", len(writes) > 0, "%d writes" % len(writes))
step = snap; window = []
for (m, p, o) in writes:
    step.api(m, p, o)
    window.append({"fa_app": all(step.may("app-a-admin", gpath(step, "/%s/%s" % (APP, r)), "manage-membership") for r in APP_A),
                   "fa_view": step.may("app-a-admin", ou, "view-members"),
                   "rd_any": any(step.may("app-a-reader-delegate", g, "manage-membership") for g in step.groups)})
check("[migration] app-a's administrator keeps every app-a role group after each of %d writes" % len(window), all(w["fa_app"] for w in window))
check("[migration] ... and keeps seeing the tree throughout", all(w["fa_view"] for w in window))
tree_drop = [i for i, (m, p, o) in enumerate(writes) if m == "PUT" and o and o.get("name") == "delegated: /" + APP]
last_group_perm = max(i for i, (m, p, o) in enumerate(writes) if o and str(o.get("name", "")).startswith("membership: /" + APP))
check("[migration] every group's write permission is written BEFORE the tree permission loses manage-membership",
      tree_drop and tree_drop[0] > last_group_perm, "group perms up to write %s, tree drop at %s" % (last_group_perm, tree_drop))
k_o = FakeKC(roles=APP_A + REVIEW); legacy(k_o); sync(k_o)
order = [o["name"] for (m, p, o) in k_o.log if m == "POST" and o and str(o.get("name", "")).startswith("membership: /" + APP)]
unlisted = [n for n in order if not M.membership_writers(APP, n[len("membership: /" + APP) + 1:])]
check("[order] the write permissions of unlisted groups (root, LEAD, ASSESSOR, contractor) are written before any listed group's",
      unlisted and order[:len(unlisted)] == unlisted and len(unlisted) == 4, str(order[:5]))
check("[after] the tree permission holds view, view-members, manage-membership-of-members only",
      sorted([x for x in kc.perms.values() if x["name"] == "delegated: /" + APP][0]["scopes"]) == sorted(M.TREE_SCOPES))
check("[after] app-a's administrator no longer writes the bare tree root (it carries no role; nobody is in it live)",
      not kc.may("app-a-admin", root, "manage-membership"))
check("[after] the user managers write every group of the tree", all(kc.may("idp-user-manager", g["id"], "manage-membership") for g in kc.tree()))
check("[after] exactly one write permission per group", sorted(x["resources"][0] for x in kc.perms.values() if x["name"].startswith("membership: "))
      == sorted(g["id"] for g in kc.tree()))
kc.log = []; sync(kc)
check("a converged realm gets no write (idempotent)", not kc.log, str(kc.log[:3]))

# 3. the reader delegate appears (reader-delegate-setup): its policy joins the tree aggregate only after the tree
#    permission lost its write; and with no partner-reader group yet it writes nothing
kc.add_client("app-a-reader-delegate"); kc.log = []; sync(kc)
check("[reader delegate, no partner roles yet] it writes no group", not any(kc.may("app-a-reader-delegate", g, "manage-membership") for g in kc.groups))
check("[reader delegate] ... but sees the tree's members", kc.may("app-a-reader-delegate", ou, "view-members"))
# 3b. the order with a tree permission that STILL has manage-membership (a realm where the reader delegate exists
#     before the split ever ran): the aggregate gains the delegate only after the scope is dropped
kc2 = FakeKC(delegates=("app-a-admin", "app-a-reader-delegate")); legacy(kc2); sync(kc2)
agg_put = [i for i, (m, p, o) in enumerate(kc2.log) if o and o.get("name") == "delegates of /" + APP and m in ("PUT", "POST")]
drop = [i for i, (m, p, o) in enumerate(kc2.log) if m == "PUT" and o and o.get("name") == "delegated: /" + APP]
rd_pol = M.delegate_policy_name("app-a-reader-delegate")
grows = [i for i in agg_put if any(kc2.policies[x]["name"] == rd_pol for x in kc2.log[i][2]["policies"])]
check("[order] the reader delegate joins `delegates of /app-a` only after the tree permission lost its write",
      grows and drop and min(grows) > drop[0], "joins at %s, drop at %s" % (grows, drop))

# 4. the partner roles are added (the client-file change that waits for the operator), then roles-setup
for r in REVIEW:
    kc.add_group("/%s/%s" % (APP, r))
before = {r: kc.may("app-a-admin", gpath(kc, "/%s/%s" % (APP, r)), "manage-membership") for r in REVIEW}
check("[partner groups just created] no delegate may write them before roles-setup runs", not any(before.values()), str(before))
sync(kc)
for who, allowed in (("app-a-admin", set(APP_A) | {"partner-reader"}), ("app-a-reader-delegate", {"partner-reader"}),
                     ("idp-user-manager", set(APP_A) | set(REVIEW) | {""})):
    got = {g["path"][len(APP) + 2:] for g in kc.tree() if kc.may(who, g["id"], "manage-membership")}
    check("[matrix] %-31s writes exactly %s" % (who, "its listed groups" if who != "idp-user-manager" else "every group"), got == allowed,
          "extra %s, missing %s" % (sorted(got - allowed), sorted(allowed - got)))
    check("[matrix] %-31s sees every group's members" % who, all(kc.may(who, g["id"], "view-members") and kc.may(who, g["id"], "manage-membership-of-members") for g in kc.tree()))

MGR = "%s-user-manager" % APP
got = {g["path"][len(APP) + 2:] for g in kc.tree() if kc.may(MGR, g["id"], "manage-membership")}
want = set(APP_A) | set(REVIEW)
check("[app manager] %s writes every app-a role group, partner ones included" % MGR, want <= got, "missing %s" % sorted(want - got))
check("[app manager] ... but never the bare tree root", "" not in got)
check("[app manager] ... and sees every group's members", all(kc.may(MGR, g["id"], "view-members") and kc.may(MGR, g["id"], "manage-membership-of-members") for g in kc.tree()))
check("[app manager] the role carries exactly query-users and query-groups", sorted(M.ROLE_GROUPS[MGR]) == ["query-groups", "query-users"], M.ROLE_GROUPS[MGR])
check("[app manager] app-a's administrator holders, app-b's owner and app-c's lead holders (APP_USER_MANAGERS)",
      M.APP_USER_MANAGERS == {APP: "administrator", "app-b": "owner", "app-c": "lead"})
check("[app manager] every application whose manager role is `admin` is configured with a manager",
      set(APP_BC_CLIENTS) <= set(M.APP_CLIENTS) and all(c in M.APP_USER_MANAGERS for c in APP_BC_CLIENTS))
k6 = FakeKC(roles=APP_A + REVIEW)
for r in APP_BC_ROLES["app-b"]:
    k6.add_group("/app-b/%s" % r)
k6.add_group("/app-b")
with contextlib.redirect_stdout(io.StringIO()):
    M.sync_delegations(k6, k6.tree() + k6.tree("app-b"))
btree = k6.tree("app-b")
check("[app manager] reaches nothing in another application's tree (app-b: no write, no sight)",
      btree and not any(k6.may(MGR, g["id"], s_) for g in btree for s_ in ("manage-membership", "view-members", "view")))
check("[app manager] ... while the all-applications user manager still writes and sees that tree",
      all(k6.may("idp-user-manager", g["id"], "manage-membership") and k6.may("idp-user-manager", g["id"], "view-members") for g in btree))
CMGR = "app-b-user-manager"
cgot = {g["path"][len("/app-b/"):] for g in btree if k6.may(CMGR, g["id"], "manage-membership")}
check("[app manager] %s writes every app-b role group (owner included), never its root" % CMGR,
      cgot == set(APP_BC_ROLES["app-b"]), sorted(cgot))
lg = k6.tree()
check("[app manager] ... and reaches nothing in app-a's tree", lg and not any(k6.may(CMGR, g["id"], s_) for g in lg
                                                                            for s_ in ("manage-membership", "view-members", "view")))
k7 = FakeKC(); legacy(k7); sync(k7)
agg_w = [i for i, (m, p, o) in enumerate(k7.log) if o and o.get("name") == "delegates of /" + APP and m in ("PUT", "POST")]
drop7 = [i for i, (m, p, o) in enumerate(k7.log) if m == "PUT" and o and o.get("name") == "delegated: /" + APP]
mpol = M.app_manager_policy_name(APP)
grows7 = [i for i in agg_w if any(k7.policies[x]["name"] == mpol for x in k7.log[i][2]["policies"])]
check("[order] the app manager joins `delegates of /app-a` only after the tree permission lost its write",
      grows7 and drop7 and min(grows7) > drop7[0], "joins at %s, drop at %s" % (grows7, drop7))
k8 = FakeKC(); legacy(k8)
del k8.groups[gpath(k8, "/roles/%s" % MGR)]
check("refuses to run without /roles/app-a-user-manager (run roles-setup)", raises(lambda: sync(k8)))

# 5. a group leaves the tree: its write permission is deleted
gone = gpath(kc, "/%s/partner-auditor" % APP); del kc.groups[gone]
for x in kc.perms.values():
    x["resources"] = [r for r in x["resources"] if r != gone]
sync(kc)
check("a group that left the tree loses its write permission", not [x for x in kc.perms.values() if x["name"] == "membership: /%s/partner-auditor" % APP])
check("... and no permission is left with empty resources (= ALL groups)", all(x["resources"] for x in kc.perms.values()))

# 6. refusals
def raises(fn, exc=(RuntimeError, SystemExit, Exit)):
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            fn()
    except exc as e:
        return str(e) or True
    return False
k3 = FakeKC(); legacy(k3)
umpid = [x for x in k3.policies.values() if x["name"] == M.UM_POLICY][0]["id"]
k3.policies[umpid]["groups"][0]["extendChildren"] = True
check("refuses a user-manager policy that also matches child groups", raises(lambda: sync(k3)))
k4 = FakeKC(); legacy(k4)
fapid = [x for x in k4.policies.values() if x["name"] == M.delegate_policy_name("app-a-admin")][0]["id"]
k4.policies[fapid]["clients"] = [k4.clients["admin-permissions"]["id"]]
check("refuses a delegate policy that matches another client", raises(lambda: sync(k4)))
check("never writes a permission with no resources (= ALL groups)", raises(lambda: M.ensure_group_permission(FakeKC(), BASE, "x", [], M.WRITE_SCOPES, "p")))
k5 = FakeKC(delegates=())
out = sync(k5)
check("a delegate client that does not exist is granted nothing (and said so)", "app-a-admin does not exist" in out
      and not any(k5.may("app-a-admin", g["id"], "manage-membership") for g in k5.tree()))
check("ensure_delegate_client refuses a client id that is not a listed delegation", raises(lambda: M.ensure_delegate_client(FakeKC(), "app-a", "x")))
for bad_ in ("http://a.example/jwks", "https://10.0.0.1/jwks", "https://localhost/jwks", "https://a.example/jwks?k=1"):
    check("the JWKS URL check refuses %s" % bad_, raises(lambda: M.check_jwks_url(bad_)))
# the JWKS pre-check (delegate-client-setup, before anything changes)
EC = {"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
TP = M.jwk_thumbprint(EC)
check("RFC 7638 thumbprint of the RFC 7638 section 3.1-style EC example is stable and unpadded", TP and "=" not in TP and len(TP) == 43, TP)
okj = lambda *ks: (lambda u: (200, json.dumps({"keys": list(ks)})))
check("JWKS pre-check: one EC P-256 key, kid = thumbprint, alg ES256, use sig -> accepted (returns the thumbprint)",
      M.jwks_precheck("https://x", "ES256", None, okj(dict(EC, kid=TP, alg="ES256", use="sig"))) == TP)
check("... and with --expect-thumbprint equal to it", M.jwks_precheck("https://x", "ES256", TP, okj(dict(EC, kid=TP))) == TP)
for name_, fetch_, exp_ in (("a 404 (not published yet)", lambda u: (404, ""), None),
                            ("two keys", okj(dict(EC, kid=TP), dict(EC, kid=TP)), None),
                            ("no keys", okj(), None),
                            ("a private member d (compromised key)", okj(dict(EC, kid=TP, d="AAAA")), None),
                            ("an RSA key when ES256 is asked", okj({"kty": "RSA", "n": "AQAB" * 100, "e": "AQAB", "kid": "x"}), None),
                            ("a P-384 key", okj(dict(EC, crv="P-384", kid=TP)), None),
                            ("alg RS256 on the EC key", okj(dict(EC, kid=TP, alg="RS256")), None),
                            ("use enc", okj(dict(EC, kid=TP, use="enc")), None),
                            ("kid that is not the thumbprint", okj(dict(EC, kid="key-1")), None),
                            ("a different thumbprint than expected", okj(dict(EC, kid=TP)), "hoPTXrlivKWoAW2vjuaNdqwFa612X04ZpmaylGRlGfc"),
                            ("not JSON", lambda u: (200, "<html>"), None)):
    check("JWKS pre-check refuses %s" % name_, raises(lambda: M.jwks_precheck("https://x", "ES256", exp_, fetch_)))
# the pre-check's fetch: no redirect, no private peer, no rebinding, bounded size
pub = lambda h, p, **k: [(2, 1, 6, "", ("93.184.216.34", p))]
priv = lambda h, p, **k: [(2, 1, 6, "", ("10.0.0.5", p))]
mixed = lambda h, p, **k: [(2, 1, 6, "", ("93.184.216.34", p)), (2, 1, 6, "", ("127.0.0.1", p))]
seen_ip = []
def getter_ok(ip, port, host, path, limit):
    seen_ip.append((ip, host)); return 200, b'{"keys":[]}'
check("fetch_public: a public name is fetched FROM the validated address, with the name for SNI/Host",
      M.fetch_public("https://app-a.example/jwks", pub, getter_ok)[0] == 200 and seen_ip == [("93.184.216.34", "app-a.example")], seen_ip)
check("fetch_public refuses a redirect (3xx)", raises(lambda: M.fetch_public("https://app-a.example/jwks", pub,
      lambda *x: (302, b"")), (ValueError,)))
check("fetch_public refuses a name that resolves to a private address (no connection made)",
      raises(lambda: M.fetch_public("https://app-a.example/jwks", priv, lambda *x: (_ for _ in ()).throw(AssertionError("connected"))), (ValueError,)))
check("fetch_public refuses a name with ANY non-public address (127.0.0.1 beside a public one)",
      raises(lambda: M.fetch_public("https://app-a.example/jwks", mixed, getter_ok), (ValueError,)))
check("fetch_public refuses http and userinfo URLs", raises(lambda: M.fetch_public("http://app-a.example/jwks", pub, getter_ok), (ValueError,))
      and raises(lambda: M.fetch_public("https://u:p@app-a.example/jwks", pub, getter_ok), (ValueError,)))
nat64 = lambda h, p, **k: [(10, 1, 6, "", ("64:ff9b::a00:5", p, 0, 0))]
check("fetch_public refuses a NAT64 address (64:ff9b::/96: an IPv4 address in disguise)",
      raises(lambda: M.fetch_public("https://app-a.example/jwks", nat64, getter_ok), (ValueError,)) and not M._public_ip("64:ff9b::a00:5")
      and not M._public_ip("64:ff9b:1::1") and M._public_ip("2606:4700::1"))
check("fetch_public refuses more than 64 KB", raises(lambda: M.fetch_public("https://app-a.example/jwks", pub,
      lambda ip, port, host, path, limit: (200, b"x" * (limit + 1))), (ValueError,)))
# the test twin's secret: never through a planted link, never with an inherited mode or owner
import tempfile as _tf, stat as _st
me = os.getuid()
d0 = _tf.mkdtemp()                                   # 0700, ours
M.write_secret_private(os.path.join(d0, "s"), "v1", owner=me)
s0 = os.lstat(os.path.join(d0, "s"))
check("write_secret_private: a fresh regular file, 0400, the owner's, holding the value",
      _st.S_ISREG(s0.st_mode) and s0.st_mode & 0o777 == 0o400 and s0.st_uid == me and open(os.path.join(d0, "s")).read() == "v1")
M.write_secret_private(os.path.join(d0, "s"), "v2", owner=me)
check("... rewriting it replaces the file (still 0400)", open(os.path.join(d0, "s")).read() == "v2"
      and os.lstat(os.path.join(d0, "s")).st_mode & 0o777 == 0o400)
victim = os.path.join(_tf.mkdtemp(), "victim"); open(victim, "w").write("untouched"); os.chmod(victim, 0o644)
os.symlink(victim, os.path.join(d0, "link"))
check("write_secret_private refuses a pre-existing SYMLINK at the target, and writes nothing through it",
      raises(lambda: M.write_secret_private(os.path.join(d0, "link"), "secret", owner=me), (ValueError,))
      and open(victim).read() == "untouched" and os.stat(victim).st_mode & 0o777 == 0o644)
d1 = _tf.mkdtemp(); os.chmod(d1, 0o777)
check("write_secret_private refuses a group- or world-writable directory", raises(lambda: M.write_secret_private(os.path.join(d1, "s"), "x", owner=me), (ValueError,)))
check("write_secret_private refuses a directory owned by someone else", raises(lambda: M.write_secret_private(os.path.join(d0, "t"), "x", owner=me + 1), (ValueError,)))
os.symlink(d0, os.path.join(d1, "dirlink")); os.chmod(d1, 0o700)
check("write_secret_private refuses a directory that is a symlink", raises(lambda: M.write_secret_private(os.path.join(d1, "dirlink", "s"), "x", owner=me), (ValueError,)))
check("... and leaves no temporary file behind", not [f for f in os.listdir(d0) if f.endswith(".tmp")])
# delegate-test-twin's command line, exactly as the operating guide writes it (options after the positionals, then --)
cli = M.parse_cli(["delegate-test-twin", "all", "run", "--secret-dir", "/root/idp-fgap/twins", "--", "sh", "-c", "echo $L --x y"])
check("CLI: `delegate-test-twin all run --secret-dir D -- sh -c ...` (the documented form) parses: dir, action, delegate, command",
      cli.fn is M.cmd_delegate_test_twin and cli.secret_dir == "/root/idp-fgap/twins" and cli.action == "run" and cli.client_id == "all"
      and cli.run_cmd == ["sh", "-c", "echo $L --x y"], vars(cli))
cli2 = M.parse_cli(["delegate-test-twin", "--secret-dir", "/d", "all", "run", "--", "true"])
check("CLI: ... and the other order still works", cli2.secret_dir == "/d" and cli2.run_cmd == ["true"])
cli3 = M.parse_cli(["delegate-test-twin", "all", "run", "--secret-dir", "/d", "--", "x", "--secret-dir", "/evil", "--"])
check("CLI: everything after the FIRST -- belongs to the command (its own options never reach idp-admin.py)",
      cli3.secret_dir == "/d" and cli3.run_cmd == ["x", "--secret-dir", "/evil", "--"], vars(cli3))
check("CLI: other commands unaffected (guard --fix)", M.parse_cli(["guard", "--fix"]).fix is True)
import tempfile
M.DELEGATE_STATE = os.path.join(tempfile.mkdtemp(), "delegate-clients.json")
# an UNRECORDED delegate is expected on client-secret with no key at all (fail closed)
k9 = FakeKC(delegates=("app-a-admin",))
k9.clients["app-a-admin"]["clientAuthenticatorType"] = "client-secret"
check("unrecorded delegate on client-secret, no key: no drift", not M.delegate_auth_report(k9), M.delegate_auth_report(k9))
k9.clients["app-a-admin"]["clientAuthenticatorType"] = "client-jwt"
check("unrecorded delegate flipped to client-jwt (no record): STIG-DELEGATE-CLIENT-DRIFT",
      any("app-a-admin authenticates with client-jwt, recorded client-secret" in l for l in M.delegate_auth_report(k9)), M.delegate_auth_report(k9))
k9.clients["app-a-admin"]["clientAuthenticatorType"] = "client-secret"
k9.clients["app-a-admin"]["attributes"] = {"use.jwks.string": "true", "jwks.string": "{\"keys\":[]}"}
check("unrecorded delegate on client-secret but carrying a JWKS string: drift",
      any("carries" in l and "jwks.string" in l for l in M.delegate_auth_report(k9)), M.delegate_auth_report(k9))
k9.clients["app-a-admin"]["clientAuthenticatorType"] = "client-jwt"
k9.clients["app-a-admin"]["attributes"].update({"use.jwks.url": "true", "jwks.url": "https://evil.example/jwks"})
with contextlib.redirect_stdout(io.StringIO()):
    M.ensure_delegate_client(k9, "app-a-admin", "x")
a9 = k9.clients["app-a-admin"]
check("ensure_delegate_client puts an unrecorded delegate back on client-secret and strips every JWKS attribute",
      a9["clientAuthenticatorType"] == "client-secret" and all((a9.get("attributes") or {}).get(k) in (None, "", "false") for k in M.JWKS_ATTRS)
      and not M.delegate_auth_report(k9), (a9["clientAuthenticatorType"], a9.get("attributes")))
k6 = FakeKC(delegates=())
with contextlib.redirect_stdout(io.StringIO()):
    c = M.ensure_delegate_client(k6, "app-a-reader-delegate", "x")
check("a new delegate is created with client-secret", k6.clients["app-a-reader-delegate"]["clientAuthenticatorType"] == "client-secret")
with contextlib.redirect_stdout(io.StringIO()):
    M.converge_delegate_auth(k6, "app-a-reader-delegate", "client-jwt", "https://app-a.example/delegate-jwks", "ES256")
rep = k6.clients["app-a-reader-delegate"]
check("the reader delegate: service account only, no browser/direct/implicit flow, no full scope",
      rep["serviceAccountsEnabled"] and not rep["standardFlowEnabled"] and not rep["directAccessGrantsEnabled"]
      and not rep["implicitFlowEnabled"] and not rep["fullScopeAllowed"] and not rep["publicClient"])
check("... converge_delegate_auth: client-jwt with its own JWKS and the chosen alg (ES256)", rep["clientAuthenticatorType"] == "client-jwt"
      and rep["attributes"].get("jwks.url") == "https://app-a.example/delegate-jwks"
      and rep["attributes"].get("token.endpoint.auth.signing.alg") == "ES256")
check("... the old secret is regenerated (no earlier secret authenticates)", k6.clients["app-a-reader-delegate"].get("secret_gen") == 1)
check("... the expected authentication is recorded", json.load(open(M.DELEGATE_STATE))["app-a-reader-delegate"]["alg"] == "ES256")
check("... and matches its record (no drift)", not M.delegate_auth_report(k6), M.delegate_auth_report(k6))
k6.log = []
with contextlib.redirect_stdout(io.StringIO()):
    M.ensure_delegate_client(k6, "app-a-reader-delegate", "x")
check("... a re-run of the setup makes no write and leaves client-jwt in place", not k6.log
      and k6.clients["app-a-reader-delegate"]["clientAuthenticatorType"] == "client-jwt", str(k6.log))
k6.clients["app-a-reader-delegate"]["clientAuthenticatorType"] = "client-secret"
check("... a later flip back to client-secret is drift (STIG-DELEGATE-CLIENT-DRIFT)",
      any("authenticates with client-secret, recorded client-jwt" in l for l in M.delegate_auth_report(k6)), M.delegate_auth_report(k6))
k6.clients["app-a-reader-delegate"]["clientAuthenticatorType"] = "client-jwt"
check("... the rotated (previous) secret is deleted after the regeneration", "client.secret.rotated" not in
      (k6.clients["app-a-reader-delegate"].get("attributes") or {}))
k6.clients["app-a-reader-delegate"]["attributes"]["client.secret.rotated"] = "kept"
check("... a rotated secret left on a delegate is drift", any("rotated" in l for l in M.delegate_auth_report(k6)))
k6.clients["app-a-reader-delegate"]["attributes"].pop("client.secret.rotated")
with contextlib.redirect_stdout(io.StringIO()):
    M.converge_delegate_auth(k6, "app-a-reader-delegate", "client-secret")
a6 = k6.clients["app-a-reader-delegate"]["attributes"]
check("ROLLBACK to client-secret with a Keycloak-like merge: every JWKS attribute cleared (sent empty), no drift",
      k6.clients["app-a-reader-delegate"]["clientAuthenticatorType"] == "client-secret"
      and all(a6.get(k) in (None, "", "false") for k in M.JWKS_ATTRS + ("token.endpoint.auth.signing.alg",))
      and not M.delegate_auth_report(k6), {k: a6.get(k) for k in M.JWKS_ATTRS})
with contextlib.redirect_stdout(io.StringIO()):
    M.converge_delegate_auth(k6, "app-a-reader-delegate", "client-jwt", "https://app-a.example/delegate-jwks", "ES256")
check("converge refuses a client that is not a delegation, and an alg outside ES256/RS256",
      raises(lambda: M.converge_delegate_auth(k6, "app-a", "client-jwt", "https://a.example/j", "ES256"))
      and raises(lambda: M.converge_delegate_auth(k6, "app-a-reader-delegate", "client-jwt", "https://a.example/j", "HS256")))
k6.sa_roles[c["id"]] = {"realmMappings": [], "clientMappings": {"realm-management": {"mappings": [{"name": "query-users"}]}}}
check("... and it is refused if its service account holds any role (e.g. query-users: realm-wide sight, J1)",
      raises(lambda: M.ensure_delegate_client(k6, "app-a-reader-delegate", "x")))

# 7. the rollback of the live apply: back to one tree-wide permission, never wider than before
k7 = FakeKC(delegates=("app-a-admin", "app-a-reader-delegate")); legacy(k7)
before = {g["id"]: k7.may("app-a-admin", g["id"], "manage-membership") for g in k7.tree()}
sync(k7); k7.log = []
with contextlib.redirect_stdout(io.StringIO()):
    M.rollback_delegations(k7, k7.tree())
after = {g["id"]: k7.may("app-a-admin", g["id"], "manage-membership") for g in k7.tree()}
check("[rollback] app-a's administrator is back to exactly its earlier grant", before == after)
check("[rollback] no per-group permission or writers aggregate is left",
      not [x for x in k7.perms.values() if x["name"].startswith("membership: ")] and not [x for x in k7.policies.values() if x["name"].startswith("writers of ")])
check("[rollback] the reader delegate writes and sees nothing", not any(k7.may("app-a-reader-delegate", g["id"], sc) for g in k7.tree()
      for sc in M.SCOPES_MEMBERS))
check("[rollback] ... and its client is disabled", k7.clients["app-a-reader-delegate"].get("enabled") is False)
first_scope = [i for i, (m, p, o) in enumerate(k7.log) if o and o.get("name") == "delegated: /" + APP]
first_agg = [i for i, (m, p, o) in enumerate(k7.log) if o and o.get("name") == "delegates of /" + APP]
first_del = [i for i, (m, p, o) in enumerate(k7.log) if m == "DELETE"]
check("[rollback] order: the reader delegate leaves the aggregate, then the tree regains its write, then the per-group ones go",
      first_agg and first_scope and first_del and first_agg[0] < first_scope[0] < first_del[0], "%s %s %s" % (first_agg[:1], first_scope[:1], first_del[:1]))
k8 = FakeKC(roles=APP_A + REVIEW); legacy(k8); sync(k8)
check("[rollback] REFUSED once a partner role group exists (the earlier shape is the escalation)", raises(lambda: M.rollback_delegations(k8, k8.tree())))
sync(k7)
k7.log = []; sync(k7)
check("[rollback] re-applying converges again", not k7.log, str(k7.log[:2]))

# 8. fgap/app_admin_fgap.py setup: never grants a write, and fails closed on any state that is not a full, consistent
#    split (review HIGH on the per-group split: it used to re-add the tree-wide write when a per-group permission was missing)
src = open(os.path.join(HERE, "..", "fgap", "app_admin_fgap.py")).read()
F = {"__name__": "app_admin_fgap_unit"}
exec(compile(src[:src.index("\nap = argparse.ArgumentParser")], "app_admin_fgap.py", "exec"), F)
check("fgap setup's tree scopes equal idp-admin's TREE_SCOPES (sight only)", F["TREE_SCOPES"] == M.TREE_SCOPES, F["TREE_SCOPES"])
setup_src = src[src.index("def setup(a):"):src.index("def test(a):")]
check("fgap setup grants no manage-membership anywhere (only split_problems names it, to detect it)",
      '"manage-membership"' not in setup_src and "SCOPES_MEMBERS" not in setup_src)
check("fgap setup checks the split BEFORE writing the tree aggregate or permission",
      setup_src.index("split_problems(") < setup_src.index('base + "/policy/aggregate"') and setup_src.index("split_problems(") < setup_src.index('base + "/permission/scope"'))
class FgapKC:
    def __init__(self, fake): self.f = fake
    def api(self, method, path, obj=None, expect=(200, 201, 204)):
        return 200, self.f.api(method, "/clients/AP/authz/resource-server" + path[len(BASE):] if path.startswith(BASE) else path, obj)
LISTED = M.APP_DELEGATIONS[APP]["app-a-admin"]
def problems(fake):
    root = [g for g in fake.groups.values() if g["path"] == "/" + APP][0]
    subs = {g["name"]: g for g in fake.tree() if g["path"] != "/" + APP}
    fapid = M.ensure_delegate_policy(fake, BASE, "app-a-admin")
    return F["split_problems"](FgapKC(fake), BASE, APP, "app-a-admin", fapid, root, subs, "delegated: /" + APP, LISTED)
f1 = FakeKC(roles=APP_A + REVIEW); legacy(f1)
pr = problems(f1)
check("[fgap] the earlier (unsplit) realm is refused: tree-wide write named, every group uncovered",
      any("TREE-WIDE" in x for x in pr) and sum("no per-group write permission" in x for x in pr) == len(f1.tree()), "%d problems" % len(pr))
f2 = FakeKC(roles=APP_A + REVIEW); legacy(f2); sync(f2)
check("[fgap] a full, consistent split passes", problems(f2) == [], str(problems(f2)))
adm_g = [x for x in f2.perms.values() if x["name"] == "membership: /%s/administrator" % APP][0]["id"]; del f2.perms[adm_g]
pr = problems(f2)
check("[fgap] PARTIAL split (one group's write permission missing) is refused, naming the group",
      len(pr) == 1 and "administrator" in pr[0], str(pr))
sync(f2)
w = [x for x in f2.policies.values() if x["name"] == "writers of /%s/partner-lead" % APP][0]
w["policies"] = w["policies"] + [M.ensure_delegate_policy(f2, BASE, "app-a-admin")]
pr = problems(f2)
check("[fgap] DRIFT (app-a's administrator among partner-lead's writers) is refused", len(pr) == 1 and "partner-lead" in pr[0] and "may NOT" in pr[0], str(pr))
sync(f2)
check("[fgap] roles-setup removes that drift", problems(f2) == [], str(problems(f2)))
f2.add_group("/%s/partner-superlead" % APP)
pr = problems(f2)
check("[fgap] a NEW role group nobody lists is refused until roles-setup covers it", len(pr) == 1 and "partner-superlead" in pr[0], str(pr))
sync(f2)
check("[fgap] ... and after roles-setup it passes, with no write for app-a's administrator on it",
      problems(f2) == [] and not f2.may("app-a-admin", [g["id"] for g in f2.tree() if g["path"].endswith("/partner-superlead")][0], "manage-membership"))
t = [x for x in f2.perms.values() if x["name"] == "delegated: /" + APP][0]; t["scopes"] = t["scopes"] + ["manage-membership"]
check("[fgap] a tree permission that regained manage-membership is refused", any("TREE-WIDE" in x for x in problems(f2)))

# 9. the delegates are reserved client ids
for cid in ("app-a-admin", "app-a-reader-delegate"):
    check("%s is reserved for add-client and refused by client-delete" % cid, cid in M.UNMANAGED_CLIENTS and cid in M.RESERVED_CLIENTS
          and cid in M.DELEGATE_CLIENTS)

# 7. retiring an application, including an INTERRUPTED --retire-app
class RetireKC(FakeKC):
    """FakeKC plus the group, member, role-mapping calls retire_apps makes."""
    def __init__(self):
        super().__init__()
        self.add_group("/roles")
        for c in ("app-b", "app-c"):
            self.add_group("/" + c)
            for r in APP_BC_ROLES[c]:
                self.add_group("/%s/%s" % (c, r))
        self.clients["realm-management"] = {"id": "RM", "clientId": "realm-management"}
        self.members, self.rm = {}, {}
        for g in self.groups.values():
            if g["path"].startswith("/roles/") and g["path"] != "/roles":
                self.rm[g["id"]] = [{"id": "r-qu", "name": "query-users"}, {"id": "r-qg", "name": "query-groups"}]
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        u = urllib.parse.urlparse(path); p = u.path; qs = dict(urllib.parse.parse_qsl(u.query))
        parts = p.strip("/").split("/")
        if parts[0] == "groups":
            if method != "GET":
                self.log.append((method, p, copy.deepcopy(obj)))
            gid = parts[1]
            if parts[2:] == ["children"]:
                par = self.groups[gid]["path"]
                return [copy.deepcopy(g) for g in self.groups.values() if g["path"].rsplit("/", 1)[0] == par and g["path"] != par][int(qs.get("first", 0)):]
            if parts[2:] == ["members"]:
                return [] if int(qs.get("first", 0)) else [{"id": x} for x in self.members.get(gid, [])]
            if parts[2:] == ["role-mappings"]:
                return {"clientMappings": {"realm-management": {"mappings": self.rm[gid]}}} if self.rm.get(gid) else {}
            if parts[2:4] == ["role-mappings", "clients"]:
                if method == "GET": return copy.deepcopy(self.rm.get(gid, []))
                if method == "DELETE": self.rm[gid] = []; return None
        if parts[0] == "users" and len(parts) == 4 and parts[2] == "groups" and method == "DELETE":
            self.log.append((method, p, None)); self.members[parts[3]].remove(parts[1]); return None
        if p == BASE + "/policy" and method == "GET" and "name" not in qs:
            return [] if int(qs.get("first", 0)) else [copy.deepcopy(x) for x in self.policies.values()]
        return super().api(method, path, obj, ok, ok404)

saved = (M.APP_CLIENTS, M.APP_USER_MANAGERS, dict(M.ROLE_GROUPS), M.ALLOWLIST, M.publish_allowlist)
k9 = RetireKC()
with contextlib.redirect_stdout(io.StringIO()):
    M.sync_delegations(k9, [g for g in k9.groups.values() if not g["path"].startswith("/roles")])
dg = gpath(k9, "/roles/app-b-user-manager"); pg = gpath(k9, "/roles/app-c-user-manager")
k9.members[dg] = ["u-dev", "u-both"]
import tempfile
M.ALLOWLIST = os.path.join(tempfile.mkdtemp(), "al.json")
M._write_json(M.ALLOWLIST, {
    "u-dev": {"username": "dev.only", "roles": ["/roles/app-b-user-manager"], "rm_roles": ["query-groups", "query-users"],
              "grants": [{"id": dg, "path": "/roles/app-b-user-manager", "roles": ["query-groups", "query-users"]}]},
    "u-both": {"username": "both", "roles": ["/roles/app-b-user-manager", "/roles/app-c-user-manager"],
               "rm_roles": ["query-groups", "query-users"],
               "grants": [{"id": dg, "path": "/roles/app-b-user-manager", "roles": ["query-groups", "query-users"]},
                          {"id": pg, "path": "/roles/app-c-user-manager", "roles": ["query-groups", "query-users"]}]}})
published = []
M.publish_allowlist = lambda kc_, al=None: published.append(al)
# the one-line change: app-b leaves the configuration
M.APP_CLIENTS = ("app-a", "app-c")
M.APP_USER_MANAGERS = {k: v for k, v in M.APP_USER_MANAGERS.items() if k != "app-b"}
M.ROLE_GROUPS.pop("app-b-user-manager", None)
check("[retire] a plain roles-setup REFUSES while the removed app's delegation is live", raises(lambda: M.retire_apps(k9, [])))
# an INTERRUPTED --retire-app: its permissions went, its policies and the manager group did not
for pid in [x["id"] for x in k9.perms.values() if "/app-b" in x["name"]]:
    del k9.perms[pid]
check("[retire] interrupted (permissions deleted, policies left): a plain roles-setup still REFUSES",
      raises(lambda: M.retire_apps(k9, [])))
check("[retire] --retire-app of a still-configured client is refused", raises(lambda: M.retire_apps(k9, ["app-c"])))
# a second window: --retire-app interrupted right AFTER the allowlist prune, before the group's roles and members are stripped
real_prune = M.prune_allowlist_grant
def prune_then_crash(kc_, gid, path):
    real_prune(kc_, gid, path)
    raise RuntimeError("simulated interruption after the allowlist prune")
M.prune_allowlist_grant = prune_then_crash
check("[retire] (interrupted right after the allowlist prune)", raises(lambda: M.retire_apps(k9, ["app-b"])))
M.prune_allowlist_grant = real_prune
check("[retire] ... the prune came BEFORE the group lost its roles and members (they are still there)",
      bool(k9.rm[dg]) and bool(k9.members[dg]) and "u-dev" not in json.load(open(M.ALLOWLIST)))
check("[retire] ... so a plain roles-setup still REFUSES (the group still carries roles/members)",
      raises(lambda: M.retire_apps(k9, [])))
# and the converse: the group already stripped, but a stale allowlist entry left - also refused
saved_al = json.load(open(M.ALLOWLIST))
stale = dict(saved_al); stale["u-stale"] = {"username": "stale.mgr", "roles": ["/roles/app-b-user-manager"], "rm_roles": [],
                                             "grants": [{"id": dg, "path": "/roles/app-b-user-manager", "roles": ["query-users"]}]}
rm_saved, mem_saved = list(k9.rm[dg]), list(k9.members[dg])
k9.rm[dg], k9.members[dg] = [], []
M._write_json(M.ALLOWLIST, stale)
left_ = M.removed_apps(k9)
check("[retire] removed_apps reports an allowlist entry still naming the removed app's manager group",
      any("allowlist entry stale.mgr" in x for x in left_.get("app-b", [])), left_)
M._write_json(M.ALLOWLIST, saved_al); k9.rm[dg], k9.members[dg] = rm_saved, mem_saved
r_ = raises(lambda: M.retire_apps(k9, ["app-b"]))
check("[retire] a second --retire-app completes it", r_ is False, r_)
left = [x["name"] for x in list(k9.perms.values()) + list(k9.policies.values()) if "app-b" in x["name"]]
check("[retire] ... nothing of app-b's delegation remains", not left, left)
check("[retire] ... the manager group: no realm-management role, no member", not k9.rm[dg] and not k9.members[dg])
al = json.load(open(M.ALLOWLIST))
check("[retire] ... the allowlist: a app-b-only entry removed, a two-grant entry pruned to app-c, published",
      "u-dev" not in al and [g["id"] for g in al["u-both"]["grants"]] == [pg] and al["u-both"]["roles"] == ["/roles/app-c-user-manager"]
      and published, al)
check("[retire] ... app-c's delegation is intact", any(x["name"] == "membership: /app-c/lead" for x in k9.perms.values())
      and k9.rm[pg])
k9.log = []; published.clear()
r_ = raises(lambda: M.retire_apps(k9, ["app-b"]))
check("[retire] a THIRD --retire-app converges with no write (idempotent)", r_ is False and not k9.log and not published, (r_, k9.log[:3]))
check("[retire] and a plain roles-setup no longer refuses", raises(lambda: M.retire_apps(k9, [])) is False)
M.APP_CLIENTS, M.APP_USER_MANAGERS, rg, M.ALLOWLIST, M.publish_allowlist = saved
M.ROLE_GROUPS.clear(); M.ROLE_GROUPS.update(rg)


# 10. a tree group carrying a realm-management role (e.g. an app role that is a composite of one) stops the whole run
kA = FakeKC(roles=APP_A + REVIEW)
carrier = [g for g in kA.tree() if g["path"] == "/%s/administrator" % APP][0]
kA.admin_carriers.add(carrier["id"])
writes_before = len(kA.log)
got = raises(lambda: M.sync_delegations(kA, kA.tree()), RuntimeError)
check("[admin carrier] sync_delegations refuses a tree group that carries a realm-management role",
      isinstance(got, str) and "realm-management" in got and "/%s/administrator" % APP in got, got)
check("[admin carrier] ... before writing anything", len(kA.log) == writes_before, kA.log[writes_before:][:3])

print("\n%d/%d passed" % (sum(res), len(res))); sys.exit(0 if all(res) else 1)

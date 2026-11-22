#!/usr/bin/env python3
"""Unit test of fgap/app_admin_fgap.py setup --enroll-existing's eligibility check (enroll_refusal, master_allowlist)
with a fake Keycloak - no live call, no root, runs anywhere.

Moving an account into /<app>/<ROLE> puts it in reach of the app's administrator, so the check must judge EFFECTIVE
privilege: a realm-management role that arrives through a group (or a composite) refuses the account exactly as a
direct one does; so does any group outside the app's tree, a role of another client, an identity binding, or an entry
in the administrator allowlist.

  python3 app_admin_enroll_unit_test.py
"""
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "..", "fgap", "app_admin_fgap.py")).read()
F = {"__name__": "app_admin_fgap_enroll_unit"}
exec(compile(src[:src.index("\nap = argparse.ArgumentParser")], "app_admin_fgap.py", "exec"), F)
enroll_refusal, master_allowlist, default_role_ids = F["enroll_refusal"], F["master_allowlist"], F["default_role_ids"]

APP, RM = "app-a", "rm-client-id"
# default-roles-example -> offline_access, account view-profile, account manage-account -> manage-account-links
COMPOSITES = {"dr": ["offline-access", "acct-view-profile", "acct-manage-account"], "acct-manage-account": ["acct-manage-links"]}
DEFAULT_ACCOUNT = ["acct-view-profile", "acct-manage-account", "acct-manage-links"]
res = []
def check(n, ok, d=""):
    res.append(bool(ok)); print("%s  %-92s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

class FakeKC:
    """Users with direct client mappings, groups (each group may carry realm-management roles) and attributes."""
    realm = "example"
    def __init__(self, master_status=200, allowlist=""):
        self.users, self.groups, self.master_status, self.allowlist = {}, {}, master_status, allowlist
    def group(self, path, rm_roles=()):
        self.groups[path] = {"id": "g" + str(len(self.groups)), "path": path, "rm": list(rm_roles)}
    def user(self, uid, groups=(), direct=None, rm_direct=(), attrs=None, eff_other=None):
        # every user holds the realm's default roles: account view-profile and manage-account (+ manage-account-links)
        eff = {"account-id": list(DEFAULT_ACCOUNT)}
        for k, v in (eff_other or {}).items():
            eff[k] = eff.get(k, []) + list(v)
        self.users[uid] = {"groups": list(groups), "direct": dict(direct or {APP: ["viewer"]}),
                           "rm_direct": list(rm_direct), "attrs": dict(attrs or {}), "eff_other": eff}
        return {"id": uid, "username": uid}
    def api(self, method, path, obj=None, expect=(200, 201, 204)):
        assert method == "GET", path
        if path == "":
            return 200, {"realm": "example", "defaultRole": {"id": "dr", "name": "default-roles-example"}}
        if path.startswith("/roles-by-id/"):
            return 200, [{"id": c} for c in COMPOSITES.get(path.split("/")[2], [])]
        p = path.split("?")[0].split("/")
        u = self.users[p[2]]
        if path.endswith("/role-mappings/clients/%s/composite" % RM):       # effective: direct + via groups
            names = set(u["rm_direct"]) | {r for g in u["groups"] for r in self.groups[g]["rm"]}
            return 200, [{"name": n} for n in sorted(names)]
        if p[3:5] == ["role-mappings", "clients"] and path.endswith("/composite"):
            return 200, [{"id": n, "name": n} for n in u["eff_other"].get(p[5], [])]
        if p[3:] == ["groups"]:
            qs = dict(x.split("=") for x in path.split("?")[1].split("&"))
            allg = [{"id": self.groups[g]["id"], "path": g} for g in u["groups"]]
            first, mx = int(qs.get("first", 0)), int(qs.get("max", 100))
            return 200, allg[first:first + mx]
        if p[3:] == ["role-mappings"]:
            return 200, {"clientMappings": {c: {"mappings": [{"name": r} for r in rs]} for c, rs in u["direct"].items()}}
        if len(p) == 3:
            return 200, {"id": p[2], "attributes": u["attrs"]}
        raise AssertionError(path)
    def raw(self, method, path, body=None, headers=None, auth=True):
        assert (method, path) == ("GET", "/admin/realms/master")
        return self.master_status, json.dumps({"attributes": {"stig.admin-allowlist.example": self.allowlist}})

kc = FakeKC(allowlist="vetted-admin,other-id")
kc.group("/app-a"); kc.group("/app-a/viewer"); kc.group("/app-b/member")
kc.group("/roles/idp-user-manager", rm_roles=("query-users", "query-groups"))
kc.group("/roles/empty")                                   # a catalogue group, whatever it carries today
kc.group("/staff", rm_roles=("view-users",))               # an ordinary-looking group that carries a realm-management role
al = master_allowlist(kc)
check("the allowlist is read from the master realm attribute for this realm", al == {"vetted-admin", "other-id"}, sorted(al))

OTHER = [{"id": "account-id", "clientId": "account"}, {"id": "app-b-id", "clientId": "app-b"}]
DEFAULTS = default_role_ids(kc)
check("the default role's grants are expanded through composites", {"acct-view-profile", "acct-manage-account", "acct-manage-links"} <= DEFAULTS, sorted(DEFAULTS))
def why(u):
    return enroll_refusal(kc, u, APP, RM, al, OTHER, DEFAULTS)

r = why(kc.user("plain", groups=["/app-a/viewer"]))
check("an ordinary member (app role, app groups, and the realm's default account roles) IS enrollable", r is None, r)
r = why(kc.user("acct-extra", eff_other={"account-id": ["acct-delete-account"]}))
check("REFUSED: an account-client role beyond the default roles", r and "account" in r, r)
r = why(kc.user("via-group", groups=["/staff"]))
check("REFUSED: a realm-management role that arrives only through a group (not a direct mapping)",
      r and "realm-management" in r and "view-users" in r, r)
r = why(kc.user("um", groups=["/roles/idp-user-manager"]))
check("REFUSED: an IdP user manager through the /roles/* catalogue group", r and "realm-management" in r, r)
r = why(kc.user("rm-direct", rm_direct=["manage-users"]))
check("REFUSED: a direct realm-management role", r and "manage-users" in r, r)
r = why(kc.user("catalogue", groups=["/roles/empty"]))
check("REFUSED: membership of any /roles/* group, even one carrying no role today", r and "/roles/empty" in r, r)
r = why(kc.user("other-app", groups=["/app-a/viewer", "/app-b/member"]))
check("REFUSED: a member of another application's tree", r and "/app-b/member" in r, r)
r = why(kc.user("other-client", direct={APP: ["viewer"], "app-b": ["student"]}))
check("REFUSED: a direct role of another client", r and "app-b" in r, r)
r = why(kc.user("carded", attrs={"cac_edipi": ["1234567890"]}))
check("REFUSED: an account bound to a card (cac_edipi)", r and "cac_edipi" in r and "1234567890" not in r, r)
r = why(kc.user("entra", attrs={"entra_oid": ["oid"]}))
check("REFUSED: an account bound to an Entra identity (entra_oid)", r and "entra_oid" in r, r)
r = why(kc.user("via-composite", eff_other={"app-b-id": ["owner"]}))
check("REFUSED: a role of another client that arrives only by composite (effective)", r and "app-b" in r and "effective" in r, r)
r = why(dict(kc.user("service-account-x"), username="service-account-x"))
check("REFUSED: a service account", r and "service account" in r, r)
many = ["/app-a/g%04d" % i for i in range(1200)] + ["/roles/empty"]
for g in many[:-1]:
    kc.group(g)
r = why(kc.user("many-groups", groups=many))
check("REFUSED: a /roles/* membership listed after the first 1000 groups (paged)", r and "/roles/empty" in r, (r or "")[:80])
r = why(kc.user("vetted-admin"))
check("REFUSED: an account on the administrator allowlist", r and "allowlist" in r, r)
try:
    master_allowlist(FakeKC(master_status=403)); got = None
except SystemExit as e:
    got = str(e)
check("an unreadable allowlist refuses enrolment altogether (fail closed)", got and "REFUSED" in got, got)

print("\n%d/%d passed" % (sum(res), len(res)))
raise SystemExit(0 if all(res) else 1)

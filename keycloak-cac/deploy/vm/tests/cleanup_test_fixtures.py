#!/usr/bin/env python3
"""Remove every test fixture the live suites create (users t.fp.* t.acc.* t.onb.* t.console*, exactly create_shapes_live_check.py's names, fgap.* e2e.* test.*, clients t-fp-*
t-acc-* t-role-* t-probe-*, groups and roles t-fp-* t-acc-* fgap-*, the legacy-delegate permission/policy), then let the
guard drop the allowlist entries of deleted accounts. Runs ON the VM as root. Prints what it removed.
  sudo python3 cleanup_test_fixtures.py [--all]    (--all: the relying-party e2e's e2e.app-b.* accounts too - not while it runs)"""
import importlib.machinery, importlib.util, subprocess, sys

ADM = "/usr/local/sbin/idp-admin.py"
ld = importlib.machinery.SourceFileLoader("idp_admin", ADM)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
kc = M.KC()
U = ("t.fp.", "t.acc.", "t.onb.", "t.console", "fgap.", "e2e.", "test.")
import re
SHP = re.compile(r"^(t\.shp\.\d{6}|tshp-\d{6}\.(entra|cac|both|r[1-5]))$")   # create_shapes_live_check.py: exactly its names
C = ("t-fp-", "t-acc-", "t-role-", "t-probe-")
G = ("t-fp-", "t-acc-", "fgap-")
gone = []
ALL = "--all" in sys.argv     # also the relying-party e2e's e2e.app-b.* accounts (only when no app-b run is in progress)
for u in M.paged(kc, "/users?briefRepresentation=true"):
    if (u["username"].startswith(U) or SHP.match(u["username"])) and (ALL or not u["username"].startswith("e2e.app-b.")):
        kc.api("DELETE", "/users/%s" % u["id"], ok404=True); gone.append(u["username"])
for c in M.paged(kc, "/clients"):
    if c["clientId"].startswith(C):
        kc.api("DELETE", "/clients/%s" % c["id"], ok404=True); gone.append("client " + c["clientId"])
def walk(groups):
    for g in groups:
        if g["name"].startswith(G):
            kc.api("DELETE", "/groups/%s" % g["id"], ok404=True); gone.append("group " + g["path"])
        else:
            walk(kc.api("GET", "/groups/%s/children?max=200" % g["id"]) or [])
walk(kc.api("GET", "/groups?max=200") or [])
for r in kc.api("GET", "/roles?max=500") or []:
    if r["name"].startswith(G):
        kc.api("DELETE", "/roles-by-id/%s" % r["id"], ok404=True); gone.append("role " + r["name"])
ap = kc.api("GET", "/clients?clientId=admin-permissions") or []
if ap:
    base = "/clients/%s/authz/resource-server" % ap[0]["id"]
    for kind in ("permission", "policy"):
        for x in kc.api("GET", base + "/%s?name=%s" % (kind, M.q("t-fp"))) or []:
            if x["name"].startswith("t-fp"):
                kc.api("DELETE", base + "/%s/%s" % (kind, x["id"]), ok404=True); gone.append("%s %s" % (kind, x["name"]))
print("removed %d: %s" % (len(gone), ", ".join(gone[:40]) + (" ..." if len(gone) > 40 else "")))
r = subprocess.run([sys.executable, ADM, "guard", "--fix"], capture_output=True, text=True)
print((r.stdout + r.stderr).strip().splitlines()[-1] if (r.stdout + r.stderr).strip() else "", "exit", r.returncode)

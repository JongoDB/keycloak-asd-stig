#!/usr/bin/env python3
"""idp-admin.py user-create-cac / user-create-pw must never attach a role to the wrong person. Run ON the VM as root
against the live realm; creates throwaway users (t.confusion.*) and deletes them. Prints PASS/FAIL per case.
  sudo python3 idp_admin_users_test.py [--check-user staff.admin1:1234567890]"""
import argparse, importlib.machinery, importlib.util, subprocess, sys, time

ADM = "/usr/local/sbin/idp-admin.py"
ld = importlib.machinery.SourceFileLoader("idp_admin", ADM)
spec = importlib.util.spec_from_loader("idp_admin", ld); m = importlib.util.module_from_spec(spec); ld.exec_module(m)
ap = argparse.ArgumentParser(); ap.add_argument("--check-user", action="append", default=[]); ap.add_argument("--delegated", action="append", default=[]); ap.add_argument("--role", default="app-b:member")
a = ap.parse_args()
kc = m.KC(); res = []
def run(*args):
    p = subprocess.run([sys.executable, ADM] + list(args), capture_output=True, text=True)
    return (p.stdout + p.stderr).strip()
def check(name, out, want):
    ok = out.startswith(want) or ("\n" + want) in out or out.split(": ", 1)[0] == want.rstrip(":")
    ok = want in out.split("\n")[-1]
    res.append(ok); print("%s  %-58s -> %s" % ("PASS" if ok else "FAIL", name, out.split("\n")[-1][:110]))
s = time.strftime("%H%M%S"); u1, u2, u3 = "t.confusion.a%s" % s, "t.confusion.b%s" % s, "t.confusion.pw%s" % s
e1, e2 = "00000%s1" % s[:4], "00000%s2" % s[:4]
mk = lambda u, e, *x: run("user-create-cac", u, e, u + "@test.invalid", "T", "Confusion", a.role, *x)
try:
    check("new username + new EDIPI", mk(u1, e1), "created:")
    check("same username again, no --existing", mk(u1, e1), "REFUSED:")
    check("--existing but a different EDIPI", mk(u1, e2, "--existing"), "REFUSED:")
    check("--existing, same EDIPI, no link", mk(u1, e1, "--existing"), "updated:")
    check("another username with an EDIPI already in use", mk(u2, e1), "REFUSED:")
    uid = m.user(kc, u1)["id"]
    kc.api("POST", "/users/%s/federated-identity/entra" % uid, {"identityProvider": "entra", "userId": "test-sub-%s" % s, "userName": "t@test.invalid"})
    check("--existing, same EDIPI, but linked to an IdP", mk(u1, e1, "--existing"), "REFUSED:")
    open("/tmp/.t-pw", "w").write("Aa1!" + s * 3)
    check("password account: new", run("user-create-pw", u3, u3 + "@test.invalid", "T", "Pw", a.role, "--temp-password-file", "/tmp/.t-pw", "--temporary"), "created:")
    check("password account: existing username", run("user-create-pw", u3, u3 + "@test.invalid", "T", "Pw", a.role, "--temp-password-file", "/tmp/.t-pw"), "REFUSED:")
    # a password account given a card mapping by the realm admin: --existing needs --accept-credentials
    pid = m.user(kc, u3)["id"]; full = kc.api("GET", "/users/%s" % pid)
    e3 = "00000%s3" % s[:4]
    kc.api("PUT", "/users/%s" % pid, dict(full, attributes=dict(full.get("attributes") or {}, cac_edipi=[e3])))
    check("--existing on an account with a password credential", mk(u3, e3, "--existing"), "REFUSED:")
    check("... accepted with --accept-credentials", mk(u3, e3, "--existing", "--accept-credentials"), "updated:")
    # an account a fine-grained delegate can manage (a member of an application group) is never taken over
    u4, e4 = "t.confusion.d%s" % s, "00000%s4" % s[:4]
    mk(u4, e4)
    gid = kc.api("GET", "/group-by-path/app-b/member")["id"]
    kc.api("PUT", "/users/%s/groups/%s" % (m.user(kc, u4)["id"], gid))
    check("--existing on an account inside a delegated group tree", mk(u4, e4, "--existing"), "REFUSED:")
    for cu in a.check_user:                         # real accounts: read-only re-verification of the same rule
        name, edipi = cu.split(":")
        u = kc.api("GET", "/users/%s" % m.user(kc, name)["id"])
        links = kc.api("GET", "/users/%s/federated-identity" % u["id"]) or []
        ok = (u.get("attributes") or {}).get("cac_edipi") == [edipi] and not links
        res.append(ok); print("%s  %-58s -> EDIPI %s, identity-provider links: %d" % ("PASS" if ok else "FAIL", "existing account %s satisfies the rule" % name,
                                                                                    "matches" if ok or not links else "?", len(links)))
finally:
    for u in (u1, u2, u3, "t.confusion.d%s" % s):
        f = kc.api("GET", "/users?exact=true&username=%s" % m.q(u))
        if f: kc.api("DELETE", "/users/%s" % f[0]["id"])
    subprocess.run(["rm", "-f", "/tmp/.t-pw"])
print("\n%d/%d passed" % (sum(res), len(res))); sys.exit(0 if all(res) else 1)

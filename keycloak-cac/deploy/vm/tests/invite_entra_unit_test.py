#!/usr/bin/env python3
"""Unit test of idp-admin.py invite's required actions, with a fake Keycloak - no live call, no root, runs anywhere.

  - invite --entra-oid (not an administrator): the account gets TERMS_AND_CONDITIONS only (stig-accounts' Entra shape:
    no password, no TOTP, nothing to enrol at the first Entra sign-in) and no set-up e-mail is sent;
  - invite without --entra-oid (a password account): UPDATE_PASSWORD, CONFIGURE_TOTP, TERMS_AND_CONDITIONS and the
    set-up e-mail, as before;
  - invite --edipi (a card account, no Entra): unchanged, as before;
  - invite --entra-oid with an administrator role group: unchanged - set-up link, promoted only after enrolment.

  python3 invite_entra_unit_test.py [--admin ../host/idp-admin.py]
"""
import argparse, contextlib, importlib.machinery, importlib.util, io, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser(); ap.add_argument("--admin", default=os.path.join(HERE, "..", "host", "idp-admin.py"))
args = ap.parse_args()
os.environ.setdefault("IDP_ADMIN_CONFIG", os.path.join(HERE, "fixtures", "idp-admin.test.json"))
ld = importlib.machinery.SourceFileLoader("idp_admin", args.admin)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)

res = []
def check(n, ok, d=""):
    res.append(bool(ok)); print("%s  %-96s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

class FakeKC:
    def __init__(self):
        self.users = {}
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        if method == "GET" and path.startswith("/users?exact=true&username="):
            name = path.split("username=", 1)[1]
            return [u for u in self.users.values() if u["username"] == name]
        if method == "POST" and path == "/users":
            uid = "u%d" % len(self.users); self.users[uid] = dict(obj, id=uid); return None
        if method == "GET" and path.startswith("/users/"):
            return self.users[path.split("/")[2]]
        raise AssertionError("unexpected %s %s" % (method, path))

calls = {}
M.bindings_or_put = lambda kc, uid, set_=None, remove=(), reason=None: calls.setdefault("bind", []).append(set_)
M.send_setup = lambda kc, u, lifespan, must=True: calls.setdefault("setup", []).append(u["username"]) or True
M.cmd_grant = lambda a: calls.setdefault("grant", []).append(a.roles)
M.promote_or_pend = lambda kc, u, roles, st, reset=False, lifespan=0: calls.setdefault("pend", []).append(roles)
M.load_state = lambda: None
M.new_state = lambda: {}

def invite(name, entra_oid=None, edipi=None, groups="app-a:viewer"):
    calls.clear(); kc = FakeKC(); M.KC = lambda: kc
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        M.cmd_invite(argparse.Namespace(username=name, email=name + "@example.mil", first=None, last=None, edipi=edipi,
                                        entra_oid=entra_oid, groups=groups, lifespan=43200))
    return next(iter(kc.users.values())), dict(calls), out.getvalue()

OID = "00000000-0000-4000-8000-0000000000a1"
u, c, out = invite("lab.entra", entra_oid=OID)
check("invite --entra-oid: TERMS_AND_CONDITIONS only (no UPDATE_PASSWORD, no CONFIGURE_TOTP)",
      u["requiredActions"] == ["TERMS_AND_CONDITIONS"], u["requiredActions"])
check("... no set-up e-mail (no password or TOTP to set up)", "setup" not in c, c)
check("... the Entra binding is written and the role groups granted", c.get("bind") == [{"entra_oid": OID}] and c.get("grant") == [["app-a:viewer"]], c)
check("... and the operator is told how the person signs in", "Microsoft Entra" in out, out.strip())

u, c, out = invite("lab.password")
check("invite (password): UPDATE_PASSWORD, CONFIGURE_TOTP, TERMS_AND_CONDITIONS, set-up e-mail - unchanged",
      u["requiredActions"] == ["UPDATE_PASSWORD", "CONFIGURE_TOTP", "TERMS_AND_CONDITIONS"] and c.get("setup") == ["lab.password"],
      (u["requiredActions"], c))

u, c, out = invite("lab.card", edipi="1234567890")
check("invite --edipi (card, no Entra): unchanged", u["requiredActions"] == ["UPDATE_PASSWORD", "CONFIGURE_TOTP", "TERMS_AND_CONDITIONS"]
      and c.get("setup") == ["lab.card"], (u["requiredActions"], c))

u, c, out = invite("lab.admin", entra_oid=OID, groups="idp-auditor")
check("invite --entra-oid with an administrator role group: unchanged (set-up actions; promoted after enrolment)",
      u["requiredActions"] == ["UPDATE_PASSWORD", "CONFIGURE_TOTP", "TERMS_AND_CONDITIONS"] and c.get("pend") == [["idp-auditor"]]
      and "setup" not in c, (u["requiredActions"], c))

print("\n%d/%d passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)

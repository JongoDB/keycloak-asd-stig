#!/usr/bin/env python3
"""Unit test of idp-admin.py rename with a fake Keycloak - no live call, no root, runs anywhere.

What it proves:
  - `rename X X --email E` (the form send_setup's and promote_or_pend's messages tell the operator to run) updates
    the e-mail on the same account; it is not refused as "X already exists", and the realm's editUsernameAllowed is
    never touched (no username change);
  - a real rename still refuses a target username that exists, and changes nothing;
  - a real rename opens editUsernameAllowed for the one change and closes it again, keeping the user id.

  python3 rename_unit_test.py [--admin ../host/idp-admin.py]
"""
import argparse, contextlib, copy, importlib.machinery, importlib.util, io, os, sys, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser(); ap.add_argument("--admin", default=os.path.join(HERE, "..", "host", "idp-admin.py"))
args = ap.parse_args()
os.environ.setdefault("IDP_ADMIN_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures", "idp-admin.test.json"))   # the lab/unit config; on a host the real one is used
ld = importlib.machinery.SourceFileLoader("idp_admin", args.admin)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)

res = []
def check(n, ok, d=""):
    res.append(bool(ok)); print("%s  %-80s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

class FakeKC:
    """Users by id, username lookup, PUT user, PUT realm (editUsernameAllowed)."""
    def __init__(self):
        self.users = {"u1": {"id": "u1", "username": "jane.doe", "email": None, "firstName": "Jane", "lastName": "Doe"},
                      "u2": {"id": "u2", "username": "john.roe", "email": "john.roe@example.mil",
                             "firstName": "John", "lastName": "Roe"}}
        self.realm_puts, self.user_puts = [], []
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        u = urllib.parse.urlparse(path); qs = dict(urllib.parse.parse_qsl(u.query)); p = u.path
        if method == "GET" and p == "/users":
            return [copy.deepcopy(x) for x in self.users.values() if x["username"] == qs.get("username")]
        if method == "GET" and p.startswith("/users/"):
            return copy.deepcopy(self.users[p.split("/")[2]])
        if method == "PUT" and p == "":
            self.realm_puts.append(obj); return None
        if method == "PUT" and p.startswith("/users/"):
            uid = p.split("/")[2]; self.user_puts.append(uid)
            cur = self.users[uid]
            if obj["username"] != cur["username"] and not (self.realm_puts and self.realm_puts[-1].get("editUsernameAllowed")):
                raise AssertionError("username changed while editUsernameAllowed is off")
            self.users[uid] = copy.deepcopy(obj); return None
        raise AssertionError("unexpected %s %s" % (method, path))

def run(kc, old, new, email=None):
    M.KC = lambda: kc
    out = io.StringIO(); code = None
    try:
        with contextlib.redirect_stdout(out):
            M.cmd_rename(argparse.Namespace(old=old, new=new, email=email, first=None, last=None))
    except SystemExit as e:
        code = e.code
    return code, out.getvalue()

# 1. same-name form sets the e-mail
kc = FakeKC()
code, out = run(kc, "jane.doe", "jane.doe", "jane.doe@example.mil")
check("rename X X --email is not refused", code is None, repr(code))
check("rename X X --email sets the e-mail", kc.users["u1"]["email"] == "jane.doe@example.mil", kc.users["u1"]["email"])
check("rename X X keeps the username and id", kc.users["u1"]["username"] == "jane.doe" and kc.users["u1"]["id"] == "u1")
check("rename X X never touches editUsernameAllowed", kc.realm_puts == [], kc.realm_puts)
check("rename X X reports an update", "updated jane.doe" in out, out.strip())

# 2. a real rename onto an existing username is refused and changes nothing
kc = FakeKC(); before = copy.deepcopy(kc.users)
code, out = run(kc, "jane.doe", "john.roe", "x@example.mil")
check("rename onto an existing username is refused", isinstance(code, str) and "already exists" in code, repr(code))
check("a refused rename changes nothing", kc.users == before and not kc.user_puts and not kc.realm_puts)

# 3. a real rename works, opening and closing editUsernameAllowed
kc = FakeKC()
code, out = run(kc, "jane.doe", "jane.smith")
check("rename to a free username succeeds", code is None and kc.users["u1"]["username"] == "jane.smith", repr(code))
check("editUsernameAllowed opened then closed", kc.realm_puts == [{"editUsernameAllowed": True}, {"editUsernameAllowed": False}],
      kc.realm_puts)
check("user id unchanged", kc.users["u1"]["id"] == "u1")

print("\n%d/%d passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)

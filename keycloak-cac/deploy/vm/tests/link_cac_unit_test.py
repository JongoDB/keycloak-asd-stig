#!/usr/bin/env python3
"""Unit test of idp-admin.py link-cac (a CAC for an EXISTING account) with a fake Keycloak - no live call, no root, runs
anywhere. The command line goes through the tool's own parser; the EDIPI comes on stdin (not a terminal), as it would
from a pipe.

What it proves:
  - present (default): a link request (stig_card_link = now, no pending card, the present-card required action) and
    the step registered/enabled; reserve (--edipi): the same plus cac_edipi_pending; bind (--bind-edipi
    --confirm-direct-bind): cac_edipi now, no request; cancel; a re-run renews; --replace removes the card and ends
    the account's sessions;
  - every refusal changes nothing: no account, a disabled one, a service account, a card already bound (no --replace),
    an invite's pending card, an EDIPI bound or reserved elsewhere, an IdP administrator (no --allow-admin; with it:
    --edipi only, never a direct bind), no way to sign in without a card, the X.509 step mapping another attribute, the
    user profile not declaring the request, a malformed EDIPI, an EDIPI on the command line, conflicting options;
  - exactly one audit line (STIG-LINK-CAC) per attempt, the card masked; no ten-digit run anywhere in the output, the
    refusals, the audit lines or an admin-API error (whose path carries the EDIPI);
  - guard: an expired request reported (exit-2 line), a live one as information.

  python3 link_cac_unit_test.py [--admin ../host/idp-admin.py]
"""
import argparse, contextlib, copy, importlib.machinery, importlib.util, io, json, os, re, sys, time, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser(); ap.add_argument("--admin", default=os.path.join(HERE, "..", "host", "idp-admin.py"))
args = ap.parse_args()
os.environ.setdefault("IDP_ADMIN_CONFIG", os.path.join(HERE, "fixtures", "idp-admin.test.json"))
ld = importlib.machinery.SourceFileLoader("idp_admin", args.admin)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)

res = []
def check(n, ok, d=""):
    res.append(bool(ok)); print("%s  %-104s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

TEN = re.compile(r"[0-9]{10}")
E1, E2, E3 = "1234567890", "2345678901", "3456789012"
DAY = 86_400_000

class FakeKC:
    """The admin calls link-cac makes: users (exact username, attribute search, read, write, credentials, groups,
    realm-management roles, logout), the realm's browser flow and its X.509 step, the user profile, required actions."""
    def __init__(self, x509_attr="cac_edipi", declared=True):
        self.users, self.logouts, self.puts, self.fail_q = {}, [], [], False
        self.ra = None                     # the present-card required action: None = not registered
        self.x509_attr = x509_attr
        self.profile = ["username", "email", "cac_edipi"] + (["cac_edipi_pending", "stig_card_link"] if declared else [])
    def add(self, name, enabled=True, attrs=None, creds=("password",), groups=(), rm=(), ra=()):
        uid = "u-" + name
        self.users[uid] = {"rep": {"id": uid, "username": name, "enabled": enabled, "attributes": copy.deepcopy(attrs or {}),
                                   "requiredActions": list(ra), "createdTimestamp": 1},
                           "creds": [{"id": "c%d" % i, "type": t} for i, t in enumerate(creds)],
                           "groups": [{"id": "g" + g, "path": g} for g in groups], "rm": [{"name": r} for r in rm]}
        return uid
    def rep(self, name):
        return self.users["u-" + name]["rep"]
    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        u = urllib.parse.urlsplit(path); qs = dict(urllib.parse.parse_qsl(u.query)); p = u.path; parts = p.strip("/").split("/")
        if method == "GET" and p == "/users" and "q" in qs:
            if self.fail_q:
                sys.exit("GET %s -> HTTP 500 server error" % path)
            k, v = qs["q"].split(":", 1)
            return [{"id": x["rep"]["id"], "username": x["rep"]["username"]} for x in self.users.values()
                    if v in (x["rep"]["attributes"].get(k) or [])]
        if method == "GET" and p == "/users" and "username" in qs:
            return [copy.deepcopy(x["rep"]) for x in self.users.values() if x["rep"]["username"] == qs["username"]]
        if method == "GET" and p == "/users":                                       # paged (guard)
            return [copy.deepcopy(x["rep"]) for x in self.users.values()] if qs.get("first", "0") == "0" else []
        if method == "GET" and p == "/users/profile":
            return {"attributes": [{"name": n} for n in self.profile]}
        if parts[0] == "users" and len(parts) == 2:
            x = self.users[parts[1]]
            if method == "GET":
                return copy.deepcopy(x["rep"])
            if method == "PUT":
                self.puts.append(parts[1]); new = copy.deepcopy(obj)
                # an attribute the user profile does not declare is not kept (unmanaged attributes are off)
                new["attributes"] = {k: v for k, v in (new.get("attributes") or {}).items() if k in self.profile and v}
                x["rep"] = new; return None
        if parts[0] == "users" and parts[2:] == ["credentials"]:
            return copy.deepcopy(self.users[parts[1]]["creds"])
        if parts[0] == "users" and parts[2:] == ["logout"] and method == "POST":
            self.logouts.append(parts[1]); return None
        if parts[0] == "users" and parts[2:] == ["groups"]:
            return copy.deepcopy(self.users[parts[1]]["groups"]) if qs.get("first", "0") == "0" else []
        if parts[0] == "users" and parts[2:4] == ["role-mappings", "clients"]:
            return copy.deepcopy(self.users[parts[1]]["rm"])
        if p == "/clients":
            return [{"id": "C-" + qs.get("clientId"), "clientId": qs.get("clientId")}]
        if method == "GET" and p == "":
            return {"browserFlow": "browser"}
        if method == "GET" and p == "/authentication/flows/browser/executions":
            return [{"providerId": "stig-x509-client-username-form", "authenticationConfig": "x1"}]
        if method == "GET" and p == "/authentication/config/x1":
            return {"config": {"x509-cert-auth.mapper-selection.user-attribute-name": self.x509_attr}}
        if method == "GET" and p == "/users/profile":
            return {"attributes": [{"name": n} for n in self.profile]}
        if p == "/authentication/required-actions/stig-present-card":
            if method == "GET":
                if self.ra is None:
                    if ok404:
                        return None
                    raise AssertionError("GET of an unregistered required action")
                return copy.deepcopy(self.ra)
            if method == "PUT":
                self.ra = copy.deepcopy(obj); return None
        if method == "POST" and p == "/authentication/register-required-action":
            self.ra = {"alias": obj["providerId"], "name": obj["name"], "enabled": False}; return None
        raise AssertionError("unexpected admin call %s %s" % (method, path))

AUDIT = []
M.CARD_AUDIT = AUDIT.append
ALL = []          # every output, refusal and audit line, for the no-ten-digits check at the end

def run(kc, argv, stdin=""):
    """(exit: None or the message, stdout, the audit lines of this attempt)."""
    M.KC = lambda: kc
    n0 = len(AUDIT); out = io.StringIO(); code = None
    old = sys.stdin; sys.stdin = io.StringIO(stdin)
    try:
        a = M.parse_cli(["link-cac"] + argv)
        with contextlib.redirect_stdout(out):
            a.fn(a)
    except SystemExit as e:
        code = e.code if e.code is not None else 0
    finally:
        sys.stdin = old
    lines = AUDIT[n0:]
    ALL.extend([out.getvalue(), str(code)] + lines)
    return code, out.getvalue(), lines

def audited(lines, *want):
    return len(lines) == 1 and lines[0].startswith("STIG-LINK-CAC ") and all(w in lines[0] for w in want)

def unchanged(kc, before):
    return {k: v["rep"] for k, v in kc.users.items()} == before and not kc.logouts

def snap(kc):
    return copy.deepcopy({k: v["rep"] for k, v in kc.users.items()})

# ---- present (default): a link request the holder completes by presenting a card
kc = FakeKC(); kc.add("jane.doe")
t0 = int(time.time() * 1000)
code, out, al = run(kc, ["jane.doe"])
r = kc.rep("jane.doe"); at = r["attributes"]
check("present: accepted", code is None, repr(code))
check("present: stig_card_link = the time of the request, no pending card, no card bound",
      at.get("stig_card_link") and t0 - 1000 <= int(at["stig_card_link"][0]) <= int(time.time() * 1000) + 1000
      and "cac_edipi_pending" not in at and "cac_edipi" not in at, at)
check("present: the present-card required action set on the account", r["requiredActions"] == ["stig-present-card"], r["requiredActions"])
check("present: the step registered and enabled when it was not", kc.ra and kc.ra["enabled"] and "registered" in out, kc.ra)
check("present: the message says what happens next, and for how long", "the card they present binds" in out and "7 days" in out, out.strip()[:120])
check("present: one audit line - mode=present card=any result=requested, the operator", audited(al, "user=jane.doe", "mode=present",
      "card=any", "result=requested", "operator="), al)
code, out, al = run(kc, ["jane.doe"])
check("present: a re-run renews the request (and says so)", code is None and "replaces its earlier link request" in out
      and kc.rep("jane.doe")["requiredActions"] == ["stig-present-card"], out.strip()[-80:])

# ---- reserve (--edipi): only the named card binds
kc = FakeKC(); kc.add("jane.doe", creds=(), attrs={"entra_oid": ["0b1c2d3e-0000-4000-8000-000000000001"]})
kc.ra = {"alias": "stig-present-card", "enabled": False}
code, out, al = run(kc, ["jane.doe", "--edipi"], E1 + "\n")
at = kc.rep("jane.doe")["attributes"]
check("reserve: an Entra-bound account with no password is accepted (it signs in through Entra)", code is None, repr(code))
check("reserve: cac_edipi_pending = the typed EDIPI, the request set, no card bound yet",
      at.get("cac_edipi_pending") == [E1] and at.get("stig_card_link") and "cac_edipi" not in at, sorted(at))
check("reserve: a disabled step is enabled", kc.ra["enabled"] and "enabled" in out, kc.ra)
check("reserve: the output names the card masked only", "******7890" in out and E1 not in out, out.strip()[:120])
check("reserve: audited mode=reserve card=******7890", audited(al, "mode=reserve", "card=******7890", "result=requested") and E1 not in al[0], al)

# ---- bind (--bind-edipi): only with the confirmation
kc = FakeKC(); kc.add("jane.doe", creds=()); b = snap(kc)
code, out, al = run(kc, ["jane.doe", "--bind-edipi"], E1 + "\n")
check("bind: refused without --confirm-direct-bind, before the EDIPI is read; nothing changed",
      isinstance(code, str) and "--confirm-direct-bind" in code and unchanged(kc, b), code)
check("bind: ... audited as refused", audited(al, "mode=bind", "result=refused"), al)
code, out, al = run(kc, ["jane.doe", "--bind-edipi", "--confirm-direct-bind"], E1 + "\n")
r = kc.rep("jane.doe")
check("bind: with --confirm-direct-bind, cac_edipi bound now (no password needed), no request, no required action",
      code is None and r["attributes"].get("cac_edipi") == [E1] and "stig_card_link" not in r["attributes"]
      and "stig-present-card" not in r["requiredActions"], (code, r))
check("bind: the step is not touched for a direct bind", kc.ra is None)
check("bind: says NOW, masked", "bound NOW" in out and "******7890" in out and E1 not in out, out.strip())
check("bind: audited mode=bind card=******7890 result=bound", audited(al, "mode=bind", "card=******7890", "result=bound"), al)

# ---- refusals: each changes nothing and is audited once
def refusal(name, kc, argv, stdin, want, *aud):
    b = snap(kc); ra0 = copy.deepcopy(kc.ra)
    code, out, al = run(kc, argv, stdin)
    check("refused: %s" % name, isinstance(code, str) and code.startswith("REFUSED") and want in code
          and unchanged(kc, b) and kc.ra == ra0, (code or "")[:150])
    check("refused: ... one audit line, result=refused%s" % ("".join(" " + x for x in aud)), audited(al, "result=refused", *aud), al)
    return code

kc = FakeKC()
kc.add("jane.doe"); kc.add("off.user", enabled=False)
kc.add("has.card", attrs={"cac_edipi": [E2]})
kc.add("invited", attrs={"cac_edipi_pending": [E3]})
kc.add("holder", attrs={"cac_edipi": [E1]}); kc.add("reserver", attrs={"cac_edipi_pending": [E3]})
kc.add("boss.admin", groups=["/roles/idp-admin"]); kc.add("rm.holder", rm=["manage-users"])
kc.add("nocred", creds=())
refusal("no such account", kc, ["ghost.user"], "", "no account ghost.user")
refusal("a disabled account", kc, ["off.user"], "", "is disabled")
c = refusal("an account that already has a card (no --replace); the card masked", kc, ["has.card"], "", "already has a card")
check("refused: ... the existing card shown masked only", "******8901" in c and E2 not in c, c)
refusal("an account carrying an invite's pending card (no --replace)", kc, ["invited"], "", "its invite named")
c = refusal("an EDIPI already bound to another account (--edipi)", kc, ["jane.doe", "--edipi"], E1 + "\n", "already bound to or reserved", "card=******7890")
check("refused: ... names the other account, the card masked", "holder" in c and E1 not in c, c)
refusal("an EDIPI reserved for another account (pending)", kc, ["jane.doe", "--edipi"], E3 + "\n", "reserver", "card=******9012")
refusal("an EDIPI already bound elsewhere (--bind-edipi)", kc, ["jane.doe", "--bind-edipi", "--confirm-direct-bind"], E1 + "\n",
        "already bound to or reserved", "mode=bind")
refusal("an IdP administrator (/roles group) without --allow-admin", kc, ["boss.admin"], "", "IdP administrator", "allow_admin=no")
refusal("an administrator by a realm-management role, without --allow-admin", kc, ["rm.holder", "--edipi"], E2 + "\n", "IdP administrator")
refusal("an administrator with --allow-admin but no --edipi (any card)", kc, ["boss.admin", "--allow-admin"], "", "only the card you name",
        "allow_admin=yes")
refusal("an administrator with --allow-admin and a direct bind", kc, ["boss.admin", "--allow-admin", "--bind-edipi", "--confirm-direct-bind"],
        E2 + "\n", "never a direct bind")
refusal("no password and no Entra binding (cannot sign in to present a card)", kc, ["nocred"], "", "cannot sign in")
refusal("a malformed EDIPI (9 digits)", kc, ["jane.doe", "--edipi"], "123456789\n", "exactly 10 digits", "card=invalid")
c = refusal("a malformed EDIPI (11 digits) - never echoed", kc, ["jane.doe", "--edipi"], "12345678901\n", "exactly 10 digits", "card=invalid")
check("refused: ... the input is not repeated", "12345678901" not in c and "5678901" not in c, c)
refusal("a malformed EDIPI (letters)", kc, ["jane.doe", "--bind-edipi", "--confirm-direct-bind"], "12345abcde\n", "exactly 10 digits")
refusal("no EDIPI on stdin", kc, ["jane.doe", "--edipi"], "", "exactly 10 digits")
c = refusal("an EDIPI on the command line (--edipi N)", kc, ["jane.doe", "--edipi", E1], "", "never given on the command line",
            "card=on-the-command-line")
check("refused: ... and never echoed back", E1 not in c)
c = refusal("an EDIPI on the command line (a second positional)", kc, ["jane.doe", E1], "", "never given on the command line")
check("refused: ... and never echoed back", E1 not in c)
refusal("an EDIPI on the command line (--bind-edipi N)", kc, ["jane.doe", "--bind-edipi", E1, "--confirm-direct-bind"], "", "never given")
refusal("--edipi with --bind-edipi", kc, ["jane.doe", "--edipi", "--bind-edipi", "--confirm-direct-bind"], E2 + "\n", "not both")
refusal("--confirm-direct-bind without --bind-edipi", kc, ["jane.doe", "--confirm-direct-bind"], "", "goes with --bind-edipi")
refusal("--cancel with another option", kc, ["jane.doe", "--cancel", "--replace"], "", "takes no other option")
refusal("--cancel without a link request", kc, ["jane.doe", "--cancel"], "", "no link request to cancel", "mode=cancel")
kc2 = FakeKC(x509_attr="cac_upn"); kc2.add("jane.doe")
refusal("the X.509 step maps cards by another attribute", kc2, ["jane.doe"], "", "map cards by cac_edipi")
kc3 = FakeKC(declared=False); kc3.add("jane.doe")
refusal("the user profile does not declare the request (roles-setup not run)", kc3, ["jane.doe"], "", "roles-setup")
kc4 = FakeKC(); kc4.add("service-account-app")
kc4.api_orig = kc4.api
def sa_api(method, path, obj=None, ok=(200, 201, 204), ok404=False):
    if path.startswith("/clients?clientId="):
        return [{"id": "C-app", "clientId": "app", "serviceAccountsEnabled": True}]
    if path == "/clients/C-app/service-account-user":
        return {"id": "u-service-account-app"}
    return kc4.api_orig(method, path, obj, ok, ok404)
kc4.api = sa_api
refusal("a client's service account", kc4, ["service-account-app"], "", "service account")

# ---- an administrator with --allow-admin --edipi: the one way
kc = FakeKC(); kc.add("boss.admin", groups=["/roles/idp-admin"])
code, out, al = run(kc, ["boss.admin", "--allow-admin", "--edipi"], E2 + "\n")
check("admin: --allow-admin --edipi -> a reserved request (the holder must present exactly that card)",
      code is None and kc.rep("boss.admin")["attributes"].get("cac_edipi_pending") == [E2], repr(code))
check("admin: ... audited allow_admin=yes mode=reserve", audited(al, "allow_admin=yes", "mode=reserve", "result=requested"), al)

# ---- --replace: the old card removed, sessions ended
kc = FakeKC(); kc.add("has.card", attrs={"cac_edipi": [E2]})
code, out, al = run(kc, ["has.card", "--replace"])
at = kc.rep("has.card")["attributes"]
check("replace: the old card removed and a request set", code is None and "cac_edipi" not in at and at.get("stig_card_link"), (code, at))
check("replace: the account's sessions ended", kc.logouts == ["u-has.card"], kc.logouts)
check("replace: the old card named masked only", "******8901" in out and E2 not in out, out.strip())
check("replace: audited replace=yes", audited(al, "replace=yes", "result=requested"), al)
kc = FakeKC(); kc.add("has.card", attrs={"cac_edipi": [E2]}, creds=())
code, out, al = run(kc, ["has.card", "--replace", "--bind-edipi", "--confirm-direct-bind"], E1 + "\n")
check("replace: --replace with a direct bind swaps the card and ends the sessions",
      code is None and kc.rep("has.card")["attributes"].get("cac_edipi") == [E1] and kc.logouts == ["u-has.card"], (code, kc.logouts))
kc = FakeKC(); kc.add("invited", attrs={"cac_edipi_pending": [E3]})
code, out, al = run(kc, ["invited", "--replace"])
at = kc.rep("invited")["attributes"]
check("replace: an invite's pending card is dropped for the new request (no card was bound: no logout)",
      code is None and "cac_edipi_pending" not in at and at.get("stig_card_link") and not kc.logouts, (code, at))

# ---- cancel
kc = FakeKC(); kc.add("jane.doe"); run(kc, ["jane.doe", "--edipi"], E1 + "\n")
code, out, al = run(kc, ["jane.doe", "--cancel"])
r = kc.rep("jane.doe")
check("cancel: the request, its named card and the required action removed",
      code is None and not {"stig_card_link", "cac_edipi_pending"} & set(r["attributes"]) and "stig-present-card" not in r["requiredActions"], r)
check("cancel: audited mode=cancel result=cancelled", audited(al, "mode=cancel", "result=cancelled"), al)

# ---- an admin-API failure whose path carries the EDIPI: the exit message and the audit line masked
kc = FakeKC(); kc.add("jane.doe"); kc.fail_q = True
code, out, al = run(kc, ["jane.doe", "--edipi"], E1 + "\n")
check("error: an admin-API failure exits non-zero, its message masked (the path carried the EDIPI)",
      isinstance(code, str) and "HTTP 500" in code and E1 not in code and "******7890" in code, code)
check("error: ... audited result=error, masked", audited(al, "result=error") and E1 not in al[0], al)

# ---- guard: requests never completed
kc = FakeKC(); now = int(time.time() * 1000)
kc.add("fresh", attrs={"stig_card_link": [str(now - DAY)]})
kc.add("stale", attrs={"stig_card_link": [str(now - 8 * DAY)], "cac_edipi_pending": [E1]})
kc.add("garbled", attrs={"stig_card_link": ["soon"]})
kc.add("plain")
exp, pend = M.card_links(kc, now)
check("guard: an expired request -> STIG-CARD-LINK-EXPIRED (exit 2), with the cancel command",
      any(l.startswith("STIG-CARD-LINK-EXPIRED user=stale") and "a named card" in l and "link-cac stale --cancel" in l for l in exp), exp)
check("guard: an unreadable request time counts as expired", any("user=garbled" in l for l in exp), exp)
check("guard: a live request -> information only", pend and pend[0].startswith("info  CARD-LINK-PENDING user=fresh") and "any card" in pend[0]
      and not any("fresh" in l for l in exp), pend)
check("guard: no card number in a guard line", not any(TEN.search(l) for l in exp + pend))

# ---- the whole run: never a ten-digit run in any output, refusal or audit line
leaks = [x for x in ALL if TEN.search(x or "")]
check("masking: no ten-digit run in any output, refusal, error or audit line (%d texts)" % len(ALL), not leaks, leaks[:2])

print("%d/%d passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)

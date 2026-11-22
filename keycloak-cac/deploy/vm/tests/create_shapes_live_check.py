#!/usr/bin/env python3
"""Live check of stig-accounts' create SHAPES on the deployed image (keycloak-asd-stig >= 523cdcd; `card-accounts on`;
`entra --auto-link-domain example.mil`). Runs ON the VM as root; joins the Keycloak container's network namespace.

A throwaway user manager `t.shp.<HHMMSS>` (idp-admin.py grant idp-user-manager: all application trees, no application
role) creates, through stig-accounts, with its OWN admin-console token:
  1. "signIn": "entra", a example.mil address -> 201, setupEmail none; stig_signin_methods=entra, entra_pending=pending;
     required actions: the terms only. (No Microsoft sign-in: nothing is ever bound.)
  2. "signIn": "cac", edipi TEST_CARDS[0] -> 201; cac_edipi bound server-side; terms only; the manager's own read of the
     account does NOT show cac_edipi.
  3. "signIn": ["entra", "cac"], edipi TEST_CARDS[1] -> 201; cac_edipi_pending set (concealed from the manager), the card
     NOT bound.
  4. refusals: a lifespan with "entra" -> 400; "entra" with a non-member-domain address -> 403; the same test card again ->
     409 with the generic message; a duplicate method ["entra", "entra"] -> 400. None creates an account.
No mail is sent (no shape here sends one). Every account it made, and the manager, are deleted in `finally` (a hang-up
or SIGTERM ends there too); afterwards the check verifies that NO account holds or reserves a test card.

TEST CARDS: EDIPIs 1111111111 and 2222222222 (repeated-digit values are reserved for tests here: never a real EDIPI). Safe to
run twice: leftovers of an earlier run - EXACTLY the names this check makes, ^t\\.shp\\.\\d{6}$ and
^tshp-\\d{6}\\.(entra|cac|both|r[1-5])$ - are removed first, and the run refuses to start while any account outside them
holds or reserves a test card.

  sudo python3 create_shapes_live_check.py [--skill <keycloak-asd-stig skill dir>]
If the run does not end with its "cleanup:" line, run tests/cleanup_test_fixtures.py (it removes the same names).
The lab runs the same code through fgap/create_shapes_lab_test.py (run()).
"""
import re, sys, time

TEST_CARDS = ("1111111111", "2222222222")
GROUP = "/app-a/viewer"
GENERIC_409 = "username, e-mail address or card already in use"
TAGS = ("entra", "cac", "both", "r1", "r2", "r3", "r4", "r5")
# exactly the names this check makes: the manager and the accounts it creates (never a prefix match)
OURS = re.compile(r"^(t\.shp\.\d{6}|tshp-\d{6}\.(entra|cac|both|r[1-5]))$")


def run(M, kc, E, persona, run_adm, BASE, REALM, stamp=None):
    """The check; returns (passed, total)."""
    res = []
    def check(n, ok, d=""): res.append(bool(ok)); print("%s  %-96s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

    def find(name):
        return next(iter(x for x in kc.api("GET", "/users?exact=true&username=%s" % M.q(name)) or [] if x["username"] == name), None)

    def card_holders():
        """Every account holding OR reserving a test card (as the master realm sees it: an exact attribute search)."""
        out = []
        for card in TEST_CARDS:
            for attr in ("cac_edipi", "cac_edipi_pending"):
                out += ["%s %s=%s" % (u["username"], attr, card)
                        for u in kc.api("GET", "/users?exact=true&q=%s" % M.q("%s:%s" % (attr, card))) or []]
        return out

    def leftovers():
        return [u for u in M.paged(kc, "/users?briefRepresentation=true") if OURS.match(u.get("username") or "")]

    attrs = kc.api("GET", "").get("attributes") or {}
    if not attrs.get("stig.accounts.card-attribute") or attrs.get("stig.accounts.entra-domain") != "example.mil":
        sys.exit("NOT RUN: card-accounts on and entra --auto-link-domain example.mil first (card-attribute=%r, entra-domain=%r)"
                 % (attrs.get("stig.accounts.card-attribute"), attrs.get("stig.accounts.entra-domain")))
    for u in leftovers():
        kc.api("DELETE", "/users/%s" % u["id"], ok404=True); print("removed a leftover of an earlier run: %s" % u["username"])
    held = card_holders()
    if held:
        sys.exit("NOT RUN: a test card is held or reserved by an account this check did not make: %s" % held)

    stamp = stamp or time.strftime("%H%M%S")
    mgr_name, made = "t.shp.%s" % stamp, []
    def uname(tag):
        assert tag in TAGS
        n = "tshp-%s.%s" % (stamp, tag); made.append(n); return n
    try:
        mgr = persona.Person(M, kc, E, run_adm, BASE, REALM, mgr_name, "idp-user-manager")
        def create(body):
            return mgr.api("POST", "/stig-accounts/users", body)
        def body(tag, email_domain, **kw):
            n = uname(tag)
            return dict({"username": n, "email": "%s@%s" % (n.replace(".", "-"), email_domain), "firstName": "Test",
                         "lastName": "Shape", "group": GROUP}, **kw)
        def full(name):
            u = find(name); return kc.api("GET", "/users/%s" % u["id"]) if u else {}
        def keys(r):
            return sorted(r.keys()) if isinstance(r, dict) else r

        # 1. entra
        b1 = body("entra", "example.mil", signIn="entra"); st, r = create(b1); u1 = full(b1["username"]); a1 = u1.get("attributes") or {}
        check("1. signIn entra: 201, setupEmail none, signIn entra, no card in the answer",
              st == 201 and r.get("setupEmail") == "none" and r.get("signIn") == "entra" and "card" not in r, (st, keys(r)))
        check("1. ... stig_signin_methods=entra, entra_pending=pending, the terms action only, no card",
              a1.get("stig_signin_methods") == ["entra"] and a1.get("entra_pending") == ["pending"]
              and u1.get("requiredActions") == ["TERMS_AND_CONDITIONS"] and not a1.get("cac_edipi"), (u1.get("requiredActions"), sorted(a1)))
        # 2. cac
        b2 = body("cac", "example.mil", signIn="cac", edipi=TEST_CARDS[0]); st, r = create(b2); u2 = full(b2["username"]); a2 = u2.get("attributes") or {}
        check("2. signIn cac (test card): 201, setupEmail none, the card masked in the answer",
              st == 201 and r.get("setupEmail") == "none" and r.get("signIn") == "cac" and r.get("card") == "******" + TEST_CARDS[0][-4:]
              and TEST_CARDS[0] not in str(r), (st, keys(r)))
        check("2. ... cac_edipi bound server-side, stig_signin_methods=cac, the terms action only",
              a2.get("cac_edipi") == [TEST_CARDS[0]] and a2.get("stig_signin_methods") == ["cac"]
              and u2.get("requiredActions") == ["TERMS_AND_CONDITIONS"], (u2.get("requiredActions"), sorted(a2)))
        st, mr = mgr.api("GET", "/users/%s" % u2["id"]) if u2 else (0, {})
        check("2. ... the manager's own read does not show cac_edipi (concealed)",
              st == 200 and isinstance(mr, dict) and "cac_edipi" not in (mr.get("attributes") or {}),
              (st, sorted((mr.get("attributes") or {}).keys()) if isinstance(mr, dict) else mr))
        # 3. both
        b3 = body("both", "example.mil", signIn=["entra", "cac"], edipi=TEST_CARDS[1]); st, r = create(b3); u3 = full(b3["username"])
        a3 = u3.get("attributes") or {}
        check("3. signIn [entra, cac] (second test card): 201, setupEmail none, signIn [cac, entra]",
              st == 201 and r.get("setupEmail") == "none" and r.get("signIn") == ["cac", "entra"] and TEST_CARDS[1] not in str(r), (st, keys(r)))
        check("3. ... cac_edipi_pending set, the card NOT bound, entra_pending=pending, stig_signin_methods=cac,entra",
              a3.get("cac_edipi_pending") == [TEST_CARDS[1]] and not a3.get("cac_edipi") and a3.get("entra_pending") == ["pending"]
              and a3.get("stig_signin_methods") == ["cac,entra"], sorted(a3))
        st, mr = mgr.api("GET", "/users/%s" % u3["id"]) if u3 else (0, {})
        check("3. ... the manager's own read shows neither the card nor the pending card",
              st == 200 and isinstance(mr, dict) and not {"cac_edipi", "cac_edipi_pending"} & set((mr.get("attributes") or {}).keys()), st)
        check("3. ... the pending card is found by an exact attribute search (q=cac_edipi_pending:<card>)",
              any(x.startswith(b3["username"] + " cac_edipi_pending=") for x in card_holders()), card_holders())
        # 4. refusals (none creates an account)
        for name_, b_, want in (
                ("lifespan with entra", body("r1", "example.mil", signIn="entra", lifespan=43200), 400),
                ("entra with a non-member-domain address", body("r2", "notify.example.mil", signIn="entra"), 403),
                ("the same test card again (cac)", body("r3", "example.mil", signIn="cac", edipi=TEST_CARDS[0]), 409),
                ("the same pending test card again ([entra, cac])", body("r4", "example.mil", signIn=["entra", "cac"], edipi=TEST_CARDS[1]), 409),
                ("a duplicate method [entra, entra]", body("r5", "example.mil", signIn=["entra", "entra"]), 400)):
            st, r = create(b_)
            generic = isinstance(r, dict) and r.get("error") == GENERIC_409        # extra fields tolerated
            ok = st == want and find(b_["username"]) is None and (want != 409 or generic)
            check("4. %s: %d%s, no account" % (name_, want, " (generic)" if want == 409 else ""), ok, (st, r))
    finally:
        gone = []
        for n in made + [mgr_name]:
            u = find(n)
            if u:
                kc.api("DELETE", "/users/%s" % u["id"], ok404=True); gone.append(n)
        rc, out = run_adm("guard")                    # drops the deleted manager's allowlist entry
        print("cleanup: deleted %s; guard exit %s" % (", ".join(gone) or "nothing", rc), flush=True)
    held = card_holders()
    check("afterwards: no account holds or reserves a test card", not held, held)
    check("afterwards: no account of this check is left", not leftovers(), [u["username"] for u in leftovers()])
    return sum(res), len(res)


if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGHUP, lambda *a: sys.exit(130))
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(130))
    import glob, importlib.machinery, importlib.util, os, socket, subprocess
    ADM = "/usr/local/sbin/idp-admin.py"
    SKILL = (sys.argv[sys.argv.index("--skill") + 1] if "--skill" in sys.argv else
             sorted(glob.glob("/srv/idp/src/keycloak-asd-stig-*/keycloak-asd-stig"), key=os.path.getmtime)[-1])
    ld = importlib.machinery.SourceFileLoader("idp_admin", ADM)
    spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
    kc = M.KC()
    _gai = socket.getaddrinfo
    socket.getaddrinfo = lambda h, p, *r, **k: _gai("127.0.0.1", M.ADMIN_PORT, *r, **k) if h == M.ADMIN_HOST else _gai(h, p, *r, **k)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import persona      # noqa: E402
    sys.path.insert(0, os.path.join(SKILL, "scripts")); import e2e_check as E            # noqa: E402
    def run_adm(*args):
        p_ = subprocess.run([sys.executable, ADM] + list(args), capture_output=True, text=True, timeout=600)
        return p_.returncode, (p_.stdout + p_.stderr).strip()
    n, t = run(M, kc, E, persona, run_adm, "https://%s" % M.ADMIN_HOST, M.REALM)
    print("\n%d/%d passed" % (n, t)); sys.exit(0 if t and n == t else 1)

#!/usr/bin/env python3
"""Live test of the delegates' account powers (review 2026-11-10, option (a)). Runs ON the VM as root, inside the
Keycloak container's network namespace (it joins it itself). Callers: a throwaway user manager (service account in
/roles/idp-user-manager) and app-a's real delegate (app-a-admin). Creates t.acc.* accounts and removes them.
Set-up e-mail goes to addresses at the IdP's own sending domain, which has no mailboxes.

  sudo python3 accounts_endpoint_test.py

  app-a's delegate: every stig-accounts call 403; lists group members and a member's groups and moves members.
  /admin/realms/<realm>/stig-accounts (the user manager): create + set-up mail (201), re-send while in set-up (204, then 429), disable
  (204); refused: a group outside the delegation (403), username/e-mail in use (409), malformed (400), re-send to a
  set-up account (409), an administrator / outsider / member also outside the delegation (403), ANY re-enable (403),
  any other path (403). Each call is an admin event attributed to the caller.
  Plain admin API, as each delegate: 403 for edit, e-mail, enable, password, credentials, identity-provider link,
  execute-actions, delete, create, a move into /roles/*, a role mapping, an outsider and an administrator.
"""
import importlib.machinery, importlib.util, json, os, socket, subprocess, sys, time, urllib.error, urllib.parse, urllib.request, uuid

ADM = "/usr/local/sbin/idp-admin.py"
SKILL = (sys.argv[sys.argv.index("--skill") + 1] if "--skill" in sys.argv else
         sorted(__import__("glob").glob("/srv/idp/src/keycloak-asd-stig-*/keycloak-asd-stig"), key=__import__("os").path.getmtime)[-1])
ld = importlib.machinery.SourceFileLoader("idp_admin", ADM)
spec = importlib.util.spec_from_loader("idp_admin", ld); M = importlib.util.module_from_spec(spec); ld.exec_module(M)
kc = M.KC()
HOST, PORT, REALM = M.ADMIN_HOST, M.ADMIN_PORT, M.REALM
_gai = socket.getaddrinfo
socket.getaddrinfo = lambda h, p, *r, **k: _gai("127.0.0.1", PORT, *r, **k) if h == HOST else _gai(h, p, *r, **k)
BASE = "https://%s" % HOST
STAMP = time.strftime("%H%M%S")
MAILDOM = "notify.example.mil"
res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s  %-82s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

def call(tok, method, path, body=None):
    tok = tok() if callable(tok) else tok          # a person's token source refreshes itself
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            t = r.read().decode(); return r.status, (json.loads(t) if t.strip().startswith(("{", "[")) else t)
    except urllib.error.HTTPError as e:
        t = e.read().decode(); return e.code, (json.loads(t) if t.strip().startswith(("{", "[")) else t)

def token(cid, secret):
    data = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": cid, "client_secret": secret}).encode()
    with urllib.request.urlopen(urllib.request.Request("%s/realms/%s/protocol/openid-connect/token" % (BASE, REALM), data=data), timeout=30) as r:
        return json.loads(r.read())["access_token"]

made_users, made_clients = [], []
delegate_old_domains = realm_old_domains = None
def mk(name, groups=(), password=None, actions=(), email=True):
    rep = {"username": name, "firstName": "T", "lastName": "Acc", "enabled": True, "groups": list(groups), "requiredActions": list(actions)}
    if email: rep["email"] = "%s@%s" % (name, MAILDOM)
    if password: rep["credentials"] = [{"type": "password", "value": "Ta1!" + uuid.uuid4().hex, "temporary": False}]
    kc.api("POST", "/users", rep); made_users.append(name)
    return M.user(kc, name)

EP = "/admin/realms/%s/stig-accounts" % REALM
try:
    # ---------------------------------------------------------------- callers
    rmc = M.client_uuid(kc, "realm-management")
    # set-up mail goes to the IdP's own sending domain in tests: add it to the realm's (a person caller's) and app-a's
    # client's allowed domains for the run (both restored after)
    DOMS = "stig.accounts.email-domains"
    def set_domains(client_rep, value):
        cr = kc.api("GET", "/clients/%s" % client_rep["id"]); at = dict(cr.get("attributes") or {})
        old = at.get(DOMS)
        if value is None: at.pop(DOMS, None)
        else: at[DOMS] = value
        cr["attributes"] = at; kc.api("PUT", "/clients/%s" % client_rep["id"], cr)
        return old
    def set_realm_domains(value):
        at = dict(kc.api("GET", "").get("attributes") or {}); old = at.get(DOMS)
        if value is None: at.pop(DOMS, None)
        else: at[DOMS] = value
        kc.api("PUT", "", {"attributes": at}); return old
    realm_old_domains = set_realm_domains(".mil,example.mil," + MAILDOM)
    sys.path.insert(0, "/root/idp-deploy/tests"); import persona       # noqa: E402
    sys.path.insert(0, os.path.join(SKILL, "scripts")); import e2e_check as E    # noqa: E402
    def run_adm(*args):
        p_ = subprocess.run([sys.executable, ADM] + list(args), capture_output=True, text=True, timeout=600)
        return p_.returncode, (p_.stdout + p_.stderr).strip()
    um_p = persona.Person(M, kc, E, run_adm, BASE, REALM, "t.acc.mgr%s" % STAMP, "idp-user-manager"); made_users.append(um_p.username)
    callers = {"user-manager": (um_p.token, um_p.user["id"], "/app-b/member"), "app-a delegate": None}
    dcl = kc.api("GET", "/clients?clientId=app-a-admin")[0]
    delegate_sa = kc.api("GET", "/clients/%s/service-account-user" % dcl["id"])
    delegate_old_domains = set_domains(kc.api("GET", "/clients?clientId=app-a-admin")[0], ".mil,example.mil," + MAILDOM)
    callers["app-a delegate"] = (token("app-a-admin", kc.api("GET", "/clients/%s/client-secret" % dcl["id"])["value"]), delegate_sa["id"],
                                 "/app-a/viewer")
    opadm = M.user(kc, "op.admin")
    kc.api("POST", "/groups", {"name": "t-acc-elsewhere%s" % STAMP})          # a group nobody is delegated
    ELSEWHERE = "/t-acc-elsewhere%s" % STAMP
    elsewhere = mk("t.acc.elsewhere%s" % STAMP, groups=["/app-b/member", ELSEWHERE], actions=["UPDATE_PASSWORD", "CONFIGURE_TOTP"])
    outsider = mk("t.acc.outsider%s" % STAMP)
    both = mk("t.acc.both%s" % STAMP, groups=["/app-b/member", "/app-a/viewer"], actions=["UPDATE_PASSWORD", "CONFIGURE_TOTP"])

    for who, (tok, sa_id, grp) in callers.items():
        # the user manager is a delegate of every application tree; app-a's of its own only
        other = ELSEWHERE if who == "user-manager" else "/app-b/member"
        mixed = elsewhere if who == "user-manager" else both
        tag = "um" if who == "user-manager" else "dg"
        if who == "user-manager":
            # ---------------------------------------------------------------- allowed
            uname, mail = "t.acc.%s%s" % (tag, STAMP), "t.acc.%s%s@%s" % (tag, STAMP, MAILDOM)
            st, body = call(tok, "POST", EP + "/users", {"username": uname, "email": mail, "firstName": "Test", "lastName": "Account", "group": grp})
            made_users.append(uname)
            check("%s: create %s into %s + set-up mail" % (who, uname, grp), st == 201 and isinstance(body, dict) and body.get("setupEmail") == "sent",
                  "HTTP %s %s" % (st, body if st != 201 else body.get("setupEmail")))
            new = M.user(kc, uname)
            ev = kc.api("GET", "/admin-events?authUser=%s&resourcePath=%s&max=20" % (sa_id, M.q("users/%s*" % new["id"])))
            ops = sorted({(e["operationType"], e["resourcePath"].split("/")[-1] if e["resourcePath"].count("/") > 1 else "user") for e in ev})
            check("%s: ... admin events attributed to the caller (create + set-up mail)" % who, ("CREATE", "user") in ops and
                  ("ACTION", "execute-actions-email") in ops, "%s" % ops)
            check("%s: ... the account is in its group, set-up pending, no credential" % who,
                  [g["path"] for g in M.paged(kc, "/users/%s/groups" % new["id"])] == [grp] and
                  {"UPDATE_PASSWORD", "CONFIGURE_TOTP"} <= set(new.get("requiredActions") or []) and not kc.api("GET", "/users/%s/credentials" % new["id"]))
            st, _ = call(tok, "POST", EP + "/users/%s/setup-email" % new["id"])
            check("%s: re-send right after create -> 429 (once per 15 min)" % who, st == 429, "HTTP %s" % st)
            fresh = mk("t.acc.fresh%s%s" % (tag, STAMP), groups=[grp], actions=["UPDATE_PASSWORD", "CONFIGURE_TOTP", "TERMS_AND_CONDITIONS"])
            st, _ = call(tok, "POST", EP + "/users/%s/setup-email" % fresh["id"])
            check("%s: re-send to an account still in set-up -> 204" % who, st == 204, "HTTP %s" % st)
            st, _ = call(tok, "POST", EP + "/users/%s/setup-email" % fresh["id"])
            check("%s: ... again at once -> 429" % who, st == 429, "HTTP %s" % st)
            member = mk("t.acc.member%s%s" % (tag, STAMP), groups=[grp], password=True)
            st1, _ = call(tok, "POST", EP + "/users/%s/disable" % member["id"])
            off = kc.api("GET", "/users/%s" % member["id"])
            ev = kc.api("GET", "/admin-events?authUser=%s&resourcePath=%s&operationTypes=UPDATE&max=5" % (sa_id, M.q("users/%s" % member["id"])))
            check("%s: disable a member -> 204, disabled, admin event attributed to the caller" % who, st1 == 204 and off["enabled"] is False and ev,
                  "HTTP %s, events %d" % (st1, len(ev)))
            tries = [call(tok, "PUT", EP + "/users/%s/enabled" % member["id"], {"enabled": True})[0],
                     call(tok, "POST", EP + "/users/%s/enable" % member["id"])[0],
                     call(tok, "PUT", "/admin/realms/%s/users/%s" % (REALM, member["id"]), {"enabled": True})[0]]
            check("%s: re-enable it (endpoint PUT enabled, POST enable, plain admin API) -> 403 each; stays disabled" % who,
                  all(t in (403, 404) for t in tries) and kc.api("GET", "/users/%s" % member["id"])["enabled"] is False, "HTTP %s" % tries)
            r = kc.api("GET", "/users/%s" % member["id"]); kc.api("PUT", "/users/%s" % member["id"], dict(r, enabled=True))   # an admin re-enables
            # ---------------------------------------------------------------- refused by the endpoint
            for label, body_, want in (
                    ("into /roles/idp-admin", {"group": "/roles/idp-admin"}, 403),
                    ("into a group outside its delegation (%s)" % other, {"group": other}, 403),
                    ("into a group that does not exist", {"group": "/nope/none"}, 403),
                    ("username already in use", {"username": uname}, 409),
                    ("e-mail already in use", {"email": mail}, 409),
                    ("username not first.last", {"username": "Bad Name"}, 400),
                    ("malformed e-mail", {"email": "a@b@c"}, 400),
                    ("lifespan over 24 h", {"lifespan": 90000}, 400)):
                b = {"username": "t.acc.x%s%s" % (tag, uuid.uuid4().hex[:6]), "email": "t.acc.x%s@%s" % (uuid.uuid4().hex[:8], MAILDOM),
                     "firstName": "T", "lastName": "X", "group": grp}
                b.update(body_)
                st, _ = call(tok, "POST", EP + "/users", b)
                if st == 201: made_users.append(b["username"])
                check("%s: create %s -> %s" % (who, label, want), st == want, "HTTP %s" % st)
            st, _ = call(tok, "POST", EP + "/users/%s/setup-email" % member["id"])
            check("%s: re-send to an account already set up -> 409" % who, st == 409, "HTTP %s" % st)
            for label, tgt in (("an administrator (the operator)", opadm), ("an outsider", outsider), ("a member also in a group outside its delegation", mixed)):
                s1, _ = call(tok, "POST", EP + "/users/%s/setup-email" % tgt["id"])
                s2, _ = call(tok, "POST", EP + "/users/%s/disable" % tgt["id"])
                check("%s: re-send / disable %s -> 403" % (who, label), (s1, s2) == (403, 403), "HTTP %s/%s" % (s1, s2))
            # an administrator's disablement is not the delegate's to undo
            adm_off = mk("t.acc.admoff%s%s" % (tag, STAMP), groups=[grp], password=True)
            kc.api("PUT", "/users/%s" % adm_off["id"], dict(kc.api("GET", "/users/%s" % adm_off["id"]), enabled=False))
            st, _ = call(tok, "PUT", EP + "/users/%s/enabled" % adm_off["id"], {"enabled": True})
            check("%s: enable what an administrator disabled -> 403, stays disabled" % who, st in (403, 404) and
                  kc.api("GET", "/users/%s" % adm_off["id"])["enabled"] is False, "HTTP %s" % st)
            s1, _ = call(tok, "GET", EP + "/users")
            s2, _ = call(tok, "DELETE", EP + "/users/%s" % new["id"])
            s3, _ = call(tok, "PUT", EP + "/users/%s" % new["id"], {"email": "evil@%s" % MAILDOM})
            check("%s: any other endpoint path or method -> 403" % who, (s1, s2, s3) == (403, 403, 403), "GET %s, DELETE %s, PUT %s" % (s1, s2, s3))
        else:
            # by design app-a creates no accounts - the operator invites; app-a lists members and moves them
            plain_m = mk("t.acc.lcm%s" % STAMP, groups=[grp], actions=["UPDATE_PASSWORD", "CONFIGURE_TOTP"])
            ep = [call(tok, "POST", EP + "/users", {"username": "t.acc.lcx%s" % STAMP, "email": "t.acc.lcx%s@%s" % (STAMP, MAILDOM),
                                                    "firstName": "T", "lastName": "X", "group": grp})[0],
                  call(tok, "POST", EP + "/users/%s/setup-email" % plain_m["id"])[0],
                  call(tok, "POST", EP + "/users/%s/disable" % plain_m["id"])[0],
                  call(tok, "GET", EP + "/users")[0]]
            made_users.append("t.acc.lcx%s" % STAMP)
            check("%s: stig-accounts create / re-send / disable / anything -> 403 (no account powers at all)" % who, ep == [403, 403, 403, 403]
                  and kc.api("GET", "/users/%s" % plain_m["id"])["enabled"] is True and not kc.api("GET", "/users?exact=true&username=t.acc.lcx%s" % STAMP),
                  "HTTP %s" % ep)
            A_ = "/admin/realms/%s" % REALM
            role_g = M.group_by_path(kc, grp)
            s1, gb = call(tok, "GET", A_ + "/group-by-path/%s" % grp.strip("/"))
            s2, mb = call(tok, "GET", A_ + "/groups/%s/members" % role_g["id"])
            s3, ug = call(tok, "GET", A_ + "/users/%s/groups" % plain_m["id"])
            check("%s: GET group-by-path, group members, a member's groups -> 200" % who,
                  (s1, s2, s3) == (200, 200, 200) and isinstance(gb, dict) and gb.get("id") == role_g["id"]
                  and plain_m["id"] in [x["id"] for x in mb] and grp in [x["path"] for x in ug], "HTTP %s/%s/%s" % (s1, s2, s3))
        # ---------------------------------------------------------------- the plain admin API refuses the rest
        A = "/admin/realms/%s" % REALM
        tgt = mk("t.acc.plain%s%s" % (tag, STAMP), groups=[grp], password=True)
        cred = kc.api("GET", "/users/%s/credentials" % tgt["id"])[0]["id"]
        app = grp.strip("/").split("/")[0]; appc = kc.api("GET", "/clients?clientId=%s" % app)[0]
        role = kc.api("GET", "/clients/%s/roles" % appc["id"])[0]
        plain = {
            "edit a member's name": ("PUT", "/users/%s" % tgt["id"], {"firstName": "Hijacked"}),
            "change a member's e-mail": ("PUT", "/users/%s" % tgt["id"], {"email": "evil.%s@%s" % (tag, MAILDOM)}),
            "enable/disable through the admin API": ("PUT", "/users/%s" % tgt["id"], {"enabled": False}),
            "reset a member's password": ("PUT", "/users/%s/reset-password" % tgt["id"], {"type": "password", "value": "Hijack-123456789!", "temporary": False}),
            "delete a member's credential": ("DELETE", "/users/%s/credentials/%s" % (tgt["id"], cred), None),
            "add an identity-provider link": ("POST", "/users/%s/federated-identity/entra" % tgt["id"], {"identityProvider": "entra", "userId": str(uuid.uuid4()), "userName": "evil"}),
            "execute-actions e-mail to a member": ("PUT", "/users/%s/execute-actions-email" % tgt["id"], ["UPDATE_PASSWORD"]),
            "delete a member": ("DELETE", "/users/%s" % tgt["id"], None),
            "create a user (outside the endpoint)": ("POST", "/users", {"username": "t.acc.plain.x%s" % tag, "enabled": True, "groups": [grp]}),
            "move a member into /roles/idp-admin": ("PUT", "/users/%s/groups/%s" % (tgt["id"], M.group_by_path(kc, "/roles/idp-admin")["id"]), None),
            "map a client role to a member": ("POST", "/users/%s/role-mappings/clients/%s" % (tgt["id"], appc["id"]), [role]),
            "map realm-admin to a member": ("POST", "/users/%s/role-mappings/clients/%s" % (tgt["id"], rmc),
                                            [kc.api("GET", "/clients/%s/roles/realm-admin" % rmc)]),
            "view an outsider": ("GET", "/users/%s" % outsider["id"], None),
            "view an administrator (the operator)": ("GET", "/users/%s" % opadm["id"], None),
        }
        for label, (m, p, b) in plain.items():
            st, _ = call(tok, m, A + p, b)
            if st in (200, 201, 204) and m == "POST" and p == "/users":
                made_users.append("t.acc.plain.x%s" % tag)
            check("%s: plain admin API, %s -> 403" % (who, label), st in (403, 404), "HTTP %s" % st)
        after = kc.api("GET", "/users/%s" % tgt["id"])
        check("%s: ... the member is untouched (name, e-mail, enabled, credentials, links, groups)" % who,
              after["firstName"] == "T" and after["email"] == tgt["email"] and after["enabled"] is True
              and [x["type"] for x in kc.api("GET", "/users/%s/credentials" % tgt["id"])] == ["password"]
              and not kc.api("GET", "/users/%s/federated-identity" % tgt["id"])
              and [g["path"] for g in M.paged(kc, "/users/%s/groups" % tgt["id"])] == [grp])
        sub = grp.rsplit("/", 1)[0] + "/" + ("maintainer" if grp.startswith("/app-b") else "editor")
        s1, _ = call(tok, "PUT", A + "/users/%s/groups/%s" % (tgt["id"], M.group_by_path(kc, sub)["id"]))
        s2, _ = call(tok, "DELETE", A + "/users/%s/groups/%s" % (tgt["id"], M.group_by_path(kc, grp)["id"]))
        check("%s: plain admin API, move a member between its application's role groups -> 204 (kept)" % who, (s1, s2) == (204, 204), "HTTP %s/%s" % (s1, s2))
        # ---------------------------------------------------------------- review 2026-11-10: relay limits, concealment
        for label, body_, want in (() if who != "user-manager" else (("an e-mail domain outside the caller's list (mail.example.com)", {"email": "t.acc.g%s@mail.example.com" % uuid.uuid4().hex[:6]}, 403),
                                   ("a URL in the first name", {"firstName": "visit https://evil.example"}, 400),
                                   ("a domain as the last name", {"lastName": "evil.com"}, 400))):
            b = {"username": "t.acc.y%s%s" % (tag, uuid.uuid4().hex[:6]), "email": "t.acc.y%s@%s" % (uuid.uuid4().hex[:8], MAILDOM),
                 "firstName": "T", "lastName": "Y", "group": grp}
            b.update(body_)
            st, _ = call(tok, "POST", EP + "/users", b)
            if st == 201: made_users.append(b["username"])
            check("%s: create with %s -> %s" % (who, label, want), st == want, "HTTP %s" % st)
        sec = mk("t.acc.secret%s%s" % (tag, STAMP), groups=[grp])
        edipi_v, oid_v = str(int(time.time() * 1000))[-10:], str(uuid.uuid4())
        r_ = kc.api("GET", "/users/%s" % sec["id"]); r_["attributes"] = {"cac_edipi": [edipi_v], "entra_oid": [oid_v]}
        kc.api("PUT", "/users/%s" % sec["id"], r_)
        conceal = {"cac_edipi", "entra_oid", "entra_vouched_oid", "entra_vouched_tid", "entra_amr", "stig_created_by"}
        st, one = call(tok, "GET", A + "/users/%s" % sec["id"])
        st2, lst = call(tok, "GET", A + "/users?search=%s" % M.q(sec["username"]))
        st3, brief = call(tok, "GET", A + "/users?briefRepresentation=false&max=500")
        st4, mem_ = call(tok, "GET", A + "/groups/%s/members?briefRepresentation=false&max=500" % M.group_by_path(kc, grp)["id"])
        leaks = []
        for nm_, x in (("user", [one] if isinstance(one, dict) else []), ("search", lst if isinstance(lst, list) else []),
                       ("listing", brief if isinstance(brief, list) else []), ("members", mem_ if isinstance(mem_, list) else [])):
            for u_ in x:
                if conceal & set((u_.get("attributes") or {}).keys()): leaks.append("%s:%s" % (nm_, u_.get("username")))
        check("%s: the member's card mapping / Entra binding / creator marker are absent from user, search, listing, members" % who,
              st == 200 and not leaks, "HTTP %s/%s/%s/%s leaks %s" % (st, st2, st3, st4, leaks[:3]))
        probes = [call(tok, "GET", A + "/users?q=%s" % M.q("cac_edipi:" + edipi_v))[0],
                  call(tok, "GET", A + "/users/count?q=%s" % M.q("cac_edipi:" + edipi_v))[0],
                  call(tok, "GET", A + "/users?q=%s" % M.q("entra_oid:" + oid_v))[0],
                  call(tok, "GET", A + "/groups/%s/members?q=%s" % (M.group_by_path(kc, grp)["id"], M.q("cac_edipi:" + edipi_v)))[0]]
        check("%s: searching or counting by a concealed attribute -> 403 (users, count, members)" % who, all(p_ == 403 for p_ in probes), "HTTP %s" % probes)
        if who != "user-manager":
            continue
        mine = kc.api("GET", "/users/%s" % new["id"])
        check("%s: ... while the operator's tooling (master realm) still sees them (creator marker on the account it created)" % who,
              ((mine.get("attributes") or {}).get("stig_created_by") or [""])[0].startswith(um_p.username + " "), "%s" % (mine.get("attributes") or {}).get("stig_created_by"))
    # ---------------------------------------------------------------- the creation cap holds under concurrency
    rate_p = persona.Person(M, kc, E, run_adm, BASE, REALM, "t.acc.rate%s" % STAMP, "idp-user-manager"); made_users.append(rate_p.username)
    rtok = rate_p.token()
    import concurrent.futures
    names = ["t.acc.rate%s.n%02d" % (STAMP, i) for i in range(25)]
    made_users.extend(names)
    def one_create(n):
        return call(rtok, "POST", EP + "/users", {"username": n, "email": "%s@%s" % (n.replace(".", "-"), MAILDOM), "firstName": "Rate",
                                                  "lastName": "Test", "group": "/app-b/member"})[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
        codes = list(ex.map(one_create, names))
    check("25 concurrent creations by one caller -> exactly 20 created, 5 refused (429)", codes.count(201) == 20 and codes.count(429) == 5,
          "201 x%d, 429 x%d, other %s" % (codes.count(201), codes.count(429), sorted(set(c_ for c_ in codes if c_ not in (201, 429)))))
finally:
    try:
        set_realm_domains(realm_old_domains)
        set_domains(kc.api("GET", "/clients?clientId=app-a-admin")[0], delegate_old_domains)
    except Exception as e:      # noqa: BLE001
        print("cleanup: app-a e-mail domains: %s" % e)
    for n in made_users:
        f = kc.api("GET", "/users?exact=true&username=%s" % M.q(n))
        if f: kc.api("DELETE", "/users/%s" % f[0]["id"])
    g_ = M.group_by_path(kc, "/t-acc-elsewhere%s" % STAMP)
    if g_: kc.api("DELETE", "/groups/%s" % g_["id"])
    for cid_ in made_clients:
        f = kc.api("GET", "/clients?clientId=%s" % cid_)
        if f: kc.api("DELETE", "/clients/%s" % f[0]["id"])
print("\n%d/%d passed" % (sum(res), len(res))); sys.exit(0 if all(res) else 1)

#!/usr/bin/env python3
"""A delegated account administrator for ONE application, with Keycloak 26 fine-grained admin permissions (v2).

The confidential client `<app>-admin` gets a service account that may:
  - view the members of group `<app>` and its subgroups (and nobody else) and move them between those subgroups. It
    holds no `manage-members`: no editing, e-mail change, password reset, credential or identity-provider-link change,
    execute-actions mail or deletion - and no stig-accounts either (by design): the operator invites people
    into `<app>/<ROLE>`; the application only lists members and moves them between role groups. It never sees or
    sets a card identity (cac_edipi: realm administrators only, unique - cac-identity-guard; concealed from
    delegates);
  - give and take `<app>` client roles, as membership of the subgroups `<app>/<ROLE>`, each of which carries exactly
    that one client role (mapped by the realm admin at setup). The service account has NO role-mapping permission
    at all, so it cannot grant another client's roles, realm roles or realm-management roles, nor change what a
    subgroup grants (that needs `manage` on the group, which it does not have).
Why groups: FGAP v2 has no "users holding role X" resource, and its policies judge the CALLER, not the target user.
In Keycloak 26.8.2 a Clients `map-roles` grant plus group `manage-members` still refuses role mapping on a member
(it also needs Users `map-roles`, which can only be granted per user or for ALL users). Subgroups carrying the roles
keep every application change inside the group tree.

Since the per-group split `setup` grants NO membership write: who writes which /<app>/<ROLE> group is idp-admin.py APP_DELEGATIONS (its config file),
applied per group by `idp-admin.py roles-setup`. `setup` gives the tree only sight (view, view-members,
manage-membership-of-members) and REFUSES, before touching the tree's aggregate or permission, any realm that is not
fully split and consistent with APP_DELEGATIONS (a group without its own write permission, the tree still holding a
tree-wide write, or the app's administrator among the writers of a group it is not listed for): run roles-setup first.

  app_admin_fgap.py --url https://kc --realm R setup --app <client> [--enroll-existing] [--admin-script idp-admin.py]
  app_admin_fgap.py --url https://kc --realm R test  --app <client> --sa-secret-file F | --sa-jwt-key PEM
Admin credentials for setup/test bookkeeping: --admin-user + --admin-password-file (master realm, admin-cli) or
--admin-client-id + --admin-secret-file. Prints no secrets. `test` creates and deletes its own throwaway users.
"""
import argparse, json, os, ssl, sys, urllib.error, urllib.parse, urllib.request

def q(s): return urllib.parse.quote(s, safe="")

class KC:
    def __init__(self, url, realm, token_form, cafile=None):
        self.url, self.realm = url.rstrip("/"), realm
        self.ctx = ssl.create_default_context(cafile=cafile)
        st, body = self.raw("POST", "/realms/%s/protocol/openid-connect/token" % token_form.pop("_realm"),
                            urllib.parse.urlencode(token_form).encode(), {"Content-Type": "application/x-www-form-urlencoded"}, auth=False)
        if st != 200:
            sys.exit("login failed: HTTP %s %s" % (st, body[:200]))
        self.token = json.loads(body)["access_token"]
    def raw(self, method, path, body=None, headers=None, auth=True):
        h = dict(headers or {})
        if auth: h["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.url + path, data=body, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=60) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
    def api(self, method, path, obj=None, expect=(200, 201, 204)):
        st, body = self.raw(method, "/admin/realms/%s%s" % (self.realm, path), json.dumps(obj).encode() if obj is not None else None,
                            {"Content-Type": "application/json"} if obj is not None else {})
        if expect and st not in expect:
            sys.exit("%s %s -> %s %s" % (method, path, st, body[:300]))
        return st, (json.loads(body) if body.strip().startswith(("{", "[")) else body)

def admin_kc(a):
    if a.admin_client_id:
        form = {"_realm": "master", "grant_type": "client_credentials", "client_id": a.admin_client_id,
                "client_secret": open(a.admin_secret_file).read().strip()}
    else:
        form = {"_realm": "master", "grant_type": "password", "client_id": "admin-cli", "username": a.admin_user,
                "password": open(a.admin_password_file).read().strip()}
    return KC(a.url, a.realm, form, a.cacert)

def one(kc, path, key, val):
    _, xs = kc.api("GET", path)
    xs = [x for x in xs if x.get(key) == val]
    return xs[0] if xs else None

TREE_SCOPES = ["view", "view-members", "manage-membership-of-members"]     # = idp-admin.py TREE_SCOPES

def app_delegations(a):
    """APP_DELEGATIONS out of idp-admin.py (the single source of who may write which group)."""
    import importlib.machinery, importlib.util
    ld = importlib.machinery.SourceFileLoader("idp_admin_cfg", a.admin_script)
    spec = importlib.util.spec_from_loader("idp_admin_cfg", ld); m = importlib.util.module_from_spec(spec); ld.exec_module(m)
    return m.APP_DELEGATIONS

def split_problems(kc, base, app, sa_id, sa_policy_id, grp, subs, tree_perm_name, listed=None):
    """Why this realm is NOT safely split for `app` (empty = it is): every group of the tree must have its own
    `membership: <path>` permission (manage-membership on exactly that group) whose aggregate holds the app's
    administrator iff APP_DELEGATIONS lists the group for it (never the root, never an unlisted new role), and the
    tree permission must carry no manage-membership. Any API answer it cannot read counts as a problem."""
    out = []
    listed = set(listed or ())
    def named(kind, n):
        st, xs = kc.api("GET", base + "/%s?name=%s" % (kind, q(n)), expect=None)
        if st != 200:
            out.append("cannot read %s %r (HTTP %s)" % (kind, n, st)); return []
        return [x for x in xs if x["name"] == n]
    tree = [("/" + app, grp["id"], "")] + [("/%s/%s" % (app, n), g["id"], n) for n, g in sorted(subs.items())]
    for path, gid, gname in tree:
        perm = named("permission", "membership: " + path)
        if not perm:
            out.append("%s has no per-group write permission `membership: %s`" % (path, path)); continue
        pid = perm[0]["id"]
        res = sorted(r["name"] for r in kc.api("GET", base + "/permission/%s/resources" % pid)[1])
        sc = sorted(x["name"] for x in kc.api("GET", base + "/permission/%s/scopes" % pid)[1])
        if res != [gid] or sc != ["manage-membership"]:
            out.append("`membership: %s` is not manage-membership on exactly that group (%s, %s)" % (path, res, sc)); continue
        pols = kc.api("GET", base + "/policy/%s/associatedPolicies" % pid)[1]
        writers = {x["id"] for p_ in pols for x in (kc.api("GET", base + "/policy/%s/associatedPolicies" % p_["id"])[1]
                                                     if p_.get("type") == "aggregate" else [p_])}
        may = gname in listed
        if (sa_policy_id in writers) != may:
            out.append("%s: %s %s write it, but APP_DELEGATIONS says it %s" % (path, sa_id, "can" if sa_policy_id in writers else "cannot",
                                                                            "may" if may else "may NOT"))
    tp = named("permission", tree_perm_name)
    if tp:
        sc = [x["name"] for x in kc.api("GET", base + "/permission/%s/scopes" % tp[0]["id"])[1]]
        if "manage-membership" in sc:
            out.append("`%s` still carries a TREE-WIDE manage-membership (the earlier shape)" % tree_perm_name)
    return out

def paged_get(kc, path, size=500):
    """Every item of a list endpoint (first/max paging), however many there are."""
    out, first = [], 0
    sep = "&" if "?" in path else "?"
    while True:
        _, page = kc.api("GET", "%s%sfirst=%d&max=%d" % (path, sep, first, size))
        out += page or []
        if not page or len(page) < size:
            return out
        first += size

def default_role_ids(kc):
    """Every role id the realm's default role (default-roles-<realm>) grants, composites expanded: what EVERY user holds
    (e.g. account:view-profile, manage-account and its manage-account-links), so it says nothing about a person."""
    _, realm = kc.api("GET", "")
    start = ((realm or {}).get("defaultRole") or {}).get("id")
    seen, todo = set(), [start] if start else []
    while todo:
        rid = todo.pop()
        if rid in seen:
            continue
        seen.add(rid)
        _, comps = kc.api("GET", "/roles-by-id/%s/composites" % rid)
        todo += [c["id"] for c in comps or [] if c.get("id") and c["id"] not in seen]
    return seen

def enroll_refusal(kc, u, app, rm_id, allowlisted, other_clients=(), defaults=frozenset()):
    """Why the account `u` must NOT be moved under the app's delegation (None = it may be). Moving it into /<app>/<ROLE>
    puts it in reach of the app's administrator, so anything that makes it more than an ordinary member of this one
    application refuses it - judged on EFFECTIVE roles (groups and composites included), not direct mappings only:
      - any realm-management role, however it arrives (an IdP administrator or user manager);
      - membership of any group outside /<app> (the /roles/* role catalogue, another application's tree, anything else);
      - a service account;
      - a role of another client, direct or effective, beyond the realm's default roles (re-pointing that account
        would reach that application);
      - an identity binding (cac_edipi, entra_oid) - as idp-admin.py user-create-cac --existing refuses one;
      - an entry in the vetted-administrator allowlist."""
    if u["id"] in allowlisted:
        return "on the administrator allowlist"
    if (u.get("username") or "").startswith("service-account-") or u.get("serviceAccountClientId"):
        return "a service account"
    _, eff = kc.api("GET", "/users/%s/role-mappings/clients/%s/composite" % (u["id"], rm_id))
    if eff:
        return "holds realm-management role(s) %s (effective)" % sorted(r["name"] for r in eff)
    gs = paged_get(kc, "/users/%s/groups?briefRepresentation=false" % u["id"])
    outside = sorted(g["path"] for g in gs if not (g["path"] == "/" + app or g["path"].startswith("/%s/" % app)))
    if outside:
        return "member of %s" % outside
    _, rm = kc.api("GET", "/users/%s/role-mappings" % u["id"])
    others = sorted(k for k in (rm.get("clientMappings") or {}) if k != app)
    if others:   # managing this account would let the app admin re-point someone else's card login
        return "also holds roles of %s" % others
    # effective roles of every other client (through a composite of a realm or app role)
    for oc in other_clients:
        _, eff_o = kc.api("GET", "/users/%s/role-mappings/clients/%s/composite" % (u["id"], oc["id"]))
        if [r for r in eff_o or [] if r.get("id") not in defaults]:       # beyond what every user holds
            return "holds roles of %s (effective)" % oc["clientId"]
    _, full = kc.api("GET", "/users/%s" % u["id"])
    bound = sorted(k for k in ("cac_edipi", "entra_oid") if (full.get("attributes") or {}).get(k))
    if bound:
        return "carries identity binding(s) %s" % bound
    return None

def master_allowlist(kc):
    """The vetted administrators' ids, as idp-admin.py publishes them on the master realm (stig.admin-allowlist.<realm>).
    Unreadable -> refuse to enroll anyone (fail closed)."""
    st, body = kc.raw("GET", "/admin/realms/master")
    if st != 200:
        sys.exit("REFUSED: cannot read the master realm's administrator allowlist (HTTP %s): not enrolling anyone" % st)
    v = (json.loads(body).get("attributes") or {}).get("stig.admin-allowlist.%s" % kc.realm) or ""
    return {x for x in v.split(",") if x}

def setup(a):
    kc = admin_kc(a); app, sa_id = a.app, a.app + "-admin"
    _, realm = kc.api("GET", "")
    if not realm.get("adminPermissionsEnabled"):
        kc.api("PUT", "", {"adminPermissionsEnabled": True}); print("realm: fine-grained admin permissions (v2) enabled")
    grp = one(kc, "/groups?search=%s&exact=true" % q(app), "name", app)
    if not grp:
        kc.api("POST", "/groups", {"name": app}); grp = one(kc, "/groups?search=%s&exact=true" % q(app), "name", app)
        print("group %s created" % app)
    appc = one(kc, "/clients?clientId=%s" % q(app), "clientId", app) or sys.exit("no client %s" % app)
    sac = one(kc, "/clients?clientId=%s" % q(sa_id), "clientId", sa_id)
    if not sac:
        kc.api("POST", "/clients", {"clientId": sa_id, "name": "%s account administrator" % app, "protocol": "openid-connect",
               "publicClient": False, "serviceAccountsEnabled": True, "standardFlowEnabled": False, "implicitFlowEnabled": False,
               "directAccessGrantsEnabled": False, "fullScopeAllowed": False, "clientAuthenticatorType": "client-secret",
               "attributes": {"oauth2.device.authorization.grant.enabled": "false", "oidc.ciba.grant.enabled": "false",
                              "client_credentials.use_refresh_token": "false"}})
        sac = one(kc, "/clients?clientId=%s" % q(sa_id), "clientId", sa_id); print("client %s created (service account)" % sa_id)
    # the admin API audience, without which every admin call is 401 on 26.8 (keycloak-notes.md)
    _, scopes = kc.api("GET", "/client-scopes")
    api_scope = [s for s in scopes if s["name"] == "kc-admin-api"]
    if api_scope:
        kc.api("PUT", "/clients/%s/default-client-scopes/%s" % (sac["id"], api_scope[0]["id"]))
    ap = one(kc, "/clients?clientId=admin-permissions", "clientId", "admin-permissions") or sys.exit("admin-permissions client missing (FGAP v2 off?)")
    base = "/clients/%s/authz/resource-server" % ap["id"]
    pol = "%s-admin service account" % app
    _, pols = kc.api("GET", base + "/policy?name=%s" % q(pol))
    if not [p for p in pols if p["name"] == pol]:
        kc.api("POST", base + "/policy/client", {"name": pol, "logic": "POSITIVE", "clients": [sac["id"]]})
    pid = [p for p in kc.api("GET", base + "/policy?name=%s" % q(pol))[1] if p["name"] == pol][0]["id"]
    # one subgroup per client role, carrying exactly that role
    _, roles = kc.api("GET", "/clients/%s/roles" % appc["id"])
    _, subs = kc.api("GET", "/groups/%s/children?max=1000" % grp["id"])
    subs = {g["name"]: g for g in subs}
    for r in roles:
        if r["name"] not in subs:
            kc.api("POST", "/groups/%s/children" % grp["id"], {"name": r["name"]})
            _, ch = kc.api("GET", "/groups/%s/children?max=1000" % grp["id"]); subs = {g["name"]: g for g in ch}
        g = subs[r["name"]]
        _, have = kc.api("GET", "/groups/%s/role-mappings/clients/%s" % (g["id"], appc["id"]))
        if [x["name"] for x in have] != [r["name"]]:
            if have: kc.api("DELETE", "/groups/%s/role-mappings/clients/%s" % (g["id"], appc["id"]), have)
            kc.api("POST", "/groups/%s/role-mappings/clients/%s" % (g["id"], appc["id"]), [r])
    print("subgroups %s/{%s}, each carrying its one client role" % (app, ",".join(sorted(subs))))
    # drop the earlier role-mapping design if present
    old = "%s: map %s client roles" % (sa_id, app)
    for p in kc.api("GET", base + "/permission?name=%s" % q(old))[1]:
        if p["name"] == old: kc.api("DELETE", base + "/permission/%s" % p["id"])
    # One permission per application group tree, shared with the IdP's user managers (`idp-admin.py roles-setup`):
    # admin permissions must be UNANIMOUS and Keycloak 26.8 combines separate permissions on one group unanimously,
    # so every delegation covering the tree is a member of ONE AFFIRMATIVE aggregate policy.
    name, agg_name = "delegated: /%s" % app, "delegates of /%s" % app
    gids = [grp["id"]] + [g["id"] for g in subs.values()]
    # the per-group split, fail closed: membership WRITES belong to `idp-admin.py roles-setup` alone (per-group `membership:`
    # permissions, APP_DELEGATIONS). This setup never grants a write, and refuses - before touching the tree's
    # aggregate or permission - unless the realm is fully split and consistent with APP_DELEGATIONS.
    dele = app_delegations(a).get(app, {})
    if sa_id not in dele:
        sys.exit("REFUSED: %s is not a delegation of %s in idp-admin.py APP_DELEGATIONS" % (sa_id, app))
    problems = split_problems(kc, base, app, sa_id, pid, grp, subs, name, dele[sa_id])
    if problems:
        sys.exit("REFUSED (nothing granted; the tree permission and its aggregate untouched):\n  - %s\n"
                 "Run `sudo idp-admin.py roles-setup` (it writes the per-group permissions from APP_DELEGATIONS), then "
                 "re-run this setup." % "\n  - ".join(problems))
    agg = [p for p in kc.api("GET", base + "/policy?name=%s" % q(agg_name))[1] if p["name"] == agg_name]
    members = {pid} | ({x["id"] for x in kc.api("GET", base + "/policy/%s/associatedPolicies" % agg[0]["id"])[1]} if agg else set())
    arep = {"name": agg_name, "type": "aggregate", "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE", "policies": sorted(members)}
    if agg:
        arep["id"] = agg[0]["id"]; kc.api("PUT", base + "/policy/aggregate/%s" % agg[0]["id"], arep)
    else:
        kc.api("POST", base + "/policy/aggregate", arep)
    aid = [p for p in kc.api("GET", base + "/policy?name=%s" % q(agg_name))[1] if p["name"] == agg_name][0]["id"]
    ex = [p for p in kc.api("GET", base + "/permission?name=%s" % q(name))[1] if p["name"] == name]
    scopes = list(TREE_SCOPES)          # never manage-membership: see split_problems
    rep = {"name": name, "resourceType": "Groups", "resources": gids, "policies": [aid], "decisionStrategy": "UNANIMOUS",
           "scopes": scopes}   # sight only: idp-admin.py TREE_SCOPES
    if ex:
        rep["id"] = ex[0]["id"]; kc.api("PUT", base + "/permission/scope/%s" % rep["id"], rep)
    else:
        kc.api("POST", base + "/permission/scope", rep)
    for old in ("%s: members of group %s" % (sa_id, app), "%s: map %s client roles" % (sa_id, app)):
        for p in kc.api("GET", base + "/permission?name=%s" % q(old))[1]:
            if p["name"] == old:
                kc.api("DELETE", base + "/permission/%s" % p["id"])
    print("permission: %s (aggregate of %d delegation policies; sight only - membership writes are roles-setup's, per group)"
          % (name, len(members)))
    if a.enroll_existing:
        _, roles = kc.api("GET", "/clients/%s/roles" % appc["id"]); seen = set()
        rmc = one(kc, "/clients?clientId=realm-management", "clientId", "realm-management") or sys.exit("no realm-management client")
        allowlisted = master_allowlist(kc)
        other_clients = [c for c in paged_get(kc, "/clients") if c["clientId"] not in (app, "realm-management")]
        defaults = default_role_ids(kc)
        for r in roles:
            us = paged_get(kc, "/clients/%s/roles/%s/users" % (appc["id"], q(r["name"])))
            for u in us:
                if u["id"] in seen: continue
                seen.add(u["id"])
                why = enroll_refusal(kc, u, app, rmc["id"], allowlisted, other_clients, defaults)
                if why:
                    print("NOT enrolled %s: %s" % (u["username"], why)); continue
                _, rm = kc.api("GET", "/users/%s/role-mappings" % u["id"])
                for rn in [m["name"] for m in rm["clientMappings"][app]["mappings"]]:
                    kc.api("PUT", "/users/%s/groups/%s" % (u["id"], subs[rn]["id"]))
                    kc.api("DELETE", "/users/%s/role-mappings/clients/%s" % (u["id"], appc["id"]), [x for x in roles if x["name"] == rn])
                print("enrolled %s: direct %s roles moved to subgroups" % (u["username"], app))

def test(a):
    adm = admin_kc(a); app, sa_id = a.app, a.sa_client_id or a.app + "-admin"      # --sa-client-id: e.g. its test twin
    if bool(a.sa_secret_file) == bool(a.sa_jwt_key):
        sys.exit("give exactly one of --sa-secret-file and --sa-jwt-key")
    if a.sa_jwt_key:                           # the delegate on client-jwt (private_key_jwt)
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import client_jwt  # noqa: E402
        cred = client_jwt.form_fields(a.sa_jwt_key, sa_id, a.url.rstrip("/") + "/realms/%s" % a.realm)
    else:
        cred = {"client_secret": open(a.sa_secret_file).read().strip()}
    sa = KC(a.url, a.realm, dict({"_realm": a.realm, "grant_type": "client_credentials", "client_id": sa_id}, **cred), a.cacert)
    grp = one(adm, "/groups?search=%s&exact=true" % q(app), "name", app)
    appc = one(adm, "/clients?clientId=%s" % q(app), "clientId", app)
    results = []
    def check(name, ok, detail=""):
        results.append(ok); print("%s  %-62s %s" % ("PASS" if ok else "FAIL", name, detail))
    # bystander: an account outside the app, holding another client's role
    other_client = [c for c in adm.api("GET", "/clients")[1] if c["clientId"] not in (app, sa_id) and not c.get("bearerOnly")
                    and adm.api("GET", "/clients/%s/roles" % c["id"])[1]][:1]
    adm.api("POST", "/users", {"username": "fgap.bystander", "email": "fgap.bystander@test.invalid", "firstName": "Fgap",
                               "lastName": "Bystander", "enabled": True, "attributes": {"cac_edipi": ["1111111111"]}}, expect=(201, 409))
    by = one(adm, "/users?username=fgap.bystander&exact=true", "username", "fgap.bystander")
    try:
        st, _ = sa.api("GET", "/users/%s" % by["id"], expect=None); check("cannot READ a non-member", st in (403, 404), "HTTP %s" % st)
        st, us = sa.api("GET", "/users?max=500", expect=None)
        check("user search lists no non-member", st in (200, 403) and (st == 403 or by["id"] not in [u["id"] for u in us]), "HTTP %s" % st)
        st, _ = sa.api("PUT", "/users/%s" % by["id"], {"firstName": "Hijacked", "attributes": {"cac_edipi": ["6666666666"]}}, expect=None)
        check("cannot EDIT a non-member (incl. its EDIPI)", st in (403, 404), "HTTP %s" % st)
        st, _ = sa.api("DELETE", "/users/%s" % by["id"], expect=None); check("cannot DELETE a non-member", st in (403, 404), "HTTP %s" % st)
        st, _ = sa.api("PUT", "/users/%s/groups/%s" % (by["id"], grp["id"]), expect=None)
        check("cannot pull a non-member into its group", st in (403, 404), "HTTP %s" % st)
        st, _ = sa.api("POST", "/users", {"username": "fgap.loose", "email": "fgap.loose@test.invalid", "firstName": "F",
                                          "lastName": "Loose", "enabled": True}, expect=None)
        check("cannot create a user OUTSIDE its group", st == 403, "HTTP %s" % st)
        _, roles = adm.api("GET", "/clients/%s/roles" % appc["id"])
        # two of the app's roles: not every role is its administrator's to write (fgap/split_delegation_test.py)
        listed = set(app_delegations(a).get(app, {}).get(a.app + "-admin", ()))
        app_roles = sorted(r["name"] for r in roles if r["name"] in listed)
        r1, r2 = app_roles[0], app_roles[1]
        _, subs = adm.api("GET", "/groups/%s/children" % grp["id"]); subs = {g["name"]: g for g in subs}
        st, _ = sa.api("POST", "/users", {"username": "fgap.withcard", "email": "fgap.withcard@test.invalid", "firstName": "Fgap",
                                          "lastName": "Card", "enabled": True, "groups": ["/%s/%s" % (app, r1)],
                                          "attributes": {"cac_edipi": ["2222222222"]}}, expect=None)
        check("cannot SET cac_edipi when creating a user", st in (400, 403), "HTTP %s" % st)
        st, _ = sa.api("POST", "/users", {"username": "fgap.member", "email": "fgap.member@test.invalid", "firstName": "Fgap",
                                          "lastName": "Member", "enabled": True, "groups": ["/%s/%s" % (app, r1)]}, expect=None)
        check("cannot create a user through the plain admin API (no manage-members)", st == 403, "HTTP %s" % st)
        st, _ = sa.api("POST", "/stig-accounts/users", {"username": "fgap.member", "email": "fgap.member@example.mil",
                                                        "firstName": "Fgap", "lastName": "Member", "group": "/%s/%s" % (app, r1)}, expect=None)
        check("cannot create accounts through stig-accounts either (by design: the operator invites)", st == 403, "HTTP %s" % st)
        # the operator invites the person (here: the realm admin creates the member)
        adm.api("POST", "/users", {"username": "fgap.member", "email": "fgap.member@test.invalid", "firstName": "Fgap", "lastName": "Member",
                                   "enabled": True, "groups": ["/%s/%s" % (app, r1)]})
        mem = one(adm, "/users?username=fgap.member&exact=true", "username", "fgap.member")
        # the realm admin maps the card (the delegate cannot); a duplicate is refused even for the realm admin
        full = adm.api("GET", "/users/%s" % mem["id"])[1]
        st, _ = adm.api("PUT", "/users/%s" % mem["id"], dict(full, attributes={"cac_edipi": ["2222222222"]}), expect=None)
        check("realm admin CAN set a member's cac_edipi", st == 204, "HTTP %s" % st)
        st, _ = adm.api("PUT", "/users/%s" % by["id"], dict(adm.api("GET", "/users/%s" % by["id"])[1], attributes={"cac_edipi": ["2222222222"]}), expect=None)
        check("duplicate cac_edipi refused, even for the realm admin", st == 400, "HTTP %s" % st)
        full = sa.api("GET", "/users/%s" % mem["id"])[1]
        st, _ = sa.api("PUT", "/users/%s" % mem["id"], dict(full, attributes={"cac_edipi": ["6666666666"]}), expect=None)
        check("delegate cannot ALTER a member's cac_edipi", st in (400, 403), "HTTP %s" % st)
        st, _ = sa.api("PUT", "/users/%s" % mem["id"], dict(full, attributes={"cac_edipi": []}), expect=None)
        check("delegate cannot REMOVE a member's cac_edipi", st in (400, 403), "HTTP %s" % st)
        st, _ = sa.api("PUT", "/users/%s" % mem["id"], dict(full, attributes={"cac_edipi": ["1111111111"]}), expect=None)
        check("delegate cannot copy another user's cac_edipi onto a member", st in (400, 403), "HTTP %s" % st)
        full = sa.api("GET", "/users/%s" % mem["id"])[1]
        st, _ = sa.api("PUT", "/users/%s" % mem["id"], dict(full, attributes=dict(full.get("attributes") or {}, entra_amr=["pwd", "mfa"])), expect=None)
        check("delegate cannot write entra_amr (MFA evidence) on a member", st in (400, 403), "HTTP %s" % st)
        now = (adm.api("GET", "/users/%s" % mem["id"])[1].get("attributes") or {}).get("cac_edipi")
        check("member's cac_edipi unchanged after those attempts", now == ["2222222222"], str(now))
        st, u = sa.api("GET", "/users/%s" % mem["id"], expect=None); check("CAN read a member", st == 200, "HTTP %s" % st)
        full = sa.api("GET", "/users/%s" % mem["id"])[1]
        st, _ = sa.api("PUT", "/users/%s" % mem["id"], dict(full, firstName="Renamed"), expect=None)
        check("cannot edit a member (no manage-members)", st == 403, "HTTP %s" % st)
        eff = lambda: [x["name"] for x in adm.api("GET", "/users/%s/role-mappings/clients/%s/composite" % (mem["id"], appc["id"]))[1]]
        check("the new member holds %s through its subgroup" % r1, eff() == [r1], str(eff()))
        st1, _ = sa.api("PUT", "/users/%s/groups/%s" % (mem["id"], subs[r2]["id"]), expect=None)
        st2, _ = sa.api("DELETE", "/users/%s/groups/%s" % (mem["id"], subs[r1]["id"]), expect=None)
        check("CAN change a member's %s role (%s -> %s) by membership" % (app, r1, r2), (st1, st2) == (204, 204) and eff() == [r2],
              "HTTP %s/%s, roles now %s" % (st1, st2, eff()))
        st, _ = sa.api("POST", "/users/%s/role-mappings/clients/%s" % (mem["id"], appc["id"]), [roles[0]], expect=None)
        check("cannot map roles directly, not even %s's" % app, st == 403, "HTTP %s" % st)
        st, _ = sa.api("POST", "/groups/%s/role-mappings/clients/%s" % (subs[r1]["id"], appc["id"]), [roles[1]], expect=None)
        check("cannot change what a subgroup grants", st == 403, "HTTP %s" % st)
        st, ms = sa.api("GET", "/groups/%s/members" % subs[r2]["id"], expect=None)
        check("CAN list a subgroup's members", st == 200 and mem["id"] in [x["id"] for x in ms], "HTTP %s" % st)
        if other_client:
            oc = other_client[0]; _, oroles = adm.api("GET", "/clients/%s/roles" % oc["id"])
            st, _ = sa.api("POST", "/users/%s/role-mappings/clients/%s" % (mem["id"], oc["id"]), [oroles[0]], expect=None)
            check("cannot map another client's role (%s)" % oc["clientId"], st == 403, "HTTP %s" % st)
        _, rr = adm.api("GET", "/roles")
        st, _ = sa.api("POST", "/users/%s/role-mappings/realm" % mem["id"], [r for r in rr if r["name"].startswith("default-roles")][:1], expect=None)
        check("cannot map a realm role", st == 403, "HTTP %s" % st)
        rm = one(adm, "/clients?clientId=realm-management", "clientId", "realm-management")
        _, mroles = adm.api("GET", "/clients/%s/roles" % rm["id"])
        st, _ = sa.api("POST", "/users/%s/role-mappings/clients/%s" % (mem["id"], rm["id"]),
                       [r for r in mroles if r["name"] == "manage-users"], expect=None)
        check("cannot grant realm-management roles (manage-users)", st == 403, "HTTP %s" % st)
        st, _ = sa.api("DELETE", "/users/%s" % mem["id"], expect=None); check("cannot delete a member", st == 403, "HTTP %s" % st)
        st1, _ = sa.api("POST", "/stig-accounts/users/%s/disable" % mem["id"], expect=None)
        st2, _ = sa.api("POST", "/stig-accounts/users/%s/setup-email" % mem["id"], expect=None)
        dis = adm.api("GET", "/users/%s" % mem["id"])[1]["enabled"]
        check("cannot disable or re-send through stig-accounts (no account powers at all)", (st1, st2) == (403, 403) and dis is True,
              "HTTP %s/%s, enabled=%s" % (st1, st2, dis))
        # what an application's admin screen relies on
        st1, gb = sa.api("GET", "/group-by-path/%s/%s" % (app, r2), expect=None)
        st2, ms2 = sa.api("GET", "/groups/%s/members" % subs[r2]["id"], expect=None)
        st3, ug = sa.api("GET", "/users/%s/groups" % mem["id"], expect=None)
        check("CAN GET group-by-path, a role group's members and a member's groups", (st1, st2, st3) == (200, 200, 200)
              and gb.get("id") == subs[r2]["id"] and mem["id"] in [x["id"] for x in ms2] and "/%s/%s" % (app, r2) in [x["path"] for x in ug],
              "HTTP %s/%s/%s" % (st1, st2, st3))
        st1, _ = sa.api("PUT", "/users/%s/groups/%s" % (mem["id"], subs[r1]["id"]), expect=None)
        st2, _ = sa.api("DELETE", "/users/%s/groups/%s" % (mem["id"], subs[r2]["id"]), expect=None)
        check("CAN move the member back (%s -> %s): PUT and DELETE on users/{id}/groups/{gid}" % (r2, r1), (st1, st2) == (204, 204), "HTTP %s/%s" % (st1, st2))
    finally:
        for n in ("fgap.bystander", "fgap.member", "fgap.loose", "fgap.withcard"):
            u = one(adm, "/users?username=%s&exact=true" % n, "username", n)
            if u: adm.api("DELETE", "/users/%s" % u["id"])
    print("\n%d/%d passed" % (sum(results), len(results))); sys.exit(0 if all(results) else 1)

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--url", required=True); ap.add_argument("--realm", required=True); ap.add_argument("--app", required=True, help="the application client id (a key of the idp-admin config's applications)")
ap.add_argument("--cacert"); ap.add_argument("--admin-user"); ap.add_argument("--admin-password-file")
ap.add_argument("--admin-client-id"); ap.add_argument("--admin-secret-file")
ap.add_argument("--admin-script", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "host", "idp-admin.py"),
                help="idp-admin.py, whose APP_DELEGATIONS says which groups <app>-admin may write")
sp = ap.add_subparsers(dest="cmd", required=True)
s = sp.add_parser("setup"); s.add_argument("--enroll-existing", action="store_true"); s.set_defaults(fn=setup)
t = sp.add_parser("test"); t.add_argument("--sa-secret-file")
t.add_argument("--sa-client-id", help="sign in as this client instead of <app>-admin: its test twin (idp-admin.py delegate-test-twin)")
t.add_argument("--sa-jwt-key", help="the delegate on client-jwt: its PEM private key (ES256/RS256), instead of --sa-secret-file")
t.set_defaults(fn=test)
a = ap.parse_args(); a.fn(a)

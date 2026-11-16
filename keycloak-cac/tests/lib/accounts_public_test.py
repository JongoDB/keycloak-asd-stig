#!/usr/bin/env python3
"""The checks behind keycloak-cac/tests/accounts-public.sh: stig-accounts (U1-U5, U7) in a passkey realm.

The caller is a lab stand-in for an application delegate: a service account holding realm-management realm-admin, so
Keycloak's own group-membership check passes without fine-grained permissions (manage-users alone does not satisfy it
on 26.8.2). What is tested here is stig-accounts' own rules; the production delegate's narrow FGAP scope (query-users,
query-groups + manage-membership on its group tree) is tested by the operator's suites against the live realm. The lab realm enforces no
administrator allowlist. Every account is a throwaway in a throwaway container.
"""
import argparse, email, glob, hashlib, json, os, re, subprocess, sys, time, urllib.error, urllib.parse, urllib.request, uuid
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "keycloak-asd-stig", "scripts"))
import kcstig as K, e2e_check as E, softauthn as S, passkey_flow as PF

ap = argparse.ArgumentParser()
ap.add_argument("--name", required=True); ap.add_argument("--port", required=True); ap.add_argument("--dir", required=True)
ap.add_argument("--smtp-host", required=True); ap.add_argument("--smtp-port", required=True)
ap.add_argument("--realm", default="public")
A = ap.parse_args()
BASE = "https://localhost:%s" % A.port
CA = os.path.join(A.dir, "root.crt")
REALM, RR = A.realm, "/realms/%s" % A.realm
os.environ.update({"KC_CLIENT_ID": "stig-automation", "KC_CACERT": CA,
                   "KC_CLIENT_SECRET": hashlib.sha256(("cac-lab-automation:" + os.environ["LAB_BOOTSTRAP_PW"]).encode()).hexdigest()[:48]})
RES = []
def check(name, ok, detail=""):
    RES.append(bool(ok)); print("%s %-88s %s" % ("PASS" if ok else "FAIL", name, str(detail)[:220]), flush=True)
kc = K.KC(BASE, "master", CA); kc.login()
MAIL = os.path.join(A.dir, "mail")
def mails():
    return sorted(glob.glob(os.path.join(MAIL, "*.eml")))
def next_mail(before):
    for _ in range(40):
        new = [m for m in mails() if m not in before]
        if new:
            msg = email.message_from_bytes(open(new[-1], "rb").read())
            body = "".join(p.get_payload(decode=True).decode("utf-8", "replace") for p in msg.walk() if p.get_content_type() == "text/plain")
            m = re.search(r"(https://\S+action-token\S+)", body)
            return msg["To"], (m.group(1) if m else None)
        time.sleep(0.5)
    return None, None
def logs(since):
    r = subprocess.run(["docker", "logs", "--since", str(since), A.name], capture_output=True, text=True)
    return r.stdout + r.stderr
def master_attr(key, value):
    m = kc.api("GET", "/realms/master")
    at = dict(m.get("attributes") or {})
    if value is None: at.pop(key, None)
    else: at[key] = value
    kc.api("PUT", "/realms/master", {"attributes": at})

# ---- set-up: the operator's switches, the realm, two organizations, groups, the delegate
kc.api("PUT", RR, {"smtpServer": {"host": A.smtp_host, "port": str(A.smtp_port), "from": "idp@lab.invalid", "auth": "false",
                                  "ssl": "false", "starttls": "false"}, "organizationsEnabled": True})
R = kc.api("GET", RR)
kc.api("PUT", RR, {"attributes": dict(R.get("attributes") or {}, **{"stig.accounts.email-domains": "*",
                                                                    "stig.accounts.email-domains-deny": ".mil,defconai.com"})})
# the operator's tooling declares the creator marker (administrators only), so it is kept and readable by the master realm
up = kc.api("GET", RR + "/users/profile")
up["attributes"].append({"name": "stig_created_by", "displayName": "Created by a delegate", "permissions": {"view": ["admin"], "edit": ["admin"]},
                         "multivalued": False, "validations": {"length": {"max": "512"}}, "annotations": {}})
kc.api("PUT", RR + "/users/profile", up)
RID = kc.api("GET", RR)["id"]          # the operator's switches are keyed by realm ID
PASSKEY_SETUP = "VERIFY_EMAIL,TERMS_AND_CONDITIONS,webauthn-register-passwordless"
master_attr("stig.accounts.setup-actions.%s" % RID, PASSKEY_SETUP)
master_attr("stig.accounts.recover.%s" % RID, "true")
master_attr("stig.accounts.reactivate.%s" % RID, "true")
orgs = {}
for alias in ("acme", "other"):
    orgs[alias] = kc.api("POST", RR + "/organizations", {"name": alias, "alias": alias, "enabled": True, "domains": [{"name": alias + ".example"}]})
app = kc.api("POST", RR + "/groups", {"name": "app"})
gids = {n: kc.api("POST", RR + "/groups/%s/children" % app, {"name": n}) for n in ("VENDOR", "FACTORY_READER")}
dsec = uuid.uuid4().hex
cid = kc.api("POST", RR + "/clients", {"clientId": "public-delegate", "protocol": "openid-connect", "publicClient": False,
                                       "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "serviceAccountsEnabled": True,
                                       "clientAuthenticatorType": "client-secret", "secret": dsec,
                                       "attributes": {"stig.accounts.organizations": orgs["acme"]}})
K.ensure_admin_api_scope(kc, REALM, cid)
sa = kc.api("GET", RR + "/clients/%s/service-account-user" % cid)
rm = kc.api("GET", RR + "/clients?clientId=realm-management")[0]
_roles = [kc.api("GET", RR + "/clients/%s/roles/%s" % (rm["id"], r)) for r in ("realm-admin",)]
kc.api("POST", RR + "/users/%s/role-mappings/clients/%s" % (sa["id"], rm["id"]), _roles)
# the STIG client policy disables full scope: the token carries a role only if the client's scope includes it
kc.api("POST", RR + "/clients/%s/scope-mappings/clients/%s" % (cid, rm["id"]), _roles)

ctx = __import__("ssl").create_default_context(cafile=CA)
def dtoken():
    data = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": "public-delegate", "client_secret": dsec}).encode()
    with urllib.request.urlopen(urllib.request.Request(BASE + RR + "/protocol/openid-connect/token", data=data), context=ctx) as r:
        return json.loads(r.read())["access_token"]
TOK = dtoken()
def call(method, path, body=None, q=None, realm=REALM, token=None):
    url = BASE + "/admin/realms/%s/stig-accounts/%s" % (realm, path) + ("?" + urllib.parse.urlencode(q) if q else "")
    h = {"Authorization": "Bearer " + (token or dtoken()), "Content-Type": "application/json"}   # tokens live 5 min
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else (b"" if method == "POST" else None), method=method, headers=h)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            t = r.read().decode(); return r.status, (json.loads(t) if t.strip() else None)
    except urllib.error.HTTPError as e:
        t = e.read().decode(); return e.code, (json.loads(t) if t.strip().startswith("{") else t)
def person(prefix, domain, group="FACTORY_READER", **extra):
    n = "%s.t%s" % (prefix, uuid.uuid4().hex[:6])
    return dict({"username": n, "email": "%s@%s" % (n, domain), "firstName": "Pat", "lastName": "Tester", "group": "/app/" + group}, **extra)
def set_up(link):
    a = S.Authenticator("ES256", workdir=A.dir)
    ok, seen, err = PF.set_up(E.Browser(CA), link, a, BASE + RR + "/account")
    return a, ok, seen, err
pfl = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client="account-console", redirect=BASE + RR + "/account/",
                                admin_url=None, client_secret=None, cacert=CA))
def signs_in(a):
    code, pages, err, _ = PF.sign_in(pfl, a, "button", cacert=CA)
    return bool(code), pages, err

# ---- U1 + U5: a reader, set up with the realm's passkey actions; onBehalfOf recorded as asserted
ob = "2b1f0c3e-1111-4a2b-9c3d-123456789abc jane.lead"
reader = person("reader", "readers.example", onBehalfOf=ob)
before = mails()
st, out = call("POST", "users", reader)
check("U1: a reader (any domain but the denylist) is created", st == 201 and out.get("setupEmail") == "sent", (st, out))
if st != 201:
    print("\n".join(l[l.find("STIG-"):][:300] for l in logs(0).splitlines() if "STIG-ACCOUNTS" in l or "STIG-ADMIN" in l)[-2000:])
    sys.exit(1)
rid = (out or {}).get("id")
to, link = next_mail(before)
u = kc.api("GET", RR + "/users/%s" % rid)
check("U1: its pending actions are the realm's passkey set-up (no password, no OTP)",
      sorted(u.get("requiredActions") or []) == sorted(PASSKEY_SETUP.split(",")), u.get("requiredActions"))
a_r, ok, seen, err = set_up(link)
check("U1: the mailed link verifies the address, shows the DoD notice and registers a passkey", ok and "login-terms" in seen
      and kc.api("GET", RR + "/users/%s" % rid).get("emailVerified") is True, "%s %s" % (seen, err))
check("... and the reader signs in with it", signs_in(a_r)[0])
attrs = kc.api("GET", RR + "/users/%s" % rid).get("attributes") or {}
cb = (attrs.get("stig_created_by") or [""])[0]
check("U5: stig_created_by names the caller and the onBehalfOf, marked as asserted",
      cb.startswith("service-account-public-delegate ") and ("onBehalfOf=%s (asserted by caller)" % ob) in cb, cb)
evs = kc.api("GET", RR + "/admin-events?operationTypes=CREATE&resourceTypes=USER&max=20") or []
rep_ev = [json.loads(e.get("representation") or "{}") for e in evs if (e.get("resourcePath") or "").endswith(rid or "?")]
check("U5: the admin event carries onBehalfOf (asserted by caller)", any(r.get("onBehalfOf") == ob + " (asserted by caller)" for r in rep_ev), rep_ev)
st, _ = call("POST", "users", person("bad", "readers.example", onBehalfOf="a\nb"))
check("U5: a malformed onBehalfOf is refused (400)", st == 400, st)

# ---- U2: the denylist
for dom in ("army.mil", "defconai.com"):
    st, _ = call("POST", "users", person("deny", dom))
    check("U2: a reader at %s is refused (realm denylist) - 403" % dom, st == 403, st)

# ---- U7: organizations
before = mails()
v = person("vendor", "acme.example", group="VENDOR", organization=orgs["acme"])
st, out = call("POST", "users", v)
vid = (out or {}).get("id")
members = [m["id"] for m in kc.api("GET", RR + "/organizations/%s/members" % orgs["acme"]) or []]
check("U7: a vendor at acme.example, organization acme (listed for the caller): created and a member", st == 201 and vid in members, (st, out))
for label, body in (("an address outside the organization's domains", person("vendor", "other.example", group="VENDOR", organization=orgs["acme"])),
                    ("an organization not listed for the caller", person("vendor", "other.example", group="VENDOR", organization=orgs["other"])),
                    ("an organization that does not exist", person("vendor", "acme.example", group="VENDOR", organization=str(uuid.uuid4()))),
                    ("a denylisted address even in a listed organization", dict(person("vendor", "acme.example", group="VENDOR", organization=orgs["acme"]), email="x.y@army.mil"))):
    st, out = call("POST", "users", body)
    made = kc.api("GET", RR + "/users?username=%s&exact=true" % body["username"])
    check("U7: %s is refused (403), nothing created" % label, st == 403 and not made, (st, out))

# ---- U1: the operator's set-up value fails closed
master_attr("stig.accounts.setup-actions.%s" % RID, "TERMS_AND_CONDITIONS")       # no credential action
st, out = call("POST", "users", person("closed", "readers.example"))
check("U1: an unreadable set-up value refuses creation (503, fail closed)", st == 503, (st, out))
master_attr("stig.accounts.setup-actions.%s" % RID, PASSKEY_SETUP)

# ---- resend
st1, _ = call("POST", "users/%s/setup-email" % vid)
st3, _ = call("POST", "users/%s/setup-email" % rid)
check("re-send: an account whose passkey is not registered counts as in set-up (429: its creation mail went < 15 min ago); "
      "one that registered its passkey does not (409)", (st1, st3) == (429, 409), (st1, st3))

# ---- U3: recovery
before = mails()
since = int(time.time())
st, out = call("POST", "users/%s/recover" % rid, q={"onBehalfOf": ob})
to, rlink = next_mail(before)
u = kc.api("GET", RR + "/users/%s" % rid)
check("U3: recover -> 204; passkeys removed, address unverified, set-up actions pending", st == 204
      and not kc.api("GET", RR + "/users/%s/credentials" % rid) and u.get("emailVerified") is False
      and sorted(u.get("requiredActions") or []) == sorted(PASSKEY_SETUP.split(",")), (st, out, u.get("requiredActions")))
check("U3: the link goes to the address ON RECORD", to and reader["email"] in to, to)
check("U3: the old passkey no longer signs in", not signs_in(a_r)[0])
a_r2, ok, seen, err = set_up(rlink)
check("U3: the recovery link registers a new passkey, and it signs in", ok and signs_in(a_r2)[0], "%s %s" % (seen, err))
st, _ = call("POST", "users/%s/recover" % rid)
check("U3: a second recovery within 24 h is refused (429)", st == 429, st)
time.sleep(1)
check("U3: logged, with onBehalfOf as asserted", "STIG-ACCOUNTS recovered" in logs(since) and "jane.lead (asserted by caller)" in logs(since))
pw = person("pwd", "readers.example")
st_pw, out_pw = call("POST", "users", pw)
pw_id = (out_pw or {}).get("id")
st_none, _ = call("POST", "users/%s/recover" % pw_id)
kc.api("PUT", RR + "/users/%s/reset-password" % pw_id, {"type": "password", "value": "Aa1!" + uuid.uuid4().hex + "Zz9#", "temporary": False})
st_pwd, _ = call("POST", "users/%s/recover" % pw_id)
check("U3: recover refuses an account with no passkey (409) and one holding a password (409); nothing removed",
      (st_none, st_pwd) == (409, 409) and [c["type"] for c in kc.api("GET", RR + "/users/%s/credentials" % pw_id)] == ["password"], (st_none, st_pwd))
master_attr("stig.accounts.recover.%s" % RID, None)
st, _ = call("POST", "users/%s/recover" % vid)
check("U3: with the operator's switch off, recover is refused (403)", st == 403, st)
master_attr("stig.accounts.recover.%s" % RID, "true")

# ---- U4: reactivation, driven by the REAL workflow steps (set-user-attribute, then disable-user). The container runs
# the workflow runner every 3 seconds (stepRunnerTaskInterval, in seconds); a test workflow with the realm's inactivity steps
# and a 20-second delay stands in for 35 days, activated for one account at a time.
def wf(name, steps):
    for w in kc.api("GET", RR + "/workflows") or []:
        if w["name"] == name:
            kc.api("DELETE", RR + "/workflows/%s" % w["id"])
    kc.api("POST", RR + "/workflows", {"name": name, "steps": steps})
    return [w for w in kc.api("GET", RR + "/workflows") if w["name"] == name][0]["id"]
INACT = wf("stig-disable-inactive-test", [{"uses": "set-user-attribute", "after": "20s", "with": {"stig_disabled_by": "inactivity"}},
                                          {"uses": "disable-user"}])
MARK = wf("stig-mark-only-test", [{"uses": "set-user-attribute", "after": "5s", "with": {"stig_disabled_by": "inactivity"}}])
def activate(wid, uid):
    for t in ("users", "USERS"):
        try:
            kc.api("POST", RR + "/workflows/%s/activate/%s/%s" % (wid, t, uid)); return True
        except K.KCError:
            pass
    return False
def wait_for(pred, secs=150):
    end = time.time() + secs
    while time.time() < end:
        if pred(): return True
        time.sleep(3)
    return False
def user(uid): return kc.api("GET", RR + "/users/%s" % uid)
def marker(uid): return ((user(uid).get("attributes") or {}).get("stig_disabled_by") or [None])[0]

check("U4 (set-up): the test inactivity workflow is activated for the reader", activate(INACT, rid))
ok_wf = wait_for(lambda: not user(rid)["enabled"])
check("U4: the workflow's own steps disable the account and leave stig_disabled_by=inactivity", ok_wf and marker(rid) == "inactivity",
      (user(rid)["enabled"], marker(rid)))
st, out = call("POST", "users/%s/reactivate" % rid, q={"onBehalfOf": ob})
u = user(rid)
sched = [w.get("name") for w in kc.api("GET", RR + "/workflows/scheduled/%s" % rid) or []]
check("U4: an account the inactivity workflow disabled is reactivated (204), the marker cleared", st == 204 and u.get("enabled") is True
      and "stig_disabled_by" not in (u.get("attributes") or {}), (st, out))
check("U4: ... and the inactivity workflows are scheduled for it again (V-222411)", "stig-disable-inactive-test" in sched
      and "stig-disable-inactive-35d" in sched, sched)
check("U4: ... and it signs in", signs_in(a_r2)[0])
st, _ = call("POST", "users/%s/reactivate" % rid)
check("U4: an enabled account is not 'reactivated' (409)", st == 409, st)
check("U4: the restarted workflow disables the unused account again, with the marker", wait_for(lambda: not user(rid)["enabled"])
      and marker(rid) == "inactivity")
# the review's case: disabled for inactivity, then an administrator changes the account -> reactivate refuses
cur = user(rid)
kc.api("PUT", RR + "/users/%s" % rid, dict(cur, firstName="Kept", enabled=False))
time.sleep(2)
st, _ = call("POST", "users/%s/reactivate" % rid)
check("U4: disabled for inactivity, then changed by an administrator (PUT): the marker is withdrawn and reactivate refuses (409)",
      st == 409 and marker(rid) is None and not user(rid)["enabled"], (st, marker(rid)))
st, _ = call("POST", "users/%s/disable" % vid)
st2, _ = call("POST", "users/%s/reactivate" % vid)
check("U4: an account disabled through stig-accounts cannot be reactivated (409)", st == 204 and st2 == 409, (st, st2))
cur = user(vid); kc.api("PUT", RR + "/users/%s" % vid, dict(cur, enabled=True))
activate(INACT, vid)
wait_for(lambda: marker(vid) == "inactivity")
call("POST", "users/%s/disable" % vid)
st, _ = call("POST", "users/%s/reactivate" % vid)
check("U4: disable through stig-accounts withdraws an inactivity marker, so reactivate refuses (409)", st == 409 and marker(vid) is None, st)
mk = person("marked", "readers.example")
before = mails(); _, mk_out = call("POST", "users", mk); mk_id = mk_out["id"]
a_mk, ok_mk, _, _ = set_up(next_mail(before)[1])
activate(MARK, mk_id)
got = wait_for(lambda: marker(mk_id) == "inactivity")
signs_in(a_mk); time.sleep(2)
check("U4: a sign-in clears the inactivity marker (stig-audit)", ok_mk and got and marker(mk_id) is None, (ok_mk, got, marker(mk_id)))
master_attr("stig.accounts.reactivate.%s" % RID, None)
st, _ = call("POST", "users/%s/reactivate" % rid)
check("U4: with the operator's switch off, reactivate is refused (403)", st == 403, st)
for w in (INACT, MARK):
    kc.api("DELETE", RR + "/workflows/%s" % w)

# ---- the main realm is left as it was: no switch set, no organization, password defaults
mid = kc.api("POST", "/realms/dod-cac/clients", {"clientId": "main-delegate", "protocol": "openid-connect", "publicClient": False,
             "standardFlowEnabled": False, "serviceAccountsEnabled": True, "clientAuthenticatorType": "client-secret", "secret": dsec})
K.ensure_admin_api_scope(kc, "dod-cac", mid)
msa = kc.api("GET", "/realms/dod-cac/clients/%s/service-account-user" % mid)
mrm = kc.api("GET", "/realms/dod-cac/clients?clientId=realm-management")[0]
_mroles = [kc.api("GET", "/realms/dod-cac/clients/%s/roles/%s" % (mrm["id"], r)) for r in ("realm-admin",)]
kc.api("POST", "/realms/dod-cac/users/%s/role-mappings/clients/%s" % (msa["id"], mrm["id"]), _mroles)
kc.api("POST", "/realms/dod-cac/clients/%s/scope-mappings/clients/%s" % (mid, mrm["id"]), _mroles)
mapp = kc.api("POST", "/realms/dod-cac/groups", {"name": "mapp"}); kc.api("POST", "/realms/dod-cac/groups/%s/children" % mapp, {"name": "ROLE"})
data = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": "main-delegate", "client_secret": dsec}).encode()
with urllib.request.urlopen(urllib.request.Request(BASE + "/realms/dod-cac/protocol/openid-connect/token", data=data), context=ctx) as r:
    mtok = json.loads(r.read())["access_token"]
mp = person("main", "army.mil", group="ROLE"); mp["group"] = "/mapp/ROLE"
st, out = call("POST", "users", mp, realm="dod-cac", token=mtok)
mu = kc.api("GET", "/realms/dod-cac/users/%s" % (out or {}).get("id", "x"), ok404=True) or {}
check("main realm: creation unchanged - password, TOTP and terms set-up, default domains (.mil)", st == 201
      and sorted(mu.get("requiredActions") or []) == ["CONFIGURE_TOTP", "TERMS_AND_CONDITIONS", "UPDATE_PASSWORD"], (st, mu.get("requiredActions")))
st1, _ = call("POST", "users/%s/recover" % mu.get("id", "x"), realm="dod-cac", token=mtok)
st2, _ = call("POST", "users/%s/reactivate" % mu.get("id", "x"), realm="dod-cac", token=mtok)
st3, _ = call("POST", "users", dict(person("main", "acme.example", group="ROLE", organization=orgs["acme"]), group="/mapp/ROLE"), realm="dod-cac", token=mtok)
check("main realm: recover and reactivate are refused (403), and an organization is refused (403)", (st1, st2, st3) == (403, 403, 403), (st1, st2, st3))
sys.exit(0 if all(RES) else 1)

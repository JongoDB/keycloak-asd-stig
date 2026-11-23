#!/usr/bin/env python3
"""Host-side admin helper for a keycloak-cac IdP on one VM (keycloak-cac/deploy/vm). Runs ON the VM as root, against Keycloak from inside its container's
network namespace (127.0.0.1:8443, certificate verified for the public host name), as the stig-automation service account (master realm).
Never prints a secret, except `client-secret`, which writes one to stdout for piping straight into a secret store.

Everything specific to one deployment - which applications have delegated role-group trees, each application's
user-manager role, which delegate service account may write which role groups, the Entra member domain, SMTP
defaults - is read from a JSON config: /srv/idp/config/idp-admin.json, or the file named by $IDP_ADMIN_CONFIG (see
idp-admin.example.json beside this script for every key). Commands that talk to Keycloak refuse to run without it.

  idp-admin.py entra --tenant <id> --client-id <appId> [--secret-file /srv/idp/secrets/entra_client_secret] [--enable]
        Microsoft Entra ID as a brokered OIDC provider (alias `entra`), members of the config's entra.memberDomain only. First broker login
        never creates an account and never matches by name or e-mail: it links only to the account whose admin-set
        entra_oid equals the token's oid. Post broker login: administrators (any realm-management role) whose
        Entra `amr` lacks "mfa" must also pass Keycloak TOTP, and are REFUSED if they hold none (no enrolment after
        Entra's single factor); everyone gets the concurrent-session limit. The amr is
        recorded in the guarded attribute entra_amr. Created DISABLED unless --enable. Idempotent.
  idp-admin.py add-client <file.json|-> [--dry-run] [--secret-to F | --secret-to-keyvault V/N] [--repo R]
        [--inheritance-statement OUT] [--host idp-host]
        register or update ONE client live through the admin API - no restart - rendered by the running image's own
        kcstig (so it equals what the next start applies), verified by a re-read, and only then installed as the host
        file /srv/idp/clients/<id>.json (root 0444). Refuses anything outside the client rules (exact https URIs, no
        localhost, client-jwt + jwks_url or client-secret, roles, no unknown field). Prints what changed; idempotent.
        --host runs it from the operator Mac over ssh (and --repo writes the repo copy there). Never prints a secret.
  idp-admin.py check-clients [--repo R] [--host idp-host]
        exit 1 if a restart would change any live client (live vs /srv/idp/clients), a host file and the repo copy
        differ, or a client's jwks_url / back-channel host now resolves to a non-public address. Run it before EVERY
        Keycloak restart.
  idp-admin.py cert-check                       exit 1 if the certificate on disk is not the one Keycloak serves (daily timer)
  idp-admin.py inheritance-statement <clientId> an application's ASD STIG control-inheritance statement (markdown)
  idp-admin.py client-secret <clientId>        print a confidential client's secret (pipe it, do not display it)
  idp-admin.py user-create-cac <username> <edipi> <email> <first> <last> <client>:<role> [--existing]
        a card holder mapped by EDIPI (the 10 digits at the end of the card's CN), with one client role. An existing
        username is refused unless --existing AND its cac_edipi equals <edipi> AND it has no identity-provider link
        AND no fine-grained delegate can manage it (any Users/Groups permission naming it, its groups or their
        ancestors, or ALL users/groups) AND it carries no password/OTP credential (unless --accept-credentials);
        an EDIPI already on another account is always refused. Prints created / updated / REFUSED.
  idp-admin.py roles-setup                      role catalogue groups + the delegations: every app tree's members visible
        to its delegates (`delegated: /<app>`), and membership of each group writable only by the user managers and
        the delegates the config lists for it (applications.<app>.delegations) (`membership: /<app>/<GROUP>`). Migration-safe from the earlier
        single tree-wide permission (sync_delegations). Idempotent.
  idp-admin.py delegate-setup <delegate> [--jwks-url U]   a membership-only delegate (config: "membershipOnly": true):
        its service-account client, writing membership of exactly the role groups the config lists for it, for accounts
        already in its application's tree; no realm-management role
  idp-admin.py onboarding-client-setup --redirect-uri U [--client-id C] [--max-auth-age 300]   the PUBLIC client an application page
        (e.g. an application's own portal) uses to create, re-send, disable and move accounts with the signed-in user manager's OWN token:
        PKCE, one redirect, one CORS origin, no refresh token, scope mappings realm-management query-users+query-groups
        only, stig-extensions admin-API profile `account-onboarding` (only those calls; writes need a fresh sign-in).
        Its shape is recorded and guarded (drift -> disabled). Refused unless the deployed extension enforces the profile.
        One client per page: idp-onboarding, or C from the config's onboarding.clientIds for another application's page.
  idp-admin.py delegate-client-setup <delegate> --jwks-url U [--alg ES256|RS256] | --client-secret
        a delegate (any configured delegation) to client-jwt with the app's JWKS (https, public
        name, resolved now), or back. Records it (guard / check-clients report a difference), regenerates the client
        secret so no earlier one authenticates; the service account and the delegation are unchanged.
  idp-admin.py delegate-test-twin <delegate> create --secret-file F | remove
        a TEMPORARY client <delegate>--test with the delegate's exact delegation and a secret, for the live $L/$T tests
        once the delegate is on client-jwt (the live delegate untouched); the guard reports one left behind
  idp-admin.py handoff-worker-setup [--rotate-secret]   the confidential client an application's hand-off intake accepts
        tokens from (config handoffIntake: clientId, audience, scope, url): client credentials only, a service account
        holding no role of any kind, fullScopeAllowed off, no default client scope, ONE optional client scope (the
        configured scope) carrying ONE audience mapper (the configured audience). Recorded (guard: drift -> disabled;
        check-clients: drift), secret to /srv/idp/secrets/handoff_client_secret (root 0600), and proved: a token asked
        for the scope carries exactly that aud, scope and azp. Idempotent; re-enables.
  idp-admin.py handoffs [list] | handoffs done|refused <id> [--note N]
        the application's open hand-offs (oldest first), each with its account as Keycloak sees it (enabled, card,
        Entra, application trees) and the idp-admin.py command(s) suggested for its kind - none, with a WARNING, when the
        account does not exist, is an IdP administrator, or is outside the filing application's tree (handoffIntake.app) -
        NEVER run automatically: the operator runs the command, then records the outcome (audited to syslog, auth
        facility). https only, the intake host resolved once to public addresses, no redirect, 20 s, 1 MiB. A note is at
        most 200 characters, printable, with no run of ten digits.
  idp-admin.py delegation-rollback              ROLLBACK of the split only: one tree-wide permission again, the reader
        delegates the config does not list as preSplitDelegates out of it and disabled; REFUSED while a tree holds a group
        its pre-split delegate must not write
  idp-admin.py grant <username> <role>...       idp-admin | idp-user-manager | idp-auditor | <app>-user-manager | <client>:<ROLE>
        (<app>-user-manager: that app's tree only; needs the app role the config's userManagerRole names)
  idp-admin.py invite first.last --email E [--groups ...] [--edipi N] [--lifespan S]   e-mail a set-up link
  idp-admin.py rename <old> <new> [--email --first --last]    same user id (sub)
  idp-admin.py set-password <username> > file    temporary password + TOTP required (stdout must not be a terminal)
  idp-admin.py smtp --user <acs smtp username>   outbound mail (password from /srv/idp/secrets/smtp_password)
  idp-admin.py guard [--fix]                    sync the idp-admin-only permission on every administrator; exit 2 if one sits in an application group (any depth), --fix moves them out and verifies; exit 1 on failure
        and an administrator not on the allowlist or holding more than its entry's grants permit (expanded now):
        --fix demotes it, resets its factors (identity bindings kept), disables it (held: user-enable refuses until
        reset-user) and ends its sessions; its admin-API changes are listed (STIG-ADMIN-REVIEW); the users it changed
        are contained (sessions, factors, disabled, held) only when the start of its unvetted period is proven - such
        changes prove the gate failed - or for an over-entry account while the gate's capability marker is missing or
        older; an allowlisted administrator it changed is alerted (ALLOWLISTED-TOUCHED), never contained; exit 2 -> mailed
  idp-admin.py reset-user <username|id> [--clear-bindings]   factors, links, e-mail, sessions; + entra_oid, cac_edipi
  idp-admin.py client-delete <clientId|uuid> / role-delete <role|clientId:role|uuid>   act on a REVIEW line
  idp-admin.py link-entra <username> <oid>      bind an account to one Entra identity (object id)
  idp-admin.py link-cac <username> [--edipi] [--replace] [--allow-admin] | --bind-edipi --confirm-direct-bind | --cancel
  idp-admin.py link-cac --cancel-all            withdraw every pending link request (the realm-wide stop)
        a CAC for an EXISTING account: its holder is asked to present the card at the next sign-in (password + OTP, or
        Entra) and that card is bound then (stig-extensions' present-card step; live 7 days); --edipi: only the card whose
        EDIPI you type at the prompt binds. Only if the person cannot present a card: --bind-edipi binds it now. Refused: a
        disabled account; one with a card or an invite's pending card (unless --replace: removed, sessions ended); a card
        bound to or reserved for another account; an IdP administrator (--allow-admin, with --edipi only; never a direct
        bind). The EDIPI is never taken from the command line, printed or logged in full. One audit line per attempt
        (STIG-LINK-CAC, syslog auth facility).
  idp-admin.py entra-amr <username>             the amr Entra sent at the user's last Entra sign-in (MFA evidence)
  idp-admin.py user-logout <username>           end the user's IdP sessions (triggers back-channel logout)
  idp-admin.py user-unlock <username>           clear a password lockout
  idp-admin.py user-enable <username> true|false
  idp-admin.py user-delete <username>
  idp-admin.py user-create-pw <username> <email> <first> <last> <client>:<role> --temp-password-file F [--temporary]
        a password+MFA user (temporary password: change at first sign-in, then TOTP enrolment)
"""
import argparse, http.client, importlib.machinery, importlib.util, json, os, re, socket, ssl, subprocess, sys, time, urllib.parse

# ------------------------------------------------------------------------- per-deployment configuration
ADMIN_CONFIG_FILE = os.environ.get("IDP_ADMIN_CONFIG") or "/srv/idp/config/idp-admin.json"
CONFIG_KEYS = {"applications", "entra", "smtp", "operatorSshHost", "repoClientsDir", "onboarding", "handoffIntake"}
APP_KEYS = {"userManagerRole", "adoptable", "delegations", "preSplitDelegates"}
DELEGATION_KEYS = {"groups", "name", "membershipOnly"}
ENTRA_KEYS, SMTP_KEYS, ONBOARDING_KEYS = {"memberDomain", "displayName"}, {"host", "port", "from", "displayName"}, {"defaultApps", "clientIds"}
# The onboarding client every deployment has; onboarding.clientIds names more, one per application page (each its own
# redirect and origin - a client has exactly one), all built, recorded and guarded the same way.
DEFAULT_ONBOARDING_CLIENT = "idp-onboarding"
HANDOFF_KEYS = {"url", "clientId", "audience", "scope", "app", "name"}
# client scopes Keycloak ships (or this tooling relies on): never the name of the hand-off scope
BUILTIN_SCOPES = {"openid", "profile", "email", "address", "phone", "offline_access", "roles", "web-origins", "acr",
                  "basic", "microprofile-jwt", "organization", "service_account", "role_list", "saml_organization",
                  "kc-admin-api"}
# checked again against RESERVED_CLIENTS / UNMANAGED_CLIENTS once those are built (below)
CONFIG_RESERVED_IDS = {"realm-management", "account", "account-console", "security-admin-console", "admin-cli", "broker",
                       "admin-permissions", "stig-automation", "break-glass-recovery", "idp-onboarding", "idp-admin",
                       "idp-user-manager", "idp-auditor", "idp"}

def load_admin_config(path):
    """The deployment's config (None when the file does not exist). Unknown keys and wrong types are refused, like a
    typo: a misspelt key that silently meant "no delegation", or a string where a list belongs (iterated letter by
    letter), would change who may write what."""
    if not os.path.exists(path):
        return None
    with open(path) as f:
        c = json.load(f)
    def no(msg):
        sys.exit("REFUSED: %s: %s" % (path, msg))
    def obj(where, v, allowed):
        if not isinstance(v, dict):
            no("%s is not an object" % where)
        extra = sorted(set(v) - allowed - {"$comment"})
        if extra:
            no("unknown key(s) %s in %s" % (", ".join(extra), where))
        return v
    def strs(where, v):
        if not isinstance(v, list) or not v or not all(isinstance(x, str) and x for x in v):
            no("%s must be a non-empty list of names" % where)
        return v
    def text(where, v):
        if not isinstance(v, str) or not v:
            no("%s must be a non-empty string" % where)
    obj("the top level", c, CONFIG_KEYS)
    apps = obj("applications", c.get("applications") or {}, set(c.get("applications") or {}))
    for app, ac in apps.items():
        obj("applications.%s" % app, ac, APP_KEYS)
        if "userManagerRole" in ac:
            text("applications.%s.userManagerRole" % app, ac["userManagerRole"])
        if "adoptable" in ac and not isinstance(ac["adoptable"], bool):
            no("applications.%s.adoptable must be true or false" % app)
        dels = obj("applications.%s.delegations" % app, ac.get("delegations") or {}, set(ac.get("delegations") or {}))
        for cid, d in dels.items():
            w = "applications.%s.delegations.%s" % (app, cid)
            obj(w, d, DELEGATION_KEYS)
            strs(w + ".groups", d.get("groups"))
            if "membershipOnly" in d and not isinstance(d["membershipOnly"], bool):
                no("%s.membershipOnly must be true or false" % w)
            if "name" in d:
                text(w + ".name", d["name"])
        for cid in strs("applications.%s.preSplitDelegates" % app, ac["preSplitDelegates"]) if "preSplitDelegates" in ac else []:
            if cid not in dels:
                no("preSplitDelegates %s is not a delegation of %s" % (cid, app))
    # never an application or delegate: Keycloak's built-ins, this tooling's own clients and role groups, any *-realm
    delegates = [d for ac in apps.values() for d in (ac.get("delegations") or {})]
    for cid in list(apps) + delegates:
        if cid in CONFIG_RESERVED_IDS or cid.endswith("-realm"):
            no("%r is a reserved client id (Keycloak built-in, this tooling's own, or *-realm)" % cid)
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", cid):
            no("%r is not a client id" % cid)
    if set(apps) & set(delegates):
        no("a delegate's client id is also an application")
    if len(delegates) != len(set(delegates)):
        no("a delegate client is listed under two applications")
    if "entra" in c:
        e = obj("entra", c["entra"], ENTRA_KEYS)
        for k in e:
            if k != "$comment":
                text("entra.%s" % k, e[k])
    if "smtp" in c:
        sm = obj("smtp", c["smtp"], SMTP_KEYS)
        for k in ("host", "from", "displayName"):
            if k in sm:
                text("smtp.%s" % k, sm[k])
        if "port" in sm and (not isinstance(sm["port"], int) or isinstance(sm["port"], bool) or not 0 < sm["port"] < 65536):
            no("smtp.port must be a port number")
    if "onboarding" in c:
        o = obj("onboarding", c["onboarding"], ONBOARDING_KEYS)
        for x in strs("onboarding.defaultApps", o["defaultApps"]) if "defaultApps" in o else []:
            if x not in apps:
                no("onboarding.defaultApps %s is not an application" % x)
        extra = strs("onboarding.clientIds", o["clientIds"]) if "clientIds" in o else []
        if len(set(extra)) != len(extra):
            no("onboarding.clientIds names a client twice")
        for x in extra:
            # never a built-in, this tooling's own (the default onboarding client included), an application, a delegate
            # or the hand-off worker: the onboarding shape (and its guard) would otherwise be applied to - or drift-fix
            # - a client that is something else
            if x in CONFIG_RESERVED_IDS or x.endswith("-realm") or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", x):
                no("onboarding.clientIds %r is reserved or not a client id" % x)
            if x in set(apps) | set(delegates) or x == (c.get("handoffIntake") or {}).get("clientId"):
                no("onboarding.clientIds %r is also an application, a delegate or the hand-off worker" % x)
    if "handoffIntake" in c:
        h = obj("handoffIntake", c["handoffIntake"], HANDOFF_KEYS)
        for k in sorted(HANDOFF_KEYS - {"name"}):
            if k not in h:
                no("handoffIntake.%s is required" % k)
        for k in h:
            if k != "$comment":
                text("handoffIntake.%s" % k, h[k])
        u_ = urllib.parse.urlsplit(h["url"])
        if u_.scheme != "https" or not u_.hostname or u_.username or u_.password or u_.query or u_.fragment \
                or "*" in h["url"] or re.fullmatch(r"[0-9.]+|\[?[0-9a-fA-F:.]+\]?", u_.hostname or ""):
            no("handoffIntake.url must be one plain https URL on a DNS name, without credentials, a query or a fragment")
        hc = h["clientId"]
        if hc in CONFIG_RESERVED_IDS or hc.endswith("-realm") or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", hc):
            no("handoffIntake.clientId %r is reserved or not a client id" % hc)
        if hc in set(apps) | set(delegates):
            no("handoffIntake.clientId %r is also an application or a delegate" % hc)
        for k in ("audience", "scope"):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", h[k]):
                no("handoffIntake.%s must be one token (letters, digits, . _ : -; no space)" % k)
        if h["scope"] in BUILTIN_SCOPES:
            no("handoffIntake.scope %r is one of Keycloak's own client scopes" % h["scope"])
        if h["app"] not in apps:
            no("handoffIntake.app %r is not an application (the filing application's tree decides whose hand-offs get a command)" % h["app"])
    for k in ("operatorSshHost", "repoClientsDir"):
        if k in c:
            text(k, c[k])
    return c

ADMIN_CONFIG = load_admin_config(ADMIN_CONFIG_FILE)
_AC = ADMIN_CONFIG or {}
_APPS = dict(_AC.get("applications") or {})

CFG_FILE = "/srv/idp/config/keycloak-cac.env"
# Off the host (the operator Mac: add-client / check-clients --host) there is no config; KC() refuses to start there.
CFG = {k: v for k, v in (l.strip().split("=", 1) for l in open(CFG_FILE) if "=" in l and not l.startswith("#"))} \
    if os.path.exists(CFG_FILE) else {}
REALM = CFG.get("CAC_REALM")
# Keycloak is reached from INSIDE its container's network namespace, on 127.0.0.1:8443: the only source the path
# filter trusts (STIG_TRUSTED_SOURCES=127.0.0.1) is one no network client can ever present - not even through
# docker-proxy, whose connections come from the bridge gateway. The certificate is still verified for the public
# host name (SNI).
ADMIN_HOST = urllib.parse.urlparse(CFG.get("CAC_PUBLIC_URL", "")).hostname
ADMIN_PORT = int(CFG.get("KC_HTTPS_PORT", "8443"))
KC_CONTAINER = os.environ.get("IDP_KC_CONTAINER", "idp-keycloak-1")
SECRETS = "/srv/idp/secrets"
STATE = "/srv/idp/state/admin-state.json"     # root-only: pending promotions, factor resets
ALLOWLIST = "/srv/idp/state/admins.json"      # root-only: the VETTED administrators (written only by grant/promote/revoke)

def enter_keycloak_netns():
    """Join the Keycloak container's network namespace (this process only; root). Idempotent."""
    if getattr(enter_keycloak_netns, "done", False):
        return
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Pid}}", KC_CONTAINER], capture_output=True, text=True)
    pid = r.stdout.strip()
    if r.returncode != 0 or not pid.isdigit() or pid == "0":
        sys.exit("keycloak container %s is not running (%s)" % (KC_CONTAINER, r.stderr.strip()[:200]))
    fd = os.open("/proc/%s/ns/net" % pid, os.O_RDONLY)
    try:
        os.setns(fd, os.CLONE_NEWNET)
    finally:
        os.close(fd)
    enter_keycloak_netns.done = True

class KC:
    def __init__(self):
        if not CFG:
            sys.exit("no %s: run this ON the IdP host (from the operator Mac use add-client / check-clients --host)" % CFG_FILE)
        if ADMIN_CONFIG is None:
            sys.exit("no %s: this deployment's applications, delegations and defaults are read from it (copy "
                     "idp-admin.example.json, edit, root 0600; or set IDP_ADMIN_CONFIG)" % ADMIN_CONFIG_FILE)
        enter_keycloak_netns()
        self.ctx = ssl.create_default_context()          # the real certificate for the admin host name
        self.token = None
        self.login()

    def login(self):
        # The stig-automation service account exists once the admin realm is hardened (CAC_ADMINS set). Until then
        # the image keeps the temporary bootstrap admin, as kcstig does: fall back to it.
        rd = lambda f: open(os.path.join(SECRETS, f)).read().strip()
        tries = [{"grant_type": "client_credentials", "client_id": "stig-automation", "client_secret": rd("automation_secret")}]
        if os.path.exists(os.path.join(SECRETS, "bootstrap_admin_password")):
            tries.append({"grant_type": "password", "client_id": "admin-cli", "username": "bootstrap",
                          "password": rd("bootstrap_admin_password")})
        for body in tries:
            st, r = self.req("POST", "/realms/master/protocol/openid-connect/token", urllib.parse.urlencode(body).encode(),
                             {"Content-Type": "application/x-www-form-urlencoded"}, auth=False)
            if st == 200:
                self.token = json.loads(r)["access_token"]; return
        sys.exit("admin login failed (stig-automation and bootstrap): HTTP %s" % st)

    def req(self, method, path, body=None, headers=None, auth=True, _retry=True):
        sock = socket.create_connection(("127.0.0.1", ADMIN_PORT), timeout=30)
        con = http.client.HTTPSConnection(ADMIN_HOST, ADMIN_PORT, context=self.ctx, timeout=60)
        con.sock = self.ctx.wrap_socket(sock, server_hostname=ADMIN_HOST)
        h = dict(headers or {})
        if auth:
            h["Authorization"] = "Bearer " + self.token
        con.request(method, path, body=body, headers=h)
        r = con.getresponse(); data = r.read().decode(); con.close()
        if r.status == 401 and auth and _retry:      # the automation token expired during a long run: log in again once
            self.login()
            return self.req(method, path, body, headers, auth, _retry=False)
        return r.status, data

    def api(self, method, path, obj=None, ok=(200, 201, 204), ok404=False):
        st, data = self.req(method, "/admin/realms/%s%s" % (REALM, path), json.dumps(obj).encode() if obj is not None else None,
                            {"Content-Type": "application/json"} if obj is not None else {})
        if st == 404 and ok404:
            return None
        if st not in ok:
            sys.exit("%s %s -> HTTP %s %s" % (method, path, st, data[:300]))
        return json.loads(data) if data.strip() else None

def q(s):
    return urllib.parse.quote(s, safe="")

POST_BROKER = "STIG Post Broker Login"

IDENTITY_BINDINGS = ("entra_oid", "cac_edipi")       # administrator-set; no identity-provider mapper may write them

def binding_cfg(alias, tenant):
    """stig-extensions AdminBoundIdentity: only `alias`, only `tenant`, compared with the admin-set entra_oid."""
    return {"stig.idp-alias": alias, "stig.tenant-id": tenant, "stig.admin-attribute": "entra_oid",
            "stig.vouched-oid-attribute": "entra_vouched_oid", "stig.vouched-tenant-attribute": "entra_vouched_tid"}

def set_exec_config(kc, flow_alias, provider, cfg):
    """Create or REPLACE the configuration of `provider`'s execution in `flow_alias` (flow() only adds a missing one)."""
    for e in kc.api("GET", "/authentication/flows/%s/executions" % q(flow_alias)):
        if e.get("providerId") == provider:
            if e.get("authenticationConfig"):
                cur = kc.api("GET", "/authentication/config/%s" % e["authenticationConfig"])
                if cur.get("config") != cfg:
                    cur["config"] = cfg; kc.api("PUT", "/authentication/config/%s" % cur["id"], cur)
            else:
                kc.api("POST", "/authentication/executions/%s/config" % e["id"],
                       {"alias": "%s-%s" % (flow_alias.lower().replace(" ", "-"), provider), "config": cfg})
            return
    raise RuntimeError("no %s execution in %s" % (provider, flow_alias))

def binding_mappers(kc):
    """(alias, mapper) of every identity-provider mapper that writes an identity binding."""
    out = []
    for idp in kc.api("GET", "/identity-provider/instances") or []:
        for m in kc.api("GET", "/identity-provider/instances/%s/mappers" % q(idp["alias"])) or []:
            if any(((m.get("config") or {}).get(k) or "").strip().lower() in IDENTITY_BINDINGS
                   for k in ("user.attribute", "attribute", "attribute.name")):
                out.append((idp["alias"], m))
    return out

FIRST_BROKER = "STIG First Broker Link by Admin"
ENTRA_PENDING = "entra_pending"                     # set by stig-accounts on an account created to sign in with Entra
ENTRA_PENDING_VALUE = "pending"                     # its fixed value (an exact attribute search finds them all)
ENTRA_INVITE_DAYS = 7                               # the first Entra sign-in may bind such an account this long

def created_ms(marker):
    """The epoch-ms time a stig-accounts marker ("<caller> <ms>") records, or None."""
    p = (marker or "").split()
    return int(p[-1]) if len(p) >= 2 and p[-1].isdigit() else None

def x509_step_configs(kc, flow_alias):
    """The configuration of every X.509 step in a flow (sub-flows included; the admin API lists them flattened); None
    for a step without one."""
    out = []
    for e in kc.api("GET", "/authentication/flows/%s/executions" % q(flow_alias or "browser")) or []:
        if e.get("providerId") in ("stig-x509-client-username-form", "auth-x509-client-username-form"):
            out.append((kc.api("GET", "/authentication/config/%s" % e["authenticationConfig"]) or {}).get("config")
                       if e.get("authenticationConfig") else None)
    return out

def cmd_card_accounts(a):
    """stig-accounts' signIn "cac" (a user manager creates an account with its card bound): on = the realm attribute
    stig.accounts.card-attribute names the X.509 mapping attribute; off = empty (no card accounts)."""
    kc = KC(); r = kc.api("GET", ""); at = dict(r.get("attributes") or {})
    if a.state == "on":
        # the card must land in the attribute the realm's X.509 step maps cards by, and every X.509 step must agree
        cfgs = x509_step_configs(kc, r.get("browserFlow"))
        names = {(c or {}).get("x509-cert-auth.mapper-selection.user-attribute-name") for c in cfgs}
        if not cfgs or None in names or len({json.dumps(c, sort_keys=True) for c in cfgs}) != 1 or names != {a.attribute}:
            sys.exit("REFUSED: the browser flow's X.509 step(s) must exist, be configured identically and map cards by %s "
                     "(found: %s)" % (a.attribute, sorted(str(x) for x in names) or "no X.509 step"))
    at["stig.accounts.card-attribute"] = a.attribute if a.state == "on" else ""
    kc.api("PUT", "", {"attributes": at})
    # the "present your card" step an Entra + CAC invite needs (stig-extensions PresentCardRequiredAction). Off leaves it
    # enabled: it acts only on an account with a live request, and an invite's needs the card attribute switched off
    # here - while link-cac's requests (cards for existing accounts) need the step whether card accounts are on or not
    if a.state == "on":
        ensure_present_card_step(kc)
    print("card accounts: %s" % ("ON (signIn cac binds %s at creation)" % a.attribute if a.state == "on" else "OFF"))

def pending_invite_cfg(domain):
    """stig-extensions PendingInviteLink: the first sign-in binds the one pending stig-accounts invite whose username or
    e-mail is the provider's UPN in `domain`. None/"" = off (the domain is sent EMPTY: an absent key would be kept)."""
    if not domain:
        return {"stig.pending-invite-domain": ""}
    return {"stig.pending-invite-domain": domain, "stig.pending-invite-max-age-days": str(ENTRA_INVITE_DAYS),
            "stig.vouched-upn-attribute": "entra_vouched_upn", "stig.card-attribute": "cac_edipi",
            "stig.created-by-attribute": CREATED_BY, "stig.vouched-idp-attribute": "entra_vouched_idp",
            "stig.vouched-acct-attribute": "entra_vouched_acct"}

# Microsoft Graph, to check that an --auto-link-domain is one of the tenant's VERIFIED domains (only then does the
# tenant own every UPN in it). Module variables so the lab can point them at its mock.
GRAPH_LOGIN = "https://login.microsoftonline.com"
GRAPH_API = "https://graph.microsoft.com"

def tenant_verified_domains(tenant, client_id, secret, timeout=15):
    """The tenant's verified domain names (lower case) through Graph (client credentials of the broker's app; needs
    Domain.Read.All application permission), or None when Graph cannot be asked (unreachable, no permission)."""
    import urllib.request, urllib.error
    try:
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret,
                                       "scope": GRAPH_API + "/.default"}).encode()
        with urllib.request.urlopen(urllib.request.Request("%s/%s/oauth2/v2.0/token" % (GRAPH_LOGIN, tenant), body), timeout=timeout) as r:
            tok = json.loads(r.read(65536))["access_token"]
        req = urllib.request.Request(GRAPH_API + "/v1.0/domains?$select=id,isVerified", headers={"Authorization": "Bearer " + tok})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {d["id"].lower() for d in json.loads(r.read(1 << 20)).get("value", []) if d.get("isVerified")}
    except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError):
        return None

def current_autolink_domain(kc):
    """The domain the live first-broker step binds pending invites in, or None (off / no such flow)."""
    try:
        for e in kc.api("GET", "/authentication/flows/%s/executions" % q(FIRST_BROKER)) or []:
            if e.get("providerId") == "idp-link-by-admin-attribute" and e.get("authenticationConfig"):
                return (kc.api("GET", "/authentication/config/%s" % e["authenticationConfig"]).get("config") or {}).get(
                    "stig.pending-invite-domain") or None
    except SystemExit:
        return None
    return None

def first_broker_flow(kc, alias, tenant, autolink_domain=None):
    first = FIRST_BROKER
    flow(kc, first, [("idp-link-by-admin-attribute", "REQUIRED", None)])
    set_exec_config(kc, first, "idp-link-by-admin-attribute", dict(binding_cfg(alias, tenant), **pending_invite_cfg(autolink_domain)))
    return first

def post_broker_flow(kc, alias="entra", tenant=None):
    """Post broker login. An administrator (any realm-management role: stig-extensions' conditional-stig-administrator)
    whose identity provider did not report MFA in `amr` must pass Keycloak TOTP - and one with NO enrolled second factor
    is refused (stig-admin-second-factor-required), never offered enrolment after the provider's single factor. Then
    the concurrent-session limit, for everyone."""
    sub = POST_BROKER + " - administrators prove MFA"
    want = ["conditional-stig-administrator", "conditional-user-attribute", "stig-admin-second-factor-required", "auth-otp-form"]
    if any(f["alias"] == POST_BROKER for f in kc.api("GET", "/authentication/flows")):
        execs = kc.api("GET", "/authentication/flows/%s/executions" % q(POST_BROKER))
        have = [e.get("providerId") for e in execs if e.get("level") == 1]
        if have and have != want:     # an earlier shape (conditional-user-role, no refusal): rebuild the sub-flow
            for e in execs:
                if e.get("level") == 0 and e.get("displayName") == sub:
                    kc.api("DELETE", "/authentication/executions/%s" % e["id"])
    # every brokered sign-in, through a new or an EXISTING link, must come from `alias` in `tenant` and carry the
    # admin-set entra_oid: a link someone else made (a delegate via the admin API, the user via the account console)
    # signs nobody in
    if not tenant:
        raise RuntimeError("post broker flow needs the tenant id")
    flow(kc, POST_BROKER, [("idp-require-admin-attribute-match", "REQUIRED", None),
                           ("user-session-limits", "REQUIRED",
          {"userRealmLimit": "3", "userClientLimit": "0", "behavior": "Deny new session",
           "errorMessage": "Maximum concurrent sessions reached. Log out of another session first."})])
    subflow(kc, POST_BROKER, sub, "CONDITIONAL",
            [("conditional-stig-administrator", "REQUIRED", None),
             ("conditional-user-attribute", "REQUIRED", {"attribute_name": "entra_amr", "attribute_expected_value": "mfa",
                                                         "not": "true", "regex": "false", "include_group_attributes": "false"}),
             ("stig-admin-second-factor-required", "REQUIRED", None),
             ("auth-otp-form", "REQUIRED", None)], first_position=True)
    set_exec_config(kc, POST_BROKER, "idp-require-admin-attribute-match", binding_cfg(alias, tenant))
    ex = kc.api("GET", "/authentication/flows/%s/executions" % q(POST_BROKER))
    got = [e.get("providerId") for e in ex if e.get("level") == 1]
    top = [(e.get("providerId") or "SUB", e["requirement"]) for e in ex if e.get("level") == 0]
    if ("idp-require-admin-attribute-match", "REQUIRED") not in top:
        raise RuntimeError("post broker flow lacks a REQUIRED idp-require-admin-attribute-match: %s" % top)
    if got != want:
        raise RuntimeError("post broker sub-flow is %s, expected %s" % (got, want))
    return POST_BROKER

def flow(kc, alias, execs, create=True):
    """Top-level flow with exactly these (provider, requirement, config) executions, in order. Idempotent: creates the
    flow if absent, adds missing executions, and resets requirements. Returns the provider list now in the flow."""
    if create and not any(f["alias"] == alias for f in kc.api("GET", "/authentication/flows")):
        kc.api("POST", "/authentication/flows", {"alias": alias, "providerId": "basic-flow", "topLevel": True, "builtIn": False,
                                                 "description": "shared IdP (idp-admin.py)"})
    for prov, req, cfg in execs:
        cur = [e for e in kc.api("GET", "/authentication/flows/%s/executions" % q(alias)) if e.get("providerId") == prov]
        if not cur:
            kc.api("POST", "/authentication/flows/%s/executions/execution" % q(alias), {"provider": prov})
            cur = [e for e in kc.api("GET", "/authentication/flows/%s/executions" % q(alias)) if e.get("providerId") == prov]
        ex = cur[-1]
        if ex.get("requirement") != req:
            ex["requirement"] = req
            kc.api("PUT", "/authentication/flows/%s/executions" % q(alias), ex)
        if cfg and not ex.get("authenticationConfig"):
            kc.api("POST", "/authentication/executions/%s/config" % ex["id"], {"alias": "%s-%s" % (alias.lower().replace(" ", "-"), prov), "config": cfg})
    # order: as listed (raise each execution until it sits at its index)
    for i, (prov, _, _) in enumerate(execs):
        while True:
            cur = kc.api("GET", "/authentication/flows/%s/executions" % q(alias))
            top = [e for e in cur if e.get("level", 0) == 0]
            idx = [e.get("providerId") for e in top].index(prov)
            cur = top
            if idx <= i:
                break
            kc.api("POST", "/authentication/executions/%s/raise-priority" % cur[idx]["id"])
    return [(e.get("providerId") or e.get("displayName")) + ":" + e.get("requirement")
            for e in kc.api("GET", "/authentication/flows/%s/executions" % q(alias))]

def subflow(kc, parent, alias, requirement, execs, first_position=False):
    """A sub-flow inside `parent` holding exactly these (provider, requirement, config) executions. Idempotent."""
    cur = [e for e in kc.api("GET", "/authentication/flows/%s/executions" % q(parent)) if e.get("displayName") == alias and e.get("authenticationFlow")]
    if not cur:
        kc.api("POST", "/authentication/flows/%s/executions/flow" % q(parent),
               {"alias": alias, "type": "basic-flow", "provider": "registration-page-form", "description": "shared IdP (idp-admin.py)"})
        cur = [e for e in kc.api("GET", "/authentication/flows/%s/executions" % q(parent)) if e.get("displayName") == alias]
    ex = cur[0]
    if ex.get("requirement") != requirement:
        ex["requirement"] = requirement; kc.api("PUT", "/authentication/flows/%s/executions" % q(parent), ex)
    if first_position:
        while kc.api("GET", "/authentication/flows/%s/executions" % q(parent))[0]["id"] != ex["id"]:
            kc.api("POST", "/authentication/executions/%s/raise-priority" % ex["id"])
    flow(kc, alias, execs, create=False)

def flow_shape(kc, alias):
    return ["%s%s:%s" % ("  " * e.get("level", 0), e.get("providerId") or e.get("displayName"), e.get("requirement"))
            for e in kc.api("GET", "/authentication/flows/%s/executions" % q(alias))]

def entra_member_domain(a):
    """The one UPN domain whose tenant members may sign in through Entra: --member-domain, else the config's
    entra.memberDomain. Required: an unfiltered provider would admit guests and every other domain of the tenant."""
    d = (getattr(a, "member_domain", None) or (_AC.get("entra") or {}).get("memberDomain") or "").lower()
    if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", d):
        sys.exit("REFUSED: no Entra member domain: set entra.memberDomain in %s or pass --member-domain" % ADMIN_CONFIG_FILE)
    return d

def cmd_entra(a):
    member_domain = entra_member_domain(a)
    kc = KC()
    old_flow = [f for f in kc.api("GET", "/authentication/flows") if f["alias"] == "STIG First Broker Link"]
    secret = open(a.secret_file).read().strip()
    # First broker login: never create, never match by name or e-mail. Link ONLY to the one account whose admin-set
    # `entra_oid` equals the Entra object id in the token (stig-extensions' idp-link-by-admin-attribute). An admin
    # sets entra_oid (idp-admin.py link-entra / invite --entra-oid); it is unique and realm-admin-only.
    # first-sign-in binding of pending invites: --auto-link-domain D on, --no-auto-link off, neither
    # = as it is now (a re-run, e.g. for a secret rotation, never switches it silently)
    if a.auto_link_domain and a.no_auto_link:
        sys.exit("REFUSED: --auto-link-domain and --no-auto-link together")
    if a.auto_link_domain and not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", a.auto_link_domain.lower()):
        sys.exit("REFUSED: --auto-link-domain is a DNS domain (e.g. the tenant's UPN suffix)")
    domain = (a.auto_link_domain.lower() if a.auto_link_domain else None) if (a.auto_link_domain or a.no_auto_link) \
        else current_autolink_domain(kc)
    if a.auto_link_domain:
        # A UPN binds an invite only because the tenant OWNS the domain: it must be one of the tenant's verified
        # domains. Graph answers when it can be asked; otherwise the operator must say they checked it (Entra admin
        # center -> Domain names: the domain is listed and Verified).
        verified = tenant_verified_domains(a.tenant, a.client_id, secret)
        if verified is not None and domain not in verified:
            sys.exit("REFUSED: %s is not a verified domain of tenant %s (Graph lists: %s)" % (domain, a.tenant, ", ".join(sorted(verified)) or "none"))
        if verified is None and not getattr(a, "domain_verified_by_operator", False):
            sys.exit("REFUSED: Graph could not confirm that %s is a verified domain of tenant %s (no Domain.Read.All, or "
                     "unreachable). Check it in the Entra admin center (Settings -> Domain names: listed, Verified) and "
                     "re-run with --domain-verified-by-operator" % (domain, a.tenant))
        print("entra: %s is a verified domain of the tenant (%s)" % (domain, "Graph" if verified is not None else "the operator's word"))
    first = first_broker_flow(kc, "entra", a.tenant, domain)
    # stig-accounts creates `signIn: entra` accounts only for this domain (realm attribute; empty = none)
    r_ = kc.api("GET", ""); at_ = dict(r_.get("attributes") or {})
    if at_.get("stig.accounts.entra-domain", "") != (domain or ""):
        at_["stig.accounts.entra-domain"] = domain or ""
        kc.api("PUT", "", {"attributes": at_})
    print("entra: first sign-in binding of pending invites %s" % (("ON for @%s (invites at most %d days old)" % (domain, ENTRA_INVITE_DAYS))
                                                                   if domain else "OFF"))
    post = post_broker_flow(kc, "entra", a.tenant)
    print("entra: first broker %s; post broker %s" % (flow_shape(kc, first), flow_shape(kc, post)))
    base = "https://login.microsoftonline.com/%s" % a.tenant
    # DISABLED (not merely hidden: a hidden provider still accepts kc_idp_hint / the broker URL) until --enable, the
    # step after tenant admin consent and a Conditional Access policy requiring MFA for this app registration.
    rep = {"alias": "entra", "displayName": (_AC.get("entra") or {}).get("displayName") or "Microsoft Entra ID", "providerId": "oidc", "enabled": bool(a.enable),
           "trustEmail": False, "storeToken": False, "addReadTokenRoleOnCreate": False, "linkOnly": False,
           "hideOnLogin": not a.enable,
           "firstBrokerLoginFlowAlias": "STIG First Broker Link by Admin", "postBrokerLoginFlowAlias": "STIG Post Broker Login",
           "config": {"issuer": base + "/v2.0", "authorizationUrl": base + "/oauth2/v2.0/authorize",
                      "tokenUrl": base + "/oauth2/v2.0/token", "logoutUrl": base + "/oauth2/v2.0/logout",
                      "jwksUrl": base + "/discovery/v2.0/keys", "useJwksUrl": "true", "validateSignature": "true",
                      "clientId": a.client_id, "clientSecret": secret, "clientAuthMethod": "client_secret_post",
                      "defaultScope": "openid profile email", "pkceEnabled": "true", "pkceMethod": "S256",
                      "syncMode": "IMPORT", "backchannelSupported": "false", "disableUserInfo": "true",
                      # fresh sign-in: an application's reauth (prompt=login / max_age) is passed on, so Entra re-authenticates too
                      "passMaxAge": "true", "prompt": "", "loginHint": "false", "uiLocales": "false",
                      "guiOrder": "10", "isAccessTokenJWT": "false", "hideOnLoginPage": str(not a.enable).lower(),
                      # members of the tenant with a UPN in the member domain only: guests (#EXT#, other domains) refused
                      "filteredByClaim": "true", "claimFilterName": "preferred_username",
                      "claimFilterValue": "^[A-Za-z0-9._%%+-]+@%s$" % re.escape(member_domain)}}
    cur = kc.api("GET", "/identity-provider/instances/entra", ok404=True)
    if cur is None:
        kc.api("POST", "/identity-provider/instances", rep); print("entra: created")
    else:
        rep["internalId"] = cur["internalId"]; kc.api("PUT", "/identity-provider/instances/entra", rep); print("entra: updated")
    for f in old_flow:   # the earlier link-by-name-or-e-mail flow, now that the provider no longer points at it
        kc.api("DELETE", "/authentication/flows/%s" % f["id"]); print("entra: removed the link-by-name flow")
    # Evidence of Entra's MFA: the ID token's amr claim (e.g. ["pwd","mfa"]) copied to an admin-only attribute on every
    # Entra sign-in. Keycloak does not act on it (MFA is Entra's job, by decision); it is for the operator to check.
    # Guarded like the card mapping: through the admin API only realm administrators may write it (a fine-grained
    # delegate is "admin" to the user profile too); the IdP mapper writes it outside the admin API.
    want = {"name": "entra_amr", "displayName": "Entra sign-in methods (amr, last Entra sign-in)",
            "permissions": {"view": ["admin"], "edit": ["admin"]}, "multivalued": True,
            "validations": {"length": {"max": "64"}, "cac-identity-guard": {"unique": "false"}}, "annotations": {}}
    oid = {"name": "entra_oid", "displayName": "Entra object id (links Entra sign-in to this account)",
           "permissions": {"view": ["admin"], "edit": ["admin"]}, "multivalued": False,
           "validations": {"length": {"max": "64"}, "pattern": {"pattern": "^[0-9a-f-]{36}$", "error-message": "an Entra object id (GUID)"},
                           "cac-identity-guard": {}}, "annotations": {}}
    up = kc.api("GET", "/users/profile")
    for w in (want, oid):
        cur = [x for x in up["attributes"] if x["name"] == w["name"]]
        if not cur or cur[0].get("validations") != w["validations"]:
            up["attributes"] = [x for x in up["attributes"] if x["name"] != w["name"]] + [w]
            kc.api("PUT", "/users/profile", up); up = kc.api("GET", "/users/profile")

    mappers = kc.api("GET", "/identity-provider/instances/entra/mappers")
    want = [{"name": "username from UPN", "identityProviderAlias": "entra", "identityProviderMapper": "oidc-username-idp-mapper",
             "config": {"template": "${CLAIM.preferred_username | localpart | lowercase}", "target": "LOCAL", "syncMode": "IMPORT"}},
            # what Entra vouches for, on every sign-in, into DEDICATED attributes - never into the admin-set entra_oid
            {"name": "entra vouched oid", "identityProviderAlias": "entra", "identityProviderMapper": "oidc-user-attribute-idp-mapper",
             "config": {"claim": "oid", "user.attribute": "entra_vouched_oid", "syncMode": "IMPORT"}},
            {"name": "entra vouched tenant", "identityProviderAlias": "entra", "identityProviderMapper": "oidc-user-attribute-idp-mapper",
             "config": {"claim": "tid", "user.attribute": "entra_vouched_tid", "syncMode": "IMPORT"}},
            # the UPN Entra vouches for (preferred_username: Entra's UPN for a member), for the pending-invite binding;
            # never the e-mail claim, which a user or an admin can change
            {"name": "entra vouched upn", "identityProviderAlias": "entra", "identityProviderMapper": "oidc-user-attribute-idp-mapper",
             "config": {"claim": "preferred_username", "user.attribute": "entra_vouched_upn", "syncMode": "IMPORT"}},
            # guests of the tenant (B2B, one-time passcode, Microsoft accounts) carry its tid but their HOME sign-in
            # name as preferred_username: Entra names their provider in idp (absent for a member), and the optional
            # acct claim is 1 for a guest. A pending invite is never bound to either (stig-extensions refuses; it
            # also refuses to bind at all unless exactly these mappers feed the attributes)
            {"name": "entra vouched idp", "identityProviderAlias": "entra", "identityProviderMapper": "oidc-user-attribute-idp-mapper",
             "config": {"claim": "idp", "user.attribute": "entra_vouched_idp", "syncMode": "IMPORT"}},
            {"name": "entra vouched acct", "identityProviderAlias": "entra", "identityProviderMapper": "oidc-user-attribute-idp-mapper",
             "config": {"claim": "acct", "user.attribute": "entra_vouched_acct", "syncMode": "IMPORT"}},
            {"name": "amr evidence", "identityProviderAlias": "entra", "identityProviderMapper": "oidc-user-attribute-idp-mapper",
             "config": {"claim": "amr", "user.attribute": "entra_amr", "syncMode": "FORCE"}}]
    for al, m in binding_mappers(kc):      # e.g. the earlier "entra object id" (oid -> entra_oid)
        kc.api("DELETE", "/identity-provider/instances/%s/mappers/%s" % (q(al), m["id"]))
        print("entra: removed mapper %s/%s, which wrote the identity binding %s" % (al, m["name"], m["config"]))
    mappers = kc.api("GET", "/identity-provider/instances/entra/mappers")
    for m in want:
        cur = [x for x in mappers if x["name"] == m["name"]]
        if not cur:
            kc.api("POST", "/identity-provider/instances/entra/mappers", m)
        elif cur[0].get("config") != m["config"]:
            kc.api("PUT", "/identity-provider/instances/entra/mappers/%s" % cur[0]["id"], dict(m, id=cur[0]["id"]))
    print("entra: %s; redirect URI %s/realms/%s/broker/entra/endpoint" % (
        "ENABLED and shown on the login page" if a.enable else "DISABLED (and hidden) until --enable", CFG["CAC_PUBLIC_URL"], REALM))

def client_uuid(kc, cid):
    cs = kc.api("GET", "/clients?clientId=%s" % q(cid))
    if not cs:
        sys.exit("no client %s" % cid)
    return cs[0]["id"]

def user(kc, username):
    us = kc.api("GET", "/users?exact=true&username=%s" % q(username))
    if not us:
        sys.exit("no user %s" % username)
    return us[0]

# ------------------------------------------------------------------------------------------- role catalogue
ROLE_GROUPS = {   # /roles/<name>: realm-management roles it carries
    "idp-admin": ["realm-admin"],
    # NOT realm-wide manage-users, which can take over an administrator's account. A user
    # manager manages only the members of the application role groups, through fine-grained admin permissions.
    "idp-user-manager": ["query-users", "query-groups"],
    "idp-auditor": ["view-events", "view-users", "query-users", "query-groups"],
}
# The applications with delegated role-group trees (/<client>/<ROLE> groups): the config's `applications`, in its
# order. Retiring one: remove it from the config, then `roles-setup --retire-app <client>` (plain roles-setup REFUSES
# while the removed app's delegation is still live: its former managers would keep their write power), then
# onboarding-client-setup with the remaining --app list.
APP_CLIENTS = tuple(_APPS)
# Per-application user managers: /roles/<app>-user-manager carries the same realm-management roles as
# /roles/idp-user-manager but reaches ONLY its own application's tree (sync_delegations: `delegates of /<app>` and every
# `writers of /<app>/<GROUP>`, never the bare root); /roles/idp-user-manager stays the all-applications role. An
# application gets one by setting `userManagerRole` in the config and re-running roles-setup.
#   app -> the client role of that app every holder must ALSO hold. The manager role is granted by the operator
#   (`grant <u> <app>-user-manager <app>:<ROLE>`), NEVER derived from that client role: the app's own delegate can write
#   the group carrying it, so deriving would let the app mint account managers. The guard reports a holder who lacks it
#   (STIG-APP-MANAGER-MISALIGNED, exit 2, nothing changed) and grant refuses to create one.
# For an application whose own `admin` role marks its administrators, that role carries no realm-management role, so
# stig-accounts treats its group as ordinary.
APP_USER_MANAGERS = {app: c["userManagerRole"] for app, c in _APPS.items() if c.get("userManagerRole")}
assert set(APP_USER_MANAGERS) <= set(APP_CLIENTS)

def app_manager_role(app):
    return "%s-user-manager" % app

ROLE_GROUPS.update({app_manager_role(app): ["query-users", "query-groups"] for app in APP_USER_MANAGERS})

def group_by_path(kc, path):
    return kc.api("GET", "/group-by-path/%s" % urllib.parse.quote(path.strip("/")), ok404=True)

def ensure_group(kc, path):
    g = group_by_path(kc, path)
    if g:
        return g
    parent, name = path.rstrip("/").rsplit("/", 1)
    if parent:
        kc.api("POST", "/groups/%s/children" % ensure_group(kc, parent)["id"], {"name": name})
    else:
        kc.api("POST", "/groups", {"name": name})
    return group_by_path(kc, path)

def set_group_client_roles(kc, g, client_id, names):
    cu = client_uuid(kc, client_id)
    have = kc.api("GET", "/groups/%s/role-mappings/clients/%s" % (g["id"], cu)) or []
    extra = [r for r in have if r["name"] not in names]
    if extra:
        kc.api("DELETE", "/groups/%s/role-mappings/clients/%s" % (g["id"], cu), extra)
    want = [kc.api("GET", "/clients/%s/roles/%s" % (cu, q(n))) for n in names if n not in [r["name"] for r in have]]
    if want:
        kc.api("POST", "/groups/%s/role-mappings/clients/%s" % (g["id"], cu), want)

def app_groups(kc):
    out = []
    for c in APP_CLIENTS:
        if not kc.api("GET", "/clients?clientId=%s" % q(c)):
            continue
        cu = client_uuid(kc, c)
        top = ensure_group(kc, "/" + c)
        out.append(top)
        for r in kc.api("GET", "/clients/%s/roles" % cu) or []:
            g = ensure_group(kc, "/%s/%s" % (c, r["name"]))
            set_group_client_roles(kc, g, c, [r["name"]])
            out.append(g)
    return out

def removed_apps(kc):
    """Applications that still have delegation objects (a /roles/<app>-user-manager group, or `membership:` /
    `delegated:` permissions, `writers of` / `delegates of` aggregates, the manager group policy) although they are no
    longer in APP_CLIENTS / APP_USER_MANAGERS - e.g. an application just taken out of the config. {app: [what remains]}."""
    out = {}
    roles_root = group_by_path(kc, "/roles")
    for g in (paged(kc, "/groups/%s/children" % roles_root["id"]) if roles_root else []):
        nm = g["path"][len("/roles/"):]
        if nm.endswith("-user-manager") and nm != "idp-user-manager" and nm not in ROLE_GROUPS and (
                paged(kc, "/groups/%s/members" % g["id"]) or (kc.api("GET", "/groups/%s/role-mappings" % g["id"]) or {}).get("clientMappings")):
            out.setdefault(nm[:-len("-user-manager")], []).append(g["path"])       # (a retired one: empty, roleless)
    # allowlist entries still naming a manager group of an application no longer configured
    for uid, e in sorted(load_allowlist().items()):
        for path in [g_.get("path") for g_ in e.get("grants") or []] + [r for r in e.get("roles") or [] if isinstance(r, str)]:
            nm = (path or "")[len("/roles/"):] if (path or "").startswith("/roles/") else (path or "")
            if nm.endswith("-user-manager") and nm != "idp-user-manager" and nm not in ROLE_GROUPS:
                out.setdefault(nm[:-len("-user-manager")], []).append("allowlist entry %s" % e.get("username", uid))
                break
    ap = kc.api("GET", "/clients?clientId=admin-permissions") or []
    if ap:
        base = "/clients/%s/authz/resource-server" % ap[0]["id"]
        for kind in ("permission", "policy"):
            for p_ in paged(kc, base + "/" + kind):
                m_ = re.match(r"^(?:membership: |delegated: |writers of |delegates of )/([^/ ]+)", p_["name"]) or \
                     re.match(r"^(.+)-user-manager group$", p_["name"])
                if m_ and m_.group(1) not in APP_CLIENTS and m_.group(1) != "idp":
                    out.setdefault(m_.group(1), []).append("%s %r" % (kind, p_["name"]))
    return out

def prune_allowlist_grant(kc, gid, path):
    """Take a retired group out of every allowlist entry (its grant, its path); an entry left with no grant leaves the
    allowlist (that account administers nothing any more). Published only if something changed."""
    al = load_allowlist(); changed = False
    for uid, e in list(al.items()):
        grants = e.get("grants") or []
        roles = e.get("roles") or []
        keep = [g_ for g_ in grants if g_.get("id") != gid and g_.get("path") != path]
        keep_roles = [r for r in roles if r not in (path, path[len("/roles/"):])]
        if len(keep) == len(grants) and len(keep_roles) == len(roles):
            continue
        changed = True
        if keep:
            e["grants"], e["roles"] = keep, keep_roles
            e["rm_roles"] = sorted(set().union(*[set(g_["roles"]) for g_ in keep]))
        else:
            al.pop(uid)
        print("retire: allowlist entry %s %s" % (e.get("username"), "pruned of %s" % path if keep else "removed (no grant left)"))
    if changed:
        _write_json(ALLOWLIST, al)
        publish_allowlist(kc, al)

def retire_apps(kc, retire):
    """Refuse while a removed application's delegation still exists (its former managers would keep their write power);
    --retire-app <client> tears it down: every `membership:` / `delegated:` permission and `writers of` / `delegates of`
    aggregate of that tree, the manager group's policy, the manager group's realm-management roles and members (the
    group itself stays, empty and roleless, so allowlist entries naming it still resolve). Verified by a re-read."""
    left = removed_apps(kc)
    bad = [x for x in retire if x in APP_CLIENTS]
    if bad:
        sys.exit("REFUSED: --retire-app %s: still configured (remove it from the config's applications first)" % ", ".join(bad))
    unasked = {k: v for k, v in left.items() if k not in retire}
    if unasked:
        sys.exit("REFUSED: delegation of removed application(s) still live - its former managers would keep their write "
                 "power: %s. Run roles-setup --retire-app <client> to tear it down." %
                 "; ".join("%s (%s)" % (k, ", ".join(v[:4]) + (" ..." if len(v) > 4 else "")) for k, v in sorted(unasked.items())))
    if not retire:
        return
    ap = kc.api("GET", "/clients?clientId=admin-permissions")[0]
    base = "/clients/%s/authz/resource-server" % ap["id"]
    for app in retire:
        pats = (r"^(membership: |delegated: )/%s(/|$)" % re.escape(app), r"^(writers of |delegates of )/%s(/|$)" % re.escape(app),
                r"^%s-user-manager group$" % re.escape(app))
        for kind in ("permission", "policy"):                 # permissions first: nothing points at a deleted policy
            for p_ in paged(kc, base + "/" + kind):
                if any(re.match(x, p_["name"]) for x in pats):
                    kc.api("DELETE", base + "/%s/%s" % ("permission" if kind == "permission" else "policy", p_["id"]), ok404=True)
                    print("retire %s: removed %s %r" % (app, kind, p_["name"]))
        g = group_by_path(kc, "/roles/%s-user-manager" % app)
        if g:
            # the allowlist FIRST: an interruption after this leaves the group still carrying roles/members, which
            # removed_apps reports, so a plain roles-setup keeps refusing until a re-run completes it
            prune_allowlist_grant(kc, g["id"], g["path"])
            for cname in ("realm-management",):
                cu = client_uuid(kc, cname)
                have = kc.api("GET", "/groups/%s/role-mappings/clients/%s" % (g["id"], cu)) or []
                if have:
                    kc.api("DELETE", "/groups/%s/role-mappings/clients/%s" % (g["id"], cu), have)
            for u in paged(kc, "/groups/%s/members" % g["id"]):
                kc.api("DELETE", "/users/%s/groups/%s" % (u["id"], g["id"]))
            print("retire %s: /roles/%s-user-manager stripped of its realm-management roles and members" % (app, app))
    left = {k: v for k, v in removed_apps(kc).items() if k in retire}
    still = {k: [x for x in v if not x.startswith("/roles/")] for k, v in left.items()}
    g_left = [g_ for g_ in (group_by_path(kc, "/roles/%s-user-manager" % x) for x in retire) if g_ and (
        paged(kc, "/groups/%s/members" % g_["id"]) or kc.api("GET", "/groups/%s/role-mappings" % g_["id"]).get("clientMappings"))]
    if any(still.values()) or g_left:
        raise RuntimeError("retire: delegation still present after the tear-down: %s %s" % (still, [x["path"] for x in g_left]))

def cmd_roles_setup(a):
    """The role catalogue: /roles/idp-admin|idp-user-manager|idp-auditor and /<app client>/<ROLE> groups, plus the
    user manager's fine-grained permission over the application groups. Idempotent."""
    kc = KC()
    if not kc.api("GET", "").get("adminPermissionsEnabled"):
        kc.api("PUT", "", {"adminPermissionsEnabled": True})
    retire_apps(kc, getattr(a, "retire_app", None) or [])
    for name, roles in ROLE_GROUPS.items():
        set_group_client_roles(kc, ensure_group(kc, "/roles/" + name), "realm-management", roles)
    up = kc.api("GET", "/users/profile")
    want = {"name": CREATED_BY, "displayName": "Created by a delegate (stig-accounts)", "permissions": {"view": ["admin"], "edit": ["admin"]},
            "multivalued": False, "validations": {"length": {"max": "255"}, "cac-identity-guard": {"unique": "false"}}, "annotations": {}}
    pend = {"name": ENTRA_PENDING, "displayName": "Entra invite pending (signs in with Entra; bound at the first sign-in)",
            "permissions": {"view": ["admin"], "edit": ["admin"]}, "multivalued": False,
            "validations": {"length": {"max": "32"}, "cac-identity-guard": {"unique": "false"}}, "annotations": {}}
    meth = {"name": "stig_signin_methods", "displayName": "Sign-in methods the delegate's create intended (stig-accounts)",
            "permissions": {"view": ["admin"], "edit": ["admin"]}, "multivalued": False,
            "validations": {"length": {"max": "32"}, "cac-identity-guard": {"unique": "false"}}, "annotations": {}}
    # the card an Entra + CAC invite NAMED: bound only when the holder presents it after the first Entra sign-in
    cardc = {"name": "cac_edipi_pending", "displayName": "Card named by an invite (bound when its holder presents it)",
             "permissions": {"view": ["admin"], "edit": ["admin"]}, "multivalued": False,
             "validations": {"length": {"max": "64"}, "cac-identity-guard": {}}, "annotations": {}}
    # an administrator's link request (link-cac): the time it was made; the present-card step binds a card while it is live
    cardl = {"name": CARD_LINK, "displayName": "Card link requested by an administrator (link-cac; time of the request)",
             "permissions": {"view": ["admin"], "edit": ["admin"]}, "multivalued": False,
             "validations": {"length": {"max": "32"}, "cac-identity-guard": {"unique": "false"}}, "annotations": {}}
    for w in (want, pend, meth, cardc, cardl):
        cur = [x for x in up["attributes"] if x["name"] == w["name"]]
        if not cur or cur[0].get("validations") != w["validations"] or cur[0].get("permissions") != w["permissions"]:
            up["attributes"] = [x for x in up["attributes"] if x["name"] != w["name"]] + [w]
            kc.api("PUT", "/users/profile", up); up = kc.api("GET", "/users/profile")
    apps = app_groups(kc)
    # The realm's admin console. The STIG client policy keeps fullScopeAllowed=false on every client, and Keycloak's
    # admin API honours a realm-management role only if the calling client may carry it, so the console is given the
    # realm-management roles as scope mappings. That grants nobody anything: a person still needs the role itself.
    rmc = client_uuid(kc, "realm-management")
    console = kc.api("GET", "/clients?clientId=security-admin-console")[0]
    have = {r["name"] for r in kc.api("GET", "/clients/%s/scope-mappings/clients/%s" % (console["id"], rmc)) or []}
    missing = [r for r in kc.api("GET", "/clients/%s/roles" % rmc) if r["name"] not in have]
    if missing:
        kc.api("POST", "/clients/%s/scope-mappings/clients/%s" % (console["id"], rmc), missing)
    sync_delegations(kc, apps)
    for old in ("idp-user-manager: members of the application role groups",):
        ap = kc.api("GET", "/clients?clientId=admin-permissions")[0]
        base = "/clients/%s/authz/resource-server" % ap["id"]
        for p in kc.api("GET", base + "/permission?name=%s" % q(old)) or []:
            if p["name"] == old:
                kc.api("DELETE", base + "/permission/%s" % p["id"])
    guard(kc, True)
    for line in app_manager_alignment(kc):
        print(line, file=sys.stderr)
    print("roles: %s; application groups: %s" % (", ".join("/roles/" + n for n in ROLE_GROUPS),
                                                 ", ".join(sorted(g["path"] for g in apps))))

# ------------------------------------------------------------------------- delegated membership (FGAP v2)
# Delegates (user managers, applications' service accounts) see the members of their application group tree and move them
# between its role groups - and NOTHING else on an existing account: no `manage-members`, which in Keycloak 26.8 is
# what allows editing, enabling, e-mail changes, password resets, credential removal, identity-provider links and
# execute-actions mail (measured on a throwaway 26.8.2, 2026-11-10). Creating an account, sending its set-up mail and
# enabling/disabling go through stig-extensions' /admin/realms/<realm>/stig-accounts, which authorises them with
# Groups manage-membership on the target group and cannot do anything else.
#
# Two kinds of permission per application tree:
#   - `delegated: /<app>` - ONE permission over every group of the tree, scopes TREE_SCOPES (see the members, and act on
#     a member's memberships). Its policy is the AFFIRMATIVE aggregate `delegates of /<app>`: the user managers plus
#     every delegation of that app. No write of any group's membership comes from it.
#   - `membership: /<app>/<GROUP>` - one permission PER GROUP, scope `manage-membership` (add someone to, or remove
#     someone from, that group), policy the aggregate `writers of /<app>/<GROUP>`: the user managers plus exactly the
#     delegations APP_DELEGATIONS lists for that group. A group nobody lists - the bare tree root, and any role group
#     added to the client later - is the user managers' alone: a new role fails closed.
# Keycloak 26.8 combines separate permissions on one group UNANIMOUSLY and allows only UNANIMOUS permissions, so each
# (group, scope) is covered by exactly one permission whose single policy is an AFFIRMATIVE aggregate. A move needs
# BOTH manage-membership on the target group AND manage-group-membership on the account, which a delegate holds only
# through manage-membership-of-members on a group the account is already in: a delegate never reaches a non-member.
TREE_SCOPES = ["view", "view-members", "manage-membership-of-members"]
WRITE_SCOPES = ["manage-membership"]
SCOPES_MEMBERS = TREE_SCOPES + WRITE_SCOPES          # what the user managers hold on every group (the union)
# app -> {delegate client id (its service account): the /<app>/<GROUP> names it may write membership of}, from the
# config's applications.<app>.delegations.<client>.groups. A delegation lists role groups only - never the bare /<app>,
# which carries no role - and a role group nobody lists stays the user managers' alone (a new role fails closed). Keep
# out of every delegation the groups only the IdP's administrators may grant.
APP_DELEGATIONS = {app: {cid: tuple(d["groups"]) for cid, d in (c.get("delegations") or {}).items()}
                   for app, c in _APPS.items() if c.get("delegations")}
# membership-only delegates (no realm-management role: they see and move only accounts already in their app's tree),
# created by `delegate-setup`; any other delegate's client is made by the application's own setup (fgap/app_admin_fgap.py)
MEMBERSHIP_ONLY_DELEGATES = {cid: app for app, c in _APPS.items() for cid, d in (c.get("delegations") or {}).items()
                             if d.get("membershipOnly")}
DELEGATE_CLIENTS = tuple(c for d in APP_DELEGATIONS.values() for c in d)
UM_POLICY = "idp-user-manager group"

def delegate_policy_name(cid):
    return "%s service account" % cid           # the name fgap/app_admin_fgap.py setup gives an app's administrator

def _named(kc, base, kind, name):
    return [p for p in kc.api("GET", base + "/%s?name=%s" % (kind, q(name))) or [] if p["name"] == name]

def ensure_group_policy(kc, base, name, path):
    """The POSITIVE group policy matching exactly the members of `path` (no child groups). Refuses a same-named policy
    that matches anything else."""
    g = group_by_path(kc, path) or sys.exit("no %s (run roles-setup)" % path)
    if not _named(kc, base, "policy", name):
        kc.api("POST", base + "/policy/group", {"name": name, "logic": "POSITIVE", "groups": [{"id": g["id"], "extendChildren": False}]})
    pid = _named(kc, base, "policy", name)[0]["id"]
    full = kc.api("GET", base + "/policy/group/%s" % pid)
    if full.get("logic") != "POSITIVE" or [(x["id"], bool(x.get("extendChildren"))) for x in full.get("groups") or []] != [(g["id"], False)]:
        raise RuntimeError("policy %r is not exactly POSITIVE %s; refusing to use it" % (name, path))
    return pid

def ensure_um_policy(kc, base):
    return ensure_group_policy(kc, base, UM_POLICY, "/roles/idp-user-manager")

def app_manager_policy_name(app):
    return "%s group" % app_manager_role(app)

def ensure_app_manager_policy(kc, base, app):
    """The policy of /roles/<app>-user-manager, or None when the app has no per-application user manager."""
    if app not in APP_USER_MANAGERS:
        return None
    return ensure_group_policy(kc, base, app_manager_policy_name(app), "/roles/" + app_manager_role(app))

def ensure_delegate_policy(kc, base, cid):
    """The client policy matching exactly the delegate's service account; None when the client does not exist (its
    delegation is then simply not granted). Refuses a same-named policy that matches anything else."""
    c = [x for x in kc.api("GET", "/clients?clientId=%s" % q(cid)) or [] if x["clientId"] == cid]
    if not c:
        return None
    name = delegate_policy_name(cid)
    if not _named(kc, base, "policy", name):
        kc.api("POST", base + "/policy/client", {"name": name, "logic": "POSITIVE", "clients": [c[0]["id"]]})
    pid = _named(kc, base, "policy", name)[0]["id"]
    full = kc.api("GET", base + "/policy/client/%s" % pid)
    if full.get("logic") != "POSITIVE" or sorted(full.get("clients") or []) != [c[0]["id"]]:
        raise RuntimeError("policy %r is not exactly POSITIVE client %s; refusing to use it" % (name, cid))
    return pid

def ensure_aggregate(kc, base, name, policy_ids):
    """An AFFIRMATIVE aggregate holding EXACTLY policy_ids (any one grants); converged, verified by a re-read."""
    want = sorted(set(policy_ids))
    rep = {"name": name, "type": "aggregate", "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE", "policies": want}
    ex = _named(kc, base, "policy", name)
    if ex:
        have = sorted(x["id"] for x in kc.api("GET", base + "/policy/%s/associatedPolicies" % ex[0]["id"]) or [])
        if have != want or ex[0].get("decisionStrategy") != "AFFIRMATIVE" or ex[0].get("logic") != "POSITIVE":
            rep["id"] = ex[0]["id"]; kc.api("PUT", base + "/policy/aggregate/%s" % ex[0]["id"], rep)
    else:
        kc.api("POST", base + "/policy/aggregate", rep)
    agg = _named(kc, base, "policy", name)[0]
    have = sorted(x["id"] for x in kc.api("GET", base + "/policy/%s/associatedPolicies" % agg["id"]) or [])
    if have != want:
        raise RuntimeError("aggregate %r holds %s after the update, not %s" % (name, have, want))
    return agg["id"]

def ensure_group_permission(kc, base, name, group_ids, scopes, policy_id):
    """A UNANIMOUS Groups permission on exactly group_ids/scopes with the one policy; converged, verified by a re-read.
    Never written with empty resources (which would mean ALL groups)."""
    if not group_ids:
        raise RuntimeError("permission %r would have no resources (= ALL groups); refusing" % name)
    rep = {"name": name, "resourceType": "Groups", "resources": sorted(group_ids), "scopes": list(scopes),
           "policies": [policy_id], "decisionStrategy": "UNANIMOUS"}
    ex = _named(kc, base, "permission", name)
    if ex:
        rep["id"] = ex[0]["id"]
        if permission_shape(kc, base, ex[0]["id"]) != (sorted(group_ids), sorted(scopes), [policy_id]):
            kc.api("PUT", base + "/permission/scope/%s" % rep["id"], rep)
    else:
        kc.api("POST", base + "/permission/scope", rep)
    pid = _named(kc, base, "permission", name)[0]["id"]
    got = permission_shape(kc, base, pid)
    if got != (sorted(group_ids), sorted(scopes), [policy_id]):
        raise RuntimeError("permission %r is %s after the update, not %s" % (name, got, (sorted(group_ids), sorted(scopes), [policy_id])))
    return pid

def permission_shape(kc, base, pid):
    """(sorted resource ids, sorted scope names, policy ids) of one permission, as Keycloak holds it."""
    res = sorted(r["name"] for r in kc.api("GET", base + "/permission/%s/resources" % pid) or [])
    sc = sorted(s["name"] for s in kc.api("GET", base + "/permission/%s/scopes" % pid) or [])
    pol = sorted(p["id"] for p in kc.api("GET", base + "/policy/%s/associatedPolicies" % pid) or [])
    return res, sc, pol

def membership_writers(app, gname):
    """The delegate client ids that may write membership of /<app>/<gname> ('' = the tree root), besides the user managers."""
    return sorted(cid for cid, groups in APP_DELEGATIONS.get(app, {}).items() if gname in groups)

def refuse_admin_carriers(kc, apps):
    """RuntimeError if any group of a configured application tree carries a realm-management role."""
    carriers = [g["path"] for app in APP_CLIENTS for g in apps
                if (g["path"] == "/" + app or g["path"].startswith("/%s/" % app)) and group_carries_admin(kc, g["path"])]
    if carriers:
        raise RuntimeError("REFUSED: %s carr%s a realm-management role (directly or by composite): no delegation may "
                           "reach it; remove that mapping or composite first" % (", ".join(carriers), "ies" if len(carriers) == 1 else "y"))

def sync_delegations(kc, apps):
    """Converge every application tree to the split delegation (above). Migration-safe order for a realm still holding
    the earlier single permission (`delegated: /<app>` with manage-membership over the whole tree):
      1. every group's own `membership:` permission is written and verified FIRST. Keycloak combines it unanimously
         with the old tree-wide one, so from this step on a delegate writes only the groups listed for it, and keeps
         every group it is listed for - nobody gains a group, and an application's administrator loses none it uses;
      2. only then does `delegated: /<app>` lose manage-membership (verified);
      3. only then does `delegates of /<app>` gain a delegation that is new (e.g. the reader delegate): before step 2
         that aggregate still carried tree-wide manage-membership;
      4. `membership:` permissions of groups no longer in the tree are deleted.
    Idempotent: a converged realm gets no write. Any failure raises or exits before the next step.
    Refused while a tree group carries a realm-management role (an app role that is a composite of one, or a mapping
    on the group or its root): its delegates and app managers would hand out administrator rights. The check runs
    before this function writes any permission, policy or aggregate; the role groups themselves (app_groups) already
    exist by then."""
    refuse_admin_carriers(kc, apps)
    ap = kc.api("GET", "/clients?clientId=admin-permissions")[0]
    base = "/clients/%s/authz/resource-server" % ap["id"]
    um = ensure_um_policy(kc, base)
    out = []
    for app in APP_CLIENTS:
        tree = [g for g in apps if g["path"] == "/" + app or g["path"].startswith("/%s/" % app)]
        if not tree:
            continue
        mpol = ensure_app_manager_policy(kc, base, app)         # /roles/<app>-user-manager: this tree only
        dpol = {}
        for cid in sorted(APP_DELEGATIONS.get(app, {})):
            pid = ensure_delegate_policy(kc, base, cid)
            if pid:
                dpol[cid] = pid
            else:
                print("delegation: %s does not exist in this realm; nothing granted to it" % cid)
        # 1. one write permission per group
        want_names = set()
        # unlisted groups (the user managers' alone) FIRST: on a realm still holding the earlier tree-wide write, the
        # groups no delegate may write are closed before any group a delegate keeps is touched
        for g in sorted(tree, key=lambda g: (bool(membership_writers(app, g["path"][len(app) + 2:])), g["path"])):
            gname = g["path"][len(app) + 2:]              # "" for the tree root
            writers = [cid for cid in membership_writers(app, gname) if cid in dpol]
            mgr = [mpol] if (mpol and gname) else []            # the app's own user managers: every role group, never the root
            agg = ensure_aggregate(kc, base, "writers of %s" % g["path"], [um] + mgr + [dpol[c] for c in writers])
            name = "membership: %s" % g["path"]; want_names.add(name)
            ensure_group_permission(kc, base, name, [g["id"]], WRITE_SCOPES, agg)
            out.append((g["path"], ["idp-user-manager"] + ([app_manager_role(app)] if mgr else []) + writers))
        # 2. the tree permission: see and act on members, never write a group
        agg_name = "delegates of /%s" % app
        ex = _named(kc, base, "policy", agg_name)
        have = {x["id"] for x in kc.api("GET", base + "/policy/%s/associatedPolicies" % ex[0]["id"]) or []} if ex else set()
        known = set(dpol.values()) | ({mpol} if mpol else set())
        tree_agg = ensure_aggregate(kc, base, agg_name, {um} | (have & known))       # nothing new in it yet (step 3)
        ensure_group_permission(kc, base, "delegated: /%s" % app, [g["id"] for g in tree], TREE_SCOPES, tree_agg)
        # 3. now every delegation of the app, and its own user managers, may see its tree
        ensure_aggregate(kc, base, agg_name, [um] + ([mpol] if mpol else []) + list(dpol.values()))
        # 4. write permissions of groups that left the tree
        prefix = "membership: /%s" % app
        for p in paged(kc, base + "/permission"):
            if (p["name"] == prefix or p["name"].startswith(prefix + "/")) and p["name"] not in want_names:
                kc.api("DELETE", base + "/permission/%s" % p["id"]); print("delegation: removed %r (group gone)" % p["name"])
    for path, who in out:
        print("membership of %-40s %s" % (path, ", ".join(who)))
    return out

def rollback_delegations(kc, apps):
    """Back to the single tree-wide permission of before the per-group split, for the rollback of the live apply ONLY. Refused once
    a tree holds a group its earlier delegates were never meant to write: there the earlier shape
    IS the escalation. Order: every delegation that did not exist before (the reader delegate) leaves the tree's
    aggregate first, then the tree permission regains manage-membership (still intersected with the per-group ones,
    so nobody widens), and only then are the per-group permissions and their aggregates deleted."""
    refuse_admin_carriers(kc, apps)            # as sync_delegations: before any permission or policy is written
    ap = kc.api("GET", "/clients?clientId=admin-permissions")[0]
    base = "/clients/%s/authz/resource-server" % ap["id"]
    um = ensure_um_policy(kc, base)
    earlier = {app: tuple(c.get("preSplitDelegates") or ()) for app, c in _APPS.items()}   # the delegations before the split
    for app in APP_CLIENTS:
        tree = [g for g in apps if g["path"] == "/" + app or g["path"].startswith("/%s/" % app)]
        if not tree:
            continue
        keep = [c for c in earlier.get(app, ())]
        for cid in keep:
            listed = set(APP_DELEGATIONS[app][cid]) | {""}
            beyond = sorted(g["path"] for g in tree if g["path"][len(app) + 2:] not in listed)
            if beyond:
                sys.exit("REFUSED: %s holds %s, which %s must never write; rolling back would re-open the escalation "
                         "the per-group split closed. Remove those roles first (client file + roles-setup), or restore a backup."
                         % ("/" + app, ", ".join(beyond), cid))
        pols = [um] + [x for x in (ensure_delegate_policy(kc, base, c) for c in keep) if x]
        agg = ensure_aggregate(kc, base, "delegates of /%s" % app, pols)
        ensure_group_permission(kc, base, "delegated: /%s" % app, [g["id"] for g in tree], SCOPES_MEMBERS, agg)
        prefix = ("membership: /%s" % app, "writers of /%s" % app)
        for p in paged(kc, base + "/permission"):
            if any(p["name"] == x or p["name"].startswith(x + "/") for x in prefix):
                kc.api("DELETE", base + "/permission/%s" % p["id"])
        for p in paged(kc, base + "/policy"):
            if p.get("type") == "aggregate" and any(p["name"] == x or p["name"].startswith(x + "/") for x in prefix):
                kc.api("DELETE", base + "/policy/%s" % p["id"])
        print("rolled back: /%s is one tree-wide permission again (%s)" % (app, ", ".join(["idp-user-manager"] + keep)))
    for cid in DELEGATE_CLIENTS:
        if any(cid in v for v in earlier.values()):
            continue
        c = [x for x in kc.api("GET", "/clients?clientId=%s" % q(cid)) or [] if x["clientId"] == cid]
        if c and c[0].get("enabled", True):
            full = kc.api("GET", "/clients/%s" % c[0]["id"]); full["enabled"] = False
            kc.api("PUT", "/clients/%s" % c[0]["id"], full); print("disabled client %s (kept, so its events stay attributable)" % cid)

def cmd_delegation_rollback(a):
    kc = KC()
    rollback_delegations(kc, app_groups(kc))
    guard(kc, True)

def cmd_delegate_setup(a):
    """Create (idempotently) a membership-only delegate's service-account client, then converge the delegations so it
    may write membership of exactly the role groups the config lists for it. No realm-management role, no stig-accounts."""
    app = MEMBERSHIP_ONLY_DELEGATES.get(a.client_id) or \
        sys.exit("REFUSED: %s is not a membership-only delegation in %s" % (a.client_id, ADMIN_CONFIG_FILE))
    jwks = check_jwks_url(a.jwks_url) if a.jwks_url else None      # before KC(): resolution from the host's own resolver
    if jwks:
        jwks_precheck(jwks, a.alg)
    kc = KC()
    groups = APP_DELEGATIONS[app][a.client_id]
    ensure_delegate_client(kc, a.client_id, (_APPS[app]["delegations"][a.client_id].get("name") or
                                             "%s delegate (membership of %s only)" % (app, ", ".join(groups))))
    if jwks:
        converge_delegate_auth(kc, a.client_id, "client-jwt", jwks, a.alg)
    sync_delegations(kc, app_groups(kc))
    guard(kc, True)
    print("%s: may write membership of %s only. Deliver its credential: %s" % (
        a.client_id, ", ".join("/%s/%s" % (app, g) for g in groups),
        "the app's JWKS (%s)" % a.jwks_url if a.jwks_url else "sudo idp-admin.py client-secret %s > <file>" % a.client_id))

def ensure_delegate_client(kc, cid, name):
    """A confidential client whose only grant is client credentials (its service account), with the admin-API audience
    and NO role of any kind. Created with client-secret; its authentication is changed ONLY by converge_delegate_auth
    (delegate-client-setup), never here, so re-running a setup never switches a client-jwt delegate back to a secret."""
    if not any(cid in d for d in APP_DELEGATIONS.values()):
        sys.exit("REFUSED: %s is not a delegation in APP_DELEGATIONS" % cid)
    attrs = {"oauth2.device.authorization.grant.enabled": "false", "oidc.ciba.grant.enabled": "false",
             "client_credentials.use_refresh_token": "false"}
    rep = {"clientId": cid, "name": name, "protocol": "openid-connect", "publicClient": False, "serviceAccountsEnabled": True,
           "standardFlowEnabled": False, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False, "fullScopeAllowed": False,
           "attributes": attrs}
    if delegate_expected(cid)["auth"] != "client-jwt":
        # no client-jwt record: client-secret and no key of any kind (a switch is delegate-client-setup's alone)
        rep["clientAuthenticatorType"] = "client-secret"
    ex = [x for x in kc.api("GET", "/clients?clientId=%s" % q(cid)) or [] if x["clientId"] == cid]
    if not ex:
        kc.api("POST", "/clients", dict(rep, clientAuthenticatorType="client-secret")); print("client %s created (service account only)" % cid)
    else:
        cur = kc.api("GET", "/clients/%s" % ex[0]["id"])
        keyed = rep.get("clientAuthenticatorType") == "client-secret" and \
            any((cur.get("attributes") or {}).get(k) not in (None, "", "false") for k in JWKS_ATTRS)
        if keyed:
            cur["attributes"] = dict(cur.get("attributes") or {}, **CLEARED_JWKS)    # sent empty: left out would be kept
        if keyed or any(cur.get(k) != v for k, v in rep.items() if k not in ("attributes", "name")) or \
                any((cur.get("attributes") or {}).get(k) != v for k, v in attrs.items()):
            cur.update({k: v for k, v in rep.items() if k not in ("attributes", "name")})
            cur["attributes"] = dict(cur.get("attributes") or {}, **attrs)
            kc.api("PUT", "/clients/%s" % ex[0]["id"], cur); print("client %s updated" % cid)
    c = [x for x in kc.api("GET", "/clients?clientId=%s" % q(cid)) if x["clientId"] == cid][0]
    scopes = [s for s in kc.api("GET", "/client-scopes") or [] if s["name"] == "kc-admin-api"]
    have = {s["id"] for s in kc.api("GET", "/clients/%s/default-client-scopes" % c["id"]) or []}
    if scopes and scopes[0]["id"] not in have:      # the admin API audience, without which every admin call is 401 on 26.8
        kc.api("PUT", "/clients/%s/default-client-scopes/%s" % (c["id"], scopes[0]["id"]))
    sa = kc.api("GET", "/clients/%s/service-account-user" % c["id"])
    rm = kc.api("GET", "/users/%s/role-mappings" % sa["id"]) or {}
    held = [r["name"] for r in rm.get("realmMappings") or [] if not r["name"].startswith("default-roles-")]
    held += ["%s:%s" % (k, r["name"]) for k, v in (rm.get("clientMappings") or {}).items() for r in v.get("mappings") or []]
    if held:
        raise RuntimeError("%s's service account holds roles %s; a delegate holds none (remove them)" % (cid, held))
    if delegate_expected(cid)["auth"] != "client-jwt":            # re-read: no key may remain on a secret delegate
        left = [p_ for p_ in delegate_auth_problems(kc, cid, delegate_expected(cid)) if "rotated" not in p_]
        if left:
            raise RuntimeError("%s still differs after the update: %s" % (cid, "; ".join(left)))
    return c

# ------------------------------------------------------------------------- delegate client authentication
# A delegate (APP_DELEGATIONS) authenticates either with a client secret or with client-jwt (private_key_jwt): the app
# signs an assertion with a key that never leaves it, Keycloak verifies it against the app's JWKS URL. The expected
# authentication of each delegate is RECORDED (DELEGATE_STATE, root-only) by delegate-client-setup; guard and
# check-clients report any difference (STIG-DELEGATE-CLIENT-DRIFT), so a later flip back to a secret is drift.
DELEGATE_STATE = "/srv/idp/state/delegate-clients.json"
DELEGATE_ALGS = ("ES256", "RS256")          # both FIPS-approved verifications (ECDSA P-256, RSA >= 2048, SHA-256)

def load_delegate_records():
    try:
        return json.load(open(DELEGATE_STATE))
    except FileNotFoundError:
        return {}

JWKS_ATTRS = ("use.jwks.url", "jwks.url", "use.jwks.string", "jwks.string")
# Keycloak's client update only SETS the attributes present in the representation (RepresentationToModel
# .updateClientProperties): an attribute left out is kept. So a key is cleared by sending it EMPTY ("false" for the
# use.* switches), never by leaving it out - and every change is re-read and checked.
CLEARED_JWKS = {"use.jwks.url": "false", "jwks.url": "", "use.jwks.string": "false", "jwks.string": "",
                "token.endpoint.auth.signing.alg": ""}
ROTATED_SECRET_ATTR = "client.secret.rotated"         # the previous secret Keycloak keeps after a rotation

def delegate_expected(cid, records=None):
    """What a delegate must authenticate with: its record, or - with none - client-secret (fail closed: an unrecorded
    delegate on client-jwt, or carrying a JWKS URL or string, is drift)."""
    return (load_delegate_records() if records is None else records).get(cid) or {"auth": "client-secret"}

def check_jwks_url(u):
    """The JWKS URL rules: add-client's (https, exact, a public DNS name: no IP literal, no local name) plus resolution
    NOW to public addresses only (Keycloak fetches it). Exits REFUSED; returns the URL."""
    errs = _url_errors("jwks_url", u) + resolve_errors({"jwks_url": u})
    if urllib.parse.urlsplit(u).query or "*" in u:
        errs.append("jwks_url: one exact URL, without a query string or a wildcard")
    if errs:
        sys.exit("REFUSED: %s" % "; ".join(errs))
    return u

def jwk_thumbprint(k):
    """RFC 7638 thumbprint (base64url, unpadded) of a public JWK: SHA-256 of its required members, sorted, no spaces."""
    import base64, hashlib
    req = {"EC": ("crv", "kty", "x", "y"), "RSA": ("e", "kty", "n")}.get(k.get("kty"))
    if not req or any(not isinstance(k.get(m), str) for m in req):
        raise ValueError("not an EC or RSA public JWK")
    core = json.dumps({m: k[m] for m in req}, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(core).digest()).rstrip(b"=").decode()

JWKS_MAX_BYTES = 65536
JWKS_FETCH_DEADLINE = 20                # seconds for the whole fetch (connect, TLS, response)

def _nat64(ip):
    """NAT64 prefixes (RFC 6052 well-known, RFC 8215 local-use): an address there is an IPv4 one in disguise."""
    import ipaddress
    return ip.version == 6 and any(ip in ipaddress.ip_network(n) for n in ("64:ff9b::/96", "64:ff9b:1::/48"))

def _public_ip(a):
    import ipaddress
    ip = ipaddress.ip_address(a.split("%", 1)[0])
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return ip.is_global and not ip.is_multicast and not ip.is_reserved and not _nat64(ip)

def _https_get(ip, port, host, path, limit):
    """GET over TLS to the ADDRESS already validated, with SNI and Host set to the name (certificate verified for the
    name). Never follows a redirect (http.client does not). -> (status, body bytes, at most limit+1)."""
    ctx = ssl.create_default_context()
    sock = socket.create_connection((ip, port), timeout=10)
    try:
        ss = ctx.wrap_socket(sock, server_hostname=host)
        if ss.getpeername()[0] != ip:
            raise ValueError("connected to %s, not the validated %s" % (ss.getpeername()[0], ip))
        con = http.client.HTTPSConnection(host, port, context=ctx, timeout=15); con.sock = ss
        con.request("GET", path, headers={"Host": host if port == 443 else "%s:%d" % (host, port), "Accept": "application/json"})
        r = con.getresponse()
        body, deadline = b"", time.time() + JWKS_FETCH_DEADLINE     # an overall deadline, not only per read
        while len(body) <= limit:
            if time.time() > deadline:
                raise ValueError("the JWKS took longer than %d s" % JWKS_FETCH_DEADLINE)
            chunk = r.read(min(8192, limit + 1 - len(body)))
            if not chunk:
                break
            body += chunk
        return r.status, body
    finally:
        sock.close()

def fetch_public(url, resolver=None, getter=None, limit=JWKS_MAX_BYTES):
    """Fetch a JWKS as the IdP host's root, safely: https only; the name resolved ONCE, every address public, and the
    connection made to that validated address (no second resolution to rebind); no redirect followed (a 3xx is
    refused, as Keycloak's own fetch does not follow one either); at most `limit` bytes. -> (status, text); raises
    ValueError with the reason otherwise."""
    p_ = urllib.parse.urlsplit(url)
    if p_.scheme != "https" or not p_.hostname or p_.username or p_.password or p_.fragment:
        raise ValueError("not a plain https URL")
    host, port = p_.hostname, p_.port or 443
    addrs = sorted({ai[4][0] for ai in (resolver or RESOLVER or socket.getaddrinfo)(host, port, proto=socket.IPPROTO_TCP)})
    if not addrs:
        raise ValueError("%s resolves to nothing" % host)
    bad = [x for x in addrs if not _public_ip(x)]
    if bad:
        raise ValueError("%s resolves to a non-public address %s" % (host, bad))
    path = (p_.path or "/") + ("?" + p_.query if p_.query else "")
    st, body = (getter or _https_get)(addrs[0], port, host, path, limit)
    if 300 <= st < 400:
        raise ValueError("the JWKS answers a redirect (%s); redirects are refused" % st)
    if len(body) > limit:
        raise ValueError("the JWKS is larger than %d bytes" % limit)
    return st, body.decode("utf-8", "replace")

def jwks_precheck(url, alg, expect_thumbprint=None, fetch=None):
    """Before switching a delegate: the app's JWKS must answer 200 with EXACTLY ONE public signing key of the chosen
    alg (ES256: EC P-256; RS256: RSA >= 2048), no private member, kid = its RFC 7638 thumbprint, and - when given -
    that thumbprint. Exits REFUSED; returns the thumbprint. `fetch(url) -> (status, text)` is replaceable for tests."""
    import base64
    def get(u):
        try:
            return fetch_public(u)
        except (ValueError, OSError, ssl.SSLError, http.client.HTTPException) as e:
            return 0, str(e)
    st, txt = (fetch or get)(url)
    if st != 200:
        sys.exit("REFUSED: the JWKS %s answers %s, not 200: publish the key first (the app), then switch" % (url, st or txt[:120]))
    try:
        keys = json.loads(txt).get("keys")
    except (ValueError, AttributeError):
        keys = None
    if not isinstance(keys, list) or len(keys) != 1 or not isinstance(keys[0], dict):
        sys.exit("REFUSED: the JWKS must hold exactly one key (it holds %s)" % (len(keys) if isinstance(keys, list) else "none"))
    k = keys[0]
    private = sorted(m for m in ("d", "p", "q", "dp", "dq", "qi", "oth", "k") if m in k)
    if private:
        sys.exit("REFUSED: the JWKS publishes PRIVATE key material (%s): the key is compromised - the app must replace it" % private)
    want = {"ES256": ("EC", "P-256"), "RS256": ("RSA", None)}[alg]
    if k.get("kty") != want[0] or (want[1] and k.get("crv") != want[1]):
        sys.exit("REFUSED: the JWKS key is %s/%s, not what %s needs (%s/%s)" % (k.get("kty"), k.get("crv"), alg, want[0], want[1] or "-"))
    if alg == "RS256":
        n = k.get("n") or ""
        if len(base64.urlsafe_b64decode(n + "=" * (-len(n) % 4))) * 8 < 2048:
            sys.exit("REFUSED: the RSA key is shorter than 2048 bits")
    if k.get("alg") not in (None, alg) or k.get("use") not in (None, "sig"):
        sys.exit("REFUSED: the JWKS key says alg %s / use %s, not %s / sig" % (k.get("alg"), k.get("use"), alg))
    try:
        tp = jwk_thumbprint(k)
    except ValueError as e:
        sys.exit("REFUSED: %s" % e)
    if k.get("kid") != tp:
        sys.exit("REFUSED: the key's kid %r is not its RFC 7638 thumbprint %s" % (k.get("kid"), tp))
    if expect_thumbprint and tp != expect_thumbprint:
        sys.exit("REFUSED: the JWKS key's thumbprint is %s, not the expected %s: a different key - stop and ask the app" % (tp, expect_thumbprint))
    return tp

def delegate_auth_problems(kc, cid, want):
    """How the live client's authentication differs from its record (empty = as recorded)."""
    c = find_client(kc, cid)
    if c is None:
        return ["recorded, but no such client"]
    c = kc.api("GET", "/clients/%s" % c["id"]); at = c.get("attributes") or {}
    probs = []
    if at.get(ROTATED_SECRET_ATTR) not in (None, ""):
        probs.append("keeps a rotated (previous) client secret: it still authenticates until it expires")
    if c.get("clientAuthenticatorType") != want["auth"]:
        probs.append("authenticates with %s, recorded %s" % (c.get("clientAuthenticatorType"), want["auth"]))
    if want["auth"] != "client-jwt":
        set_ = sorted(k for k in JWKS_ATTRS if at.get(k) not in (None, "", "false"))
        if set_:
            probs.append("carries %s while it must authenticate with a client secret (no key of any kind)" % set_)
    if want["auth"] == "client-jwt":
        for k, v in (("use.jwks.url", "true"), ("jwks.url", want["jwks_url"]), ("token.endpoint.auth.signing.alg", want["alg"])):
            if at.get(k) != v:
                probs.append("attribute %s is %r, recorded %r" % (k, at.get(k), v))
        for k in ("jwks.string", "use.jwks.string"):
            if at.get(k) not in (None, "", "false"):
                probs.append("attribute %s is set (keys other than the recorded JWKS URL)" % k)
    return probs

def converge_delegate_auth(kc, cid, auth, jwks_url=None, alg=None):
    """Switch delegate `cid` to `auth` (client-jwt with jwks_url + alg, or client-secret), record it FIRST, regenerate
    its client secret (so no earlier secret, leaked or stale, authenticates again - for client-jwt the new one is never
    shown; for client-secret the operator then pipes it with client-secret), verify, and check that its service account
    still holds no role. Nothing else about the client or its delegation changes."""
    if cid not in DELEGATE_CLIENTS:
        sys.exit("REFUSED: %s is not a delegation in APP_DELEGATIONS" % cid)
    if auth == "client-jwt" and (not jwks_url or alg not in DELEGATE_ALGS):
        sys.exit("REFUSED: client-jwt needs --jwks-url and --alg (%s)" % "|".join(DELEGATE_ALGS))
    c = find_client(kc, cid) or sys.exit("REFUSED: no client %s (create it first: its setup command)" % cid)
    want = {"auth": auth, "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "operator": operator()}
    if auth == "client-jwt":
        want.update({"jwks_url": jwks_url, "alg": alg})
    rec = load_delegate_records(); rec[cid] = want; _write_json(DELEGATE_STATE, rec)
    full = kc.api("GET", "/clients/%s" % c["id"]); at = dict(full.get("attributes") or {})
    at.update(CLEARED_JWKS)                                   # explicit: an attribute left out would be kept
    if auth == "client-jwt":
        at.update({"use.jwks.url": "true", "jwks.url": jwks_url, "token.endpoint.auth.signing.alg": alg})
    full["attributes"], full["clientAuthenticatorType"] = at, auth
    kc.api("PUT", "/clients/%s" % c["id"], full)
    kc.api("POST", "/clients/%s/client-secret" % c["id"])        # regenerated; never printed here
    # the previous secret survives a regeneration as the ROTATED secret (CLIENT_SECRET_ROTATION) - drop it too
    kc.api("DELETE", "/clients/%s/client-secret/rotated" % c["id"], ok=(200, 204, 404), ok404=True)
    probs = delegate_auth_problems(kc, cid, want)
    if probs:
        raise RuntimeError("%s does not match its record after the change: %s" % (cid, "; ".join(probs)))
    sa = kc.api("GET", "/clients/%s/service-account-user" % c["id"])
    rm = kc.api("GET", "/users/%s/role-mappings" % sa["id"]) or {}
    held = [r["name"] for r in rm.get("realmMappings") or [] if not r["name"].startswith("default-roles-")]
    held += ["%s:%s" % (k, r["name"]) for k, v in (rm.get("clientMappings") or {}).items() for r in v.get("mappings") or []]
    if held:
        raise RuntimeError("%s's service account holds roles %s; a delegate holds none" % (cid, held))
    return want

def delegate_auth_report(kc):
    """REPORT ONLY (guard, check-clients): one line per delegate (EVERY one in DELEGATE_CLIENTS, recorded or not: an
    unrecorded one must be on client-secret with no key) whose authentication differs from what is expected."""
    rec = load_delegate_records(); out = []
    for cid in sorted(set(DELEGATE_CLIENTS) | set(rec)):
        if cid not in rec and find_client(kc, cid) is None:
            continue                                   # a delegate that does not exist yet (and was never recorded)
        out += ["STIG-DELEGATE-CLIENT-DRIFT client=%s %s" % (cid, p_) for p_ in delegate_auth_problems(kc, cid, delegate_expected(cid, rec))]
    return out

# ---- a TEST TWIN of a delegate, for the live delegation tests ($L, $T) once the delegate is on client-jwt
# The live delegate authenticates only with the app's key (JWKS URL), which never leaves the app, so the tests cannot
# sign in as it - and giving it a second, operator-held key (a jwks.string) would break "the app's JWKS only". Instead
# the tests run as a TEMPORARY twin: a separate client `<delegate>--test` with a client secret (root-only file), no role,
# whose client policy is added to exactly the aggregates the delegate's policy is in - the same delegation - and removed
# with the client afterwards. The live delegate is never touched. The guard reports a twin that still exists
# (STIG-DELEGATE-TEST-TWIN, exit 2, mailed), and roles-setup drops a twin from every aggregate it rewrites.
TWIN_SUFFIX = "--test"

def twin_id(cid):
    return cid + TWIN_SUFFIX

def _authz_base(kc):
    ap_ = kc.api("GET", "/clients?clientId=admin-permissions")[0]
    return "/clients/%s/authz/resource-server" % ap_["id"]

TWIN_MAX_AGE = 7200                     # seconds: guard --fix removes an older twin
TWIN_CREATED_ATTR, TWIN_OF_ATTR = "stig.test-twin.created", "stig.test-twin.of"

def create_test_twin(kc, cid, secret_file):
    if cid not in DELEGATE_CLIENTS:
        sys.exit("REFUSED: %s is not a delegation in APP_DELEGATIONS" % cid)
    dl = find_client(kc, cid) or sys.exit("REFUSED: no client %s" % cid)
    if not kc.api("GET", "/clients/%s" % dl["id"]).get("enabled", True):
        sys.exit("REFUSED: %s is disabled: a twin would carry a delegation its delegate does not exercise" % cid)
    tid = twin_id(cid)
    if find_client(kc, tid):
        sys.exit("REFUSED: %s already exists (remove it first: delegate-test-twin %s remove)" % (tid, cid))
    base = _authz_base(kc)
    dpol = _named(kc, base, "policy", delegate_policy_name(cid)) or sys.exit("REFUSED: %s has no delegation policy" % cid)
    aggs = [p_ for p_ in paged(kc, base + "/policy") if p_.get("type") == "aggregate"
            and dpol[0]["id"] in {x["id"] for x in kc.api("GET", base + "/policy/%s/associatedPolicies" % p_["id"]) or []}]
    kc.api("POST", "/clients", {"clientId": tid, "name": "TEST twin of %s (temporary, for the live delegation tests)" % cid,
                                "protocol": "openid-connect", "publicClient": False, "serviceAccountsEnabled": True,
                                "standardFlowEnabled": False, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
                                "fullScopeAllowed": False, "clientAuthenticatorType": "client-secret",
                                "attributes": {"oauth2.device.authorization.grant.enabled": "false", "oidc.ciba.grant.enabled": "false",
                                               "client_credentials.use_refresh_token": "false",
                                               TWIN_CREATED_ATTR: str(int(time.time())), TWIN_OF_ATTR: cid}})
    c = find_client(kc, tid)
    scopes = [s_ for s_ in kc.api("GET", "/client-scopes") or [] if s_["name"] == "kc-admin-api"]
    if scopes:
        kc.api("PUT", "/clients/%s/default-client-scopes/%s" % (c["id"], scopes[0]["id"]))
    pid = ensure_delegate_policy(kc, base, tid)
    for agg in aggs:                        # exactly the delegate's aggregates: the same delegation, nothing more
        have = [x["id"] for x in kc.api("GET", base + "/policy/%s/associatedPolicies" % agg["id"]) or []]
        ensure_aggregate(kc, base, agg["name"], have + [pid])
    try:
        write_secret_private(secret_file, kc.api("GET", "/clients/%s/client-secret" % c["id"])["value"])
    except ValueError as e:
        remove_test_twin(kc, cid)                 # never leave a twin whose secret could not be stored safely
        sys.exit("REFUSED: %s (the twin was removed again)" % e)
    print("%s created: the delegation of %s (%d aggregates: %s); its secret is in %s (0400). Remove it after the tests: "
          "idp-admin.py delegate-test-twin %s remove" % (tid, cid, len(aggs), ", ".join(sorted(a_["name"] for a_ in aggs)), secret_file, cid))

def remove_test_twin(kc, cid):
    tid = twin_id(cid); base = _authz_base(kc)
    pol = _named(kc, base, "policy", delegate_policy_name(tid))
    if pol:
        for agg in [p_ for p_ in paged(kc, base + "/policy") if p_.get("type") == "aggregate"]:
            have = [x["id"] for x in kc.api("GET", base + "/policy/%s/associatedPolicies" % agg["id"]) or []]
            if pol[0]["id"] in have:
                ensure_aggregate(kc, base, agg["name"], [x for x in have if x != pol[0]["id"]])
        kc.api("DELETE", base + "/policy/%s" % pol[0]["id"])
    c = find_client(kc, tid)
    if c:
        kc.api("DELETE", "/clients/%s" % c["id"])
    print("%s removed (client, policy, aggregate memberships)" % tid)

def test_twins_present(kc, fix=False):
    """One line per test twin that exists. With fix, a twin is REMOVED when its delegate is disabled or gone, or it is
    older than TWIN_MAX_AGE (or carries no creation time): a forgotten twin is a second credential with the delegation."""
    out = []
    for cid in DELEGATE_CLIENTS:
        t = find_client(kc, twin_id(cid))
        if not t:
            continue
        t = kc.api("GET", "/clients/%s" % t["id"]); dl = find_client(kc, cid)
        created = (t.get("attributes") or {}).get(TWIN_CREATED_ATTR) or ""
        age = int(time.time()) - int(created) if created.isdigit() else None
        why = []
        if not dl or not kc.api("GET", "/clients/%s" % dl["id"]).get("enabled", True):
            why.append("its delegate is disabled or gone")
        if age is None or age < 0 or age > TWIN_MAX_AGE:       # a creation time in the future is not trusted either
            why.append("older than %d s (%s)" % (TWIN_MAX_AGE, "no creation time" if age is None else "%d s" % age))
        out.append("STIG-DELEGATE-TEST-TWIN client=%s exists%s: remove it (idp-admin.py delegate-test-twin %s remove)"
                   % (twin_id(cid), (" - " + "; ".join(why)) if why else "", cid))
        if fix and why:
            remove_test_twin(kc, cid)
            out.append("STIG-DELEGATE-TEST-TWIN client=%s REMOVED (%s)" % (twin_id(cid), "; ".join(why)))
    return out

def cmd_delegate_test_twin(a):
    cids = list(DELEGATE_CLIENTS) if a.client_id == "all" else [a.client_id]
    if a.action == "run":
        # create the twin(s), run the command, and ALWAYS remove them and their secrets (a hang-up or SIGTERM too)
        import signal
        cmd = a.run_cmd
        if not a.secret_dir or not cmd:
            sys.exit("REFUSED: run needs --secret-dir D and a command after --")
        os.makedirs(a.secret_dir, mode=0o700, exist_ok=True)
        for sig in (signal.SIGHUP, signal.SIGTERM):
            signal.signal(sig, lambda *x: sys.exit(130))
        kc = KC(); made, rc = [], 1
        try:
            for cid in cids:
                create_test_twin(kc, cid, os.path.join(a.secret_dir, cid)); made.append(cid)
            print("running with twins %s (secrets in %s/<delegate>): %s" % ([twin_id(c) for c in made], a.secret_dir, " ".join(cmd)), flush=True)
            rc = subprocess.call(cmd)
        finally:
            for cid in made:
                try:
                    remove_test_twin(kc, cid)
                except Exception as e:      # noqa: BLE001
                    print("FAILED to remove %s: %s - remove it by hand" % (twin_id(cid), e), file=sys.stderr); rc = rc or 1
            for cid in cids:
                try:
                    os.unlink(os.path.join(a.secret_dir, cid))
                except FileNotFoundError:
                    pass
        sys.exit(rc)
    if len(cids) != 1:
        sys.exit("REFUSED: create and remove take one delegate")
    kc = KC()
    if a.action == "create":
        if not a.secret_file:
            sys.exit("REFUSED: create needs --secret-file (written 0400, root-only)")
        create_test_twin(kc, cids[0], a.secret_file)
    else:
        remove_test_twin(kc, cids[0])

def cmd_delegate_client_setup(a):
    """Switch one delegate's authentication: --jwks-url U --alg ES256|RS256 (client-jwt), or --client-secret (back)."""
    if a.client_secret == bool(a.jwks_url):
        sys.exit("REFUSED: give either --jwks-url (with --alg) or --client-secret")
    jwks = check_jwks_url(a.jwks_url) if a.jwks_url else None       # before KC(): resolution from the host's own resolver
    tp = jwks_precheck(jwks, a.alg, a.expect_thumbprint) if jwks else None     # the app's key is there, and the right one
    if tp:
        print("%s: the JWKS holds one %s key, thumbprint %s" % (a.client_id, a.alg, tp))
    kc = KC()
    want = converge_delegate_auth(kc, a.client_id, "client-jwt" if jwks else "client-secret", jwks, a.alg)
    for line in delegate_auth_report(kc):
        print(line, file=sys.stderr)
    print("%s: %s, recorded in %s; its old client secret no longer authenticates%s" % (
        a.client_id, ("client-jwt %s, JWKS %s" % (want["alg"], want["jwks_url"])) if jwks else "client-secret",
        DELEGATE_STATE, "" if jwks else (": deliver the new one with: sudo idp-admin.py client-secret %s > <file>" % a.client_id)))

# ------------------------------------------------------------------------- portal account administration (option D)
# A browser page of an application (e.g. its own portal) lets the IdP's user managers create, re-send, disable and move
# accounts WITH THEIR OWN TOKEN: the app holds no credential that can do any of it (the design choice:
# option D). The token comes from a dedicated PUBLIC client held to stig-extensions' admin-API profile
# `account-onboarding` (AdminApiGuardFilter: only stig-accounts create/setup-email/disable, membership PUT/DELETE and a
# few reads; every write needs an authentication <= stig.admin-api.max-auth-age seconds old, else 401 + RFC 9470
# challenge). Its scope mappings carry realm-management query-users and query-groups ONLY, so no token from it is ever
# realm-admin, whoever signs in. What it may do is still decided per person by FGAP (the user manager's delegation).
# The expected shape of each such client is recorded in ONBOARDING_STATE (root-only) by onboarding-client-setup; the
# guard compares the live client to it and, with --fix, DISABLES a drifted one (it holds nothing, so off is safe).
ONBOARDING_CLIENT_IDS = (DEFAULT_ONBOARDING_CLIENT,) + tuple((_AC.get("onboarding") or {}).get("clientIds") or ())
ONBOARDING_STATE = "/srv/idp/state/onboarding-clients.json"
ONBOARDING_PROFILE_ATTR, ONBOARDING_PROFILE = "stig.admin-api.profile", "account-onboarding"
ONBOARDING_MAX_AGE_ATTR = "stig.admin-api.max-auth-age"
GATE_ADMIN_API_PROFILE_KEY = "admin-api-profile"      # stig-extensions capability marker: the profile is enforced
ONBOARDING_SCOPE_ROLES = ("query-groups", "query-users")
# the realm admin console's own default scopes (kc-admin-api: the admin-API audience; web-origins: allowed-origins,
# which is what makes the admin API answer CORS for this one origin; basic: auth_time, which the step-up reads)
ONBOARDING_DEFAULT_SCOPES = ("acr", "basic", "email", "kc-admin-api", "profile", "roles", "web-origins")

ONBOARDING_OPS_ATTR = "stig.admin-api.operations"          # capability 2: the writes the client may make
ONBOARDING_OPERATIONS = ("create", "setup-email", "disable", "membership")
# by default the portal never disables (offboarding = removing the app's roles); a whole-account disable is a hand-off
ONBOARDING_DEFAULT_OPS = ("create", "setup-email", "membership")

def onboarding_needed_cap(want):
    """The capability marker a recorded client needs: 2 when it records an operations list, else 1."""
    return 2 if want and want.get("operations") else 1

def onboarding_attrs(max_age, dpop=False, ops=None):
    """dpop: access tokens bound to a key the page holds (DPoP, RFC 9449): the admin API then refuses the token without a
    fresh proof from that key (measured, lab 2026-11-18), so a token copied out of the page is useless elsewhere."""
    return {ONBOARDING_PROFILE_ATTR: ONBOARDING_PROFILE, ONBOARDING_MAX_AGE_ATTR: str(max_age),
            "dpop.bound.access.tokens": "true" if dpop else "false",
            "pkce.code.challenge.method": "S256", "use.refresh.tokens": "false", "access.token.lifespan": "300",
            "client.session.idle.timeout": "600", "oauth2.device.authorization.grant.enabled": "false",
            "oidc.ciba.grant.enabled": "false", "standard.token.exchange.enabled": "false",
            "client.use.lightweight.access.token.enabled": "false", "post.logout.redirect.uris": "+",
            **({ONBOARDING_OPS_ATTR: ",".join(ops)} if ops else {})}

def onboarding_rep(cid, redirect, origin, max_age, dpop=False, ops=None):
    return {"clientId": cid, "name": "Account administration from an application page (user managers' own token)",
            "protocol": "openid-connect", "enabled": True, "publicClient": True, "bearerOnly": False,
            "standardFlowEnabled": True, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False, "fullScopeAllowed": False, "consentRequired": False,
            "frontchannelLogout": False, "redirectUris": [redirect], "webOrigins": [origin],
            "authenticationFlowBindingOverrides": {},          # the realm's own STIG browser flow, never another
            "attributes": onboarding_attrs(max_age, dpop, ops)}

def load_onboarding():
    try:
        return json.load(open(ONBOARDING_STATE))
    except FileNotFoundError:
        return {}

def gate_capability(kc, key):
    """A stig-extensions capability marker (the allowlist gate's operationalInfo): its int value, 0 when absent (an older
    extension), None when the server info cannot be read (never taken for "absent")."""
    try:
        st_, d = kc.req("GET", "/admin/serverinfo")
        if st_ != 200:
            return None
        info = (((json.loads(d).get("providers") or {}).get("authenticator") or {}).get("providers") or {}).get(GATE_PROVIDER) or {}
        v = (info.get("operationalInfo") or {}).get(key)
        return 0 if v is None else int(v)
    except Exception:      # noqa: BLE001 - unreadable
        return None

def gate_marker(kc, key):
    """A stig-extensions operationalInfo value as a string; "" when absent (an older extension), None when unreadable."""
    try:
        st_, d = kc.req("GET", "/admin/serverinfo")
        if st_ != 200:
            return None
        info = (((json.loads(d).get("providers") or {}).get("authenticator") or {}).get("providers") or {}).get(GATE_PROVIDER) or {}
        return str((info.get("operationalInfo") or {}).get(key) or "")
    except Exception:      # noqa: BLE001 - unreadable
        return None

def referer_audit_report(kc):
    """(report lines, info lines) for V-222447 at runtime: the extension's referer-audit marker. "off" is a REPORT
    (exit 2, nothing changed): a deployment variable (STIG_REFERER_AUDIT=off) switched the sanitised Referer audit off."""
    v = gate_marker(kc, "referer-audit")
    if v == "sanitised":
        return [], []
    if v == "off":
        return ["STIG-REFERER-AUDIT-OFF the Referer is not recorded (STIG_REFERER_AUDIT=off in the deployment): V-222447 "
                "not met - remove the setting and restart; nothing changed"], []
    return [], ["info  referer-audit marker %s (an image older than the sanitised Referer audit?)" % ("unreadable" if v is None else "absent")]

def onboarding_problems(kc, cid, want, allow_disabled=False):
    """Every way the live client differs from its record (empty = as recorded). `want`: {redirect, origin, max_age}."""
    c = find_client(kc, cid)
    if c is None:
        return ["recorded as an onboarding client, but no such client exists"]
    c = kc.api("GET", "/clients/%s" % c["id"])
    probs = []
    rep = onboarding_rep(cid, want["redirect"], want["origin"], int(want.get("max_age", 300)), bool(want.get("dpop")),
                         want.get("operations"))
    for k, v in rep.items():
        if k in ("attributes", "name"):
            continue
        if k == "enabled" and allow_disabled:
            continue
        have = c.get(k)
        if k == "authenticationFlowBindingOverrides":
            have = {k_: v_ for k_, v_ in (have or {}).items() if v_}          # Keycloak may return {} or empty values
        if k in ("redirectUris", "webOrigins"):
            have = sorted(have or [])
            v = sorted(v)
        if have != v:
            probs.append("%s is %r, recorded %r" % (k, have, v))
    la = c.get("attributes") or {}
    for k, v in rep["attributes"].items():
        if la.get(k) != v:
            probs.append("attribute %s is %r, recorded %r" % (k, la.get(k), v))
    if c.get("protocolMappers"):
        probs.append("has its own protocol mappers %s (none allowed: one could rewrite auth_time or audience)"
                     % sorted(m.get("name") for m in c["protocolMappers"]))
    ds = sorted(x["name"] for x in kc.api("GET", "/clients/%s/default-client-scopes" % c["id"]) or [])
    if ds != sorted(ONBOARDING_DEFAULT_SCOPES):
        probs.append("default client scopes %s, expected %s" % (ds, sorted(ONBOARDING_DEFAULT_SCOPES)))
    os_ = sorted(x["name"] for x in kc.api("GET", "/clients/%s/optional-client-scopes" % c["id"]) or [])
    if os_:
        probs.append("optional client scopes %s (none allowed)" % os_)
    probs += onboarding_scope_mapper_problems(kc)
    sm = kc.api("GET", "/clients/%s/scope-mappings" % c["id"]) or {}
    realm_sm = sorted(r["name"] for r in sm.get("realmMappings") or [])
    client_sm = {k: sorted(r["name"] for r in v.get("mappings") or []) for k, v in (sm.get("clientMappings") or {}).items()}
    if realm_sm:
        probs.append("realm-role scope mappings %s (none allowed)" % realm_sm)
    if client_sm != {"realm-management": sorted(ONBOARDING_SCOPE_ROLES)}:
        probs.append("client-role scope mappings %s, expected only realm-management %s" % (client_sm, list(ONBOARDING_SCOPE_ROLES)))
    return probs

# The realm-level client scopes the onboarding client takes by default are shared with other clients, so a mapper
# added to one changes this client's tokens too. These are what the step-up, the audience, the roles cap and CORS rest
# on: exactly these mapper types (by name -> type), and the auth_time mapper reading the session's AUTH_TIME note.
ONBOARDING_SCOPE_MAPPERS = {
    "basic": {"auth_time": "oidc-usersessionmodel-note-mapper", "sub": "oidc-sub-mapper"},
    "roles": {"client roles": "oidc-usermodel-client-role-mapper", "realm roles": "oidc-usermodel-realm-role-mapper",
              "audience resolve": "oidc-audience-resolve-mapper"},
    "kc-admin-api": {"admin-api-audience": "oidc-admin-api-audience-mapper"},
    "web-origins": {"allowed web origins": "oidc-allowed-origins-mapper"},
}
# never acceptable in ANY of its default scopes: these can write any claim (auth_time, azp, allowed-origins, aud, ...)
FORBIDDEN_MAPPERS = ("oidc-hardcoded-claim-mapper", "oidc-script-based-protocol-mapper", "oidc-claims-param-token-mapper",
                     "oidc-audience-mapper")        # also on the scopes with no exact list (acr, email, profile)

def onboarding_scope_mapper_problems(kc):
    probs = []
    scopes = {s_["name"]: s_ for s_ in kc.api("GET", "/client-scopes") or []}
    for name in ONBOARDING_DEFAULT_SCOPES:
        ms = (scopes.get(name) or {}).get("protocolMappers") or []
        bad = sorted(m["name"] for m in ms if m.get("protocolMapper") in FORBIDDEN_MAPPERS
                     or (m.get("config") or {}).get("claim.name") in ("auth_time", "azp", "allowed-origins", "aud")
                     and m.get("protocolMapper") != "oidc-usersessionmodel-note-mapper")
        if bad:
            probs.append("client scope %s (shared) carries mappers that can rewrite token claims: %s" % (name, bad))
        want = ONBOARDING_SCOPE_MAPPERS.get(name)
        if want is None:
            continue
        have = {m["name"]: m.get("protocolMapper") for m in ms}
        if have != want:
            probs.append("client scope %s (shared) has mappers %s, expected exactly %s" % (name, have, want))
        if name == "basic":
            at = next((m for m in ms if m["name"] == "auth_time"), None)
            cfg = (at or {}).get("config") or {}
            if cfg.get("user.session.note") != "AUTH_TIME" or cfg.get("claim.name") != "auth_time" or cfg.get("access.token.claim") != "true":
                probs.append("client scope basic: the auth_time mapper does not put the session's AUTH_TIME in the access token (%s)" % cfg)
    return probs

def onboarding_guard(kc, fix, marker):
    """Violations among the onboarding clients (each a printed line). A client that drifted from its record (or has
    none) is a violation and, with fix, is DISABLED (verified) whatever else this run could or could not read: turning
    it off can only remove access. An enabled onboarding client while the deployed extension states it does NOT
    enforce the admin-API profile is a violation too; while that capability cannot be read, that one reason is not
    asserted (never taken for "absent"), but a drifted client is still disabled. `fix` is the run's own --fix, even on
    a run the gate marker turned report-only for administrators."""
    out = []
    recorded = load_onboarding()
    profile_cap = gate_capability(kc, GATE_ADMIN_API_PROFILE_KEY)
    for cid in sorted(set(recorded) | set(ONBOARDING_CLIENT_IDS)):
        c = find_client(kc, cid)
        if c is None:
            if cid in recorded:
                print("info  onboarding client %s is recorded but absent: run onboarding-client-setup, or remove its record" % cid)
            continue
        c = kc.api("GET", "/clients/%s" % c["id"])
        why = []
        if cid not in recorded:
            why.append("no record in %s (create it with onboarding-client-setup)" % ONBOARDING_STATE)
        else:
            why += onboarding_problems(kc, cid, recorded[cid], allow_disabled=True)
        need = onboarding_needed_cap(recorded.get(cid))
        if c.get("enabled") and profile_cap is not None and profile_cap < need:
            why.append("the deployed stig-extensions does not enforce what this client relies on (capability %s=%s, needs %d)"
                       % (GATE_ADMIN_API_PROFILE_KEY, profile_cap, need))
        if not why:
            if not c.get("enabled"):
                print("info  onboarding client %s matches its record and is DISABLED (re-enable with onboarding-client-setup)" % cid)
            continue
        if not c.get("enabled"):
            print("info  onboarding client %s is DISABLED and differs from its record: %s" % (cid, "; ".join(why)))
            continue
        for w in why:
            print("STIG-ONBOARDING-CLIENT-DRIFT client=%s %s" % (cid, w), file=sys.stderr)
        out.append(cid)
        if fix:
            c["enabled"] = False
            kc.api("PUT", "/clients/%s" % c["id"], c)
            if kc.api("GET", "/clients/%s" % c["id"]).get("enabled"):
                raise RuntimeError("could not disable the drifted onboarding client %s" % cid)
            print("STIG-ONBOARDING-CLIENT-DRIFT client=%s DISABLED (verified); fix the cause, then re-run "
                  "onboarding-client-setup" % cid, file=sys.stderr)
    if profile_cap is None and any(find_client(kc, cid_) for cid_ in set(recorded) | set(ONBOARDING_CLIENT_IDS)):
        print("info  the admin-API profile capability could not be read this run: only that check was skipped", file=sys.stderr)
    return out

def cmd_onboarding_client_setup(a):
    """Create or converge the public client an application page uses to act with a user manager's own token, record
    its expected shape (ONBOARDING_STATE, written first), and verify. Refused unless the deployed stig-extensions
    enforces the admin-API profile, so the client never exists unenforced. Idempotent; re-enables a disabled client."""
    redirect = a.redirect_uri
    errs = _url_errors("redirect_uri", redirect)
    pr_ = urllib.parse.urlsplit(redirect)
    if pr_.query or "*" in redirect:
        errs.append("redirect_uri: one exact URI, without a query string or a wildcard")
    if errs:
        sys.exit("REFUSED: %s" % "; ".join(errs))
    origin = "%s://%s" % (pr_.scheme, pr_.netloc)
    if a.origin and a.origin.rstrip("/") != origin:
        sys.exit("REFUSED: --origin %s is not the redirect URI's origin %s" % (a.origin, origin))
    if not 30 <= a.max_auth_age <= 900:
        sys.exit("REFUSED: --max-auth-age must be 30..900 seconds")
    ops = [x.strip() for x in a.operations.split(",") if x.strip()] if a.operations else []
    if not ops or any(x not in ONBOARDING_OPERATIONS for x in ops):
        sys.exit("REFUSED: --operations is a comma list of %s" % ", ".join(ONBOARDING_OPERATIONS))
    ops = [x for x in ONBOARDING_OPERATIONS if x in ops]          # canonical order, no duplicates
    need = 2 if ops != list(ONBOARDING_OPERATIONS) else 1
    kc = KC()
    cap = gate_capability(kc, GATE_ADMIN_API_PROFILE_KEY)
    if not cap or cap < need:
        sys.exit("REFUSED: the deployed stig-extensions does not enforce %s (capability %s=%s, needs %d): upgrade the image "
                 "first; the client would otherwise reach more than it should" % (
                     "the admin-API profile" if need == 1 else "an operations list", GATE_ADMIN_API_PROFILE_KEY, cap, need))
    rm = find_client(kc, "realm-management") or sys.exit("no realm-management client")
    # the application trees the page serves (recorded; reach itself is per person: each caller writes only the trees
    # their own manager roles cover - FGAP, sync_delegations - so listing a tree here grants nobody anything)
    apps = sorted(set(a.app or (_AC.get("onboarding") or {}).get("defaultApps") or []))
    if not apps:
        sys.exit("REFUSED: name the application tree(s) the page serves: --app (or onboarding.defaultApps in the config)")
    bad_apps = [x for x in apps if x not in APP_USER_MANAGERS]
    if bad_apps:
        sys.exit("REFUSED: --app %s has no per-application user manager (APP_USER_MANAGERS)" % ", ".join(bad_apps))
    want = {"redirect": redirect, "origin": origin, "max_age": a.max_auth_age, "dpop": bool(a.require_dpop), "apps": apps,
            **({"operations": ops} if need == 2 else {}),
            "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "operator": operator()}
    rec = load_onboarding(); rec[a.client_id] = want; _write_json(ONBOARDING_STATE, rec)
    rep = onboarding_rep(a.client_id, redirect, origin, a.max_auth_age, bool(a.require_dpop), want.get("operations"))
    ex = find_client(kc, a.client_id)
    if not ex:
        kc.api("POST", "/clients", rep); print("client %s created (public, PKCE, user managers' own token)" % a.client_id)
    c = kc.api("GET", "/clients/%s" % find_client(kc, a.client_id)["id"])
    if ex:
        cur = dict(c); cur.update({k: v for k, v in rep.items() if k != "attributes"})
        cur["attributes"] = dict(c.get("attributes") or {}, **rep["attributes"])
        if ONBOARDING_OPS_ATTR not in rep["attributes"]:
            cur["attributes"].pop(ONBOARDING_OPS_ATTR, None)
        # Keycloak MERGES flow binding overrides on update: an override is removed only by sending it with an empty
        # value (an omitted or {} map leaves it in place - measured, lab 2026-11-18)
        cur["authenticationFlowBindingOverrides"] = {k: "" for k, v in (c.get("authenticationFlowBindingOverrides") or {}).items() if v}
        if cur != c:
            kc.api("PUT", "/clients/%s" % c["id"], cur); print("client %s updated" % a.client_id)
    for m in c.get("protocolMappers") or []:
        sys.exit("REFUSED: %s has its own protocol mapper %r: remove it in the console first (none is allowed)" % (a.client_id, m.get("name")))
    scopes = {s_["name"]: s_["id"] for s_ in kc.api("GET", "/client-scopes") or []}
    missing = [n for n in ONBOARDING_DEFAULT_SCOPES if n not in scopes]
    if missing:
        sys.exit("REFUSED: the realm has no client scope %s" % missing)
    for kind in ("default", "optional"):
        have = {x["name"]: x["id"] for x in kc.api("GET", "/clients/%s/%s-client-scopes" % (c["id"], kind)) or []}
        want_names = set(ONBOARDING_DEFAULT_SCOPES) if kind == "default" else set()
        for n, sid in have.items():
            if n not in want_names:
                kc.api("DELETE", "/clients/%s/%s-client-scopes/%s" % (c["id"], kind, sid))
        for n in sorted(want_names - set(have)):
            kc.api("PUT", "/clients/%s/%s-client-scopes/%s" % (c["id"], kind, scopes[n]))
    sm = kc.api("GET", "/clients/%s/scope-mappings" % c["id"]) or {}
    if sm.get("realmMappings"):
        kc.api("DELETE", "/clients/%s/scope-mappings/realm" % c["id"], sm["realmMappings"])
    for k, v in (sm.get("clientMappings") or {}).items():
        extra = [r for r in v.get("mappings") or [] if k != "realm-management" or r["name"] not in ONBOARDING_SCOPE_ROLES]
        if extra:
            kc.api("DELETE", "/clients/%s/scope-mappings/clients/%s" % (c["id"], find_client(kc, k)["id"]), extra)
    have = {r["name"] for r in kc.api("GET", "/clients/%s/scope-mappings/clients/%s" % (c["id"], rm["id"])) or []}
    add = [kc.api("GET", "/clients/%s/roles/%s" % (rm["id"], q(n))) for n in ONBOARDING_SCOPE_ROLES if n not in have]
    if add:
        kc.api("POST", "/clients/%s/scope-mappings/clients/%s" % (c["id"], rm["id"]), add)
    probs = onboarding_problems(kc, a.client_id, want)
    if probs:
        raise RuntimeError("%s does not match its record after setup: %s" % (a.client_id, "; ".join(probs)))
    guard(kc, True)
    print("%s: public client for %s; redirect %s, CORS origin %s; tokens carry at most realm-management %s; writes need "
          "an authentication <= %d s old (enforced by stig-extensions). Who may act: holders of /roles/idp-user-manager or "
          "/roles/<app>-user-manager, each within their delegation." % (a.client_id, ", ".join(apps), redirect, origin,
                                                                       "+".join(ONBOARDING_SCOPE_ROLES), a.max_auth_age))

# ------------------------------------------------------------------------- hand-off intake
# An application files requests for the IdP team ("hand-offs": link a card, reset someone's sign-in, unlock, ...) and
# exposes them at an intake API. `handoffs` reads the open ones and records what the operator did, so nobody copies
# details from one site to the other. It is a pull: the application never calls the IdP, and NOTHING here changes an
# account - the operator runs the suggested idp-admin.py command, then marks the hand-off done (or refused).
# Config (handoffIntake):
#   url       the intake API: GET <url>/handoffs?status=open, POST <url>/handoffs/<id>/outcome
#   clientId  the confidential client whose client-credentials token the intake accepts (azp); service account only,
#             no role of any kind (handoff-worker-setup creates and records it; guard and check-clients report drift)
#   audience  what the intake requires in aud: an audience mapper, inside the client scope below
#   scope     what the intake requires in scope: an OPTIONAL client scope of that name, the worker's only scope
HANDOFF = dict(_AC.get("handoffIntake") or {})
HANDOFF_CLIENT_IDS = (HANDOFF["clientId"],) if HANDOFF else ()
HANDOFF_STATE = "/srv/idp/state/handoff-worker.json"      # root-only: the worker's recorded shape
HANDOFF_SECRET_FILE = os.path.join(SECRETS, "handoff_client_secret")   # root 0600
HANDOFF_TOKEN_LIFESPAN = 300          # seconds the worker's access token lives (an intake may refuse more than 600)
HANDOFF_MAX_LIFETIME, HANDOFF_SKEW = 600, 60
HANDOFF_MAX_BYTES = 1 << 20           # an answer larger than this is refused (100 hand-offs are a few kB)
HANDOFF_DEADLINE = 20                 # seconds for a whole request: connect, TLS, answer
HANDOFF_NOTE_MAX = 200
# ten or more digits, alone or in groups split by single spaces, dots or hyphens (an EDIPI, written any way): a note
# never carries one - stricter than the intake's own check, so it never answers 400 for this
HANDOFF_DIGITS = re.compile(r"\d(?:[ .-]?\d){9,}")
HANDOFF_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")       # used with fullmatch
HANDOFF_SAFE_USERNAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}")     # used with fullmatch: printable in a command
# tests replace these: the intake host must resolve to public addresses only; the resolver; the TLS context
HANDOFF_PUBLIC_ONLY, HANDOFF_RESOLVER, HANDOFF_CTX = True, None, None

def handoff_audit_syslog(line):
    """One audit line to the system log (facility auth, tag idp-admin): what reaches the SIEM with the host's logs."""
    import syslog
    syslog.openlog("idp-admin", syslog.LOG_PID, syslog.LOG_AUTH)
    syslog.syslog(syslog.LOG_NOTICE, line)
    syslog.closelog()

HANDOFF_AUDIT = handoff_audit_syslog      # tests replace it

def handoff_config():
    if not HANDOFF:
        sys.exit("no handoffIntake in %s: url, clientId, audience and scope (see idp-admin.example.json)" % ADMIN_CONFIG_FILE)
    return HANDOFF

def load_handoff():
    try:
        return json.load(open(HANDOFF_STATE))
    except FileNotFoundError:
        return {}

def handoff_attrs():
    return {"access.token.lifespan": str(HANDOFF_TOKEN_LIFESPAN), "client_credentials.use_refresh_token": "false",
            "use.refresh.tokens": "false", "oauth2.device.authorization.grant.enabled": "false",
            "oidc.ciba.grant.enabled": "false", "standard.token.exchange.enabled": "false",
            "client.use.lightweight.access.token.enabled": "false"}

def handoff_rep(cid, name=None):
    """A confidential client whose only grant is client credentials (its service account)."""
    return {"clientId": cid, "name": name or "Hand-off intake worker (client credentials, no roles)",
            "protocol": "openid-connect", "enabled": True, "publicClient": False, "bearerOnly": False,
            "clientAuthenticatorType": "client-secret", "serviceAccountsEnabled": True, "standardFlowEnabled": False,
            "implicitFlowEnabled": False, "directAccessGrantsEnabled": False, "fullScopeAllowed": False,
            "consentRequired": False, "frontchannelLogout": False, "authorizationServicesEnabled": False,
            "redirectUris": [], "webOrigins": [], "authenticationFlowBindingOverrides": {}, "attributes": handoff_attrs()}

HANDOFF_MAPPER_NAME = "intake audience"
def handoff_mapper(aud):
    return {"name": HANDOFF_MAPPER_NAME, "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
            "config": {"included.custom.audience": aud, "access.token.claim": "true", "id.token.claim": "false",
                       "introspection.token.claim": "true"}}

def handoff_scope_attrs():
    return {"include.in.token.scope": "true", "display.on.consent.screen": "false"}

def _mapper_ok(m, aud):
    cfg = m.get("config") or {}
    return m.get("protocolMapper") == "oidc-audience-mapper" and cfg.get("included.custom.audience") == aud \
        and cfg.get("access.token.claim") == "true" and cfg.get("id.token.claim") in (None, "false") \
        and not cfg.get("included.client.audience")

def find_scope(kc, name):
    return next((s_ for s_ in kc.api("GET", "/client-scopes") or [] if s_["name"] == name), None)

def clients_carrying_scope(kc, sid, name, but=None):
    """clientIds (other than `but`) that carry the client scope, as a default or an optional scope."""
    out = []
    for c_ in kc.api("GET", "/clients") or []:
        if c_["clientId"] == but:
            continue
        if "defaultClientScopes" in c_ and "optionalClientScopes" in c_:
            names = set(c_.get("defaultClientScopes") or []) | set(c_.get("optionalClientScopes") or [])
            if name in names:
                out.append(c_["clientId"])
            continue
        for kind in ("default", "optional"):
            if any(x["id"] == sid for x in kc.api("GET", "/clients/%s/%s-client-scopes" % (c_["id"], kind)) or []):
                out.append(c_["clientId"]); break
    return out

def handoff_problems(kc, cid, want, allow_disabled=False):
    """Every way the live worker differs from its record (empty = as recorded). `want`: {audience, scope}."""
    probs = []
    if HANDOFF and cid == HANDOFF.get("clientId") and (want.get("audience"), want.get("scope")) != (HANDOFF["audience"], HANDOFF["scope"]):
        probs.append("recorded with audience %r and scope %r, the config says %r and %r: re-run handoff-worker-setup"
                     % (want.get("audience"), want.get("scope"), HANDOFF["audience"], HANDOFF["scope"]))
    c = find_client(kc, cid)
    if c is None:
        return probs + ["recorded as the hand-off worker, but no such client exists"]
    c = kc.api("GET", "/clients/%s" % c["id"])
    for k, v in handoff_rep(cid).items():
        if k in ("attributes", "name") or (k == "enabled" and allow_disabled):
            continue
        have = c.get(k)
        if k == "authenticationFlowBindingOverrides":
            have = {k_: v_ for k_, v_ in (have or {}).items() if v_}
        if k in ("redirectUris", "webOrigins"):
            have = sorted(have or [])
        if k == "authorizationServicesEnabled":
            have = bool(have)                 # Keycloak leaves the key out of a client without authorization services
        if have != v:
            probs.append("%s is %r, recorded %r" % (k, have, v))
    la = c.get("attributes") or {}
    for k, v in handoff_attrs().items():
        if la.get(k) != v:
            probs.append("attribute %s is %r, recorded %r" % (k, la.get(k), v))
    if la.get(ROTATED_SECRET_ATTR) not in (None, ""):
        probs.append("keeps a rotated (previous) client secret: it still authenticates until it expires")
    keyed = sorted(k for k in JWKS_ATTRS if la.get(k) not in (None, "", "false"))
    if keyed:
        probs.append("carries %s (it authenticates with its client secret only)" % keyed)
    if c.get("protocolMappers"):
        probs.append("has its own protocol mappers %s (none allowed: the audience comes from its scope only)"
                     % sorted(m.get("name") for m in c["protocolMappers"]))
    ds = sorted(x["name"] for x in kc.api("GET", "/clients/%s/default-client-scopes" % c["id"]) or [])
    if ds:
        probs.append("default client scopes %s (none allowed: each adds claims)" % ds)
    os_ = sorted(x["name"] for x in kc.api("GET", "/clients/%s/optional-client-scopes" % c["id"]) or [])
    if os_ != [want.get("scope")]:
        probs.append("optional client scopes %s, expected exactly [%r]" % (os_, want.get("scope")))
    sc = find_scope(kc, want.get("scope"))
    if sc is None:
        probs.append("no client scope %r" % want.get("scope"))
    else:
        sa_ = sc.get("attributes") or {}
        if sc.get("protocol") != "openid-connect" or sa_.get("include.in.token.scope") != "true":
            probs.append("client scope %s is not an openid-connect scope included in the token's scope" % sc["name"])
        ms = sc.get("protocolMappers") or []
        if len(ms) != 1 or not _mapper_ok(ms[0], want.get("audience")):
            probs.append("client scope %s has mappers %s, expected exactly one audience mapper adding %r"
                         % (sc["name"], sorted((m.get("name"), m.get("protocolMapper")) for m in ms), want.get("audience")))
        for kind in ("default-default", "default-optional"):
            if any(x["id"] == sc["id"] for x in kc.api("GET", "/%s-client-scopes" % kind) or []):
                probs.append("client scope %s is a realm %s client scope (every new client would get it)" % (sc["name"], kind))
        others = clients_carrying_scope(kc, sc["id"], sc["name"], but=cid)
        if others:
            probs.append("client scope %s is also on %s (only the worker may carry it)" % (sc["name"], others))
    sm = kc.api("GET", "/clients/%s/scope-mappings" % c["id"]) or {}
    if sm.get("realmMappings") or any(v.get("mappings") for v in (sm.get("clientMappings") or {}).values()):
        probs.append("has role scope mappings (none allowed)")
    sa = kc.api("GET", "/clients/%s/service-account-user" % c["id"], ok404=True) if c.get("serviceAccountsEnabled") else None
    if sa:
        rm = kc.api("GET", "/users/%s/role-mappings" % sa["id"]) or {}
        held = [r["name"] for r in rm.get("realmMappings") or []]
        held += ["%s:%s" % (k, r["name"]) for k, v in (rm.get("clientMappings") or {}).items() for r in v.get("mappings") or []]
        if held:
            probs.append("its service account holds roles %s (none of any kind allowed)" % sorted(held))
        gs = [g["path"] for g in kc.api("GET", "/users/%s/groups" % sa["id"]) or []]
        if gs:
            probs.append("its service account is in groups %s (none allowed)" % gs)
    return probs

def handoff_guard(kc, fix):
    """Violations among hand-off workers (each a printed line). A worker that drifted from its record (or has none, or
    is no longer configured) is a violation and, with fix, is DISABLED (verified): turning it off only stops the
    polling. `fix` is the run's own --fix."""
    out = []
    recorded = load_handoff()
    for cid in sorted(set(recorded) | set(HANDOFF_CLIENT_IDS)):
        c = find_client(kc, cid)
        if c is None:
            if cid in recorded:
                print("info  hand-off worker %s is recorded but absent: run handoff-worker-setup, or remove its record" % cid)
            continue
        c = kc.api("GET", "/clients/%s" % c["id"])
        why = []
        if cid not in recorded:
            why.append("no record in %s (create it with handoff-worker-setup)" % HANDOFF_STATE)
        else:
            why += handoff_problems(kc, cid, recorded[cid], allow_disabled=True)
        if cid not in HANDOFF_CLIENT_IDS:
            why.append("recorded, but no longer the configured handoffIntake.clientId")
        if not why:
            if not c.get("enabled"):
                print("info  hand-off worker %s matches its record and is DISABLED (re-enable with handoff-worker-setup)" % cid)
            continue
        if not c.get("enabled"):
            print("info  hand-off worker %s is DISABLED and differs from its record: %s" % (cid, "; ".join(why)))
            continue
        for w in why:
            print("STIG-HANDOFF-WORKER-DRIFT client=%s %s" % (cid, w), file=sys.stderr)
        out.append(cid)
        if fix:
            c["enabled"] = False
            kc.api("PUT", "/clients/%s" % c["id"], c)
            if kc.api("GET", "/clients/%s" % c["id"]).get("enabled"):
                raise RuntimeError("could not disable the drifted hand-off worker %s" % cid)
            print("STIG-HANDOFF-WORKER-DRIFT client=%s DISABLED (verified); fix the cause, then re-run handoff-worker-setup"
                  % cid, file=sys.stderr)
    return out

def jwt_claims(tok):
    """The payload of a compact JWS, decoded (never trusted for anything but the self-check: the token came straight from
    the IdP over verified TLS)."""
    import base64
    parts = tok.split(".") if isinstance(tok, str) else []
    if len(parts) != 3:
        raise ValueError("not a compact JWT")
    pl = parts[1] + "=" * (-len(parts[1]) % 4)
    c = json.loads(base64.urlsafe_b64decode(pl.encode()))
    if not isinstance(c, dict):
        raise ValueError("the JWT payload is not an object")
    return c

def handoff_token_problems(claims, cid, aud, scope, issuer, now=None):
    """Why the intake would refuse this token, or why it carries more than it should (empty = exactly as agreed): iss,
    azp, aud EXACTLY [aud], scope EXACTLY scope, typ Bearer, a lifetime of at most HANDOFF_MAX_LIFETIME, no iat from
    the future."""
    now = time.time() if now is None else now
    probs = []
    if claims.get("iss") != issuer:
        probs.append("iss is %r, expected %r" % (claims.get("iss"), issuer))
    if claims.get("azp") != cid:
        probs.append("azp is %r, expected %r" % (claims.get("azp"), cid))
    auds = claims.get("aud")
    auds = [auds] if isinstance(auds, str) else auds if isinstance(auds, list) else []
    if auds != [aud]:
        probs.append("aud is %r, expected exactly [%r]" % (claims.get("aud"), aud))
    scopes = claims.get("scope").split() if isinstance(claims.get("scope"), str) else []
    if scopes != [scope]:
        probs.append("scope is %r, expected exactly %r" % (claims.get("scope"), scope))
    if claims.get("typ") not in (None, "Bearer"):
        probs.append("typ is %r, not an access token" % claims.get("typ"))
    iat, exp = claims.get("iat"), claims.get("exp")
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (iat, exp)):
        probs.append("iat/exp missing or not integers")
    else:
        if exp - iat > HANDOFF_MAX_LIFETIME:
            probs.append("lives %d s (exp - iat), at most %d allowed" % (exp - iat, HANDOFF_MAX_LIFETIME))
        if iat > now + HANDOFF_SKEW:
            probs.append("iat is %d s in the future" % (iat - now))
    return probs

class HandoffError(Exception):
    pass

def handoff_get_token(post, cid, secret, scope):
    """A client-credentials access token for the worker, asking for exactly its scope. `post(path, body, headers) ->
    (status, text)`: through Keycloak's own network namespace (setup) or the public URL (handoffs)."""
    body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": cid, "client_secret": secret,
                                   "scope": scope}).encode()
    st, text = post("/realms/%s/protocol/openid-connect/token" % REALM, body,
                    {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    try:
        d = json.loads(text)
    except ValueError:
        d = {}
    if st != 200 or not isinstance(d, dict) or not isinstance(d.get("access_token"), str):
        raise HandoffError("the IdP refused the worker's token request: HTTP %s %s" % (st, clean((d or {}).get("error") if isinstance(d, dict) else "", 80)))
    return d["access_token"]

def handoff_issuer():
    base = CFG.get("CAC_PUBLIC_URL", "").rstrip("/")
    if not base or not REALM:
        sys.exit("no CAC_PUBLIC_URL / CAC_REALM in %s: run this ON the IdP host" % CFG_FILE)
    return "%s/realms/%s" % (base, REALM)

def clean(v, n=200):
    """A value from another system, safe to print on a terminal: printable characters only, at most n."""
    s = v if isinstance(v, str) else "" if v is None else str(v)
    s = "".join(ch if ch.isprintable() else "?" for ch in s)
    return s if len(s) <= n else s[:n - 3] + "..."

class _Deadline:
    """An overall deadline for one request (SIGALRM, main thread only; per-socket timeouts bound each read anyway)."""
    def __init__(self, seconds):
        self.s, self.on = seconds, False
    def __enter__(self):
        import signal, threading
        if hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread():
            def fire(*_):
                raise TimeoutError("no complete answer within %d s" % self.s)
            self.prev = signal.signal(signal.SIGALRM, fire); signal.setitimer(signal.ITIMER_REAL, self.s); self.on = True
        return self
    def __exit__(self, *exc):
        if self.on:
            import signal
            signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, self.prev)
        return False

def https_call(url, method="GET", headers=None, body=None, limit=HANDOFF_MAX_BYTES, public_only=True, resolver=None,
               ctx=None, deadline=HANDOFF_DEADLINE):
    """One HTTPS request, safely: https only, no credentials in the URL; the name resolved ONCE (every address public
    when public_only) and the connection made to that validated address, certificate verified for the name; no
    redirect followed (a 3xx raises); at most `limit` bytes; at most `deadline` seconds in all. -> (status, lower-case
    headers, text); raises ValueError / OSError / ssl.SSLError / TimeoutError otherwise."""
    p_ = urllib.parse.urlsplit(url)
    if p_.scheme != "https" or not p_.hostname or p_.username or p_.password or p_.fragment:
        raise ValueError("not a plain https URL")
    host, port = p_.hostname, p_.port or 443
    with _Deadline(deadline):
        addrs = sorted({ai[4][0] for ai in (resolver or socket.getaddrinfo)(host, port, proto=socket.IPPROTO_TCP)})
        if not addrs:
            raise ValueError("%s resolves to nothing" % host)
        bad = [x for x in addrs if not _public_ip(x)] if public_only else []
        if bad:
            raise ValueError("%s resolves to a non-public address %s" % (host, bad))
        ctx = ctx or ssl.create_default_context()
        sock = socket.create_connection((addrs[0], port), timeout=min(10, deadline))
        try:
            ss = ctx.wrap_socket(sock, server_hostname=host)
            con = http.client.HTTPSConnection(host, port, context=ctx, timeout=min(10, deadline)); con.sock = ss
            h = {"Host": host if port == 443 else "%s:%d" % (host, port), "Accept": "application/json",
                 "User-Agent": "idp-admin"}
            h.update(headers or {})
            con.request(method, (p_.path or "/") + ("?" + p_.query if p_.query else ""), body=body, headers=h)
            r = con.getresponse()
            hd = {k.lower(): v for k, v in r.getheaders()}
            data = b""
            while len(data) <= limit:
                chunk = r.read1(min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data += chunk
        finally:
            sock.close()
    if 300 <= r.status < 400:
        raise ValueError("%s answered a redirect (%s); redirects are refused" % (host, r.status))
    if len(data) > limit:
        raise ValueError("%s answered more than %d bytes" % (host, limit))
    return r.status, hd, data.decode("utf-8", "replace")

def handoff_note(note):
    """The outcome note, checked: at most HANDOFF_NOTE_MAX characters, printable, no run of ten digits (-> the note;
    exits REFUSED otherwise, before anything is sent)."""
    n = (note or "").strip()
    if len(n) > HANDOFF_NOTE_MAX:
        sys.exit("REFUSED: the note is %d characters, at most %d" % (len(n), HANDOFF_NOTE_MAX))
    if any(not ch.isprintable() for ch in n):
        sys.exit("REFUSED: the note holds a control character or a line break")
    if HANDOFF_DIGITS.search(n):
        sys.exit("REFUSED: the note holds a run of ten or more digits (a card number never goes in a hand-off note)")
    return n

def handoff_session():
    """(token, intake url) for the configured worker, from the PUBLIC token endpoint (this host's own resolver, never
    Keycloak's network namespace: the intake is reached from the host). The token is checked before it is used."""
    h = handoff_config()
    try:
        secret = open(HANDOFF_SECRET_FILE).read().strip()
    except OSError as e:
        sys.exit("cannot read the worker's secret %s (%s): run handoff-worker-setup first" % (HANDOFF_SECRET_FILE, e.strerror))
    issuer = handoff_issuer()
    base = issuer[:issuer.index("/realms/")]
    def post(path, body, headers):
        st, _, text = https_call(base + path, "POST", headers, body, public_only=False, resolver=HANDOFF_RESOLVER, ctx=HANDOFF_CTX)
        return st, text
    try:
        tok = handoff_get_token(post, h["clientId"], secret, h["scope"])
        probs = handoff_token_problems(jwt_claims(tok), h["clientId"], h["audience"], h["scope"], issuer)
    except (HandoffError, ValueError, OSError, ssl.SSLError, http.client.HTTPException) as e:
        sys.exit("FAILED: worker token: %s" % e)
    if probs:
        sys.exit("REFUSED: the IdP issued the worker a token the intake would refuse or that carries more than agreed: %s. "
                 "Run idp-admin.py check-clients, then handoff-worker-setup" % "; ".join(probs))
    return tok, h["url"].rstrip("/")

def intake_call(url, token, method, path, obj=None):
    hdr = {"Authorization": "Bearer " + token}
    body = None
    if obj is not None:
        body = json.dumps(obj).encode(); hdr["Content-Type"] = "application/json"
    return https_call(url + path, method, hdr, body, public_only=HANDOFF_PUBLIC_ONLY, resolver=HANDOFF_RESOLVER, ctx=HANDOFF_CTX)

def intake_error(st, hd, text):
    """A refusal from the intake in one line: its problem+json title/detail, and what to do."""
    try:
        pj = json.loads(text)
    except ValueError:
        pj = {}
    pj = pj if isinstance(pj, dict) else {}
    why = clean(pj.get("detail") or pj.get("title") or text[:120], 200)
    hint = {401: "the token was not accepted (bad, expired, or another issuer)",
            403: "the token lacks the audience, the scope or the client the intake requires: check-clients, handoff-worker-setup",
            404: "no such hand-off", 409: "it is closed with another outcome, or cancelled",
            429: "rate limited%s" % (" - retry after %s s" % clean(hd.get("retry-after"), 10) if hd.get("retry-after") else "")}.get(st, "")
    return "HTTP %s %s%s" % (st, why, " (%s)" % hint if hint else "")

# The idp-admin.py command(s) suggested for each kind (with the username only; anything in <> the operator fills in from
# what they verify themselves). Never run automatically.
HANDOFF_SUGGESTIONS = {
    "link_cac": (["link-cac {u}"],
                 "{u} is asked to present their CAC at their next sign-in (password + OTP, or Entra), and that card is bound "
                 "then. To bind only one card, add --edipi and type the number you read from the card holder (never from the "
                 "hand-off) at the prompt. Only if they cannot present a card: link-cac {u} --bind-edipi --confirm-direct-bind. "
                 "A card already bound to or reserved for another account is refused."),
    "link_entra": (["link-entra {u} <Entra object id>"],
                   "The object id: Entra admin center -> Users -> the person -> Object ID (or az ad user show --id <upn> --query id -o tsv)."),
    "reset_credentials": (["reset-user {u}", "rename {u} {u} --email <address>", "send-setup {u}"],
                          "reset-user also clears the e-mail: set it again (the address you verified) before send-setup."),
    "disable_enable_unlock": (["user-enable {u} false", "user-enable {u} true", "user-unlock {u}"],
                              "One kind, three actions: confirm with the filer which one. An account the guard disabled needs reset-user before user-enable true."),
    "change_name_email": (["rename {u} {u} --email <address> --first <First> --last <Last>"],
                          "The new values are not in the hand-off: confirm them with the filer. A new username: rename {u} <new.username> (same user id)."),
    "delete_account": (["user-delete {u}"],
                       "Cannot be undone: a new account gets a new user id. Prefer user-enable {u} false unless deletion was approved."),
    "consider_disable": (["user-enable {u} false"],
                         "Their last role in the filing application was removed. Disable only if they hold no other application's role (guard lists accounts with none: info STIG-ACCOUNT-NO-APP-ROLE)."),
}

HANDOFF_SHARED_KINDS = ("delete_account", "reset_credentials", "disable_enable_unlock")   # act on the whole account

def handoff_account(kc, username, kind):
    """What the IdP itself says about a hand-off's account, so a wrong or compromised intake cannot steer the operator:
    (state line, warning or None, caution or None). A WARNING means NO command is suggested: no such account; an IdP
    administrator (/roles or a /roles/* group, or any effective realm-management role); not a member of the filing
    application's tree (handoffIntake.app) - except consider_disable, filed after the last role was removed, which is
    warned instead when the account still holds ANY application's group or role (direct, composite or through a
    group). A CAUTION keeps the command: a whole-account action (delete, reset, disable/enable/unlock) on an account
    another application also uses. Never prints a card number or an Entra object id."""
    app = HANDOFF.get("app")
    if not isinstance(username, str) or not HANDOFF_SAFE_USERNAME.fullmatch(username):
        return "", "the username has characters a command cannot carry", None
    us = [u for u in kc.api("GET", "/users?exact=true&username=%s" % q(username)) or []
          if (u.get("username") or "").lower() == username.lower()]
    if len(us) != 1:
        return "no such account", "there is NO account %s in the realm" % username, None
    u = kc.api("GET", "/users/%s" % us[0]["id"])
    at = u.get("attributes") or {}
    links = sorted(l.get("identityProvider") for l in kc.api("GET", "/users/%s/federated-identity" % u["id"]) or [])
    groups = [g["path"] for g in paged(kc, "/users/%s/groups" % u["id"])]
    trees = sorted({p_.strip("/").split("/")[0] for p_ in groups if p_.strip("/").split("/")[0] in APP_CLIENTS})
    roles = {cid: sorted(effective_client_roles(kc, u["id"], cid)) for cid in APP_CLIENTS}
    roles = {cid: r for cid, r in roles.items() if r}
    state = "%s; card %s; Entra %s%s; application trees %s; application roles %s" % (
        "enabled" if u.get("enabled") else "DISABLED", "bound" if any(at.get("cac_edipi") or []) else "not bound",
        "bound" if any(at.get("entra_oid") or []) else "not bound", " (linked)" if "entra" in links else "",
        ", ".join("/" + t for t in trees) or "none",
        ", ".join("%s:%s" % (cid, r) for cid in sorted(roles) for r in roles[cid]) or "none")
    admin = [p_ for p_ in groups if p_ == "/roles" or p_.startswith("/roles/")] or sorted(rm_roles(kc, u["id"]))
    if admin:
        return state, "%s is an IdP ADMINISTRATOR (%s): an application never files for an administrator" % (username, ", ".join(admin)), None
    used_by = sorted(set(trees) | set(roles))
    if kind == "consider_disable":
        if used_by:
            return state, "%s still holds groups or roles of %s: do not disable for this hand-off" % (
                username, ", ".join(used_by)), None
        return state, None, None
    if app not in trees:
        return state, "%s is not a member of /%s, the filing application's tree" % (username, app), None
    others = [x for x in used_by if x != app]
    if kind == "link_cac" and any(at.get("cac_edipi") or []):
        return state, None, "%s already has a card: link-cac refuses it unless --replace (which removes that card and ends the " \
            "account's sessions) - confirm with the filer that the card bound now is wrong or lost" % username
    if kind in HANDOFF_SHARED_KINDS and others:
        return state, None, "%s is also used by %s: this acts on the WHOLE account, for those applications too - confirm with them first" % (
            username, ", ".join(others))
    return state, None, None

def handoff_suggestion(kind, username):
    """(command lines, note) for one hand-off. An unsafe username gives no command line, never a quoted one."""
    cmds, note = HANDOFF_SUGGESTIONS.get(kind, ([], "An unknown kind: handle it by hand."))
    if not isinstance(username, str) or not HANDOFF_SAFE_USERNAME.fullmatch(username):
        return [], "The username has characters a command cannot carry: check the hand-off by hand."
    return ["sudo idp-admin.py " + c.format(u=username) for c in cmds], note.format(u=username)

def handoff_items(text):
    """The list answer, validated: [{id, kind, username, status, filedBy, filedAt}]; raises ValueError."""
    d = json.loads(text)
    items = d.get("items") if isinstance(d, dict) else None
    if not isinstance(items, list):
        raise ValueError("the answer has no items list")
    out = []
    for it in items:
        if not isinstance(it, dict) or not isinstance(it.get("id"), str) or not HANDOFF_ID_RE.fullmatch(it["id"]):
            raise ValueError("an item without a usable id: %s" % clean(json.dumps(it)[:120]))
        out.append(it)
    return out

def cmd_handoffs(a):
    """List the open hand-offs with the suggested command for each, or record an outcome (done / refused)."""
    action = a.action or "list"
    if action == "list":
        if a.id or a.note is not None:
            sys.exit("REFUSED: list takes no id and no --note")
        tok, url = handoff_session()
        try:
            st, hd, text = intake_call(url, tok, "GET", "/handoffs?status=open")
        except (ValueError, OSError, ssl.SSLError, http.client.HTTPException) as e:
            sys.exit("FAILED: %s: %s" % (url, e))
        if st != 200:
            sys.exit("FAILED: listing hand-offs: %s" % intake_error(st, hd, text))
        try:
            items = handoff_items(text)
        except ValueError as e:
            sys.exit("FAILED: the intake's answer is not a hand-off list: %s" % e)
        if not items:
            print("no open hand-offs"); return
        # each account as the IdP sees it (Keycloak's network namespace from here on: the intake call is done)
        try:
            kc = KC()
        except SystemExit as e:
            kc = None
            print("WARNING: the accounts could not be checked in Keycloak (%s): no command is suggested for any hand-off" % e)
        for it in items:
            print("%s  %-22s %-28s filed %s by %s" % (clean(it["id"], 64), clean(it.get("kind"), 22), clean(it.get("username"), 60),
                                                      clean(it.get("filedAt"), 30), clean(it.get("filedBy"), 120)))
            caution = None
            if kc is None:
                state, warn = "", "the account was not checked"
            else:
                try:
                    state, warn, caution = handoff_account(kc, it.get("username"), it.get("kind"))
                except SystemExit as e:
                    state, warn = "", "the account could not be read (%s)" % e
            if state:
                print("    account: %s" % state)
            if warn:
                print("    WARNING: %s. No command suggested: check this hand-off by hand with the filer (the intake may be "
                      "wrong or compromised)." % warn)
                continue
            if caution:
                print("    CAUTION: %s." % caution)
            cmds, note = handoff_suggestion(it.get("kind"), it.get("username"))
            for c in cmds:
                print("    run:  %s" % c)
            if note:
                print("    note: %s" % note)
        print("%d open. Nothing was changed. After acting: idp-admin.py handoffs done <id> [--note ...], or "
              "handoffs refused <id> --note <why>" % len(items))
        return
    if not a.id or not HANDOFF_ID_RE.fullmatch(a.id):
        sys.exit("REFUSED: %s needs the hand-off's id (as listed)" % action)
    if action == "refused" and not (a.note or "").strip():
        sys.exit("REFUSED: refused needs --note: why (the filer reads it)")
    note = handoff_note(a.note)
    tok, url = handoff_session()
    line = "STIG-HANDOFF-OUTCOME id=%s outcome=%s operator=%s intake=%s note=%s" % (
        a.id, action, clean(operator(), 64), urllib.parse.urlsplit(url).hostname, json.dumps(note))
    try:
        st, hd, text = intake_call(url, tok, "POST", "/handoffs/%s/outcome" % q(a.id), {"outcome": action, "note": note})
    except (ValueError, OSError, ssl.SSLError, http.client.HTTPException) as e:
        HANDOFF_AUDIT("%s result=error reason=%s" % (line, json.dumps(clean(str(e), 120))))
        sys.exit("FAILED: %s: %s (the outcome may or may not be recorded: list again)" % (url, e))
    if st == 200:
        try:
            item = json.loads(text)
        except ValueError:
            item = None
        item = item if isinstance(item, dict) else {}
        if item.get("id") != a.id or item.get("status") != action:
            HANDOFF_AUDIT("%s result=unexpected status=%s" % (line, json.dumps(clean(item.get("status"), 20))))
            sys.exit("FAILED: the intake answered 200 but the hand-off is %r, not %r" % (clean(item.get("status"), 20), action))
        HANDOFF_AUDIT("%s result=recorded kind=%s username=%s" % (line, clean(item.get("kind"), 40).replace(" ", "_"),
                                                                    clean(item.get("username"), 100).replace(" ", "_")))
        print("hand-off %s (%s, %s): %s recorded" % (a.id, clean(item.get("kind"), 40), clean(item.get("username"), 100), action))
        return
    HANDOFF_AUDIT("%s result=refused-by-intake http=%s" % (line, st))
    sys.exit("REFUSED by the intake: %s" % intake_error(st, hd, text))

def cmd_handoff_worker_setup(a):
    """Create or converge the hand-off worker (handoffIntake.clientId): a confidential client, service account only, no
    role of any kind, fullScopeAllowed off, no default client scope, exactly one OPTIONAL client scope (handoffIntake.scope)
    carrying exactly one audience mapper (handoffIntake.audience). Records it first (HANDOFF_STATE; guard and check-clients
    report drift), writes its secret to HANDOFF_SECRET_FILE (root 0600; --rotate-secret makes a new one), verifies the
    shape, then asks for a token and checks it carries exactly the agreed aud, scope and azp. Idempotent; re-enables."""
    h = handoff_config()
    cid, aud, scope = h["clientId"], h["audience"], h["scope"]
    kc = KC()
    want = {"audience": aud, "scope": scope, "url": h["url"], "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "operator": operator()}
    rec = load_handoff(); rec[cid] = want; _write_json(HANDOFF_STATE, rec)
    # the scope: openid-connect, in the token's scope claim, exactly one audience mapper; never a realm default
    sc = find_scope(kc, scope)
    if sc is None:
        kc.api("POST", "/client-scopes", {"name": scope, "protocol": "openid-connect", "attributes": handoff_scope_attrs(),
                                           "description": "hand-off intake: read open hand-offs, record outcomes"})
        sc = find_scope(kc, scope); print("client scope %s created" % scope)
    sc = kc.api("GET", "/client-scopes/%s" % sc["id"])
    if sc.get("protocol") != "openid-connect":
        sys.exit("REFUSED: client scope %s exists with protocol %s: remove or rename it first" % (scope, sc.get("protocol")))
    if any((sc.get("attributes") or {}).get(k) != v for k, v in handoff_scope_attrs().items()):
        full = dict(sc); full["attributes"] = dict(sc.get("attributes") or {}, **handoff_scope_attrs()); full.pop("protocolMappers", None)
        kc.api("PUT", "/client-scopes/%s" % sc["id"], full); print("client scope %s updated" % scope)
    ms = kc.api("GET", "/client-scopes/%s/protocol-mappers/models" % sc["id"]) or []
    keep = next((m for m in ms if _mapper_ok(m, aud)), None)
    for m in ms:
        if m is not keep:
            kc.api("DELETE", "/client-scopes/%s/protocol-mappers/models/%s" % (sc["id"], m["id"]))
            print("client scope %s: mapper %r removed" % (scope, m.get("name")))
    if keep is None:
        kc.api("POST", "/client-scopes/%s/protocol-mappers/models" % sc["id"], handoff_mapper(aud))
        print("client scope %s: audience mapper (%s) added" % (scope, aud))
    for kind in ("default-default", "default-optional"):
        if any(x["id"] == sc["id"] for x in kc.api("GET", "/%s-client-scopes" % kind) or []):
            kc.api("DELETE", "/%s-client-scopes/%s" % (kind, sc["id"])); print("client scope %s: no longer a realm %s scope" % (scope, kind))
    for other in clients_carrying_scope(kc, sc["id"], scope, but=cid):
        oc = find_client(kc, other)
        for kind in ("default", "optional"):
            kc.api("DELETE", "/clients/%s/%s-client-scopes/%s" % (oc["id"], kind, sc["id"]), ok=(200, 204, 404), ok404=True)
        print("client scope %s: taken off client %s (only the worker may carry it)" % (scope, other))
    # the client
    rep = handoff_rep(cid, h.get("name"))
    ex = find_client(kc, cid)
    if not ex:
        kc.api("POST", "/clients", rep); print("client %s created (service account only, no roles)" % cid)
    c = kc.api("GET", "/clients/%s" % find_client(kc, cid)["id"])
    if ex:
        c.setdefault("authorizationServicesEnabled", False)    # left out by Keycloak when off: compare it as off
        cur = dict(c); cur.update({k: v for k, v in rep.items() if k not in ("attributes", "name")})
        if h.get("name"):
            cur["name"] = h["name"]
        cur["attributes"] = dict(c.get("attributes") or {}, **rep["attributes"])
        if any((c.get("attributes") or {}).get(k) not in (None, "", "false") for k in JWKS_ATTRS):
            cur["attributes"].update(CLEARED_JWKS)           # sent empty: an attribute left out would be kept
        cur["authenticationFlowBindingOverrides"] = {k: "" for k, v in (c.get("authenticationFlowBindingOverrides") or {}).items() if v}
        cur.pop("protocolMappers", None)
        if cur != {k: v for k, v in c.items() if k != "protocolMappers"}:
            kc.api("PUT", "/clients/%s" % c["id"], cur); print("client %s updated" % cid)
    for m in c.get("protocolMappers") or []:
        kc.api("DELETE", "/clients/%s/protocol-mappers/models/%s" % (c["id"], m["id"])); print("client %s: own mapper %r removed" % (cid, m.get("name")))
    for kind in ("default", "optional"):
        for x in kc.api("GET", "/clients/%s/%s-client-scopes" % (c["id"], kind)) or []:
            if not (kind == "optional" and x["id"] == sc["id"]):
                kc.api("DELETE", "/clients/%s/%s-client-scopes/%s" % (c["id"], kind, x["id"]))
    if not any(x["id"] == sc["id"] for x in kc.api("GET", "/clients/%s/optional-client-scopes" % c["id"]) or []):
        kc.api("PUT", "/clients/%s/optional-client-scopes/%s" % (c["id"], sc["id"]))
    sm = kc.api("GET", "/clients/%s/scope-mappings" % c["id"]) or {}
    if sm.get("realmMappings"):
        kc.api("DELETE", "/clients/%s/scope-mappings/realm" % c["id"], sm["realmMappings"])
    for k, v in (sm.get("clientMappings") or {}).items():
        if v.get("mappings"):
            kc.api("DELETE", "/clients/%s/scope-mappings/clients/%s" % (c["id"], find_client(kc, k)["id"]), v["mappings"])
    # its service account: no role of any kind (the realm's default roles included), in no group
    sa = kc.api("GET", "/clients/%s/service-account-user" % c["id"])
    rm = kc.api("GET", "/users/%s/role-mappings" % sa["id"]) or {}
    if rm.get("realmMappings"):
        kc.api("DELETE", "/users/%s/role-mappings/realm" % sa["id"], rm["realmMappings"])
    for k, v in (rm.get("clientMappings") or {}).items():
        if v.get("mappings"):
            kc.api("DELETE", "/users/%s/role-mappings/clients/%s" % (sa["id"], v.get("id") or find_client(kc, k)["id"]), v["mappings"])
    for g in kc.api("GET", "/users/%s/groups" % sa["id"]) or []:
        kc.api("DELETE", "/users/%s/groups/%s" % (sa["id"], g["id"])); print("client %s: service account taken out of %s" % (cid, g["path"]))
    # the secret: a new one on --rotate-secret; never a rotated (previous) one left authenticating; root 0600 file
    if a.rotate_secret:
        kc.api("POST", "/clients/%s/client-secret" % c["id"]); print("client %s: new secret" % cid)
    kc.api("DELETE", "/clients/%s/client-secret/rotated" % c["id"], ok=(200, 204, 404), ok404=True)
    secret = kc.api("GET", "/clients/%s/client-secret" % c["id"])["value"]
    try:
        write_secret_private(HANDOFF_SECRET_FILE, secret, mode=0o600)
    except (ValueError, OSError) as e:
        raise RuntimeError("could not write the worker's secret to %s: %s" % (HANDOFF_SECRET_FILE, e))
    probs = handoff_problems(kc, cid, want)
    if probs:
        raise RuntimeError("%s does not match its record after setup: %s" % (cid, "; ".join(probs)))
    # proof: a token, asked for exactly the scope, carries exactly the agreed aud, scope and azp
    issuer = handoff_issuer()
    try:
        tok = handoff_get_token(lambda path, body, hdr: kc.req("POST", path, body, hdr, auth=False), cid, secret, scope)
        cl = jwt_claims(tok)
    except (HandoffError, ValueError) as e:
        raise RuntimeError("%s: %s" % (cid, e))
    tp = handoff_token_problems(cl, cid, aud, scope, issuer)
    if tp:
        raise RuntimeError("%s's token is not as agreed: %s" % (cid, "; ".join(tp)))
    print("%s: confidential client, service account only, no roles; token aud=%s scope=%s azp=%s, lives %d s; secret in %s "
          "(root 0600). Intake: %s. List with: idp-admin.py handoffs" % (cid, aud, scope, cid, cl["exp"] - cl["iat"],
                                                                         HANDOFF_SECRET_FILE, h["url"]))

def effective_client_roles(kc, uid, client_id):
    """The names of `client_id`'s roles the account holds effectively (direct, composite or through a group)."""
    c = find_client(kc, client_id)
    if c is None:
        return set()
    return {r["name"] for r in kc.api("GET", "/users/%s/role-mappings/clients/%s/composite" % (uid, c["id"])) or []}

def direct_client_roles(kc, uid, client_id):
    """The names of `client_id`'s roles mapped DIRECTLY to the account (not through a group or a composite)."""
    c = find_client(kc, client_id)
    if c is None:
        return set()
    return {r["name"] for r in kc.api("GET", "/users/%s/role-mappings/clients/%s" % (uid, c["id"])) or []}

def entra_invites(kc, now_ms=None):
    """(expired, pending) lines for accounts created to sign in with Entra (entra_pending) and not yet bound. Expired
    (older than ENTRA_INVITE_DAYS) can no longer bind: a REPORT (exit 2) for the operator to disable or remove; pending:
    information. Nothing is changed."""
    now_ms = now_ms or int(time.time() * 1000)
    expired, pending = [], []
    # an exact attribute search (stig-accounts writes the fixed value "pending"), enabled accounts only: a disabled
    # one can no longer sign in at all, so it is no longer an open invitation
    for u in paged(kc, "/users?briefRepresentation=false&enabled=true&q=%s:%s" % (ENTRA_PENDING, ENTRA_PENDING_VALUE)):
        at = u.get("attributes") or {}
        p = (at.get(ENTRA_PENDING) or [""])[0]
        if not p or (at.get("entra_oid") or [""])[0] or not u.get("enabled"):
            continue
        times = [t for t in (u.get("createdTimestamp"), created_ms((at.get(CREATED_BY) or [""])[0]), int(p) if p.isdigit() else None) if t]
        age = (now_ms - min(times)) / 86_400_000 if times else None
        if age is None or age > ENTRA_INVITE_DAYS:
            expired.append("STIG-ENTRA-INVITE-EXPIRED user=%s created %s ago, never signed in with Entra: it can no longer be "
                           "bound - disable it (user-enable %s false) or remove it after review"
                           % (u["username"], "%.1f days" % age if age is not None else "(unknown)", u["username"]))
        else:
            pending.append("info  ENTRA-INVITE-PENDING user=%s waits for its first Entra sign-in (%.1f of %d days used)"
                           % (u["username"], age, ENTRA_INVITE_DAYS))
    return expired, pending

def pending_cards(kc, now_ms=None):
    """(expired, pending) lines for Entra + CAC invites whose named card (cac_edipi_pending) was never presented. Live
    for 7 days; after that it is ignored (never bound, free for another create): REPORT the leftover (exit 2) for the
    operator to clear. Nothing is changed."""
    now_ms = now_ms or int(time.time() * 1000)
    expired, pending = [], []
    for u in paged(kc, "/users?briefRepresentation=false&q=stig_signin_methods:cac,entra"):
        at = u.get("attributes") or {}
        if not (at.get("cac_edipi_pending") or [""])[0]:
            continue
        times = [t for t in (u.get("createdTimestamp"), created_ms((at.get(CREATED_BY) or [""])[0])) if t]
        age = (now_ms - min(times)) / 86_400_000 if times else None
        if age is None or age > ENTRA_INVITE_DAYS:
            expired.append("STIG-CARD-PENDING-EXPIRED user=%s: the card its invite named was never presented (%s); it is "
                           "ignored and free for another invite - clear cac_edipi_pending, or re-invite"
                           % (u["username"], "%.1f days" % age if age is not None else "age unknown"))
        else:
            pending.append("info  CARD-PENDING user=%s: its first Entra sign-in will ask for the card the invite named (%.1f of %d days)"
                           % (u["username"], age, ENTRA_INVITE_DAYS))
    return expired, pending

def edipi_usernames(kc):
    """REPORT ONLY: accounts whose USERNAME is (or holds) a run of ten digits - an EDIPI as a username ends up in every
    event, log line and token that names the account. Printed masked (last four digits). Nothing is changed."""
    out = []
    for u in paged(kc, "/users?briefRepresentation=true"):
        n = u.get("username") or ""
        if re.search(r"[0-9]{10}", n):
            out.append("STIG-USERNAME-IS-EDIPI user=%s id=%s: a username carrying a 10-digit run (an EDIPI?) is written "
                       "to every event and log line naming the account - rename it (first.last); nothing changed"
                       % (re.sub(r"[0-9]{6,}([0-9]{4})", r"******\1", n), u["id"]))
    return out

def accounts_without_app_role(kc):
    """INFORMATION ONLY: enabled people (no service account, no administrator) who hold no role of any application
    client, directly or through a group - e.g. offboarded from an application by removing their last group
    of it. They can still sign in to the IdP and reach nothing; consider disabling
    them (V-222412). The 35-day inactivity workflow disables them anyway if they stop signing in."""
    admins = set(admin_members(kc))
    apps = [(c, find_client(kc, c)) for c in APP_CLIENTS]
    apps = [(c, x["id"]) for c, x in apps if x]
    out = []
    for u in paged(kc, "/users?briefRepresentation=true"):
        if not u.get("enabled") or u["id"] in admins or (u.get("username") or "").startswith("service-account-"):
            continue
        if any(kc.api("GET", "/users/%s/role-mappings/clients/%s/composite" % (u["id"], cid)) for _, cid in apps):
            continue
        out.append("info  STIG-ACCOUNT-NO-APP-ROLE user=%s enabled, holds no application role (offboarded?): consider "
                   "disabling it (idp-admin.py user-enable %s false)" % (u["username"], u["username"]))
    return out

def onboarding_apps(want):
    """The application trees an onboarding record serves (records before 2026-11-20 hold one "app")."""
    return list(want.get("apps") or ([want["app"]] if want.get("app") else []))

def app_manager_alignment(kc):
    """REPORT ONLY: one line per holder of /roles/<app>-user-manager who does not hold <app>:<required role> (directly,
    as administrators hold application roles, or through a group); per /roles/<x>-user-manager group whose application
    is no longer configured (e.g. just taken out of the config) yet still has members; per onboarding client recorded
    as serving such an application. Nothing is changed."""
    out = []
    configured = {"/roles/" + app_manager_role(x) for x in APP_USER_MANAGERS}
    roles_root = group_by_path(kc, "/roles")
    for g in (paged(kc, "/groups/%s/children" % roles_root["id"]) if roles_root else []):
        if g["path"].endswith("-user-manager") and g["path"] != "/roles/idp-user-manager" and g["path"] not in configured:
            n = len(paged(kc, "/groups/%s/members" % g["id"]))
            if n:
                out.append("STIG-APP-MANAGER-ORPHANED %s has %d member(s) but its application is no longer configured "
                           "(APP_USER_MANAGERS): revoke it from them; nothing changed" % (g["path"], n))
    for cid, want in sorted(load_onboarding().items()):
        for x in onboarding_apps(want):
            if x not in APP_USER_MANAGERS:
                out.append("STIG-ONBOARDING-APP-UNKNOWN client=%s is recorded as serving %s, which is no longer configured: "
                           "re-run onboarding-client-setup with the current --app list; nothing changed" % (cid, x))
    for app, need in sorted(APP_USER_MANAGERS.items()):
        g = group_by_path(kc, "/roles/" + app_manager_role(app))
        if not g:
            continue
        for u in paged(kc, "/groups/%s/members" % g["id"]):
            if need not in effective_client_roles(kc, u["id"], app):
                out.append("STIG-APP-MANAGER-MISALIGNED user=%s holds /roles/%s but not %s:%s: give the role "
                           "(idp-admin.py grant %s %s:%s) or revoke the manager role (revoke, then re-grant what stays); "
                           "nothing changed" % (u["username"], app_manager_role(app), app, need, u["username"], app, need))
    return out

def admin_members(kc):
    """Every account holding ANY realm-management role, effective (direct, composite or through a group), plus every
    /roles/* member: administrators are found by what they can do, not only by where they are listed."""
    rmc = client_uuid(kc, "realm-management")
    out = {}
    for u in all_accounts(kc):
        if kc.api("GET", "/users/%s/role-mappings/clients/%s/composite" % (u["id"], rmc)):
            out[u["id"]] = u["username"]
    for name in ROLE_GROUPS:
        g = group_by_path(kc, "/roles/" + name)
        if g:
            for u in paged(kc, "/groups/%s/members" % g["id"]):
                out[u["id"]] = u["username"]
    return out

def app_tree_groups(kc, uid):
    return [g for g in paged(kc, "/users/%s/groups" % uid) if g["path"].strip("/").split("/")[0] in APP_CLIENTS]

def take_out_of_app_groups(kc, uid):
    """Remove an administrator from EVERY group in an application tree, at any depth, mapping directly whatever
    client roles those groups carried; then re-read and fail unless no application-tree membership remains."""
    moved = []
    for g in app_tree_groups(kc, uid):
        app = g["path"].strip("/").split("/")[0]
        cu = client_uuid(kc, app)
        carried = kc.api("GET", "/groups/%s/role-mappings/clients/%s" % (g["id"], cu)) or []
        if carried:
            kc.api("POST", "/users/%s/role-mappings/clients/%s" % (uid, cu), carried)
        kc.api("DELETE", "/users/%s/groups/%s" % (uid, g["id"]))
        moved.append(g["path"])
    left = [g["path"] for g in app_tree_groups(kc, uid)]
    if left:
        raise RuntimeError("administrator %s still in application groups %s after removal" % (uid, left))
    return moved

ADMIN_PROTECTION, ADMIN_POLICY = "administrators: idp-admin only", "members of /roles/idp-admin"

def sync_admin_protection(kc, admins):
    """Server-side, fail-safe protection: a Users permission on every administrator's id whose only policy is
    POSITIVE and matches members of /roles/idp-admin. Keycloak combines all permissions on a resource unanimously,
    so a delegate whose group permission covers an administrator is still refused, and an account that is not an
    idp-admin is never GRANTED anything by it (a POSITIVE group policy evaluates to deny for them). Never left with
    empty resources (empty means ALL users): with no administrators the permission is removed."""
    ap = kc.api("GET", "/clients?clientId=admin-permissions")
    if not ap:
        return
    base = "/clients/%s/authz/resource-server" % ap[0]["id"]
    pname, polname = ADMIN_PROTECTION, ADMIN_POLICY
    perm = [p for p in kc.api("GET", base + "/permission?name=%s" % q(pname)) or [] if p["name"] == pname]
    if not admins:
        for p in perm:
            kc.api("DELETE", base + "/permission/%s" % p["id"])
        return
    g = group_by_path(kc, "/roles/idp-admin") or sys.exit("no /roles/idp-admin (run roles-setup)")
    pol = [p for p in kc.api("GET", base + "/policy?name=%s" % q(polname)) or [] if p["name"] == polname]
    if not pol:
        kc.api("POST", base + "/policy/group", {"name": polname, "logic": "POSITIVE", "groups": [{"id": g["id"], "extendChildren": False}]})
        pol = [p for p in kc.api("GET", base + "/policy?name=%s" % q(polname)) if p["name"] == polname]
    full = kc.api("GET", base + "/policy/group/%s" % pol[0]["id"])
    if full.get("logic") != "POSITIVE" or [(x["id"], bool(x.get("extendChildren"))) for x in full.get("groups") or []] != [(g["id"], False)]:
        raise RuntimeError("policy %r is not exactly POSITIVE /roles/idp-admin; refusing to use it" % polname)
    rep = {"name": pname, "resourceType": "Users", "resources": sorted(admins), "policies": [pol[0]["id"]], "decisionStrategy": "UNANIMOUS",
           "scopes": ["view", "manage", "map-roles", "manage-group-membership", "impersonate", "reset-password"]}
    if perm:
        rep["id"] = perm[0]["id"]; kc.api("PUT", base + "/permission/scope/%s" % rep["id"], rep)
    else:
        kc.api("POST", base + "/permission/scope", rep)

GUARD_OK, GUARD_FIXED, GUARD_VIOLATION = "ok", "fixed", "violation"

def guard(kc, fix):
    """GUARD_OK; GUARD_FIXED (violations found and verified gone, fix=True); GUARD_VIOLATION (found, fix=False).
    Any failure raises (RuntimeError) or exits (HTTP error) - it is never reported as success."""
    fix_requested = fix               # the onboarding clients are fixed (disabled) even on a report-only run below
    ap = kc.api("GET", "/clients?clientId=admin-permissions")
    if ap:
        base = "/clients/%s/authz/resource-server" % ap[0]["id"]
        for kind, name in (("permission", "protect administrators"), ("policy", "not a delegate")):
            for p in kc.api("GET", base + "/%s?name=%s" % (kind, q(name))) or []:
                if p["name"] == name:
                    kc.api("DELETE", base + "/%s/%s" % (kind, p["id"])); print("guard: removed the unsafe earlier %s %r" % (kind, name))
    admins = admin_members(kc)
    sync_admin_protection(kc, admins)
    mapped = binding_mappers(kc)
    for al, m in mapped:
        print("STIG-IDP-MAPPER-WRITES-BINDING idp=%s mapper=%s config=%s" % (al, m["name"], m.get("config")), file=sys.stderr)
        if fix:
            kc.api("DELETE", "/identity-provider/instances/%s/mappers/%s" % (q(al), m["id"]))
            print("STIG-IDP-MAPPER-WRITES-BINDING idp=%s mapper=%s removed" % (al, m["name"]), file=sys.stderr)
    if fix and binding_mappers(kc):
        raise RuntimeError("identity-provider mappers still write an identity binding")
    state_on_disk = os.path.exists(STATE)
    st = load_state() or new_state()
    untrusted, failures = [], []
    # Never act on a missing record: a host restored without srv/idp/state would otherwise see every administrator -
    # the sole one included - as unvetted. Stop, alert, publish nothing (the gates keep what is published).
    try:
        allow_on_disk = os.path.exists(ALLOWLIST)
        allow0 = load_allowlist() if allow_on_disk else {}
        stm_, dm_ = kc.req("GET", "/admin/realms/master")
        if stm_ != 200:                  # unknown is never "nothing published"
            raise RuntimeError("reading the master realm answered HTTP %s" % stm_)
        published = (json.loads(dm_).get("attributes") or {}).get(ALLOWLIST_ATTR)
    except Exception as ex:      # noqa: BLE001
        print("STIG-ADMIN-GUARD-STOPPED cannot read the allowlist or its published copy (%s): nothing done" % ex, file=sys.stderr)
        return GUARD_VIOLATION
    stop = guard_preflight(allow_on_disk, allow0, published, state_on_disk)
    if stop:
        print("STIG-ADMIN-GUARD-STOPPED %s: nothing contained, nothing published; restore srv/idp/state from the backup "
              "(keycloak-cac/deploy/vm/README.md, restore from backup)" % stop, file=sys.stderr)
        return GUARD_VIOLATION
    # An unreadable gate marker is never "0": report only for this run (no publish, no containment), retry next run.
    marker = gate_version(kc)
    if marker is None:
        print("STIG-ADMIN-GATE-MARKER-UNREADABLE the deployed gate's capability marker could not be read: report only this "
              "run (nothing published, nothing contained); the next run retries", file=sys.stderr)
        fix = False
        untrusted.append("(gate marker unreadable)")
    # The allowlist decides who may be an administrator (written only by grant/promote after their checks, removed by
    # revoke). Everyone holding any realm-management role by ANY route who is not on it, or holds more than their
    # entry records, is unvetted: demoted (every route removed), the account DISABLED and its sessions ended until the
    # operator re-vets it (grant, then user-enable), exit 2 -> mailed. Which accounts are unvetted is decided from the
    # live roles only, never from event history.
    allow = load_allowlist()
    if any([migrate_entry(kc, e_) for e_ in allow.values()]):      # older entries gain grant snapshots, once
        _write_json(ALLOWLIST, allow)
        print("guard: allowlist entries given grant snapshots (groups by id)")
    sa_ids = {sa["id"] for sa in all_accounts(kc) if (sa.get("username") or "").startswith("service-account-") and is_service_account(kc, sa)}
    if marker is not None and publish_allowlist(kc, allow):
        print("STIG-ADMIN-ALLOWLIST-REPUBLISHED the master-realm copy differed from %s and was rewritten" % ALLOWLIST, file=sys.stderr)
        untrusted.append("(published allowlist)")
    holders = rm_holders(kc)
    _gate = {}
    def gate_v():
        return marker if marker is not None else 0      # with an unreadable marker nothing is contained (fix is off)
    def gate_ok():
        if "v" not in _gate:
            _gate["v"] = marker is not None and marker >= GATE_ROLE_EXTENT_MIN
            print("guard: the deployed gate %s role extent (capability marker)" % ("checks" if _gate["v"] else "is NOT confirmed to check"))
        return _gate["v"]
    gcache = {}
    for uid, (name, held) in holders.items():
        e = allow.get(uid)
        standing = effective_standing(NOT_LISTED if (not e or uid in sa_ids) else classify(held, entry_items(e), lambda gid: group_live(kc, gid, gcache)),
                                      gate_v())
        if standing == VETTED:
            continue
        if standing == NEEDS_REGRANT:
            # availability-safe: the gate refuses it until the operator accepts the change; nothing is contained
            snap = set().union(*[set(g["roles"]) for g in e.get("grants") or []]) if e.get("grants") else set(e.get("rm_roles") or [])
            print("STIG-ADMIN-NEEDS-REGRANT user=%s its granted groups now carry more than when it was vetted (%s), or a granted "
                  "group is gone: the gate refuses it until the operator re-runs: idp-admin.py grant %s %s"
                  % (name, sorted(held - snap) or "a granted group no longer exists", name,
                     " ".join(p_.rsplit("/", 1)[-1] for p_ in admin_role_args([g["path"] for g in e.get("grants") or []] or e.get("roles") or []))),
                  file=sys.stderr)
            untrusted.append(name)
            continue
        why = ("a service account (never an administrator)" if uid in sa_ids else "not on the allowlist" if not e
               else "its entry cannot be read" if standing == NOT_LISTED
               else "holds more than its entry: %s" % sorted(held - set().union(*[set(g["roles"]) for g in e.get("grants") or []])))
        print("STIG-ADMIN-UNVETTED user=%s %s (holds %s)" % (name, why, sorted(held)), file=sys.stderr)
        untrusted.append(name)
        if fix:
            # the account itself, step by step: one failing step never stops the others; held whatever happens
            a_lines, a_fails = contain_user(kc, st, uid, why, pre=[("demote", lambda: demote(kc, kc.api("GET", "/users/%s" % uid))),
                                                                   ("allowlist", lambda: allowlist_drop(uid, kc))])
            for line in a_lines:
                print("STIG-ADMIN-UNVETTED user=%s %s" % (name, line), file=sys.stderr)
            failures.extend("%s %s" % (name, f) for f in a_fails)
            print("STIG-ADMIN-UNVETTED user=%s factors reset (identity bindings kept), DISABLED; user-enable refuses it until "
                  "reset-user, or a grant/promote that passes its checks" % name, file=sys.stderr)
        # What it did through the admin API is LISTED. The users it changed are CONTAINED when that proves the gate
        # failed, or when it held more than its entry and the deployed gate is not confirmed to check role extent.
        if fix:
            try:
                over = standing == OVER_ENTRY
                changed, proven = changed_users(kc, st, uid, e)
                reason = containment_reason(over, gate_ok() if over else True, changed, proven)
                if changed and not proven:
                    print("STIG-ADMIN-CONTAINMENT user=%s none: when it became unvetted cannot be proven, so the users it "
                          "changed are listed for review only" % name, file=sys.stderr)
                if reason:
                    print("STIG-ADMIN-CONTAINMENT user=%s %s" % (name, reason), file=sys.stderr)
                    c_lines, c_fails = contain_changed(kc, st, changed, load_allowlist())
                    failures.extend(c_fails)
                    for line in c_lines:
                        print("STIG-ADMIN-CONTAINED user=%s %s" % (name, line), file=sys.stderr)
            except BaseException as ex:      # noqa: BLE001
                failures.append("%s containment" % name)
                print("STIG-ADMIN-CONTAINED user=%s could not contain the users it changed: %s" % (name, ex), file=sys.stderr)
        try:
            since, lines = review_actor(kc, st, uid, e)
            if lines:
                print("STIG-ADMIN-GATE-FAILURE user=%s the allowlist gate refuses an administrator that is not on the allowlist or "
                      "holds more than its entry, at every sign-in and on the admin API, so it should not have been able to make any change while unvetted. The changes "
                      "below (listed from %s) are to be INVESTIGATED as a gate failure; act on them with reset-user "
                      "[--clear-bindings], client-delete or role-delete." % (name, since), file=sys.stderr)
            for line in lines:
                print("STIG-ADMIN-REVIEW user=%s %s" % (name, line), file=sys.stderr)
        except BaseException as ex:      # noqa: BLE001
            failures.append("%s review" % name)
            print("STIG-ADMIN-REVIEW user=%s could not list its changes: %s" % (name, ex), file=sys.stderr)
    for uid, e in sorted(load_allowlist().items()):
        if uid in holders:
            continue
        if kc.api("GET", "/users/%s" % uid, ok404=True) is None:
            allowlist_drop(uid, kc)                     # the account was deleted: nothing to report
            continue
        print("STIG-ADMIN-ALLOWLIST-REMOVED user=%s no longer holds any realm-management role (was %s, granted %s by %s)"
              % (e["username"], e.get("roles"), e.get("granted_at"), e.get("operator")), file=sys.stderr)
        untrusted.append(e["username"])
        allowlist_drop(uid, kc)              # in report mode too: a stale entry must never vet anything
    for hid in list((st.get("guard_disabled") or {}).keys()):     # a hold on a deleted account means nothing
        if kc.api("GET", "/users/%s" % hid, ok404=True) is None:
            st["guard_disabled"].pop(hid, None)
    admins = admin_members(kc)
    save_state(st)
    bad = [(uid, name, [g["path"] for g in app_tree_groups(kc, uid)]) for uid, name in admins.items()]
    bad = [b for b in bad if b[2]]
    for uid, name, inside in bad:
        print("STIG-ADMIN-IN-DELEGATED-GROUP user=%s groups=%s" % (name, inside), file=sys.stderr)
        if fix:
            take_out_of_app_groups(kc, uid)          # raises unless verified gone
            print("STIG-ADMIN-IN-DELEGATED-GROUP user=%s fixed (verified: no application-tree membership)" % name, file=sys.stderr)
    onboarding = onboarding_guard(kc, fix_requested, marker)
    handoff = handoff_guard(kc, fix_requested)          # the hand-off worker: drift -> disabled, like an onboarding client
    print("guard: %d administrators protected (idp-admin-only permission); %d were in an application group; "
          "%d allowlist violations; %d onboarding-client violations; %d hand-off-worker violations%s" % (
              len(admins), len(bad), len(untrusted), len(onboarding), len(handoff),
              " - fixed" if (bad or untrusted or onboarding or handoff) and fix else ""))
    onboarding = onboarding + handoff
    if failures:
        raise RuntimeError("remediation steps failed: %s" % failures)
    if (bad or untrusted or mapped) and not fix:
        return GUARD_VIOLATION
    if onboarding and not fix_requested:
        return GUARD_VIOLATION
    return GUARD_FIXED if (bad or untrusted or mapped or onboarding) else GUARD_OK

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

def unvetted_since(kc, st, uid, entry):
    """(since, proven): from when an unvetted account's actions are looked at. Never vetted: all of its events. Vetted
    at some point: everything after its LAST vetting (vetted_at) - whatever it did after the operator last vetted it
    is not covered by that vetting. Always proven: there is no list-only fallback."""
    vetted = int((st.get("vetted_at") or {}).get(uid, 0))
    return (vetted, True) if vetted else (0, True)

def review_actor(kc, st, uid, entry):
    """Every admin-API change this account made from unvetted_since() (failing wide), one line each: operation,
    resource type, resource path, time. Nothing is changed - on no account: the operator decides, with reset-user
    [--clear-bindings], client-delete or role-delete, which address the resource by exact id or by name, never by an
    event path. Returns (since as text, lines)."""
    if not UUID.match(uid):
        raise RuntimeError("not a user id: %r" % uid)
    since, proven = unvetted_since(kc, st, uid, entry)
    out = []
    for e in admin_events(kc, "authUser=%s" % q(uid)):
        try:
            if e.get("time", 0) < since:
                continue
            path = e.get("resourcePath") or ""
            parts = path.split("/")
            hint = (" (if not legitimate: idp-admin.py reset-user %s [--clear-bindings])" % parts[1]
                    if len(parts) >= 2 and parts[0] == "users" and UUID.match(parts[1]) and parts[1] != uid else "")
            out.append("REVIEW %s %s %s at %s%s" % (e.get("operationType"), e.get("resourceType"), json.dumps(path),
                                                  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e.get("time", 0) / 1000)), hint))
        except Exception as ex:      # noqa: BLE001 - one odd event never hides the others
            out.append("REVIEW (unreadable event: %s)" % ex)
    when = (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(since / 1000)) + " (the first change that took it beyond its vetting)"
            if since else "its first event (never vetted)" if proven else "its first event (the point it became unvetted is unknown)")
    return when, out

class BindingConflict(Exception):
    pass

class NoBindingsEndpoint(Exception):
    pass

def write_bindings(kc, uid, set_=None, remove=(), present=None, reason=None):
    """Write identity bindings server-side through stig-extensions' stig-bindings endpoint (realm administrators only):
    its admin event carries the card MASKED. A PUT of the user representation would store the full EDIPI in the admin
    event (Keycloak records the request body). 409 -> BindingConflict; no endpoint (an older image) -> NoBindingsEndpoint."""
    body = {}
    if set_:
        body["set"] = dict(set_)
    if remove:
        body["remove"] = list(remove)
    if present:
        body["presentCard"] = present
    if reason:
        body["reason"] = reason
    st, data = kc.req("POST", "/admin/realms/%s/stig-bindings/users/%s" % (REALM, uid), json.dumps(body).encode(),
                      {"Content-Type": "application/json"})
    if st == 200:
        return
    if st == 409:
        raise BindingConflict(mask_digits(clean(data, 200)))
    if st in (404, 405):
        raise NoBindingsEndpoint("the running image has no stig-bindings endpoint (deploy the image with it)")
    raise RuntimeError("stig-bindings: HTTP %s %s" % (st, mask_digits(clean(data, 200))))

PROFILE_FIELDS = ("username", "email", "firstName", "lastName", "emailVerified", "enabled", "requiredActions")

def put_user(kc, uid, changes, containment=False):
    """Change ONLY these profile fields of a user (username, e-mail, names, the two flags, required actions), server-side
    through stig-bindings: Keycloak's admin event for a user PUT holds every attribute, the card included, even when the
    request sends none; the endpoint's event holds only the fields.
      - 404/405 (an image without the endpoint): the former PUT of just these fields (the event then stores the
        account's attributes, as before this change).
      - any other refusal or error: FAILS CLOSED (exit) - except the guard's containment disable (containment=True,
        changes exactly {"enabled": False}), which must always land: then a PUT of exactly {"enabled": false}.
    (A test double without raw requests goes straight to the PUT.)"""
    changes = {k: v for k, v in changes.items() if k in PROFILE_FIELDS and v is not None}
    if containment and changes != {"enabled": False}:
        raise ValueError("a containment update is exactly {enabled: false}")
    if getattr(kc, "req", None) is not None:
        st, data = kc.req("POST", "/admin/realms/%s/stig-bindings/users/%s" % (REALM, uid),
                          json.dumps({"profile": changes, "reason": "containment" if containment else "profile"}).encode(),
                          {"Content-Type": "application/json"})
        if st == 200:
            return
        if st not in (404, 405):
            if not containment:
                sys.exit("FAILED: stig-bindings refused the profile update (HTTP %s %s); nothing was changed"
                         % (st, mask_digits(clean(data, 160))))
            print("WARNING: stig-bindings refused the containment disable (HTTP %s %s): disabling with a PUT of "
                  "{enabled: false} only" % (st, mask_digits(clean(data, 160))), file=sys.stderr)
            kc.api("PUT", "/users/%s" % uid, {"enabled": False})
            return
    kc.api("PUT", "/users/%s" % uid, dict(changes, id=uid))

def bindings_or_put(kc, uid, set_=None, remove=(), reason=None):
    """write_bindings, or - on an image without the endpoint - the former full PUT, with a warning (the admin event then
    stores the account's attributes as they are)."""
    try:
        write_bindings(kc, uid, set_=set_, remove=remove, reason=reason)
    except NoBindingsEndpoint:
        print("WARNING: this image has no stig-bindings endpoint: written with a user PUT (its admin event stores the "
              "account's attributes in full)", file=sys.stderr)
        rep_ = kc.api("GET", "/users/%s" % uid); attrs = dict(rep_.get("attributes") or {})
        for k in remove:
            attrs.pop(k, None)
        attrs.update({k: [v] for k, v in (set_ or {}).items()})
        rep_["attributes"] = attrs
        kc.api("PUT", "/users/%s" % uid, rep_)

def clear_bindings(kc, u):
    """Remove the administrator-set identity bindings (entra_oid, cac_edipi), verified. Returns what was removed."""
    attrs = kc.api("GET", "/users/%s" % u["id"]).get("attributes") or {}
    had = [k for k in IDENTITY_BINDINGS if attrs.get(k)]
    if had:
        bindings_or_put(kc, u["id"], remove=had, reason="clear bindings")
    left = [k for k in IDENTITY_BINDINGS if (kc.api("GET", "/users/%s" % u["id"]).get("attributes") or {}).get(k)]
    if left:
        raise RuntimeError("%s: identity bindings still set: %s" % (u["username"], left))
    return ["binding:" + k for k in had]

def hold(st, uid, why):
    """The guard disabled this account: user-enable refuses it until reset-user, or a grant/promote that passes its
    checks, releases it."""
    st.setdefault("guard_disabled", {})[uid] = {"at": now_ms(), "why": why}

def release(st, uid):
    if st.setdefault("guard_disabled", {}).pop(uid, None) is not None:
        save_state(st)

def reset_verified(kc, uid):
    """Re-read the account: True only if it holds no credential, no identity-provider link and no e-mail address."""
    u = kc.api("GET", "/users/%s" % uid)
    return (not (kc.api("GET", "/users/%s/credentials" % uid) or []) and not (kc.api("GET", "/users/%s/federated-identity" % uid) or [])
            and not u.get("email"))

def contain_user(kc, st, uid, why, pre=()):
    """Contain one account: `pre` steps (the unvetted account's demote and allowlist drop), then reset its factors
    (identity bindings are never cleared automatically - only reset-user --clear-bindings does), disable it, end its sessions - each step on its own, so one failing never stops the others.
    The account is HELD whatever happens (user-enable refuses it). reset_at - from which grant's promotion checks look
    at the account's history - moves ONLY when the reset returned AND a re-read shows nothing left: after a failed or
    partial reset, every factor anyone planted still counts. Returns (lines, failures)."""
    lines, failures, reset_ok = [], [], False
    steps = list(pre) + [
        ("reset", lambda: reset_factors(kc, kc.api("GET", "/users/%s" % uid), [why])),
        ("disable", lambda: put_user(kc, uid, {"enabled": False}, containment=True)),   # the one field; always lands
        ("logout", lambda: kc.api("POST", "/users/%s/logout" % uid))]
    for label, step in steps:
        try:
            r_ = step()
            reset_ok = reset_ok or label == "reset"
            lines.append("%s: done%s" % (label, (" %s" % r_) if isinstance(r_, list) else ""))
        except BaseException as ex:      # noqa: BLE001 - reported, and the remaining steps still run
            lines.append("%s: FAILED %s" % (label, ex))
            failures.append(label)
    hold(st, uid, why)
    clean = False
    if reset_ok:
        try:
            clean = reset_verified(kc, uid)
        except BaseException as ex:      # noqa: BLE001
            lines.append("reset check: FAILED %s" % ex)
    nb = []
    if clean:
        try:
            nb = untrusted_bindings(kc, uid)
        except BaseException as ex:      # noqa: BLE001 - provenance unknown: keep reset_at where it is
            nb = ["(provenance unreadable: %s)" % ex]
    if clean and not nb:
        st["reset_at"][uid] = now_ms()
    elif clean:
        lines.append("reset_at unchanged: identity binding(s) %s not proven to be the operator's remain (kept: bindings are "
                     "never cleared automatically; reset-user --clear-bindings after review)" % nb)
    else:
        failures.append("reset not verified")
        lines.append("reset NOT verified: its history still counts at grant (reset_at unchanged); held")
    return lines, failures

GATE_PROVIDER, GATE_ROLE_EXTENT_KEY, GATE_ROLE_EXTENT_MIN = "stig-admin-allowlist-gate", "allowlist-role-extent", 1
GATE_GRANT_ENTRIES = 2      # the marker from which the gate reads grant-level entries (group:<path>)

def gate_version(kc):
    """The deployed extension's capability marker (server info: the allowlist gate's operationalInfo): 0 when the gate
    states none (an older extension); None when the server info cannot be read; 1 = refuses a role beyond the entry
    (expanded role names); 2 = reads grant-level entries."""
    try:
        st, d = kc.req("GET", "/admin/serverinfo")
        if st != 200:
            return None                  # unreadable: never taken for "no marker"
        info = (((json.loads(d).get("providers") or {}).get("authenticator") or {}).get("providers") or {}).get(GATE_PROVIDER) or {}
        v = (info.get("operationalInfo") or {}).get(GATE_ROLE_EXTENT_KEY)
        return 0 if v is None else int(v)
    except Exception:      # noqa: BLE001 - unreadable
        return None

def gate_enforces_roles(kc):
    """True only when the deployed gate states that every allowlist check also refuses a role beyond the entry."""
    v = gate_version(kc)
    return v is not None and v >= GATE_ROLE_EXTENT_MIN

def guard_preflight(allow_on_disk, allow, published_ids, state_on_disk):
    """Why the guard must not act this run (a reason), or None. A missing or empty allowlist file while the published
    allowlist still names administrators, or a missing guard state while there are vetted administrators, is a lost
    record (e.g. a restore without srv/idp/state) - never "everyone is unvetted"."""
    if (not allow_on_disk or not allow) and (published_ids or "").strip(","):
        return "the allowlist file is %s while the published allowlist still names administrators" % ("missing" if not allow_on_disk else "empty")
    if allow and not state_on_disk:
        return "the guard state file is missing while the allowlist names administrators"
    return None

def changed_users(kc, st, uid, entry):
    """The users (other than itself) an unvetted account changed from unvetted_since(): ({id: [what]}, proven)."""
    since, proven = unvetted_since(kc, st, uid, entry)
    out = {}
    for e in admin_events(kc, "authUser=%s" % q(uid)):
        parts = (e.get("resourcePath") or "").split("/")
        if e.get("time", 0) >= since and len(parts) >= 2 and parts[0] == "users" and UUID.match(parts[1]) and parts[1] != uid:
            out.setdefault(parts[1], []).append("%s %s" % (e.get("operationType"), e.get("resourcePath")))
    return out, proven

def containment_reason(over_entry, gate_ok, changed, proven=True):
    """Why the users an unvetted account changed must be contained, or None. Never when the start of its unvetted
    period cannot be proven (they are listed for review only):
      - it changed users while unvetted: those changes prove the gate failed (whatever the marker says);
      - it held more than its entry and the deployed gate is not confirmed to check role extent (marker missing or
        older): the gate could not have stopped it."""
    if not proven:
        return None
    if changed:
        return "it changed users while unvetted: the gate failed"
    if over_entry and not gate_ok:
        return "the deployed gate is not confirmed to refuse a role beyond the entry (capability marker missing or older)"
    return None

def touch_allowlisted(kc, tid):
    """An allowlisted administrator another (unvetted) account changed: end its sessions; remove only the credentials
    and identity-provider links someone other than the operator's tooling added (by the admin events); flag a
    binding someone else set. Never disables it, never touches operator-set bindings. Returns (lines, failures)."""
    lines, failures = [], []
    evs = user_events(kc, tid)
    nonop = [e for e in evs if not operator_actor(kc, e.get("authDetails") or {})]
    resets = [e.get("time", 0) for e in nonop if (e.get("resourcePath") or "").endswith("/reset-password")]
    linked = {(e.get("resourcePath") or "").rsplit("/", 1)[-1] for e in nonop if e.get("operationType") == "CREATE"
              and "/federated-identity/" in (e.get("resourcePath") or "")}
    for label, step in (
            ("logout", lambda: kc.api("POST", "/users/%s/logout" % tid)),
            ("credentials", lambda: [c.get("type") for c in kc.api("GET", "/users/%s/credentials" % tid) or []
                                     if c.get("type") == "password" and any(abs(c.get("createdDate", 0) - t) <= 10000 for t in resets)
                                     and kc.api("DELETE", "/users/%s/credentials/%s" % (tid, c["id"])) is None]),
            ("links", lambda: [l["identityProvider"] for l in kc.api("GET", "/users/%s/federated-identity" % tid) or []
                               if l.get("identityProvider") in linked
                               and kc.api("DELETE", "/users/%s/federated-identity/%s" % (tid, q(l["identityProvider"]))) is None]),
            ("bindings", lambda: ["REVIEW binding %s %s (kept)" % (b, "set by a non-operator" if op is False else "of unknown provenance")
                                  for b, op in sorted(binding_provenance(kc, tid, events=evs).items()) if op is not True])):
        try:
            r_ = step()
            lines.append("%s: %s" % (label, r_ if isinstance(r_, list) else "done"))
        except BaseException as ex:      # noqa: BLE001
            lines.append("%s: FAILED %s" % (label, ex)); failures.append(label)
    return lines, failures

def contain_changed(kc, st, changed, allow):
    """Contain each changed user pending review (contain_user: sessions, factors, disabled, held - identity bindings
    kept). An allowlisted administrator is never disabled for another account's actions: touch_allowlisted."""
    lines, failures = [], []
    for tid, what in sorted(changed.items()):
        try:
            v = kc.api("GET", "/users/%s" % tid, ok404=True)
            if not v or v.get("id") != tid:
                lines.append("CONTAIN user %s: no longer exists" % tid)
                continue
            if tid in allow:
                # never disabled because of ANOTHER account's actions, and its operator-set bindings stay (it must
                # still sign in by card): sessions ended, only what a non-operator added is removed
                t_lines, t_fails = touch_allowlisted(kc, tid)
                failures.extend("touched %s %s" % (tid, f) for f in t_fails)
                lines.append("STIG-ADMIN-ALLOWLISTED-TOUCHED user=%s (it was changed: %s): %s; NOT disabled - review it"
                             % (v["username"], "; ".join(what), "; ".join(t_lines)))
                continue
            c_lines, c_fails = contain_user(kc, st, tid, "changed by an unvetted administrator",
                                            pre=[("logout", lambda: kc.api("POST", "/users/%s/logout" % tid))])
            failures.extend("contain %s %s" % (tid, f) for f in c_fails)
            lines.append("CONTAINED user=%s: %s; DISABLED and held pending review (it was changed: %s); after review: "
                         "reset-user, then user-enable" % (v["username"], "; ".join(c_lines), "; ".join(what)))
        except BaseException as ex:      # noqa: BLE001 - one user never stops the others
            failures.append("contain %s" % tid)
            lines.append("FAILED to contain user %s: %s" % (tid, ex))
    return lines, failures

def cmd_reset_user(a):
    """Reset an account's factors (passwords, OTP, WebAuthn, identity-provider links, e-mail) and end its sessions.
    --clear-bindings also removes the administrator-set identity bindings (entra_oid, cac_edipi), verified."""
    kc = KC(); u = by_name_or_id(kc, a.user)
    gone, released, nb = reset_user(kc, u, a.clear_bindings)
    print("%s: reset %s" % (u["username"], gone))
    if nb:
        sys.exit("REFUSED to release %s: identity binding(s) %s are not proven to be set by the operator's tooling and remain; "
                 "after review re-run with --clear-bindings (the hold and the factor-reset point stay)" % (u["username"], nb))

def reset_user(kc, u, clear):
    """reset-user's work: factors, links, e-mail, sessions (+ bindings when `clear`). reset_at moves and a guard hold is
    released ONLY when no identity binding a non-operator set remains. Returns (gone, released, remaining bindings)."""
    gone = reset_factors(kc, u, ["operator: reset-user"])
    if clear:
        gone += clear_bindings(kc, u)
    nb = untrusted_bindings(kc, u["id"])
    st = load_state() or new_state()
    if nb:
        return gone, False, nb
    st["reset_at"][u["id"]] = now_ms(); save_state(st)
    release(st, u["id"])
    return gone, True, []

def cmd_client_delete(a):
    """Delete a client by exact clientId (looked up, encoded) or by its UUID."""
    kc = KC()
    if UUID.match(a.client):
        c = kc.api("GET", "/clients/%s" % a.client, ok404=True)
    else:
        c = next((x for x in kc.api("GET", "/clients?clientId=%s" % q(a.client)) or [] if x["clientId"] == a.client), None)
    if not c:
        sys.exit("no such client %s" % a.client)
    if c["clientId"] in ("realm-management", "account", "account-console", "security-admin-console", "admin-cli", "broker",
                         "admin-permissions") + DELEGATE_CLIENTS + APP_CLIENTS + ONBOARDING_CLIENT_IDS:
        sys.exit("REFUSED: %s is a client this deployment relies on" % c["clientId"])
    # a host file left behind would re-create the client at the next Keycloak start. Only a file holding exactly this
    # one client object is removed; a file holding other clients too is never edited here: refused before any change
    files = host_client_files().get(c["clientId"], [])
    shared = [f for f in files if not isinstance(load_json_strict(open(f).read()), dict)]
    if shared:
        sys.exit("REFUSED: %s is defined in %s, which holds other clients too: move it to its own %s.json (or remove "
                 "it from that file) first; nothing deleted" % (c["clientId"], shared, c["clientId"]))
    kc.api("DELETE", "/clients/%s" % c["id"]); print("deleted client %s (%s)" % (c["clientId"], c["id"]))
    for f in files:
        os.remove(f); print("removed %s (else the next Keycloak start re-creates it); remove the repo copy too" % f)

def cmd_role_delete(a):
    """Delete a realm role by exact name (or <clientId>:<role> for a client role), looked up and encoded, or by UUID."""
    kc = KC()
    if UUID.match(a.role):
        r = kc.api("GET", "/roles-by-id/%s" % a.role, ok404=True)
    elif ":" in a.role:
        cid, rn = a.role.split(":", 1)
        c = next((x for x in kc.api("GET", "/clients?clientId=%s" % q(cid)) or [] if x["clientId"] == cid), None)
        r = c and kc.api("GET", "/clients/%s/roles/%s" % (c["id"], q(rn)), ok404=True)
    else:
        r = kc.api("GET", "/roles/%s" % q(a.role), ok404=True)
    if not r or not UUID.match(r.get("id", "")):
        sys.exit("no such role %s" % a.role)
    if r.get("name", "").startswith("default-roles-") or r.get("name") in ("offline_access", "uma_authorization"):
        sys.exit("REFUSED: %s is a built-in role" % r["name"])
    kc.api("DELETE", "/roles-by-id/%s" % r["id"]); print("deleted role %s (%s)" % (r["name"], r["id"]))

def by_name_or_id(kc, x):
    if UUID.match(x):
        u = kc.api("GET", "/users/%s" % x, ok404=True)
        return u or sys.exit("no such user %s" % x)
    return user(kc, x)

def group_carries_admin(kc, gpath):
    """The group or any ancestor holds a realm-management role, directly or by composite."""
    rmc = client_uuid(kc, "realm-management")
    parts = gpath.strip("/").split("/")
    for k in range(1, len(parts) + 1):
        g = group_by_path(kc, "/" + "/".join(parts[:k]))
        if g and kc.api("GET", "/groups/%s/role-mappings/clients/%s/composite" % (g["id"], rmc)):
            return True
    return False

def demote(kc, u):
    """Take every administrator right off an account, whatever the route: /roles/* memberships, memberships of groups
    that carry a realm-management role themselves or through an ancestor, realm-management roles mapped directly,
    and any directly mapped realm or client role whose composites reach one. Verified."""
    rmc = client_uuid(kc, "realm-management")
    for g in paged(kc, "/users/%s/groups" % u["id"]):
        if g["path"].startswith("/roles/") or group_carries_admin(kc, g["path"]):
            kc.api("DELETE", "/users/%s/groups/%s" % (u["id"], g["id"]))
    rm = kc.api("GET", "/users/%s/role-mappings" % u["id"]) or {}
    realm_bad = [r for r in rm.get("realmMappings") or [] if _reaches_rm(kc, r["id"], rmc)]
    if realm_bad:
        kc.api("DELETE", "/users/%s/role-mappings/realm" % u["id"], realm_bad)
    for cname, cm in (rm.get("clientMappings") or {}).items():
        bad = [r for r in cm.get("mappings") or [] if cm["id"] == rmc or _reaches_rm(kc, r["id"], rmc)]
        if bad:
            kc.api("DELETE", "/users/%s/role-mappings/clients/%s" % (u["id"], cm["id"]), bad)
    if is_admin(kc, u["id"]):
        raise RuntimeError("%s still holds administrator rights after demotion (another route: %s)" % (u["username"], sorted(rm_roles(kc, u["id"]))))

def _reaches_rm(kc, rid, rmc, seen=None):
    """A role whose composites (recursively) include a realm-management role."""
    seen = seen or set()
    if rid in seen:
        return False
    seen.add(rid)
    for c in kc.api("GET", "/roles-by-id/%s/composites" % rid) or []:
        if c.get("clientRole") and c.get("containerId") == rmc:
            return True
        if c.get("composite") and _reaches_rm(kc, c["id"], rmc, seen):
            return True
    return False

def cmd_user_unlock(a):
    """Clear a password lockout (the card path is never locked by password failures)."""
    kc = KC(); u = user(kc, a.username)
    kc.api("DELETE", "/attack-detection/brute-force/users/%s" % u["id"])
    print("unlocked %s" % a.username)

def cmd_guard(a):
    """Keep administrators out of the delegates' reach, failing closed:
      - a Users permission on every administrator (found by effective realm-management roles and /roles/*) that
        only /roles/idp-admin members satisfy (POSITIVE policy, UNANIMOUS with the delegated permissions);
      - administrators found in any application-tree group (any depth) are reported and, with --fix, taken out
        (roles those groups carried are mapped directly), verified by re-reading;
      - exit 2 if a violation was found (fixed or not), 1 on any failure."""
    # INFORMATION: a recorded delegate JWKS whose name no longer resolves to public addresses only (resolved here,
    # from the host's own resolver, before KC() enters Keycloak's network namespace)
    jwks_info = ["info  STIG-DELEGATE-JWKS-UNRESOLVABLE client=%s %s" % (cid, e)
                 for cid, w in sorted(load_delegate_records().items()) if w.get("auth") == "client-jwt"
                 for e in resolve_errors({"jwks_url": w.get("jwks_url")})]
    kc = KC()
    try:
        st = guard(kc, a.fix)
        misaligned = app_manager_alignment(kc)          # REPORT ONLY: never fixed automatically
        misaligned += delegate_auth_report(kc)          # REPORT ONLY: a delegate's authentication differs from its record
        misaligned += test_twins_present(kc, a.fix)     # a test twin; --fix removes a stale one or one whose delegate is off
        expired_invites, pending_invites = entra_invites(kc)
        misaligned += expired_invites                   # REPORT ONLY: an Entra invite nobody used in time
        misaligned += edipi_usernames(kc)               # REPORT ONLY: an EDIPI as a username
        ra_report, ra_info = referer_audit_report(kc)
        misaligned += ra_report                         # REPORT ONLY: the Referer audit switched off (V-222447)
        expired_cards, pending_cards_ = pending_cards(kc)
        misaligned += expired_cards                     # REPORT ONLY: an invite's card never presented in time
        pending_invites += pending_cards_
        expired_links, pending_links = card_links(kc)
        misaligned += expired_links                     # REPORT ONLY: a link-cac request never completed in time
        pending_invites += pending_links
    except RuntimeError as e:
        print("guard: FAILED: %s" % e, file=sys.stderr); sys.exit(1)
    for line in misaligned:
        print(line, file=sys.stderr)
    for line in jwks_info + pending_invites + ra_info:
        print(line)                                # information only
    try:
        for line in accounts_without_app_role(kc):
            print(line)                        # information only: never changes the exit code
    except Exception as e:      # noqa: BLE001
        print("info  could not list accounts without an application role: %s" % e)
    if st != GUARD_OK or misaligned:
        sys.exit(2)

def admin_paths(kc, uid):
    return [g["path"] for g in paged(kc, "/users/%s/groups" % uid) if g["path"].startswith("/roles/")]

def is_admin(kc, uid):
    """An administrator by membership of a /roles/* group OR by holding any realm-management role effectively."""
    return bool(admin_paths(kc, uid)) or bool(kc.api("GET", "/users/%s/role-mappings/clients/%s/composite" % (uid, client_uuid(kc, "realm-management"))))

def send_setup(kc, u, lifespan, must=True):
    """E-mail the person a one-use link: accept the terms, set a password, enrol TOTP (admin-issued action token).
    Returns True when sent; with must=False a failure is returned (False) instead of ending the command."""
    if not u.get("email"):
        if must:
            raise RuntimeError("%s has no e-mail address; set one (rename %s %s --email ...) and send the link again" % (
                u["username"], u["username"], u["username"]))
        return False
    st, data = kc.req("PUT", "/admin/realms/%s/users/%s/execute-actions-email?lifespan=%d&client_id=account-console&redirect_uri=%s" % (
        REALM, u["id"], lifespan, q("%s/realms/%s/account/" % (CFG["CAC_PUBLIC_URL"], REALM))),
        json.dumps(["UPDATE_PASSWORD", "CONFIGURE_TOTP", "TERMS_AND_CONDITIONS"]).encode(), {"Content-Type": "application/json"})
    if st not in (200, 204):
        if must:
            raise RuntimeError("set-up e-mail to %s failed: HTTP %s %s" % (u["username"], st, data[:200]))
        return False
    return True

def admin_role_args(roles):
    return [r for r in roles if r.startswith("/roles/") or r in ROLE_GROUPS]

def apply_roles(kc, u, roles, st):
    """Join /roles groups FIRST and put the account under the administrators' permission in the same call, then the
    application roles (directly for an administrator, through the /<client>/<ROLE> group for anyone else)."""
    paths = ["/roles/" + r if not r.startswith("/") else r for r in admin_role_args(roles)]
    groups = [group_by_path(kc, p_) or sys.exit("no group %s (run roles-setup)" % p_) for p_ in paths]
    if groups:
        # the allowlist entry is written BEFORE the membership (from what those groups carry), so a guard run in
        # between can never take the account for an unvetted administrator
        rmc = client_uuid(kc, "realm-management")
        prev = load_allowlist().get(u["id"]) or {}
        # what this account may hold: its previous vetted entry plus what the granted groups carry - never whatever it
        # happens to hold now (a right given in the console must not be written into the allowlist)
        cache = {}
        prev_ids = [g["id"] for g in (prev.get("grants") or []) if group_live(kc, g["id"], cache) is not None]
        prev_paths = [g["path"] for g in (prev.get("grants") or []) if g["id"] in prev_ids] or \
                     [x for x in prev.get("roles") or [] if isinstance(x, str) and x.startswith("/")]
        grants = make_grants(kc, prev_paths + paths, cache)
        expected = set().union(*[set(g["roles"]) for g in grants]) if grants else set()
        extra = rm_roles(kc, u["id"]) - expected
        if extra:
            sys.exit("REFUSED: %s already holds realm-management roles nobody vetted (%s): revoke them first "
                     "(idp-admin.py revoke %s), then grant" % (u["username"], sorted(extra), u["username"]))
        try:
            allowlist_put(kc, u, [g["path"] for g in grants], rm=expected, grants=grants)
            for g in groups:
                kc.api("PUT", "/users/%s/groups/%s" % (u["id"], g["id"]))
            if not rm_roles(kc, u["id"]) <= expected:
                raise RuntimeError("%s holds more realm-management roles than its allowlist entry" % u["username"])
        except BaseException:
            # a failed grant leaves no allowlist entry behind (and no membership): back to the previous entry
            for g in groups:
                kc.req("DELETE", "/admin/realms/%s/users/%s/groups/%s" % (REALM, u["id"], g["id"]))
            al = load_allowlist()
            if prev:
                al[u["id"]] = prev
            else:
                al.pop(u["id"], None)
            _write_json(ALLOWLIST, al); publish_allowlist(kc, al)
            raise
    admin = is_admin(kc, u["id"])
    if admin:
        sync_admin_protection(kc, admin_members(kc))
        st["pending"].pop(u["id"], None)
        save_state(st)
    for r in roles:
        if ":" in r:
            cid, role = r.split(":", 1); cu = client_uuid(kc, cid)
            if admin:
                kc.api("POST", "/users/%s/role-mappings/clients/%s" % (u["id"], cu), [kc.api("GET", "/clients/%s/roles/%s" % (cu, q(role)))])
            else:
                g = group_by_path(kc, "/%s/%s" % (cid, role)) or sys.exit("no group /%s/%s (run roles-setup)" % (cid, role))
                kc.api("PUT", "/users/%s/groups/%s" % (u["id"], g["id"]))
    return take_out_of_app_groups(kc, u["id"]) if admin else []

CREATED_BY = "stig_created_by"      # set by stig-accounts on accounts a delegate created

def promote_or_pend(kc, u, roles, st, reset, lifespan=43200, email=None, clear=False):
    """The promotion rule, shared by grant, invite and promote. Returns 'promoted' or 'pending'; raises/exits if refused."""
    uid = u["id"]
    if is_service_account(kc, u):
        sys.exit("REFUSED: %s is a client's service account: service accounts are never administrators (use a person's "
                 "account)" % u["username"])
    u = kc.api("GET", "/users/%s" % uid)
    creator = ((u.get("attributes") or {}).get(CREATED_BY) or [None])[0]
    if creator and not (reset and email):
        sys.exit("REFUSED: %s was created by a delegate (%s): it is the delegate's until its credentials are reset and the "
                 "operator sets its e-mail address - re-run with --reset-credentials --email <address checked by you>"
                 % (u["username"], creator.split(" ")[0]))
    risks = promotion_risks(kc, u, st, since=st["reset_at"].get(uid, 0))
    if creator:
        risks.append("created by a delegate (%s)" % creator.split(" ")[0])
    dr = delegation_reasons(kc, u)
    if dr:
        risks.append("a delegated administrator can manage it now (%s)" % "; ".join(dr))
    if risks and not reset:
        sys.exit("REFUSED: %s cannot be made an administrator with the factors it has:\n  - %s\nRe-run with "
                 "--reset-credentials to remove every password, OTP and identity-provider link first (and --clear-bindings when an "
                 "identity binding is listed); the person then "
                 "re-enrols by card, or through a set-up link once the account is out of every delegate's reach."
                 % (u["username"], "\n  - ".join(risks)))
    if risks:
        moved = take_out_of_app_groups(kc, uid)           # out of every delegate's reach before anything else
        gone = reset_factors(kc, u, risks)
        st["reset_at"][uid] = int(time.time() * 1000); save_state(st)
        if email:
            put_user(kc, uid, {"email": email, "emailVerified": False}); gone.append("e-mail set by the operator")
            if creator:     # the operator has now reset it and set its address: no longer the delegate's
                bindings_or_put(kc, uid, remove=[CREATED_BY], reason="operator reset")
            if creator and (kc.api("GET", "/users/%s" % uid).get("attributes") or {}).get(CREATED_BY):
                raise RuntimeError("could not clear the delegate-created marker of %s" % u["username"])
        print("%s: reset %s%s" % (u["username"], gone or "nothing", ("; application groups -> direct roles: %s" % moved) if moved else ""))
        u = kc.api("GET", "/users/%s" % uid)
        if delegation_reasons(kc, u):
            raise RuntimeError("%s is still within a delegate's reach after the reset" % u["username"])
    cleared = binding_gate(kc, u, clear)                 # refuses while a binding not proven the operator's remains
    if cleared:
        print("%s: identity bindings cleared on request: %s" % (u["username"], cleared))
        u = kc.api("GET", "/users/%s" % uid)
    path = strong_path(kc, u)
    if path is None:
        st["pending"][uid] = {"roles": roles, "since": int(time.time() * 1000)}; save_state(st)
        take_out_of_app_groups(kc, uid)
        if uid in st["reset_at"]:
            # never mail a set-up link on the strength of an address that survived (or followed) a reset
            how = ("its factors were reset and its e-mail cleared: set the address explicitly (rename %s %s --email ...), "
                   "then send-setup" % (u["username"], u["username"]))
        elif send_setup(kc, u, lifespan, must=False):
            how = "a set-up link went to its e-mail address"
        elif u.get("email"):
            how = "the set-up e-mail could NOT be sent (Keycloak's mail log says why): retry with send-setup"
        else:
            how = "it has no e-mail address: set one with rename --email, then send-setup"
        print("PENDING: %s becomes %s only after it holds a second factor (%s); then: idp-admin.py promote %s"
              % (u["username"], ",".join(admin_role_args(roles)), how, u["username"]))
        return "pending"
    moved = apply_roles(kc, u, roles, st)
    release(st, uid)             # vetted again, with every promotion check passed
    print("%s: promoted to %s (sign-in path: %s)%s" % (u["username"], ",".join(admin_role_args(roles)), path,
                                                        ("; application groups -> direct roles: %s" % moved) if moved else ""))
    return "promoted"

def cmd_grant(a):
    """Give roles. Becoming an administrator (/roles/*) is a promotion: refused while the account carries anything a
    non-administrator set or could set (see promotion_risks), unless --reset-credentials; and the administrator role
    is granted only once the account has a card or a second factor nobody else set (else it is left pending)."""
    kc = KC(); u = user(kc, a.username)
    st = load_state() or new_state()
    for app, need in APP_USER_MANAGERS.items():
        if app_manager_role(app) in a.roles or "/roles/" + app_manager_role(app) in a.roles:
            if "%s:%s" % (app, need) not in a.roles and need not in direct_client_roles(kc, u["id"], app):
                sys.exit("REFUSED: %s is for %s's %s holders only, granted together: grant %s %s %s:%s. Holding %s:%s only "
                         "through the /%s/%s group does not count: the application's own delegate can write that group"
                         % (app_manager_role(app), app, need, a.username, app_manager_role(app), app, need, app, need, app, need))
    entry = load_allowlist().get(u["id"])
    want = {"/roles/" + r if not r.startswith("/") else r for r in admin_role_args(a.roles)}
    already = bool(entry) and want <= set(entry.get("roles") or []) and is_admin(kc, u["id"])     # nothing new
    if admin_role_args(a.roles) and not already:
        promote_or_pend(kc, u, a.roles, st, a.reset_credentials, email=a.email, clear=a.clear_bindings)
    else:
        moved = apply_roles(kc, u, a.roles, st)
        print("%s: groups %s%s" % (a.username, [g["path"] for g in paged(kc, "/users/%s/groups" % u["id"])],
                                   ("; moved to direct mappings: %s" % moved) if moved else ""))
    if guard(kc, True) not in (GUARD_OK, GUARD_FIXED):   # anything else has already raised; belt and braces
        raise RuntimeError("guard did not complete")
    if is_admin(kc, u["id"]) and app_tree_groups(kc, u["id"]):
        raise RuntimeError("%s is an administrator but still in application groups" % a.username)

def cmd_promote(a):
    """Finish a pending promotion once the person has enrolled a second factor (or has a card)."""
    kc = KC(); u = user(kc, a.username)
    st = load_state() or new_state()
    p = st["pending"].get(u["id"]) or sys.exit("REFUSED: %s has no pending promotion" % a.username)
    if promote_or_pend(kc, u, p["roles"], st, reset=False, clear=a.clear_bindings) != "promoted":
        sys.exit(3)
    if guard(kc, True) not in (GUARD_OK, GUARD_FIXED):
        raise RuntimeError("guard did not complete")

def cmd_revoke(a):
    """Take an administrator's rights away (every route) and its allowlist entry."""
    kc = KC(); u = user(kc, a.username)
    demote(kc, u); allowlist_drop(u["id"], kc)
    sync_admin_protection(kc, admin_members(kc))
    print("%s: administrator rights and allowlist entry removed" % a.username)

def cmd_allowlist(a):
    """Show the allowlist; --init <username>: create it with that one administrator (only when it does not exist)."""
    kc = KC()
    if a.init:
        if os.path.exists(ALLOWLIST):
            sys.exit("REFUSED: %s exists; use grant" % ALLOWLIST)
        u = user(kc, a.init)
        if not is_admin(kc, u["id"]):
            sys.exit("REFUSED: %s holds no administrator rights" % a.init)
        e = allowlist_put(kc, u, admin_paths(kc, u["id"]))
        print("allowlist created with %s: %s" % (a.init, e["roles"]))
    for uid, e in sorted(load_allowlist().items(), key=lambda x: x[1]["username"]):
        print("%s %s roles=%s granted %s by %s (%d realm-management roles)" % (uid[:8], e["username"], e["roles"], e["granted_at"],
                                                                             e["operator"], len(e["rm_roles"])))

def cmd_send_setup(a):
    kc = KC(); send_setup(kc, user(kc, a.username), a.lifespan); print("set-up link sent to %s" % a.username)

def cmd_rename(a):
    """Rename an account in place (same user id, so applications keyed on `sub` keep it)."""
    kc = KC(); u = kc.api("GET", "/users/%s" % user(kc, a.old)["id"])
    same = a.new == a.old           # `rename X X --email ...`: only the e-mail and names change
    if not same and kc.api("GET", "/users?exact=true&username=%s" % q(a.new)):
        sys.exit("REFUSED: %s already exists" % a.new)
    u.update({"username": a.new, "email": a.email or u.get("email"), "firstName": a.first or u.get("firstName"),
              "lastName": a.last or u.get("lastName"), "emailVerified": True})
    changes = {k: u[k] for k in ("username", "email", "firstName", "lastName", "emailVerified")}
    if same:
        put_user(kc, u["id"], changes)
    else:
        # The STIG realm keeps usernames read-only (editUsernameAllowed=false, also for admins): open it for this one
        # change, then close it again whatever happens.
        kc.api("PUT", "", {"editUsernameAllowed": True})
        try:
            put_user(kc, u["id"], changes)
        finally:
            kc.api("PUT", "", {"editUsernameAllowed": False})
    after = kc.api("GET", "/users/%s" % u["id"])
    if same:
        print("updated %s (e-mail %s, id %s unchanged)" % (after["username"], after.get("email"), u["id"][:8]))
        return
    print("renamed %s -> %s (id %s unchanged: %s)" % (a.old, after["username"], u["id"][:8], after["id"] == u["id"]))

def cmd_set_password(a):
    """Generate a temporary password (change at next sign-in) and require TOTP set-up; the password goes to stdout
    only, for piping into a 0600 file. Fails rather than print to a terminal."""
    import secrets as _s, string
    if sys.stdout.isatty():
        sys.exit("REFUSED: stdout is a terminal; pipe it into a file")
    kc = KC(); u = kc.api("GET", "/users/%s" % user(kc, a.username)["id"])
    alphabet = string.ascii_letters + string.digits
    pw = "".join(_s.choice(alphabet) for _ in range(20)) + "-" + _s.choice("!#%+") + _s.choice(string.digits) + "aZ"
    kc.api("PUT", "/users/%s/reset-password" % u["id"], {"type": "password", "value": pw, "temporary": True})
    put_user(kc, u["id"], {"requiredActions": sorted(set(u.get("requiredActions") or []) | {"CONFIGURE_TOTP"})})
    sys.stdout.write(pw)

def cmd_smtp(a):
    kc = KC()
    kc.api("PUT", "", {"smtpServer": {"host": a.host, "port": str(a.port), "starttls": "true", "ssl": "false", "auth": "true",
                                      "user": a.user, "password": open(a.password_file).read().strip(),
                                      "from": a.sender, "fromDisplayName": a.display_name}})
    print("smtp: %s:%s as %s, from %s" % (a.host, a.port, a.user.split(".")[0] + ".<app>.<tenant>", a.sender))
    # the same relay for unit-failure alerts (idp-alert, independent of Keycloak)
    prev = {}
    if os.path.exists("/srv/idp/config/alert.env"):
        prev = dict(l.strip().split("=", 1) for l in open("/srv/idp/config/alert.env") if "=" in l)
    to = a.alert_to or prev.get("ALERT_TO")
    if to:
        with open(os.open("/srv/idp/config/alert.env", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write("ALERT_TO=%s\nSMTP_HOST=%s\nSMTP_PORT=%s\nSMTP_USER=%s\nSMTP_FROM=%s\n" % (to, a.host, a.port, a.user, a.sender))
        print("alerts: unit failures mailed to %s" % to)

def cmd_invite(a):
    """Create first.last with an email, give it role groups, optionally map a card (realm admin only), and e-mail an
    execute-actions link: set a password, configure TOTP, accept the terms. The link expires after --lifespan
    seconds (at most 86400)."""
    import re as _re
    if not _re.fullmatch(r"[a-z][a-z0-9-]*\.[a-z][a-z0-9.-]*", a.username):
        sys.exit("username must be first.last in lower case")
    if a.lifespan > 86400:
        sys.exit("lifespan is at most 86400 s (24 h)")
    kc = KC()
    if kc.api("GET", "/users?exact=true&username=%s" % q(a.username)):
        sys.exit("REFUSED: %s already exists" % a.username)
    first, last = (a.first or a.username.split(".")[0].title()), (a.last or a.username.split(".", 1)[1].title())
    rep = {"username": a.username, "email": a.email, "firstName": first, "lastName": last, "enabled": True,
           "emailVerified": False, "requiredActions": ["UPDATE_PASSWORD", "CONFIGURE_TOTP", "TERMS_AND_CONDITIONS"]}
    binds = {}
    if a.edipi:
        binds["cac_edipi"] = a.edipi
    if a.entra_oid:
        binds["entra_oid"] = a.entra_oid
    roles = [r for r in a.groups.split(",") if r]
    kc.api("POST", "/users", rep)
    u = user(kc, a.username)
    if binds:                # server-side (stig-bindings): the admin event never holds the full EDIPI
        try:
            bindings_or_put(kc, u["id"], set_=binds, reason="invite")
        except BindingConflict as e:
            kc.api("DELETE", "/users/%s" % u["id"])
            sys.exit("REFUSED: %s (the new account was removed again)" % e)
    if admin_role_args(roles):
        # never an administrator by invitation: created with no group (out of every delegate's reach), promoted
        # only after the person has enrolled a second factor through this link (idp-admin.py promote)
        st = load_state() or new_state()
        promote_or_pend(kc, u, roles, st, reset=False, lifespan=a.lifespan)
        print("invited %s <%s>: link valid %d h; administrator after enrolment" % (a.username, a.email, a.lifespan // 3600))
        return
    if roles:
        cmd_grant(argparse.Namespace(username=a.username, roles=roles, reset_credentials=False))
    send_setup(kc, u, a.lifespan)
    print("invited %s <%s>: link valid %d h" % (a.username, a.email, a.lifespan // 3600))

def cmd_link_entra(a):
    """Bind an account to one Entra identity by its object id (Entra → Users → the person → Object ID, or
    `az ad user show --id <upn> --query id -o tsv`). Realm-admin only, unique."""
    import re as _re
    if not _re.fullmatch(r"[0-9a-f-]{36}", a.oid):
        sys.exit("not an Entra object id")
    kc = KC(); u = kc.api("GET", "/users/%s" % user(kc, a.username)["id"])
    try:
        bindings_or_put(kc, u["id"], set_={"entra_oid": a.oid}, reason="link-entra")
    except BindingConflict as e:
        sys.exit("REFUSED: %s" % e)
    print("%s: entra_oid set; their next Entra sign-in links to this account" % a.username)

# ------------------------------------------------------------------------- link-cac: a card for an EXISTING account
CARD_ATTR = "cac_edipi"                   # the attribute the realm's X.509 step maps cards by (checked live)
CARD_PENDING = CARD_ATTR + "_pending"     # the card a request names: only that card binds (reserved meanwhile)
CARD_LINK = "stig_card_link"              # stig-extensions AccountsPolicy.LINK_ATTRIBUTE: "<epoch-ms>[ admin]" of the request
PRESENT_CARD = "stig-present-card"        # stig-extensions PresentCardRequiredAction
CARD_LINK_DAYS = 7                        # AccountsPolicy.LINK_DAYS: a request is live this long from the time it was made
EDIPI_RE = re.compile(r"[0-9]{10}")       # used with fullmatch
CARD_AUDIT = handoff_audit_syslog         # tests replace it

class LinkRefused(Exception):
    pass

def mask_edipi(e):
    """A card number for a terminal, a log line or an audit record: the last four digits at most."""
    return "******" + e[-4:] if isinstance(e, str) and len(e) >= 4 else "****"

def mask_digits(s):
    """Any run of ten or more digits in a text (an EDIPI in an admin-API path, an error) reduced to its last four."""
    return re.sub(r"[0-9]{6,}([0-9]{4})", r"******\1", s if isinstance(s, str) else str(s))

def read_edipi(what):
    """The EDIPI, typed at a prompt that does not show it (twice; the two must agree), or one line on stdin when stdin
    is not a terminal. Never from the command line: sudo writes the command line to the auth log, and the shell keeps
    it in its history. Exactly ten digits; a refusal never repeats what was typed."""
    import getpass
    if sys.stdin.isatty():
        e = getpass.getpass("EDIPI %s (the 10 digits at the end of the card's CN; not shown): " % what).strip()
        if getpass.getpass("the same EDIPI again: ").strip() != e:
            raise LinkRefused("the two entries differ")
    else:
        e = (sys.stdin.readline() or "").strip()
    if not EDIPI_RE.fullmatch(e):
        raise LinkRefused("not an EDIPI: exactly 10 digits (nothing was changed)")
    return e

def card_holders(kc, edipi):
    """{user id: username} of every account whose card (cac_edipi) IS this EDIPI or whose pending request (cac_edipi_pending)
    names it, whatever its age: one card, one account."""
    out = {}
    for attr in (CARD_ATTR, CARD_PENDING):
        for x in kc.api("GET", "/users?q=%s&exact=true" % q(attr + ":" + edipi)) or []:
            out[x["id"]] = x.get("username")
    return out

def x509_card_attribute(kc):
    """The one attribute every X.509 step of the browser flow maps cards by, or None (no step, one without a
    configuration, or steps that differ) - as stig-extensions' present-card step reads it."""
    cfgs = x509_step_configs(kc, kc.api("GET", "").get("browserFlow"))
    if not cfgs or None in cfgs or len({json.dumps(c, sort_keys=True) for c in cfgs}) != 1:
        return None
    return cfgs[0].get("x509-cert-auth.mapper-selection.user-attribute-name")

def ensure_present_card_step(kc):
    """The present-card required action registered and enabled. Returns what was done ("" when nothing)."""
    ra = kc.api("GET", "/authentication/required-actions/%s" % PRESENT_CARD, ok404=True)
    did = ""
    if ra is None:
        kc.api("POST", "/authentication/register-required-action", {"providerId": PRESENT_CARD, "name": "Present your CAC"})
        ra = kc.api("GET", "/authentication/required-actions/%s" % PRESENT_CARD); did = "registered"
    if not ra.get("enabled"):
        ra["enabled"] = True; kc.api("PUT", "/authentication/required-actions/%s" % PRESENT_CARD, ra); did = did or "enabled"
    return did

def cmd_link_cac(a):
    """Bind a card to an EXISTING account (see link_cac). One audit line per attempt (syslog, auth facility), the card
    masked; an EDIPI is never printed or logged in full."""
    if a.cancel_all:
        if a.username or a.stray or a.cancel or a.edipi or a.bind_edipi or a.replace or a.allow_admin or a.confirm_direct_bind:
            CARD_AUDIT("STIG-LINK-CAC user=* mode=cancel-all card=- replace=no allow_admin=no operator=%s result=refused "
                       "reason=\"--cancel-all takes no username and no other option\"" % clean(operator(), 64))
            sys.exit("REFUSED: --cancel-all takes no username and no other option")
        return cancel_all_links(a)
    if not a.username:
        sys.exit("REFUSED: link-cac needs a username (or --cancel-all)")
    mode = "cancel" if a.cancel else "bind" if a.bind_edipi else "reserve" if a.edipi else "present"
    st = {"card": "-" if mode == "cancel" else "any" if mode == "present" else "?"}
    def audit(result, reason=None):
        CARD_AUDIT("STIG-LINK-CAC user=%s mode=%s card=%s replace=%s allow_admin=%s operator=%s result=%s%s" % (
            mask_digits(clean(a.username, 100)).replace(" ", "_"), mode, st["card"], "yes" if a.replace else "no",
            "yes" if a.allow_admin else "no", clean(operator(), 64), result,
            "" if reason is None else " reason=%s" % json.dumps(mask_digits(clean(reason, 240)))))
    try:
        result, msg = link_cac(a, mode, st)
    except LinkRefused as e:
        audit("refused", str(e))
        sys.exit("REFUSED: %s" % mask_digits(e))
    except RuntimeError as e:
        audit("error", str(e))
        sys.exit("FAILED: %s" % mask_digits(e))
    except SystemExit as e:              # an admin-API failure (its path may carry the EDIPI), or no Keycloak
        audit("error", str(e.code))
        sys.exit(mask_digits(e.code) if isinstance(e.code, str) else e.code)
    audit(result)
    print(msg)

def link_cac(a, mode, st):
    """(result, message) of one link-cac; raises LinkRefused before anything is changed.
      present (default)   the account must present a card at its next sign-in (password + OTP, or Entra): the card the
                          holder presents is bound then - never one bound to or reserved for another account
      reserve (--edipi)   the same, but only the card whose EDIPI the operator typed binds (reserved meanwhile)
      bind (--bind-edipi --confirm-direct-bind)   bound NOW, nobody presenting it: only when the person cannot present a card
      cancel (--cancel)   withdraw a pending link request
    A request lives 7 days. Refused: no such account, a disabled one, a service account; an IdP administrator unless
    --allow-admin, and then only `reserve`; an account that already has a card, or a card its invite named, unless
    --replace (which removes it and ends the account's sessions); an EDIPI bound to or reserved for another account."""
    if a.edipi not in (None, True) or a.bind_edipi not in (None, True) or a.stray:
        st["card"] = "on-the-command-line"
        raise LinkRefused("an EDIPI is never given on the command line (sudo logs the command line, the shell keeps it): "
                          "give --edipi or --bind-edipi alone and type it at the prompt (or on stdin)")
    if a.cancel and (a.edipi or a.bind_edipi or a.replace or a.allow_admin or a.confirm_direct_bind):
        raise LinkRefused("--cancel takes no other option")
    if a.edipi and a.bind_edipi:
        raise LinkRefused("--edipi (the holder presents that card) or --bind-edipi (bound now), not both")
    if a.bind_edipi and not a.confirm_direct_bind:
        raise LinkRefused("--bind-edipi binds a card nobody presents: only when the person cannot present one, after you "
                          "verified the card and its holder yourself - re-run with --confirm-direct-bind")
    if a.confirm_direct_bind and not a.bind_edipi:
        raise LinkRefused("--confirm-direct-bind goes with --bind-edipi only")
    kc = KC()
    found = [x for x in kc.api("GET", "/users?exact=true&username=%s" % q(a.username)) or []
             if (x.get("username") or "").lower() == a.username.lower()]
    if len(found) != 1:
        raise LinkRefused("there is no account %s" % a.username)
    u = kc.api("GET", "/users/%s" % found[0]["id"]); name = u["username"]
    at = u.get("attributes") or {}
    first = lambda k: ((at.get(k) or [""])[0] or "").strip()
    if is_service_account(kc, u):
        raise LinkRefused("%s is a client's service account: it never signs in with a card" % name)
    if not u.get("enabled"):
        raise LinkRefused("%s is disabled: a card is bound only to an account in use (user-enable it first, if it should be)" % name)
    card, pend, link = first(CARD_ATTR), first(CARD_PENDING), first(CARD_LINK)
    if mode == "cancel":
        if not link:
            raise LinkRefused("%s has no link request to cancel%s" % (
                name, " (its pending card is an invite's: link-cac --replace drops it)" if pend else ""))
        bindings_link(kc, u["id"], remove=[k for k in (CARD_LINK, CARD_PENDING) if first(k)], present="remove",
                      reason="link-cac cancel")
        now = kc.api("GET", "/users/%s" % u["id"]); nat = now.get("attributes") or {}
        if nat.get(CARD_LINK) or nat.get(CARD_PENDING) or PRESENT_CARD in (now.get("requiredActions") or []):
            raise RuntimeError("%s: the link request is still there after the cancel" % name)
        return "cancelled", "%s: link request cancelled (no card was bound; the present-card step is no longer asked)" % name
    admin = is_admin(kc, u["id"])
    if admin:
        if not a.allow_admin:
            raise LinkRefused("%s is an IdP administrator: a card is an administrator's strongest sign-in. If that is "
                              "intended: link-cac %s --allow-admin --edipi (only the card you verified binds, and only when "
                              "its holder presents it)" % (name, name))
        if mode == "bind":
            raise LinkRefused("never a direct bind on an IdP administrator, even with --allow-admin: its holder presents "
                              "the card (--allow-admin --edipi)")
        if mode == "present":
            raise LinkRefused("an IdP administrator gets only the card you name: --allow-admin --edipi")
    if card and not a.replace:
        raise LinkRefused("%s already has a card (%s): --replace removes it (and ends the account's sessions) before the "
                          "new one is requested or bound" % (name, mask_edipi(card)))
    if pend and not link and not a.replace:
        raise LinkRefused("%s carries a card its invite named, not presented yet (%s): wait for it, or --replace drops it"
                          % (name, mask_edipi(pend)))
    if mode in ("present", "reserve"):
        creds = {c.get("type") for c in kc.api("GET", "/users/%s/credentials" % u["id"]) or []}
        if "password" not in creds and not first("entra_oid"):
            raise LinkRefused("%s has no password and no Entra binding, so it cannot sign in to present a card: send-setup "
                              "%s first, or - only if the person cannot present a card - --bind-edipi" % (name, name))
        mapped = x509_card_attribute(kc)
        if mapped != CARD_ATTR:
            raise LinkRefused("the browser flow's X.509 step(s) must exist, be configured identically and map cards by %s "
                              "(found: %s): a bound card would open nothing" % (CARD_ATTR, mapped or "none or several"))
        declared = {x["name"] for x in kc.api("GET", "/users/profile").get("attributes") or []}
        if not {CARD_LINK, CARD_PENDING} <= declared:
            raise LinkRefused("the user profile does not declare %s: run idp-admin.py roles-setup first"
                              % " and ".join(sorted({CARD_LINK, CARD_PENDING} - declared)))
    edipi = None
    if mode in ("reserve", "bind"):
        try:
            edipi = read_edipi("of %s's card" % name)
        except LinkRefused:
            st["card"] = "invalid"; raise
        st["card"] = mask_edipi(edipi)
        others = {i: n for i, n in card_holders(kc, edipi).items() if i != u["id"]}
        if others:
            raise LinkRefused("card %s is already bound to or reserved for another account (%s): one card, one account"
                              % (mask_edipi(edipi), ", ".join(sorted(str(n) for n in others.values()))))
    step = ensure_present_card_step(kc) if mode != "bind" else ""
    removed = bool(card) and a.replace
    if mode == "bind":
        set_ = {CARD_ATTR: edipi}
    else:
        # "<ms> admin" records that the account was an IdP administrator when asked: the present-card step then binds
        # only a named card, even if the account is no administrator by the time it is presented
        set_ = {CARD_LINK: str(now_ms()) + (" admin" if admin else "")}
        if edipi:
            set_[CARD_PENDING] = edipi
    drop = [k for k, v in ((CARD_PENDING, pend), (CARD_LINK, link), (CARD_ATTR, card if a.replace else "")) if v and k not in set_]
    # written server-side (stig-bindings): the admin event shows the card masked, never the full EDIPI
    bindings_link(kc, u["id"], set_=set_, remove=drop, present="remove" if mode == "bind" else "add",
                  reason="link-cac %s%s" % (mode, " replace" if a.replace else ""))
    if removed:
        kc.api("POST", "/users/%s/logout" % u["id"])          # whoever signed in with the removed card is signed out
    now = kc.api("GET", "/users/%s" % u["id"]); nat = now.get("attributes") or {}
    got = lambda k: ((nat.get(k) or [""])[0] or "").strip()
    if mode == "bind":
        ok = got(CARD_ATTR) == edipi and not got(CARD_LINK) and not got(CARD_PENDING)
    else:
        ok = bool(got(CARD_LINK)) and got(CARD_PENDING) == (edipi or "") and PRESENT_CARD in (now.get("requiredActions") or []) \
            and (not a.replace or not got(CARD_ATTR))
    if not ok:
        raise RuntimeError("%s: the account does not read back as requested (is %s declared in the user profile? roles-setup)"
                           % (name, CARD_LINK if mode != "bind" else CARD_ATTR))
    notes = []
    if removed:
        notes.append("its previous card %s removed and its sessions ended" % mask_edipi(card))
    if link and mode != "bind":
        notes.append("replaces its earlier link request")
    if step:
        notes.append("the present-card step was %s" % step)
    tail = (" (%s)" % "; ".join(notes)) if notes else ""
    if mode == "bind":
        return "bound", "%s: card %s bound NOW, without its holder presenting it%s" % (name, mask_edipi(edipi), tail)
    which = "only card %s binds" % mask_edipi(edipi) if edipi else "the card they present binds"
    return "requested", ("%s: at the next sign-in (password + OTP, or Entra) the holder is asked to present their CAC; %s. "
                         "Live %d days; then it is ignored (guard reports it)%s" % (name, which, CARD_LINK_DAYS, tail))

def bindings_link(kc, uid, **kw):
    """write_bindings for link-cac: a conflict or an image without the endpoint is a refusal (nothing written)."""
    try:
        write_bindings(kc, uid, **kw)
    except BindingConflict as e:
        raise LinkRefused("the IdP refused it: %s (one card, one account)" % e)
    except NoBindingsEndpoint as e:
        raise LinkRefused("%s: link-cac needs it" % e)

def cancel_all_links(a):
    """link-cac --cancel-all: withdraw EVERY pending link request at once (the realm-wide stop). One audit line per
    account and one for the run."""
    kc = KC(); n = 0
    for u in paged(kc, "/users?briefRepresentation=false"):
        at = u.get("attributes") or {}
        if not (at.get(CARD_LINK) or [""])[0]:
            continue
        try:
            write_bindings(kc, u["id"], remove=[k for k in (CARD_LINK, CARD_PENDING) if (at.get(k) or [""])[0]],
                           present="remove", reason="link-cac cancel-all")
            res, n = "cancelled", n + 1
        except (BindingConflict, NoBindingsEndpoint, RuntimeError) as e:
            res = "error reason=%s" % json.dumps(mask_digits(clean(str(e), 200)))
        CARD_AUDIT("STIG-LINK-CAC user=%s mode=cancel-all card=- replace=no allow_admin=no operator=%s result=%s"
                   % (clean(u["username"], 100).replace(" ", "_"), clean(operator(), 64), res))
        print("%s: %s" % (u["username"], res.split(" ")[0]))
    CARD_AUDIT("STIG-LINK-CAC user=* mode=cancel-all card=- replace=no allow_admin=no operator=%s result=done cancelled=%d"
               % (clean(operator(), 64), n))
    print("cancel-all: %d link request(s) cancelled" % n)

def card_links(kc, now_ms_=None):
    """(expired, pending) lines for link-cac requests (stig_card_link) never completed. Live for 7 days from the request;
    after that the present-card step ignores it: REPORT the leftover (exit 2) for the operator to cancel or renew."""
    now_ = now_ms_ or int(time.time() * 1000)
    expired, pending = [], []
    for u in paged(kc, "/users?briefRepresentation=false"):
        at = u.get("attributes") or {}
        v = ((at.get(CARD_LINK) or [""])[0] or "").strip()
        if not v:
            continue
        named = "a named card" if (at.get(CARD_PENDING) or [""])[0] else "any card"
        t_ = v.split()[0] if re.fullmatch(r"[0-9]{1,15}( admin)?", v) else ""
        age = (now_ - int(t_)) / 86_400_000 if t_ else None
        if age is None or age > CARD_LINK_DAYS or age < -1 / 288:
            expired.append("STIG-CARD-LINK-EXPIRED user=%s: its link request (link-cac, %s) was not completed in %d days (%s); "
                           "it is ignored - link-cac %s --cancel, or request again" % (
                               u["username"], named, CARD_LINK_DAYS, "%.1f days" % age if age is not None else "time unreadable",
                               u["username"]))
        else:
            pending.append("info  CARD-LINK-PENDING user=%s: asked to present %s at the next sign-in (%.1f of %d days)"
                           % (u["username"], named, age, CARD_LINK_DAYS))
    return expired, pending

def cmd_client_secret(a):
    kc = KC(); sys.stdout.write(kc.api("GET", "/clients/%s/client-secret" % client_uuid(kc, a.client))["value"])

def cmd_entra_amr(a):
    """Show the amr claim Entra sent at a user's last Entra sign-in ("mfa" among them means Entra performed MFA)."""
    kc = KC(); u = kc.api("GET", "/users/%s" % user(kc, a.username)["id"])
    links = [l["identityProvider"] for l in kc.api("GET", "/users/%s/federated-identity" % u["id"]) or []]
    amr = (u.get("attributes") or {}).get("entra_amr")
    print("%s: linked=%s entra_amr=%s -> %s" % (a.username, links, amr,
          "MFA performed" if amr and "mfa" in amr else ("no MFA in amr" if amr else "no amr recorded (no Entra sign-in since the mapper, or Entra sent none)")))

def cmd_user_logout(a):
    """End every session of the user at the IdP; Keycloak sends back-channel logout to each client that has it."""
    kc = KC(); kc.api("POST", "/users/%s/logout" % user(kc, a.username)["id"]); print("logged out", a.username)

def cmd_user_enable(a):
    kc = KC(); u = user(kc, a.username); u["enabled"] = a.enabled == "true"
    held = ((load_state() or new_state()).get("guard_disabled") or {}).get(u["id"])
    if u["enabled"] and held:
        sys.exit("REFUSED: the guard disabled %s (%s, %s): run reset-user (or a grant/promote that passes its checks) "
                 "first" % (a.username, held.get("why"), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(held.get("at", 0) / 1000))))
    put_user(kc, u["id"], {"enabled": u["enabled"]}); print("%s enabled=%s" % (a.username, u["enabled"]))

def cmd_user_delete(a):
    kc = KC(); u = user(kc, a.username); kc.api("DELETE", "/users/%s" % u["id"]); allowlist_drop(u["id"], kc); print("deleted", a.username)

def paged(kc, path, page=100):
    """Every item of a paginated admin list (first/max), however many there are."""
    out, first = [], 0
    while True:
        sep = "&" if "?" in path else "?"
        batch = kc.api("GET", "%s%sfirst=%d&max=%d" % (path, sep, first, page)) or []
        out += batch
        if len(batch) < page:
            return out
        first += page

def delegation_reasons(kc, u):
    """Why a fine-grained (FGAP v2) delegate could manage this account; empty when none can. Fails closed: any API
    error aborts the command (KC.api exits), and a permission whose resources cannot be resolved counts as covering
    the account. Covered: a Users permission naming it or ALL users (empty resources), a Groups permission on ALL
    groups or on one of its groups or their ancestors."""
    ap = kc.api("GET", "/clients?clientId=admin-permissions") or []
    if not ap:
        return []
    base = "/clients/%s/authz/resource-server" % ap[0]["id"]
    mine = {g["id"]: g["path"] for g in paged(kc, "/users/%s/groups" % u["id"])}
    ancestors = set()
    for path in mine.values():
        parts = path.strip("/").split("/")
        ancestors |= {"/" + "/".join(parts[:i]) for i in range(1, len(parts) + 1)}
    reasons = []
    for p in paged(kc, base + "/permission"):
        rtype = p.get("resourceType")
        if rtype not in ("Users", "Groups"):
            continue
        if p["name"] == ADMIN_PROTECTION and rtype == "Users":
            pols = kc.api("GET", base + "/policy/%s/associatedPolicies" % p["id"]) or []
            if [(x["name"], x.get("logic")) for x in pols] == [(ADMIN_POLICY, "POSITIVE")]:
                continue                      # the guard's own permission: only /roles/idp-admin satisfies it
        res = [r["name"] for r in kc.api("GET", base + "/permission/%s/resources" % p["id"]) or []]
        if not res:
            reasons.append("%r covers ALL %s" % (p["name"], rtype.lower())); continue
        if rtype == "Users" and u["id"] in res:
            reasons.append("%r names this user" % p["name"]); continue
        if rtype == "Groups":
            for gid in res:
                g = kc.api("GET", "/groups/%s" % gid, ok404=True)
                if g is None or g.get("path") in ancestors:
                    reasons.append("%r covers group %s" % (p["name"], g["path"] if g else gid)); break
    return reasons

# ------------------------------------------------------------------ promotion to administrator
# A delegate (user manager, an application's service account) may manage application members: change e-mail, send
# execute-actions mail, reset passwords, delete credentials, POST federated-identity, even pre-create first.last. So a
# member's password, OTP, identity-provider link or e-mail cannot be trusted for an administrator unless nobody but
# an administrator ever changed the account. Every admin-API change is an admin event (enabled, with details, never
# expired here), which is how "nobody but an administrator" is proved.

def now_ms():
    return int(time.time() * 1000)

def _write_json(path, obj):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
    os.replace(tmp, path)

def load_state():
    try:
        st = json.load(open(STATE))
    except FileNotFoundError:
        return None
    for k in ("known_admins", "vetted", "log_scan_ms"):      # retired (event-history provenance)
        st.pop(k, None)
    st.setdefault("vetted_at", {})
    st.setdefault("reset_at", {}); st.setdefault("pending", {})
    return st

def save_state(st):
    """Write the state. `vetted_at` is MERGED with what is on disk (latest per account): a caller holding an older copy
    of the state (grant loads it before allowlist_put records the vetting) must never erase when an account was vetted -
    without it, a vetted account would look never vetted."""
    cur = load_state() or {}
    va = dict(st.get("vetted_at") or {})
    for k, v in (cur.get("vetted_at") or {}).items():
        va[k] = max(int(v), int(va.get(k, 0)))
    st["vetted_at"] = va
    _write_json(STATE, st)

def new_state():
    return {"reset_at": {}, "pending": {}}

def load_allowlist():
    """{uid: {username, roles (/roles groups granted), rm_roles (effective realm-management roles granted), granted_at,
    operator}}. A missing file is "nobody vetted" only where nothing is published either (a fresh install); while the
    published allowlist still names administrators the guard stops and alerts instead (guard_preflight)."""
    try:
        return json.load(open(ALLOWLIST))
    except FileNotFoundError:
        return {}

def operator():
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"

ALLOWLIST_ATTR = "stig.admin-allowlist.%s" % REALM     # master-realm attribute read by stig-extensions at sign-in
# ... and, per vetted id, the realm-management roles its entry permits (effective names): the gate refuses an account
# holding any role beyond them. "<id>=<role>,<role>;<id>=..."; an unreadable value refuses every administrator.
ALLOWLIST_ROLES_ATTR = "stig.admin-allowlist-roles.%s" % REALM

def publish_allowlist(kc, al=None):
    """The vetted ids, for stig-extensions' sign-in checks, as a MASTER-realm attribute (only the master realm - this
    tooling, break-glass - can write it; the realm's own administrators cannot). Verified by reading it back."""
    al = al if al is not None else load_allowlist()
    ids = ",".join(sorted(al.keys()))
    # Grant-level entries (group:<path>, expanded by the gate at check time) once the deployed gate reads them
    # (marker >= 2); before that, the expanded role names the older gate compares against.
    gv = gate_version(kc)
    if gv is None:
        raise RuntimeError("the deployed gate's capability marker cannot be read: not publishing the allowlist (retry)")
    grant_level = gv >= GATE_GRANT_ENTRIES
    items = {}
    for uid, e in al.items():
        e = dict(e); migrate_entry(kc, e)
        it = entry_items(e) if grant_level else sorted(set().union(*[set(g["roles"]) for g in e["grants"]])) if e.get("grants") else list(e.get("rm_roles") or [])
        bad = [r for r in it if not r or any(c in r for c in ",;=")]
        if grant_level and any(not g.get("roles") for g in e.get("grants") or []):
            bad.append("a grant with no realm-management roles")
        if not it or bad:
            raise RuntimeError("allowlist entry %s has nothing publishable (%s)" % (e.get("username"), bad or it))
        items[uid] = sorted(it)
    roles = ";".join("%s=%s" % (uid, ",".join(items[uid])) for uid in sorted(al))
    want = {ALLOWLIST_ATTR: ids, ALLOWLIST_ROLES_ATTR: roles}
    st, d = kc.req("GET", "/admin/realms/master")
    if st != 200:
        raise RuntimeError("cannot read the master realm: HTTP %s" % st)
    attrs = json.loads(d).get("attributes") or {}
    if any(attrs.get(k) != v for k, v in want.items()):
        attrs.update(want)
        st, d = kc.req("PUT", "/admin/realms/master", json.dumps({"attributes": attrs}).encode(), {"Content-Type": "application/json"})
        if st not in (200, 204):
            raise RuntimeError("cannot publish the allowlist: HTTP %s %s" % (st, d[:200]))
        st, d = kc.req("GET", "/admin/realms/master")
        got = json.loads(d).get("attributes") or {}
        if any(got.get(k) != v for k, v in want.items()):
            raise RuntimeError("the published allowlist does not read back")
        return True
    return False

def allowlist_put(kc, u, roles, rm=None, grants=None):
    al = load_allowlist()
    al[u["id"]] = {"username": u["username"], "roles": sorted(set(roles)), "rm_roles": sorted(rm if rm is not None else rm_roles(kc, u["id"])),
                   "grants": grants if grants is not None else make_grants(kc, [r for r in roles if r.startswith("/")]),
                   "granted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "operator": operator()}
    _write_json(ALLOWLIST, al)
    publish_allowlist(kc, al)
    st = load_state() or new_state(); st.setdefault("vetted_at", {})[u["id"]] = now_ms(); save_state(st)
    return al[u["id"]]

def allowlist_drop(uid, kc=None):
    """Off the allowlist: published at once, and the account's sessions ended (Keycloak's logout also sets not-before,
    which invalidates every refresh and offline token issued until now)."""
    al = load_allowlist()
    if al.pop(uid, None) is not None:
        _write_json(ALLOWLIST, al)
    if kc is not None:
        publish_allowlist(kc, al)
        if kc.api("GET", "/users/%s" % uid, ok404=True) is not None:
            kc.api("POST", "/users/%s/logout" % uid)

def group_live(kc, gid, cache=None):
    """A granted group's realm-management roles NOW (its own and its parents', composites expanded), by group id;
    None when the id no longer exists."""
    if cache is not None and gid in cache:
        return cache[gid]
    out = None
    if UUID.match(gid or "") and kc.api("GET", "/groups/%s" % gid, ok404=True):
        rmc = client_uuid(kc, "realm-management")
        out = {r["name"] for r in kc.api("GET", "/groups/%s/role-mappings/clients/%s/composite" % (gid, rmc)) or []}
    if cache is not None:
        cache[gid] = out
    return out

def make_grants(kc, paths, cache=None):
    """[{id, path, roles}] for granted /roles groups: the group by ID and a snapshot of what it carries now."""
    out = []
    for p_ in sorted(set(paths)):
        g = group_by_path(kc, p_) or sys.exit("no group %s (run roles-setup)" % p_)
        out.append({"id": g["id"], "path": p_, "roles": sorted(group_live(kc, g["id"], cache) or [])})
    return out

def migrate_entry(kc, e):
    """An entry written before grant snapshots existed: its /roles paths become groups by id, each snapshot being what
    the group carries now AND the entry recorded (never wider than what was vetted). Returns True if it changed."""
    if e.get("grants"):
        return False
    rec = set(e.get("rm_roles") or [])
    gr = []
    for p_ in [x for x in e.get("roles") or [] if isinstance(x, str) and x.startswith("/")]:
        g = group_by_path(kc, p_)
        if g:
            gr.append({"id": g["id"], "path": p_, "roles": sorted((group_live(kc, g["id"]) or set()) & rec)})
    e["grants"] = gr
    return True

def entry_items(e):
    """What the gate reads for an entry: group:<id>@<role>+<role> per grant; an entry without grants gives its
    recorded role names (the older format)."""
    if e.get("grants"):
        return ["group:%s@%s" % (g["id"], "+".join(g["roles"])) for g in e["grants"]]
    return list(e.get("rm_roles") or [])

VETTED, NOT_LISTED, OVER_ENTRY, NEEDS_REGRANT = "vetted", "not-listed", "over-entry", "needs-regrant"

def effective_standing(standing, gate_ver):
    """NEEDS_REGRANT is availability-safe only where the deployed gate itself refuses the account for it (marker >= 2,
    grant entries); with an older or unconfirmed gate the account is handled as over-entry."""
    return OVER_ENTRY if standing == NEEDS_REGRANT and gate_ver < GATE_GRANT_ENTRIES else standing

def classify(effective, items, live):
    """The gate's own classification (stig-extensions StigAdministrators.classify), item for item: within the grant
    snapshots -> vetted (a granted group gone -> needs-regrant); beyond them only by roles the granted groups carry NOW
    (a composite or group changed after the grant) -> needs-regrant; beyond even that -> over-entry; no entry or an
    unreadable item -> not-listed. `live(group id)` -> that group's roles now, or None if the id is gone."""
    if not items:
        return NOT_LISTED
    snap, now, missing = set(), set(), False
    for it in items:
        if it.startswith("group:"):
            rest = it[6:]
            if rest.count("@") != 1 or rest.index("@") == 0:
                return NOT_LISTED
            gid, roles = rest.split("@")
            snap |= {r.strip() for r in roles.split("+") if r.strip()}
            l = live(gid)
            if l is None:
                missing = True
            else:
                now |= l
        elif any(c in it for c in ":@+"):
            return NOT_LISTED
        else:
            snap.add(it); now.add(it)
    extra = set(effective) - snap
    if not extra:
        return NEEDS_REGRANT if missing else VETTED
    return NEEDS_REGRANT if extra <= now else OVER_ENTRY

def rm_roles(kc, uid):
    """The realm-management roles this account holds EFFECTIVELY: direct, composite, group, ancestor group."""
    rmc = client_uuid(kc, "realm-management")
    return {r["name"] for r in kc.api("GET", "/users/%s/role-mappings/clients/%s/composite" % (uid, rmc)) or []}

def all_accounts(kc):
    """Every account of the realm INCLUDING clients' service-account users, which Keycloak's /users listing leaves out."""
    seen, out = set(), []
    for u in paged(kc, "/users?briefRepresentation=true"):
        if u["id"] not in seen:
            seen.add(u["id"]); out.append(u)
    for c in paged(kc, "/clients"):
        if c.get("serviceAccountsEnabled"):
            sa = kc.api("GET", "/clients/%s/service-account-user" % c["id"], ok404=True)
            if sa and sa["id"] not in seen:
                seen.add(sa["id"]); out.append(sa)
    return out

def rm_holders(kc):
    """uid -> (username, effective realm-management roles) for every account holding any, by any route."""
    out = {}
    for u in all_accounts(kc):
        held = rm_roles(kc, u["id"])
        if held:
            out[u["id"]] = (u["username"], held)
    return out

def master_realm_id(kc):
    if not hasattr(kc, "_master_id"):
        st, d = kc.req("GET", "/admin/realms/master")
        if st != 200:
            sys.exit("cannot read the master realm: HTTP %s" % st)
        kc._master_id = json.loads(d)["id"]
    return kc._master_id

def operator_actor(kc, auth):
    """Only the operator's tooling (the master realm: idp-admin.py's automation account, break-glass - unreachable
    from the network) counts as having set an account's credentials, links or e-mail."""
    return auth.get("realmId") == master_realm_id(kc)

def admin_events(kc, query):
    out, first = [], 0
    while True:
        page = kc.api("GET", "/admin-events?%s&first=%d&max=200" % (query, first)) or []
        out += page
        if len(page) < 200:
            return out
        first += 200

def user_events(kc, uid):
    """This account's own admin events, oldest first."""
    return sorted(admin_events(kc, "resourcePath=%s" % q("users/%s*" % uid)), key=lambda e: e.get("time", 0))

def events_complete(kc, created_ms):
    """True only when the realm's admin events can prove an account's whole history: recorded, with representations,
    and either never expiring or the account younger than their retention."""
    if not hasattr(kc, "_ev_cfg"):
        kc._ev_cfg = kc.api("GET", "/events/config") or {}
    cfg = kc._ev_cfg
    if not cfg.get("adminEventsEnabled") or not cfg.get("adminEventsDetailsEnabled"):
        return False
    exp = cfg.get("adminEventsExpiration")
    return not exp or (created_ms is not None and created_ms >= (time.time() - int(exp)) * 1000)

def binding_provenance(kc, uid, events=None, current=None, created_ms=None):
    """{binding: True (set by the operator's tooling) | False (set by someone else) | None (unknown)} for each identity
    binding the account holds now: the admin event that introduced its CURRENT value decides (representations of the
    account's create/update events, oldest first). When the admin events cannot prove the history (not recorded, no
    representations, or older than their retention), every binding is None (unknown)."""
    if current is None:
        u_ = kc.api("GET", "/users/%s" % uid)
        current, created_ms = u_.get("attributes") or {}, u_.get("createdTimestamp")
    if not events_complete(kc, created_ms):
        return {b: None for b in IDENTITY_BINDINGS if current.get(b)}
    events = user_events(kc, uid) if events is None else events
    last, who = {b: None for b in IDENTITY_BINDINGS}, {b: None for b in IDENTITY_BINDINGS}
    for e in events:
        if e.get("resourcePath") != "users/%s" % uid or e.get("operationType") not in ("CREATE", "UPDATE"):
            continue
        try:
            r = json.loads(e.get("representation") or "null")
        except ValueError:
            continue
        if not isinstance(r, dict):
            continue
        sb = r.get("stigBindings")
        if isinstance(sb, dict):            # stig-bindings (this tooling): the card masked, the object id as it is
            for b in IDENTITY_BINDINGS:
                if b in sb:
                    v = None if sb[b] is None else (("masked", sb[b]) if b == "cac_edipi" else (sb[b],))
                    if v != last[b]:
                        last[b], who[b] = v, operator_actor(kc, e.get("authDetails") or {})
            continue
        if str(r.get("stig") or "").startswith("card bound"):      # the present-card step: bound by its holder
            last["cac_edipi"], who["cac_edipi"] = ("masked", r.get("card")), None
            continue
        if "attributes" not in r:
            continue
        for b in IDENTITY_BINDINGS:
            v = tuple((r.get("attributes") or {}).get(b) or ()) or None
            if v != last[b]:
                last[b], who[b] = v, operator_actor(kc, e.get("authDetails") or {})
    def now_(b):
        vals = tuple(current.get(b) or ())
        return ("masked", mask_edipi(vals[0])) if vals and isinstance(last[b], tuple) and last[b][:1] == ("masked",) else vals
    return {b: (who[b] if last[b] == now_(b) else None) for b in IDENTITY_BINDINGS if current.get(b)}

def nonoperator_bindings(kc, uid, **kw):
    """The identity bindings the account holds now that someone OTHER than the operator's tooling set."""
    return sorted(b for b, op in binding_provenance(kc, uid, **kw).items() if op is False)

def untrusted_bindings(kc, uid, **kw):
    """The identity bindings the account holds now that are NOT proven to be the operator's (someone else set them, or
    their provenance is unknown). They block promotion, the release of a hold and the factor-reset point - never more:
    nothing is contained or disabled for them."""
    return sorted(b for b, op in binding_provenance(kc, uid, **kw).items() if op is not True)

def binding_gate(kc, u, clear):
    """At promotion, after any reset: refuse while an identity binding not proven to be the operator's remains, unless
    the operator asked to clear them (--clear-bindings). Returns the bindings cleared."""
    nb = untrusted_bindings(kc, u["id"])
    if not nb:
        return []
    if not clear:
        sys.exit("REFUSED: %s holds identity binding(s) %s not proven to be set by the operator's tooling; after review re-run "
                 "with --clear-bindings (then bind it again: user-create-cac --existing / link-entra)" % (u["username"], nb))
    gone = clear_bindings(kc, u)
    if untrusted_bindings(kc, u["id"]):
        raise RuntimeError("%s: identity bindings still not trusted after clearing" % u["username"])
    return gone

def promotion_risks(kc, u, st, since=0):
    """Why this account's factors, links or e-mail cannot be trusted for an administrator; empty when they can. Reads
    the admin events of THIS account only, at grant time: any change by anyone but the operator's tooling counts (no
    representation matching). `since` (ms): changes before a recorded factor reset no longer count."""
    reasons = []
    for e in admin_events(kc, "resourcePath=%s" % q("users/%s*" % u["id"])):
        if e.get("time", 0) < since:
            continue
        if not operator_actor(kc, e.get("authDetails") or {}):
            ad = e.get("authDetails") or {}
            reasons.append("%s %s by a non-administrator (realm %s, user %s) at %s" % (
                e.get("operationType"), e.get("resourcePath"), (ad.get("realmId") or "?")[:8], (ad.get("userId") or "?")[:8],
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e.get("time", 0) / 1000))))
    cfg = kc.api("GET", "/events/config")
    exp = cfg.get("adminEventsExpiration")
    if not cfg.get("adminEventsEnabled") or not cfg.get("adminEventsDetailsEnabled"):
        reasons.append("admin events are not fully recorded, so who changed this account cannot be proved")
    elif exp and u.get("createdTimestamp", 0) < (time.time() - int(exp)) * 1000 and since < (time.time() - int(exp)) * 1000:
        reasons.append("the account is older than the admin-event retention (%ss), so its history cannot be proved" % exp)
    # A link signs in only when the provider vouches for the admin-set entra_oid (idp-require-admin-attribute-match,
    # post broker login); Entra's link id is its pairwise `sub`, not the oid, so links are judged by that rule and by
    # provenance (an admin-API link is an admin event above): one to another provider, or with no entra_oid, is not.
    # an identity binding someone other than the tooling set is a risk whatever reset_at says (a reset never clears it)
    for b in untrusted_bindings(kc, u["id"]):
        reasons.append("identity binding %s is not proven to be set by the operator's tooling" % b)
    oid = ((u.get("attributes") or {}).get("entra_oid") or [None])[0]
    for l in kc.api("GET", "/users/%s/federated-identity" % u["id"]) or []:
        if l.get("identityProvider") != "entra" or not oid:
            reasons.append("identity-provider link %s without an administrator-set entra_oid" % l.get("identityProvider"))
    return reasons

def reset_factors(kc, u, why):
    """Remove every password, OTP and WebAuthn credential and every identity-provider link, clear pending required
    actions, end all sessions; clear an e-mail a non-administrator may have set. The card mapping (admin-only) stays."""
    gone = []
    for c in kc.api("GET", "/users/%s/credentials" % u["id"]) or []:
        kc.api("DELETE", "/users/%s/credentials/%s" % (u["id"], c["id"])); gone.append(c.get("type"))
    for l in kc.api("GET", "/users/%s/federated-identity" % u["id"]) or []:
        kc.api("DELETE", "/users/%s/federated-identity/%s" % (u["id"], q(l["identityProvider"]))); gone.append("link:" + l["identityProvider"])
    rep = kc.api("GET", "/users/%s" % u["id"])
    rep["requiredActions"] = []
    # The e-mail is where set-up and credential links go. Nothing proves who last set it (a delegate's change can be
    # followed by others), so a reset always clears it; the operator sets it again explicitly (rename --email).
    if rep.get("email"):
        gone.append("email")
    rep["email"], rep["emailVerified"] = "", False          # "" clears it; None would mean "unchanged"
    put_user(kc, u["id"], {"requiredActions": [], "email": rep["email"], "emailVerified": False})
    kc.api("POST", "/users/%s/logout" % u["id"])
    if kc.api("GET", "/users/%s" % u["id"]).get("email"):
        raise RuntimeError("factor reset of %s: the e-mail address is still set" % u["username"])
    left = [c.get("type") for c in kc.api("GET", "/users/%s/credentials" % u["id"]) or []] + \
           [l["identityProvider"] for l in kc.api("GET", "/users/%s/federated-identity" % u["id"]) or []]
    if left:
        raise RuntimeError("factor reset of %s incomplete: %s remain" % (u["username"], left))
    return gone

def is_service_account(kc, u):
    """The account IS the service account of a client (that client's service-account user has this very id)."""
    name = u.get("username") or ""
    if not name.startswith("service-account-"):
        return False
    c = kc.api("GET", "/clients?clientId=%s" % q(name[len("service-account-"):])) or []
    if not c or not c[0].get("serviceAccountsEnabled"):
        return False
    sa = kc.api("GET", "/clients/%s/service-account-user" % c[0]["id"], ok404=True)
    return bool(sa) and sa.get("id") == u["id"]

def strong_path(kc, u):
    """How an administrator can sign in without a factor anyone else set: a card mapping (admin-only attribute), or
    an OTP/WebAuthn credential enrolled with no untrusted change since."""
    if (u.get("attributes") or {}).get("cac_edipi") and binding_provenance(kc, u["id"]).get("cac_edipi") is True:
        return "card"                # only a card mapping the operator's tooling set
    if is_service_account(kc, u):
        return None                  # never an administrator
    types = {c.get("type") for c in kc.api("GET", "/users/%s/credentials" % u["id"]) or []}
    if types & {"otp", "webauthn"}:
        return "otp"
    return None

def cmd_user_create_cac(a):
    """Create a card holder, or add a role to an EXISTING one only when it is provably the same person: its
    cac_edipi equals the requested EDIPI and it has no identity-provider link. Anything else is refused."""
    kc = KC()
    if not (a.edipi.isdigit() and len(a.edipi) == 10):
        sys.exit("EDIPI must be the 10 digits at the end of the card's CN")
    taken = [u for u in kc.api("GET", "/users?q=%s&exact=true" % q("cac_edipi:" + a.edipi)) or [] if u["username"] != a.username]
    if taken:
        sys.exit("REFUSED: EDIPI already mapped to another account (%s); one card, one account" % taken[0]["username"])
    found = kc.api("GET", "/users?exact=true&username=%s" % q(a.username))
    if found:
        u = kc.api("GET", "/users/%s" % found[0]["id"])
        have = (u.get("attributes") or {}).get("cac_edipi", [])
        links = kc.api("GET", "/users/%s/federated-identity" % u["id"]) or []
        if have != [a.edipi]:
            sys.exit("REFUSED: %s exists with a different or no EDIPI; not the same person as requested" % a.username)
        if links:
            sys.exit("REFUSED: %s exists and is linked to %s; resolve that link first" % (a.username, [l["identityProvider"] for l in links]))
        reasons = delegation_reasons(kc, u)
        if reasons:
            sys.exit("REFUSED: %s can be managed by a delegated administrator (%s), so it is not provably the same "
                     "person; resolve that first" % (a.username, "; ".join(reasons)))
        creds = [c.get("type") for c in kc.api("GET", "/users/%s/credentials" % u["id"]) or []]
        if creds and not a.accept_credentials:
            sys.exit("REFUSED: %s carries credentials %s that someone other than the card holder may have set; "
                     "check them, then re-run with --accept-credentials" % (a.username, creds))
        if not a.existing:
            sys.exit("REFUSED: %s exists (same EDIPI, no links); re-run with --existing to add the role to it" % a.username)
        outcome = "updated"
    else:
        kc.api("POST", "/users", {"username": a.username, "email": a.email, "firstName": a.first, "lastName": a.last,
                                  "enabled": True, "emailVerified": True})
        u = user(kc, a.username); outcome = "created"
        try:                 # the card server-side (stig-bindings): the admin event never holds the full EDIPI
            bindings_or_put(kc, u["id"], set_={"cac_edipi": a.edipi}, reason="user-create-cac")
        except BindingConflict as e:
            kc.api("DELETE", "/users/%s" % u["id"])
            sys.exit("REFUSED: %s (the new account was removed again)" % e)
    cid, role = a.role.split(":", 1); cu = client_uuid(kc, cid)
    kc.api("POST", "/users/%s/role-mappings/clients/%s" % (u["id"], cu), [kc.api("GET", "/clients/%s/roles/%s" % (cu, q(role)))])
    print("%s: %s (cac_edipi verified, no identity-provider link), role %s:%s" % (outcome, a.username, cid, role))

def cmd_user_create_pw(a):
    kc = KC()
    pw = open(a.temp_password_file).read().strip()
    if kc.api("GET", "/users?exact=true&username=%s" % q(a.username)):
        sys.exit("REFUSED: %s already exists; a password account is only ever created new" % a.username)
    kc.api("POST", "/users", {"username": a.username, "email": a.email, "firstName": a.first, "lastName": a.last,
                              "enabled": True, "attributes": {"account_type": ["temporary"]},
                              "credentials": [{"type": "password", "value": pw, "temporary": a.temporary}]})
    u = user(kc, a.username)
    cid, role = a.role.split(":", 1); cu = client_uuid(kc, cid)
    r = kc.api("GET", "/clients/%s/roles/%s" % (cu, q(role)))
    kc.api("POST", "/users/%s/role-mappings/clients/%s" % (u["id"], cu), [r])
    print("created: %s (%s:%s, account_type=temporary, temporary password=%s)" % (a.username, cid, role, a.temporary))

# ------------------------------------------------------------------------------------------- client files (add-client)
# Every Keycloak start re-applies /srv/idp/clients/*.json through the image's kcstig (client_rep + upsert_client), over
# the live clients. add-client applies ONE file live through the admin API with that same kcstig - loaded out of the
# RUNNING image, so the two can never render a client differently - verifies the result, and only then installs the
# host file, so a restart keeps exactly what is live. check-clients answers "would a restart change anything?".
CLIENTS_DIR = "/srv/idp/clients"
KCSTIG_IN_IMAGE = "/opt/kcstig"                          # scripts/kcstig.py + references/ (inheritance statement)
KC_PROFILE_IN_IMAGE = "/opt/keycloak/data/cac/profile.json"   # the profile the image's apply renders clients with
REMOTE_ADMIN = "/usr/local/sbin/idp-admin.py"
REPO_CLIENTS = _AC.get("repoClientsDir") or "clients"      # --repo R: the client files are R/<this>
ROLE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")          # used with fullmatch
MAX_URIS = 20
# not managed by client files: Keycloak's own clients and the ones this deployment creates by other means
UNMANAGED_CLIENTS = ("realm-management", "account", "account-console", "security-admin-console", "admin-cli", "broker",
                     "admin-permissions") + DELEGATE_CLIENTS + ONBOARDING_CLIENT_IDS + HANDOFF_CLIENT_IDS
# never registered by add-client: Keycloak's built-ins, the master realm's own clients (<realm>-realm, stig-automation,
# the break-glass client) and this deployment's sensitive clients. Any *-realm id is refused too.
RESERVED_CLIENTS = UNMANAGED_CLIENTS + ("stig-automation", "break-glass-recovery", "master-realm") \
    + (("%s-realm" % REALM,) if REALM else ()) \
    + tuple(ROLE_GROUPS)                       # idp-admin, idp-user-manager, idp-auditor, <app>-user-manager
MANAGED_ATTR, MANAGED_VAL = "stig.created-by", "add-client"   # set on every client add-client creates or adopts; the name upstream kcstig add-client uses (PR #7)
# live clients that pre-date add-client and are managed by their host file: --adopt <id> marks them (once)
_clash = (set(APP_CLIENTS) | set(DELEGATE_CLIENTS)) & (set(RESERVED_CLIENTS) - set(DELEGATE_CLIENTS)) | \
    (set(APP_CLIENTS) & set(UNMANAGED_CLIENTS))
if _clash:
    sys.exit("REFUSED: %s: reserved client id(s) configured as an application or delegate: %s" % (ADMIN_CONFIG_FILE, sorted(_clash)))
OPERATOR_SSH_HOST = _AC.get("operatorSshHost") or "<idp host>"      # only for the hints printed to the operator
ADOPTABLE = tuple(app for app, c in _APPS.items() if c.get("adoptable"))

# The kcstig client keys add-client accepts: confidential OIDC with client-jwt or client-secret. kcstig's other keys
# (SAML, client-x509, public clients, service accounts) need a review this command cannot do: refused, like a typo.
OWNER_KEYS = {"owner", "owner_contact"}       # this IdP's: who asked for the client (kcstig ignores them at a restart)
OWNER_ATTR, OWNER_CONTACT_ATTR = "stig.owner", "stig.owner-contact"
OWNER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")                     # used with fullmatch
ADD_CLIENT_KEYS = OWNER_KEYS | {"client_id", "type", "name", "root_url", "redirect_uris", "post_logout_redirect_uris",
                   "backchannel_logout_url", "web_origins", "auth", "jwks_url", "roles", "privileged", "standard_flow", "par"}

def load_kcstig(src=None, profile=None):
    """(kcstig module, merged profile) - by default copied out of the running Keycloak image, so add-client renders a
    client exactly as the image's next apply will. `src`/`profile` (or IDP_KCSTIG_DIR / IDP_KCSTIG_PROFILE) point at a
    keycloak-asd-stig/keycloak-asd-stig checkout and a profile instead (tests)."""
    if getattr(load_kcstig, "cache", None):
        return load_kcstig.cache
    import atexit, shutil, tempfile
    src = src or os.environ.get("IDP_KCSTIG_DIR")
    profile = profile or os.environ.get("IDP_KCSTIG_PROFILE")
    if not src or not profile:
        tmp = tempfile.mkdtemp(prefix="idp-kcstig-"); atexit.register(shutil.rmtree, tmp, True)
        if not src:
            r = subprocess.run(["docker", "cp", "%s:%s" % (KC_CONTAINER, KCSTIG_IN_IMAGE), tmp], capture_output=True, text=True)
            if r.returncode != 0:
                sys.exit("cannot copy kcstig out of %s: %s" % (KC_CONTAINER, r.stderr.strip()[:300]))
            src = os.path.join(tmp, os.path.basename(KCSTIG_IN_IMAGE))
        if not profile:
            r = subprocess.run(["docker", "exec", KC_CONTAINER, "cat", KC_PROFILE_IN_IMAGE], capture_output=True, text=True)
            if r.returncode != 0:
                sys.exit("cannot read the image's profile %s: %s" % (KC_PROFILE_IN_IMAGE, r.stderr.strip()[:300]))
            profile = os.path.join(tmp, "profile.json")
            fd = os.open(profile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(r.stdout)
    ld = importlib.machinery.SourceFileLoader("kcstig", os.path.join(src, "scripts", "kcstig.py"))
    spec = importlib.util.spec_from_loader("kcstig", ld); ks = importlib.util.module_from_spec(spec); ld.exec_module(ks)
    if not ADD_CLIENT_KEYS - OWNER_KEYS <= set(ks.CLIENT_KEYS):
        sys.exit("the image's kcstig no longer accepts %s: update idp-admin.py before adding clients" % sorted(ADD_CLIENT_KEYS - OWNER_KEYS - set(ks.CLIENT_KEYS)))
    os.environ.pop("STIG_CLIENTS_DIR", None)          # the profile alone: the client under test is rendered on its own
    import contextlib, io
    with contextlib.redirect_stderr(io.StringIO()):    # the image's own profile warnings are not this client's business
        p = ks.load_profile(profile)
    load_kcstig.cache = (ks, p, src, profile)
    return load_kcstig.cache

def _is_ip_literal(h):
    """True for ANY spelling of an IP address: dotted, short (127.1), decimal (2130706433), octal or hex (0x7f.1) IPv4
    - everything inet_aton accepts, which is what resolvers accept - and IPv6 (IPv4-mapped included)."""
    import ipaddress
    h = (h or "").strip("[]").rstrip(".")
    try:
        socket.inet_aton(h); return True
    except (OSError, ValueError):
        pass
    try:
        ipaddress.ip_address(h.split("%", 1)[0]); return True
    except ValueError:
        return False

def _is_local_name(h):
    h = (h or "").lower().rstrip(".")
    return (h == "localhost" or h.startswith("localhost.") or "." not in h
            or h.endswith((".localhost", ".local", ".internal", ".localdomain", ".home.arpa", ".lan")))

FETCHED_BY_KEYCLOAK = ("jwks_url", "backchannel_logout_url")
RESOLVER = None          # tests replace it; default socket.getaddrinfo
RESOLVE_BACKOFF = (2, 5)  # seconds before the 2nd and 3rd try

def resolve_errors(c, resolver=None):
    """For the URLs Keycloak itself fetches (jwks_url, backchannel_logout_url): resolve the name NOW and refuse an
    address that is not public (private, loopback, link-local, reserved, multicast, unspecified; IPv4-mapped IPv6
    unwrapped). A guard against pointing Keycloak at internal services (SSRF), not a guarantee: DNS can change later."""
    import ipaddress
    resolver = resolver or RESOLVER or socket.getaddrinfo
    errs = []
    for k in FETCHED_BY_KEYCLOAK:
        u = c.get(k)
        if not isinstance(u, str):
            continue
        h = urllib.parse.urlsplit(u).hostname
        if not h:
            continue
        addrs, last = None, None
        for wait in (0,) + tuple(RESOLVE_BACKOFF):     # 3 tries: a transient resolver failure is not drift
            if wait:
                time.sleep(wait)
            try:
                addrs = sorted({ai[4][0] for ai in resolver(h, 443, proto=socket.IPPROTO_TCP)}); break
            except (OSError, UnicodeError) as ex:
                last = ex
        if addrs is None:
            errs.append("%s: %s does not resolve (%s, 3 tries) - Keycloak must be able to reach it" % (k, h, last)); continue
        for ad in addrs:
            ip = ipaddress.ip_address(ad.split("%", 1)[0])
            ip = getattr(ip, "ipv4_mapped", None) or ip
            if not ip.is_global or ip.is_multicast or ip.is_reserved or _nat64(ip):
                errs.append("%s: %s resolves to %s, not a public address - Keycloak fetches this URL" % (k, h, ad))
        if not addrs:
            errs.append("%s: %s resolves to nothing" % (k, h))
    return errs

_HERE = os.path.dirname(os.path.realpath(__file__))
VCR_PATHS = [os.environ.get("IDP_VCR") or "", os.path.join(_HERE, "validate-client-request.py"),
             # run from a keycloak-asd-stig checkout: the validator itself, not a copy
             os.path.join(_HERE, "..", "..", "..", "..", "keycloak-rp-integration", "scripts", "validate-client-request.py"),
             "/usr/local/lib/idp/validate-client-request.py"]

def vcr():
    """The PUBLIC client-request validator (keycloak-asd-stig keycloak-rp-integration/scripts/validate-client-request.py),
    used unmodified: from this checkout when run from it, else the copy setup-host.sh installs in /usr/local/lib/idp/
    (or $IDP_VCR). add-client applies ITS URL, host, client_id and reserved-id rules - so what an app team
    validates before sending a request and what the operator registers cannot drift - and adds this IdP's stricter
    ones on top."""
    if getattr(vcr, "mod", None):
        return vcr.mod
    path = next((x for x in VCR_PATHS if x and os.path.exists(x)), None)
    if not path:
        sys.exit("validate-client-request.py is not installed (looked in %s)" % [x for x in VCR_PATHS if x])
    ld = importlib.machinery.SourceFileLoader("validate_client_request", path)
    spec = importlib.util.spec_from_loader("validate_client_request", ld); m = importlib.util.module_from_spec(spec); ld.exec_module(m)
    vcr.mod = m
    return m

def _url_errors(field, u, origin=False, strict=True):
    """The public validator's check_url first (IP literals in every spelling, https, exact URIs, no fragment or
    userinfo, ASCII DNS hosts), always with dev_request off: this is the PRODUCTION IdP, so `localhost` is refused
    outright (its TLS gate and egress rules assume no development client here); then this IdP's additions."""
    V = vcr(); r = V.Result()
    p = V.check_url(r, field, u, False, origin_only=origin)
    if r.errors:
        return r.errors
    errs = ["%s (strict: --lenient to accept)" % w for w in r.warnings] if strict else []
    # (non-ASCII, non-printable and whitespace anywhere in a URL: refused by the public validator itself since 53ae148)
    if "\\" in u:
        errs.append("%s: %r contains a backslash" % (field, u))
    h = (p.hostname or "").rstrip(".").lower()
    if _is_ip_literal(h):                                    # belt and braces: whatever inet_aton/ipaddress accept
        errs.append("%s: %r uses an IP literal - a DNS name is required" % (field, u))
    elif _is_local_name(h):                                  # single-label, .local, .internal, localhost
        errs.append("%s: %r points at a local-only name - not allowed on the production IdP" % (field, u))
    return errs

def validate_client(c, strict=True):
    """Every reason the client file is refused (empty = acceptable). The public validator's rules (vcr()) for URLs,
    hosts, client ids and reserved ids and role names, plus this IdP's: confidential OIDC only, post-logout URIs
    required, localhost and local-only names refused (no development clients on the production IdP), at most
    MAX_URIS URIs per list, case-variant duplicates refused, `name` printable ASCII. Roles keep this IdP's pattern
    (some applications' are UPPER_CASE; the public validator wants lower case) but Keycloak's built-in role names are refused in
    any case. Ids and roles are matched with fullmatch: a trailing newline never passes. Strict (the default): the
    public validator's warnings (a query string in a URI) are errors too, and every redirect, post-logout and
    back-channel URI, web origin and jwks_url must be on root_url's origin, so root_url is required. `owner` / `owner_contact` are optional here (files that pre-date
    them); add-client requires them."""
    V = vcr()
    if not isinstance(c, dict):
        return ["the file must hold exactly ONE client object"]
    errs = ["unknown field %r (accepted: %s)" % (k, ", ".join(sorted(ADD_CLIENT_KEYS))) for k in sorted(set(c) - ADD_CLIENT_KEYS)]
    cid = c.get("client_id")
    if not isinstance(cid, str) or not V.CLIENT_ID_RE.fullmatch(cid):
        errs.append("client_id: %r must match %s" % (cid, V.CLIENT_ID_RE.pattern))
    elif cid in V.RESERVED_CLIENT_IDS or cid in RESERVED_CLIENTS or cid.endswith("-realm"):
        errs.append("client_id: %s is reserved (a built-in, master-realm or platform client): not managed by client files" % cid)
    if c.get("type", "oidc-confidential") != "oidc-confidential":
        errs.append("type: %r - add-client registers confidential OIDC clients only" % c.get("type"))
    if "name" in c and (not isinstance(c["name"], str) or not c["name"].strip() or len(c["name"]) > 100
                        or any(not (0x20 <= ord(ch) <= 0x7e) for ch in c["name"])):
        errs.append("name: must be 1-100 printable ASCII characters (no control or bidi characters)")
    for k in ("privileged", "par"):
        if k in c and not isinstance(c[k], bool):
            errs.append("%s: must be true or false" % k)
    if "standard_flow" in c and c["standard_flow"] is not True:
        errs.append("standard_flow: must be true (the authorization-code flow is the only sign-in flow)")
    def url_list(k, required, origin=False):
        v = c.get(k)
        if v is None:
            if required:
                errs.append("%s: required (a non-empty list of exact https URIs)" % k)
            return
        if not isinstance(v, list) or (required and not v):
            errs.append("%s: must be a %slist" % (k, "non-empty " if required else "")); return
        if len(v) > MAX_URIS:
            errs.append("%s: at most %d entries" % (k, MAX_URIS))
        if len(set(str(x).lower() for x in v)) != len(v):
            errs.append("%s: duplicate entries (compared case-insensitively)" % k)
        for i, u in enumerate(v):
            errs.extend(_url_errors("%s[%d]" % (k, i), u, origin, strict))
    url_list("redirect_uris", True)
    url_list("post_logout_redirect_uris", True)
    url_list("web_origins", False, origin=True)
    for k in ("backchannel_logout_url", "root_url"):
        if k in c:
            errs.extend(_url_errors(k, c[k], strict=strict))
    auth = c.get("auth")
    if auth == "client-jwt":
        if "jwks_url" not in c:
            errs.append("auth client-jwt: jwks_url is required (the service's public keys)")
        else:
            errs.extend(_url_errors("jwks_url", c["jwks_url"], strict=strict))
    elif auth == "client-secret":
        if "jwks_url" in c:
            errs.append("jwks_url: only for auth client-jwt")
    else:
        errs.append("auth: %r must be client-jwt (with jwks_url; preferred) or client-secret" % auth)
    roles = c.get("roles")
    if not isinstance(roles, list) or not roles:
        errs.append("roles: required, a non-empty list of the service's client roles")
    else:
        if len(set(map(str, roles))) != len(roles):
            errs.append("roles: duplicate entries")
        errs.extend("roles: %r must match %s" % (r, ROLE_RE.pattern) for r in roles
                    if not isinstance(r, str) or not ROLE_RE.fullmatch(r))
        reserved = {x.lower() for x in V.RESERVED_ROLES}
        errs.extend("roles: %r is a Keycloak built-in role name" % r for r in roles if isinstance(r, str) and r.lower() in reserved)
    if "owner" in c and (not isinstance(c["owner"], str) or not OWNER_RE.fullmatch(c["owner"])):
        errs.append("owner: %r must match %s (a team or person id)" % (c.get("owner"), OWNER_RE.pattern))
    if "owner_contact" in c and (not isinstance(c["owner_contact"], str) or len(c["owner_contact"]) > 254
                                 or not V.EMAIL_RE.fullmatch(c["owner_contact"])):
        errs.append("owner_contact: %r is not an e-mail address" % (c.get("owner_contact"),))
    if strict and "root_url" not in c:
        errs.append("root_url: required in strict mode (every URI is checked against its origin; --lenient to accept)")
    if strict and isinstance(c.get("root_url"), str) and not errs:       # origins only of URIs that are otherwise valid
        def org(u):
            x = urllib.parse.urlsplit(u)
            return (x.scheme, (x.hostname or "").lower().rstrip("."), x.port or (443 if x.scheme == "https" else 80))
        ro = org(c["root_url"])
        for k in ("redirect_uris", "post_logout_redirect_uris", "backchannel_logout_url", "web_origins", "jwks_url"):
            for i, u in enumerate(c.get(k) if isinstance(c.get(k), list) else [c.get(k)] if isinstance(c.get(k), str) else []):
                if isinstance(u, str) and org(u) != ro:
                    errs.append("%s%s: %r is not on root_url's origin %s://%s (strict: --lenient to accept)"
                                % (k, "[%d]" % i if isinstance(c.get(k), list) else "", u, ro[0], ro[1]))
    return errs

def load_json_strict(text):
    """json.loads with the public validator's own strictness (its load_request hooks): duplicate keys anywhere in the
    document, and NaN / Infinity, are refused."""
    V = vcr()
    return json.loads(text, object_pairs_hook=V._no_duplicate_keys, parse_constant=V._no_constants)

def parse_client_file(raw, where, strict=True):
    try:
        c = load_json_strict(raw)
    except ValueError as ex:
        sys.exit("REFUSED: %s is not acceptable JSON: %s" % (where, ex))
    errs = validate_client(c, strict)
    if errs:
        sys.exit("REFUSED: %s:\n  - %s" % (where, "\n  - ".join(errs)))
    return c

def refuse_unresolvable(c, where, resolver=None):
    errs = resolve_errors(c, resolver)
    if errs:
        sys.exit("REFUSED: %s:\n  - %s" % (where, "\n  - ".join(errs)))

def desired_client(ks, p, c):
    """(representation, roles) exactly as the image's kcstig renders the file at a Keycloak start."""
    rep = ks.client_rep(c, p)
    return rep, list(rep.pop("_roles", []))

def _same(k, have, want):
    if have in (None, "") and want in (None, ""):
        return True
    if k in ("redirectUris", "webOrigins") and isinstance(have, list) and isinstance(want, list):
        return sorted(have) == sorted(want)
    return have == want

def find_client(kc, cid):
    return next((x for x in kc.api("GET", "/clients?clientId=%s" % q(cid)) or [] if x.get("clientId") == cid), None)

def client_changes(kc, rep, roles, live):
    """What applying `rep`/`roles` changes on the live client, as kcstig's upsert_client would: [(what, have, want)].
    Live roles the file does not name are returned separately: a restart keeps them, so add-client does too."""
    if live is None:
        out = [(k, None, v) for k, v in rep.items() if k != "attributes"]
        out += [("attributes." + k, None, v) for k, v in rep.get("attributes", {}).items()]
        return out + [("role", None, r) for r in roles] + [("default scope", None, "stig-claims")], []
    out = []
    for k, v in rep.items():
        if k == "attributes":
            la = live.get("attributes") or {}
            out += [("attributes." + ak, la.get(ak), av) for ak, av in v.items() if not _same(ak, la.get(ak), av)]
        elif not _same(k, live.get(k), v):
            out.append((k, live.get(k), v))
    have = [r["name"] for r in kc.api("GET", "/clients/%s/roles" % live["id"]) or []]
    out += [("role", None, r) for r in roles if r not in have]
    if rep.get("protocol") == "openid-connect":
        if "offline_access" in [s["name"] for s in kc.api("GET", "/clients/%s/optional-client-scopes" % live["id"]) or []]:
            out.append(("optional scope", "offline_access", None))
        if stig_claims_id(kc) and "stig-claims" not in [s["name"] for s in kc.api("GET", "/clients/%s/default-client-scopes" % live["id"]) or []]:
            out.append(("default scope", None, "stig-claims"))
    return out, sorted(r for r in have if r not in roles)

def stig_claims_id(kc):
    return next((s["id"] for s in kc.api("GET", "/client-scopes") or [] if s["name"] == "stig-claims"), None)

def apply_client(kc, rep, roles, live):
    """kcstig's upsert_client, step for step (same PUT merge, same role description, same scopes). Returns the uuid."""
    if live is None:
        kc.api("POST", "/clients", rep)
        live = find_client(kc, rep["clientId"])
        if not live:
            sys.exit("FAILED: client %s was created but cannot be read back" % rep["clientId"])
    else:
        cur = dict(live); cur.update(rep)
        cur["attributes"] = dict(live.get("attributes") or {}, **rep.get("attributes", {}))
        kc.api("PUT", "/clients/%s" % live["id"], cur)
    cu = live["id"]
    for role in roles:
        if kc.api("GET", "/clients/%s/roles/%s" % (cu, q(role)), ok404=True) is None:
            kc.api("POST", "/clients/%s/roles" % cu, {"name": role, "description": "ASD STIG app role (kcstig)"})
    if rep.get("protocol") == "openid-connect":
        for sc in kc.api("GET", "/clients/%s/optional-client-scopes" % cu) or []:
            if sc["name"] == "offline_access":
                kc.api("DELETE", "/clients/%s/optional-client-scopes/%s" % (cu, sc["id"]))
        sid = stig_claims_id(kc)
        if sid:
            kc.api("PUT", "/clients/%s/default-client-scopes/%s" % (cu, sid))
    return cu

def _show(v):
    s = json.dumps(v) if not isinstance(v, str) else v
    return s if len(s) <= 140 else s[:137] + "..."

def print_changes(cid, changes, extra, out=None):
    out = out or sys.stdout
    for what, have, want in changes:
        print("  %-44s %s -> %s" % (what, "(none)" if have in (None, "") else _show(have), "(removed)" if want is None else _show(want)), file=out)
    for r in extra:
        print("  %-44s %s: live, not in the file - kept (a restart keeps it too); remove with: idp-admin.py role-delete %s:%s"
              % ("role (extra)", r, cid, r), file=out)

def host_client_files(d=None):
    """{client_id: [host files naming it]} - kcstig reads every *.json there (one object or a list) in name order."""
    import glob
    out = {}
    for f in sorted(glob.glob(os.path.join(d or CLIENTS_DIR, "*.json"))):
        try:
            obj = load_json_strict(open(f).read())
        except ValueError:
            out.setdefault("(unreadable)", []).append(f); continue
        for c in (obj if isinstance(obj, list) else [obj]):
            out.setdefault(c.get("client_id") if isinstance(c, dict) else "(unreadable)", []).append(f)
    return out

def write_host_file(cid, raw, d=None):
    """Install the host copy atomically: root-owned, mode 0444, the operator's bytes verbatim."""
    d = d or CLIENTS_DIR
    path = os.path.join(d, cid + ".json"); tmp = path + ".tmp-%d" % os.getpid()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
        if os.geteuid() == 0:
            os.chown(tmp, 0, 0)
        os.chmod(tmp, 0o444); os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return path

def write_secret_private(path, value, owner=0, mode=0o400):
    """Write a secret so that nobody but `owner` (root) can ever read it, whatever was at the path before:
      - the directory must be a real directory (not a link), owned by `owner`, not group- or world-writable;
      - an existing target that is not a regular file (a symlink, a FIFO, ...) is refused, never followed;
      - the value goes into a FRESH file created with O_CREAT|O_EXCL|O_NOFOLLOW (mode 0400) in that directory, checked
        with fstat (regular, `mode` - 0400 by default -, owned by `owner`), then os.replace()d onto the path (atomic,
        replaces a link itself).
    Raises ValueError with the reason."""
    import stat as st_, secrets as sec_
    path = os.path.abspath(path); d = os.path.dirname(path)
    ds = os.lstat(d)
    if not st_.S_ISDIR(ds.st_mode):
        raise ValueError("%s is not a directory (a link or a file)" % d)
    if ds.st_uid != owner or ds.st_mode & 0o022:
        raise ValueError("%s must be owned by uid %d and not group- or world-writable (it is uid %d, mode %o)"
                         % (d, owner, ds.st_uid, ds.st_mode & 0o777))
    if os.path.lexists(path) and not st_.S_ISREG(os.lstat(path).st_mode):
        raise ValueError("%s exists and is not a regular file (a symlink?): refused, never followed" % path)
    tmp = os.path.join(d, ".%s.%s.tmp" % (os.path.basename(path), sec_.token_hex(8)))
    if mode & 0o077:
        raise ValueError("a secret file is never readable or writable by group or others (mode %o)" % mode)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), mode)
    try:
        os.fchmod(fd, mode)
        fs = os.fstat(fd)
        if not st_.S_ISREG(fs.st_mode) or fs.st_mode & 0o777 != mode or fs.st_uid != owner:
            raise ValueError("the new file is not a regular %04o file owned by uid %d" % (mode, owner))
        os.write(fd, value.encode()); os.fsync(fd)
    except BaseException:
        os.close(fd); os.unlink(tmp); raise
    os.close(fd)
    os.replace(tmp, path)

def write_file_nofollow(path, data, mode=0o644):
    """Write bytes to path without following a symlink planted there (O_NOFOLLOW): refused instead."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)

def write_secret_file(path, value):
    # O_NOFOLLOW: a symlink planted at the path is refused, never followed to somewhere else
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(fd, "w") as f:
        os.fchmod(f.fileno(), 0o600); f.write(value)

def secret_to_keyvault(target, value):
    """`<vault>/<name>`: az keyvault secret set from a 0600 temp file (never on a command line)."""
    import shutil, tempfile
    vault, name = target.split("/", 1)
    d = tempfile.mkdtemp(prefix="idp-secret-")
    try:
        f = os.path.join(d, "v"); write_secret_file(f, value)
        r = subprocess.run(["az", "keyvault", "secret", "set", "--vault-name", vault, "--name", name, "--file", f,
                            "--encoding", "utf-8", "--output", "none"], capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit("FAILED: az keyvault secret set %s: %s" % (target, r.stderr.strip()[:300]))
    finally:
        shutil.rmtree(d, True)

def check_secret_opts(a, auth):
    if (a.secret_to or a.secret_to_keyvault) and auth != "client-secret":
        sys.exit("REFUSED: --secret-to/--secret-to-keyvault: the client uses %s, it has no secret" % auth)
    if a.secret_to_keyvault:
        if not re.match(r"^[A-Za-z0-9-]{3,24}/[A-Za-z0-9-]{1,127}$", a.secret_to_keyvault):
            sys.exit("REFUSED: --secret-to-keyvault wants <vault>/<secret name>")
        import shutil
        if not shutil.which("az"):
            sys.exit("REFUSED: --secret-to-keyvault needs the az CLI here (run from the operator Mac with --host)")

def repo_clients_dir(repo):
    d = os.path.join(repo, REPO_CLIENTS)
    if not os.path.isdir(d):
        sys.exit("REFUSED: --repo %s has no %s" % (repo, REPO_CLIENTS))
    return d

def inheritance_statement(cid):
    """The image's kcstig `inherit` for this application, rendered against the image's profile. Returns markdown."""
    import tempfile, shutil, contextlib, io
    ks, p, src, profile = load_kcstig()
    d = tempfile.mkdtemp(prefix="idp-inherit-")
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            ks.cmd_inherit(argparse.Namespace(profile=profile, app=cid, out=d, clients_dir=None))
        return open(os.path.join(d, "%s-stig-inheritance.md" % cid)).read()
    finally:
        shutil.rmtree(d, True)

def add_client(kc, raw, a, out=None):
    """The work of add-client on the host. Returns (client_id, created, changes); exits on any refusal or failure."""
    out = out or sys.stdout
    c = parse_client_file(raw, a.file, not getattr(a, "lenient", False))
    cid = c["client_id"]
    check_secret_opts(a, c["auth"])
    owner, contact = check_owner_opts(a, c)
    if a.file not in ("-", None) and os.path.basename(a.file) != cid + ".json":
        print("note: the host file will be %s.json (named after client_id), not %s" % (cid, os.path.basename(a.file)), file=out)
    others = [f for f in host_client_files().get(cid, []) if os.path.basename(f) != cid + ".json"]
    if others:
        sys.exit("REFUSED: %s is also defined in %s; the restart applies files in name order, so remove it there first" % (cid, others))
    ks, p, _, _ = load_kcstig()
    rep, roles = desired_client(ks, p, c)
    live = find_client(kc, cid)
    managed = os.path.exists(os.path.join(CLIENTS_DIR, cid + ".json"))
    adopt = getattr(a, "adopt", None)
    if adopt and adopt != cid:
        sys.exit("REFUSED: --adopt %s does not name this file's client %s" % (adopt, cid))
    if live is not None and ((live.get("attributes") or {}).get(MANAGED_ATTR) != MANAGED_VAL):
        # no takeover: an existing client is changed only if add-client created it, or it is an adoptable client
        # already managed by its host file and the operator says --adopt <id>
        if not managed:
            sys.exit("REFUSED: client %s exists live, was not created by add-client and has no host file: not taken over" % cid)
        if adopt != cid or cid not in ADOPTABLE:
            sys.exit("REFUSED: client %s exists live but was not created by add-client (no %s=%s); %s" % (
                cid, MANAGED_ATTR, MANAGED_VAL, "re-run with --adopt %s to take it under add-client" % cid if cid in ADOPTABLE
                else "only %s can be adopted" % ", ".join(ADOPTABLE)))
        print("WARNING: adopting %s - it pre-dates add-client; it %s marked %s=%s and changed only by its file"
              % (cid, "would be" if a.dry_run else "is now", MANAGED_ATTR, MANAGED_VAL), file=out)
    elif adopt:
        sys.exit("REFUSED: --adopt %s: %s" % (adopt, "no such live client" if live is None else "already managed by add-client"))
    # one team's file never silently updates another team's client: changing an existing client takes --update <id>
    # (or --adopt <id>), and a different owner takes --transfer
    upd = getattr(a, "update", None)
    if upd and upd != cid:
        sys.exit("REFUSED: --update %s does not name this file's client %s" % (upd, cid))
    if live is None and upd:
        sys.exit("REFUSED: --update %s: there is no such client; drop --update to create it" % cid)
    if live is not None:
        if upd != cid and adopt != cid:
            sys.exit("REFUSED: client %s already exists: changing it takes --update %s (check that this file is meant to "
                     "replace it - another team may have asked for the same client_id)" % (cid, cid))
        la = live.get("attributes") or {}
        lo = la.get(OWNER_ATTR)
        if not lo:
            # an unowned client (it pre-dates owners): nothing to transfer; the first owner is recorded only through
            # --adopt or --update (both checked above), and always said so - owner binding prevents accidents, it is
            # not authentication (anyone who can run this as root on the IdP host can claim)
            if getattr(a, "transfer", False):
                sys.exit("REFUSED: --transfer: %s has no owner recorded yet, so there is nothing to transfer; run it "
                         "without --transfer to record the first owner" % cid)
            print("NOTICE: first owner recorded for %s: %s (%s) - it had none%s" % (
                cid, owner, contact, " (dry run: not yet)" if a.dry_run else ""), file=out)
        elif lo != owner:
            if not getattr(a, "transfer", False):
                sys.exit("REFUSED: client %s is owned by %s (%s); this file says %s. Ownership changes only with --transfer"
                         % (cid, lo, la.get(OWNER_CONTACT_ATTR, "no contact"), owner))
            print("WARNING: transferring %s from %s (%s) to %s (%s)" % (cid, lo, la.get(OWNER_CONTACT_ATTR, "-"), owner, contact), file=out)
        elif getattr(a, "transfer", False) and lo == owner:
            sys.exit("REFUSED: --transfer: %s is already owned by %s" % (cid, owner))
        print_uri_diff(live, rep, out)
    elif getattr(a, "transfer", False):
        sys.exit("REFUSED: --transfer: %s does not exist yet" % cid)
    # the marker and the owner ride on the rendered client (the restart path's upsert merges attributes, so they
    # survive restarts)
    rep["attributes"] = dict(rep.get("attributes", {}), **{MANAGED_ATTR: MANAGED_VAL, OWNER_ATTR: owner, OWNER_CONTACT_ATTR: contact})
    changes, extra = client_changes(kc, rep, roles, live)
    hpath = os.path.join(CLIENTS_DIR, cid + ".json")
    old = open(hpath, "rb").read() if os.path.exists(hpath) else None
    file_change = old != raw
    print("client %s: %s" % (cid, "NEW" if live is None else ("%d live change(s)" % len(changes) if changes else "live client already matches")), file=out)
    print_changes(cid, changes, extra, out)
    print("host file %s: %s" % (hpath, "unchanged" if not file_change else ("new" if old is None else "content changes")), file=out)
    if a.dry_run:
        print("dry run: nothing changed", file=out)
        return cid, live is None, changes
    if changes:
        apply_client(kc, rep, roles, live)
        live2 = find_client(kc, cid)
        left, _ = client_changes(kc, rep, roles, live2)
        if left:
            print_changes(cid, left, [], out)
            sys.exit("FAILED: client %s does not match its file after the apply (above); the host file was NOT written" % cid)
        print("client %s: %s and verified (a re-read matches the file)" % (cid, "created" if live is None else "updated"), file=out)
    if file_change:
        write_host_file(cid, raw)
        print("host file %s: written (root 0444) - a restart now keeps this client as it is live" % hpath, file=out)
    return cid, live is None, changes

def check_owner_opts(a, c):
    """--owner / --owner-contact are required and must equal the file's owner / owner_contact (which the host file and
    the repo copy carry). Returns (owner, contact)."""
    owner, contact = getattr(a, "owner", None), getattr(a, "owner_contact", None)
    if not owner or not contact:
        sys.exit("REFUSED: --owner <team-or-person> and --owner-contact <e-mail> are required (who asked for this client)")
    if c.get("owner") != owner or c.get("owner_contact") != contact:
        sys.exit("REFUSED: the file must carry \"owner\": %s and \"owner_contact\": %s (it says %r / %r) - the host file "
                 "and the repo copy record who owns the client" % (json.dumps(owner), json.dumps(contact), c.get("owner"), c.get("owner_contact")))
    return owner, contact

URI_FIELDS = (("redirectUris", None), ("webOrigins", None), ("rootUrl", None), ("post.logout.redirect.uris", "##"),
              ("backchannel.logout.url", None), ("jwks.url", None))

def print_uri_diff(live, rep, out=None):
    """Before/after of every URI field of an existing client, one URI per line (- removed, + added, = kept)."""
    out = out or sys.stdout
    def vals(d, k, sep):
        v = d.get(k) if k in ("redirectUris", "webOrigins", "rootUrl") else (d.get("attributes") or {}).get(k)
        if v in (None, ""):
            return []
        return list(v) if isinstance(v, list) else (v.split(sep) if sep else [v])
    print("URI fields of %s (before -> after):" % rep["clientId"], file=out)
    for k, sep in URI_FIELDS:
        before, after = vals(live, k, sep), vals(rep, k, sep)
        lines = ["      - %s" % u for u in before if u not in after] + ["      + %s" % u for u in after if u not in before]
        print("  %-28s %s" % (k, "unchanged (%d)" % len(after) if not lines else ""), file=out)
        for l in lines:
            print(l, file=out)

def cmd_add_client(a):
    raw = sys.stdin.buffer.read() if a.file == "-" else open(a.file, "rb").read()
    if a.host:
        return add_client_remote(a, raw)
    if a.secret_stdout and sys.stdout.isatty():
        sys.exit("REFUSED: --secret-stdout writes the secret to stdout: pipe it, never to a terminal")
    real_out = sys.stdout
    if a.secret_stdout:
        sys.stdout = sys.stderr                     # only the secret goes to stdout
    # resolve BEFORE KC() moves this process into Keycloak's network namespace, where the host's resolver is unreachable
    refuse_unresolvable(parse_client_file(raw, a.file, not a.lenient), a.file)
    kc = KC()
    cid, created, _ = add_client(kc, raw, a)
    c = json.loads(raw)
    if a.dry_run:
        return
    if a.repo:
        dst = os.path.join(repo_clients_dir(a.repo), cid + ".json")
        write_file_nofollow(dst, raw); print("repo copy: %s" % dst)
    else:
        print("repo copy (from the operator Mac, in the repository root):\n  ssh %s 'sudo cat %s/%s.json' > %s/%s.json"
              % (OPERATOR_SSH_HOST, CLIENTS_DIR, cid, REPO_CLIENTS, cid))
    if c["auth"] == "client-secret":
        val = kc.api("GET", "/clients/%s/client-secret" % client_uuid(kc, cid))["value"]
        if a.secret_stdout:
            real_out.write(val); real_out.flush()
        if a.secret_to:
            write_secret_file(a.secret_to, val); print("secret: written to %s (0600)" % a.secret_to)
        if a.secret_to_keyvault:
            secret_to_keyvault(a.secret_to_keyvault, val); print("secret: stored in Key Vault %s" % a.secret_to_keyvault)
        if not (a.secret_to or a.secret_to_keyvault or a.secret_stdout):
            print("secret: not delivered; deliver it with --secret-to / --secret-to-keyvault, or "
                  "ssh %s 'sudo idp-admin.py client-secret %s' > <file> && chmod 600 <file>" % (OPERATOR_SSH_HOST, cid))
        val = None
    if a.inheritance_statement:
        md = inheritance_statement(cid)
        write_file_nofollow(a.inheritance_statement, md.encode(), 0o644); print("inheritance statement: %s" % a.inheritance_statement)
    print("issuer https://%s/realms/%s; roles in resource_access.%s.roles" % (ADMIN_HOST, REALM, cid))
    if cid not in APP_CLIENTS:
        print("delegation groups: %s is not in the config's applications, so it has no /%s/<ROLE> groups and no "
              "delegated user management yet. If it needs them: add it under \"applications\" in %s, then "
              "sudo idp-admin.py roles-setup (keycloak-cac/deploy/vm/ADMIN.md)" % (cid, cid, ADMIN_CONFIG_FILE))

def _ssh(host, args, stdin=None):
    import shlex
    return subprocess.run(["ssh", "--", host, " ".join(shlex.quote(x) for x in ["sudo"] + args)], input=stdin, capture_output=True)

def add_client_remote(a, raw):
    """From the operator Mac: validate here, apply on `--host` (stdin carries the file), write the repo copy, deliver
    the secret here. The secret travels only over the ssh pipe into this process."""
    c = parse_client_file(raw, a.file, not a.lenient)
    cid = c["client_id"]
    check_secret_opts(a, c["auth"])
    check_owner_opts(a, c)
    refuse_unresolvable(c, a.file)
    repo_dir = repo_clients_dir(a.repo) if a.repo else None
    args = [a.remote_path, "add-client", "-"] + (["--dry-run"] if a.dry_run else []) + (["--adopt", a.adopt] if a.adopt else []) \
        + ["--owner", a.owner, "--owner-contact", a.owner_contact] + (["--update", a.update] if a.update else []) \
        + (["--transfer"] if a.transfer else []) + (["--lenient"] if a.lenient else [])
    want_secret = c["auth"] == "client-secret" and not a.dry_run and (a.secret_to or a.secret_to_keyvault)
    if want_secret:
        args.append("--secret-stdout")
    r = _ssh(a.host, args, raw)
    sys.stderr.write(r.stderr.decode()) if want_secret else sys.stdout.write(r.stdout.decode() + r.stderr.decode())
    if r.returncode != 0:
        sys.exit("FAILED on %s (exit %d): nothing written here" % (a.host, r.returncode))
    if a.dry_run:
        return
    if repo_dir:
        dst = os.path.join(repo_dir, cid + ".json"); write_file_nofollow(dst, raw); print("repo copy: %s" % dst)
    if want_secret:
        val = r.stdout.decode()
        if not val:
            sys.exit("FAILED: no secret came back from %s" % a.host)
        if a.secret_to:
            write_secret_file(a.secret_to, val); print("secret: written to %s (0600)" % a.secret_to)
        if a.secret_to_keyvault:
            secret_to_keyvault(a.secret_to_keyvault, val); print("secret: stored in Key Vault %s" % a.secret_to_keyvault)
        val = None
    if a.inheritance_statement:
        r = _ssh(a.host, [a.remote_path, "inheritance-statement", cid])
        if r.returncode != 0:
            sys.exit("FAILED: inheritance statement: %s" % r.stderr.decode()[:300])
        write_file_nofollow(a.inheritance_statement, r.stdout, 0o644); print("inheritance statement: %s" % a.inheritance_statement)

def _first_cert_der(pem_text):
    end = "-----END CERTIFICATE-----"
    i = pem_text.index("-----BEGIN CERTIFICATE-----"); j = pem_text.index(end, i) + len(end)
    return ssl.PEM_cert_to_DER_cert(pem_text[i:j])

def _not_before(der):
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".pem") as f:
        f.write(ssl.DER_cert_to_PEM_cert(der)); f.flush()
        return ssl._ssl._test_decode_cert(f.name).get("notBefore")     # stdlib-only decode, as the image's tools do

def served_cert_der(host="127.0.0.1", port=443, sni=None):
    """The leaf certificate Keycloak presents on the published port. Not verified: it is compared, not trusted."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=15) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni or ADMIN_HOST) as s:
            return s.getpeercert(binary_form=True)

def cmd_cert_check(a):
    """Exit 1 (mailed by idp-cert-check.timer) when the certificate on disk is not the one Keycloak serves: a renewal
    was installed but Keycloak not restarted - the TLS hook skips the restart while check-clients reports drift."""
    import hashlib
    disk = _first_cert_der(open(a.cert).read())
    served = served_cert_der(sni=a.sni)
    hd, hs = hashlib.sha256(disk).hexdigest(), hashlib.sha256(served).hexdigest()
    if hd == hs:
        print("cert-check: Keycloak serves the certificate on disk (sha256 %s..., notBefore %s)" % (hd[:16], _not_before(disk)))
        return
    print("IDP-CERT-NOT-SERVED %s (notBefore %s, sha256 %s...) is not the certificate Keycloak serves (notBefore %s, "
          "sha256 %s...): a restart is pending. If the TLS hook skipped it, fix the client drift (sudo idp-admin.py "
          "check-clients), then restart Keycloak (keycloak-cac/deploy/vm/README.md, TLS certificate)." % (a.cert, _not_before(disk), hd[:16],
                                                                                 _not_before(served), hs[:16]), file=sys.stderr)
    sys.exit(1)

def cmd_inheritance_statement(a):
    sys.stdout.write(inheritance_statement(a.client))

def resolve_host_files():
    """{client_id: resolve_errors} for every readable single-client host file. Run BEFORE KC(): inside Keycloak's
    network namespace the host's resolver is unreachable."""
    out = {}
    for cid, fs in host_client_files().items():
        if cid == "(unreadable)" or len(fs) != 1:
            continue
        c = load_json_strict(open(fs[0]).read())
        if isinstance(c, dict):
            out[cid] = resolve_errors(c)
    return out

def check_clients(kc, repo_dir=None, out=None, resolved=None):
    """Drift lines (empty = a restart changes nothing and the repo agrees). Prints a line per client. Also re-resolves
    every jwks_url / back-channel host: one that now resolves to a non-public address (or not at all) is drift."""
    out = out or sys.stdout
    resolved = resolve_host_files() if resolved is None else resolved
    ks, p, _, _ = load_kcstig()
    drift = []
    def bad(msg):
        drift.append(msg); print("DRIFT " + msg, file=out)
    files = host_client_files()
    for f in files.pop("(unreadable)", []):
        bad("%s: not a client file kcstig can read - the next start fails or skips it" % f)
    for cid, fs in sorted(files.items(), key=lambda kv: str(kv[0])):
        if len(fs) > 1:
            bad("%s: defined in %d host files %s - the last one wins at a restart" % (cid, len(fs), fs)); continue
        c = load_json_strict(open(fs[0]).read())
        errs = validate_client(c, strict=False)
        if errs:
            bad("%s: host file %s breaks the client rules: %s" % (cid, fs[0], "; ".join(errs)))
            if not isinstance(c, dict):
                continue
        try:
            rep, roles = desired_client(ks, p, c)
        except SystemExit as ex:
            bad("%s: kcstig refuses the host file: %s" % (cid, ex)); continue
        for e in resolved.get(cid, []):
            bad("%s: %s" % (cid, e))
        live = find_client(kc, cid)
        if live is None:
            bad("%s: host file but no live client - a restart CREATES it" % cid); continue
        changes, extra = client_changes(kc, rep, roles, live)
        la = live.get("attributes") or {}
        if c.get("owner") and (la.get(OWNER_ATTR), la.get(OWNER_CONTACT_ATTR)) != (c.get("owner"), c.get("owner_contact")):
            bad("%s: owner in the host file (%s, %s) differs from the live client's (%s, %s)" % (
                cid, c.get("owner"), c.get("owner_contact"), la.get(OWNER_ATTR), la.get(OWNER_CONTACT_ATTR)))
        elif not c.get("owner"):
            print("info  %s: no owner recorded yet (adopt it: keycloak-cac/deploy/vm/README.md, adding a client)" % cid, file=out)
        if changes:
            bad("%s: live differs from its host file - a restart would change:" % cid); print_changes(cid, changes, [], out)
        else:
            print("ok    %s: live matches %s%s" % (cid, fs[0], " (live-only roles kept: %s)" % extra if extra else ""), file=out)
    drec = load_delegate_records()
    for cid in sorted(set(DELEGATE_CLIENTS) | set(drec)):
        if cid not in drec and find_client(kc, cid) is None:
            continue
        want = delegate_expected(cid, drec)
        dp = delegate_auth_problems(kc, cid, want)
        for pr_ in dp:
            bad("%s: %s" % (cid, pr_))
        if not dp:
            print("ok    %s: delegate authentication matches %s (%s)" % (cid, "its record" if cid in drec else "the default",
                                                                       want.get("alg") or want["auth"]), file=out)
    for cid, want in sorted(load_onboarding().items()):
        probs = onboarding_problems(kc, cid, want, allow_disabled=True)
        ob_c = find_client(kc, cid)
        if ob_c and not ob_c.get("enabled", True):
            print("info  %s: onboarding client is DISABLED (by the guard?): re-enable with onboarding-client-setup" % cid, file=out)
        for pr_ in probs:
            bad("%s: %s" % (cid, pr_))
        if not probs:
            print("ok    %s: onboarding client matches its record (%s)" % (cid, want.get("redirect")), file=out)
        for x in onboarding_apps(want):
            if x in APP_USER_MANAGERS:
                print("ok    %s: serves /%s (writers: /roles/idp-user-manager, /roles/%s)" % (cid, x, app_manager_role(x)), file=out)
            else:
                bad("%s: recorded as serving %s, no longer configured (re-run onboarding-client-setup with the current --app list)" % (cid, x))
    hrec = load_handoff()
    for cid in sorted(set(hrec) | set(HANDOFF_CLIENT_IDS)):
        hw = find_client(kc, cid)
        if cid not in hrec:
            if hw is not None:
                bad("%s: the configured hand-off worker exists with no record (create it with handoff-worker-setup)" % cid)
            continue
        probs = handoff_problems(kc, cid, hrec[cid], allow_disabled=True)
        if cid not in HANDOFF_CLIENT_IDS:
            probs.append("recorded as a hand-off worker, but no longer the configured handoffIntake.clientId")
        if hw and not hw.get("enabled", True):
            print("info  %s: hand-off worker is DISABLED (by the guard?): re-enable with handoff-worker-setup" % cid, file=out)
        for pr_ in probs:
            bad("%s: %s" % (cid, pr_))
        if not probs:
            print("ok    %s: hand-off worker matches its record (aud %s, scope %s)" % (cid, hrec[cid].get("audience"),
                                                                                    hrec[cid].get("scope")), file=out)
    for c_ in kc.api("GET", "/clients") or []:
        if c_["clientId"] not in files and c_["clientId"] not in UNMANAGED_CLIENTS:
            print("info  %s: live client with no host file (not managed by client files; a restart leaves it alone)" % c_["clientId"], file=out)
    if repo_dir:
        drift += compare_repo({cid: open(fs[0], "rb").read() for cid, fs in files.items() if len(fs) == 1}, repo_dir, out)
    return drift

def compare_repo(host_raw, repo_dir, out=None):
    """host_raw: {client_id: bytes of its host file}. Drift lines for every disagreement with the repo copies."""
    out = out or sys.stdout
    drift = []
    repo = host_client_files(repo_dir)
    for cid in sorted(set(host_raw) | set(k for k in repo if k != "(unreadable)"), key=str):
        if cid not in repo:
            m = "%s: on the host, no repo copy in %s" % (cid, repo_dir)
        elif cid not in host_raw:
            m = "%s: repo copy %s, no host file - setup-host.sh would install it" % (cid, repo[cid])
        elif json.loads(host_raw[cid]) != json.load(open(repo[cid][0])):
            m = "%s: host file and repo copy %s differ" % (cid, repo[cid][0])
        else:
            print("ok    %s: repo copy matches the host file" % cid, file=out); continue
        drift.append(m); print("DRIFT " + m, file=out)
    return drift

def cmd_check_clients(a):
    if a.host:
        r = _ssh(a.host, [a.remote_path, "check-clients", "--emit-files"])
        sys.stdout.write(r.stderr.decode())
        if r.returncode not in (0, 1):
            sys.exit("FAILED on %s (exit %d)" % (a.host, r.returncode))
        drift = r.returncode == 1
        if a.repo:
            drift = bool(compare_repo({k: v.encode() for k, v in json.loads(r.stdout)["files"].items()}, repo_clients_dir(a.repo))) or drift
        print("check-clients: %s" % ("DRIFT - fix it before any Keycloak restart" if drift else "no drift"))
        sys.exit(1 if drift else 0)
    out = sys.stderr if a.emit_files else sys.stdout
    resolved = resolve_host_files()        # before KC() enters Keycloak's network namespace
    kc = KC()
    drift = check_clients(kc, repo_clients_dir(a.repo) if a.repo else None, out, resolved)
    if a.emit_files:
        files = {cid: open(fs[0]).read() for cid, fs in host_client_files().items() if len(fs) == 1 and cid != "(unreadable)"}
        sys.stdout.write(json.dumps({"files": files}))
    else:
        print("check-clients: %s" % ("%d DRIFT - fix it before any Keycloak restart" % len(drift) if drift else "no drift"), file=out)
    sys.exit(1 if drift else 0)

def build_parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    e = sp.add_parser("entra"); e.add_argument("--tenant", required=True); e.add_argument("--client-id", required=True)
    e.add_argument("--secret-file", default=os.path.join(SECRETS, "entra_client_secret"))
    e.add_argument("--member-domain", help="the UPN domain whose tenant members may sign in (default: the config's entra.memberDomain)")
    e.add_argument("--enable", action="store_true", help="enable and show the provider: only after tenant admin consent AND a Conditional Access policy requiring MFA for the app")
    e.add_argument("--auto-link-domain", help="bind a pending stig-accounts invite (signIn entra) at its FIRST Entra sign-in, by the UPN in this domain")
    e.add_argument("--no-auto-link", action="store_true", help="switch the first-sign-in binding of pending invites off (default: as it is)")
    e.add_argument("--domain-verified-by-operator", action="store_true",
                   help="with --auto-link-domain, when Graph cannot be asked: you checked the domain is Verified in the tenant")
    ca = sp.add_parser("card-accounts", help="let user managers create CAC accounts through stig-accounts (signIn cac)")
    ca.add_argument("state", choices=["on", "off"]); ca.add_argument("--attribute", default="cac_edipi", choices=["cac_edipi"])
    ca.set_defaults(fn=cmd_card_accounts)
    e.set_defaults(fn=cmd_entra)
    c = sp.add_parser("client-secret"); c.add_argument("client"); c.set_defaults(fn=cmd_client_secret)
    u = sp.add_parser("user-enable"); u.add_argument("username"); u.add_argument("enabled", choices=["true", "false"]); u.set_defaults(fn=cmd_user_enable)
    rs = sp.add_parser("roles-setup"); rs.set_defaults(fn=cmd_roles_setup)
    rs.add_argument("--retire-app", action="append", default=[],
                    help="tear down the delegation of an application removed from the configuration")
    rd = sp.add_parser("delegate-setup", help="a membership-only delegate (config: membershipOnly): its listed role groups, nothing else")
    rd.add_argument("client_id", choices=sorted(MEMBERSHIP_ONLY_DELEGATES) or None,
                    help="the delegate's client id (applications.<app>.delegations.<id> with \"membershipOnly\": true)")
    rd.add_argument("--jwks-url", help="client-jwt (private_key_jwt) with the app's OWN delegate JWKS (else its authentication is left as it is)")
    rd.add_argument("--alg", choices=DELEGATE_ALGS, default="ES256", help="with --jwks-url: the app's signing algorithm")
    rd.set_defaults(fn=cmd_delegate_setup)
    dc = sp.add_parser("delegate-client-setup", help="switch a delegate (APP_DELEGATIONS) to client-jwt with the app's JWKS, or back to a secret")
    dc.add_argument("client_id", choices=list(DELEGATE_CLIENTS))
    dc.add_argument("--jwks-url", help="the app's JWKS for THIS delegate (https, public DNS name)")
    dc.add_argument("--alg", choices=DELEGATE_ALGS, default="ES256", help="the app's signing algorithm (default ES256)")
    dc.add_argument("--expect-thumbprint", help="the RFC 7638 thumbprint the app's key must have (the app tells you)")
    dc.add_argument("--client-secret", action="store_true", help="ROLLBACK: back to a client secret (a new one; the old one stays dead)")
    dc.set_defaults(fn=cmd_delegate_client_setup)
    tw = sp.add_parser("delegate-test-twin", help="a TEMPORARY twin of a delegate (same delegation, a secret) for the live $L/$T tests")
    tw.add_argument("client_id", choices=list(DELEGATE_CLIENTS) + ["all"]); tw.add_argument("action", choices=["run", "create", "remove"])
    tw.add_argument("--secret-file", help="create: where its secret is written (0400)")
    tw.add_argument("--secret-dir", help="run: a root-owned directory; each twin's secret is <dir>/<delegate> (0400) during the run")
    tw.set_defaults(run_cmd=[])          # run: the command after `--` (parse_cli takes it out before argparse)
    tw.set_defaults(fn=cmd_delegate_test_twin)
    ob = sp.add_parser("onboarding-client-setup", help="the public client an application page uses to manage accounts with a user manager's OWN token")
    ob.add_argument("--redirect-uri", required=True, help="the page's exact callback, e.g. https://<app host>/admin/accounts/callback")
    ob.add_argument("--origin", help="its origin (checked: must be the redirect URI's); the only origin the admin API answers CORS for")
    ob.add_argument("--client-id", default=ONBOARDING_CLIENT_IDS[0], choices=list(ONBOARDING_CLIENT_IDS))
    ob.add_argument("--app", action="append", choices=sorted(APP_USER_MANAGERS),
                    help="an application tree the page serves (repeat for several; default the config's onboarding.defaultApps). Recorded; "
                         "each caller still reaches only the trees their own manager roles cover")
    ob.add_argument("--max-auth-age", type=int, default=300, help="seconds since sign-in a write may be made (30..900)")
    ob.add_argument("--operations", default=",".join(ONBOARDING_DEFAULT_OPS),
                    help="the writes it may make: a comma list of %s (default %s: no disable - a whole-account disable is a hand-off to the IdP's operators)"
                    % ("|".join(ONBOARDING_OPERATIONS), ",".join(ONBOARDING_DEFAULT_OPS)))
    ob.add_argument("--require-dpop", action="store_true", help="bind its tokens to a key the page holds (DPoP): the page must send DPoP proofs")
    ob.set_defaults(fn=cmd_onboarding_client_setup)
    hw = sp.add_parser("handoff-worker-setup", help="create or converge the hand-off intake worker client (config handoffIntake): "
                       "service account only, no roles, one optional scope with one audience mapper; secret to a root 0600 file")
    hw.add_argument("--rotate-secret", action="store_true", help="give it a new client secret (the old one stops working at once)")
    hw.set_defaults(fn=cmd_handoff_worker_setup)
    ho = sp.add_parser("handoffs", help="list an application's open hand-offs (with the suggested command for each), or record an "
                       "outcome: handoffs done|refused <id> [--note ...]. Never changes an account")
    ho.add_argument("action", nargs="?", choices=["list", "done", "refused"], default="list")
    ho.add_argument("id", nargs="?", help="done / refused: the hand-off's id, as listed")
    ho.add_argument("--note", help="done / refused: at most %d characters, no run of ten digits (required for refused)" % HANDOFF_NOTE_MAX)
    ho.set_defaults(fn=cmd_handoffs)
    rb = sp.add_parser("delegation-rollback", help="ROLLBACK ONLY: back to one tree-wide permission (refused once a tree holds a group its pre-split delegate must not write)")
    rb.set_defaults(fn=cmd_delegation_rollback)
    gr = sp.add_parser("grant"); gr.add_argument("username"); gr.add_argument("roles", nargs="+", help="idp-admin | idp-user-manager | idp-auditor | <app>-user-manager | <client>:<ROLE>")
    gr.add_argument("--reset-credentials", action="store_true", help="promotion of an account a non-administrator touched: remove every password, OTP and identity-provider link first")
    gr.add_argument("--email", help="with --reset-credentials: the e-mail address, checked by the operator (required for a delegate-created account)")
    gr.add_argument("--clear-bindings", action="store_true", help="also clear identity bindings not proven to be set by the operator's tooling (else refused)")
    gr.set_defaults(fn=cmd_grant)
    pr = sp.add_parser("promote"); pr.add_argument("username")
    pr.add_argument("--clear-bindings", action="store_true", help="also clear identity bindings not proven to be set by the operator's tooling (else refused)")
    pr.set_defaults(fn=cmd_promote)
    rv = sp.add_parser("revoke"); rv.add_argument("username"); rv.set_defaults(fn=cmd_revoke)
    ru = sp.add_parser("reset-user"); ru.add_argument("user", help="username or user id")
    ru.add_argument("--clear-bindings", action="store_true", help="also remove the identity bindings entra_oid and cac_edipi")
    ru.set_defaults(fn=cmd_reset_user)
    cd_ = sp.add_parser("client-delete"); cd_.add_argument("client", help="exact clientId or client UUID"); cd_.set_defaults(fn=cmd_client_delete)
    rd_ = sp.add_parser("role-delete"); rd_.add_argument("role", help="realm role name, <clientId>:<role>, or role UUID"); rd_.set_defaults(fn=cmd_role_delete)
    al_ = sp.add_parser("allowlist"); al_.add_argument("--init"); al_.set_defaults(fn=cmd_allowlist)
    ss = sp.add_parser("send-setup"); ss.add_argument("username"); ss.add_argument("--lifespan", type=int, default=43200); ss.set_defaults(fn=cmd_send_setup)
    rn = sp.add_parser("rename"); rn.add_argument("old"); rn.add_argument("new"); rn.add_argument("--email"); rn.add_argument("--first"); rn.add_argument("--last"); rn.set_defaults(fn=cmd_rename)
    spw = sp.add_parser("set-password"); spw.add_argument("username"); spw.set_defaults(fn=cmd_set_password)
    _smtp = _AC.get("smtp") or {}
    sm = sp.add_parser("smtp"); sm.add_argument("--host", default=_smtp.get("host"), required=not _smtp.get("host"))
    sm.add_argument("--port", type=int, default=int(_smtp.get("port") or 587))
    sm.add_argument("--user", required=True); sm.add_argument("--password-file", default=os.path.join(SECRETS, "smtp_password"))
    sm.add_argument("--from", dest="sender", default=_smtp.get("from"), required=not _smtp.get("from")); sm.add_argument("--alert-to")
    sm.add_argument("--display-name", default=_smtp.get("displayName") or "Sign-in"); sm.set_defaults(fn=cmd_smtp)
    iv = sp.add_parser("invite"); iv.add_argument("username"); iv.add_argument("--email", required=True); iv.add_argument("--first"); iv.add_argument("--last")
    iv.add_argument("--groups", default="", help="comma list: idp-admin,idp-user-manager,idp-auditor,<client>:<ROLE>")
    iv.add_argument("--edipi"); iv.add_argument("--entra-oid"); iv.add_argument("--lifespan", type=int, default=43200); iv.set_defaults(fn=cmd_invite)
    gd = sp.add_parser("guard"); gd.add_argument("--fix", action="store_true"); gd.set_defaults(fn=cmd_guard)
    le = sp.add_parser("link-entra"); le.add_argument("username"); le.add_argument("oid"); le.set_defaults(fn=cmd_link_entra)
    lc = sp.add_parser("link-cac", help="bind a CAC to an EXISTING account: its holder presents it at the next sign-in "
                                        "(--edipi: only that card), or - only if they cannot - --bind-edipi --confirm-direct-bind")
    lc.add_argument("username", nargs="?")
    lc.add_argument("stray", nargs="*", help=argparse.SUPPRESS)          # an EDIPI typed here is refused, never echoed
    lc.add_argument("--edipi", nargs="?", const=True, default=None,
                    help="only the card with this EDIPI binds (typed at a prompt that does not show it; never on the command line)")
    lc.add_argument("--bind-edipi", nargs="?", const=True, default=None,
                    help="bind the card now, nobody presenting it (prompted; IdP administrators never); needs --confirm-direct-bind")
    lc.add_argument("--confirm-direct-bind", action="store_true", help="with --bind-edipi: you verified the card and its holder yourself")
    lc.add_argument("--replace", action="store_true", help="the account already has a card (or an invite's pending one): remove it, end its sessions")
    lc.add_argument("--allow-admin", action="store_true", help="the account is an IdP administrator: allowed with --edipi only")
    lc.add_argument("--cancel", action="store_true", help="withdraw a pending link request")
    lc.add_argument("--cancel-all", action="store_true", help="withdraw EVERY pending link request in the realm (the realm-wide stop)")
    lc.set_defaults(fn=cmd_link_cac)
    am = sp.add_parser("entra-amr"); am.add_argument("username"); am.set_defaults(fn=cmd_entra_amr)
    ul = sp.add_parser("user-unlock"); ul.add_argument("username"); ul.set_defaults(fn=cmd_user_unlock)
    lo = sp.add_parser("user-logout"); lo.add_argument("username"); lo.set_defaults(fn=cmd_user_logout)
    d = sp.add_parser("user-delete"); d.add_argument("username"); d.set_defaults(fn=cmd_user_delete)
    uc = sp.add_parser("user-create-cac")
    for x in ("username", "edipi", "email", "first", "last", "role"):
        uc.add_argument(x)
    uc.add_argument("--accept-credentials", action="store_true", help="with --existing: accept an account that has a password/OTP credential (checked by the operator)")
    uc.add_argument("--existing", action="store_true", help="the account may already exist: verify it is the same person (EDIPI, no links) and add the role")
    uc.set_defaults(fn=cmd_user_create_cac)
    ac = sp.add_parser("add-client", help="register or update one client live (no restart), then install its host file")
    ac.add_argument("file", help="the client JSON (one object, keycloak-asd-stig profile.md rules), or - for stdin")
    ac.add_argument("--dry-run", action="store_true", help="validate and show what would change; change nothing")
    ac.add_argument("--owner", required=True, help="the team or person who asked for the client (must equal the file's \"owner\")")
    ac.add_argument("--owner-contact", required=True, help="their e-mail (must equal the file's \"owner_contact\")")
    ac.add_argument("--update", metavar="ID", help="the client exists and this file replaces it (required to change an existing client)")
    ac.add_argument("--transfer", action="store_true", help="with --update: the client changes owner (refused otherwise)")
    ac.add_argument("--lenient", action="store_true", help="accept the public validator's warnings (query strings, URIs off root_url's origin); strict by default")
    ac.add_argument("--adopt", metavar="ID", help="take a pre-existing file-managed client (%s) under add-client (once; warns)" % ", ".join(ADOPTABLE))
    ac.add_argument("--repo", help="repository root: also write <repoClientsDir>/<id>.json there (config; default clients/)")
    ac.add_argument("--secret-to", help="client-secret clients: write the secret to this file (0600)")
    ac.add_argument("--secret-to-keyvault", help="client-secret clients: store the secret as <vault>/<name> (az CLI)")
    ac.add_argument("--secret-stdout", action="store_true", help=argparse.SUPPRESS)   # the --host protocol: secret only, never a terminal
    ac.add_argument("--inheritance-statement", help="write the application's ASD STIG control-inheritance statement (markdown) here")
    ac.add_argument("--host", help="run from the operator Mac: apply on this ssh host (the operator's ssh alias for the IdP VM)")
    ac.add_argument("--remote-path", default=REMOTE_ADMIN, help="idp-admin.py on --host (default %(default)s)")
    ac.set_defaults(fn=cmd_add_client)
    cc = sp.add_parser("check-clients", help="exit 1 if any live client differs from its host file (or the repo copy)")
    cc.add_argument("--repo", help="repository root: also compare <repoClientsDir>/*.json (config; default clients/)")
    cc.add_argument("--host", help="run from the operator Mac against this ssh host"); cc.add_argument("--remote-path", default=REMOTE_ADMIN)
    cc.add_argument("--emit-files", action="store_true", help=argparse.SUPPRESS)      # the --host protocol
    cc.set_defaults(fn=cmd_check_clients)
    ck = sp.add_parser("cert-check", help="exit 1 if the certificate on disk is not the one Keycloak serves (a restart is pending)")
    ck.add_argument("--cert", default="/srv/idp/tls/tls.crt"); ck.add_argument("--sni", help="server name (default: the public host)")
    ck.set_defaults(fn=cmd_cert_check)
    ih = sp.add_parser("inheritance-statement", help="print an application's ASD STIG control-inheritance statement (markdown)")
    ih.add_argument("client"); ih.set_defaults(fn=cmd_inheritance_statement)
    p = sp.add_parser("user-create-pw")
    for x in ("username", "email", "first", "last", "role"):
        p.add_argument(x)
    p.add_argument("--temp-password-file", required=True); p.add_argument("--temporary", action="store_true"); p.set_defaults(fn=cmd_user_create_pw)
    return ap

def parse_cli(argv):
    """The command line, with delegate-test-twin's command taken from after the FIRST `--` before argparse sees it, so
    options may stand anywhere before the `--` (`delegate-test-twin all run --secret-dir D -- cmd ...`, as the operating guide
    writes it): an argparse REMAINDER positional would swallow such options."""
    argv = list(argv); run_cmd = []
    if "delegate-test-twin" in argv and "--" in argv:
        i = argv.index("--"); argv, run_cmd = argv[:i], argv[i + 1:]
    a = build_parser().parse_args(argv)
    if a.fn is cmd_delegate_test_twin:
        a.run_cmd = run_cmd
    return a

if __name__ == "__main__":
    a = parse_cli(sys.argv[1:]); a.fn(a)

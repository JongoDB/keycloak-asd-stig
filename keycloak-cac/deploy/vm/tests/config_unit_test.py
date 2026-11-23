#!/usr/bin/env python3
"""Unit test of idp-admin.py's config loading: what it refuses at import, before any command runs. No Keycloak, no
root, runs anywhere. Each config is loaded in a fresh interpreter (the module reads it at import).

  python3 config_unit_test.py
"""
import copy, json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ADM = os.path.join(HERE, "..", "host", "idp-admin.py")
BASE = json.load(open(os.path.join(HERE, "fixtures", "idp-admin.test.json")))
res = []
def check(n, ok, d=""):
    res.append(bool(ok)); print("%s  %-92s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)

def load(cfg):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f); p = f.name
    try:
        r = subprocess.run([sys.executable, ADM, "--help"], env=dict(os.environ, IDP_ADMIN_CONFIG=p),
                           capture_output=True, text=True, timeout=60)
        return r.returncode, (r.stdout + r.stderr)
    finally:
        os.unlink(p)

def variant(fn):
    c = copy.deepcopy(BASE); fn(c); return c

rc, out = load(BASE)
check("the lab config loads", rc == 0, out[-200:] if rc else "")

refused = [
    ("an application named realm-management (delegating realm-admin)",
     lambda c: c["applications"].update({"realm-management": {"delegations": {"x-del": {"groups": ["realm-admin"]}}}}), "reserved"),
    ("an application named *-realm", lambda c: c["applications"].update({"example-realm": {}}), "reserved"),
    ("an application named after this tooling's own client (stig-automation)",
     lambda c: c["applications"].update({"stig-automation": {}}), "reserved"),
    ("an application named after a role group (idp-admin)", lambda c: c["applications"].update({"idp-admin": {}}), "reserved"),
    ("a delegate named security-admin-console",
     lambda c: c["applications"]["app-b"].update({"delegations": {"security-admin-console": {"groups": ["member"]}}}), "reserved"),
    ("a delegate named admin-cli",
     lambda c: c["applications"]["app-b"].update({"delegations": {"admin-cli": {"groups": ["member"]}}}), "reserved"),
    ("a delegate whose id is also an application",
     lambda c: c["applications"]["app-b"].update({"delegations": {"app-c": {"groups": ["member"]}}}), "also an application"),
    ("groups as a string (would be iterated letter by letter)",
     lambda c: c["applications"]["app-a"]["delegations"]["app-a-admin"].update({"groups": "administrator"}), "list of names"),
    ("an empty groups list", lambda c: c["applications"]["app-a"]["delegations"]["app-a-admin"].update({"groups": []}), "list of names"),
    ("membershipOnly as a string",
     lambda c: c["applications"]["app-a"]["delegations"]["app-a-reader-delegate"].update({"membershipOnly": "yes"}), "true or false"),
    ("userManagerRole not a string", lambda c: c["applications"]["app-b"].update({"userManagerRole": ["owner"]}), "string"),
    ("an unknown key in entra", lambda c: c["entra"].update({"memberDomian": "x"}), "unknown key"),
    ("an unknown key in smtp", lambda c: c["smtp"].update({"hots": "x"}), "unknown key"),
    ("smtp.port as a string", lambda c: c["smtp"].update({"port": "587"}), "port number"),
    ("an unknown key in onboarding", lambda c: c["onboarding"].update({"apps": ["app-a"]}), "unknown key"),
    ("onboarding.defaultApps naming no application", lambda c: c["onboarding"].update({"defaultApps": ["nonesuch"]}), "not an application"),
    ("onboarding.defaultApps as a string", lambda c: c["onboarding"].update({"defaultApps": "app-a"}), "list of names"),
    ("onboarding.clientIds naming the default onboarding client", lambda c: c["onboarding"].update({"clientIds": ["idp-onboarding"]}), "reserved"),
    ("onboarding.clientIds naming a built-in", lambda c: c["onboarding"].update({"clientIds": ["admin-cli"]}), "reserved"),
    ("onboarding.clientIds naming an application", lambda c: c["onboarding"].update({"clientIds": ["app-a"]}), "also an application"),
    ("onboarding.clientIds naming a delegate", lambda c: c["onboarding"].update({"clientIds": ["app-a-admin"]}), "also an application"),
    ("onboarding.clientIds naming the hand-off worker",
     lambda c: (c.update({"handoffIntake": {"url": "https://app-a.example.mil/intake", "clientId": "x-worker", "audience": "a",
                                            "scope": "app-a.intake", "app": "app-a"}}), c["onboarding"].update({"clientIds": ["x-worker"]})),
     "hand-off worker"),
    ("onboarding.clientIds not a client id", lambda c: c["onboarding"].update({"clientIds": ["App B"]}), "not a client id"),
    ("onboarding.clientIds naming a client twice",
     lambda c: c["onboarding"].update({"clientIds": ["app-b-onboarding", "app-b-onboarding"]}), "twice"),
    ("onboarding.clientIds as a string", lambda c: c["onboarding"].update({"clientIds": "app-b-onboarding"}), "list of names"),
    ("preSplitDelegates naming no delegation", lambda c: c["applications"]["app-a"].update({"preSplitDelegates": ["x"]}), "not a delegation"),
    ("an unknown top-level key", lambda c: c.update({"application": {}}), "unknown key"),
    ("applications not an object", lambda c: c.update({"applications": ["app-a"]}), "not an object"),
]
for name, fn, want in refused:
    rc, out = load(variant(fn))
    check("REFUSED: " + name, rc != 0 and "REFUSED" in out and want in out, out.strip().splitlines()[-1][:110] if out.strip() else rc)

# onboarding.clientIds: more onboarding clients, each built and guarded like the default one
def ids(cfg):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f); p = f.name
    try:
        code = ("import importlib.machinery, importlib.util; ld = importlib.machinery.SourceFileLoader('m', %r); "
                "s = importlib.util.spec_from_loader('m', ld); M = importlib.util.module_from_spec(s); ld.exec_module(M); "
                "print(','.join(M.ONBOARDING_CLIENT_IDS))" % ADM)
        r = subprocess.run([sys.executable, "-c", code], env=dict(os.environ, IDP_ADMIN_CONFIG=p), capture_output=True, text=True, timeout=60)
        return r.stdout.strip()
    finally:
        os.unlink(p)
check("no onboarding.clientIds: the default onboarding client only", ids(BASE) == "idp-onboarding", ids(BASE))
two = variant(lambda c: c["onboarding"].update({"clientIds": ["app-b-onboarding"]}))
check("onboarding.clientIds: the default first, then each named one", ids(two) == "idp-onboarding,app-b-onboarding", ids(two))
rc, out = load(two)
check("a config with onboarding.clientIds loads", rc == 0, out[-200:] if rc else "")
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
    json.dump(two, f); p2 = f.name
r = subprocess.run([sys.executable, ADM, "onboarding-client-setup", "--help"], env=dict(os.environ, IDP_ADMIN_CONFIG=p2),
                   capture_output=True, text=True, timeout=60); os.unlink(p2)
check("onboarding-client-setup --client-id offers the named client", "app-b-onboarding" in r.stdout, r.stdout[-160:].replace("\n", " "))

print("\n%d/%d passed" % (sum(res), len(res)))
raise SystemExit(0 if all(res) else 1)

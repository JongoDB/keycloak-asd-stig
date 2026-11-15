#!/usr/bin/env bash
# kcstig auth_mode=passkey and extra-realm profiles, without a container (fast, in the guards job):
#   - a WebAuthn algorithm name Keycloak does not know (EdDSA - Keycloak spells it Ed25519), RS1, an empty list,
#     user verification or discoverable credentials other than required, or registration_flow=keep are REFUSED;
#   - the rendered realm carries both WebAuthn policies, the deny registration flow, the conditional passkey step,
#     no password/OTP set-up, and the inactivity workflow's disabled marker;
#   - a non-passkey profile renders exactly as before for the parts passkey mode adds (no registration flow, no
#     WebAuthn policy beyond the old defaults, the inactivity workflow unchanged);
#   - cac-config's extra-realm profiles: merged over the main profile without its users/clients/admins, refused
#     when they name the main realm, master, a duplicate, `keycloak` or `admin`, or carry an invalid profile.
#   keycloak-cac/tests/passkey-profile.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
python3 - "$ROOT" <<'PY'
import contextlib, io, json, os, subprocess, sys, tempfile
ROOT = sys.argv[1]
sys.path.insert(0, os.path.join(ROOT, "keycloak-asd-stig", "scripts"))
import kcstig as K
res = []
def check(name, ok, detail=""):
    res.append(bool(ok)); print("%s %-78s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)
T = tempfile.mkdtemp()
def prof(obj, name="p.json"):
    path = os.path.join(T, name); json.dump(obj, open(path, "w")); return path
def load(obj):
    """(profile or None, exit message)"""
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            return K.load_profile(prof(obj)), err.getvalue()
    except SystemExit as e:
        return None, str(e)
base = {"realm": {"name": "partners", "display_name": "Partners"}, "auth_mode": "passkey"}

p, msg = load(base)
check("passkey profile with the defaults loads", p is not None, msg)
check("... ES256 + RS256, UV required, discoverable required, attestation none", p and p["webauthn"]["algorithms"] == ["ES256", "RS256"]
      and p["webauthn"]["user_verification"] == "required" and p["webauthn"]["discoverable"] == "required" and p["webauthn"]["attestation"] == "none")
check("... registration flow denied, disabled marker on", p and p["registration_flow"] == "deny" and p["accounts"]["disabled_marker"] is True)
for label, over, needle in [
        ("EdDSA (Keycloak's name is Ed25519) is refused", {"webauthn": {"algorithms": ["ES256", "EdDSA"]}}, "Ed25519"),
        ("an unknown algorithm name is refused", {"webauthn": {"algorithms": ["ES256", "es256"]}}, "not a Keycloak algorithm name"),
        ("RS1 (SHA-1) is refused", {"webauthn": {"algorithms": ["RS1"]}}, "RS1"),
        ("an empty algorithm list is refused", {"webauthn": {"algorithms": []}}, "non-empty"),
        ("user verification other than required is refused", {"webauthn": {"user_verification": "preferred"}}, "user_verification"),
        ("a non-discoverable credential is refused", {"webauthn": {"discoverable": "preferred"}}, "discoverable"),
        ("an unknown attestation value is refused", {"webauthn": {"attestation": "full"}}, "attestation"),
        ("an unknown sign-in style is refused", {"webauthn": {"sign_in": "password"}}, "sign_in"),
        ("registration_flow=keep is refused in a passkey realm", {"registration_flow": "keep"}, "registration"),
        ("a temporary password is refused in a passkey realm", {"users": [{"username": "a.b", "temporary_password": "x" * 20}]}, "temporary_password"),
        ("an RP ID that is not a host name is refused", {"webauthn": {"rp_id": "https://x"}}, "rp_id")]:
    p2, msg = load(K.deep_merge(base, over))
    check(label, p2 is None and needle in msg, msg[:110])
p3, msg = load(K.deep_merge(base, {"webauthn": {"algorithms": ["ES256", "Ed25519"]}}))
check("Ed25519 loads with a warning (verify refuses it until its CMVP status is confirmed)", p3 is not None and "Ed25519" in msg, msg[:110])

r = K.render(p)
R = r["realm"]
check("both WebAuthn policies: ES256 + RS256, UV required, resident key required",
      R["webAuthnPolicyPasswordlessSignatureAlgorithms"] == ["ES256", "RS256"] == R["webAuthnPolicySignatureAlgorithms"]
      and R["webAuthnPolicyPasswordlessUserVerificationRequirement"] == "required" == R["webAuthnPolicyUserVerificationRequirement"]
      and R["webAuthnPolicyPasswordlessResidentKey"] == "required" and R["webAuthnPolicyPasswordlessPasskeysEnabled"] is True)
check("... attestation none, any attachment, RP ID the IdP's own host",
      R["webAuthnPolicyPasswordlessAttestationConveyancePreference"] == "none"
      and R["webAuthnPolicyPasswordlessAuthenticatorAttachment"] == "not specified" and R["webAuthnPolicyPasswordlessRpId"] == "")
check("registration flow bound to a deny flow", r["registration_flow"] == ("STIG Registration - Deny", [("exec", "deny-access-authenticator", "REQUIRED", None)]))
flat = json.dumps(r["browser_flow"])
check("browser flow: username form, CONDITIONAL [credential not used -> passkey], allowlist gate",
      '"auth-username-form"' in flat and '"CONDITIONAL"' in flat and '"conditional-credential"' in flat
      and '"webauthn-passwordless", "included": "false"' in flat and K.PASSKEY_AUTH in flat and K.ALLOWLIST_GATE in flat)
check("browser flow: no password, OTP, two-factor WebAuthn or certificate step",
      not any(x in flat for x in ('"stig-username-password-form"', '"auth-username-password-form"', '"auth-otp-form"',
                                  '"webauthn-authenticator"', "x509")))
pd, _ = load(K.deep_merge(base, {"webauthn": {"sign_in": "discoverable"}}))
fd = json.dumps(K.render(pd)["browser_flow"])
check("sign_in=discoverable: the passkey step alone, no username form", K.PASSKEY_AUTH in fd and "auth-username-form" not in fd
      and "conditional-credential" not in fd and K.ALLOWLIST_GATE in fd)
wf = r["workflows"][0]
check("the disabled marker is declared in the user profile, administrators only",
      [x["permissions"] for x in r["user_profile_attributes"] if x["name"] == "stig_disabled_by"] == [{"view": ["admin"], "edit": ["admin"]}])
check("inactivity workflow: set stig_disabled_by=inactivity after 35 d, then disable",
      wf["steps"] == [{"uses": "set-user-attribute", "after": "35d", "with": {"stig_disabled_by": "inactivity"}}, {"uses": "disable-user"}])

for mode in ("cac", "cac_or_mfa", "mfa"):
    pc, msg = load({"realm": {"name": "defconai"}, "auth_mode": mode})
    rc = K.render(pc)
    keys = {k: v for k, v in rc["realm"].items() if k.startswith("webAuthn")}
    check("auth_mode=%s: nothing passkey mode adds" % mode,
          rc["registration_flow"] is None and pc["registration_flow"] == "keep"
          and keys == {"webAuthnPolicyUserVerificationRequirement": "required", "webAuthnPolicyAuthenticatorAttachment": "cross-platform",
                       "webAuthnPolicySignatureAlgorithms": ["ES256", "RS256"], "webAuthnPolicyRpEntityName": "Application"}
          and rc["workflows"][0]["steps"] == [{"uses": "disable-user", "after": "35d"}]
          and "conditional-credential" not in json.dumps(rc["browser_flow"])
          and "stig_disabled_by" not in json.dumps(rc["user_profile_attributes"]), sorted(keys))
pk, _ = load({"realm": {"name": "defconai"}, "auth_mode": "cac_or_mfa", "registration_flow": "deny"})
check("registration_flow=deny can be chosen for any realm", K.render(pk)["registration_flow"][0] == "STIG Registration - Deny")

# ---- extra-realm profiles (cac-config.py)
CC = os.path.join(ROOT, "keycloak-cac", "bin", "cac-config.py")
main = K.deep_merge(K.DEFAULTS, {"realm": {"name": "defconai"}, "auth_mode": "cac", "lockout": {"permanent": False},
                                 "users": [{"username": "main.user", "cac_upn": "1@mil"}],
                                 "clients": [{"client_id": "main-app", "redirect_uris": ["https://m/cb"]}],
                                 "admin": {"users": [{"username": "op", "alt_token_upn": "2@mil"}]}})
mainp = prof(main, "main.json")
def extra(files, clients=None):
    d = tempfile.mkdtemp(dir=T); out = tempfile.mkdtemp(dir=T); cd = tempfile.mkdtemp(dir=T)
    for n, obj in files.items():
        json.dump(obj, open(os.path.join(d, n), "w"))
    for realm, objs in (clients or {}).items():
        os.makedirs(os.path.join(cd, realm)); json.dump(objs, open(os.path.join(cd, realm, "c.json"), "w"))
    env = dict(os.environ, CAC_EXTRA_REALM_PROFILES=d, CAC_CLIENTS_DIR=cd, PYTHONPATH=os.path.join(ROOT, "keycloak-asd-stig", "scripts"))
    r = subprocess.run([sys.executable, CC, "extra-profiles", out, mainp], env=env, capture_output=True, text=True)
    return r, out
r1, out = extra({"10-partners.json": base}, {"partners": {"client_id": "partner-app", "redirect_uris": ["https://p/cb"]}})
lines = [l.split() for l in r1.stdout.splitlines() if l.strip()]
check("an extra realm profile renders (realm, profile path, its own clients dir)", r1.returncode == 0 and len(lines) == 1
      and lines[0][0] == "partners" and lines[0][2].endswith("/partners"), (r1.stderr or "")[-200:])
if r1.returncode == 0 and lines:
    ep = json.load(open(lines[0][1]))
    check("... merged over the main profile: lockout kept, users/clients/admins not inherited",
          ep["lockout"]["permanent"] is False and ep["users"] == [] and ep["clients"] == [] and ep["admin"]["users"] == []
          and ep["auth_mode"] == "passkey" and ep["realm"]["name"] == "partners")
    check("... written mode 0600", oct(os.stat(lines[0][1]).st_mode & 0o777) == "0o600")
for label, files, needle in [
        ("an extra realm named like the main realm is refused", {"a.json": {"realm": {"name": "defconai"}}}, "main realm"),
        ("an extra realm named master is refused", {"a.json": {"realm": {"name": "Master"}}}, "master"),
        ("two profiles for one realm are refused", {"a.json": base, "b.json": base}, "already defined"),
        ("an extra realm may not set keycloak", {"a.json": dict(base, keycloak={"url": "https://x"})}, "keycloak"),
        ("an extra realm may not set admin", {"a.json": dict(base, admin={"users": []})}, "admin"),
        ("an invalid realm name is refused", {"a.json": {"realm": {"name": "a/b"}}}, "realm.name"),
        ("an extra profile with an invalid WebAuthn name is refused", {"a.json": K.deep_merge(base, {"webauthn": {"algorithms": ["EdDSA"]}})}, "Ed25519")]:
    rr, _ = extra(files)
    check(label, rr.returncode != 0 and needle in rr.stderr, rr.stderr.strip()[-120:])
rn, _ = extra({})
check("no extra profile: nothing printed, success", rn.returncode == 0 and not rn.stdout.strip())
sys.exit(0 if all(res) else 1)
PY

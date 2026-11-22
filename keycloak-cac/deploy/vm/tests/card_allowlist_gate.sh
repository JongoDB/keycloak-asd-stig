#!/usr/bin/env bash
# The allowlist gate on the CARD path, with the DEPLOYED image (production trusts only DoD PKI, so a test card cannot
# reach the live realm). Runs ON the VM as root: a throwaway container of the live image in lab mode (mock PKI,
# dev-file database), no published port; the checks run inside its network namespace. For a card holder who becomes
# an administrator (realm-admin) without being on the realm's allowlist (master attribute stig.admin-allowlist.<realm>):
#   (b) the access token it obtained BEFORE the promotion gets 403 on its first admin-API request, and an access token
#       minted afterwards from the old refresh token gets 403 too (or the refresh is refused)
#   (a) a fresh card sign-in is refused: no authorization code, so no token is ever issued
#   (c) its existing SSO session (cookie) gets no code either
#   fail closed: the realm enforced by configuration (STIG_ALLOWLIST_ENFORCED_REALMS) and its allowlist attribute
#       removed -> the administrator's card is refused
#   control: the same holder, put on the allowlist, signs in with the card and reaches the admin API (200)
#   sudo ./card_allowlist_gate.sh [skill dir]
set -euo pipefail
S=/srv/idp
SKILL="${1:-$(ls -td $S/src/keycloak-asd-stig-*/keycloak-asd-stig | head -1)}"
IMG=$(grep -E "^KEYCLOAK_(ADMIN_)?IMAGE=" $S/compose/.env | head -1 | cut -d= -f2)
NAME="idp-card-gate-$$"; T="$(mktemp -d)"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$T"; }; trap cleanup EXIT
BPW="$(openssl rand -hex 16)"
docker run -d --name "$NAME" -e CAC_LAB_MODE=true -e KC_DB=dev-file -e CAC_AUTH_MODE=cac_or_mfa \
  -e CAC_PUBLIC_URL="https://localhost:8443" -e KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -hex 16)" -e CAC_AUTOMATION_SECRET="$BPW" \
  -e STIG_ALLOWLIST_ENFORCED_REALMS=dod-cac "$IMG" >/dev/null
for i in $(seq 1 120); do
  docker exec "$NAME" /opt/keycloak-cac/bin/cac-entrypoint.sh health >/dev/null 2>&1 && break
  docker inspect -f '{{.State.Running}}' "$NAME" | grep -q true || { docker logs "$NAME" 2>&1 | tail -20; echo "FAIL container stopped"; exit 1; }
  sleep 5
done
L=/opt/keycloak/data/cac/lab
for f in ca/root.crt users/doe.john.crt users/doe.john.key; do docker exec "$NAME" cat "$L/$f" > "$T/$(basename "$f")"; done
echo "image: $IMG"
BPW="$BPW" python3 - "$SKILL/scripts" "$T" "$NAME" <<'PY'
import argparse, json, os, ssl, subprocess, sys, time, urllib.error, urllib.parse, urllib.request, uuid
sys.path.insert(0, sys.argv[1]); import e2e_check as E
T, NAME = sys.argv[2], sys.argv[3]
pid = subprocess.run(["docker", "inspect", "-f", "{{.State.Pid}}", NAME], capture_output=True, text=True, check=True).stdout.strip()
fd = os.open("/proc/%s/ns/net" % pid, os.O_RDONLY); os.setns(fd, os.CLONE_NEWNET); os.close(fd)   # master answers only here
BASE, REALM = "https://localhost:8443", "dod-cac"; RED = BASE + "/admin/%s/console/" % REALM
CTX = ssl.create_default_context(cafile=T + "/root.crt")
res = []
def check(n, ok, d=""): res.append(bool(ok)); print("%s  %-74s %s" % ("PASS" if ok else "FAIL", n, d), flush=True)
def http(method, url, body=None, tok=None, form=False):
    h = {"Authorization": "Bearer " + tok} if tok else {}
    if body is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        body = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, body, h, method=method), context=CTX, timeout=60) as r:
            t = r.read().decode(); return r.status, (json.loads(t) if t.strip()[:1] in ("[", "{") else t)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]
st, tk = http("POST", BASE + "/realms/master/protocol/openid-connect/token", {"grant_type": "client_credentials",
              "client_id": "stig-automation", "client_secret": os.environ["BPW"]}, form=True)
if st != 200: sys.exit("no master token: %s %s" % (st, tk))
ADM = tk["access_token"]
def adm(method, path, body=None): return http(method, BASE + "/admin/realms" + path, body, ADM)
def set_allowlist(ids):
    """The ids, and each one's entry: the realm-management roles it holds now (effective names)."""
    m = adm("GET", "/master")[1]; at = m.get("attributes") or {}
    if ids is None:
        at.pop("stig.admin-allowlist." + REALM, None); at.pop("stig.admin-allowlist-roles." + REALM, None)
    else:
        at["stig.admin-allowlist." + REALM] = ",".join(ids)
        ent = []
        for i in ids:
            st_, rl = adm("GET", "/%s/users/%s/role-mappings/clients/%s/composite" % (REALM, i, rmc))
            ent.append("%s=%s" % (i, ",".join(sorted(r["name"] for r in rl)) if st_ == 200 and rl else "none"))
        at["stig.admin-allowlist-roles." + REALM] = ";".join(ent)
    return adm("PUT", "/master", {"attributes": at})[0]
fl = E.Flow(argparse.Namespace(url=BASE, realm=REALM, client="security-admin-console", redirect=RED, admin_url=None, client_secret=None, cacert=T + "/root.crt"))
def card():
    b, final, seen, _, ver = E.cac_login(fl, T + "/doe.john.crt", T + "/doe.john.key")
    code = urllib.parse.parse_qs(urllib.parse.urlparse(final).query).get("code", [None])[0] if final and "code=" in final else None
    return b, code, seen, ver
def admin_api(at):
    st_, b_ = http("GET", BASE + "/admin/realms/%s/users?max=1" % REALM, tok=at)
    return st_ if st_ != 403 else ("403 allowlist" if "not allowed" in str(b_) else 403)

john = adm("GET", "/%s/users?username=doe.john&exact=true" % REALM)[1][0]
rmc = adm("GET", "/%s/clients?clientId=realm-management" % REALM)[1][0]["id"]
ra = adm("GET", "/%s/clients/%s/roles/realm-admin" % (REALM, rmc))[1]
sac = adm("GET", "/%s/clients?clientId=security-admin-console" % REALM)[1][0]   # its tokens carry realm-management roles (as production's)
adm("POST", "/%s/clients/%s/scope-mappings/clients/%s" % (REALM, sac["id"], rmc), adm("GET", "/%s/clients/%s/roles" % (REALM, rmc))[1])
check("setup: the realm enforces an allowlist that does not hold doe.john", set_allowlist([str(uuid.uuid4())]) == 204)
b0, code0, seen0, ver0 = card()
tok0 = fl.token(code0, ver0) if code0 else None
check("setup: doe.john (not an administrator) signs in with the card, holds tokens and an SSO session", bool(tok0), "%s" % seen0)
check("setup: ... and its token is refused by the admin API while not an administrator", tok0 and admin_api(tok0["access_token"]) in (403, "403 allowlist"))
st_p = adm("POST", "/%s/users/%s/role-mappings/clients/%s" % (REALM, john["id"], rmc), [ra])[0]
check("setup: doe.john made realm-admin directly (as a console promotion would)", st_p == 204, "HTTP %s" % st_p)
since = int(time.time())
check("(b) the access token obtained BEFORE the promotion: first admin-API request -> 403 (by the allowlist filter)",
      admin_api(tok0["access_token"]) == "403 allowlist")
st_r, nt = http("POST", BASE + "/realms/%s/protocol/openid-connect/token" % REALM, {"grant_type": "refresh_token",
                "client_id": "security-admin-console", "refresh_token": tok0["refresh_token"]}, form=True)
st_n = admin_api(nt["access_token"]) if st_r == 200 else "refresh refused %s" % st_r
check("(b) an access token minted AFTER the promotion from the old refresh token -> 403 (by the allowlist filter)",
      st_n in ("403 allowlist", "refresh refused 400", "refresh refused 401"), "%s" % st_n)
u1, v1 = fl.auth_url(); k1, l1, p1 = b0.go(u1, None, RED)
f1, s1 = fl.finish(b0, k1, l1, p1, {}) if k1 != "redirect" else (l1, [])
check("(c) its existing SSO session (cookie): no authorization code", not (f1 and "code=" in f1), "%s" % (s1 or k1))
_, code1, seen1, _ = card()
check("(a) a fresh card sign-in: refused, no authorization code (no token issued)", code1 is None, "%s" % seen1)
time.sleep(2)
logs = subprocess.run(["docker", "logs", "--since", str(since), NAME], capture_output=True, text=True); logs = logs.stdout + logs.stderr
print("\n".join(l[:300] for l in logs.splitlines() if "NOT-ALLOWLISTED" in l or "LOGIN_ERROR" in l))
check("... logged STIG-ADMIN-NOT-ALLOWLISTED for the card path and the admin API", "path=card" in logs and "path=admin-api" in logs)
check("enforced realm: the allowlist attribute REMOVED", set_allowlist(None) == 204)
_, code_m, seen_m, _ = card()
check("(fail closed) with the realm enforced by configuration and no allowlist at all: the administrator's card is refused",
      code_m is None, "%s" % seen_m)
check("control: doe.john put on the allowlist", set_allowlist([john["id"]]) == 204)
_, code2, seen2, ver2 = card()
tok2 = fl.token(code2, ver2) if code2 else None
check("control: ... signs in with the card and reaches the admin API (200)", bool(tok2) and admin_api(tok2["access_token"]) == 200, "%s" % seen2)
print("\n%d/%d passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)
PY

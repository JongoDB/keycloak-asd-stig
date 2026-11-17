"""Minimal OIDC relying party for an ASD STIG-hardened Keycloak: Flask + Authlib.

Authorization code + PKCE S256 + nonce, private_key_jwt (or a client secret read from a file), roles from the
access token, 15-minute local idle / 8-hour absolute session, RP-initiated logout (POST, same-origin only) and
back-channel logout. The browser cookie carries only an opaque session id; tokens, roles and the login-in-progress
state (PKCE verifier, nonce) stay on the server.
Configuration (env): see ../README.md. Run: python app.py   (or any WSGI server)
"""
import base64
import ipaddress
import json
import os
import secrets
import threading
import time
from functools import wraps
from urllib.parse import urlencode, urlsplit

from authlib.integrations.flask_client import OAuth
from authlib.oauth2.rfc7523 import PrivateKeyJWT
from flask import Flask, jsonify, redirect, request, session
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey
from werkzeug.middleware.proxy_fix import ProxyFix

ISSUER = os.environ["OIDC_ISSUER"]              # https://idp.example.mil/realms/<realm> - from the operator
CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
BASE = os.environ["APP_BASE_URL"].rstrip("/")   # public base URL, = root_url in client-request.json
APP_ORIGIN = "%s://%s" % urlsplit(BASE)[:2]
IDLE = float(os.environ.get("SESSION_IDLE_MINUTES", "15")) * 60     # <= the IdP's idle (10 for admin apps)
MAX_AGE = float(os.environ.get("SESSION_MAX_HOURS", "8")) * 3600    # <= the IdP's SSO max lifespan
PENDING_TTL = 600                                                   # an unfinished login expires after 10 minutes
MAX_PENDING = int(os.environ.get("MAX_PENDING_LOGINS", "1000"))     # logins in progress held; beyond it the oldest is dropped
PER_IP = int(os.environ.get("LOGIN_RATE_PER_IP", "30"))             # login starts per client IP (IPv6: per /64) per 10 minutes
SECURE = BASE.startswith("https://")
BCL_EVENT = "http://schemas.openid.net/event/backchannel-logout"
ALGS = ["RS256", "PS256", "ES256"]


def read_file(var):
    with open(os.environ[var]) as f:
        return f.read().strip()


def audit(event, **kw):
    print(json.dumps(dict(event=event, **kw)), flush=True)


app = Flask(__name__)
app.secret_key = read_file("SESSION_SECRET_FILE")
app.config.update(SESSION_COOKIE_NAME="__Host-session" if SECURE else "session", SESSION_COOKIE_SECURE=SECURE,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")   # session.permanent stays False
if os.environ.get("TRUST_PROXY") == "1":     # only behind your own TLS-terminating proxy that overwrites X-Forwarded-*
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


class TTLCache:
    """Server-side store for Authlib's login-in-progress state, so the cookie holds only a marker. Bounded and
    expiring: when full, the oldest unfinished login is dropped (never a refusal, so a flood of anonymous /login
    requests cannot lock real users out). Use Redis or a database when running more than one replica."""
    def __init__(self, cap):
        self.cap, self.d, self.lock = cap, {}, threading.Lock()

    def _sweep(self, now):
        for k in [k for k, (_, exp) in self.d.items() if exp < now]:
            del self.d[k]

    def get(self, key):
        with self.lock:
            v = self.d.get(key)
            return v[0] if v and v[1] >= time.time() else None

    def set(self, key, value, expires=None):
        now = time.time()
        with self.lock:
            self._sweep(now)
            self.d.pop(key, None)
            while len(self.d) >= self.cap:                  # dicts keep insertion order: the first is the oldest
                del self.d[next(iter(self.d))]
            self.d[key] = (value, now + min(expires or PENDING_TTL, PENDING_TTL))

    def delete(self, key):
        with self.lock:
            self.d.pop(key, None)


# --- client authentication: private_key_jwt (preferred) or a secret from a file ----------------------------
oauth = OAuth(app, cache=TTLCache(MAX_PENDING))
kwargs = {"scope": "openid", "code_challenge_method": "S256"}
common = dict(client_id=CLIENT_ID, server_metadata_url=ISSUER + "/.well-known/openid-configuration")
if os.environ.get("OIDC_PRIVATE_KEY_FILE"):
    KID = os.environ["OIDC_KEY_ID"]
    PRIVATE = RSAKey.import_key(read_file("OIDC_PRIVATE_KEY_FILE"), {"kid": KID})
    PUBLIC_JWKS = {"keys": [dict(PRIVATE.as_dict(private=False), kid=KID, alg="RS256", use="sig")]}
    oauth.register("idp", client_secret=PRIVATE, client_kwargs=dict(kwargs, token_endpoint_auth_method="private_key_jwt"),
                   client_auth_methods=[PrivateKeyJWT(headers={"kid": KID})], **common)
else:
    PUBLIC_JWKS = {"keys": []}
    oauth.register("idp", client_secret=read_file("OIDC_CLIENT_SECRET_FILE"), client_kwargs=kwargs, **common)
idp = oauth.idp

# Server-side sessions: local session id -> record. The cookie holds only {"lsid": ...}.
LIVE = {}
LOCK = threading.Lock()


def sweep(now):
    """Drop sessions past their idle or absolute limit (also those nobody comes back to)."""
    for k in [k for k, v in LIVE.items() if now - v["last_seen"] > IDLE or now - v["login_at"] > MAX_AGE]:
        audit("session_timeout", user=LIVE[k]["user"]["sub"], sid=LIVE[k]["sid"])
        del LIVE[k]


# --- JWKS for verifying access and logout tokens: refetch only for an unknown kid, at most once a minute -----
_jwks = {"set": None, "fetched": 0.0}
JWKS_COOLDOWN = 60


def _kid(token):
    head = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))).get("kid")


def key_set_for(token):
    kid = _kid(token)
    with LOCK:
        ks = _jwks["set"]
        known = ks is not None and any(k.kid == kid for k in ks.keys)
        if not known and time.time() - _jwks["fetched"] >= JWKS_COOLDOWN:
            ks = _jwks["set"] = KeySet.import_key_set(idp.fetch_jwk_set(force=True))
            _jwks["fetched"] = time.time()
    if ks is None:
        raise ValueError("no JWKS")
    return ks


def verify_jwt(token, header_typ=None, **claims):
    tok = jwt.decode(token, key_set_for(token), algorithms=ALGS)
    if header_typ is not None and tok.header.get("typ") != header_typ:
        raise ValueError("unexpected token type %r" % tok.header.get("typ"))
    reg = jwt.JWTClaimsRegistry(leeway=60, iss={"essential": True, "value": idp.load_server_metadata()["issuer"]},
                                exp={"essential": True}, **{k: {"essential": True, "value": v} for k, v in claims.items()})
    reg.validate(tok.claims)
    return tok.claims


def current():
    """The caller's live session record, after the idle and absolute limits; None if there is none."""
    lsid = session.get("lsid")
    if not lsid:
        return None
    now = time.time()
    with LOCK:
        sweep(now)
        rec = LIVE.get(lsid)
        if rec is None:                 # timed out, logged out, or ended by back-channel logout
            session.clear()
            return None
        rec["last_seen"] = now
        return rec


def login_required(role=None):
    def deco(f):
        @wraps(f)
        def inner(*a, **kw):
            rec = current()
            if not rec:
                return jsonify(error="login required"), 401
            if role and role not in rec["user"]["roles"]:
                audit("forbidden", user=rec["user"]["sub"], role=role, path=request.path)
                return jsonify(error="role %s required" % role), 403
            return f(rec, *a, **kw)
        return inner
    return deco


def same_origin():
    """CSRF check for state-changing requests: the browser's Origin (or Referer) must be this app's origin."""
    src = request.headers.get("Origin") or request.headers.get("Referer") or ""
    return src != "null" and "%s://%s" % urlsplit(src)[:2] == APP_ORIGIN


# Per-client limit on login starts: 429 beyond LOGIN_RATE_PER_IP in 10 minutes. request.remote_addr honours
# TRUST_PROXY through ProxyFix. IPv6 clients are counted per /64, so rotating addresses inside one prefix does not
# reset the count. The table itself is bounded (oldest bucket dropped).
LOGIN_STARTS = {}            # bucket -> timestamps within PENDING_TTL, least recently used first
MAX_BUCKETS = 10 * MAX_PENDING


def ip_bucket(ip):
    try:
        a = ipaddress.ip_address((ip or "").split("%")[0])
    except ValueError:
        return ip or "?"
    if a.version == 6 and a.ipv4_mapped:
        return str(a.ipv4_mapped)
    return str(ipaddress.ip_network("%s/64" % a, strict=False)) if a.version == 6 else str(a)


def admit_login(ip, now):
    key = ip_bucket(ip)
    with LOCK:
        mine = [t for t in LOGIN_STARTS.pop(key, []) if now - t < PENDING_TTL]
        if len(mine) >= PER_IP:
            LOGIN_STARTS[key] = mine
            return False
        LOGIN_STARTS[key] = mine + [now]
        while len(LOGIN_STARTS) > MAX_BUCKETS:
            del LOGIN_STARTS[next(iter(LOGIN_STARTS))]
        return True


@app.get("/login")
def login():
    if not admit_login(request.remote_addr, time.time()):
        audit("login_throttled", ip=ip_bucket(request.remote_addr))
        return "Too many sign-in attempts. Try again shortly.", 429, {"Retry-After": "60"}
    # Authlib adds state, nonce and the PKCE S256 challenge; the verifier and nonce go to the server-side cache.
    return idp.authorize_redirect(BASE + "/oauth2/callback")


@app.get("/oauth2/callback")
def callback():
    # Checks state, sends the PKCE verifier, and validates the ID token: signature (JWKS), iss, aud, exp, nonce.
    token = idp.authorize_access_token()
    claims = token["userinfo"]
    at = verify_jwt(token["access_token"], azp=CLIENT_ID, sub=claims["sub"])   # roles live in the access token
    roles = at.get("resource_access", {}).get(CLIENT_ID, {}).get("roles", [])
    session.clear()                                  # drop the login-in-progress marker; new local session id
    lsid, now = secrets.token_urlsafe(32), time.time()
    with LOCK:
        sweep(now)
        LIVE[lsid] = {"sid": claims.get("sid"), "login_at": now, "last_seen": now, "id_token": token["id_token"],
                      "user": {"sub": claims["sub"], "sid": claims.get("sid"), "roles": roles,
                               "username": claims.get("preferred_username"),
                               "previousLogin": claims.get("previous_login")}}
    session["lsid"] = lsid
    audit("login", user=claims["sub"], sid=claims.get("sid"))
    return redirect("/")


@app.get("/")
def index():
    if current():
        return ('<a href="/me">me</a> <form method="post" action="/logout" style="display:inline">'
                '<button>Log off</button></form>')
    return '<a href="/login">Log in</a>'


@app.get("/me")
@login_required()
def me(rec):
    return jsonify(rec["user"])          # show previousLogin in the UI (V-222437)


@app.get("/approve")
@login_required("approver")
def approve(rec):
    return jsonify(ok=True)


@app.post("/logout")
def logout():
    if not same_origin():
        return jsonify(error="cross-origin logout refused"), 403
    lsid = session.get("lsid")
    with LOCK:
        rec = LIVE.pop(lsid, None) if lsid else None
    session.clear()
    if not rec:
        return redirect("/logged-out", 303)
    audit("logout", user=rec["user"]["sub"], sid=rec["sid"])
    end = idp.load_server_metadata()["end_session_endpoint"]
    return redirect(end + "?" + urlencode({"id_token_hint": rec["id_token"],
                                           "post_logout_redirect_uri": BASE + "/logged-out"}), 303)


@app.get("/logged-out")
def logged_out():
    return "You have been logged off. Close the browser to end any remaining sessions."


@app.post("/oauth2/backchannel-logout")
def backchannel_logout():
    try:
        c = verify_jwt(request.form.get("logout_token", ""), header_typ="logout+jwt", aud=CLIENT_ID)
        now = time.time()
        if (BCL_EVENT not in (c.get("events") or {}) or "nonce" in c or c.get("typ", "Logout") != "Logout"
                or not (c.get("sid") or c.get("sub"))
                or not isinstance(c.get("iat"), (int, float)) or c["iat"] > now + 60 or now - c["iat"] > 120):
            raise ValueError("not a fresh logout token")
    except Exception:
        return jsonify(error="invalid_request"), 400, {"Cache-Control": "no-store"}
    sid, sub = c.get("sid"), c.get("sub")
    with LOCK:
        # sid names one IdP session; a token with only sub ends every session of that user.
        gone = [k for k, v in LIVE.items() if (v["sid"] == sid if sid else v["user"]["sub"] == sub)]
        for k in gone:
            del LIVE[k]
    audit("backchannel_logout", user=sub, sid=sid, sessions=len(gone))
    return "", 200, {"Cache-Control": "no-store"}


@app.get("/.well-known/jwks.json")
def jwks():
    return jsonify(PUBLIC_JWKS)               # public keys only


@app.errorhandler(Exception)
def failed(e):
    if hasattr(e, "code") and isinstance(e.code, int) and e.code < 500:
        return e
    audit("error", message=str(e))
    return "Sign-in failed. Try again or contact the help desk.", 500


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "3000")))

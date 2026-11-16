"""Minimal OIDC relying party for an ASD STIG-hardened Keycloak: Flask + Authlib.

Authorization code + PKCE S256 + nonce, private_key_jwt (or a client secret read from a file), roles from the
access token, 15-minute local idle / 8-hour absolute session, RP-initiated and back-channel logout.
Configuration (env): see ../README.md. Run: flask --app app run   (or any WSGI server)
"""
import json
import os
import secrets
import threading
import time
from functools import wraps
from urllib.parse import urlencode

from authlib.integrations.flask_client import OAuth
from authlib.oauth2.rfc7523 import PrivateKeyJWT
from flask import Flask, jsonify, redirect, request, session
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey
from werkzeug.middleware.proxy_fix import ProxyFix

ISSUER = os.environ["OIDC_ISSUER"]              # https://idp.example.mil/realms/<realm> - from the operator
CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
BASE = os.environ["APP_BASE_URL"].rstrip("/")   # public base URL, = root_url in client-request.json
IDLE = float(os.environ.get("SESSION_IDLE_MINUTES", "15")) * 60     # <= the IdP's idle (10 for admin apps)
MAX_AGE = float(os.environ.get("SESSION_MAX_HOURS", "8")) * 3600    # <= the IdP's SSO max lifespan
SECURE = BASE.startswith("https://")
BCL_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def read_file(var):
    with open(os.environ[var]) as f:
        return f.read().strip()


app = Flask(__name__)
app.secret_key = read_file("SESSION_SECRET_FILE")
app.config.update(SESSION_COOKIE_NAME="__Host-session" if SECURE else "session", SESSION_COOKIE_SECURE=SECURE,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")   # session.permanent stays False
if os.environ.get("TRUST_PROXY") == "1":     # only behind your own TLS-terminating proxy
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# --- client authentication: private_key_jwt (preferred) or a secret from a file ----------------------------
oauth = OAuth(app)
kwargs = {"scope": "openid", "code_challenge_method": "S256"}
if os.environ.get("OIDC_PRIVATE_KEY_FILE"):
    KID = os.environ["OIDC_KEY_ID"]
    PRIVATE = RSAKey.import_key(read_file("OIDC_PRIVATE_KEY_FILE"), {"kid": KID})
    PUBLIC_JWKS = {"keys": [dict(PRIVATE.as_dict(private=False), kid=KID, alg="RS256", use="sig")]}
    kwargs["token_endpoint_auth_method"] = "private_key_jwt"
    oauth.register("idp", client_id=CLIENT_ID, client_secret=PRIVATE,
                   server_metadata_url=ISSUER + "/.well-known/openid-configuration", client_kwargs=kwargs,
                   client_auth_methods=[PrivateKeyJWT(headers={"kid": KID})])
else:
    PUBLIC_JWKS = {"keys": []}
    oauth.register("idp", client_id=CLIENT_ID, client_secret=read_file("OIDC_CLIENT_SECRET_FILE"),
                   server_metadata_url=ISSUER + "/.well-known/openid-configuration", client_kwargs=kwargs)
idp = oauth.idp

# Server-side record of live logins. Flask's session is a signed cookie, so the server must hold what a
# back-channel logout (which arrives without the user's cookie) can revoke. Use Redis or a DB with replicas.
LIVE = {}            # local session id -> {"sid", "login_at", "last_seen"}
LOCK = threading.Lock()


def audit(event, **kw):
    print(json.dumps(dict(event=event, **kw)), flush=True)


def verify_jwt(token, **claims):
    key_set = KeySet.import_key_set(idp.fetch_jwk_set())
    try:
        tok = jwt.decode(token, key_set, algorithms=["RS256", "PS256", "ES256"])
    except Exception:
        tok = jwt.decode(token, KeySet.import_key_set(idp.fetch_jwk_set(force=True)), algorithms=["RS256", "PS256", "ES256"])
    reg = jwt.JWTClaimsRegistry(iss={"essential": True, "value": idp.load_server_metadata()["issuer"]},
                                exp={"essential": True}, **{k: {"essential": True, "value": v} for k, v in claims.items()})
    reg.validate(tok.claims)
    return tok.claims


@app.before_request
def enforce_session_limits():
    lsid = session.get("lsid")
    if not lsid:
        return
    now = time.time()
    with LOCK:
        rec = LIVE.get(lsid)
        if rec and (now - rec["last_seen"] > IDLE or now - rec["login_at"] > MAX_AGE):
            LIVE.pop(lsid, None)
            audit("session_timeout", user=session.get("user", {}).get("sub"), sid=rec["sid"])
            rec = None
        if rec is None:                    # timed out, or ended by back-channel logout
            session.clear()
            return redirect("/logged-out?reason=ended") if request.path not in ("/logged-out",) else None
        rec["last_seen"] = now


def login_required(role=None):
    def deco(f):
        @wraps(f)
        def inner(*a, **kw):
            user = session.get("user")
            if not user:
                return jsonify(error="login required"), 401
            if role and role not in user["roles"]:
                return jsonify(error="role %s required" % role), 403
            return f(*a, **kw)
        return inner
    return deco


@app.get("/login")
def login():
    # Authlib adds state, nonce and the PKCE S256 challenge, and keeps the verifier in the session.
    return idp.authorize_redirect(BASE + "/oauth2/callback")


@app.get("/oauth2/callback")
def callback():
    # Checks state, sends the PKCE verifier, and validates the ID token: signature (JWKS), iss, aud, exp, nonce.
    token = idp.authorize_access_token()
    claims = token["userinfo"]
    at = verify_jwt(token["access_token"], azp=CLIENT_ID, sub=claims["sub"])   # roles live in the access token
    roles = at.get("resource_access", {}).get(CLIENT_ID, {}).get("roles", [])
    session.clear()                                  # drop the login-in-progress state; new local session id
    lsid, now = secrets.token_urlsafe(32), time.time()
    with LOCK:
        LIVE[lsid] = {"sid": claims.get("sid"), "login_at": now, "last_seen": now}
    session.update(lsid=lsid, id_token=token["id_token"],
                   user={"sub": claims["sub"], "sid": claims.get("sid"), "username": claims.get("preferred_username"),
                         "roles": roles, "previousLogin": claims.get("previous_login")})
    audit("login", user=claims["sub"], sid=claims.get("sid"))
    return redirect("/")


@app.get("/")
def index():
    return '<a href="/me">me</a> <a href="/logout">Log off</a>' if session.get("user") else '<a href="/login">Log in</a>'


@app.get("/me")
@login_required()
def me():
    return jsonify(session["user"])          # show previousLogin in the UI (V-222437)


@app.get("/approve")
@login_required("approver")
def approve():
    return jsonify(ok=True)


@app.get("/logout")
def logout():
    id_token, lsid = session.get("id_token"), session.get("lsid")
    audit("logout", user=session.get("user", {}).get("sub"))
    with LOCK:
        LIVE.pop(lsid, None)
    session.clear()
    if not id_token:
        return redirect("/logged-out")
    end = idp.load_server_metadata()["end_session_endpoint"]
    return redirect(end + "?" + urlencode({"id_token_hint": id_token, "post_logout_redirect_uri": BASE + "/logged-out"}))


@app.get("/logged-out")
def logged_out():
    return "You have been logged off. Close the browser to end any remaining sessions."


@app.post("/oauth2/backchannel-logout")
def backchannel_logout():
    try:
        c = verify_jwt(request.form.get("logout_token", ""), aud=CLIENT_ID)
        if BCL_EVENT not in c.get("events", {}) or "nonce" in c or not (c.get("sid") or c.get("sub")):
            raise ValueError("not a logout token")
        if abs(time.time() - c.get("iat", 0)) > 120:
            raise ValueError("stale logout token")
    except Exception:
        return jsonify(error="invalid_request"), 400, {"Cache-Control": "no-store"}
    with LOCK:
        gone = [k for k, v in LIVE.items() if v["sid"] == c.get("sid")]
        for k in gone:
            del LIVE[k]
    audit("backchannel_logout", user=c.get("sub"), sid=c.get("sid"), sessions=len(gone))
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

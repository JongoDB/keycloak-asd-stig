// Minimal OIDC relying party for an ASD STIG-hardened Keycloak: Express + openid-client v6 + jose.
// Authorization code + PKCE S256 + nonce, private_key_jwt (or a client secret read from a file), roles from the
// access token, 15-minute local idle / 8-hour absolute session, RP-initiated and back-channel logout.
// Configuration (env): see ../README.md. Node >= 20.
import crypto from 'node:crypto';
import fs from 'node:fs';
import express from 'express';
import session from 'express-session';
import * as client from 'openid-client';
import * as jose from 'jose';

const env = (k, d) => process.env[k] ?? d;
const ISSUER = env('OIDC_ISSUER');                      // https://idp.example.mil/realms/<realm> - from the operator
const CLIENT_ID = env('OIDC_CLIENT_ID');
const BASE = env('APP_BASE_URL').replace(/\/$/, '');    // public base URL, = root_url in client-request.json
const IDLE_MS = Number(env('SESSION_IDLE_MINUTES', '15')) * 60_000;   // <= the IdP's idle (10 for admin apps)
const MAX_MS = Number(env('SESSION_MAX_HOURS', '8')) * 3_600_000;     // <= the IdP's SSO max lifespan
const SECURE = BASE.startsWith('https://');             // always true outside a loopback dev setup
const REDIRECT_URI = `${BASE}/oauth2/callback`;
const POST_LOGOUT_URI = `${BASE}/logged-out`;

// --- client authentication: private_key_jwt (preferred) or a secret from a file -----------------------------
let clientAuth, publicJwks = { keys: [] };
if (process.env.OIDC_PRIVATE_KEY_FILE) {
  const pem = fs.readFileSync(process.env.OIDC_PRIVATE_KEY_FILE, 'utf8');
  const kid = env('OIDC_KEY_ID');
  const key = await jose.importPKCS8(pem, 'RS256');
  clientAuth = client.PrivateKeyJwt({ key, kid });
  const pub = await jose.exportJWK(crypto.createPublicKey(pem));
  publicJwks = { keys: [{ ...pub, kid, alg: 'RS256', use: 'sig' }] };
} else {
  const secret = fs.readFileSync(env('OIDC_CLIENT_SECRET_FILE'), 'utf8').trim();
  clientAuth = client.ClientSecretBasic(secret);
}

const config = await client.discovery(new URL(ISSUER), CLIENT_ID, undefined, clientAuth);
const meta = config.serverMetadata();
const jwks = jose.createRemoteJWKSet(new URL(meta.jwks_uri));

// Back-channel logout arrives without the user's cookie: remember which local sessions belong to which IdP
// session (sid). Use a shared store (Redis, DB) for both maps when running more than one replica.
const store = new session.MemoryStore();
const sessionsBySid = new Map();

const app = express();
if (env('TRUST_PROXY', '0') === '1') app.set('trust proxy', 1);   // only behind your own TLS-terminating proxy
app.use(session({
  store, name: SECURE ? '__Host-sid' : 'sid', secret: fs.readFileSync(env('SESSION_SECRET_FILE'), 'utf8').trim(),
  resave: false, saveUninitialized: false, rolling: false,
  cookie: { httpOnly: true, secure: SECURE, sameSite: 'lax', path: '/' },   // no maxAge: a browser-session cookie
}));

// Idle and absolute limits, enforced on every request.
app.use((req, res, next) => {
  const s = req.session;
  if (s.user) {
    const now = Date.now();
    if (now - s.lastSeen > IDLE_MS || now - s.loginAt > MAX_MS) {
      console.log(JSON.stringify({ event: 'session_timeout', user: s.user.sub, sid: s.user.sid }));
      return s.destroy(() => res.redirect('/logged-out?reason=timeout'));
    }
    s.lastSeen = now;
  }
  next();
});

const requireLogin = (req, res, next) => (req.session.user ? next() : res.status(401).json({ error: 'login required' }));
const requireRole = (role) => (req, res, next) =>
  req.session.user?.roles.includes(role) ? next() : res.status(403).json({ error: `role ${role} required` });

app.get('/login', async (req, res) => {
  const verifier = client.randomPKCECodeVerifier();
  req.session.oidc = { verifier, nonce: client.randomNonce(), state: client.randomState() };
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT_URI, scope: 'openid', state: req.session.oidc.state, nonce: req.session.oidc.nonce,
    code_challenge: await client.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256',
  });
  res.redirect(url.href);
});

app.get('/oauth2/callback', async (req, res, next) => {
  try {
    const o = req.session.oidc;
    if (!o) return res.status(400).send('no login in progress');
    // Validates state, PKCE, and the ID token: signature (JWKS), iss, aud, exp, iat, nonce.
    const tokens = await client.authorizationCodeGrant(config, new URL(req.originalUrl, BASE), {
      pkceCodeVerifier: o.verifier, expectedNonce: o.nonce, expectedState: o.state, idTokenExpected: true,
    });
    const claims = tokens.claims();
    // Client roles are in the access token; verify it before trusting them.
    const { payload: at } = await jose.jwtVerify(tokens.access_token, jwks, { issuer: meta.issuer });
    if (at.azp !== CLIENT_ID || at.sub !== claims.sub) throw new Error('access token not issued to this client');
    const roles = at.resource_access?.[CLIENT_ID]?.roles ?? [];
    req.session.regenerate((err) => {                    // new session id after login (fixation)
      if (err) return next(err);
      const now = Date.now();
      Object.assign(req.session, {
        loginAt: now, lastSeen: now, idToken: tokens.id_token,
        user: { sub: claims.sub, sid: claims.sid, username: claims.preferred_username, roles,
                previousLogin: claims.previous_login ?? null },
      });
      if (claims.sid) sessionsBySid.set(claims.sid, [...(sessionsBySid.get(claims.sid) ?? []), req.sessionID]);
      console.log(JSON.stringify({ event: 'login', user: claims.sub, sid: claims.sid }));
      res.redirect('/');
    });
  } catch (e) { next(e); }
});

app.get('/', (req, res) => res.send(req.session.user ? `<a href="/me">me</a> <a href="/logout">Log off</a>` : '<a href="/login">Log in</a>'));
app.get('/me', requireLogin, (req, res) => res.json(req.session.user));   // show previousLogin in the UI (V-222437)
app.get('/approve', requireLogin, requireRole('approver'), (req, res) => res.json({ ok: true }));

// RP-initiated logout: end the local session, then the IdP session.
app.get('/logout', (req, res) => {
  const idToken = req.session.idToken;
  console.log(JSON.stringify({ event: 'logout', user: req.session.user?.sub }));
  req.session.destroy(() => {
    res.clearCookie(SECURE ? '__Host-sid' : 'sid', { path: '/', secure: SECURE, httpOnly: true, sameSite: 'lax' });
    if (!idToken) return res.redirect('/logged-out');
    res.redirect(client.buildEndSessionUrl(config, { id_token_hint: idToken, post_logout_redirect_uri: POST_LOGOUT_URI }).href);
  });
});
app.get('/logged-out', (req, res) => res.send('You have been logged off. Close the browser to end any remaining sessions.'));

// Back-channel logout: Keycloak POSTs logout_token when the SSO session ends (logout elsewhere, admin action).
app.post('/oauth2/backchannel-logout', express.urlencoded({ extended: false }), async (req, res) => {
  try {
    const { payload } = await jose.jwtVerify(req.body.logout_token ?? '', jwks, {
      issuer: meta.issuer, audience: CLIENT_ID, maxTokenAge: '2m',
    });
    if (!payload.events?.['http://schemas.openid.net/event/backchannel-logout'] || 'nonce' in payload ||
        !(payload.sid || payload.sub)) throw new Error('not a logout token');
    const ids = payload.sid ? sessionsBySid.get(payload.sid) ?? [] : [];
    sessionsBySid.delete(payload.sid);
    await Promise.all(ids.map((id) => new Promise((r) => store.destroy(id, r))));
    console.log(JSON.stringify({ event: 'backchannel_logout', user: payload.sub, sid: payload.sid, sessions: ids.length }));
    res.set('Cache-Control', 'no-store').sendStatus(200);
  } catch (e) {
    res.set('Cache-Control', 'no-store').status(400).json({ error: 'invalid_request' });
  }
});

app.get('/.well-known/jwks.json', (req, res) => res.json(publicJwks));   // public keys only

app.use((err, req, res, next) => {              // log the detail, show the user nothing internal
  console.error(JSON.stringify({ event: 'error', message: err.message }));
  res.status(500).send('Sign-in failed. Try again or contact the help desk.');
});

app.listen(Number(env('PORT', '3000')), env('HOST', '127.0.0.1'));

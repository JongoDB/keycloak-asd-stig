// Minimal OIDC relying party for an ASD STIG-hardened Keycloak: Express + openid-client v6 + jose.
// Authorization code + PKCE S256 + nonce, private_key_jwt (or a client secret read from a file), roles from the
// access token, 15-minute local idle / 8-hour absolute session, RP-initiated logout (POST, same-origin only) and
// back-channel logout. Sessions are server-side; the cookie carries only the session id.
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
const APP_ORIGIN = new URL(BASE).origin;
const IDLE_MS = Number(env('SESSION_IDLE_MINUTES', '15')) * 60_000;   // <= the IdP's idle (10 for admin apps)
const MAX_MS = Number(env('SESSION_MAX_HOURS', '8')) * 3_600_000;     // <= the IdP's SSO max lifespan
const MAX_SESSIONS = Number(env('MAX_SESSIONS', '10000'));            // cap on sessions and logins in progress
const PENDING_MS = 10 * 60_000;                                       // an unfinished login expires after 10 minutes
const SECURE = BASE.startsWith('https://');             // always true outside a localhost dev setup
const COOKIE = SECURE ? '__Host-sid' : 'sid';
const REDIRECT_URI = `${BASE}/oauth2/callback`;
const POST_LOGOUT_URI = `${BASE}/logged-out`;
const BCL_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
const audit = (event, kv) => console.log(JSON.stringify({ event, ...kv }));

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
const jwks = jose.createRemoteJWKSet(new URL(meta.jwks_uri));   // refetches only for an unknown kid, with a cooldown

// Back-channel logout arrives without the user's cookie: remember which local sessions belong to which IdP
// session (sid) and user (sub). Use a shared store (Redis, DB) for the sessions and both maps with replicas.
const store = new session.MemoryStore();
const bySid = new Map(), bySub = new Map();
const remember = (map, key, id) => key && map.set(key, new Set([...(map.get(key) ?? []), id]));
const forget = (s, id) => {
  for (const [map, key] of [[bySid, s?.user?.sid], [bySub, s?.user?.sub]]) {
    const set = map.get(key); set?.delete(id); if (set && !set.size) map.delete(key);
  }
};
const destroy = (id, s) => new Promise((r) => { forget(s, id); store.destroy(id, r); });

// Expire abandoned logins and sessions nobody returns to (the per-request check below only sees active users).
const expired = (s, now) => (s.user ? now - s.lastSeen > IDLE_MS || now - s.loginAt > MAX_MS
                                    : now - (s.startedAt ?? 0) > PENDING_MS);
setInterval(() => store.all((err, all) => {
  const now = Date.now();
  for (const [id, s] of Object.entries(all ?? {})) {
    if (expired(s, now)) { if (s.user) audit('session_timeout', { user: s.user.sub, sid: s.user.sid }); destroy(id, s); }
  }
}), 60_000).unref();

const app = express();
if (env('TRUST_PROXY', '0') === '1') app.set('trust proxy', 1);   // only behind your own proxy that overwrites X-Forwarded-*
app.use(session({
  store, name: COOKIE, secret: fs.readFileSync(env('SESSION_SECRET_FILE'), 'utf8').trim(),
  resave: false, saveUninitialized: false, rolling: false,
  cookie: { httpOnly: true, secure: SECURE, sameSite: 'lax', path: '/' },   // no maxAge: a browser-session cookie
}));

// Idle and absolute limits, enforced on every request.
app.use((req, res, next) => {
  const s = req.session;
  if (s.user) {
    const now = Date.now();
    if (expired(s, now)) {
      audit('session_timeout', { user: s.user.sub, sid: s.user.sid });
      forget(s, req.sessionID);
      return s.destroy(() => res.redirect('/logged-out?reason=timeout'));
    }
    s.lastSeen = now;
  }
  next();
});

const requireLogin = (req, res, next) => (req.session.user ? next() : res.status(401).json({ error: 'login required' }));
const requireRole = (role) => (req, res, next) => {
  if (req.session.user?.roles.includes(role)) return next();
  audit('forbidden', { user: req.session.user?.sub, role, path: req.path });
  res.status(403).json({ error: `role ${role} required` });
};
// CSRF check for state-changing requests: the browser's Origin (or Referer) must be this app's origin.
const sameOrigin = (req) => {
  const src = req.get('origin') ?? req.get('referer');
  try { return !!src && src !== 'null' && new URL(src).origin === APP_ORIGIN; } catch { return false; }
};

app.get('/login', (req, res, next) => store.length(async (err, n) => {
  try {
    if (err) throw err;
    if (n >= MAX_SESSIONS) return res.status(503).send('Too many sign-ins in progress. Try again shortly.');
    const verifier = client.randomPKCECodeVerifier();
    req.session.startedAt = Date.now();
    req.session.oidc = { verifier, nonce: client.randomNonce(), state: client.randomState() };
    const url = client.buildAuthorizationUrl(config, {
      redirect_uri: REDIRECT_URI, scope: 'openid', state: req.session.oidc.state, nonce: req.session.oidc.nonce,
      code_challenge: await client.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256',
    });
    res.redirect(url.href);
  } catch (e) { next(e); }
}));

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
      remember(bySid, claims.sid, req.sessionID);
      remember(bySub, claims.sub, req.sessionID);
      audit('login', { user: claims.sub, sid: claims.sid });
      res.redirect('/');
    });
  } catch (e) { next(e); }
});

app.get('/', (req, res) => res.send(req.session.user
  ? '<a href="/me">me</a> <form method="post" action="/logout" style="display:inline"><button>Log off</button></form>'
  : '<a href="/login">Log in</a>'));
app.get('/me', requireLogin, (req, res) => res.json(req.session.user));   // show previousLogin in the UI (V-222437)
app.get('/approve', requireLogin, requireRole('approver'), (req, res) => res.json({ ok: true }));

// RP-initiated logout: POST from this origin only; end the local session, then the IdP session.
app.post('/logout', (req, res) => {
  if (!sameOrigin(req)) return res.status(403).json({ error: 'cross-origin logout refused' });
  const { idToken, user } = req.session;
  audit('logout', { user: user?.sub, sid: user?.sid });
  forget(req.session, req.sessionID);
  req.session.destroy(() => {
    res.clearCookie(COOKIE, { path: '/', secure: SECURE, httpOnly: true, sameSite: 'lax' });
    if (!idToken) return res.redirect(303, '/logged-out');
    res.redirect(303, client.buildEndSessionUrl(config, { id_token_hint: idToken, post_logout_redirect_uri: POST_LOGOUT_URI }).href);
  });
});
app.get('/logged-out', (req, res) => res.send('You have been logged off. Close the browser to end any remaining sessions.'));

// Back-channel logout: Keycloak POSTs logout_token when the SSO session ends (logout elsewhere, admin action).
app.post('/oauth2/backchannel-logout', express.urlencoded({ extended: false, limit: '16kb' }), async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const { payload } = await jose.jwtVerify(req.body.logout_token ?? '', jwks, {
      issuer: meta.issuer, audience: CLIENT_ID, typ: 'logout+jwt', maxTokenAge: '2m', clockTolerance: 60,
    });
    const now = Date.now() / 1000;
    if (!payload.events?.[BCL_EVENT] || 'nonce' in payload || (payload.typ ?? 'Logout') !== 'Logout' ||
        !(payload.sid || payload.sub) || typeof payload.iat !== 'number' || payload.iat > now + 60) {
      throw new Error('not a logout token');
    }
    // sid names one IdP session; a token with only sub ends every session of that user.
    const ids = [...((payload.sid ? bySid.get(payload.sid) : bySub.get(payload.sub)) ?? [])];
    await Promise.all(ids.map((id) => new Promise((r) => store.get(id, (e, s) => destroy(id, s).then(r)))));
    audit('backchannel_logout', { user: payload.sub, sid: payload.sid, sessions: ids.length });
    res.sendStatus(200);
  } catch (e) {
    res.status(400).json({ error: 'invalid_request' });
  }
});

app.get('/.well-known/jwks.json', (req, res) => res.json(publicJwks));   // public keys only

app.use((err, req, res, next) => {              // log the detail, show the user nothing internal
  audit('error', { message: err.message });
  res.status(500).send('Sign-in failed. Try again or contact the help desk.');
});

app.listen(Number(env('PORT', '3000')), env('HOST', '127.0.0.1'));

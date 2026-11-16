// Minimal OIDC relying party for an ASD STIG-hardened Keycloak: net/http + coreos/go-oidc v3 + x/oauth2.
// Authorization code + PKCE S256 + nonce, private_key_jwt (or a client secret read from a file), roles from the
// access token, 15-minute local idle / 8-hour absolute session, RP-initiated logout (POST, same-origin only) and
// back-channel logout. Sessions are server-side; the cookie carries only the session id.
// Configuration (env): see ../README.md.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

const (
	bclEvent   = "http://schemas.openid.net/event/backchannel-logout"
	pendingTTL = 10 * time.Minute // an unfinished login expires after 10 minutes
)

type session struct {
	Sub, Sid, Username, PreviousLogin, IDToken string
	Roles                                    []string
	LoginAt, LastSeen                        time.Time
	// login in progress
	State, Nonce, Verifier string
}

type rp struct {
	clientID, base, cookie, origin string
	maxSessions                    int
	secure                 bool
	idle, maxAge           time.Duration
	oauth                  oauth2.Config
	idVerifier, atVerifier *oidc.IDTokenVerifier
	logoutVerifier         *oidc.IDTokenVerifier
	endSession             string
	signer                 jose.Signer // nil with a client secret
	jwks                   jose.JSONWebKeySet
	ctx                    context.Context

	mu       sync.Mutex
	sessions map[string]*session // server-side; use Redis or a DB with replicas
}

func env(k, d string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return d
}

func readFile(k string) []byte {
	b, err := os.ReadFile(os.Getenv(k))
	if err != nil {
		log.Fatalf("%s: %v", k, err)
	}
	return b
}

func randString() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func audit(event string, kv map[string]any) {
	kv["event"] = event
	b, _ := json.Marshal(kv)
	log.Println(string(b))
}

func main() {
	issuer, clientID := os.Getenv("OIDC_ISSUER"), os.Getenv("OIDC_CLIENT_ID") // issuer: from the operator
	base := strings.TrimSuffix(os.Getenv("APP_BASE_URL"), "/")                  // = root_url in the request
	idleMin, err := strconv.ParseFloat(env("SESSION_IDLE_MINUTES", "15"), 64) // <= the IdP's idle
	if err != nil {
		log.Fatal("SESSION_IDLE_MINUTES: ", err)
	}
	maxH, err := strconv.ParseFloat(env("SESSION_MAX_HOURS", "8"), 64) // <= the IdP's SSO max
	if err != nil {
		log.Fatal("SESSION_MAX_HOURS: ", err)
	}

	// The IdP's certificate chains to a DoD (or other private) root that is not in public trust stores.
	ctx := context.Background()
	if f := os.Getenv("OIDC_CA_FILE"); f != "" {
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(readFile("OIDC_CA_FILE")) {
			log.Fatal("OIDC_CA_FILE: no certificates")
		}
		hc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
		ctx = oidc.ClientContext(ctx, hc)
		ctx = context.WithValue(ctx, oauth2.HTTPClient, hc)
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatal(err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&meta); err != nil {
		log.Fatal(err)
	}

	a := &rp{clientID: clientID, base: base, secure: strings.HasPrefix(base, "https://"),
		idle: time.Duration(idleMin * float64(time.Minute)), maxAge: time.Duration(maxH * float64(time.Hour)),
		endSession: meta.EndSession, ctx: ctx, sessions: map[string]*session{}}
	a.origin = originOf(base)
	if a.maxSessions, err = strconv.Atoi(env("MAX_SESSIONS", "10000")); err != nil || a.maxSessions < 1 {
		log.Fatal("MAX_SESSIONS: must be a positive integer")
	}
	a.cookie = "sid"
	if a.secure {
		a.cookie = "__Host-sid"
	}
	endpoint := provider.Endpoint()
	a.oauth = oauth2.Config{ClientID: clientID, Endpoint: endpoint, RedirectURL: base + "/oauth2/callback",
		Scopes: []string{oidc.ScopeOpenID}}

	// --- client authentication: private_key_jwt (preferred) or a secret from a file ----------------------------
	if os.Getenv("OIDC_PRIVATE_KEY_FILE") != "" {
		blk, _ := pem.Decode(readFile("OIDC_PRIVATE_KEY_FILE"))
		if blk == nil {
			log.Fatal("OIDC_PRIVATE_KEY_FILE: not PEM")
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		priv, ok := k.(*rsa.PrivateKey)
		if !ok {
			log.Fatal("OIDC_PRIVATE_KEY_FILE: expected an RSA key")
		}
		kid := os.Getenv("OIDC_KEY_ID")
		a.signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: priv, KeyID: kid}},
			(&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			log.Fatal(err)
		}
		a.jwks = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &priv.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"}}}
		a.oauth.Endpoint.AuthStyle = oauth2.AuthStyleInParams // client_id in the body, no Basic header
	} else {
		a.oauth.ClientSecret = strings.TrimSpace(string(readFile("OIDC_CLIENT_SECRET_FILE")))
		a.oauth.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
		a.jwks = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	}

	// ID token: signature (JWKS), iss, aud, exp. Nonce is checked in the callback.
	a.idVerifier = provider.Verifier(&oidc.Config{ClientID: clientID})
	// Access token: aud differs, so check azp == client_id by hand.
	a.atVerifier = provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
	a.logoutVerifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, s := a.current(w, r); s != nil && s.Sub != "" {
			w.Write([]byte(`<a href="/me">me</a> <form method="post" action="/logout" style="display:inline"><button>Log off</button></form>`))
			return
		}
		w.Write([]byte(`<a href="/login">Log in</a>`))
	})
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("GET /oauth2/callback", a.callback)
	mux.HandleFunc("GET /me", a.require("", func(w http.ResponseWriter, r *http.Request, s *session) {
		writeJSON(w, 200, map[string]any{"sub": s.Sub, "sid": s.Sid, "username": s.Username, "roles": s.Roles,
			"previousLogin": s.PreviousLogin}) // show previousLogin in the UI (V-222437)
	}))
	mux.HandleFunc("GET /approve", a.require("approver", func(w http.ResponseWriter, r *http.Request, s *session) {
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	mux.HandleFunc("POST /logout", a.logout)
	mux.HandleFunc("GET /logged-out", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("You have been logged off. Close the browser to end any remaining sessions."))
	})
	mux.HandleFunc("POST /oauth2/backchannel-logout", a.backchannelLogout)
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, a.jwks) // public keys only
	})
	// TRUST_PROXY: this app builds every URL from APP_BASE_URL, so forwarded headers are never read. Behind a
	// proxy, set APP_BASE_URL to the public URL; use X-Forwarded-For for audit only when TRUST_PROXY=1.
	go func() { // expire abandoned logins and sessions nobody returns to
		for range time.Tick(time.Minute) {
			a.mu.Lock()
			for id, s := range a.sessions {
				if a.expired(s, time.Now()) {
					delete(a.sessions, id)
				}
			}
			a.mu.Unlock()
		}
	}()
	srv := &http.Server{Addr: env("HOST", "127.0.0.1") + ":" + env("PORT", "3000"), Handler: mux,
		ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// sameOrigin is the CSRF check for state-changing requests: Origin (or Referer) must be this app's origin.
func (a *rp) sameOrigin(r *http.Request) bool {
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	return src != "" && src != "null" && originOf(src) == a.origin
}

func (a *rp) expired(s *session, now time.Time) bool {
	if s.Sub == "" {
		return now.Sub(s.LastSeen) > pendingTTL
	}
	return now.Sub(s.LastSeen) > a.idle || now.Sub(s.LoginAt) > a.maxAge
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (a *rp) setCookie(w http.ResponseWriter, id string, del bool) {
	c := &http.Cookie{Name: a.cookie, Value: id, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode}
	if del {
		c.Value, c.MaxAge = "", -1
	} // no Expires/MaxAge otherwise: a browser-session cookie
	http.SetCookie(w, c)
}

// current returns the caller's session after applying the idle and absolute limits.
func (a *rp) current(w http.ResponseWriter, r *http.Request) (string, *session) {
	c, err := r.Cookie(a.cookie)
	if err != nil {
		return "", nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[c.Value]
	if s == nil {
		return "", nil
	}
	now := time.Now()
	if s.Sub != "" && a.expired(s, now) {
		delete(a.sessions, c.Value)
		a.setCookie(w, "", true)
		audit("session_timeout", map[string]any{"user": s.Sub, "sid": s.Sid})
		return "", nil
	}
	s.LastSeen = now
	return c.Value, s
}

func (a *rp) require(role string, h func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, s := a.current(w, r)
		if s == nil || s.Sub == "" {
			writeJSON(w, 401, map[string]string{"error": "login required"})
			return
		}
		if role != "" && !slices.Contains(s.Roles, role) {
			writeJSON(w, 403, map[string]string{"error": "role " + role + " required"})
			return
		}
		h(w, r, s)
	}
}

func (a *rp) login(w http.ResponseWriter, r *http.Request) {
	s := &session{State: randString(), Nonce: randString(), Verifier: oauth2.GenerateVerifier(), LastSeen: time.Now()}
	id := randString()
	a.mu.Lock()
	for k, p := range a.sessions { // drop abandoned logins
		if p.Sub == "" && a.expired(p, time.Now()) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= a.maxSessions {
		a.mu.Unlock()
		http.Error(w, "Too many sign-ins in progress. Try again shortly.", http.StatusServiceUnavailable)
		return
	}
	a.sessions[id] = s
	a.mu.Unlock()
	a.setCookie(w, id, false)
	http.Redirect(w, r, a.oauth.AuthCodeURL(s.State, oidc.Nonce(s.Nonce), oauth2.S256ChallengeOption(s.Verifier)), http.StatusFound)
}

func (a *rp) clientAssertion() string {
	now := time.Now()
	tok, err := jwt.Signed(a.signer).Claims(jwt.Claims{Issuer: a.clientID, Subject: a.clientID,
		Audience: jwt.Audience{a.oauth.Endpoint.TokenURL}, ID: randString(),
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(60 * time.Second))}).Serialize()
	if err != nil {
		panic(err)
	}
	return tok
}

func (a *rp) callback(w http.ResponseWriter, r *http.Request) {
	fail := func(err error) {
		audit("login_failed", map[string]any{"error": err.Error()})
		http.Error(w, "Sign-in failed. Try again or contact the help desk.", http.StatusBadRequest)
	}
	c, err := r.Cookie(a.cookie)
	if err != nil {
		fail(errors.New("no login in progress"))
		return
	}
	a.mu.Lock()
	s := a.sessions[c.Value]
	delete(a.sessions, c.Value) // one-time; a new id is issued below (fixation)
	a.mu.Unlock()
	if s == nil || s.State == "" || r.URL.Query().Get("state") != s.State {
		fail(errors.New("state mismatch"))
		return
	}
	opts := []oauth2.AuthCodeOption{oauth2.VerifierOption(s.Verifier)}
	if a.signer != nil {
		opts = append(opts, oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
			oauth2.SetAuthURLParam("client_assertion", a.clientAssertion()))
	}
	tok, err := a.oauth.Exchange(a.ctx, r.URL.Query().Get("code"), opts...)
	if err != nil {
		fail(err)
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := a.idVerifier.Verify(r.Context(), rawID)
	if err != nil {
		fail(err)
		return
	}
	if idt.Nonce != s.Nonce {
		fail(errors.New("nonce mismatch"))
		return
	}
	var claims struct {
		Sid           string `json:"sid"`
		Username      string `json:"preferred_username"`
		PreviousLogin string `json:"previous_login"`
	}
	if err := idt.Claims(&claims); err != nil {
		fail(err)
		return
	}
	// Client roles are in the access token; verify it before trusting them.
	att, err := a.atVerifier.Verify(r.Context(), tok.AccessToken)
	if err != nil {
		fail(err)
		return
	}
	var at struct {
		Azp            string                         `json:"azp"`
		ResourceAccess map[string]struct{ Roles []string } `json:"resource_access"`
	}
	if err := att.Claims(&at); err != nil || at.Azp != a.clientID || att.Subject != idt.Subject {
		fail(errors.New("access token not issued to this client"))
		return
	}
	now := time.Now()
	ns := &session{Sub: idt.Subject, Sid: claims.Sid, Username: claims.Username, PreviousLogin: claims.PreviousLogin,
		IDToken: rawID, Roles: at.ResourceAccess[a.clientID].Roles, LoginAt: now, LastSeen: now}
	id := randString()
	a.mu.Lock()
	if len(a.sessions) >= a.maxSessions {
		a.mu.Unlock()
		http.Error(w, "Too many sessions. Try again shortly.", http.StatusServiceUnavailable)
		return
	}
	a.sessions[id] = ns
	a.mu.Unlock()
	a.setCookie(w, id, false)
	audit("login", map[string]any{"user": ns.Sub, "sid": ns.Sid})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *rp) logout(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin logout refused"})
		return
	}
	id, s := a.current(w, r)
	a.setCookie(w, "", true)
	if s == nil || s.IDToken == "" {
		http.Redirect(w, r, "/logged-out", http.StatusSeeOther)
		return
	}
	a.mu.Lock()
	delete(a.sessions, id)
	a.mu.Unlock()
	audit("logout", map[string]any{"user": s.Sub})
	q := url.Values{"id_token_hint": {s.IDToken}, "post_logout_redirect_uri": {a.base + "/logged-out"}}
	http.Redirect(w, r, a.endSession+"?"+q.Encode(), http.StatusSeeOther)
}

// headerTyp returns the JOSE header's typ (the signature is checked separately, on the same bytes).
func headerTyp(raw string) string {
	seg, _, _ := strings.Cut(raw, ".")
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return ""
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if json.Unmarshal(b, &h) != nil {
		return ""
	}
	return h.Typ
}

func (a *rp) backchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	bad := func() { writeJSON(w, 400, map[string]string{"error": "invalid_request"}) }
	raw := r.PostFormValue("logout_token")
	lt, err := a.logoutVerifier.Verify(r.Context(), raw) // sig, iss, aud, exp
	if err != nil || headerTyp(raw) != "logout+jwt" {
		bad()
		return
	}
	var c struct {
		Sid    string                     `json:"sid"`
		Typ    *string                    `json:"typ"`
		Nonce  *string                    `json:"nonce"`
		Events map[string]json.RawMessage `json:"events"`
	}
	now := time.Now()
	if err := lt.Claims(&c); err != nil || c.Events[bclEvent] == nil || c.Nonce != nil ||
		(c.Typ != nil && *c.Typ != "Logout") || (c.Sid == "" && lt.Subject == "") ||
		lt.IssuedAt.After(now.Add(time.Minute)) || now.Sub(lt.IssuedAt) > 2*time.Minute {
		bad()
		return
	}
	n := 0
	a.mu.Lock()
	for id, s := range a.sessions {
		// sid names one IdP session; a token with only sub ends every session of that user.
		if (c.Sid != "" && s.Sid == c.Sid) || (c.Sid == "" && s.Sub != "" && s.Sub == lt.Subject) {
			delete(a.sessions, id)
			n++
		}
	}
	a.mu.Unlock()
	audit("backchannel_logout", map[string]any{"user": lt.Subject, "sid": c.Sid, "sessions": n})
	w.WriteHeader(http.StatusOK)
}

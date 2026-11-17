package iam

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nixuw/iam-go-sdk/internal/hooks"
	"github.com/nixuw/iam-go-sdk/internal/webflow"
)

const (
	// refreshLease is how long one instance holds the right to redeem a
	// session's refresh token.
	refreshLease = 20 * time.Second
	// refreshRetry is the pause after a refresh failed for a reason other
	// than invalid_grant (IAM unreachable, rate limited).
	refreshRetry  = 30 * time.Second
	revokeTimeout = 5 * time.Second
)

func init() {
	webflow.Engine = func(login any) webflow.LoginEngine {
		l, ok := login.(*Login)
		if !ok || l == nil || l.sessions == nil {
			return disabledEngine{}
		}
		return l.sessions
	}
	hooks.SetClock = func(instance any, now func() time.Time) {
		switch v := instance.(type) {
		case *Verifier:
			v.p.clock = now
		case *Caller:
			v.cl.p.clock = now
		case *Login:
			v.cl.p.clock = now
			if v.sessions != nil {
				if mem, ok := v.sessions.store.(*memoryStore); ok {
					mem.now = now
				}
			}
		}
	}
	hooks.SetSleep = func(instance any, sleep func(context.Context, time.Duration) error) {
		if c, ok := instance.(*Caller); ok {
			c.sleep = sleep
		}
	}
}

// sessionManager is the built-in local session and the sign-in flow on top
// of it. It implements webflow.LoginEngine for the HTTP adapters.
type sessionManager struct {
	l          *Login
	store      SessionStore
	seal       *sealer
	maxAge     time.Duration
	cookie     string // session cookie name
	bindCookie string // cookie binding a browser to the sign-ins it started
	secure     bool
	locks      keyedMutex
}

// sessionRecord is what a local session holds. It is stored encrypted and
// never leaves the server.
type sessionRecord struct {
	User         User      `json:"user"`
	IDToken      string    `json:"id_token,omitempty"`
	AccessToken  string    `json:"access_token,omitempty"`
	AccessExpiry time.Time `json:"access_expiry"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	// LeaseUntil marks that an instance is redeeming the refresh token.
	LeaseUntil time.Time `json:"lease_until,omitzero"`
	// RetryAt postpones the next refresh attempt after a transient failure.
	RetryAt time.Time `json:"retry_at,omitzero"`
}

// pendingRecord is a sign-in in progress, stored under its state.
type pendingRecord struct {
	Pending PendingLogin `json:"pending"`
	// Binding is the hash of the value of the browser's binding cookie.
	Binding string `json:"binding"`
}

func newSessionManager(ctx context.Context, l *Login, cfg LoginConfig, redirect *url.URL) (*sessionManager, error) {
	keys := cfg.SessionKeys
	if keys == nil {
		if len(cfg.SessionKey) == 0 {
			if cfg.SessionStore != nil {
				return nil, configError("SessionKey", "is required together with SessionStore: it signs the session cookie and encrypts the stored data")
			}
			return nil, nil // protocol-only use: AuthCodeURL and Exchange
		}
		static := [][]byte{cfg.SessionKey}
		keys = func(context.Context) ([][]byte, error) { return static, nil }
	}
	m := &sessionManager{l: l, seal: &sealer{keys: keys}, store: cfg.SessionStore, maxAge: cfg.SessionMaxAge, cookie: cfg.SessionCookieName, secure: !cfg.AllowInsecureCookie}
	if _, err := m.seal.current(ctx); err != nil {
		return nil, err
	}
	if m.store == nil {
		m.store = newMemoryStore()
	}
	switch {
	case m.maxAge == 0:
		m.maxAge = defaultSession
	case m.maxAge < 0:
		return nil, configError("SessionMaxAge", "must not be negative")
	}
	if m.cookie == "" {
		m.cookie = "iam_session"
	}
	if strings.ContainsAny(m.cookie, " \t\r\n=;,\"\\") {
		return nil, configError("SessionCookieName", "is not a valid cookie name")
	}
	m.bindCookie = m.cookie + "_login"
	if m.secure && redirect.Scheme == "http" {
		return nil, configError("AllowInsecureCookie", "RedirectURL uses http, and browsers do not keep Secure cookies over plain http: use https, or set AllowInsecureCookie for local development")
	}
	return m, nil
}

// ---- webflow.LoginEngine ----------------------------------------------------

// Start begins a sign-in: the one-time state is stored on the server, bound
// to this browser, and the browser is sent to IAM.
func (m *sessionManager) Start(ctx context.Context, r *webflow.Request) *webflow.Response {
	q, _ := url.ParseQuery(r.RawQuery)
	opts := AuthOptions{Prompt: q.Get("prompt"), LoginHint: q.Get("login_hint"), ReturnTo: q.Get("return_to")}
	if len(opts.LoginHint) > 256 {
		opts.LoginHint = ""
	}
	if v := q.Get("max_age"); v != "" {
		secs, err := strconv.ParseInt(v, 10, 32)
		if err != nil || secs < 0 {
			return m.fail(ctx, configError("max_age", "must be a non-negative number of seconds"), http.StatusBadRequest)
		}
		if opts.MaxAge = secondsDuration(secs); secs == 0 {
			// max_age=0 means "authenticate now".
			opts.Prompt = strings.TrimSpace(opts.Prompt + " login")
		}
	}
	if _, err := checkPrompt(opts.Prompt); err != nil {
		return m.fail(ctx, err, http.StatusBadRequest)
	}
	req, err := m.l.AuthCodeURL(ctx, opts)
	if err != nil {
		return m.fail(ctx, err, 0)
	}
	res := &webflow.Response{Status: http.StatusFound, Location: req.URL}
	// The browser binding: one random value per browser, shared by the
	// sign-ins it has in progress (several tabs).
	binding, ok := m.seal.verify(ctx, m.bindCookie, r.Cookie(m.bindCookie))
	if !ok {
		if binding, err = randomToken(32); err != nil {
			return m.fail(ctx, err, 0)
		}
	}
	signed, err := m.seal.sign(ctx, m.bindCookie, binding)
	if err != nil {
		return m.fail(ctx, err, 0)
	}
	res.Cookies = append(res.Cookies, m.newCookie(m.bindCookie, signed, pendingLoginTTL))
	if err := m.put(ctx, pendingKeyPrefix+req.Pending.State, pendingRecord{Pending: req.Pending, Binding: hashString(binding)}, pendingLoginTTL); err != nil {
		return m.fail(ctx, err, 0)
	}
	return res
}

// Callback completes a sign-in and establishes the local session.
func (m *sessionManager) Callback(ctx context.Context, r *webflow.Request) *webflow.Response {
	q, err := url.ParseQuery(r.RawQuery)
	if err != nil {
		return m.fail(ctx, errInvalidCallback("the callback parameters are malformed"), 0)
	}
	state := q.Get("state")
	if state == "" || len(state) > 512 {
		return m.fail(ctx, errInvalidCallback("state missing"), 0)
	}
	// Take the pending sign-in: it can be used exactly once.
	key := pendingKeyPrefix + state
	raw, err := m.store.Get(ctx, key)
	if err != nil {
		return m.fail(ctx, &NetworkError{Op: "session store", Err: err}, 0)
	}
	if raw == nil {
		return m.fail(ctx, errInvalidCallback("no sign-in is pending for this state (unknown, expired or already used)"), 0)
	}
	taken, err := m.store.CompareAndSwap(ctx, key, raw, []byte{0}, time.Minute)
	if err != nil {
		return m.fail(ctx, &NetworkError{Op: "session store", Err: err}, 0)
	}
	if !taken {
		return m.fail(ctx, errInvalidCallback("no sign-in is pending for this state (unknown, expired or already used)"), 0)
	}
	_ = m.store.Delete(ctx, key)
	var rec pendingRecord
	if err := m.decode(ctx, key, raw, &rec); err != nil {
		return m.fail(ctx, errInvalidCallback("no sign-in is pending for this state (unknown, expired or already used)"), 0)
	}
	// The callback must arrive in the browser that started the sign-in.
	binding, ok := m.seal.verify(ctx, m.bindCookie, r.Cookie(m.bindCookie))
	if !ok || subtle.ConstantTimeCompare([]byte(hashString(binding)), []byte(rec.Binding)) != 1 {
		return m.fail(ctx, errInvalidCallback("the callback does not belong to a sign-in started in this browser"), 0)
	}
	result, err := m.l.Exchange(ctx, &rec.Pending, q)
	if err != nil {
		return m.fail(ctx, err, 0)
	}
	id, err := randomToken(32)
	if err != nil {
		return m.fail(ctx, err, 0)
	}
	now := m.l.cl.p.clock().UTC()
	session := sessionRecord{
		User: *result.User, IDToken: result.Tokens.IDToken, AccessToken: result.Tokens.AccessToken, AccessExpiry: result.Tokens.Expiry,
		RefreshToken: result.Tokens.RefreshToken, CreatedAt: now, ExpiresAt: now.Add(m.maxAge),
	}
	if err := m.put(ctx, sessionKeyPrefix+id, session, m.maxAge); err != nil {
		return m.fail(ctx, err, 0)
	}
	signed, err := m.seal.sign(ctx, m.cookie, id)
	if err != nil {
		return m.fail(ctx, err, 0)
	}
	// A new sign-in always gets a new session ID; a previous session of
	// this browser ends.
	if old, ok := m.seal.verify(ctx, m.cookie, r.Cookie(m.cookie)); ok {
		_ = m.store.Delete(ctx, sessionKeyPrefix+old)
	}
	returnTo := result.ReturnTo
	if returnTo == "" {
		returnTo = "/"
	}
	return &webflow.Response{Status: http.StatusFound, Location: returnTo, Cookies: []*http.Cookie{m.newCookie(m.cookie, signed, m.maxAge)}}
}

// Logout clears the local session first, revokes the refresh token when
// there is one, and then sends the browser to IAM's logout endpoint.
func (m *sessionManager) Logout(ctx context.Context, r *webflow.Request) *webflow.Response {
	p := m.l.cl.p
	res := &webflow.Response{Status: http.StatusFound, Cookies: []*http.Cookie{m.newCookie(m.cookie, "", -1)}}
	idToken := ""
	if id, ok := m.seal.verify(ctx, m.cookie, r.Cookie(m.cookie)); ok {
		key := sessionKeyPrefix + id
		var rec sessionRecord
		if raw, err := m.store.Get(ctx, key); err == nil && raw != nil && m.decode(ctx, key, raw, &rec) == nil {
			idToken = rec.IDToken
		}
		if err := m.store.Delete(ctx, key); err != nil {
			p.log.ErrorContext(ctx, "iam: deleting the local session failed", "error", err.Error())
		}
		if rec.RefreshToken != "" {
			rctx, cancel := context.WithTimeout(ctx, revokeTimeout)
			if err := m.l.Revoke(rctx, rec.RefreshToken); err != nil {
				p.log.WarnContext(ctx, "iam: revoking the refresh token at logout failed", "error", err.Error())
			}
			cancel()
		}
	}
	state, err := randomToken(16)
	if err != nil {
		state = ""
	}
	location, err := m.l.LogoutURL(ctx, idToken, state)
	if err != nil {
		// IAM is unreachable: the local session is gone all the same.
		p.log.WarnContext(ctx, "iam: the logout endpoint is unknown; staying on this site", "error", err.Error())
		location = m.l.postLogout
		if location == "" {
			location = "/"
		}
	}
	res.Location = location
	return res
}

// Authenticate returns the user of the request's local session. When the
// session's access token has expired and there is a refresh token, the
// session is refreshed first, which is also how a disabled user or an ended
// IAM session becomes visible to the application.
func (m *sessionManager) Authenticate(ctx context.Context, r *webflow.Request, loginPath string) (any, *webflow.Response) {
	id, ok := m.seal.verify(ctx, m.cookie, r.Cookie(m.cookie))
	if !ok {
		return nil, m.challenge(r, loginPath, false)
	}
	rec, raw, err := m.load(ctx, id)
	if err != nil {
		return nil, m.fail(ctx, err, 0)
	}
	now := m.l.cl.p.clock()
	if rec != nil && !now.Before(rec.ExpiresAt) {
		_ = m.store.Delete(ctx, sessionKeyPrefix+id)
		rec = nil
	}
	if rec != nil && rec.needsRefresh(now) {
		if rec, err = m.refresh(ctx, id, rec, raw); err != nil {
			return nil, m.fail(ctx, err, 0)
		}
	}
	if rec == nil {
		return nil, m.challenge(r, loginPath, true)
	}
	user := rec.User
	return &user, nil
}

// ---- session handling -------------------------------------------------------

func (rec *sessionRecord) needsRefresh(now time.Time) bool {
	return rec.RefreshToken != "" && !now.Before(rec.AccessExpiry) && !now.Before(rec.RetryAt) && !now.Before(rec.LeaseUntil)
}

// refresh redeems the session's refresh token. It returns the session to
// continue with, or nil when IAM ended it (invalid_grant).
//
// Refreshes of one session are serialised: within this process by a lock,
// across instances by a lease written with CompareAndSwap. Whoever does not
// get the lease carries on with the session as it is.
func (m *sessionManager) refresh(ctx context.Context, id string, rec *sessionRecord, raw []byte) (*sessionRecord, error) {
	p := m.l.cl.p
	key := sessionKeyPrefix + id
	defer m.locks.lock(id)()
	// Look again under the lock: a concurrent request may have refreshed.
	rec, raw, err := m.load(ctx, id)
	if err != nil || rec == nil {
		return nil, err
	}
	now := p.clock()
	if !rec.needsRefresh(now) {
		return rec, nil
	}
	ttl := rec.ExpiresAt.Sub(now)
	leased := *rec
	leased.LeaseUntil = now.Add(refreshLease)
	leasedRaw, err := m.encode(ctx, key, leased)
	if err != nil {
		return nil, err
	}
	won, err := m.store.CompareAndSwap(ctx, key, raw, leasedRaw, ttl)
	if err != nil {
		return nil, &NetworkError{Op: "session store", Err: err}
	}
	if !won {
		return rec, nil // another instance is refreshing this session
	}
	result, err := m.l.Refresh(ctx, rec.RefreshToken)
	switch {
	case err == nil && result.User != nil && result.User.Subject != rec.User.Subject:
		err = errors.New("the refreshed ID token names another user")
		fallthrough
	case errors.Is(err, ErrLoginRequired), errors.Is(err, ErrInvalidToken):
		// IAM no longer stands behind this session: the user was disabled,
		// signed out, withdrew consent, or the refresh token is spent.
		p.log.InfoContext(ctx, "iam: local session ended because the refresh was refused", "sub", rec.User.Subject, "error", err.Error())
		_ = m.store.Delete(ctx, key)
		return nil, nil
	case err != nil:
		// IAM is unreachable or busy: keep the session and try again later.
		p.log.WarnContext(ctx, "iam: refreshing the local session failed; keeping the session", "sub", rec.User.Subject, "error", err.Error())
		rec.RetryAt = p.clock().Add(refreshRetry)
		if retryRaw, eerr := m.encode(ctx, key, *rec); eerr == nil {
			_, _ = m.store.CompareAndSwap(ctx, key, leasedRaw, retryRaw, ttl)
		}
		return rec, nil
	}
	next := *rec
	next.AccessToken, next.AccessExpiry = result.Tokens.AccessToken, result.Tokens.Expiry
	if result.Tokens.RefreshToken != "" {
		next.RefreshToken = result.Tokens.RefreshToken
	}
	if result.Tokens.IDToken != "" {
		next.IDToken = result.Tokens.IDToken
	}
	if result.User != nil {
		// Profile data may have changed; the authentication facts stay.
		next.User.Name, next.User.PreferredUsername = result.User.Name, result.User.PreferredUsername
		next.User.Email, next.User.EmailVerified = result.User.Email, result.User.EmailVerified
	}
	next.RetryAt, next.LeaseUntil = time.Time{}, time.Time{}
	// The new refresh token replaces the old one in a single write. If the
	// write fails it is lost, and with it the session's ability to refresh.
	nextRaw, err := m.encode(ctx, key, next)
	if err == nil {
		for attempt := 0; attempt < 3; attempt++ {
			if err = m.store.Set(ctx, key, nextRaw, ttl); err == nil {
				break
			}
		}
	}
	if err != nil {
		p.log.ErrorContext(ctx, "iam: storing the refreshed session failed", "sub", rec.User.Subject, "error", err.Error())
		return nil, &NetworkError{Op: "session store", Err: err}
	}
	return &next, nil
}

// load reads a session. A missing or unreadable session is (nil, nil, nil).
func (m *sessionManager) load(ctx context.Context, id string) (*sessionRecord, []byte, error) {
	key := sessionKeyPrefix + id
	raw, err := m.store.Get(ctx, key)
	if err != nil {
		return nil, nil, &NetworkError{Op: "session store", Err: err}
	}
	if raw == nil {
		return nil, nil, nil
	}
	var rec sessionRecord
	if err := m.decode(ctx, key, raw, &rec); err != nil {
		return nil, nil, nil
	}
	return &rec, raw, nil
}

func (m *sessionManager) put(ctx context.Context, key string, v any, ttl time.Duration) error {
	raw, err := m.encode(ctx, key, v)
	if err != nil {
		return err
	}
	if err := m.store.Set(ctx, key, raw, ttl); err != nil {
		return &NetworkError{Op: "session store", Err: err}
	}
	return nil
}

func (m *sessionManager) encode(ctx context.Context, key string, v any) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return m.seal.seal(ctx, key, plain)
}

func (m *sessionManager) decode(ctx context.Context, key string, raw []byte, v any) error {
	plain, err := m.seal.open(ctx, key, raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

// ---- responses --------------------------------------------------------------

// newCookie builds a cookie of the local session: HttpOnly, Secure,
// SameSite=Lax. A negative maxAge deletes it.
func (m *sessionManager) newCookie(name, value string, maxAge time.Duration) *http.Cookie {
	c := &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode}
	if maxAge < 0 {
		c.MaxAge = -1
	} else {
		c.MaxAge = int(maxAge / time.Second)
	}
	return c
}

// challenge answers a request without a valid session: a page request is
// sent to the login page and returns to where it was afterwards; an API
// request gets 401 and no redirect.
func (m *sessionManager) challenge(r *webflow.Request, loginPath string, clear bool) *webflow.Response {
	res := &webflow.Response{}
	if clear {
		res.Cookies = []*http.Cookie{m.newCookie(m.cookie, "", -1)}
	}
	if isPageRequest(r) {
		target := r.Path
		if r.RawQuery != "" {
			target += "?" + r.RawQuery
		}
		res.Status = http.StatusFound
		res.Location = loginPath
		if back := localPath(target); back != "" && r.Path != loginPath {
			res.Location += "?return_to=" + url.QueryEscape(back)
		}
		return res
	}
	res.Status, res.Err, res.Code, res.Description = http.StatusUnauthorized, ErrLoginRequired, "login_required", "sign in to use this endpoint"
	return res
}

// isPageRequest tells a browser navigation from an API call.
func isPageRequest(r *webflow.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if mode := r.Header("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	if strings.EqualFold(r.Header("X-Requested-With"), "XMLHttpRequest") {
		return false
	}
	return strings.Contains(r.Header("Accept"), "text/html")
}

// fail turns an error of the sign-in flow into a response. The error itself
// goes to the application's error handler and to the log; the browser only
// gets a short, safe description.
func (m *sessionManager) fail(ctx context.Context, err error, status int) *webflow.Response {
	res := &webflow.Response{Status: status, Err: err}
	var oe *OAuthError
	switch {
	case errors.Is(err, ErrInvalidCallback):
		res.Code, res.Description = "invalid_request", "the sign-in could not be completed; start again"
		res.Status = pick(status, http.StatusBadRequest)
	case errors.As(err, &oe) && oe.StatusCode == 0:
		// IAM reported an error in the authorization response.
		res.Code, res.Description = oe.Code, oe.Description
		switch oe.Code {
		case "access_denied":
			res.Status = pick(status, http.StatusForbidden)
		case "login_required", "interaction_required", "consent_required":
			res.Status = pick(status, http.StatusUnauthorized)
		default:
			res.Status = pick(status, http.StatusBadRequest)
		}
	case errors.As(err, &oe) && oe.Code == "invalid_grant":
		res.Code, res.Description = "invalid_grant", "the sign-in could not be completed; start again"
		res.Status = pick(status, http.StatusBadRequest)
	case errors.Is(err, ErrInvalidToken):
		res.Code, res.Description = "invalid_token", "the sign-in could not be completed"
		res.Status = pick(status, http.StatusBadRequest)
	case errors.Is(err, ErrNetwork), errors.Is(err, ErrUnavailable), errors.As(err, &oe) && oe.Temporary():
		res.Code, res.Description = "temporarily_unavailable", "sign-in is temporarily unavailable"
		res.Status = pick(status, http.StatusServiceUnavailable)
	case errors.Is(err, ErrConfig) && status == http.StatusBadRequest:
		res.Code, res.Description = "invalid_request", "the request parameters are invalid"
	default:
		res.Code, res.Description = "server_error", "sign-in failed"
		res.Status = pick(status, http.StatusInternalServerError)
	}
	level := m.l.cl.p.log.WarnContext
	if res.Status >= 500 {
		level = m.l.cl.p.log.ErrorContext
	}
	level(ctx, "iam: sign-in request failed", "status", res.Status, "code", res.Code, "error", err.Error())
	return res
}

func pick(status, fallback int) int {
	if status != 0 {
		return status
	}
	return fallback
}

func errInvalidCallback(reason string) error {
	return &callbackError{reason: reason}
}

type callbackError struct{ reason string }

func (e *callbackError) Error() string        { return ErrInvalidCallback.Error() + ": " + e.reason }
func (e *callbackError) Is(target error) bool { return target == ErrInvalidCallback }

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// disabledEngine answers when the adapters' handlers are used with a Login
// that was created without a session key.
type disabledEngine struct{}

func (disabledEngine) refuse() *webflow.Response {
	return &webflow.Response{
		Status: http.StatusInternalServerError, Code: "server_error", Description: "sign-in is not configured",
		Err: configError("SessionKey", "is required to use the built-in local session (login handlers and middleware)"),
	}
}

func (d disabledEngine) Start(context.Context, *webflow.Request) *webflow.Response { return d.refuse() }
func (d disabledEngine) Callback(context.Context, *webflow.Request) *webflow.Response {
	return d.refuse()
}
func (d disabledEngine) Logout(context.Context, *webflow.Request) *webflow.Response {
	return d.refuse()
}
func (d disabledEngine) Authenticate(context.Context, *webflow.Request, string) (any, *webflow.Response) {
	return nil, d.refuse()
}

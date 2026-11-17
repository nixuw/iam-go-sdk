package iam

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// pendingLoginTTL is how long a started sign-in may take until the
	// callback arrives (password, MFA and consent pages included).
	pendingLoginTTL = 15 * time.Minute
	// recentRefreshTTL is how long the result of a refresh is remembered
	// for callers that still present the previous refresh token.
	recentRefreshTTL = time.Minute
	defaultSession   = 8 * time.Hour
	minSessionKeyLen = 32
)

// The identity scopes an OIDC application can be registered for.
var loginScopes = []string{"openid", "profile", "email", "offline_access"}

// LoginConfig configures user sign-in for a web backend: an OIDC application
// of type "web_backend" registered in IAM.
type LoginConfig struct {
	// Issuer is the IAM issuer. Required.
	Issuer string
	// ClientID is the client ID of the OIDC application (app_…). Required.
	ClientID string
	// Credential authenticates the OIDC application with the method it is
	// registered for. Required.
	Credential Credential
	// RedirectURL is the callback address, byte for byte as registered in
	// IAM. Required.
	RedirectURL string
	// PostLogoutRedirectURL is where IAM sends the browser after logout. It
	// must be registered in IAM. Empty leaves the user on IAM's "signed
	// out" page.
	PostLogoutRedirectURL string
	// Scopes are the identity scopes to request: openid (mandatory),
	// profile, email, offline_access. Empty means openid and profile.
	Scopes []string
	// FetchUserInfo additionally reads the user's current profile from the
	// UserInfo endpoint after sign-in. The ID token already carries the
	// profile; this is only needed for the very latest data.
	FetchUserInfo bool
	// Leeway is the tolerated clock difference when validating ID tokens.
	// Zero means the default of 60 seconds, which is also the maximum.
	Leeway time.Duration

	// SessionKey protects the built-in local session: it signs the session
	// cookie and encrypts the session data in the store. At least 32 bytes
	// of high entropy. Required to use the handlers and the middleware of
	// the adapters; not needed when only AuthCodeURL and Exchange are used.
	SessionKey []byte
	// SessionKeys supplies the session keys at run time instead of
	// SessionKey, to replace the key without a restart: the first key is
	// used for new data, all of them are accepted for existing data.
	SessionKeys func(ctx context.Context) ([][]byte, error)
	// SessionStore keeps the local sessions. Nil means an in-process store,
	// which needs no external service but is not shared between instances;
	// run several instances with a shared store.
	SessionStore SessionStore
	// SessionMaxAge is the upper limit of a local session's lifetime. Zero
	// means 8 hours. IAM does not notify the application when the user signs
	// out elsewhere, so keep it no longer than IAM's own session.
	SessionMaxAge time.Duration
	// SessionCookieName is the name of the session cookie. Empty means
	// "iam_session".
	SessionCookieName string
	// AllowInsecureCookie omits the Secure attribute of the cookies, for
	// local development over plain http. Off by default.
	AllowInsecureCookie bool

	// HTTPClient is used to reach IAM. Nil means a client with a 10 second
	// timeout.
	HTTPClient *http.Client
	// Logger receives diagnostics. Nil disables logging.
	Logger *slog.Logger
	// AllowInsecureIssuer permits an http:// issuer. For integration
	// environments only.
	AllowInsecureIssuer bool
	// TolerateStartupFailure makes NewLogin succeed when IAM cannot be
	// reached at startup; discovery and the key download are then retried
	// on use.
	TolerateStartupFailure bool
}

// User is the signed-in user as IAM vouches for it. Issuer and Subject
// together are the unique, stable key of a user: map local accounts by this
// pair, never by email or username.
type User struct {
	// Issuer is the IAM issuer.
	Issuer string `json:"iss"`
	// Subject is the user ID. It never changes and is never reused.
	Subject string `json:"sub"`
	// Name and PreferredUsername are present with the profile scope.
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	// Email and EmailVerified are present with the email scope when the
	// user has an email address.
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	// AMR lists how the user authenticated, e.g. ["pwd", "otp"].
	AMR []string `json:"amr,omitempty"`
	// AuthTime is when the user authenticated at IAM.
	AuthTime time.Time `json:"auth_time"`
	// SessionID is the ID of the user's IAM session (sid).
	SessionID string `json:"sid,omitempty"`
}

// TokenSet holds the tokens of a sign-in. Keep them on the server; never
// hand them to browser scripts.
type TokenSet struct {
	// AccessToken is only good for IAM's UserInfo endpoint. It cannot call
	// business APIs and must not be parsed.
	AccessToken string
	// Expiry is when the access token expires.
	Expiry time.Time
	// IDToken is needed again at logout (id_token_hint).
	IDToken string
	// RefreshToken is present when the application is allowed to refresh.
	// It changes with every refresh; store the new value atomically.
	RefreshToken string
	// Scopes are the scopes IAM granted.
	Scopes []string
}

// LoginResult is the outcome of a completed sign-in or refresh.
type LoginResult struct {
	// User is the signed-in user. After a refresh it is nil when IAM
	// returned no new ID token.
	User *User
	// Tokens are the tokens IAM issued.
	Tokens *TokenSet
	// ReturnTo is the local page the sign-in was started from.
	ReturnTo string
}

// AuthOptions are the optional parameters of an authorization request.
type AuthOptions struct {
	// Prompt is "none" (no interaction; an error comes back when the user
	// would have to act), "login" (force re-authentication), "consent"
	// (show the consent page again), or empty.
	Prompt string
	// MaxAge demands that the user authenticated no longer ago than this;
	// the ID token's auth_time is then checked. Zero sends no max_age (use
	// Prompt "login" to force re-authentication).
	MaxAge time.Duration
	// LoginHint pre-fills the login name.
	LoginHint string
	// ReturnTo is a local path to return to after sign-in. Anything that is
	// not a path on this site is ignored.
	ReturnTo string
}

// AuthRequest is a prepared authorization request.
type AuthRequest struct {
	// URL is where to redirect the browser.
	URL string
	// Pending must be kept on the server, bound to the browser that started
	// the sign-in, and handed to Exchange when the callback arrives. Use it
	// once, then delete it.
	Pending PendingLogin
}

// PendingLogin is the one-time state of a started sign-in. It is plain data
// so that it can be stored in an existing session; treat it as opaque.
type PendingLogin struct {
	// State is the state parameter of the authorization request; the
	// callback must bring it back. It can serve as the key under which the
	// pending sign-in is stored.
	State string `json:"state"`
	// Nonce is echoed in the ID token and ties it to this sign-in.
	Nonce string `json:"nonce"`
	// CodeVerifier is the PKCE secret. It must never leave the server.
	CodeVerifier string `json:"code_verifier"`
	// MaxAge is the max_age that was requested, in seconds; -1 when none.
	MaxAge int64 `json:"max_age"`
	// ReturnTo is the local path to return to after the sign-in.
	ReturnTo string `json:"return_to,omitempty"`
	// CreatedAt is when the sign-in was started; it expires after 15 minutes.
	CreatedAt time.Time `json:"created_at"`
}

// Login signs users in with the authorization code flow and PKCE. The
// adapters build handlers and middleware on it; applications with their own
// session handling use AuthCodeURL and Exchange directly.
type Login struct {
	cl         *client
	redirect   string
	postLogout string
	scopes     []string
	leeway     time.Duration
	userInfo   bool
	sessions   *sessionManager // nil without session keys

	refreshMu sync.Mutex
	refreshes map[string]*refreshCall
}

type refreshCall struct {
	fl     *flight
	result *LoginResult
	until  time.Time // zero while in flight
}

// NewLogin validates the configuration, reads the discovery document and
// downloads the signing keys.
func NewLogin(ctx context.Context, cfg LoginConfig) (*Login, error) {
	p, err := newProvider(commonConfig{issuer: cfg.Issuer, insecure: cfg.AllowInsecureIssuer, hc: cfg.HTTPClient, log: cfg.Logger})
	if err != nil {
		return nil, err
	}
	if cfg.ClientID == "" {
		return nil, configError("ClientID", "is required: the client ID of the OIDC application")
	}
	if cfg.Credential == nil {
		return nil, configError("Credential", "is required: ClientSecret or PrivateKeyJWT")
	}
	if _, err := cfg.Credential.fingerprint(ctx); err != nil {
		return nil, err
	}
	redirect, err := checkAppURL("RedirectURL", cfg.RedirectURL, true)
	if err != nil {
		return nil, err
	}
	if _, err := checkAppURL("PostLogoutRedirectURL", cfg.PostLogoutRedirectURL, false); err != nil {
		return nil, err
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile"}
	}
	for _, s := range scopes {
		if !slices.Contains(loginScopes, s) {
			return nil, configError("Scopes", fmt.Sprintf("%q is not an identity scope; only openid, profile, email and offline_access can be requested at sign-in", s))
		}
	}
	if !slices.Contains(scopes, "openid") {
		return nil, configError("Scopes", "must include openid")
	}
	leeway, err := checkLeeway(cfg.Leeway)
	if err != nil {
		return nil, err
	}
	l := &Login{
		cl:       &client{p: p, id: cfg.ClientID, cred: cfg.Credential},
		redirect: cfg.RedirectURL, postLogout: cfg.PostLogoutRedirectURL,
		scopes: slices.Clone(scopes), leeway: leeway, userInfo: cfg.FetchUserInfo,
		refreshes: map[string]*refreshCall{},
	}
	if l.sessions, err = newSessionManager(ctx, l, cfg, redirect); err != nil {
		return nil, err
	}
	if err := p.start(ctx, true, cfg.TolerateStartupFailure); err != nil {
		return nil, err
	}
	return l, nil
}

// checkAppURL validates an address of the application itself.
func checkAppURL(field, raw string, required bool) (*url.URL, error) {
	if raw == "" {
		if required {
			return nil, configError(field, "is required")
		}
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.Fragment != "" {
		return nil, configError(field, "must be an absolute http(s) URL without fragment, exactly as registered in IAM")
	}
	return u, nil
}

// AuthCodeURL prepares an authorization request with a fresh state, nonce
// and PKCE (S256) challenge.
func (l *Login) AuthCodeURL(ctx context.Context, opts AuthOptions) (*AuthRequest, error) {
	meta, err := l.cl.p.metadata(ctx)
	if err != nil {
		return nil, err
	}
	if meta.AuthorizationEndpoint == "" {
		return nil, &NetworkError{Op: "discovery", Err: errors.New("the issuer has no authorization endpoint")}
	}
	endpoint, err := url.Parse(meta.AuthorizationEndpoint)
	if err != nil {
		return nil, &NetworkError{Op: "discovery", Err: errors.New("the authorization endpoint is not a valid URL")}
	}
	prompt, err := checkPrompt(opts.Prompt)
	if err != nil {
		return nil, err
	}
	if opts.MaxAge < 0 {
		return nil, configError("AuthOptions.MaxAge", "must not be negative")
	}
	state, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	verifier, err := randomToken(32) // 43 characters of the unreserved set
	if err != nil {
		return nil, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	pending := PendingLogin{State: state, Nonce: nonce, CodeVerifier: verifier, MaxAge: -1, ReturnTo: localPath(opts.ReturnTo), CreatedAt: l.cl.p.clock().UTC()}

	q := endpoint.Query()
	q.Set("response_type", "code")
	q.Set("client_id", l.cl.id)
	q.Set("redirect_uri", l.redirect)
	q.Set("scope", strings.Join(l.scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", "S256")
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	if opts.MaxAge > 0 {
		pending.MaxAge = int64(opts.MaxAge / time.Second)
		q.Set("max_age", strconv.FormatInt(pending.MaxAge, 10))
	}
	if opts.LoginHint != "" {
		q.Set("login_hint", opts.LoginHint)
	}
	endpoint.RawQuery = q.Encode()
	return &AuthRequest{URL: endpoint.String(), Pending: pending}, nil
}

func checkPrompt(prompt string) (string, error) {
	values := strings.Fields(prompt)
	for _, v := range values {
		if v != "none" && v != "login" && v != "consent" {
			return "", configError("AuthOptions.Prompt", "must be none, login or consent")
		}
	}
	if len(values) > 1 && slices.Contains(values, "none") {
		return "", configError("AuthOptions.Prompt", "none cannot be combined with another value")
	}
	return strings.Join(values, " "), nil
}

// localPath returns raw when it is a path on this site, and "" otherwise.
// It keeps a sign-in from being used to redirect a user somewhere else.
func localPath(raw string) string {
	if raw == "" || raw[0] != '/' || len(raw) > 2048 || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n\t") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return ""
	}
	return raw
}

// Exchange completes a sign-in from the parameters of the callback request
// and the pending state stored for the browser. In this order it checks the
// state, checks that iss is the configured issuer, reports an error response
// of IAM (as *OAuthError, e.g. access_denied or login_required, for the
// application to present or to fall back from), redeems the code and
// validates the ID token. Any failure means the user is not signed in.
func (l *Login) Exchange(ctx context.Context, pending *PendingLogin, callback url.Values) (*LoginResult, error) {
	p := l.cl.p
	if pending == nil || pending.State == "" || pending.CodeVerifier == "" {
		return nil, fmt.Errorf("%w: no sign-in is pending for this callback", ErrInvalidCallback)
	}
	state := callback.Get("state")
	if len(callback["state"]) != 1 || subtle.ConstantTimeCompare([]byte(state), []byte(pending.State)) != 1 {
		return nil, fmt.Errorf("%w: state mismatch", ErrInvalidCallback)
	}
	if len(callback["iss"]) != 1 || callback.Get("iss") != p.issuer {
		return nil, fmt.Errorf("%w: iss is not the configured issuer", ErrInvalidCallback)
	}
	if code := callback.Get("error"); code != "" {
		return nil, &OAuthError{Code: code, Description: callback.Get("error_description")}
	}
	if p.clock().Sub(pending.CreatedAt) > pendingLoginTTL {
		return nil, fmt.Errorf("%w: the sign-in took too long, start again", ErrInvalidCallback)
	}
	code := callback.Get("code")
	if code == "" || len(callback["code"]) != 1 {
		return nil, fmt.Errorf("%w: no authorization code", ErrInvalidCallback)
	}
	started := p.clock()
	tr, _, err := l.cl.token(ctx, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {l.redirect}, "code_verifier": {pending.CodeVerifier},
	})
	if err != nil {
		return nil, err
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("%w: the token response has no ID token", ErrInvalidToken)
	}
	user, err := l.verifyIDToken(ctx, tr.IDToken, idTokenCheck{nonce: pending.Nonce, checkNonce: true, maxAge: pending.MaxAge, accessToken: tr.AccessToken})
	if err != nil {
		return nil, err
	}
	if l.userInfo {
		if user, err = l.mergeUserInfo(ctx, user, tr.AccessToken); err != nil {
			return nil, err
		}
	}
	p.log.InfoContext(ctx, "iam: user signed in", "sub", user.Subject)
	return &LoginResult{User: user, Tokens: tokenSet(tr, started), ReturnTo: pending.ReturnTo}, nil
}

func tokenSet(tr *tokenResponse, issued time.Time) *TokenSet {
	return &TokenSet{
		AccessToken: tr.AccessToken, Expiry: issued.Add(time.Duration(tr.ExpiresIn) * time.Second),
		IDToken: tr.IDToken, RefreshToken: tr.RefreshToken, Scopes: splitScope(tr.Scope),
	}
}

// Refresh redeems a refresh token. IAM rotates refresh tokens: the result
// carries a new one and the old value must never be used again, or IAM
// revokes the whole chain. Therefore:
//
//   - concurrent calls with the same refresh token are merged into one
//     request, and for a minute afterwards a call with that old value gets
//     the same result instead of asking IAM again;
//   - the caller must store the new refresh token atomically.
//
// This protects one process. Several instances sharing sessions need a
// store with atomic updates, see SessionStore.
//
// When IAM answers invalid_grant the error matches ErrLoginRequired: the
// user has to sign in again.
func (l *Login) Refresh(ctx context.Context, refreshToken string) (*LoginResult, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("%w: no refresh token", ErrLoginRequired)
	}
	sum := sha256.Sum256([]byte(refreshToken))
	key := string(sum[:])
	now := l.cl.p.clock()

	l.refreshMu.Lock()
	for k, c := range l.refreshes {
		if !c.until.IsZero() && !now.Before(c.until) {
			delete(l.refreshes, k)
		}
	}
	call := l.refreshes[key]
	if call == nil {
		call = &refreshCall{fl: newFlight()}
		l.refreshes[key] = call
		go func() {
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tokenFetchTimeout)
			defer cancel()
			result, err := l.refresh(fctx, refreshToken)
			l.refreshMu.Lock()
			if err == nil {
				call.result, call.until = result, l.cl.p.clock().Add(recentRefreshTTL)
			} else {
				delete(l.refreshes, key)
			}
			l.refreshMu.Unlock()
			call.fl.finish(err)
		}()
	}
	l.refreshMu.Unlock()
	if err := call.fl.wait(ctx); err != nil {
		return nil, err
	}
	return call.result, nil
}

func (l *Login) refresh(ctx context.Context, refreshToken string) (*LoginResult, error) {
	started := l.cl.p.clock()
	tr, _, err := l.cl.token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
	if err != nil {
		var oe *OAuthError
		if errors.As(err, &oe) && oe.Code == "invalid_grant" {
			return nil, fmt.Errorf("%w: %w", ErrLoginRequired, err)
		}
		return nil, err
	}
	result := &LoginResult{Tokens: tokenSet(tr, started)}
	if tr.IDToken != "" {
		// A refreshed ID token repeats the original nonce and auth_time;
		// neither is checked again.
		result.User, err = l.verifyIDToken(ctx, tr.IDToken, idTokenCheck{maxAge: -1, accessToken: tr.AccessToken})
		switch {
		case errors.Is(err, ErrInvalidToken):
			return nil, err
		case err != nil:
			// The ID token could not be checked (signing keys unreachable).
			// IAM has already rotated the refresh token, so the new tokens
			// must not be lost: return them without the unverified ID token.
			l.cl.p.log.WarnContext(ctx, "iam: the refreshed ID token could not be verified and is discarded", "error", err.Error())
			result.User, result.Tokens.IDToken = nil, ""
		}
	}
	return result, nil
}

// UserInfo reads the user's current profile with the access token of a
// sign-in. subject is the user ID of the ID token: a response about another
// user is refused.
func (l *Login) UserInfo(ctx context.Context, accessToken, subject string) (*User, error) {
	p := l.cl.p
	meta, err := p.metadata(ctx)
	if err != nil {
		return nil, err
	}
	if meta.UserinfoEndpoint == "" {
		return nil, &NetworkError{Op: "userinfo", Err: errors.New("the issuer has no userinfo endpoint")}
	}
	req, err := http.NewRequest(http.MethodGet, meta.UserinfoEndpoint, nil)
	if err != nil {
		return nil, &NetworkError{Op: "userinfo", Err: errors.New("invalid endpoint address")}
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, body, err := p.do(ctx, "userinfo", req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, protocolError("userinfo", res, body)
	}
	var u User
	if err := json.Unmarshal(body, &userInfoClaims{User: &u}); err != nil || u.Subject == "" {
		return nil, &NetworkError{Op: "userinfo", Err: errors.New("the userinfo response is malformed")}
	}
	if u.Subject != subject {
		return nil, fmt.Errorf("%w: the userinfo response is about another user", ErrInvalidToken)
	}
	u.Issuer = p.issuer
	return &u, nil
}

// userInfoClaims decodes a UserInfo response, which has no iss, auth_time,
// amr or sid.
type userInfoClaims struct{ *User }

func (c *userInfoClaims) UnmarshalJSON(data []byte) error {
	var v struct {
		Sub               string `json:"sub"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	c.Subject, c.Name, c.PreferredUsername, c.Email, c.EmailVerified = v.Sub, v.Name, v.PreferredUsername, v.Email, v.EmailVerified
	return nil
}

// mergeUserInfo overlays the profile from UserInfo on the identity of the
// ID token.
func (l *Login) mergeUserInfo(ctx context.Context, user *User, accessToken string) (*User, error) {
	info, err := l.UserInfo(ctx, accessToken, user.Subject)
	if err != nil {
		return nil, err
	}
	merged := *user
	merged.Name, merged.PreferredUsername, merged.Email, merged.EmailVerified = info.Name, info.PreferredUsername, info.Email, info.EmailVerified
	return &merged, nil
}

// LogoutURL returns the address of IAM's logout endpoint for RP-initiated
// logout. Clear the local session first, then redirect the browser here.
// IAM only returns to PostLogoutRedirectURL (with state) when idTokenHint is
// an ID token it issued to this application; without it the user stays on
// IAM's "signed out" page.
func (l *Login) LogoutURL(ctx context.Context, idTokenHint, state string) (string, error) {
	meta, err := l.cl.p.metadata(ctx)
	if err != nil {
		return "", err
	}
	if meta.EndSessionEndpoint == "" {
		return "", &NetworkError{Op: "discovery", Err: errors.New("the issuer has no logout endpoint")}
	}
	endpoint, err := url.Parse(meta.EndSessionEndpoint)
	if err != nil {
		return "", &NetworkError{Op: "discovery", Err: errors.New("the logout endpoint is not a valid URL")}
	}
	q := endpoint.Query()
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if l.postLogout != "" {
		q.Set("post_logout_redirect_uri", l.postLogout)
		if state != "" {
			q.Set("state", state)
		}
	}
	endpoint.RawQuery = q.Encode()
	return endpoint.String(), nil
}

// Revoke revokes a refresh token of this application at IAM, which ends the
// whole refresh chain. IAM answers successfully whether or not the token
// existed.
func (l *Login) Revoke(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return nil
	}
	return l.cl.revoke(ctx, refreshToken, "refresh_token")
}

type userKey struct{}

// ContextWithUser returns a context carrying the signed-in user. The
// adapters call it before invoking the application's handler.
func ContextWithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, userKey{}, user)
}

// UserFromContext returns the signed-in user stored by an adapter, or nil
// when the request did not pass the login middleware.
func UserFromContext(ctx context.Context) *User {
	user, _ := ctx.Value(userKey{}).(*User)
	return user
}

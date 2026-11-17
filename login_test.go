package iam_test

import (
	"bytes"
	"crypto"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamtest"
	"github.com/nixuw/iam-go-sdk/internal/hooks"
)

var alice = iamtest.User{Subject: "0b7c7a3e-user-alice", Name: "Alice Example", Username: "alice", Email: "alice@example.test", EmailVerified: true, AMR: []string{"pwd", "otp"}}

// loginIssuer is a fake issuer with one OIDC application and a signed-in
// user.
func loginIssuer(t *testing.T) *iamtest.Issuer {
	t.Helper()
	iss := iamtest.NewIssuer(t)
	iss.AddLoginClient(iamtest.LoginClient{
		ID: appID, Secret: "ssk_portal_secret", RedirectURIs: []string{redirect},
		PostLogoutRedirectURIs: []string{"https://portal.example.test/"}, RefreshTokens: true,
	})
	iss.SignIn(alice)
	return iss
}

func newLogin(t *testing.T, iss *iamtest.Issuer, mutate ...func(*iam.LoginConfig)) *iam.Login {
	t.Helper()
	cfg := iam.LoginConfig{
		Issuer: iss.URL(), ClientID: appID, Credential: iam.ClientSecret("ssk_portal_secret"), RedirectURL: redirect,
		Scopes: []string{"openid", "profile", "email"}, HTTPClient: iss.HTTPClient(),
	}
	for _, m := range mutate {
		m(&cfg)
	}
	l, err := iam.NewLogin(ctx, cfg)
	if err != nil {
		t.Fatalf("NewLogin: %v", err)
	}
	return l
}

// visit plays the browser: it follows the authorization URL to the fake
// issuer and returns the parameters of the redirect back to the callback.
func visit(t *testing.T, iss *iamtest.Issuer, authURL string) url.Values {
	t.Helper()
	client := *iss.HTTPClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("the authorization endpoint answered HTTP %d", res.StatusCode)
	}
	back, err := url.Parse(res.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(back.String(), redirect) {
		t.Fatalf("redirected to %q", res.Header.Get("Location"))
	}
	return back.Query()
}

// signIn runs a complete sign-in through the protocol-only API.
func signIn(t *testing.T, iss *iamtest.Issuer, l *iam.Login, opts iam.AuthOptions) (*iam.LoginResult, error) {
	t.Helper()
	req, err := l.AuthCodeURL(ctx, opts)
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	return l.Exchange(ctx, &req.Pending, visit(t, iss, req.URL))
}

// TestLoginProtocol covers LOGIN-01 to LOGIN-04 and LOGIN-09: the two
// protocol-level operations an application with its own sessions uses.
func TestLoginProtocol(t *testing.T) {
	iss := loginIssuer(t)
	l := newLogin(t, iss)

	a, err := l.AuthCodeURL(ctx, iam.AuthOptions{ReturnTo: "/reports?year=2026", LoginHint: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := l.AuthCodeURL(ctx, iam.AuthOptions{ReturnTo: "https://evil.example.test/"})
	u, _ := url.Parse(a.URL)
	q := u.Query()
	if !strings.HasPrefix(a.URL, iss.URL()+iamtest.PathAuthorize+"?") || q.Get("response_type") != "code" || q.Get("client_id") != appID ||
		q.Get("redirect_uri") != redirect || q.Get("scope") != "openid profile email" || q.Get("code_challenge_method") != "S256" ||
		q.Get("state") != a.Pending.State || q.Get("nonce") != a.Pending.Nonce || q.Get("login_hint") != "alice" {
		t.Fatalf("authorization request: %v", q)
	}
	if len(a.Pending.State) < 43 || len(a.Pending.Nonce) < 43 || len(a.Pending.CodeVerifier) < 43 || len(q.Get("code_challenge")) != 43 {
		t.Fatalf("one-time values are too short: %+v", a.Pending)
	}
	if strings.Contains(a.URL, a.Pending.CodeVerifier) {
		t.Fatal("the code verifier must never leave the server")
	}
	// Fresh values for every sign-in.
	if a.Pending.State == b.Pending.State || a.Pending.Nonce == b.Pending.Nonce || a.Pending.CodeVerifier == b.Pending.CodeVerifier {
		t.Fatal("state, nonce and PKCE must be generated anew for every sign-in")
	}
	// Only local return addresses are kept.
	if a.Pending.ReturnTo != "/reports?year=2026" || b.Pending.ReturnTo != "" {
		t.Fatalf("return addresses: %q %q", a.Pending.ReturnTo, b.Pending.ReturnTo)
	}

	callback := visit(t, iss, a.URL)
	result, err := l.Exchange(ctx, &a.Pending, callback)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	user := result.User
	if user.Issuer != iss.URL() || user.Subject != alice.Subject || user.Name != "Alice Example" || user.PreferredUsername != "alice" ||
		user.Email != "alice@example.test" || !user.EmailVerified || strings.Join(user.AMR, " ") != "pwd otp" || user.AuthTime.IsZero() || user.SessionID == "" {
		t.Fatalf("user: %+v", user)
	}
	if result.Tokens.AccessToken == "" || result.Tokens.IDToken == "" || result.Tokens.RefreshToken == "" || result.Tokens.Expiry.Before(time.Now()) || result.ReturnTo != "/reports?year=2026" {
		t.Fatalf("tokens: %+v", result.Tokens)
	}
	// The code was redeemed with PKCE and cannot be used again.
	_, err = l.Exchange(ctx, &a.Pending, callback)
	var oe *iam.OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Fatalf("second exchange of the same code: %v", err)
	}

	// private_key_jwt works for the OIDC application as well.
	key := newRSAKey(t)
	iss.AddLoginClient(iamtest.LoginClient{ID: "app_example_key", PublicKeys: map[string]crypto.PublicKey{"portal-1": &key.PublicKey}, RedirectURIs: []string{redirect}})
	byKey := newLogin(t, iss, func(c *iam.LoginConfig) {
		c.ClientID, c.Credential = "app_example_key", iam.PrivateKeyJWT("portal-1", key)
	})
	if res, err := signIn(t, iss, byKey, iam.AuthOptions{}); err != nil || res.User.Subject != alice.Subject || res.Tokens.RefreshToken != "" {
		t.Fatalf("sign-in with private_key_jwt: %v", err)
	}
}

// TestLoginSecurityChecks is AC-04: each of these must fail the sign-in.
func TestLoginSecurityChecks(t *testing.T) {
	iss := loginIssuer(t)
	l := newLogin(t, iss)
	type attempt struct {
		pending  func(*iam.PendingLogin)
		callback func(url.Values)
		idToken  func(claims map[string]any, sign func(header, claims map[string]any) string) string
		want     error
	}
	for name, a := range map[string]attempt{
		"state does not match":         {callback: func(q url.Values) { q.Set("state", "someone-elses-state") }, want: iam.ErrInvalidCallback},
		"state missing":                {callback: func(q url.Values) { q.Del("state") }, want: iam.ErrInvalidCallback},
		"iss is another issuer":        {callback: func(q url.Values) { q.Set("iss", "https://attacker.example.test") }, want: iam.ErrInvalidCallback},
		"iss with a trailing slash":    {callback: func(q url.Values) { q.Set("iss", q.Get("iss")+"/") }, want: iam.ErrInvalidCallback},
		"iss missing":                  {callback: func(q url.Values) { q.Del("iss") }, want: iam.ErrInvalidCallback},
		"code missing":                 {callback: func(q url.Values) { q.Del("code") }, want: iam.ErrInvalidCallback},
		"sign-in started too long ago": {pending: func(p *iam.PendingLogin) { p.CreatedAt = p.CreatedAt.Add(-time.Hour) }, want: iam.ErrInvalidCallback},
		"nonce does not match":         {pending: func(p *iam.PendingLogin) { p.Nonce = "another-nonce" }, want: iam.ErrInvalidToken},
		"ID token for another client": {idToken: func(c map[string]any, _ func(h, c map[string]any) string) string {
			c["aud"] = "app_someone_else"
			return ""
		}, want: iam.ErrInvalidToken},
		"ID token with two audiences": {idToken: func(c map[string]any, _ func(h, c map[string]any) string) string {
			c["aud"] = []string{appID, "app_someone_else"}
			return ""
		}, want: iam.ErrInvalidToken},
		"ID token expired": {idToken: func(c map[string]any, _ func(h, c map[string]any) string) string {
			c["exp"] = time.Now().Add(-5 * time.Minute).Unix()
			return ""
		}, want: iam.ErrInvalidToken},
		"ID token from another issuer": {idToken: func(c map[string]any, _ func(h, c map[string]any) string) string {
			c["iss"] = "https://attacker.example.test"
			return ""
		}, want: iam.ErrInvalidToken},
		"ID token signature invalid": {idToken: func(c map[string]any, sign func(h, c map[string]any) string) string {
			token := sign(map[string]any{"typ": "JWT"}, c)
			return token[:strings.LastIndex(token, ".")+1] + strings.Repeat("A", 342)
		}, want: iam.ErrInvalidToken},
		"ID token signed with an unknown key": {idToken: func(c map[string]any, sign func(h, c map[string]any) string) string {
			return sign(map[string]any{"typ": "JWT", "kid": "unknown-key"}, c)
		}, want: iam.ErrInvalidToken},
		"ID token without signature (alg none)": {idToken: func(c map[string]any, _ func(h, c map[string]any) string) string {
			return b64(map[string]any{"alg": "none", "typ": "JWT"}) + "." + b64(c) + "."
		}, want: iam.ErrInvalidToken},
		"an access token in place of the ID token": {idToken: func(c map[string]any, sign func(h, c map[string]any) string) string {
			return sign(map[string]any{"typ": "at+jwt"}, c)
		}, want: iam.ErrInvalidToken},
		"at_hash does not match the access token": {idToken: func(c map[string]any, _ func(h, c map[string]any) string) string {
			c["at_hash"] = "AAAAAAAAAAAAAAAAAAAAAA"
			return ""
		}, want: iam.ErrInvalidToken},
	} {
		t.Run(name, func(t *testing.T) {
			iss.OnIDToken(a.idToken)
			defer iss.OnIDToken(nil)
			req, err := l.AuthCodeURL(ctx, iam.AuthOptions{})
			if err != nil {
				t.Fatal(err)
			}
			callback := visit(t, iss, req.URL)
			if a.callback != nil {
				a.callback(callback)
			}
			if a.pending != nil {
				a.pending(&req.Pending)
			}
			result, err := l.Exchange(ctx, &req.Pending, callback)
			if result != nil || !errors.Is(err, a.want) {
				t.Fatalf("the sign-in must fail with %v, got %v", a.want, err)
			}
		})
	}
	// Without a pending sign-in there is nothing to complete.
	if _, err := l.Exchange(ctx, nil, url.Values{"state": {"x"}, "code": {"y"}, "iss": {iss.URL()}}); !errors.Is(err, iam.ErrInvalidCallback) {
		t.Fatalf("callback without a pending sign-in: %v", err)
	}
	// And the plain case still works after all of the above.
	if _, err := signIn(t, iss, l, iam.AuthOptions{}); err != nil {
		t.Fatalf("regular sign-in: %v", err)
	}
}

// LOGIN-02: error responses of IAM reach the application as *OAuthError.
func TestErrorCallbacks(t *testing.T) {
	iss := loginIssuer(t)
	l := newLogin(t, iss)
	iss.FailAuthorize("access_denied")
	_, err := signIn(t, iss, l, iam.AuthOptions{})
	var oe *iam.OAuthError
	if !errors.As(err, &oe) || oe.Code != "access_denied" || oe.StatusCode != 0 {
		t.Fatalf("access_denied: %v", err)
	}
	// prompt=none while nobody is signed in at IAM.
	iss.SignOut()
	_, err = signIn(t, iss, l, iam.AuthOptions{Prompt: "none"})
	if !errors.As(err, &oe) || oe.Code != "login_required" {
		t.Fatalf("prompt=none: %v", err)
	}
	// An error callback is only believed with the right state and issuer.
	iss.FailAuthorize("consent_required")
	req, _ := l.AuthCodeURL(ctx, iam.AuthOptions{Prompt: "none"})
	callback := visit(t, iss, req.URL)
	callback.Set("iss", "https://attacker.example.test")
	if _, err := l.Exchange(ctx, &req.Pending, callback); !errors.Is(err, iam.ErrInvalidCallback) {
		t.Fatalf("error callback with a foreign iss: %v", err)
	}
	for _, prompt := range []string{"select_account", "none login"} {
		if _, err := l.AuthCodeURL(ctx, iam.AuthOptions{Prompt: prompt}); !errors.Is(err, iam.ErrConfig) {
			t.Fatalf("prompt %q: %v", prompt, err)
		}
	}
}

// LOGIN-01 / LOGIN-03: max_age is sent and auth_time is checked against it.
func TestMaxAge(t *testing.T) {
	iss := loginIssuer(t)
	l := newLogin(t, iss)
	req, _ := l.AuthCodeURL(ctx, iam.AuthOptions{MaxAge: 5 * time.Minute, Prompt: "login"})
	u, _ := url.Parse(req.URL)
	if u.Query().Get("max_age") != "300" || u.Query().Get("prompt") != "login" || req.Pending.MaxAge != 300 {
		t.Fatalf("max_age / prompt not sent: %v", u.Query())
	}
	if _, err := l.Exchange(ctx, &req.Pending, visit(t, iss, req.URL)); err != nil {
		t.Fatalf("fresh authentication: %v", err)
	}
	// IAM answers with an authentication older than requested.
	iss.OnIDToken(func(c map[string]any, _ func(h, c map[string]any) string) string {
		c["auth_time"] = time.Now().Add(-time.Hour).Unix()
		return ""
	})
	if _, err := signIn(t, iss, l, iam.AuthOptions{MaxAge: 5 * time.Minute}); !errors.Is(err, iam.ErrInvalidToken) {
		t.Fatalf("stale authentication: %v", err)
	}
	iss.OnIDToken(func(c map[string]any, _ func(h, c map[string]any) string) string {
		delete(c, "auth_time")
		return ""
	})
	if _, err := signIn(t, iss, l, iam.AuthOptions{MaxAge: 5 * time.Minute}); !errors.Is(err, iam.ErrInvalidToken) {
		t.Fatalf("auth_time missing: %v", err)
	}
}

// LOGIN-07 at the protocol level: refresh tokens rotate, concurrent
// refreshes are merged, and invalid_grant means "sign in again".
func TestRefresh(t *testing.T) {
	iss := loginIssuer(t)
	l := newLogin(t, iss)
	result, err := signIn(t, iss, l, iam.AuthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	first := result.Tokens.RefreshToken
	before := iss.Requests(iamtest.PathToken)

	var wg sync.WaitGroup
	results := make([]*iam.LoginResult, 20)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := l.Refresh(ctx, first)
			if err != nil {
				t.Errorf("concurrent refresh: %v", err)
			}
			results[i] = r
		}()
	}
	wg.Wait()
	if n := iss.Requests(iamtest.PathToken) - before; n != 1 {
		t.Fatalf("%d refresh requests for 20 concurrent calls, want 1", n)
	}
	second := results[0].Tokens.RefreshToken
	for _, r := range results {
		if r == nil || r.Tokens.RefreshToken != second || second == first || r.User == nil || r.User.Subject != alice.Subject {
			t.Fatalf("refresh results differ or did not rotate")
		}
	}
	// A straggler that still holds the old value gets the same result
	// instead of triggering IAM's reuse detection.
	late, err := l.Refresh(ctx, first)
	if err != nil || late.Tokens.RefreshToken != second || iss.Requests(iamtest.PathToken)-before != 1 {
		t.Fatalf("late refresh with the old value: %v", err)
	}
	// The chain continues with the new value.
	third, err := l.Refresh(ctx, second)
	if err != nil || third.Tokens.RefreshToken == second {
		t.Fatalf("refresh with the rotated value: %v", err)
	}
	// The user signs out at IAM: the next refresh is refused for good.
	iss.SignOut()
	_, err = l.Refresh(ctx, third.Tokens.RefreshToken)
	var oe *iam.OAuthError
	if !errors.Is(err, iam.ErrLoginRequired) || !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Fatalf("refresh after the IAM session ended: %v", err)
	}
	if _, err := l.Refresh(ctx, ""); !errors.Is(err, iam.ErrLoginRequired) {
		t.Fatalf("refresh without a token: %v", err)
	}
}

// LOGIN-04: the latest profile from UserInfo, bound to the same subject.
func TestUserInfo(t *testing.T) {
	iss := loginIssuer(t)
	l := newLogin(t, iss, func(c *iam.LoginConfig) { c.FetchUserInfo = true })
	result, err := signIn(t, iss, l, iam.AuthOptions{})
	if err != nil || result.User.Name != "Alice Example" || result.User.SessionID == "" || len(result.User.AMR) == 0 {
		t.Fatalf("sign-in with UserInfo: %v %+v", err, result)
	}
	if iss.Requests(iamtest.PathUserInfo) != 1 {
		t.Fatalf("FetchUserInfo must read UserInfo once, saw %d requests", iss.Requests(iamtest.PathUserInfo))
	}
	// The profile changes at IAM: UserInfo has the latest data.
	iss.SignIn(iamtest.User{Subject: alice.Subject, Name: "Alice Renamed", Username: "alice", Email: "alice@example.test"})
	latest, err := l.UserInfo(ctx, result.Tokens.AccessToken, alice.Subject)
	if err != nil || latest.Name != "Alice Renamed" || latest.Subject != alice.Subject || latest.Issuer != iss.URL() {
		t.Fatalf("UserInfo: %v %+v", err, latest)
	}
	if _, err := l.UserInfo(ctx, result.Tokens.AccessToken, "another-user"); !errors.Is(err, iam.ErrInvalidToken) {
		t.Fatalf("UserInfo about another subject: %v", err)
	}
	// An ID token is not an access token.
	_, err = l.UserInfo(ctx, result.Tokens.IDToken, alice.Subject)
	var oe *iam.OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_token" || oe.StatusCode != 401 {
		t.Fatalf("UserInfo with an ID token: %v", err)
	}
}

// LOGIN-08: the logout address.
func TestLogoutURL(t *testing.T) {
	iss := loginIssuer(t)
	l := newLogin(t, iss, func(c *iam.LoginConfig) { c.PostLogoutRedirectURL = "https://portal.example.test/" })
	result, err := signIn(t, iss, l, iam.AuthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := l.LogoutURL(ctx, result.Tokens.IDToken, "bye")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	if !strings.HasPrefix(raw, iss.URL()+iamtest.PathLogout) || u.Query().Get("id_token_hint") != result.Tokens.IDToken ||
		u.Query().Get("post_logout_redirect_uri") != "https://portal.example.test/" || u.Query().Get("state") != "bye" {
		t.Fatalf("logout URL: %v", u.Query())
	}
	// IAM returns to the registered address, with the state.
	client := *iss.HTTPClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Get(raw)
	if err != nil || res.Header.Get("Location") != "https://portal.example.test/?state=bye" {
		t.Fatalf("logout redirect: %v %q", err, res.Header.Get("Location"))
	}
	res.Body.Close()
	// Revoking the refresh token ends the chain.
	if err := l.Revoke(ctx, result.Tokens.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Refresh(ctx, result.Tokens.RefreshToken); !errors.Is(err, iam.ErrLoginRequired) {
		t.Fatalf("refresh after revocation: %v", err)
	}
}

func TestLoginConfiguration(t *testing.T) {
	iss := loginIssuer(t)
	base := iam.LoginConfig{Issuer: iss.URL(), ClientID: appID, Credential: iam.ClientSecret("s"), RedirectURL: redirect, HTTPClient: iss.HTTPClient()}
	for field, mutate := range map[string]func(*iam.LoginConfig){
		"Issuer":                func(c *iam.LoginConfig) { c.Issuer = "" },
		"ClientID":              func(c *iam.LoginConfig) { c.ClientID = "" },
		"Credential":            func(c *iam.LoginConfig) { c.Credential = nil },
		"RedirectURL":           func(c *iam.LoginConfig) { c.RedirectURL = "/callback" },
		"PostLogoutRedirectURL": func(c *iam.LoginConfig) { c.PostLogoutRedirectURL = "portal" },
		"Scopes":                func(c *iam.LoginConfig) { c.Scopes = []string{"openid", "order.read"} },
		"Leeway":                func(c *iam.LoginConfig) { c.Leeway = -time.Second },
		"SessionKey":            func(c *iam.LoginConfig) { c.SessionKey = []byte("too short") },
		"SessionMaxAge":         func(c *iam.LoginConfig) { c.SessionKey = bytes.Repeat([]byte{1}, 32); c.SessionMaxAge = -time.Hour },
		"AllowInsecureCookie": func(c *iam.LoginConfig) {
			c.SessionKey = bytes.Repeat([]byte{1}, 32)
			c.RedirectURL = "http://portal.example.test/callback"
		},
	} {
		cfg := base
		mutate(&cfg)
		var ce *iam.ConfigError
		if _, err := iam.NewLogin(ctx, cfg); !errors.As(err, &ce) || ce.Field != field {
			t.Fatalf("%s: %v", field, err)
		}
	}
	cfg := base
	cfg.Scopes = []string{"profile"}
	if _, err := iam.NewLogin(ctx, cfg); !errors.Is(err, iam.ErrConfig) {
		t.Fatalf("scopes without openid: %v", err)
	}
	// The default scopes are openid and profile.
	l := newLogin(t, iss, func(c *iam.LoginConfig) { c.Scopes = nil })
	req, _ := l.AuthCodeURL(ctx, iam.AuthOptions{})
	if u, _ := url.Parse(req.URL); u.Query().Get("scope") != "openid profile" {
		t.Fatalf("default scopes: %q", u.Query().Get("scope"))
	}
	_ = hooks.SetClock
}

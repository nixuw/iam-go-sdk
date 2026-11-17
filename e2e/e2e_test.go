//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamhttp"
	"github.com/nixuw/iam-go-sdk/internal/hooks"
	"github.com/nixuw/iam-go-sdk/internal/orderv1"
)

var ctx = context.Background()

// The provider application of the fixture is "order" with these permissions;
// they are the ones the examples use.
const (
	readScope  = "order.read"
	writeScope = "order.write"
)

var (
	readRule  = iam.Rule{Scopes: []string{readScope}, Principals: []string{iam.PrincipalService, iam.PrincipalUser}}
	writeRule = iam.Rule{Scopes: []string{writeScope}, Principals: []string{iam.PrincipalService}}
)

func orderTarget(scopes ...string) iam.Target {
	return iam.Target{Resource: fx.Provider.Resource, Scopes: scopes}
}

func secretCaller(t *testing.T, tr *countingTransport) *iam.Caller {
	t.Helper()
	cfg := iam.CallerConfig{
		Issuer: fx.Issuer, ClientID: fx.CallerSecret.ClientID, Credential: iam.ClientSecret(fx.CallerSecret.ClientSecret),
		AllowInsecureIssuer: fx.AllowInsecure, AllowInsecureTransport: fx.AllowInsecure,
	}
	if tr != nil {
		cfg.HTTPClient = tr.client()
	}
	c, err := iam.NewCaller(ctx, cfg)
	if err != nil {
		t.Fatalf("NewCaller (client_secret_basic): %v", err)
	}
	return c
}

func keyCaller(t *testing.T) *iam.Caller {
	t.Helper()
	key, err := iam.ParsePrivateKeyPEM([]byte(fx.CallerKey.PrivateKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	c, err := iam.NewCaller(ctx, iam.CallerConfig{
		Issuer: fx.Issuer, ClientID: fx.CallerKey.ClientID, Credential: iam.PrivateKeyJWT(fx.CallerKey.KeyID, key),
		AllowInsecureIssuer: fx.AllowInsecure, AllowInsecureTransport: fx.AllowInsecure,
	})
	if err != nil {
		t.Fatalf("NewCaller (private_key_jwt): %v", err)
	}
	return c
}

func newVerifier(t *testing.T, tr *countingTransport, mutate ...func(*iam.VerifierConfig)) *iam.Verifier {
	t.Helper()
	cfg := iam.VerifierConfig{Issuer: fx.Issuer, Audience: fx.Provider.Resource, AllowInsecureIssuer: fx.AllowInsecure}
	if tr != nil {
		cfg.HTTPClient = tr.client()
	}
	for _, m := range mutate {
		m(&cfg)
	}
	v, err := iam.NewVerifier(ctx, cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func mustToken(t *testing.T, c *iam.Caller, target iam.Target) string {
	t.Helper()
	token, err := c.Token(ctx, target)
	if err != nil {
		t.Fatalf("token for %s %v: %v", target.Resource, target.Scopes, err)
	}
	return token
}

// ---- sign-in ------------------------------------------------------------------

func newLogin(t *testing.T) *iam.Login {
	t.Helper()
	l, err := iam.NewLogin(ctx, iam.LoginConfig{
		Issuer: fx.Issuer, ClientID: fx.Login.ClientID, Credential: iam.ClientSecret(fx.Login.ClientSecret),
		RedirectURL: fx.Login.BaseURL + "/callback", PostLogoutRedirectURL: fx.Login.BaseURL + "/",
		Scopes: []string{"openid", "profile", "email"}, AllowInsecureIssuer: fx.AllowInsecure,
	})
	if err != nil {
		t.Fatalf("NewLogin: %v", err)
	}
	return l
}

var (
	signInOnce   sync.Once
	signInResult *iam.LoginResult
)

// userTokens signs the fixture's user in once, through the protocol-level
// API, and returns the tokens of that sign-in: an ID token and an access
// token for UserInfo. Neither may ever be accepted by a provider.
func userTokens(t *testing.T) *iam.LoginResult {
	t.Helper()
	if fx.ControlURL == "" {
		t.Skip("this scenario needs the test operator (control_url in the fixture)")
	}
	signInOnce.Do(func() {
		l := newLogin(t)
		req, err := l.AuthCodeURL(ctx, iam.AuthOptions{})
		if err != nil {
			t.Fatalf("AuthCodeURL: %v", err)
		}
		signInResult, err = l.Exchange(ctx, &req.Pending, userAuthorizes(t, "tokens", req.URL).Query())
		if err != nil {
			t.Fatalf("Exchange: %v", err)
		}
	})
	if signInResult == nil {
		t.Fatal("the sign-in for the token batch failed earlier")
	}
	return signInResult
}

// TestLoginExample is AC-03: the sign-in example, as shipped, against the
// real IAM: sign-in, callback, the user's identity, a protected page, logout
// and the return from IAM.
func TestLoginExample(t *testing.T) {
	if fx.ControlURL == "" {
		t.Skip("this scenario needs the test operator (control_url in the fixture)")
	}
	base := fx.Login.BaseURL
	site, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	serveExample(t, "login-fiber", site.Host,
		"IAM_CLIENT_ID="+fx.Login.ClientID, "IAM_CLIENT_SECRET="+fx.Login.ClientSecret,
		"APP_BASE_URL="+base, "APP_SESSION_KEY="+strings.Repeat("e2e-session-key.", 2))

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(rawURL string) (int, string, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
		req.Header.Set("Accept", "text/html")
		res, err := browser.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", rawURL, err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		location := res.Header.Get("Location")
		if strings.HasPrefix(location, "/") {
			location = base + location
		}
		return res.StatusCode, location, string(body)
	}

	// A protected page sends the browser to the login path, which sends it
	// on to IAM.
	status, location, _ := get(base + "/profile")
	if status != http.StatusFound || location != base+"/login?return_to=%2Fprofile" {
		t.Fatalf("protected page without a session: HTTP %d → %s", status, location)
	}
	status, location, _ = get(location)
	if status != http.StatusFound || !strings.HasPrefix(location, fx.Issuer+"/") {
		t.Fatalf("login path: HTTP %d → %s", status, location)
	}
	// The user signs in at IAM, which redirects back with code, state, iss.
	callback := userAuthorizes(t, "login-example", location)
	if !strings.HasPrefix(callback.String(), base+"/callback?") || callback.Query().Get("code") == "" || callback.Query().Get("iss") != fx.Issuer {
		t.Fatalf("IAM redirected to %s", callback)
	}
	// The callback establishes the session and returns to the page.
	status, location, body := get(callback.String())
	if status != http.StatusFound || location != base+"/profile" {
		t.Fatalf("callback: HTTP %d → %s %s", status, location, body)
	}
	status, _, body = get(base + "/profile")
	var user map[string]string
	if status != http.StatusOK || json.Unmarshal([]byte(body), &user) != nil || user["sub"] != fx.Login.Subject || user["iss"] != fx.Issuer ||
		user["name"] != fx.Login.Name || user["email"] != fx.Login.Email {
		t.Fatalf("protected page after sign-in: HTTP %d %s", status, body)
	}
	// The same callback cannot be used a second time.
	if status, _, _ := get(callback.String()); status != http.StatusBadRequest {
		t.Fatalf("replayed callback: HTTP %d", status)
	}

	// Logout: the local session ends, then IAM's, and IAM returns to the
	// registered address with the state.
	status, location, _ = get(base + "/logout")
	logout, _ := url.Parse(location)
	if status != http.StatusFound || !strings.HasPrefix(location, fx.Issuer+"/") || logout.Query().Get("id_token_hint") == "" ||
		logout.Query().Get("post_logout_redirect_uri") != base+"/" || logout.Query().Get("state") == "" {
		t.Fatalf("logout: HTTP %d → %s", status, location)
	}
	back := userConfirmsLogout(t, "login-example", location)
	if back != base+"/?state="+logout.Query().Get("state") {
		t.Fatalf("IAM returned to %q after logout", back)
	}
	if status, _, _ := get(back); status != http.StatusOK {
		t.Fatalf("post-logout page: HTTP %d", status)
	}
	if status, location, _ := get(base + "/profile"); status != http.StatusFound || !strings.HasPrefix(location, base+"/login") {
		t.Fatalf("protected page after logout: HTTP %d → %s", status, location)
	}
}

// TestSignInProtocol runs the protocol-level sign-in (LOGIN-09) against the
// real IAM, with the checks of AC-04 that a real callback allows, refresh
// with rotation, and the end of the refresh chain when the user signs out
// at IAM.
func TestSignInProtocol(t *testing.T) {
	if fx.ControlURL == "" {
		t.Skip("this scenario needs the test operator (control_url in the fixture)")
	}
	l := newLogin(t)
	req, err := l.AuthCodeURL(ctx, iam.AuthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	callback := userAuthorizes(t, "protocol", req.URL).Query()

	// A callback with another state or another issuer is refused before
	// anything is sent to IAM; the code stays unused.
	for name, damage := range map[string]func(url.Values){
		"state": func(q url.Values) { q.Set("state", "not-the-state-of-this-sign-in") },
		"iss":   func(q url.Values) { q.Set("iss", fx.Issuer+"/") },
	} {
		damaged := url.Values{}
		for k, v := range callback {
			damaged[k] = v
		}
		damage(damaged)
		if _, err := l.Exchange(ctx, &req.Pending, damaged); !errors.Is(err, iam.ErrInvalidCallback) {
			t.Fatalf("callback with a wrong %s: %v", name, err)
		}
	}
	// The nonce binds the ID token to this sign-in.
	other, _ := l.AuthCodeURL(ctx, iam.AuthOptions{})
	otherCallback := userAuthorizes(t, "protocol", other.URL).Query()
	other.Pending.Nonce = "another-nonce"
	if _, err := l.Exchange(ctx, &other.Pending, otherCallback); !errors.Is(err, iam.ErrInvalidToken) {
		t.Fatalf("ID token with another nonce: %v", err)
	}

	result, err := l.Exchange(ctx, &req.Pending, callback)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if result.User.Subject != fx.Login.Subject || result.User.Issuer != fx.Issuer || result.User.Name != fx.Login.Name || result.User.Email != fx.Login.Email ||
		result.User.SessionID == "" || result.User.AuthTime.IsZero() || len(result.User.AMR) == 0 {
		t.Fatalf("user: %+v", result.User)
	}
	if jwtPart(t, result.Tokens.AccessToken, 1)["aud"] != fx.Issuer+"/oidc/userinfo" || jwtPart(t, result.Tokens.IDToken, 0)["typ"] != "JWT" || result.Tokens.RefreshToken == "" {
		t.Fatalf("tokens of the sign-in are not what IAM documents")
	}
	// The code is spent.
	var oe *iam.OAuthError
	if _, err := l.Exchange(ctx, &req.Pending, callback); !errors.As(err, &oe) || oe.Code != "invalid_grant" || oe.RequestID == "" {
		t.Fatalf("second exchange of the code: %v", err)
	}
	// UserInfo with the access token of the sign-in.
	info, err := l.UserInfo(ctx, result.Tokens.AccessToken, result.User.Subject)
	if err != nil || info.Subject != fx.Login.Subject || info.Name != fx.Login.Name {
		t.Fatalf("UserInfo: %v %+v", err, info)
	}
	if _, err := l.UserInfo(ctx, result.Tokens.IDToken, result.User.Subject); !errors.As(err, &oe) || oe.StatusCode != http.StatusUnauthorized {
		t.Fatalf("UserInfo must refuse an ID token: %v", err)
	}

	// Refresh: concurrent calls with one refresh token lead to one request,
	// the token rotates, and the chain continues.
	var wg sync.WaitGroup
	refreshed := make([]*iam.LoginResult, 8)
	for i := range refreshed {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := l.Refresh(ctx, result.Tokens.RefreshToken)
			if err != nil {
				t.Errorf("concurrent refresh: %v", err)
				return
			}
			refreshed[i] = r
		}()
	}
	wg.Wait()
	if t.Failed() {
		t.FailNow()
	}
	second := refreshed[0].Tokens.RefreshToken
	for _, r := range refreshed {
		if r.Tokens.RefreshToken != second || second == result.Tokens.RefreshToken || r.User == nil || r.User.Subject != fx.Login.Subject {
			t.Fatal("concurrent refreshes must share one rotated result")
		}
	}
	third, err := l.Refresh(ctx, second)
	if err != nil || third.Tokens.RefreshToken == second {
		t.Fatalf("the chain must survive the concurrent refresh (IAM saw the old token only once): %v", err)
	}

	// RP-initiated logout with the ID token as hint: IAM returns to the
	// registered address. Afterwards the session-bound refresh chain is dead.
	logoutURL, err := l.LogoutURL(ctx, third.Tokens.IDToken, "protocol-state")
	if err != nil {
		t.Fatal(err)
	}
	if back := userConfirmsLogout(t, "protocol", logoutURL); back != fx.Login.BaseURL+"/?state=protocol-state" {
		t.Fatalf("IAM returned to %q after logout", back)
	}
	if _, err := l.Refresh(ctx, third.Tokens.RefreshToken); !errors.Is(err, iam.ErrLoginRequired) {
		t.Fatalf("refresh after the user signed out at IAM: %v", err)
	}
}

// ---- caller -------------------------------------------------------------------

// TestSystemTokens is AC-06, with AC-07 and AC-08 against the real token
// endpoint.
func TestSystemTokens(t *testing.T) {
	tr := &countingTransport{}
	bySecret, byKey := secretCaller(t, tr), keyCaller(t)
	for name, c := range map[string]*iam.Caller{"client_secret_basic": bySecret, "private_key_jwt": byKey} {
		token := mustToken(t, c, orderTarget(readScope))
		header, claims := jwtPart(t, token, 0), jwtPart(t, token, 1)
		if claims["aud"] != fx.Provider.Resource || claims["principal_type"] != "service" || claims["sub"] != claims["client_id"] ||
			claims["scope"] != readScope || header["typ"] != "at+jwt" || header["alg"] != "RS256" {
			t.Fatalf("%s: token %v %v", name, header, claims)
		}
	}
	// Two requests in a row with private_key_jwt: every assertion is fresh,
	// IAM would refuse a repeated jti.
	mustToken(t, byKey, orderTarget(readScope, writeScope))

	// 100 calls, one request.
	before := tr.count("/token")
	first := mustToken(t, bySecret, orderTarget(readScope))
	for i := 0; i < 100; i++ {
		if mustToken(t, bySecret, orderTarget(readScope)) != first {
			t.Fatal("the cached token changed")
		}
	}
	if n := tr.count("/token") - before; n != 0 {
		t.Fatalf("%d token requests for 101 cached calls", n)
	}
	// One token per target: the token for the other application has its
	// audience, and no permission of this one.
	other := mustToken(t, bySecret, iam.Target{Resource: fx.OtherResource})
	if c := jwtPart(t, other, 1); c["aud"] != fx.OtherResource || strings.Contains(c["scope"].(string), "order.") {
		t.Fatalf("token for the other application: %v", c)
	}

	// A target without a grant: IAM refuses, the refusal is remembered and
	// not repeated.
	before = tr.count("/token")
	for i := 0; i < 50; i++ {
		_, err := bySecret.Token(ctx, iam.Target{Resource: fx.NoGrantResource})
		var oe *iam.OAuthError
		if !errors.As(err, &oe) || oe.Code != "invalid_target" || oe.StatusCode != http.StatusBadRequest || oe.RequestID == "" {
			t.Fatalf("no grant: %v", err)
		}
	}
	if n := tr.count("/token") - before; n != 1 {
		t.Fatalf("%d refused requests reached IAM for 50 calls, want 1", n)
	}
	// A permission outside the grant.
	_, err := byKey.Token(ctx, orderTarget("order.refund"))
	var oe *iam.OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_scope" {
		t.Fatalf("permission outside the grant: %v", err)
	}
	// IAM unreachable: the cached token is still handed out.
	tr.cut.Store(true)
	if mustToken(t, bySecret, orderTarget(readScope)) != first {
		t.Fatal("the cached token must stay usable while IAM is unreachable")
	}
	tr.cut.Store(false)
}

// ---- provider -----------------------------------------------------------------

// probe is one token of the batch and what a provider must answer to it on
// the read endpoint (order.read; service and user) and on the write endpoint
// (order.write; service only).
type probe struct {
	name        string
	token       string
	read, write int
}

var (
	batchOnce sync.Once
	batch     []probe
)

// tokenBatch assembles the tokens of the checklist of section 12 of the
// provider guide: tokens really issued by IAM, and forgeries made from them.
func tokenBatch(t *testing.T) []probe {
	t.Helper()
	signIn := userTokens(t)
	batchOnce.Do(func() {
		caller := secretCaller(t, nil)
		read := mustToken(t, caller, orderTarget(readScope))
		both := mustToken(t, caller, orderTarget(readScope, writeScope))
		parts := strings.Split(read, ".")
		header, claims := jwtPart(t, read, 0), jwtPart(t, read, 1)

		// alg none, with the claims of a valid token.
		none := b64(map[string]any{"alg": "none", "typ": "at+jwt", "kid": header["kid"]}) + "." + parts[1] + "."
		// HS256, with a public key of IAM as the secret.
		res, err := http.Get(fx.Issuer + "/oauth2/jwks")
		if err != nil {
			t.Fatal(err)
		}
		jwks, _ := io.ReadAll(res.Body)
		res.Body.Close()
		hs, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: jwks}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", header["kid"]))
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(claims)
		obj, _ := hs.Sign(payload)
		hs256, _ := obj.CompactSerialize()
		// More permissions written into the payload; the signature is the old one.
		claims["scope"] = readScope + " " + writeScope
		tampered := parts[0] + "." + b64(claims) + "." + parts[2]
		// A kid IAM does not publish.
		header["kid"] = "no-such-key"
		unknownKid := b64(header) + "." + parts[1] + "." + parts[2]

		batch = []probe{
			{"no token", "", 401, 401},
			{"system token with order.read", read, 200, 403},
			{"system token with order.read and order.write", both, 200, 200},
			{"user-delegated token", fx.Tokens.UserDelegated, 200, 403},
			{"token for another application", mustToken(t, caller, iam.Target{Resource: fx.OtherResource}), 401, 401},
			{"access token of a sign-in (aud is UserInfo)", signIn.Tokens.AccessToken, 401, 401},
			{"ID token", signIn.Tokens.IDToken, 401, 401},
			{"alg none", none, 401, 401},
			{"HS256 signed with a public key", hs256, 401, 401},
			{"payload changed", tampered, 401, 401},
			{"signature changed", parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2])), 401, 401},
			{"unknown kid", unknownKid, 401, 401},
			{"not a JWT", "not-a-token", 401, 401},
		}
	})
	if batch == nil {
		t.Fatal("the token batch could not be assembled earlier")
	}
	return batch
}

// answer is what a provider said to a probe.
type answer struct {
	status    int
	code      string // error of the challenge
	challenge string
}

func httpProbe(t *testing.T, method, rawURL, token string) answer {
	t.Helper()
	req, _ := http.NewRequest(method, rawURL, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	a := answer{status: res.StatusCode, challenge: res.Header.Get("WWW-Authenticate")}
	for _, code := range []string{"invalid_token", "insufficient_scope"} {
		if strings.Contains(a.challenge, `error="`+code+`"`) {
			a.code = code
		}
	}
	if a.status/100 == 2 {
		a.status = 200
	}
	return a
}

// sdkProvider serves the two endpoints behind the SDK's net/http middleware.
func sdkProvider(t *testing.T, v *iam.Verifier) string {
	t.Helper()
	guard := iamhttp.Guard(v)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(iamhttp.Caller(r).ClientID)) })
	mux := http.NewServeMux()
	mux.Handle("/items", guard.Require(readRule)(ok))
	mux.Handle("/items/write", guard.Require(writeRule)(ok))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

var (
	providersOnce                    sync.Once
	fiberAddr, netHTTPAddr, grpcAddr string
)

// exampleProviders starts the three provider examples once.
func exampleProviders(t *testing.T) {
	t.Helper()
	providersOnce.Do(func() {
		fiberAddr, netHTTPAddr, grpcAddr = freeAddr(t), freeAddr(t), freeAddr(t)
		serveExample(t, "provider-fiber", fiberAddr, "IAM_RESOURCE="+fx.Provider.Resource)
		serveExample(t, "provider-nethttp", netHTTPAddr, "IAM_RESOURCE="+fx.Provider.Resource)
		serveExample(t, "provider-grpc", grpcAddr, "IAM_RESOURCE="+fx.Provider.Resource)
	})
	if grpcAddr == "" {
		t.Fatal("the provider examples could not be started earlier")
	}
}

// TestProviderChecklist is AC-09 with tokens of the real IAM, and AC-14: the
// provider examples for Fiber, net/http and gRPC, as shipped, all give the
// answers the specification demands.
func TestProviderChecklist(t *testing.T) {
	probes := tokenBatch(t)
	exampleProviders(t)
	realm := `Bearer realm="` + fx.Provider.Resource + `"`

	check := func(t *testing.T, p probe, endpoint string, want int, got answer) {
		t.Helper()
		if got.status != want {
			t.Fatalf("%s on the %s endpoint: HTTP %d, want %d (%s)", p.name, endpoint, got.status, want, got.challenge)
		}
		switch {
		case want == 401 && p.token == "" && got.challenge != realm:
			t.Fatalf("%s: the challenge must carry the realm only: %q", p.name, got.challenge)
		case want == 401 && p.token != "" && (got.code != "invalid_token" || !strings.HasPrefix(got.challenge, realm)):
			t.Fatalf("%s: challenge %q", p.name, got.challenge)
		case want == 403 && (got.code != "insufficient_scope" || !strings.Contains(got.challenge, `scope="`+writeScope+`"`)):
			t.Fatalf("%s: challenge %q", p.name, got.challenge)
		}
		if p.token != "" && strings.Contains(got.challenge, p.token) {
			t.Fatalf("%s: the challenge echoes the token", p.name)
		}
	}

	inProcess := sdkProvider(t, newVerifier(t, nil))
	for name, urls := range map[string][2]string{
		"SDK middleware (net/http)": {inProcess + "/items", inProcess + "/items/write"},
		"example provider-fiber":    {"http://" + fiberAddr + "/api/orders/42", "http://" + fiberAddr + "/api/orders"},
		"example provider-nethttp":  {"http://" + netHTTPAddr + "/api/orders/42", "http://" + netHTTPAddr + "/api/orders"},
	} {
		t.Run(name, func(t *testing.T) {
			writeMethod := http.MethodPost
			if strings.HasSuffix(urls[1], "/items/write") {
				writeMethod = http.MethodGet
			}
			for _, p := range probes {
				check(t, p, "read", p.read, httpProbe(t, http.MethodGet, urls[0], p.token))
				check(t, p, "write", p.write, httpProbe(t, writeMethod, urls[1], p.token))
			}
		})
	}

	t.Run("example provider-grpc", func(t *testing.T) {
		conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		client := orderv1.NewOrderServiceClient(conn)
		want := map[int]codes.Code{200: codes.OK, 401: codes.Unauthenticated, 403: codes.PermissionDenied}
		for _, p := range probes {
			callCtx := ctx
			if p.token != "" {
				callCtx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+p.token)
			}
			var trailer metadata.MD
			_, err := client.GetOrder(callCtx, orderv1.NewText("42"), grpc.Trailer(&trailer))
			if status.Code(err) != want[p.read] {
				t.Fatalf("%s on GetOrder: %v, want %v", p.name, err, want[p.read])
			}
			if p.read == 401 && !strings.HasPrefix(strings.Join(trailer.Get("www-authenticate"), ""), realm) {
				t.Fatalf("%s on GetOrder: trailer %v", p.name, trailer)
			}
			if _, err := client.CreateOrder(callCtx, orderv1.NewText("x")); status.Code(err) != want[p.write] {
				t.Fatalf("%s on CreateOrder: %v, want %v", p.name, err, want[p.write])
			}
			// CancelOrder has no access rule in the example: closed.
			if _, err := client.CancelOrder(callCtx, orderv1.NewText("42")); status.Code(err) == codes.OK || status.Code(err) == codes.Unimplemented {
				t.Fatalf("%s reached a method without an access rule: %v", p.name, err)
			}
		}
	})

	// A token that has expired by more than the leeway: the provider's clock
	// is moved instead of waiting for the token's lifetime.
	t.Run("expired token", func(t *testing.T) {
		v := newVerifier(t, nil)
		token := mustToken(t, secretCaller(t, nil), orderTarget(readScope))
		exp := time.Unix(int64(jwtPart(t, token, 1)["exp"].(float64)), 0)
		hooks.SetClock(v, func() time.Time { return exp.Add(59 * time.Second) })
		if _, err := v.Verify(ctx, token, readRule); err != nil {
			t.Fatalf("59 s after exp is inside the leeway: %v", err)
		}
		hooks.SetClock(v, func() time.Time { return exp.Add(61 * time.Second) })
		if _, err := v.Verify(ctx, token, readRule); !errors.Is(err, iam.ErrInvalidToken) {
			t.Fatalf("61 s after exp: %v", err)
		}
	})
}

// TestSameVerdictAsIAM is AC-12: for the same batch of tokens, the SDK and
// IAM's own sample resource server reach the same verdict.
func TestSameVerdictAsIAM(t *testing.T) {
	if fx.Provider.SampleRSURL == "" {
		t.Skip("the fixture names no sample resource server of IAM")
	}
	probes := tokenBatch(t)
	sdk := sdkProvider(t, newVerifier(t, nil))
	for _, p := range probes {
		for _, path := range []string{"/items", "/items/write"} {
			theirs := httpProbe(t, http.MethodGet, fx.Provider.SampleRSURL+path, p.token)
			ours := httpProbe(t, http.MethodGet, sdk+path, p.token)
			if ours.status != theirs.status || ours.code != theirs.code {
				t.Errorf("%s on %s: the SDK says %d %q, IAM's sample resource server says %d %q", p.name, path, ours.status, ours.code, theirs.status, theirs.code)
			}
			if (ours.status == 401 || ours.status == 403) && ours.challenge != theirs.challenge {
				t.Errorf("%s on %s: challenges differ:\n  SDK: %s\n  IAM: %s", p.name, path, ours.challenge, theirs.challenge)
			}
		}
	}
}

// TestIntrospectionAndRevocation covers the optional parts: revocation by
// the caller and introspection by the provider (VERIFY-08).
func TestIntrospectionAndRevocation(t *testing.T) {
	v := newVerifier(t, nil, func(c *iam.VerifierConfig) {
		c.Introspection = &iam.IntrospectionConfig{ClientID: fx.Provider.Introspection.ClientID, Credential: iam.ClientSecret(fx.Provider.Introspection.ClientSecret)}
	})
	clock := time.Now()
	hooks.SetClock(v, func() time.Time { return clock })
	caller := secretCaller(t, nil)
	target := orderTarget(readScope)
	token := mustToken(t, caller, target)
	strict := readRule
	strict.Introspect = true
	if _, err := v.Verify(ctx, token, strict); err != nil {
		t.Fatalf("active token with introspection: %v", err)
	}
	if err := caller.Revoke(ctx, target); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// Offline validation cannot see the revocation ...
	if _, err := v.Verify(ctx, token, readRule); err != nil {
		t.Fatalf("offline validation of a revoked token: %v", err)
	}
	// ... introspection does, once the cached answer has aged out.
	clock = clock.Add(31 * time.Second)
	if _, err := v.Verify(ctx, token, strict); !errors.Is(err, iam.ErrInvalidToken) {
		t.Fatalf("revoked token with introspection: %v", err)
	}
	// A new token is active again; permissions are still checked.
	fresh := mustToken(t, caller, target)
	if fresh == token {
		t.Fatal("a revoked token was handed out again")
	}
	if _, err := v.Verify(ctx, fresh, strict); err != nil {
		t.Fatalf("new token with introspection: %v", err)
	}
	needsWrite := writeRule
	needsWrite.Introspect = true
	if _, err := v.Verify(ctx, fresh, needsWrite); !errors.Is(err, iam.ErrInsufficientScope) {
		t.Fatalf("introspection must not replace the permission check: %v", err)
	}
}

// ---- the examples together ----------------------------------------------------

// TestExamplesTogether is AC-13 and AC-14 with the programs as shipped: the
// caller examples obtain tokens from the real IAM and call the provider
// examples over HTTP and gRPC.
func TestExamplesTogether(t *testing.T) {
	exampleProviders(t)
	secretEnv := []string{"IAM_SVC_CLIENT_ID=" + fx.CallerSecret.ClientID, "IAM_SVC_CLIENT_SECRET=" + fx.CallerSecret.ClientSecret, "ORDER_RESOURCE=" + fx.Provider.Resource}
	keyFile := filepath.Join(t.TempDir(), "private.pem")
	if err := os.WriteFile(keyFile, []byte(fx.CallerKey.PrivateKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	keyEnv := []string{"IAM_SVC_CLIENT_ID=" + fx.CallerKey.ClientID, "IAM_SVC_KEY_ID=" + fx.CallerKey.KeyID, "IAM_SVC_PRIVATE_KEY_FILE=" + keyFile, "ORDER_RESOURCE=" + fx.Provider.Resource}

	for provider, addr := range map[string]string{"provider-fiber": fiberAddr, "provider-nethttp": netHTTPAddr} {
		for credential, env := range map[string][]string{"client_secret_basic": secretEnv, "private_key_jwt": keyEnv} {
			out, err := runExample(t, "caller", append(env, "ORDER_API_URL=http://"+addr)...)
			clientID := strings.TrimPrefix(env[0], "IAM_SVC_CLIENT_ID=")
			if err != nil || !strings.Contains(out, "HTTP 200") || !strings.Contains(out, `"requested_by":"`+clientID+`"`) {
				t.Fatalf("caller (%s) → %s: %v\n%s", credential, provider, err, out)
			}
		}
	}
	out, err := runExample(t, "caller-grpc", append(secretEnv, "ORDER_GRPC_ADDR="+grpcAddr)...)
	if err != nil || !strings.Contains(out, "order 42 requested by "+fx.CallerSecret.ClientID) {
		t.Fatalf("caller-grpc → provider-grpc: %v\n%s", err, out)
	}
	// A target the credential has no grant on: the example reports IAM's
	// refusal with the request ID.
	out, err = runExample(t, "caller", "IAM_SVC_CLIENT_ID="+fx.CallerSecret.ClientID, "IAM_SVC_CLIENT_SECRET="+fx.CallerSecret.ClientSecret,
		"ORDER_RESOURCE="+fx.NoGrantResource, "ORDER_API_URL=http://"+fiberAddr)
	if err == nil || !strings.Contains(out, "invalid_target") || !strings.Contains(out, "request id") {
		t.Fatalf("caller without a grant: %v\n%s", err, out)
	}
	if strings.Contains(out, fx.CallerSecret.ClientSecret) {
		t.Fatal("the example printed the client secret")
	}
}

// TestOfflineValidation is AC-10 against the real IAM.
//
// It is the last test of the file on purpose: it lets IAM activate a new
// signing key. A provider that was shown a token with an unknown kid shortly
// before does not download the keys again for 30 seconds (the rate limit of
// the specification), so tokens of a key activated within that window are
// refused by it for that long. The example providers of the tests above have
// just been shown such tokens.
func TestOfflineValidation(t *testing.T) {
	tr := &countingTransport{}
	v := newVerifier(t, tr)
	clock := time.Now()
	hooks.SetClock(v, func() time.Time { return clock })
	caller := secretCaller(t, nil)
	old := mustToken(t, caller, orderTarget(readScope))

	// 20+ validations, one download of the keys.
	for i := 0; i < 25; i++ {
		if _, err := v.Verify(ctx, old, readRule); err != nil {
			t.Fatalf("validation %d: %v", i, err)
		}
	}
	if n := tr.count("/jwks"); n != 1 {
		t.Fatalf("%d JWKS downloads for 25 validations, want 1", n)
	}
	// Tokens with a kid IAM does not publish do not cause a download each.
	header := jwtPart(t, old, 0)
	header["kid"] = "forged-kid"
	parts := strings.Split(old, ".")
	forged := b64(header) + "." + parts[1] + "." + parts[2]
	for i := 0; i < 30; i++ {
		if _, err := v.Verify(ctx, forged, readRule); !errors.Is(err, iam.ErrInvalidToken) {
			t.Fatalf("forged kid: %v", err)
		}
	}
	if n := tr.count("/jwks"); n != 2 {
		t.Fatalf("%d JWKS downloads after 30 tokens with an unknown kid, want 2", n)
	}

	// IAM activates a new signing key: a token signed with it verifies (the
	// unknown kid triggers one download), and the old token still does.
	if fx.ControlURL != "" {
		clock = clock.Add(31 * time.Second) // past the pause after the forged kid
		kid := rotateSigningKey(t)
		caller.Invalidate(orderTarget(readScope), "")
		fresh := mustToken(t, caller, orderTarget(readScope))
		if jwtPart(t, fresh, 0)["kid"] != kid {
			t.Fatalf("the new token is not signed with the new key %s", kid)
		}
		if _, err := v.Verify(ctx, fresh, readRule); err != nil {
			t.Fatalf("token signed with the new key: %v", err)
		}
		if _, err := v.Verify(ctx, old, readRule); err != nil {
			t.Fatalf("token signed with the previous key: %v", err)
		}
		if n := tr.count("/jwks"); n != 3 {
			t.Fatalf("%d JWKS downloads after the rotation, want 3", n)
		}
	}

	// The connection to IAM is cut: tokens that have not expired still
	// verify, also when the cached keys are due for a refresh.
	tr.cut.Store(true)
	for _, advance := range []time.Duration{0, 11 * time.Minute} {
		clock = clock.Add(advance)
		for i := 0; i < 3; i++ {
			if _, err := v.Verify(ctx, old, readRule); err != nil {
				t.Fatalf("validation while IAM is unreachable (+%s): %v", advance, err)
			}
		}
	}
}

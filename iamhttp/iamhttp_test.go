package iamhttp_test

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamhttp"
	"github.com/nixuw/iam-go-sdk/iamtest"
	"github.com/nixuw/iam-go-sdk/internal/adaptertest"
)

func serve(t *testing.T, ln net.Listener, h http.Handler) {
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func custom(onError func(error)) iamhttp.Option {
	return iamhttp.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
		onError(err)
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("custom"))
	})
}

func TestLogin(t *testing.T) {
	adaptertest.Login(t, func(t *testing.T, ln net.Listener, routes adaptertest.LoginRoutes) {
		var opts []iamhttp.Option
		if routes.Custom {
			opts = append(opts, custom(routes.OnError))
		}
		auth := iamhttp.Login(routes.Login, opts...)
		me := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(adaptertest.UserJSON(iamhttp.User(r)))
		})
		mux := http.NewServeMux()
		mux.HandleFunc("GET /login", auth.Start)
		mux.HandleFunc("GET /callback", auth.Callback)
		mux.HandleFunc("GET /logout", auth.Logout)
		mux.Handle("/profile", auth.Require()(me))
		mux.Handle("/api/me", auth.Require()(me))
		mux.HandleFunc("GET /bye", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("bye")) })
		serve(t, ln, mux)
	})
}

func TestGuard(t *testing.T) {
	adaptertest.Guard(t, func(t *testing.T, ln net.Listener, routes adaptertest.GuardRoutes) {
		var opts []iamhttp.Option
		if routes.Custom {
			opts = append(opts, custom(routes.OnError))
		}
		guard := iamhttp.Guard(routes.Verifier, opts...)
		who := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(adaptertest.CallerJSON(iamhttp.Caller(r)))
		})
		mux := http.NewServeMux()
		mux.Handle("GET /orders", guard.Require(adaptertest.ReadRule)(who))
		mux.Handle("POST /orders", guard.Require(adaptertest.WriteRule)(who))
		mux.Handle("GET /closed", guard.Require(iam.Rule{})(who))
		mux.HandleFunc("GET /public", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("public")) })
		serve(t, ln, mux)
	})
}

// LOGIN-05: with an https site, the cookies of the local session are
// HttpOnly, Secure and SameSite=Lax.
func TestSessionCookieIsSecure(t *testing.T) {
	const site = "https://portal.example.test"
	iss := iamtest.NewIssuer(t)
	iss.AddLoginClient(iamtest.LoginClient{ID: "app_example_portal", Secret: "ssk_portal_secret", RedirectURIs: []string{site + "/callback"}})
	iss.SignIn(iamtest.User{Subject: "user-1", Name: "Alice Example"})
	login, err := iam.NewLogin(context.Background(), iam.LoginConfig{
		Issuer: iss.URL(), ClientID: "app_example_portal", Credential: iam.ClientSecret("ssk_portal_secret"), HTTPClient: iss.HTTPClient(),
		RedirectURL: site + "/callback", SessionKey: bytes.Repeat([]byte("k"), 32), SessionCookieName: "portal_session",
	})
	if err != nil {
		t.Fatal(err)
	}
	auth := iamhttp.Login(login)

	start := httptest.NewRecorder()
	auth.Start(start, httptest.NewRequest("GET", site+"/login", nil))
	// The browser goes to IAM and comes back with the code.
	client := *iss.HTTPClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Get(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	back, _ := url.Parse(res.Header.Get("Location"))
	callback := httptest.NewRequest("GET", site+"/callback?"+back.RawQuery, nil)
	for _, c := range start.Result().Cookies() {
		callback.AddCookie(c)
	}
	done := httptest.NewRecorder()
	auth.Callback(done, callback)
	if done.Code != http.StatusFound {
		t.Fatalf("callback: HTTP %d %s", done.Code, done.Body.String())
	}
	cookies := append(start.Result().Cookies(), done.Result().Cookies()...)
	if len(cookies) != 2 || cookies[1].Name != "portal_session" {
		t.Fatalf("cookies: %v", cookies)
	}
	for _, c := range cookies {
		if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
			t.Fatalf("cookie %s must be HttpOnly, Secure, SameSite=Lax: %+v", c.Name, c)
		}
		if strings.Count(c.Value, ".") != 1 || len(c.Value) > 200 {
			t.Fatalf("cookie %s must only hold a signed identifier, not session data", c.Name)
		}
	}
	// The session works for a request that carries the cookie.
	var seen *iam.User
	protected := auth.Require()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = iamhttp.User(r) }))
	req := httptest.NewRequest("GET", site+"/profile", nil)
	req.AddCookie(cookies[1])
	protected.ServeHTTP(httptest.NewRecorder(), req)
	if seen == nil || seen.Subject != "user-1" || iam.UserFromContext(req.Context()) != nil {
		t.Fatalf("user of the session: %+v", seen)
	}
}

// Without a session key the handlers refuse to work instead of running
// without protection.
func TestLoginWithoutSessionKey(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	login, err := iam.NewLogin(context.Background(), iam.LoginConfig{
		Issuer: iss.URL(), ClientID: "app_example_portal", Credential: iam.ClientSecret("s"), HTTPClient: iss.HTTPClient(),
		RedirectURL: "https://portal.example.test/callback",
	})
	if err != nil {
		t.Fatalf("protocol-only use needs no session key: %v", err)
	}
	rec := httptest.NewRecorder()
	iamhttp.Login(login).Start(rec, httptest.NewRequest("GET", "/login", nil))
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("Location") != "" {
		t.Fatalf("Start without a session key: HTTP %d", rec.Code)
	}
}

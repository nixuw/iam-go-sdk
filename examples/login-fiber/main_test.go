package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamtest"
)

// The example signs a user in, serves the protected page and signs out,
// against the local fake issuer.
func TestExample(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	iss := iamtest.NewIssuer(t)
	iss.AddLoginClient(iamtest.LoginClient{ID: "app_example_portal", Secret: "ssk_portal_secret", RedirectURIs: []string{base + "/callback"}, PostLogoutRedirectURIs: []string{base + "/"}})
	iss.SignIn(iamtest.User{Subject: "user-1", Name: "Alice Example", Email: "alice@example.test"})

	t.Setenv("IAM_ISSUER", iss.URL())
	t.Setenv("IAM_CLIENT_ID", "app_example_portal")
	t.Setenv("IAM_CLIENT_SECRET", "ssk_portal_secret")
	t.Setenv("APP_BASE_URL", base)
	t.Setenv("APP_SESSION_KEY", strings.Repeat("k", 32))
	t.Setenv("IAM_ALLOW_INSECURE", "true") // the test site speaks plain http on loopback
	cfg := loadConfig()
	cfg.HTTPClient = iss.HTTPClient() // trust the fake issuer's certificate
	app, err := newApp(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Listener(ln) }()
	// A bounded shutdown: connections the test's HTTP client opened but never
	// used would otherwise keep a graceful shutdown waiting.
	t.Cleanup(func() { _ = app.ShutdownWithTimeout(time.Second) })

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Transport: iss.HTTPClient().Transport}
	get := func(path string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		req.Header.Set("Accept", "text/html")
		res, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res, string(body)
	}
	// Opening the protected page leads through IAM and back.
	res, body := get("/profile")
	var user map[string]string
	if res.StatusCode != 200 || res.Request.URL.Path != "/profile" || json.Unmarshal([]byte(body), &user) != nil ||
		user["sub"] != "user-1" || user["iss"] != iss.URL() || user["name"] != "Alice Example" {
		t.Fatalf("after sign-in: HTTP %d at %s: %s", res.StatusCode, res.Request.URL, body)
	}
	// Signing out ends the local session and returns from IAM to the site.
	if res, _ := get("/logout"); res.StatusCode != 200 || res.Request.URL.Path != "/" || res.Request.URL.Query().Get("state") == "" {
		t.Fatalf("after logout: HTTP %d at %s", res.StatusCode, res.Request.URL)
	}
	iss.SignOut()
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if res, _ := get("/profile"); res.StatusCode != http.StatusFound || !strings.HasPrefix(res.Header.Get("Location"), "/login") {
		t.Fatalf("protected page after logout: HTTP %d", res.StatusCode)
	}
	// A missing value is reported by name.
	cfg.ClientID = ""
	var ce *iam.ConfigError
	if _, err := newApp(context.Background(), cfg); !errors.As(err, &ce) || ce.Field != "ClientID" {
		t.Fatalf("missing client ID: %v", err)
	}
}

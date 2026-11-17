// Package adaptertest holds the scenarios that every HTTP adapter must pass.
// Each adapter's tests mount the same routes with their framework and run
// these scenarios against them, so that Fiber and net/http applications are
// held to identical behaviour on top of the one core.
package adaptertest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamtest"
	"github.com/nixuw/iam-go-sdk/internal/hooks"
)

// LoginRoutes is what an adapter test mounts for the sign-in scenarios:
//
//	GET /login, /callback, /logout   the three sign-in handlers
//	GET /profile, /api/me            behind Require; answer UserJSON
//	GET /bye                         public; answers "bye"
//
// With Custom set, the handlers are built with an error handler that calls
// OnError and answers HTTP 418 with the body "custom".
type LoginRoutes struct {
	Login   *iam.Login
	Custom  bool
	OnError func(err error)
}

// ServeLogin serves the routes on the listener with the adapter under test
// until the test ends.
type ServeLogin func(t *testing.T, ln net.Listener, routes LoginRoutes)

// UserJSON is the body the protected routes answer with.
func UserJSON(u *iam.User) []byte {
	raw, _ := json.Marshal(map[string]string{"sub": u.Subject, "name": u.Name, "email": u.Email, "iss": u.Issuer})
	return raw
}

const (
	clientID     = "app_example_portal"
	clientSecret = "ssk_portal_secret"
)

var alice = iamtest.User{Subject: "0b7c7a3e-user-alice", Name: "Alice Example", Username: "alice", Email: "alice@example.test", EmailVerified: true}

// site is one application under test together with its fake issuer.
type site struct {
	t      *testing.T
	iss    *iamtest.Issuer
	login  *iam.Login
	url    string
	clock  *clock
	errors []error
	mu     sync.Mutex
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newSite(t *testing.T, serve ServeLogin, custom bool) *site {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &site{t: t, iss: iamtest.NewIssuer(t), url: "http://" + ln.Addr().String(), clock: &clock{t: time.Now()}}
	s.iss.AddLoginClient(iamtest.LoginClient{
		ID: clientID, Secret: clientSecret, RedirectURIs: []string{s.url + "/callback"},
		PostLogoutRedirectURIs: []string{s.url + "/bye"}, RefreshTokens: true,
	})
	s.iss.SignIn(alice)
	s.iss.SetClock(s.clock.Now)
	s.login, err = iam.NewLogin(context.Background(), iam.LoginConfig{
		Issuer: s.iss.URL(), ClientID: clientID, Credential: iam.ClientSecret(clientSecret), HTTPClient: s.iss.HTTPClient(),
		RedirectURL: s.url + "/callback", PostLogoutRedirectURL: s.url + "/bye", Scopes: []string{"openid", "profile", "email"},
		SessionKey: bytes.Repeat([]byte("k"), 32), AllowInsecureCookie: true, // the test site speaks plain http on loopback
	})
	if err != nil {
		t.Fatalf("NewLogin: %v", err)
	}
	hooks.SetClock(s.login, s.clock.Now)
	serve(t, ln, LoginRoutes{Login: s.login, Custom: custom, OnError: func(err error) {
		s.mu.Lock()
		s.errors = append(s.errors, err)
		s.mu.Unlock()
	}})
	return s
}

// browser is an HTTP client with a cookie jar that follows redirects one at
// a time, so that a test can look at every hop. It trusts the fake issuer.
type browser struct {
	t      *testing.T
	client *http.Client
}

func (s *site) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: s.t, client: &http.Client{
		Jar: jar, Transport: s.iss.HTTPClient().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// hop is one response in a chain of redirects.
type hop struct {
	URL      string
	Status   int
	Header   http.Header
	Body     string
	Location string
}

func (b *browser) get(rawURL, accept string) hop {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		b.t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	res, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	h := hop{URL: rawURL, Status: res.StatusCode, Header: res.Header, Body: string(body)}
	if loc := res.Header.Get("Location"); loc != "" {
		next, err := res.Request.URL.Parse(loc)
		if err != nil {
			b.t.Fatalf("bad Location %q", loc)
		}
		h.Location = next.String()
	}
	return h
}

const (
	page = "text/html,application/xhtml+xml"
	api  = "application/json"
)

// navigate opens a page like a browser does and follows the redirects. It
// stops before a hop for which stop returns true.
func (b *browser) navigate(rawURL string, stop func(next string) bool) []hop {
	b.t.Helper()
	var hops []hop
	for i := 0; i < 12; i++ {
		h := b.get(rawURL, page)
		hops = append(hops, h)
		if h.Status < 300 || h.Status > 399 || h.Location == "" || (stop != nil && stop(h.Location)) {
			return hops
		}
		rawURL = h.Location
	}
	b.t.Fatalf("too many redirects from %s", rawURL)
	return nil
}

func last(hops []hop) hop { return hops[len(hops)-1] }

func (s *site) refreshRequests() int {
	n := 0
	for _, form := range s.iss.TokenRequests() {
		if form.Get("grant_type") == "refresh_token" {
			n++
		}
	}
	return n
}

// Login runs the sign-in scenarios (LOGIN-01 … LOGIN-08, AC-03 … AC-05)
// against an adapter.
func Login(t *testing.T, serve ServeLogin) {
	t.Run("sign-in, protected page, logout", func(t *testing.T) {
		s := newSite(t, serve, false)
		b := s.browser()
		hops := b.navigate(s.url+"/profile?tab=security", nil)
		// protected page → /login → IAM → /callback → back to the page
		if len(hops) != 5 || hops[0].Status != 302 || !strings.HasPrefix(hops[0].Location, s.url+"/login?return_to=") ||
			!strings.HasPrefix(hops[1].Location, s.iss.URL()+iamtest.PathAuthorize) || !strings.HasPrefix(hops[2].Location, s.url+"/callback?") ||
			hops[3].Location != s.url+"/profile?tab=security" || hops[4].Status != 200 {
			t.Fatalf("sign-in redirect chain: %+v", locations(hops))
		}
		var user map[string]string
		if json.Unmarshal([]byte(hops[4].Body), &user) != nil || user["sub"] != alice.Subject || user["name"] != alice.Name || user["email"] != alice.Email || user["iss"] != s.iss.URL() {
			t.Fatalf("user handed to the application: %s", hops[4].Body)
		}
		// The cookies: HttpOnly, SameSite=Lax; no token ever reaches the
		// browser (cookies, bodies, addresses).
		for _, h := range hops {
			for _, c := range h.Header.Values("Set-Cookie") {
				if strings.HasPrefix(h.URL, s.url) && (!strings.Contains(c, "HttpOnly") || !strings.Contains(c, "SameSite=Lax") || !strings.Contains(c, "Path=/")) {
					t.Fatalf("cookie attributes: %q", c)
				}
			}
			if strings.HasPrefix(h.URL, s.url) && h.Header.Get("Cache-Control") != "no-store" && h.Status != 200 {
				t.Fatalf("sign-in responses must not be cached: %s", h.URL)
			}
		}
		for _, secret := range s.iss.Sensitive() {
			if secret == "" || strings.HasPrefix(secret, "code-") {
				continue // the authorization code travels through the browser by design
			}
			for _, h := range hops {
				if strings.HasPrefix(h.URL, s.url) && (strings.Contains(h.Body, secret) || strings.Contains(strings.Join(h.Header.Values("Set-Cookie"), "\n"), secret) || strings.Contains(h.Location, secret)) {
					t.Fatalf("a token or secret reached the browser at %s", h.URL)
				}
			}
		}
		// Signed in: no further trip to IAM.
		before := s.iss.Requests(iamtest.PathAuthorize)
		if h := b.get(s.url+"/profile", page); h.Status != 200 || s.iss.Requests(iamtest.PathAuthorize) != before {
			t.Fatalf("second visit: HTTP %d", h.Status)
		}
		if h := b.get(s.url+"/api/me", api); h.Status != 200 {
			t.Fatalf("API call with a session: HTTP %d", h.Status)
		}

		// Logout: local session first, refresh token revoked, then IAM's
		// logout endpoint, which returns to the registered address.
		hops = b.navigate(s.url+"/logout", nil)
		if len(hops) != 3 || !strings.HasPrefix(hops[0].Location, s.iss.URL()+iamtest.PathLogout) || !strings.HasPrefix(hops[1].Location, s.url+"/bye?state=") || hops[2].Body != "bye" {
			t.Fatalf("logout redirect chain: %+v", locations(hops))
		}
		logout, _ := url.Parse(hops[0].Location)
		if logout.Query().Get("id_token_hint") == "" || logout.Query().Get("post_logout_redirect_uri") != s.url+"/bye" || logout.Query().Get("state") == "" {
			t.Fatalf("logout request: %v", logout.Query())
		}
		if s.iss.Requests(iamtest.PathRevoke) != 1 {
			t.Fatalf("the refresh token must be revoked at logout: %d revocations", s.iss.Requests(iamtest.PathRevoke))
		}
		if h := b.get(s.url+"/api/me", api); h.Status != 401 {
			t.Fatalf("after logout: HTTP %d", h.Status)
		}
	})

	t.Run("pages are redirected, API requests get 401", func(t *testing.T) {
		s := newSite(t, serve, false)
		b := s.browser()
		h := b.get(s.url+"/api/me", api)
		var body map[string]string
		if h.Status != 401 || h.Location != "" || json.Unmarshal([]byte(h.Body), &body) != nil || body["error"] != "login_required" {
			t.Fatalf("API request without a session: HTTP %d %s", h.Status, h.Body)
		}
		req, _ := http.NewRequest(http.MethodPost, s.url+"/api/me", nil)
		req.Header.Set("Accept", page)
		res, err := b.client.Do(req)
		if err != nil || res.StatusCode == 302 {
			t.Fatalf("a POST is never redirected to the login page: %v", err)
		}
		res.Body.Close()
		if h := b.get(s.url+"/profile", page); h.Status != 302 || h.Location != s.url+"/login?return_to=%2Fprofile" {
			t.Fatalf("page request without a session: HTTP %d → %s", h.Status, h.Location)
		}
		// Only this site is ever returned to.
		for _, target := range []string{"https://evil.example.test/", "//evil.example.test", "/\\evil.example.test"} {
			hops := s.browser().navigate(s.url+"/login?return_to="+url.QueryEscape(target), nil)
			if got := hops[len(hops)-2].Location; got != s.url+"/" {
				t.Fatalf("return_to=%q led to %s", target, got)
			}
		}
	})

	t.Run("the callback is one-time and bound to the browser", func(t *testing.T) {
		s := newSite(t, serve, false)
		atCallback := func(next string) bool { return strings.HasPrefix(next, s.url+"/callback") }
		refused := func(what string, h hop) {
			t.Helper()
			if h.Status != 400 || !strings.Contains(h.Body, "invalid_request") || len(h.Header.Values("Set-Cookie")) != 0 {
				t.Fatalf("%s: HTTP %d %s", what, h.Status, h.Body)
			}
		}
		// Unknown state.
		refused("unknown state", s.browser().get(s.url+"/callback?code=x&state=unknown&iss="+url.QueryEscape(s.iss.URL()), page))
		// A callback delivered to another browser (login CSRF / fixation).
		victim, attacker := s.browser(), s.browser()
		callback := last(attacker.navigate(s.url+"/login", atCallback)).Location
		refused("callback in a browser that did not start the sign-in", victim.get(callback, page))
		// ... and the attempt consumed the pending sign-in.
		refused("pending sign-in used twice", attacker.get(callback, page))
		// A regular callback cannot be replayed either.
		b := s.browser()
		callback = last(b.navigate(s.url+"/login", atCallback)).Location
		if h := b.get(callback, page); h.Status != 302 || h.Location != s.url+"/" {
			t.Fatalf("regular callback: HTTP %d", h.Status)
		}
		refused("replayed callback", b.get(callback, page))
		// A callback whose iss is not the configured issuer.
		b = s.browser()
		callback = last(b.navigate(s.url+"/login", atCallback)).Location
		refused("foreign iss", b.get(strings.Replace(callback, "iss=", "iss=https%3A%2F%2Fattacker.example.test&x=", 1), page))
		// A forged or damaged session cookie is no session.
		b = s.browser()
		site, _ := url.Parse(s.url)
		b.client.Jar.SetCookies(site, []*http.Cookie{{Name: "iam_session", Value: "forged.c2lnbmF0dXJl", Path: "/"}})
		if h := b.get(s.url+"/api/me", api); h.Status != 401 {
			t.Fatalf("forged session cookie: HTTP %d", h.Status)
		}
	})

	t.Run("error responses of IAM", func(t *testing.T) {
		s := newSite(t, serve, false)
		s.iss.FailAuthorize("access_denied")
		h := last(s.browser().navigate(s.url+"/login", nil))
		var body map[string]string
		if h.Status != 403 || json.Unmarshal([]byte(h.Body), &body) != nil || body["error"] != "access_denied" {
			t.Fatalf("access_denied: HTTP %d %s", h.Status, h.Body)
		}
		s.iss.SignOut()
		if h := last(s.browser().navigate(s.url+"/login?prompt=none", nil)); h.Status != 401 || !strings.Contains(h.Body, "login_required") {
			t.Fatalf("prompt=none without an IAM session: HTTP %d %s", h.Status, h.Body)
		}
		if h := s.browser().get(s.url+"/login?prompt=whatever", page); h.Status != 400 {
			t.Fatalf("unsupported prompt: HTTP %d", h.Status)
		}
		// With an error handler the application decides what to show.
		custom := newSite(t, serve, true)
		custom.iss.FailAuthorize("consent_required")
		h = last(custom.browser().navigate(custom.url+"/login?prompt=none", nil))
		var oe *iam.OAuthError
		if h.Status != 418 || h.Body != "custom" || len(custom.errors) != 1 || !errors.As(custom.errors[0], &oe) || oe.Code != "consent_required" {
			t.Fatalf("custom error handler: HTTP %d %q %v", h.Status, h.Body, custom.errors)
		}
	})

	t.Run("refresh keeps the session, IAM ends it", func(t *testing.T) {
		s := newSite(t, serve, false)
		b := s.browser()
		if h := last(b.navigate(s.url+"/profile", nil)); h.Status != 200 {
			t.Fatalf("sign-in: HTTP %d", h.Status)
		}
		// The access token expires: concurrent requests of the session
		// lead to exactly one refresh, and all of them succeed.
		s.clock.Advance(16 * time.Minute)
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if h := b.get(s.url+"/api/me", api); h.Status != 200 {
					t.Errorf("request during refresh: HTTP %d %s", h.Status, h.Body)
				}
			}()
		}
		wg.Wait()
		if n := s.refreshRequests(); n != 1 {
			t.Fatalf("%d refresh requests for 20 concurrent requests of one session, want 1", n)
		}
		// The rotated refresh token was stored: the next refresh works.
		s.clock.Advance(16 * time.Minute)
		if h := b.get(s.url+"/api/me", api); h.Status != 200 || s.refreshRequests() != 2 {
			t.Fatalf("second refresh: HTTP %d, %d refreshes", h.Status, s.refreshRequests())
		}
		// IAM is unreachable when the next refresh is due: the session stays.
		s.clock.Advance(16 * time.Minute)
		s.iss.SetDown(true)
		if h := b.get(s.url+"/api/me", api); h.Status != 200 {
			t.Fatalf("session while IAM is down: HTTP %d", h.Status)
		}
		s.iss.SetDown(false)
		// The user signs out at IAM (or is disabled): the refresh is
		// refused with invalid_grant and the local session ends.
		s.iss.SignOut()
		s.clock.Advance(time.Minute)
		h := b.get(s.url+"/api/me", api)
		if h.Status != 401 || !strings.Contains(strings.Join(h.Header.Values("Set-Cookie"), ";"), "Max-Age=0") {
			t.Fatalf("after IAM refused the refresh: HTTP %d %v", h.Status, h.Header.Values("Set-Cookie"))
		}
		if h := b.get(s.url+"/profile", page); h.Status != 302 {
			t.Fatalf("page after the session ended: HTTP %d", h.Status)
		}
	})

	t.Run("the local session has an upper limit", func(t *testing.T) {
		s := newSite(t, serve, false)
		b := s.browser()
		b.navigate(s.url+"/profile", nil)
		s.clock.Advance(7 * time.Hour)
		if h := b.get(s.url+"/api/me", api); h.Status != 200 {
			t.Fatalf("within the session lifetime: HTTP %d", h.Status)
		}
		s.clock.Advance(2 * time.Hour)
		if h := b.get(s.url+"/api/me", api); h.Status != 401 {
			t.Fatalf("past the session lifetime: HTTP %d", h.Status)
		}
	})
}

func locations(hops []hop) []string {
	var out []string
	for _, h := range hops {
		out = append(out, h.URL+" → "+http.StatusText(h.Status)+" "+h.Location)
	}
	return out
}

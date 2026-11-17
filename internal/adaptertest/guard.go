package adaptertest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamtest"
	"github.com/nixuw/iam-go-sdk/internal/hooks"
)

// Resource is the resource identifier of the provider application the guard
// scenarios run against.
const Resource = "urn:example:app:orders"

// Access rules of the provider routes.
var (
	ReadRule  = iam.Rule{Scopes: []string{"order.read"}, Principals: []string{iam.PrincipalService, iam.PrincipalUser}}
	WriteRule = iam.Rule{Scopes: []string{"order.write"}, Principals: []string{iam.PrincipalService}}
)

// GuardRoutes is what an adapter test mounts for the provider scenarios:
//
//	GET  /orders   behind Require(ReadRule); answers CallerJSON
//	POST /orders   behind Require(WriteRule); answers CallerJSON
//	GET  /closed   behind Require(iam.Rule{}): no rule declared
//	GET  /public   no middleware; answers "public"
//
// With Custom set, the guard is built with an error handler that calls
// OnError and writes HTTP 418 with the body "custom" — the SDK must keep
// the status and the challenge of a bearer error all the same.
type GuardRoutes struct {
	Verifier *iam.Verifier
	Custom   bool
	OnError  func(err error)
}

// ServeGuard serves the routes on the listener with the adapter under test
// until the test ends.
type ServeGuard func(t *testing.T, ln net.Listener, routes GuardRoutes)

// CallerJSON is the body the protected routes answer with.
func CallerJSON(id *iam.Identity) []byte {
	raw, _ := json.Marshal(map[string]string{"client_id": id.ClientID, "sub": id.Subject, "principal_type": id.PrincipalType, "scope": strings.Join(id.Scopes, " ")})
	return raw
}

type answer struct {
	status    int
	challenge string
	header    http.Header
	body      string
}

func call(t *testing.T, method, rawURL, authorization string) answer {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return answer{status: res.StatusCode, challenge: res.Header.Get("WWW-Authenticate"), header: res.Header, body: string(body)}
}

// Guard runs the provider scenarios (VERIFY-01 … VERIFY-07, AC-09, AC-11)
// against an adapter.
func Guard(t *testing.T, serve ServeGuard) {
	iss := iamtest.NewIssuer(t)
	errSuspended := errors.New("client is suspended")
	start := func(custom bool, tolerate bool) (string, *iam.Verifier, *[]error) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		v, err := iam.NewVerifier(context.Background(), iam.VerifierConfig{
			Issuer: iss.URL(), Audience: Resource, HTTPClient: iss.HTTPClient(), TolerateStartupFailure: tolerate,
			Authorize: func(_ context.Context, id *iam.Identity) error {
				if id.ClientID == "svc_suspended" {
					return errSuspended
				}
				return nil
			},
		})
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		var seen []error
		serve(t, ln, GuardRoutes{Verifier: v, Custom: custom, OnError: func(err error) { seen = append(seen, err) }})
		return "http://" + ln.Addr().String(), v, &seen
	}
	base, _, _ := start(false, false)
	read := iss.ServiceToken(Resource, "svc_example_caller", "order.read")
	user := iss.UserToken(Resource, "app_example_portal", "user-1", "order.read", "order.write")
	realm := `Bearer realm="` + Resource + `"`

	t.Run("RFC 6750 responses", func(t *testing.T) {
		// No token: 401, the challenge carries the realm only, no body.
		a := call(t, "GET", base+"/orders", "")
		if a.status != 401 || a.challenge != realm || a.body != "" || a.header.Get("Cache-Control") != "no-store" {
			t.Fatalf("no token: %d %q %q", a.status, a.challenge, a.body)
		}
		// A token in the URL is not a token.
		if a := call(t, "GET", base+"/orders?access_token="+read, ""); a.status != 401 || a.challenge != realm {
			t.Fatalf("token in the query string: %d %q", a.status, a.challenge)
		}
		// Invalid token: 401 invalid_token, JSON body, nothing echoed.
		expired := iss.AccessToken(iamtest.Token{Subject: "svc_example_caller", ClientID: "svc_example_caller", Audience: Resource, Principal: "service", Scopes: []string{"order.read"}, IssuedAt: time.Now().Add(-time.Hour)})
		a = call(t, "GET", base+"/orders", "Bearer "+expired)
		if a.status != 401 || a.challenge != realm+`, error="invalid_token", error_description="token expired"` ||
			a.body != `{"error":"invalid_token","error_description":"token expired"}`+"\n" && a.body != `{"error":"invalid_token","error_description":"token expired"}` ||
			!strings.HasPrefix(a.header.Get("Content-Type"), "application/json") {
			t.Fatalf("expired token: %d %q %q", a.status, a.challenge, a.body)
		}
		for name, token := range map[string]string{
			"another audience": iss.ServiceToken("urn:example:app:billing", "svc_example_caller", "order.read"),
			"an ID token":      iss.AccessToken(iamtest.Token{Audience: Resource, Header: map[string]any{"typ": "JWT"}}),
			"garbage":          "garbage",
		} {
			if a := call(t, "GET", base+"/orders", "Bearer "+token); a.status != 401 || !strings.Contains(a.challenge, `error="invalid_token"`) || strings.Contains(a.body+a.challenge, token) {
				t.Fatalf("%s: %d %q", name, a.status, a.challenge)
			}
		}
		// Valid token without the permission: 403 insufficient_scope with
		// the scope the endpoint requires.
		a = call(t, "POST", base+"/orders", "Bearer "+read)
		if a.status != 403 || a.challenge != realm+`, error="insufficient_scope", error_description="the token lacks order.write", scope="order.write"` || !strings.Contains(a.body, `"insufficient_scope"`) {
			t.Fatalf("missing permission: %d %q %q", a.status, a.challenge, a.body)
		}
		// Valid token of a principal type the endpoint does not accept.
		if a := call(t, "POST", base+"/orders", "Bearer "+user); a.status != 403 || !strings.Contains(a.challenge, `error="insufficient_scope"`) || !strings.Contains(a.challenge, `scope="order.write"`) {
			t.Fatalf("principal type: %d %q", a.status, a.challenge)
		}
	})

	t.Run("the handler gets the caller", func(t *testing.T) {
		var who map[string]string
		a := call(t, "GET", base+"/orders", "Bearer "+read)
		if a.status != 200 || json.Unmarshal([]byte(a.body), &who) != nil || who["client_id"] != "svc_example_caller" || who["principal_type"] != "service" || who["scope"] != "order.read" {
			t.Fatalf("system token: %d %s", a.status, a.body)
		}
		a = call(t, "GET", base+"/orders", "Bearer "+user)
		if a.status != 200 || json.Unmarshal([]byte(a.body), &who) != nil || who["sub"] != "user-1" || who["client_id"] != "app_example_portal" || who["principal_type"] != "user" {
			t.Fatalf("user-delegated token: %d %s", a.status, a.body)
		}
		if a := call(t, "GET", base+"/public", ""); a.status != 200 || a.body != "public" {
			t.Fatalf("unprotected route: %d", a.status)
		}
	})

	t.Run("an endpoint without a rule is closed", func(t *testing.T) {
		if a := call(t, "GET", base+"/closed", "Bearer "+read); a.status != 403 || !strings.Contains(a.challenge, `error="insufficient_scope"`) {
			t.Fatalf("valid token on an endpoint without a rule: %d %q", a.status, a.challenge)
		}
		if a := call(t, "GET", base+"/closed", ""); a.status != 401 {
			t.Fatalf("no token on an endpoint without a rule: %d", a.status)
		}
	})

	t.Run("the application's own refusal", func(t *testing.T) {
		suspended := iss.ServiceToken(Resource, "svc_suspended", "order.read")
		a := call(t, "GET", base+"/orders", "Bearer "+suspended)
		if a.status != 403 || a.challenge != "" || strings.Contains(a.body, "invalid_token") || strings.Contains(a.body, "insufficient_scope") {
			t.Fatalf("business refusal must not use the token error codes: %d %q %q", a.status, a.challenge, a.body)
		}
		customBase, _, seen := start(true, false)
		a = call(t, "GET", customBase+"/orders", "Bearer "+suspended)
		if a.status != 418 || a.body != "custom" || len(*seen) != 1 || !errors.Is((*seen)[0], iam.ErrDenied) || !errors.Is((*seen)[0], errSuspended) {
			t.Fatalf("business refusal with an error handler: %d %q %v", a.status, a.body, *seen)
		}
	})

	t.Run("a custom body keeps status and challenge", func(t *testing.T) {
		customBase, _, seen := start(true, false)
		a := call(t, "POST", customBase+"/orders", "Bearer "+read)
		var be *iam.BearerError
		if a.status != 403 || a.body != "custom" || !strings.Contains(a.challenge, `error="insufficient_scope"`) || !strings.Contains(a.challenge, `scope="order.write"`) ||
			len(*seen) != 1 || !errors.As((*seen)[0], &be) {
			t.Fatalf("custom error body: %d %q %q", a.status, a.challenge, a.body)
		}
		if a := call(t, "GET", customBase+"/orders", ""); a.status != 401 || a.challenge != realm || a.body != "custom" {
			t.Fatalf("custom error body without a token: %d %q %q", a.status, a.challenge, a.body)
		}
	})

	t.Run("no signing key: 503, not 401", func(t *testing.T) {
		iss.SetDown(true)
		downBase, v, _ := start(false, true)
		clock := &clock{t: time.Now()}
		hooks.SetClock(v, clock.Now)
		a := call(t, "GET", downBase+"/orders", "Bearer "+read)
		if a.status != 503 || a.challenge != "" || a.header.Get("Retry-After") == "" || !strings.Contains(a.body, "temporarily_unavailable") {
			t.Fatalf("no keys: %d %q %q", a.status, a.challenge, a.body)
		}
		// A request without a token is still simply unauthenticated.
		if a := call(t, "GET", downBase+"/orders", ""); a.status != 401 {
			t.Fatalf("no token while IAM is down: %d", a.status)
		}
		iss.SetDown(false)
		clock.Advance(31 * time.Second)
		if a := call(t, "GET", downBase+"/orders", "Bearer "+read); a.status != 200 {
			t.Fatalf("after IAM came back: %d %s", a.status, a.body)
		}
	})
}

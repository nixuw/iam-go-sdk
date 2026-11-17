package iam_test

import (
	"context"
	"crypto"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamtest"
	"github.com/nixuw/iam-go-sdk/internal/hooks"
)

var ordersRead = iam.Target{Resource: orders, Scopes: []string{"order.read"}}

// TestSystemTokenWithBothCredentials is AC-06.
func TestSystemTokenWithBothCredentials(t *testing.T) {
	iss := serviceIssuer(t)
	key := newRSAKey(t)
	iss.AddServiceClient(iamtest.ServiceClient{ID: "svc_example_key", PublicKeys: map[string]crypto.PublicKey{"caller-2026-11": &key.PublicKey}})
	iss.Grant("svc_example_key", orders, "order.read")

	bySecret := newCaller(t, iss)
	byKey := newCaller(t, iss, func(c *iam.CallerConfig) {
		c.ClientID, c.Credential = "svc_example_key", iam.PrivateKeyJWT("caller-2026-11", key)
	})
	for name, caller := range map[string]*iam.Caller{"client_secret_basic": bySecret, "private_key_jwt": byKey} {
		token, err := caller.Token(ctx, ordersRead)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		claims := claimsOf(t, token)
		if claims["aud"] != orders || claims["principal_type"] != "service" || claims["scope"] != "order.read" {
			t.Fatalf("%s: claims %v", name, claims)
		}
	}
	// Every request carries exactly one resource and the requested scope;
	// a private_key_jwt request sends no Basic header and a fresh assertion.
	for _, form := range iss.TokenRequests() {
		if form.Get("grant_type") != "client_credentials" || form.Get("resource") != orders || form.Get("scope") != "order.read" || form.Has("client_secret") {
			t.Fatalf("token request: %v", form)
		}
	}
	// No scope: IAM issues every permission of the grant.
	token, err := bySecret.Token(ctx, iam.Target{Resource: orders})
	if err != nil || claimsOf(t, token)["scope"] != "order.read order.write" {
		t.Fatalf("token without scope: %v %v", err, token != "")
	}
	// CALL-01: an empty resource is refused before anything is sent.
	before := iss.Requests(iamtest.PathToken)
	var ce *iam.ConfigError
	if _, err := bySecret.Token(ctx, iam.Target{}); !errors.As(err, &ce) || ce.Field != "Target.Resource" || iss.Requests(iamtest.PathToken) != before {
		t.Fatalf("empty resource: %v", err)
	}
	// A PEM key works the same way.
	if _, err := iam.ParsePrivateKeyPEM([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")); err == nil {
		t.Fatal("a broken PEM key must be refused")
	}
}

// TestTokenCacheAndRenewal is AC-07.
func TestTokenCacheAndRenewal(t *testing.T) {
	iss := serviceIssuer(t)
	iss.SetTokenLifetime(10 * time.Minute)
	clock := newClock()
	caller := newCaller(t, iss)
	hooks.SetClock(caller, clock.Now)

	// 100 calls within the lifetime: one request.
	first, err := caller.Token(ctx, ordersRead)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if tok, err := caller.Token(ctx, ordersRead); err != nil || tok != first {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if n := iss.Requests(iamtest.PathToken); n != 1 {
		t.Fatalf("%d token requests for 101 calls, want 1", n)
	}
	// The cache key is (target, permission set): the order of the scopes
	// does not matter, another set is another token.
	both := iam.Target{Resource: orders, Scopes: []string{"order.write", "order.read"}}
	swapped := iam.Target{Resource: orders, Scopes: []string{"order.read", "order.write", "order.read"}}
	a, _ := caller.Token(ctx, both)
	b, _ := caller.Token(ctx, swapped)
	if a == "" || a != b || a == first || iss.Requests(iamtest.PathToken) != 2 {
		t.Fatalf("cache key: %d requests", iss.Requests(iamtest.PathToken))
	}

	// Concurrent calls on a cold cache are merged into one request.
	cold := newCaller(t, iss)
	before := iss.Requests(iamtest.PathToken)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cold.Token(ctx, ordersRead); err != nil {
				t.Errorf("concurrent call: %v", err)
			}
		}()
	}
	wg.Wait()
	if n := iss.Requests(iamtest.PathToken) - before; n != 1 {
		t.Fatalf("%d token requests for 50 concurrent calls, want 1", n)
	}

	// Renewal before expiry: no call fails or waits for it.
	clock.Advance(8*time.Minute + time.Second) // inside the renewal window of a 10 minute token
	if tok, err := caller.Token(ctx, ordersRead); err != nil || tok != first {
		t.Fatalf("a call during renewal must be served from the cache: %v", err)
	}
	eventually(t, "the renewed token", func() bool {
		tok, err := caller.Token(ctx, ordersRead)
		if err != nil {
			t.Fatalf("call during renewal: %v", err)
		}
		return tok != first
	})
	// expires_in drives the schedule: a token past its lifetime is never
	// handed out.
	renewed, _ := caller.Token(ctx, ordersRead)
	clock.Advance(11 * time.Minute)
	if tok, err := caller.Token(ctx, ordersRead); err != nil || tok == renewed {
		t.Fatalf("an expired token was returned: %v", err)
	}
}

// TestFailuresAreNotAmplified is AC-08.
func TestFailuresAreNotAmplified(t *testing.T) {
	t.Run("a target without a grant", func(t *testing.T) {
		iss := serviceIssuer(t)
		clock := newClock()
		caller := newCaller(t, iss)
		hooks.SetClock(caller, clock.Now)
		// An application that keeps asking for one minute.
		for i := 0; i < 600; i++ {
			_, err := caller.Token(ctx, iam.Target{Resource: billing})
			var oe *iam.OAuthError
			if !errors.As(err, &oe) || oe.Code != "invalid_target" || oe.StatusCode != 400 || oe.RequestID == "" {
				t.Fatalf("call %d: %v", i, err)
			}
			clock.Advance(100 * time.Millisecond)
		}
		if n := iss.Requests(iamtest.PathToken); n > 4 {
			t.Fatalf("%d refused requests reached IAM in one minute; the limit of IAM is 30", n)
		}
		// Many misconfigured targets at once stay within the budget too.
		for i := 0; i < 600; i++ {
			_, _ = caller.Token(ctx, iam.Target{Resource: "urn:example:app:missing-" + string(rune('a'+i%20))})
			clock.Advance(100 * time.Millisecond)
		}
		if n := iss.Requests(iamtest.PathToken); n > 20 {
			t.Fatalf("%d refused requests reached IAM in two minutes", n)
		}
		// A target that is fine is not held back by the others for long.
		clock.Advance(time.Minute)
		if _, err := caller.Token(ctx, ordersRead); err != nil {
			t.Fatalf("authorised target: %v", err)
		}
	})

	t.Run("a wrong credential", func(t *testing.T) {
		iss := serviceIssuer(t)
		clock := newClock()
		var secret atomic.Value
		secret.Store("ssk_wrong")
		caller := newCaller(t, iss, func(c *iam.CallerConfig) {
			c.Credential = iam.ClientSecretFunc(func(context.Context) (string, error) { return secret.Load().(string), nil })
		})
		hooks.SetClock(caller, clock.Now)
		for i := 0; i < 600; i++ {
			// Every target fails with the same refused credential.
			_, err := caller.Token(ctx, iam.Target{Resource: orders, Scopes: []string{[]string{"order.read", "order.write"}[i%2]}})
			var oe *iam.OAuthError
			if !errors.As(err, &oe) || oe.Code != "invalid_client" {
				t.Fatalf("call %d: %v", i, err)
			}
			clock.Advance(100 * time.Millisecond)
		}
		if n := iss.Requests(iamtest.PathToken); n > 4 {
			t.Fatalf("%d failed authentications reached IAM in one minute", n)
		}
		// Replacing the credential lifts the back-off at once (CALL-08).
		secret.Store("ssk_example_secret")
		if _, err := caller.Token(ctx, ordersRead); err != nil {
			t.Fatalf("after the secret was corrected: %v", err)
		}
	})

	t.Run("429 with Retry-After", func(t *testing.T) {
		iss := serviceIssuer(t)
		clock := newClock()
		caller := newCaller(t, iss)
		hooks.SetClock(caller, clock.Now)
		iss.Fail(iamtest.PathToken, iamtest.Fault{Status: 429, Error: "temporarily_unavailable", RetryAfter: 40})
		_, err := caller.Token(ctx, ordersRead)
		var oe *iam.OAuthError
		if !errors.As(err, &oe) || oe.StatusCode != 429 || oe.RetryAfter != 40*time.Second || !oe.Temporary() {
			t.Fatalf("429: %v", err)
		}
		for i := 0; i < 39; i++ {
			clock.Advance(time.Second)
			// No target is asked for before Retry-After has passed.
			if _, err := caller.Token(ctx, iam.Target{Resource: orders, Scopes: []string{"order.write"}}); err == nil {
				t.Fatal("a request was sent before Retry-After had passed")
			}
		}
		if n := iss.Requests(iamtest.PathToken); n != 1 {
			t.Fatalf("%d requests during Retry-After, want 1", n)
		}
		clock.Advance(2 * time.Second)
		if _, err := caller.Token(ctx, ordersRead); err != nil {
			t.Fatalf("after Retry-After: %v", err)
		}
	})

	t.Run("IAM unavailable", func(t *testing.T) {
		iss := serviceIssuer(t)
		iss.SetTokenLifetime(10 * time.Minute)
		clock := newClock()
		caller := newCaller(t, iss)
		hooks.SetClock(caller, clock.Now)
		token, err := caller.Token(ctx, ordersRead)
		if err != nil {
			t.Fatal(err)
		}
		// 503 is retried within the acquisition, with back-off.
		iss.Fail(iamtest.PathToken, iamtest.Fault{Status: 503, Error: "temporarily_unavailable", Times: 2})
		if _, err := caller.Token(ctx, iam.Target{Resource: orders, Scopes: []string{"order.write"}}); err != nil {
			t.Fatalf("two 503 answers must be survived by retrying: %v", err)
		}
		// IAM goes away entirely: the cached token stays usable until it
		// expires, also while its renewal keeps failing.
		iss.SetDown(true)
		clock.Advance(9 * time.Minute)
		for i := 0; i < 20; i++ {
			if tok, err := caller.Token(ctx, ordersRead); err != nil || tok != token {
				t.Fatalf("cached token while IAM is down: %v", err)
			}
			clock.Advance(time.Second)
		}
		// A token that is not cached cannot be had: a network error.
		if _, err := caller.Token(ctx, iam.Target{Resource: orders}); !errors.Is(err, iam.ErrNetwork) {
			t.Fatalf("uncached target while IAM is down: %v", err)
		}
		// Past its lifetime the cached token is not handed out any more.
		clock.Advance(2 * time.Minute)
		if _, err := caller.Token(ctx, ordersRead); !errors.Is(err, iam.ErrNetwork) {
			t.Fatalf("expired token while IAM is down: %v", err)
		}
		iss.SetDown(false)
		clock.Advance(time.Minute)
		if tok, err := caller.Token(ctx, ordersRead); err != nil || tok == token {
			t.Fatalf("after IAM came back: %v", err)
		}
	})
}

// TestCredentialRotation is AC-16: secrets and keys change without a
// restart, following IAM's overlapping rotation, and no token request fails.
func TestCredentialRotation(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	t.Run("secret", func(t *testing.T) {
		var secret atomic.Value
		secret.Store("ssk_old")
		iss.AddServiceClient(iamtest.ServiceClient{ID: svcID, Secrets: []string{"ssk_old"}})
		iss.Grant(svcID, orders, "order.read")
		caller := newCaller(t, iss, func(c *iam.CallerConfig) {
			c.Credential = iam.ClientSecretFunc(func(context.Context) (string, error) { return secret.Load().(string), nil })
		})
		mustToken := func(step string) {
			t.Helper()
			caller.Invalidate(ordersRead, "")
			if _, err := caller.Token(ctx, ordersRead); err != nil {
				t.Fatalf("%s: %v", step, err)
			}
		}
		mustToken("before the rotation")
		iss.AddServiceClient(iamtest.ServiceClient{ID: svcID, Secrets: []string{"ssk_old", "ssk_new"}}) // overlap begins
		mustToken("overlap, still using the old secret")
		secret.Store("ssk_new")
		mustToken("overlap, switched to the new secret")
		iss.AddServiceClient(iamtest.ServiceClient{ID: svcID, Secrets: []string{"ssk_new"}}) // old secret revoked
		mustToken("after the old secret was revoked")
	})
	t.Run("private key", func(t *testing.T) {
		oldKey, newKey := newRSAKey(t), newRSAKey(t)
		var current atomic.Value
		current.Store(iam.SigningKey{KeyID: "k1", Key: oldKey})
		iss.AddServiceClient(iamtest.ServiceClient{ID: "svc_example_key", PublicKeys: map[string]crypto.PublicKey{"k1": &oldKey.PublicKey}})
		iss.Grant("svc_example_key", orders, "order.read")
		caller := newCaller(t, iss, func(c *iam.CallerConfig) {
			c.ClientID = "svc_example_key"
			c.Credential = iam.PrivateKeyJWTFunc(func(context.Context) (iam.SigningKey, error) { return current.Load().(iam.SigningKey), nil })
		})
		mustToken := func(step string) {
			t.Helper()
			caller.Invalidate(ordersRead, "")
			if _, err := caller.Token(ctx, ordersRead); err != nil {
				t.Fatalf("%s: %v", step, err)
			}
		}
		mustToken("before the rotation")
		iss.AddServiceClient(iamtest.ServiceClient{ID: "svc_example_key", PublicKeys: map[string]crypto.PublicKey{"k1": &oldKey.PublicKey, "k2": &newKey.PublicKey}})
		mustToken("both keys registered, signing with the old one")
		current.Store(iam.SigningKey{KeyID: "k2", Key: newKey})
		mustToken("signing with the new key")
		iss.AddServiceClient(iamtest.ServiceClient{ID: "svc_example_key", PublicKeys: map[string]crypto.PublicKey{"k2": &newKey.PublicKey}})
		mustToken("after the old key was revoked")
	})
}

func TestCallerConfiguration(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	base := iam.CallerConfig{Issuer: iss.URL(), ClientID: svcID, Credential: iam.ClientSecret("s"), HTTPClient: iss.HTTPClient()}
	small := newRSAKey(t)
	for field, mutate := range map[string]func(*iam.CallerConfig){
		"Issuer":   func(c *iam.CallerConfig) { c.Issuer = "" },
		"ClientID": func(c *iam.CallerConfig) { c.ClientID = "" },
		"Credential": func(c *iam.CallerConfig) {
			c.Credential = nil
		},
	} {
		cfg := base
		mutate(&cfg)
		var ce *iam.ConfigError
		if _, err := iam.NewCaller(ctx, cfg); !errors.As(err, &ce) || ce.Field != field {
			t.Fatalf("%s: %v", field, err)
		}
	}
	for name, cred := range map[string]iam.Credential{
		"empty secret": iam.ClientSecret(""),
		"empty kid":    iam.PrivateKeyJWT("", small),
		"nil key":      iam.PrivateKeyJWT("k", nil),
		"failing source": iam.ClientSecretFunc(func(context.Context) (string, error) {
			return "", errors.New("vault sealed")
		}),
	} {
		cfg := base
		cfg.Credential = cred
		if _, err := iam.NewCaller(ctx, cfg); !errors.Is(err, iam.ErrConfig) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// targetServer is a stand-in for a target application. respond decides the
// answer from the number of the request (1-based) and the token it carried.
type targetServer struct {
	*httptest.Server
	mu     sync.Mutex
	tokens []string
	bodies []string
}

func newTarget(t *testing.T, tls bool, respond func(n int, w http.ResponseWriter, r *http.Request)) *targetServer {
	t.Helper()
	ts := &targetServer{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts.mu.Lock()
		ts.tokens = append(ts.tokens, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		ts.bodies = append(ts.bodies, string(body))
		n := len(ts.tokens)
		ts.mu.Unlock()
		respond(n, w, r)
	})
	if tls {
		ts.Server = httptest.NewTLSServer(handler)
	} else {
		ts.Server = httptest.NewServer(handler)
	}
	t.Cleanup(ts.Close)
	return ts
}

func (ts *targetServer) seen() []string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]string(nil), ts.tokens...)
}

func challenge(w http.ResponseWriter, status int, value string) {
	w.Header().Set("WWW-Authenticate", value)
	w.WriteHeader(status)
}

// TestOutboundClient covers CALL-05, CALL-06 and CALL-07.
func TestOutboundClient(t *testing.T) {
	iss := serviceIssuer(t)
	ok := func(_ int, w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }

	t.Run("attaches the token of its target", func(t *testing.T) {
		caller := newCaller(t, iss)
		target := newTarget(t, true, ok)
		client := &http.Client{Transport: caller.Transport(ordersRead, target.Client().Transport)}
		for i := 0; i < 3; i++ {
			res, err := client.Get(target.URL + "/api/orders/42")
			if err != nil || res.StatusCode != 200 {
				t.Fatalf("call: %v", err)
			}
			res.Body.Close()
		}
		seen := target.seen()
		if len(seen) != 3 || seen[0] == "" || seen[0] != seen[2] || claimsOf(t, seen[0])["aud"] != orders {
			t.Fatalf("tokens seen by the target: %d", len(seen))
		}
	})

	t.Run("refuses plaintext unless allowed", func(t *testing.T) {
		target := newTarget(t, false, ok)
		strict := newCaller(t, iss)
		if _, err := strict.HTTPClient(ordersRead).Get(target.URL); !errors.Is(err, iam.ErrInsecureTransport) || len(target.seen()) != 0 {
			t.Fatalf("plaintext target: %v", err)
		}
		relaxed := newCaller(t, iss, func(c *iam.CallerConfig) { c.AllowInsecureTransport = true })
		res, err := relaxed.HTTPClient(ordersRead).Get(target.URL)
		if err != nil || target.seen()[0] == "" {
			t.Fatalf("plaintext target with AllowInsecureTransport: %v", err)
		}
		res.Body.Close()
	})

	t.Run("does not carry the token to another origin", func(t *testing.T) {
		caller := newCaller(t, iss, func(c *iam.CallerConfig) { c.AllowInsecureTransport = true })
		other := newTarget(t, false, ok)
		target := newTarget(t, false, func(_ int, w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/elsewhere", http.StatusFound)
		})
		res, err := caller.HTTPClient(ordersRead).Get(target.URL + "/start")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if got := other.seen(); len(got) != 1 || got[0] != "" {
			t.Fatalf("the redirect target received a token: %q", got)
		}
		// With BaseURL the binding is explicit: other addresses are refused
		// before anything is sent.
		bound := iam.Target{Resource: orders, Scopes: []string{"order.read"}, BaseURL: target.URL + "/api"}
		client := caller.HTTPClient(bound)
		for _, u := range []string{other.URL + "/api/x", target.URL + "/apix", target.URL + "/other"} {
			if _, err := client.Get(u); !errors.Is(err, iam.ErrTargetMismatch) {
				t.Fatalf("%s: %v", u, err)
			}
		}
		if len(other.seen()) != 1 {
			t.Fatal("a request outside BaseURL was sent")
		}
	})

	t.Run("401 invalid_token: new token, one retry", func(t *testing.T) {
		caller := newCaller(t, iss)
		target := newTarget(t, true, func(n int, w http.ResponseWriter, _ *http.Request) {
			if n == 1 {
				challenge(w, 401, `Bearer realm="`+orders+`", error="invalid_token", error_description="token expired"`)
				return
			}
			_, _ = w.Write([]byte("ok"))
		})
		client := &http.Client{Transport: caller.Transport(ordersRead, target.Client().Transport)}
		before := iss.Requests(iamtest.PathToken)
		res, err := client.Post(target.URL+"/api/orders", "application/json", strings.NewReader(`{"id":42}`))
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("retried call: %v", err)
		}
		res.Body.Close()
		seen := target.seen()
		if len(seen) != 2 || seen[0] == seen[1] || iss.Requests(iamtest.PathToken)-before != 2 {
			t.Fatalf("expected a second request with a new token, saw %d requests", len(seen))
		}
		if target.bodies[1] != `{"id":42}` {
			t.Fatalf("the body was not replayed: %q", target.bodies[1])
		}
	})

	t.Run("401 invalid_token twice: an error, no loop", func(t *testing.T) {
		caller := newCaller(t, iss)
		target := newTarget(t, true, func(_ int, w http.ResponseWriter, _ *http.Request) {
			challenge(w, 401, `Bearer realm="`+orders+`", error="invalid_token", error_description="audience is not this resource"`)
		})
		client := &http.Client{Transport: caller.Transport(ordersRead, target.Client().Transport)}
		_, err := client.Get(target.URL)
		be := bearerError(t, err)
		if !errors.Is(err, iam.ErrInvalidToken) || be.Status != 401 || be.Description != "audience is not this resource" || len(target.seen()) != 2 {
			t.Fatalf("persistent 401: %v after %d requests", err, len(target.seen()))
		}
	})

	t.Run("401 on a request that cannot be replayed", func(t *testing.T) {
		caller := newCaller(t, iss)
		target := newTarget(t, true, func(_ int, w http.ResponseWriter, _ *http.Request) {
			challenge(w, 401, `Bearer error="invalid_token"`)
		})
		client := &http.Client{Transport: caller.Transport(ordersRead, target.Client().Transport)}
		first, _ := caller.Token(ctx, ordersRead)
		req, _ := http.NewRequest(http.MethodPost, target.URL, io.NopCloser(strings.NewReader("stream")))
		if _, err := client.Do(req); !errors.Is(err, iam.ErrInvalidToken) || len(target.seen()) != 1 {
			t.Fatalf("non-replayable request: %v after %d requests", err, len(target.seen()))
		}
		// The refused token is gone from the cache all the same.
		if next, _ := caller.Token(ctx, ordersRead); next == first {
			t.Fatal("the refused token is still cached")
		}
	})

	t.Run("403 insufficient_scope: no retry, a recognisable error", func(t *testing.T) {
		caller := newCaller(t, iss)
		target := newTarget(t, true, func(_ int, w http.ResponseWriter, _ *http.Request) {
			challenge(w, 403, `Bearer realm="`+orders+`", error="insufficient_scope", error_description="the token lacks order.refund", scope="order.read order.refund"`)
		})
		client := &http.Client{Transport: caller.Transport(ordersRead, target.Client().Transport)}
		before := iss.Requests(iamtest.PathToken)
		_, err := client.Get(target.URL)
		be := bearerError(t, err)
		if !errors.Is(err, iam.ErrInsufficientScope) || be.Scope != "order.read order.refund" || be.Realm != orders || len(target.seen()) != 1 || iss.Requests(iamtest.PathToken)-before != 1 {
			t.Fatalf("403: %v after %d requests", err, len(target.seen()))
		}
	})

	t.Run("other responses pass through", func(t *testing.T) {
		caller := newCaller(t, iss)
		target := newTarget(t, true, func(n int, w http.ResponseWriter, _ *http.Request) {
			switch n {
			case 1:
				w.WriteHeader(http.StatusForbidden) // the target's own business refusal
			case 2:
				challenge(w, 401, `Basic realm="admin"`)
			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		client := &http.Client{Transport: caller.Transport(ordersRead, target.Client().Transport)}
		for _, want := range []int{403, 401, 500} {
			res, err := client.Get(target.URL)
			if err != nil || res.StatusCode != want {
				t.Fatalf("want HTTP %d untouched: %v", want, err)
			}
			res.Body.Close()
		}
	})

	t.Run("token failures surface as the request error", func(t *testing.T) {
		caller := newCaller(t, iss)
		target := newTarget(t, true, ok)
		client := &http.Client{Transport: caller.Transport(iam.Target{Resource: billing}, target.Client().Transport)}
		_, err := client.Get(target.URL)
		var oe *iam.OAuthError
		if !errors.As(err, &oe) || oe.Code != "invalid_target" || len(target.seen()) != 0 {
			t.Fatalf("no grant: %v", err)
		}
		if _, err := caller.HTTPClient(iam.Target{}).Get(target.URL); !errors.Is(err, iam.ErrConfig) {
			t.Fatalf("invalid target: %v", err)
		}
	})
}

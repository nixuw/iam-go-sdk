package iam_test

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamtest"
	"github.com/nixuw/iam-go-sdk/internal/hooks"
	"github.com/nixuw/iam-go-sdk/internal/webflow"
)

// sharedStore is a SessionStore as an application would supply it to run
// several instances: here a map standing in for a shared store with atomic
// compare-and-swap.
type sharedStore struct {
	mu    sync.Mutex
	items map[string][]byte
}

func (s *sharedStore) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items[key], nil
}

func (s *sharedStore) Set(_ context.Context, key string, value []byte, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[key] = bytes.Clone(value)
	return nil
}

func (s *sharedStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
	return nil
}

func (s *sharedStore) CompareAndSwap(_ context.Context, key string, old, value []byte, _ time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.items[key]; !ok || !bytes.Equal(current, old) {
		return false, nil
	}
	s.items[key] = bytes.Clone(value)
	return true, nil
}

func (s *sharedStore) dump() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for k, v := range s.items {
		b.WriteString(k)
		b.Write(v)
	}
	return b.String()
}

// cookies is the cookie jar of one simulated browser.
type cookies map[string]string

func (c cookies) request(method, path, query string) *webflow.Request {
	return &webflow.Request{
		Method: method, Path: path, RawQuery: query,
		Header: func(name string) string {
			if name == "Accept" {
				return "application/json"
			}
			return ""
		},
		Cookie: func(name string) string { return c[name] },
	}
}

func (c cookies) apply(res *webflow.Response) {
	for _, ck := range res.Cookies {
		if ck.MaxAge < 0 {
			delete(c, ck.Name)
		} else {
			c[ck.Name] = ck.Value
		}
	}
}

// webSignIn signs the browser in through the engine of one instance.
func webSignIn(t *testing.T, iss *iamtest.Issuer, engine webflow.LoginEngine, jar cookies) {
	t.Helper()
	start := engine.Start(ctx, jar.request("GET", "/login", ""))
	if start.Err != nil {
		t.Fatalf("Start: %v", start.Err)
	}
	jar.apply(start)
	done := engine.Callback(ctx, jar.request("GET", "/callback", visit(t, iss, start.Location).Encode()))
	if done.Err != nil || done.Status != http.StatusFound {
		t.Fatalf("Callback: %v", done.Err)
	}
	jar.apply(done)
}

// GAP-05 / LOGIN-07: several instances share the sessions. Requests of one
// session that reach different instances at the same moment must lead to a
// single refresh, because IAM revokes the whole chain when a rotated refresh
// token is presented twice.
func TestRefreshAcrossInstances(t *testing.T) {
	iss := loginIssuer(t)
	clock := newClock()
	iss.SetClock(clock.Now)
	store := &sharedStore{items: map[string][]byte{}}
	key := bytes.Repeat([]byte("k"), 32)
	instance := func() webflow.LoginEngine {
		l := newLogin(t, iss, func(c *iam.LoginConfig) { c.SessionKey, c.SessionStore = key, store })
		hooks.SetClock(l, clock.Now)
		return webflow.Engine(l)
	}
	a, b := instance(), instance()
	jar := cookies{}
	webSignIn(t, iss, a, jar)

	// The session is valid on the instance that did not create it.
	if user, refuse := b.Authenticate(ctx, jar.request("GET", "/api/me", ""), "/login"); refuse != nil || user.(*iam.User).Subject != alice.Subject {
		t.Fatalf("session on the second instance: %+v", refuse)
	}
	refreshes := func() int {
		n := 0
		for _, f := range iss.TokenRequests() {
			if f.Get("grant_type") == "refresh_token" {
				n++
			}
		}
		return n
	}
	for round := 1; round <= 3; round++ {
		clock.Advance(16 * time.Minute) // the access token has expired
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				engine := []webflow.LoginEngine{a, b}[i%2]
				if _, refuse := engine.Authenticate(ctx, jar.request("GET", "/api/me", ""), "/login"); refuse != nil {
					t.Errorf("round %d: request refused: %v", round, refuse.Err)
				}
			}()
		}
		wg.Wait()
		if n := refreshes(); n != round {
			t.Fatalf("round %d: %d refresh requests in total, want %d", round, n, round)
		}
	}

	// What the store holds is encrypted: no token, no user data.
	stored := store.dump()
	for _, secret := range append(iss.Sensitive(), alice.Subject, alice.Email) {
		if secret != "" && strings.Contains(stored, secret) {
			t.Fatal("the session store holds session data in clear text")
		}
	}
	// A session cannot be read with another key, and a value cannot be
	// moved to another session ID.
	other := webflow.Engine(newLogin(t, iss, func(c *iam.LoginConfig) { c.SessionKey, c.SessionStore = bytes.Repeat([]byte("x"), 32), store }))
	if _, refuse := other.Authenticate(ctx, jar.request("GET", "/api/me", ""), "/login"); refuse == nil {
		t.Fatal("a session was accepted under a different session key")
	}
}

// CFG-04: the session key can be replaced without ending the sessions.
func TestSessionKeyRotation(t *testing.T) {
	iss := loginIssuer(t)
	oldKey, newKey := bytes.Repeat([]byte("o"), 32), bytes.Repeat([]byte("n"), 32)
	var keys atomic.Value
	keys.Store([][]byte{oldKey})
	l := newLogin(t, iss, func(c *iam.LoginConfig) {
		c.SessionKeys = func(context.Context) ([][]byte, error) { return keys.Load().([][]byte), nil }
	})
	engine := webflow.Engine(l)
	jar := cookies{}
	webSignIn(t, iss, engine, jar)
	authenticated := func() bool {
		_, refuse := engine.Authenticate(ctx, jar.request("GET", "/api/me", ""), "/login")
		return refuse == nil
	}
	keys.Store([][]byte{newKey, oldKey}) // new key first, old key still accepted
	if !authenticated() {
		t.Fatal("the session must survive the introduction of a new key")
	}
	later := cookies{}
	webSignIn(t, iss, engine, later)
	keys.Store([][]byte{newKey}) // old key retired
	if authenticated() {
		t.Fatal("a session of the retired key must end")
	}
	if _, refuse := engine.Authenticate(ctx, later.request("GET", "/api/me", ""), "/login"); refuse != nil {
		t.Fatal("a session of the new key must stay")
	}
}

// LOGIN-01: the one-time values of a sign-in live on the server; the browser
// only ever holds an opaque, signed binding.
func TestPendingSignInStaysOnTheServer(t *testing.T) {
	iss := loginIssuer(t)
	l := newLogin(t, iss, func(c *iam.LoginConfig) { c.SessionKey = bytes.Repeat([]byte("k"), 32) })
	engine := webflow.Engine(l)
	jar := cookies{}
	start := engine.Start(ctx, jar.request("GET", "/login", "return_to=%2Fdashboard"))
	jar.apply(start)
	u, _ := url.Parse(start.Location)
	for name, value := range jar {
		for _, param := range []string{"state", "nonce", "code_challenge"} {
			if strings.Contains(value, u.Query().Get(param)) {
				t.Fatalf("cookie %s carries the %s of the sign-in", name, param)
			}
		}
	}
	// Two tabs of one browser can sign in side by side.
	second := engine.Start(ctx, jar.request("GET", "/login", ""))
	jar.apply(second)
	for i, s := range []*webflow.Response{second, start} {
		done := engine.Callback(ctx, jar.request("GET", "/callback", visit(t, iss, s.Location).Encode()))
		if done.Err != nil {
			t.Fatalf("tab %d: %v", i, done.Err)
		}
		jar.apply(done)
		if i == 1 && done.Location != "/dashboard" {
			t.Fatalf("return address: %q", done.Location)
		}
	}
}

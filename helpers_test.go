package iam_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamtest"
	"github.com/nixuw/iam-go-sdk/internal/hooks"
)

// Placeholder identifiers used throughout the tests.
const (
	orders   = "urn:example:app:orders"
	billing  = "urn:example:app:billing"
	svcID    = "svc_example_caller"
	appID    = "app_example_portal"
	redirect = "https://portal.example.test/callback"
)

var ctx = context.Background()

// fakeClock is a clock the test moves by hand.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// logSink collects everything an instance logs, at the most verbose level.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *logSink) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(s, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func newVerifier(t *testing.T, iss *iamtest.Issuer, mutate ...func(*iam.VerifierConfig)) *iam.Verifier {
	t.Helper()
	cfg := iam.VerifierConfig{Issuer: iss.URL(), Audience: orders, HTTPClient: iss.HTTPClient()}
	for _, m := range mutate {
		m(&cfg)
	}
	v, err := iam.NewVerifier(ctx, cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func newCaller(t *testing.T, iss *iamtest.Issuer, mutate ...func(*iam.CallerConfig)) *iam.Caller {
	t.Helper()
	cfg := iam.CallerConfig{Issuer: iss.URL(), ClientID: svcID, Credential: iam.ClientSecret("ssk_example_secret"), HTTPClient: iss.HTTPClient()}
	for _, m := range mutate {
		m(&cfg)
	}
	c, err := iam.NewCaller(ctx, cfg)
	if err != nil {
		t.Fatalf("NewCaller: %v", err)
	}
	// Retries inside one acquisition do not really wait in tests.
	hooks.SetSleep(c, func(context.Context, time.Duration) error { return nil })
	return c
}

// serviceIssuer is a fake issuer with one secret-based service credential
// that holds a grant on the orders application.
func serviceIssuer(t *testing.T) *iamtest.Issuer {
	t.Helper()
	iss := iamtest.NewIssuer(t)
	iss.AddServiceClient(iamtest.ServiceClient{ID: svcID, Secrets: []string{"ssk_example_secret"}})
	iss.Grant(svcID, orders, "order.read", "order.write")
	return iss
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// bearerError extracts the RFC 6750 error or fails the test.
func bearerError(t *testing.T, err error) *iam.BearerError {
	t.Helper()
	var be *iam.BearerError
	if !errors.As(err, &be) {
		t.Fatalf("expected a *iam.BearerError, got %v", err)
	}
	return be
}

// claimsOf decodes the payload of a JWT without verifying it.
func claimsOf(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// eventually waits for a condition that a background goroutine brings about.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func b64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

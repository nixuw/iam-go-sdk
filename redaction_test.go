package iam_test

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamtest"
	"github.com/nixuw/iam-go-sdk/internal/hooks"
	"github.com/nixuw/iam-go-sdk/internal/webflow"
)

// TestNothingSensitiveIsLogged is AC-17: the scenarios of all three modules
// run with the most verbose logging, and neither the log nor any returned
// error contains a token, a secret, a client assertion, an authorization
// code or a PKCE verifier.
func TestNothingSensitiveIsLogged(t *testing.T) {
	iss := loginIssuer(t)
	key := newRSAKey(t)
	iss.AddServiceClient(iamtest.ServiceClient{ID: svcID, Secrets: []string{"ssk_example_secret"}})
	iss.AddServiceClient(iamtest.ServiceClient{ID: "svc_example_key", PublicKeys: map[string]crypto.PublicKey{"k1": &key.PublicKey}})
	iss.Grant(svcID, orders, "order.read")
	iss.Grant("svc_example_key", orders, "order.read")
	clock := newClock()
	iss.SetClock(clock.Now)

	sink := &logSink{}
	var failures []string
	note := func(err error) {
		if err != nil {
			failures = append(failures, err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err))
		}
	}

	// ---- provider side ----
	v := newVerifier(t, iss, func(c *iam.VerifierConfig) { c.Logger = sink.logger() })
	good := iss.ServiceToken(orders, svcID, "order.read")
	for _, token := range []string{
		good, good + "x", "garbage",
		iss.ServiceToken(billing, svcID, "order.read"),
		iss.AccessToken(iamtest.Token{Audience: orders, KeyID: "unknown-kid"}),
		iss.AccessToken(iamtest.Token{Audience: orders, Header: map[string]any{"typ": "JWT"}}),
	} {
		_, err := v.Verify(ctx, token, readRule)
		note(err)
		_, err = v.Verify(ctx, token, writeRule)
		note(err)
		_, err = v.Verify(ctx, token, iam.Rule{})
		note(err)
	}

	// ---- caller side ----
	for i, cfg := range []func(*iam.CallerConfig){
		func(c *iam.CallerConfig) {},
		func(c *iam.CallerConfig) { c.Credential = iam.ClientSecret("ssk_a_wrong_secret_value") },
		func(c *iam.CallerConfig) {
			c.ClientID, c.Credential = "svc_example_key", iam.PrivateKeyJWT("k1", key)
		},
		func(c *iam.CallerConfig) {
			c.ClientID, c.Credential = "svc_example_key", iam.PrivateKeyJWT("not-registered", key)
		},
	} {
		caller := newCaller(t, iss, cfg, func(c *iam.CallerConfig) { c.Logger = sink.logger() })
		hooks.SetClock(caller, clock.Now)
		for _, target := range []iam.Target{ordersRead, {Resource: billing}, {Resource: orders, Scopes: []string{"order.refund"}}} {
			_, err := caller.Token(ctx, target)
			note(err)
		}
		if i == 0 { // a caller whose requests reach IAM: rate limited once
			iss.Fail(iamtest.PathToken, iamtest.Fault{Status: 429, Error: "temporarily_unavailable", RetryAfter: 5})
		}
		_, err := caller.Token(ctx, iam.Target{Resource: orders})
		note(err)
		clock.Advance(6 * time.Second)
		iss.SetDown(true)
		_, err = caller.Token(ctx, iam.Target{Resource: orders, Scopes: []string{"order.read", "order.write"}})
		note(err)
		iss.SetDown(false)
		note(caller.Revoke(ctx, ordersRead))
		_, err = caller.HTTPClient(ordersRead).Get("http://orders.example.test/plaintext")
		note(err)
	}

	// ---- sign-in ----
	l := newLogin(t, iss, func(c *iam.LoginConfig) {
		c.Logger, c.SessionKey, c.FetchUserInfo = sink.logger(), bytes.Repeat([]byte("k"), 32), true
		c.PostLogoutRedirectURL = "https://portal.example.test/"
	})
	hooks.SetClock(l, clock.Now)
	engine := webflow.Engine(l)
	jar := cookies{}
	webSignIn(t, iss, engine, jar)
	// refresh, then a refused refresh
	clock.Advance(16 * time.Minute)
	if _, refuse := engine.Authenticate(ctx, jar.request("GET", "/api/me", ""), "/login"); refuse != nil {
		t.Fatalf("refresh: %v", refuse.Err)
	}
	iss.SignOut()
	clock.Advance(16 * time.Minute)
	_, refuse := engine.Authenticate(ctx, jar.request("GET", "/api/me", ""), "/login")
	note(refuse.Err)
	iss.SignIn(alice)
	// failing callbacks: wrong state, foreign iss, IAM error, bad ID token
	for _, damage := range []func(url.Values){
		func(q url.Values) { q.Set("state", "unknown-state") },
		func(q url.Values) { q.Set("iss", "https://attacker.example.test") },
		func(q url.Values) { q.Set("code", q.Get("code")+"-tampered") },
		nil,
	} {
		other := cookies{}
		start := engine.Start(ctx, other.request("GET", "/login", ""))
		other.apply(start)
		if damage == nil {
			iss.OnIDToken(func(c map[string]any, _ func(h, c map[string]any) string) string {
				c["aud"] = "app_someone_else"
				return ""
			})
		}
		query := visit(t, iss, start.Location)
		if damage != nil {
			damage(query)
		}
		note(engine.Callback(ctx, other.request("GET", "/callback", query.Encode())).Err)
		iss.OnIDToken(nil)
	}
	iss.FailAuthorize("access_denied")
	other := cookies{}
	start := engine.Start(ctx, other.request("GET", "/login", ""))
	other.apply(start)
	note(engine.Callback(ctx, other.request("GET", "/callback", visit(t, iss, start.Location).Encode())).Err)
	// a complete sign-in and logout, with the protocol-level calls as well
	webSignIn(t, iss, engine, jar)
	if res := engine.Logout(ctx, jar.request("GET", "/logout", "")); res.Status != http.StatusFound {
		t.Fatalf("logout: %v", res.Err)
	}
	result, err := signIn(t, iss, l, iam.AuthOptions{})
	note(err)
	_, err = l.UserInfo(ctx, result.Tokens.IDToken, alice.Subject)
	note(err)
	_, err = l.Refresh(ctx, "rt_not_a_real_refresh_token_value")
	note(err)
	note(l.Revoke(ctx, result.Tokens.RefreshToken))

	// ---- the check ----
	log := sink.String()
	if !strings.Contains(log, "level=DEBUG") || !strings.Contains(log, "level=WARN") || len(failures) < 30 {
		t.Fatalf("the scenarios did not exercise logging and errors as intended: %d errors, %d bytes of log", len(failures), len(log))
	}
	sensitive := append(iss.Sensitive(), "ssk_a_wrong_secret_value", "rt_not_a_real_refresh_token_value", result.Tokens.AccessToken, result.Tokens.IDToken)
	checked := 0
	for _, secret := range sensitive {
		if len(secret) < 12 {
			continue
		}
		checked++
		if strings.Contains(log, secret) {
			t.Errorf("the log contains a sensitive value (%.12s…)", secret)
		}
		for _, f := range failures {
			if strings.Contains(f, secret) {
				t.Errorf("an error message contains a sensitive value (%.12s…): %.80s", secret, f)
			}
		}
	}
	if checked < 40 {
		t.Fatalf("only %d sensitive values were checked", checked)
	}
	_ = context.Background
}

package iam_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamtest"
	"github.com/nixuw/iam-go-sdk/internal/hooks"
)

var (
	readRule  = iam.Rule{Scopes: []string{"order.read"}, Principals: []string{iam.PrincipalService, iam.PrincipalUser}}
	writeRule = iam.Rule{Scopes: []string{"order.write"}, Principals: []string{iam.PrincipalService}}
)

// TestTokenValidationChecklist is AC-09: the checklist of section 12 of the
// provider guide, item by item, against tokens signed by the issuer.
func TestTokenValidationChecklist(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	v := newVerifier(t, iss)
	now := time.Now()
	valid := iamtest.Token{Subject: svcID, ClientID: svcID, Audience: orders, Principal: "service", Scopes: []string{"order.read"}}
	with := func(mutate func(*iamtest.Token)) string {
		tok := valid
		mutate(&tok)
		return iss.AccessToken(tok)
	}
	good := iss.AccessToken(valid)
	parts := strings.Split(good, ".")

	// alg none: the same header and claims, no signature.
	none := b64(map[string]any{"alg": "none", "typ": "at+jwt", "kid": iss.KeyID()}) + "." + parts[1] + "."
	// HS256 with the issuer's public key as the secret.
	der, err := x509.MarshalPKIXPublicKey(iss.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	hs, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: der}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", iss.KeyID()))
	if err != nil {
		t.Fatal(err)
	}
	hsObj, _ := hs.Sign([]byte(`{"iss":"` + iss.URL() + `","aud":"` + orders + `","scope":"order.read","principal_type":"service","exp":9999999999,"iat":1}`))
	hs256, _ := hsObj.CompactSerialize()

	cases := []struct {
		name   string
		token  string
		rule   iam.Rule
		status int
		code   string
		scope  string
	}{
		{name: "no token", token: "", rule: readRule, status: 401},
		{name: "alg none", token: none, rule: readRule, status: 401, code: "invalid_token"},
		{name: "HS256 signed with the public key", token: hs256, rule: readRule, status: 401, code: "invalid_token"},
		{name: "ID token (typ JWT)", token: with(func(k *iamtest.Token) { k.Header = map[string]any{"typ": "JWT"} }), rule: readRule, status: 401, code: "invalid_token"},
		{name: "payload changed", token: parts[0] + "." + b64(map[string]any{"iss": iss.URL(), "aud": orders, "scope": "order.read order.write"}) + "." + parts[2], rule: readRule, status: 401, code: "invalid_token"},
		{name: "signature changed", token: parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2])), rule: readRule, status: 401, code: "invalid_token"},
		{name: "unknown kid", token: with(func(k *iamtest.Token) { k.KeyID = "no-such-key" }), rule: readRule, status: 401, code: "invalid_token"},
		{name: "kid missing", token: with(func(k *iamtest.Token) { k.Header = map[string]any{"kid": nil} }), rule: readRule, status: 401, code: "invalid_token"},
		{name: "iss with a trailing slash", token: with(func(k *iamtest.Token) { k.Claims = map[string]any{"iss": iss.URL() + "/"} }), rule: readRule, status: 401, code: "invalid_token"},
		{name: "aud is another application", token: with(func(k *iamtest.Token) { k.Audience = billing }), rule: readRule, status: 401, code: "invalid_token"},
		{name: "aud is UserInfo (sign-in token)", token: with(func(k *iamtest.Token) { k.Audience = iss.UserInfoAudience(); k.Principal = "user" }), rule: readRule, status: 401, code: "invalid_token"},
		{name: "aud is an array containing this application", token: with(func(k *iamtest.Token) { k.Claims = map[string]any{"aud": []string{orders}} }), rule: readRule, status: 401, code: "invalid_token"},
		{name: "expired for more than 60 s", token: with(func(k *iamtest.Token) { k.IssuedAt = now.Add(-17 * time.Minute) }), rule: readRule, status: 401, code: "invalid_token"},
		{name: "exp missing", token: with(func(k *iamtest.Token) { k.Claims = map[string]any{"exp": nil} }), rule: readRule, status: 401, code: "invalid_token"},
		{name: "iat missing", token: with(func(k *iamtest.Token) { k.Claims = map[string]any{"iat": nil} }), rule: readRule, status: 401, code: "invalid_token"},
		{name: "issued in the future", token: with(func(k *iamtest.Token) { k.IssuedAt = now.Add(5 * time.Minute) }), rule: readRule, status: 401, code: "invalid_token"},
		{name: "not a JWT", token: "not-a-token", rule: readRule, status: 401, code: "invalid_token"},
		{name: "permission missing", token: good, rule: writeRule, status: 403, code: "insufficient_scope", scope: "order.write"},
		{name: "one of two permissions missing", token: good, rule: iam.Rule{Scopes: []string{"order.read", "order.refund"}, Principals: []string{"service"}}, status: 403, code: "insufficient_scope", scope: "order.read order.refund"},
		{name: "permission is only a prefix", token: with(func(k *iamtest.Token) { k.Scopes = []string{"order.read.all"} }), rule: readRule, status: 403, code: "insufficient_scope", scope: "order.read"},
		{name: "principal type not accepted", token: with(func(k *iamtest.Token) { k.Principal = "user"; k.Scopes = []string{"order.write"} }), rule: writeRule, status: 403, code: "insufficient_scope", scope: "order.write"},
		{name: "principal type missing", token: with(func(k *iamtest.Token) { k.Claims = map[string]any{"principal_type": nil} }), rule: readRule, status: 403, code: "insufficient_scope", scope: "order.read"},
		// A token with both kinds of problem is invalid first (401, not 403).
		{name: "wrong audience and missing permission", token: with(func(k *iamtest.Token) { k.Audience = billing }), rule: writeRule, status: 401, code: "invalid_token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := v.Verify(ctx, tc.token, tc.rule)
			if err == nil {
				t.Fatalf("accepted: %+v", id)
			}
			be := bearerError(t, err)
			if be.Status != tc.status || be.Code != tc.code || be.Scope != tc.scope || be.Realm != orders {
				t.Fatalf("got %d %q scope=%q realm=%q, want %d %q scope=%q", be.Status, be.Code, be.Scope, be.Realm, tc.status, tc.code, tc.scope)
			}
			challenge := be.WWWAuthenticate()
			switch {
			case tc.code == "" && challenge != `Bearer realm="`+orders+`"`:
				t.Fatalf("a request without a token must be challenged with the realm only: %q", challenge)
			case tc.code != "" && !strings.Contains(challenge, `error="`+tc.code+`"`):
				t.Fatalf("challenge lacks the error: %q", challenge)
			case tc.scope != "" && !strings.Contains(challenge, `scope="`+tc.scope+`"`):
				t.Fatalf("challenge lacks the required scope: %q", challenge)
			}
			want := map[int]error{401: iam.ErrInvalidToken, 403: iam.ErrInsufficientScope}[tc.status]
			if tc.code == "" {
				want = iam.ErrNoToken
			}
			if !errors.Is(err, want) {
				t.Fatalf("errors.Is(%v, %v) = false", err, want)
			}
			if tc.token != "" && (strings.Contains(err.Error(), tc.token) || strings.Contains(challenge, tc.token)) {
				t.Fatal("the error echoes the token")
			}
		})
	}

	t.Run("within the 60 s leeway", func(t *testing.T) {
		if _, err := v.Verify(ctx, with(func(k *iamtest.Token) { k.IssuedAt = now.Add(-15*time.Minute - 30*time.Second) }), readRule); err != nil {
			t.Fatalf("a token that expired 30 s ago is inside the leeway: %v", err)
		}
	})
	t.Run("valid system token", func(t *testing.T) {
		id, err := v.Verify(ctx, good, readRule)
		if err != nil {
			t.Fatal(err)
		}
		if id.ClientID != svcID || id.Subject != svcID || id.PrincipalType != iam.PrincipalService || !id.IsService() || !id.HasScope("order.read") ||
			id.HasScope("order") || id.TokenID == "" || id.Audience != orders || id.Issuer != iss.URL() || id.ExpiresAt.Before(now) || id.SessionID != "" {
			t.Fatalf("identity: %+v", id)
		}
	})
	t.Run("valid user-delegated token", func(t *testing.T) {
		id, err := v.Verify(ctx, iss.UserToken(orders, appID, "user-1", "order.read"), readRule)
		if err != nil {
			t.Fatal(err)
		}
		if !id.IsUser() || id.Subject != "user-1" || id.ClientID != appID || id.SessionID == "" || id.AuthTime.IsZero() {
			t.Fatalf("identity: %+v", id)
		}
	})
	t.Run("application/at+jwt, any case", func(t *testing.T) {
		if _, err := v.Verify(ctx, with(func(k *iamtest.Token) { k.Header = map[string]any{"typ": "Application/AT+JWT"} }), readRule); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Authorization header", func(t *testing.T) {
		if _, err := v.VerifyHeader(ctx, "bearer "+good, readRule); err != nil {
			t.Fatalf("the scheme is case-insensitive: %v", err)
		}
		for _, h := range []string{"", "Bearer", "Bearer ", "Basic abc", good} {
			if _, err := v.VerifyHeader(ctx, h, readRule); !errors.Is(err, iam.ErrNoToken) {
				t.Fatalf("header %q: %v", h, err)
			}
		}
	})
}

// TestOfflineValidation is AC-10.
func TestOfflineValidation(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	clock := newClock()
	v := newVerifier(t, iss)
	hooks.SetClock(v, clock.Now)
	token := iss.ServiceToken(orders, svcID, "order.read")

	// 20+ validations, one JWKS download.
	for i := 0; i < 25; i++ {
		if _, err := v.Verify(ctx, token, readRule); err != nil {
			t.Fatalf("validation %d: %v", i, err)
		}
	}
	if n := iss.Requests(iamtest.PathJWKS); n != 1 {
		t.Fatalf("%d JWKS downloads for 25 validations, want 1", n)
	}

	// A stream of tokens with an unknown kid is not amplified to IAM.
	forged := iss.AccessToken(iamtest.Token{Audience: orders, KeyID: "forged-kid"})
	for i := 0; i < 40; i++ {
		if _, err := v.Verify(ctx, forged, readRule); !errors.Is(err, iam.ErrInvalidToken) {
			t.Fatalf("forged kid %d: %v", i, err)
		}
	}
	if n := iss.Requests(iamtest.PathJWKS); n != 2 {
		t.Fatalf("%d JWKS downloads after 40 unknown kids, want 2 (one retry, then rate limited)", n)
	}

	// IAM activates a new signing key: new and old tokens both verify.
	clock.Advance(31 * time.Second) // past the rate limit of the unknown kid above
	old := token
	iss.RotateKey()
	fresh := iss.ServiceToken(orders, svcID, "order.read")
	if _, err := v.Verify(ctx, fresh, readRule); err != nil {
		t.Fatalf("token signed with the new key: %v", err)
	}
	if _, err := v.Verify(ctx, old, readRule); err != nil {
		t.Fatalf("token signed with the previous key: %v", err)
	}

	// IAM becomes unreachable: tokens that have not expired still verify.
	iss.SetDown(true)
	for _, tok := range []string{old, fresh} {
		if _, err := v.Verify(ctx, tok, readRule); err != nil {
			t.Fatalf("validation while IAM is down: %v", err)
		}
	}
	// ... also once the cache is due for a refresh, which then fails.
	clock.Advance(11 * time.Minute)
	token = iss.AccessToken(iamtest.Token{Subject: svcID, ClientID: svcID, Audience: orders, Principal: "service", Scopes: []string{"order.read"}, IssuedAt: clock.Now()})
	for i := 0; i < 5; i++ {
		if _, err := v.Verify(ctx, token, readRule); err != nil {
			t.Fatalf("validation with stale keys while IAM is down: %v", err)
		}
	}
	// ... but not forever: after 24 hours the cached keys are dropped, and
	// the answer is "unavailable", not "invalid token".
	clock.Advance(25 * time.Hour)
	token = iss.AccessToken(iamtest.Token{Subject: svcID, ClientID: svcID, Audience: orders, Principal: "service", Scopes: []string{"order.read"}, IssuedAt: clock.Now()})
	_, err := v.Verify(ctx, token, readRule)
	if be := bearerError(t, err); be.Status != http.StatusServiceUnavailable || !errors.Is(err, iam.ErrUnavailable) || be.WWWAuthenticate() != "" {
		t.Fatalf("with no trustworthy key left: %v", err)
	}
	// IAM is back: validation recovers by itself.
	iss.SetDown(false)
	clock.Advance(31 * time.Second)
	if _, err := v.Verify(ctx, token, readRule); err != nil {
		t.Fatalf("after IAM came back: %v", err)
	}
}

// A key that IAM retired stops verifying once the cache was refreshed.
func TestRetiredKeyStopsVerifying(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	clock := newClock()
	v := newVerifier(t, iss)
	hooks.SetClock(v, clock.Now)
	oldKid := iss.KeyID()
	old := iss.AccessToken(iamtest.Token{Subject: svcID, ClientID: svcID, Audience: orders, Principal: "service", Scopes: []string{"order.read"}, Lifetime: time.Hour})
	iss.RotateKey()
	iss.RetireKey(oldKid)
	if _, err := v.Verify(ctx, old, readRule); err != nil {
		t.Fatalf("before the cache is refreshed the key is still trusted: %v", err)
	}
	clock.Advance(11 * time.Minute)
	eventually(t, "the retired key to be dropped", func() bool {
		_, err := v.Verify(ctx, old, readRule)
		return errors.Is(err, iam.ErrInvalidToken)
	})
}

// TestDefaultDeny is AC-11: an endpoint without a complete rule is closed.
func TestDefaultDeny(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	v := newVerifier(t, iss)
	token := iss.ServiceToken(orders, svcID, "order.read")
	for name, rule := range map[string]iam.Rule{
		"no rule at all":         {},
		"no principal types":     {Scopes: []string{"order.read"}},
		"no permissions":         {Principals: []string{iam.PrincipalService}},
		"unknown principal type": {Scopes: []string{"order.read"}, Principals: []string{"anyone"}},
	} {
		_, err := v.Verify(ctx, token, rule)
		if be := bearerError(t, err); be.Status != http.StatusForbidden || !errors.Is(err, iam.ErrInsufficientScope) {
			t.Fatalf("%s: %v", name, err)
		}
		// The token is still checked first: an invalid one is 401.
		if _, err := v.Verify(ctx, "garbage", rule); !errors.Is(err, iam.ErrInvalidToken) {
			t.Fatalf("%s with an invalid token: %v", name, err)
		}
	}
}

// BASE-04: what happens when IAM is unreachable at startup is the
// application's choice, and "no keys" is not reported as "invalid token".
func TestStartupWithoutIAM(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	iss.SetDown(true)
	cfg := iam.VerifierConfig{Issuer: iss.URL(), Audience: orders, HTTPClient: iss.HTTPClient()}
	if _, err := iam.NewVerifier(ctx, cfg); !errors.Is(err, iam.ErrNetwork) {
		t.Fatalf("by default an unreachable IAM fails the start: %v", err)
	}
	cfg.TolerateStartupFailure = true
	v, err := iam.NewVerifier(ctx, cfg)
	if err != nil {
		t.Fatalf("TolerateStartupFailure: %v", err)
	}
	clock := newClock()
	hooks.SetClock(v, clock.Now)
	token := iss.ServiceToken(orders, svcID, "order.read")
	if _, err := v.Verify(ctx, token, readRule); !errors.Is(err, iam.ErrUnavailable) {
		t.Fatalf("without any key the answer must be unavailable: %v", err)
	}
	iss.SetDown(false)
	clock.Advance(31 * time.Second)
	if _, err := v.Verify(ctx, token, readRule); err != nil {
		t.Fatalf("once IAM is reachable: %v", err)
	}
}

// BASE-01 / BASE-02 / CFG: configuration is validated at construction and
// the error names the field.
func TestVerifierConfiguration(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	base := iam.VerifierConfig{Issuer: iss.URL(), Audience: orders, HTTPClient: iss.HTTPClient()}
	for field, mutate := range map[string]func(*iam.VerifierConfig){
		"Issuer":   func(c *iam.VerifierConfig) { c.Issuer = "" },
		"Audience": func(c *iam.VerifierConfig) { c.Audience = "" },
		"Leeway":   func(c *iam.VerifierConfig) { c.Leeway = 2 * time.Minute },
		"Introspection.ClientID": func(c *iam.VerifierConfig) {
			c.Introspection = &iam.IntrospectionConfig{Credential: iam.ClientSecret("x")}
		},
		"Introspection.Credential": func(c *iam.VerifierConfig) {
			c.Introspection = &iam.IntrospectionConfig{ClientID: svcID, Credential: iam.ClientSecret("")}
		},
	} {
		cfg := base
		mutate(&cfg)
		_, err := iam.NewVerifier(ctx, cfg)
		var ce *iam.ConfigError
		if !errors.As(err, &ce) || ce.Field != field || !errors.Is(err, iam.ErrConfig) {
			t.Fatalf("%s: %v", field, err)
		}
	}
	// The issuer is compared character by character, never normalised.
	for _, issuer := range []string{iss.URL() + "/", strings.ToUpper(iss.URL()[:5]) + iss.URL()[5:]} {
		cfg := base
		cfg.Issuer = issuer
		if _, err := iam.NewVerifier(ctx, cfg); !errors.Is(err, iam.ErrConfig) {
			t.Fatalf("issuer %q must not match the discovery document: %v", issuer, err)
		}
	}
	// http issuers are refused unless explicitly allowed.
	cfg := base
	cfg.Issuer = "http://iam.example.test"
	var ce *iam.ConfigError
	if _, err := iam.NewVerifier(ctx, cfg); !errors.As(err, &ce) || ce.Field != "Issuer" {
		t.Fatalf("http issuer: %v", err)
	}
	for _, issuer := range []string{"iam.example.test", "https://iam.example.test?x=1", "https://user@iam.example.test", "ftp://iam.example.test"} {
		cfg.Issuer = issuer
		if _, err := iam.NewVerifier(ctx, cfg); !errors.Is(err, iam.ErrConfig) {
			t.Fatalf("issuer %q: %v", issuer, err)
		}
	}
}

// VERIFY-07: the application's own decision after verification.
func TestAuthorizeHook(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	errBlocked := errors.New("client is suspended")
	var seen *iam.Identity
	v := newVerifier(t, iss, func(c *iam.VerifierConfig) {
		c.Authorize = func(_ context.Context, id *iam.Identity) error {
			seen = id
			if id.ClientID == "svc_blocked" {
				return errBlocked
			}
			return nil
		}
	})
	if _, err := v.Verify(ctx, iss.ServiceToken(orders, svcID, "order.read"), readRule); err != nil || seen == nil || seen.ClientID != svcID {
		t.Fatalf("allowed caller: %v", err)
	}
	_, err := v.Verify(ctx, iss.ServiceToken(orders, "svc_blocked", "order.read"), readRule)
	if !errors.Is(err, iam.ErrDenied) || !errors.Is(err, errBlocked) {
		t.Fatalf("blocked caller: %v", err)
	}
	// The application's refusal is neither invalid_token nor insufficient_scope.
	var be *iam.BearerError
	if errors.As(err, &be) || errors.Is(err, iam.ErrInvalidToken) || errors.Is(err, iam.ErrInsufficientScope) {
		t.Fatalf("a business refusal must not look like a token error: %v", err)
	}
	// The hook only ever sees callers whose token passed every check.
	seen = nil
	if _, err := v.Verify(ctx, iss.ServiceToken(orders, "svc_blocked", "order.read"), writeRule); !errors.Is(err, iam.ErrInsufficientScope) || seen != nil {
		t.Fatalf("hook ran before the rule was checked: %v", err)
	}
}

// VERIFY-08: optional introspection.
func TestIntrospection(t *testing.T) {
	iss := serviceIssuer(t)
	iss.AddServiceClient(iamtest.ServiceClient{ID: "svc_orders_rs", Secrets: []string{"ssk_rs_secret"}})
	iss.AllowIntrospection("svc_orders_rs", orders)
	clock := newClock()
	v := newVerifier(t, iss, func(c *iam.VerifierConfig) {
		c.Introspection = &iam.IntrospectionConfig{ClientID: "svc_orders_rs", Credential: iam.ClientSecret("ssk_rs_secret")}
	})
	hooks.SetClock(v, clock.Now)
	caller := newCaller(t, iss)
	target := iam.Target{Resource: orders, Scopes: []string{"order.read"}}
	token, err := caller.Token(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	strict := readRule
	strict.Introspect = true

	// Off by default: a rule that does not ask for it never contacts IAM.
	if _, err := v.Verify(ctx, token, readRule); err != nil || iss.Requests(iamtest.PathIntrospect) != 0 {
		t.Fatalf("plain rule: %v, %d introspections", err, iss.Requests(iamtest.PathIntrospect))
	}
	// On: the answer is cached for a short time.
	for i := 0; i < 5; i++ {
		if _, err := v.Verify(ctx, token, strict); err != nil {
			t.Fatal(err)
		}
	}
	if n := iss.Requests(iamtest.PathIntrospect); n != 1 {
		t.Fatalf("%d introspection requests for 5 validations, want 1 (cached)", n)
	}
	// Permissions and principal type are still checked.
	lax := writeRule
	lax.Introspect = true
	if _, err := v.Verify(ctx, token, lax); !errors.Is(err, iam.ErrInsufficientScope) {
		t.Fatalf("introspection must not replace checks 7 and 8: %v", err)
	}
	// The caller revokes its token: offline validation cannot see it,
	// introspection does once the cached answer has aged out.
	if err := caller.Revoke(ctx, target); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, token, readRule); err != nil {
		t.Fatalf("offline validation does not see revocation: %v", err)
	}
	clock.Advance(31 * time.Second)
	if _, err := v.Verify(ctx, token, strict); !errors.Is(err, iam.ErrInvalidToken) {
		t.Fatalf("revoked token with introspection: %v", err)
	}
	// Introspection unreachable: fail closed with "unavailable".
	fresh, err := caller.Token(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	iss.SetDown(true)
	if _, err := v.Verify(ctx, fresh, strict); !errors.Is(err, iam.ErrUnavailable) {
		t.Fatalf("introspection down: %v", err)
	}
	if _, err := v.Verify(ctx, fresh, readRule); err != nil {
		t.Fatalf("endpoints without introspection keep working: %v", err)
	}
	iss.SetDown(false)
	// A rule asking for introspection without configuration is refused.
	plain := newVerifier(t, iss)
	if _, err := plain.Verify(ctx, fresh, strict); !errors.Is(err, iam.ErrUnavailable) {
		t.Fatalf("introspection not configured: %v", err)
	}
}

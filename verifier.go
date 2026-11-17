package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	maxLeeway     = 60 * time.Second
	maxTokenBytes = 16 * 1024
)

// VerifierConfig configures the provider side: an application that receives
// access tokens issued by IAM. Only Issuer and Audience are required.
type VerifierConfig struct {
	// Issuer is the IAM issuer. It must be identical, character by
	// character, to the issuer of the discovery document and to the iss
	// claim of every token. Required.
	Issuer string
	// Audience is this application's resource identifier, exactly as shown
	// on its page in the IAM console. The SDK never derives it. Required.
	Audience string
	// Leeway is the tolerated clock difference for exp and iat. Zero means
	// the default of 60 seconds, which is also the maximum.
	Leeway time.Duration
	// Authorize, when set, runs after a token passed every check, with the
	// verified caller. Returning an error refuses the request; this is the
	// place for a temporary block by client ID and similar decisions. The
	// refusal is reported as ErrDenied wrapping the returned error, never as
	// invalid_token or insufficient_scope.
	Authorize func(ctx context.Context, caller *Identity) error
	// Introspection enables the optional introspection of tokens for rules
	// that ask for it (Rule.Introspect). Off by default.
	Introspection *IntrospectionConfig
	// HTTPClient is used to reach IAM. Nil means a client with a 10 second
	// timeout. Replace it for proxies, custom CAs, tracing, or to resolve
	// the issuer's host to a cluster-internal address.
	HTTPClient *http.Client
	// Logger receives diagnostics. Nil disables logging. Tokens and
	// credentials are never logged.
	Logger *slog.Logger
	// AllowInsecureIssuer permits an http:// issuer. For integration
	// environments only.
	AllowInsecureIssuer bool
	// TolerateStartupFailure makes NewVerifier succeed when IAM cannot be
	// reached at startup; discovery and the key download are then retried
	// on use, and requests are answered with ErrUnavailable until the keys
	// are there. Invalid configuration still fails immediately.
	TolerateStartupFailure bool
}

// Rule is the access requirement of one protected endpoint. Both parts must
// be declared explicitly; a rule that lacks either refuses every request.
type Rule struct {
	// Scopes are the permission codes the token must carry, all of them.
	// Whole codes are compared; there is no prefix or wildcard matching.
	Scopes []string
	// Principals are the accepted principal types: PrincipalService,
	// PrincipalUser, or both.
	Principals []string
	// Introspect additionally asks IAM whether the token is still active,
	// which is the only way to notice a token its owner revoked. Requires
	// VerifierConfig.Introspection.
	Introspect bool
}

// declared reports whether the rule states both requirements.
func (r Rule) declared() bool {
	if len(r.Scopes) == 0 || len(r.Principals) == 0 {
		return false
	}
	for _, s := range r.Scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n") {
			return false
		}
	}
	for _, p := range r.Principals {
		if p != PrincipalService && p != PrincipalUser {
			return false
		}
	}
	return true
}

// Identity is the verified caller of a request: the content of an access
// token that passed every check. Look at PrincipalType before interpreting
// Subject.
type Identity struct {
	// Issuer is the IAM issuer that signed the token.
	Issuer string
	// Subject is the client ID of the calling system for a system token, or
	// the user ID for a user-delegated token.
	Subject string
	// ClientID is the client the token was issued to: the service credential
	// of the calling system, or the OIDC application acting for the user.
	ClientID string
	// PrincipalType is PrincipalService or PrincipalUser.
	PrincipalType string
	// Scopes are the permission codes carried by the token.
	Scopes []string
	// TokenID is the jti claim, for audit logs.
	TokenID string
	// Audience is the resource identifier the token was issued for.
	Audience string
	// IssuedAt and ExpiresAt delimit the lifetime of the token.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// SessionID is the user's IAM session (sid). User-delegated tokens only.
	SessionID string
	// AuthTime is when the user authenticated. User-delegated tokens only.
	AuthTime time.Time
}

// HasScope reports whether the token carries the permission code.
func (i *Identity) HasScope(scope string) bool { return slices.Contains(i.Scopes, scope) }

// IsUser reports whether the caller is a user (a user-delegated token).
func (i *Identity) IsUser() bool { return i.PrincipalType == PrincipalUser }

// IsService reports whether the caller is a system acting as itself.
func (i *Identity) IsService() bool { return i.PrincipalType == PrincipalService }

// Verifier validates inbound access tokens offline, with cached signing
// keys, as laid down in the Token Validation Specification.
type Verifier struct {
	p         *provider
	audience  string
	leeway    time.Duration
	authorize func(context.Context, *Identity) error
	intro     *introspector
}

// NewVerifier validates the configuration, reads the discovery document and
// downloads the signing keys.
func NewVerifier(ctx context.Context, cfg VerifierConfig) (*Verifier, error) {
	p, err := newProvider(commonConfig{issuer: cfg.Issuer, insecure: cfg.AllowInsecureIssuer, hc: cfg.HTTPClient, log: cfg.Logger})
	if err != nil {
		return nil, err
	}
	if cfg.Audience == "" {
		return nil, configError("Audience", "is required: the resource identifier of this application")
	}
	leeway, err := checkLeeway(cfg.Leeway)
	if err != nil {
		return nil, err
	}
	v := &Verifier{p: p, audience: cfg.Audience, leeway: leeway, authorize: cfg.Authorize}
	if cfg.Introspection != nil {
		if v.intro, err = newIntrospector(ctx, p, cfg.Introspection); err != nil {
			return nil, err
		}
	}
	if err := p.start(ctx, true, cfg.TolerateStartupFailure); err != nil {
		return nil, err
	}
	return v, nil
}

func checkLeeway(d time.Duration) (time.Duration, error) {
	switch {
	case d == 0:
		return maxLeeway, nil
	case d < 0 || d > maxLeeway:
		return 0, configError("Leeway", "must be between 0 and 60 seconds")
	}
	return d, nil
}

// Audience returns the configured resource identifier of this application.
func (v *Verifier) Audience() string { return v.audience }

// VerifyHeader verifies the token of an Authorization header value (HTTP) or
// of the authorization metadata (gRPC). A missing header, another scheme or
// an empty token is ErrNoToken. Tokens are only ever read from this header.
func (v *Verifier) VerifyHeader(ctx context.Context, authorization string, rule Rule) (*Identity, error) {
	scheme, token, _ := strings.Cut(strings.TrimSpace(authorization), " ")
	token = strings.TrimSpace(token)
	if !strings.EqualFold(scheme, "Bearer") || token == "" {
		return nil, noToken(v.audience)
	}
	return v.Verify(ctx, token, rule)
}

// Verify checks an access token against the access rule of an endpoint and
// returns the caller's identity. It does not depend on HTTP or gRPC.
//
// The checks run in the order of the specification. Checks 1 to 6 decide
// whether the token is valid here; a failure is ErrInvalidToken (401).
// Checks 7 and 8 decide whether this valid token may use the endpoint; a
// failure is ErrInsufficientScope (403). When no signing key is available
// at all the result is ErrUnavailable (503). All three are reported as
// *BearerError.
func (v *Verifier) Verify(ctx context.Context, token string, rule Rule) (*Identity, error) {
	if token == "" {
		return nil, noToken(v.audience)
	}
	if len(token) > maxTokenBytes {
		return nil, v.invalid("token too large")
	}
	// 1. alg: a compact JWS signed with RS256. The accepted algorithm is
	// fixed here, never taken from the token.
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(jws.Signatures) != 1 {
		return nil, v.invalid("not a JWT signed with RS256")
	}
	header := jws.Signatures[0].Protected
	// 2. typ: an access token. This refuses ID tokens, whose typ is JWT.
	typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
	if !strings.EqualFold(typ, "at+jwt") && !strings.EqualFold(typ, "application/at+jwt") {
		return nil, v.invalid("typ is not at+jwt")
	}
	// 3. signature and kid, with a key of the configured issuer.
	if header.KeyID == "" {
		return nil, v.invalid("kid missing")
	}
	key, err := v.p.keys.key(ctx, header.KeyID)
	switch {
	case errors.Is(err, errKeyNotFound):
		return nil, v.invalid("signing key not found")
	case errors.Is(err, ErrUnavailable):
		return nil, unavailable(v.audience, "the signing keys of the issuer are not available")
	case err != nil:
		return nil, err
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, v.invalid("signature invalid")
	}
	var c accessClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, v.invalid("claims malformed")
	}
	// 4. iss, compared character by character.
	if c.Iss != v.p.issuer {
		return nil, v.invalid("issuer mismatch")
	}
	// 5. aud: one string, equal to this application's resource identifier.
	// An array is refused even when it contains the identifier.
	var aud string
	if json.Unmarshal(c.Aud, &aud) != nil || aud != v.audience {
		return nil, v.invalid("audience is not this resource")
	}
	// 6. exp and iat, both required.
	now := v.p.clock()
	if c.Exp == nil || *c.Exp <= 0 || now.After(unixTime(*c.Exp).Add(v.leeway)) {
		return nil, v.invalid("token expired")
	}
	if c.Iat == nil || *c.Iat <= 0 || unixTime(*c.Iat).After(now.Add(v.leeway)) {
		return nil, v.invalid("token issued in the future")
	}
	if c.Nbf != nil && unixTime(*c.Nbf).After(now.Add(v.leeway)) {
		return nil, v.invalid("token not yet valid")
	}
	id := &Identity{
		Issuer: c.Iss, Subject: c.Sub, ClientID: c.ClientID, PrincipalType: c.PrincipalType,
		Scopes: splitScope(c.Scope), TokenID: c.JTI, Audience: aud,
		IssuedAt: unixTime(*c.Iat), ExpiresAt: unixTime(*c.Exp), SessionID: c.SID,
	}
	if c.AuthTime != nil {
		id.AuthTime = unixTime(*c.AuthTime)
	}
	// Optional: ask IAM whether the token was revoked. This is still about
	// the validity of the token, so it precedes checks 7 and 8.
	if rule.Introspect {
		if v.intro == nil {
			v.p.log.ErrorContext(ctx, "iam: a rule asks for introspection but VerifierConfig.Introspection is not set; refusing the request")
			return nil, unavailable(v.audience, "introspection is not configured")
		}
		active, err := v.intro.active(ctx, token, id)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			v.p.log.WarnContext(ctx, "iam: introspection failed; refusing the request", "error", err.Error())
			return nil, unavailable(v.audience, "introspection is not available")
		}
		if !active {
			return nil, v.invalid("token is not active")
		}
	}
	required := strings.Join(rule.Scopes, " ")
	// Default deny: an endpoint without a complete rule is closed.
	if !rule.declared() {
		v.p.log.ErrorContext(ctx, "iam: a protected endpoint has no complete access rule (scopes and principal types); refusing the request")
		return nil, insufficientScope(v.audience, "no access rule is declared for this endpoint", "")
	}
	// 7. scope: every required permission, compared as a whole code.
	for _, need := range rule.Scopes {
		if !id.HasScope(need) {
			return nil, insufficientScope(v.audience, "the token lacks "+need, required)
		}
	}
	// 8. principal_type: one the endpoint accepts.
	if !slices.Contains(rule.Principals, id.PrincipalType) {
		return nil, insufficientScope(v.audience, "this endpoint does not accept "+printable(id.PrincipalType)+" tokens", required)
	}
	// From here on the token content is fact. What follows is the
	// application's own decision, reported with its own error.
	if v.authorize != nil {
		if err := v.authorize(ctx, id); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrDenied, err)
		}
	}
	return id, nil
}

func (v *Verifier) invalid(description string) *BearerError {
	return invalidToken(v.audience, description)
}

// accessClaims are the claims of an access token (specification 5.1).
type accessClaims struct {
	Iss           string          `json:"iss"`
	Sub           string          `json:"sub"`
	Aud           json.RawMessage `json:"aud"`
	Exp           *float64        `json:"exp"`
	Iat           *float64        `json:"iat"`
	Nbf           *float64        `json:"nbf"`
	JTI           string          `json:"jti"`
	ClientID      string          `json:"client_id"`
	Scope         string          `json:"scope"`
	PrincipalType string          `json:"principal_type"`
	SID           string          `json:"sid"`
	AuthTime      *float64        `json:"auth_time"`
}

func unixTime(seconds float64) time.Time {
	return time.Unix(int64(seconds), 0)
}

// printable keeps a claim value that ends up in an error description short
// and harmless.
func printable(s string) string {
	if s == "" {
		return "untyped"
	}
	if len(s) > 32 {
		s = s[:32]
	}
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, s)
}

type identityKey struct{}

// ContextWithIdentity returns a context carrying the verified caller. The
// adapters call it before invoking the application's handler.
func ContextWithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFromContext returns the verified caller stored by an adapter, or
// nil when the request did not pass a Verifier.
func IdentityFromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey{}).(*Identity)
	return id
}

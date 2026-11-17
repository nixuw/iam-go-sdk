package iam

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Error categories. Use errors.Is to test for a category and errors.As to
// reach the detailed error types.
var (
	// ErrConfig reports an incomplete or invalid configuration. The concrete
	// error is a *ConfigError naming the offending field.
	ErrConfig = errors.New("iam: invalid configuration")
	// ErrNetwork reports that IAM could not be reached (connection failure,
	// timeout, or a response that is not an IAM protocol response).
	ErrNetwork = errors.New("iam: IAM is unreachable")
	// ErrNoToken reports a request without a bearer token.
	ErrNoToken = errors.New("iam: no bearer token")
	// ErrInvalidToken reports a token that is not valid here (checks 1 to 6
	// of the specification, or a failed ID token validation).
	ErrInvalidToken = errors.New("iam: invalid token")
	// ErrInsufficientScope reports a valid token that may not use the
	// endpoint: a required permission is missing or the principal type is
	// not accepted (checks 7 and 8).
	ErrInsufficientScope = errors.New("iam: insufficient scope")
	// ErrUnavailable reports that tokens cannot be verified right now, for
	// example because no signing key could be obtained from IAM yet. It is
	// not a statement about the token.
	ErrUnavailable = errors.New("iam: token verification unavailable")
	// ErrDenied reports that the application's own check after token
	// verification (VerifierConfig.Authorize) refused the caller.
	ErrDenied = errors.New("iam: denied by the application")
	// ErrInvalidCallback reports an authorization response that must not be
	// trusted: unknown or mismatching state, wrong iss, missing code.
	ErrInvalidCallback = errors.New("iam: invalid authorization response")
	// ErrLoginRequired reports that there is no valid local session.
	ErrLoginRequired = errors.New("iam: login required")
	// ErrInsecureTransport reports an attempt to send a token over a
	// plaintext connection without CallerConfig.AllowInsecureTransport.
	ErrInsecureTransport = errors.New("iam: refusing to send a token over a plaintext connection")
	// ErrTargetMismatch reports a request made with a target-bound client to
	// an address outside Target.BaseURL.
	ErrTargetMismatch = errors.New("iam: request is not addressed to the bound target")
)

// ConfigError describes one invalid configuration field.
type ConfigError struct {
	// Field is the name of the configuration field, e.g. "Issuer".
	Field string
	// Reason says what is wrong with it. It never contains secret values.
	Reason string
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return "iam: invalid configuration: " + e.Field + ": " + e.Reason
}

// Is reports whether target is ErrConfig.
func (e *ConfigError) Is(target error) bool { return target == ErrConfig }

func configError(field, reason string) *ConfigError {
	return &ConfigError{Field: field, Reason: reason}
}

// OAuthError is a protocol error returned by IAM: the JSON error of the
// token, revocation or introspection endpoint, or the error parameters of an
// authorization response.
type OAuthError struct {
	// Code is the value of "error", e.g. invalid_target.
	Code string
	// Description is the value of "error_description".
	Description string
	// StatusCode is the HTTP status of the response; 0 for an error carried
	// by an authorization response (redirect).
	StatusCode int
	// RequestID is the X-Request-ID response header: the trace ID under
	// which an IAM administrator finds this request.
	RequestID string
	// RetryAfter is the Retry-After response header; 0 when absent.
	RetryAfter time.Duration
}

// Error implements the error interface.
func (e *OAuthError) Error() string {
	var b strings.Builder
	b.WriteString("iam: ")
	if e.Code != "" {
		b.WriteString(e.Code)
	} else {
		b.WriteString("unexpected response")
	}
	if e.Description != "" {
		b.WriteString(": ")
		b.WriteString(e.Description)
	}
	if e.StatusCode != 0 {
		b.WriteString(" (HTTP ")
		b.WriteString(strconv.Itoa(e.StatusCode))
		b.WriteString(")")
	}
	if e.RequestID != "" {
		b.WriteString(" [request id ")
		b.WriteString(e.RequestID)
		b.WriteString("]")
	}
	return b.String()
}

// Temporary reports whether repeating the same request later can succeed
// without any change on the caller's side (HTTP 429 and 5xx).
func (e *OAuthError) Temporary() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

// NetworkError wraps a failure to reach IAM.
type NetworkError struct {
	// Op names what was being done, e.g. "discovery" or "token request".
	Op string
	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *NetworkError) Error() string { return "iam: " + e.Op + ": " + e.Err.Error() }

// Unwrap returns the underlying error.
func (e *NetworkError) Unwrap() error { return e.Err }

// Is reports whether target is ErrNetwork.
func (e *NetworkError) Is(target error) bool { return target == ErrNetwork }

// OAuth error codes used with BearerError.Code (RFC 6750).
const (
	codeInvalidToken      = "invalid_token"
	codeInsufficientScope = "insufficient_scope"
	codeUnavailable       = "temporarily_unavailable"
)

// BearerError is the RFC 6750 outcome of an access token check. A Verifier
// returns it for a request it refuses; an outbound client bound to a target
// returns it when the target refused the token it was sent.
type BearerError struct {
	// Status is the HTTP status: 401, 403 or 503.
	Status int
	// Code is "invalid_token", "insufficient_scope",
	// "temporarily_unavailable" (503), or empty when the request carried no
	// token at all.
	Code string
	// Description explains which check failed. It never contains token
	// content.
	Description string
	// Scope lists, space separated, the permissions the endpoint requires
	// (only with insufficient_scope).
	Scope string
	// Realm is the resource identifier of the application that refused.
	Realm string
}

// Error implements the error interface.
func (e *BearerError) Error() string {
	switch {
	case e.Code == "":
		return "iam: no bearer token"
	case e.Description == "":
		return "iam: " + e.Code
	default:
		return "iam: " + e.Code + ": " + e.Description
	}
}

// Is maps the error to ErrNoToken, ErrInvalidToken, ErrInsufficientScope or
// ErrUnavailable.
func (e *BearerError) Is(target error) bool {
	switch target {
	case ErrNoToken:
		return e.Code == ""
	case ErrInvalidToken:
		return e.Code == codeInvalidToken
	case ErrInsufficientScope:
		return e.Code == codeInsufficientScope
	case ErrUnavailable:
		return e.Code == codeUnavailable
	}
	return false
}

// WWWAuthenticate returns the value of the WWW-Authenticate response header
// for this error. It is empty for a 503, which is not an authentication
// failure.
func (e *BearerError) WWWAuthenticate() string {
	if e.Status != http.StatusUnauthorized && e.Status != http.StatusForbidden {
		return ""
	}
	var b strings.Builder
	b.WriteString(`Bearer realm=`)
	b.WriteString(quoteParam(e.Realm))
	if e.Code != "" {
		b.WriteString(`, error=`)
		b.WriteString(quoteParam(e.Code))
		if e.Description != "" {
			b.WriteString(`, error_description=`)
			b.WriteString(quoteParam(e.Description))
		}
	}
	if e.Scope != "" {
		b.WriteString(`, scope=`)
		b.WriteString(quoteParam(e.Scope))
	}
	return b.String()
}

// quoteParam renders s as an HTTP quoted-string. Control characters and
// non-ASCII bytes are dropped: RFC 6750 restricts the values to printable
// ASCII.
func quoteParam(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func noToken(realm string) *BearerError {
	return &BearerError{Status: http.StatusUnauthorized, Realm: realm}
}

func invalidToken(realm, description string) *BearerError {
	return &BearerError{Status: http.StatusUnauthorized, Code: codeInvalidToken, Description: description, Realm: realm}
}

func insufficientScope(realm, description, scope string) *BearerError {
	return &BearerError{Status: http.StatusForbidden, Code: codeInsufficientScope, Description: description, Scope: scope, Realm: realm}
}

func unavailable(realm, description string) *BearerError {
	return &BearerError{Status: http.StatusServiceUnavailable, Code: codeUnavailable, Description: description, Realm: realm}
}

// transient reports whether err is worth retrying with back-off: IAM was
// unreachable or answered 5xx. A 429 is not included: it carries its own
// waiting time.
func transient(err error) bool {
	if errors.Is(err, ErrNetwork) {
		return true
	}
	var oe *OAuthError
	return errors.As(err, &oe) && oe.StatusCode >= 500
}

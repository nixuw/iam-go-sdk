// Package iam is the Go SDK for integrating a business application with IAM.
//
// It covers the three integration scenarios, each with its own constructor:
//
//   - NewLogin: OpenID Connect sign-in for a web backend (authorization code
//     with PKCE, ID token validation, local session, refresh, logout).
//   - NewCaller: system tokens for calling other applications (client
//     credentials with a resource indicator, caching, renewal, back-off) and
//     outbound clients that attach them.
//   - NewVerifier: validation of inbound access tokens according to the
//     Token Validation Specification (see SpecVersion), per-endpoint access
//     rules and RFC 6750 errors.
//
// The package itself depends on no web framework and not on gRPC. Thin
// adapters live in sub-packages: iamfiber (Fiber v2), iamhttp (net/http and
// compatible routers) and iamgrpc. Package iamtest provides a local fake
// issuer for unit tests.
//
// # Configuration
//
// Every value comes from the application: the SDK has no built-in issuer,
// client ID, credential or resource identifier, and it reads neither
// environment variables nor files. Endpoints are never configured; they are
// taken from the issuer's discovery document.
//
// # Errors
//
// Errors are returned, never panicked, and can be classified with errors.Is
// and errors.As:
//
//   - ErrConfig (*ConfigError): the configuration is incomplete or invalid.
//   - *OAuthError: IAM answered with a protocol error.
//   - ErrNetwork (*NetworkError): IAM could not be reached.
//   - ErrNoToken, ErrInvalidToken, ErrInsufficientScope, ErrUnavailable
//     (*BearerError): the outcome of verifying an access token, or what a
//     target application answered to an outbound call.
//
// # Concurrency
//
// There is no global state. Any number of instances may coexist in a process
// and every exported method is safe for concurrent use.
package iam

// Version is the version of this SDK.
const Version = "1.0.0"

// SpecVersion is the version of the Token Validation Specification
// (《Token 验证规范》) that the Verifier and the adapters implement.
const SpecVersion = "1.1"

// Principal types carried by the principal_type claim of an access token.
// Always look at the principal type before interpreting the subject.
const (
	// PrincipalService marks a system token: the caller is an application
	// acting as itself; the subject is its client ID.
	PrincipalService = "service"
	// PrincipalUser marks a user-delegated token: the subject is a user ID
	// and ClientID is the application acting on the user's behalf.
	PrincipalUser = "user"
)

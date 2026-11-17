// Package iamhttp adapts the IAM SDK to net/http. Its handlers and
// middleware work with the standard library's ServeMux and with every router
// built on http.Handler, such as chi, Gin (gin.WrapH) and Echo
// (echo.WrapHandler, echo.WrapMiddleware).
//
// User sign-in:
//
//	auth := iamhttp.Login(login)
//	mux.HandleFunc("GET /login", auth.Start)
//	mux.HandleFunc("GET /callback", auth.Callback)
//	mux.HandleFunc("GET /logout", auth.Logout)
//	mux.Handle("GET /profile", auth.Require()(profile)) // iamhttp.User(r)
//
// Provider side:
//
//	guard := iamhttp.Guard(verifier)
//	mux.Handle("GET /api/orders/{id}", guard.Require(iam.Rule{
//		Scopes:     []string{"order.read"},
//		Principals: []string{iam.PrincipalService, iam.PrincipalUser},
//	})(getOrder)) // iamhttp.Caller(r)
//
// The caller side needs no adapter: (*iam.Caller).HTTPClient is a standard
// *http.Client.
package iamhttp

import (
	"encoding/json"
	"errors"
	"net/http"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/internal/webflow"
)

// ErrorHandler writes the response for a request the SDK refused.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Option customises Login or Guard.
type Option func(*options)

type options struct {
	loginPath string
	onError   ErrorHandler
}

// WithLoginPath tells the Require middleware of Login where the Start
// handler is mounted. The default is "/login".
func WithLoginPath(path string) Option {
	return func(o *options) { o.loginPath = path }
}

// WithErrorHandler replaces the default error response.
//
// For Login, the handler is called when a sign-in request fails, including
// error responses of IAM such as access_denied, login_required and
// consent_required (as *iam.OAuthError): show a page or fall back as the
// application sees fit.
//
// For Guard, the handler is called with a *iam.BearerError (use errors.As)
// when a token was refused: it chooses the format of the body, while the
// status and the WWW-Authenticate header required by RFC 6750 are fixed by
// the SDK and cannot be removed. When the application's own Authorize check
// refused the caller, the error matches iam.ErrDenied and the handler
// decides the whole response.
func WithErrorHandler(h ErrorHandler) Option {
	return func(o *options) { o.onError = h }
}

func build(opts []Option) options {
	o := options{loginPath: "/login"}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// LoginHandlers are the HTTP entry points of user sign-in with the built-in
// local session.
type LoginHandlers struct {
	engine webflow.LoginEngine
	opts   options
}

// Login returns the sign-in handlers for l, which must have been created
// with a session key.
func Login(l *iam.Login, opts ...Option) *LoginHandlers {
	return &LoginHandlers{engine: webflow.Engine(l), opts: build(opts)}
}

// Start begins a sign-in: it redirects the browser to IAM. Optional query
// parameters: return_to (a local path to come back to), prompt, max_age and
// login_hint.
func (h *LoginHandlers) Start(w http.ResponseWriter, r *http.Request) {
	h.write(w, r, h.engine.Start(r.Context(), request(r)))
}

// Callback handles the redirect back from IAM. Mount it on the path of the
// registered callback address. It validates the response, redeems the code,
// validates the ID token, creates the local session and returns to the page
// the sign-in started from.
func (h *LoginHandlers) Callback(w http.ResponseWriter, r *http.Request) {
	h.write(w, r, h.engine.Callback(r.Context(), request(r)))
}

// Logout ends the local session, revokes the refresh token and redirects to
// IAM's logout endpoint.
func (h *LoginHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	h.write(w, r, h.engine.Logout(r.Context(), request(r)))
}

// Require returns middleware that only lets signed-in users through. A page
// request without a session is redirected to the login path and comes back
// afterwards; an API request gets 401 and no redirect. Handlers behind it
// read the user with User.
func (h *LoginHandlers) Require() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, refuse := h.engine.Authenticate(r.Context(), request(r), h.opts.loginPath)
			if refuse != nil {
				h.write(w, r, refuse)
				return
			}
			next.ServeHTTP(w, r.WithContext(iam.ContextWithUser(r.Context(), user.(*iam.User))))
		})
	}
}

// User returns the signed-in user of a request that passed Require, or nil.
func User(r *http.Request) *iam.User { return iam.UserFromContext(r.Context()) }

func (h *LoginHandlers) write(w http.ResponseWriter, r *http.Request, res *webflow.Response) {
	w.Header().Set("Cache-Control", "no-store")
	for _, c := range res.Cookies {
		http.SetCookie(w, c)
	}
	switch {
	case res.Err != nil && h.opts.onError != nil:
		h.opts.onError(w, r, res.Err)
	case res.Err != nil:
		writeJSON(w, res.Status, res.Code, res.Description)
	case res.Location != "":
		http.Redirect(w, r, res.Location, res.Status)
	default:
		w.WriteHeader(res.Status)
	}
}

// GuardMiddleware protects provider endpoints with access rules.
type GuardMiddleware struct {
	verifier *iam.Verifier
	opts     options
}

// Guard returns the provider-side middleware factory for v.
func Guard(v *iam.Verifier, opts ...Option) *GuardMiddleware {
	return &GuardMiddleware{verifier: v, opts: build(opts)}
}

// Require returns middleware that verifies the bearer token of every request
// against rule before the handler runs. The token is read from the
// Authorization header only. Refused requests get the RFC 6750 response:
//
//   - no token: 401, WWW-Authenticate with realm only
//   - invalid token: 401 invalid_token
//   - missing permission or principal type not accepted: 403
//     insufficient_scope, with the required scope
//   - no signing key available: 503
//
// A rule that does not declare both permissions and principal types refuses
// every request. Handlers behind it read the caller with Caller.
func (g *GuardMiddleware) Require(rule iam.Rule) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := g.verifier.VerifyHeader(r.Context(), r.Header.Get("Authorization"), rule)
			if err != nil {
				g.refuse(w, r, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(iam.ContextWithIdentity(r.Context(), id)))
		})
	}
}

// Caller returns the verified caller of a request that passed Require, or
// nil.
func Caller(r *http.Request) *iam.Identity { return iam.IdentityFromContext(r.Context()) }

func (g *GuardMiddleware) refuse(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Cache-Control", "no-store")
	var be *iam.BearerError
	if !errors.As(err, &be) {
		switch {
		case g.opts.onError != nil && errors.Is(err, iam.ErrDenied):
			g.opts.onError(w, r, err)
		case errors.Is(err, iam.ErrDenied):
			writeJSON(w, http.StatusForbidden, "access_denied", "the application refused this caller")
		default:
			// The check itself could not be carried out (request cancelled).
			writeJSON(w, http.StatusServiceUnavailable, "temporarily_unavailable", "the token could not be verified")
		}
		return
	}
	challenge := be.WWWAuthenticate()
	if challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	if be.Status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "30")
	}
	if g.opts.onError != nil {
		// The application formats the body; status and challenge stay.
		fw := &fixedWriter{ResponseWriter: w, status: be.Status, challenge: challenge}
		g.opts.onError(fw, r, err)
		fw.finish()
		return
	}
	if be.Code == "" {
		w.WriteHeader(be.Status)
		return
	}
	writeJSON(w, be.Status, be.Code, be.Description)
}

// fixedWriter lets an application-supplied error handler write the body of
// a bearer error response while the status and the challenge stay as the
// specification demands.
type fixedWriter struct {
	http.ResponseWriter
	status    int
	challenge string
	wrote     bool
}

func (f *fixedWriter) WriteHeader(int) {
	if f.wrote {
		return
	}
	f.wrote = true
	if f.challenge != "" {
		f.Header().Set("WWW-Authenticate", f.challenge)
	}
	f.ResponseWriter.WriteHeader(f.status)
}

func (f *fixedWriter) Write(b []byte) (int, error) {
	f.WriteHeader(f.status)
	return f.ResponseWriter.Write(b)
}

func (f *fixedWriter) finish() { f.WriteHeader(f.status) }

// Unwrap supports http.ResponseController.
func (f *fixedWriter) Unwrap() http.ResponseWriter { return f.ResponseWriter }

func request(r *http.Request) *webflow.Request {
	return &webflow.Request{
		Method: r.Method, Path: r.URL.EscapedPath(), RawQuery: r.URL.RawQuery,
		Header: r.Header.Get,
		Cookie: func(name string) string {
			c, err := r.Cookie(name)
			if err != nil {
				return ""
			}
			return c.Value
		},
	}
}

// writeJSON writes the SDK's default error body: the OAuth error shape.
func writeJSON(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}

// Package iamfiber adapts the IAM SDK to Fiber v2, the framework IAM itself
// is built on.
//
// User sign-in:
//
//	auth := iamfiber.Login(login)
//	app.Get("/login", auth.Start)
//	app.Get("/callback", auth.Callback)
//	app.Get("/logout", auth.Logout)
//	app.Get("/profile", auth.Require(), profile) // iamfiber.User(c)
//
// Provider side:
//
//	guard := iamfiber.Guard(verifier)
//	app.Get("/api/orders/:id", guard.Require(iam.Rule{
//		Scopes:     []string{"order.read"},
//		Principals: []string{iam.PrincipalService, iam.PrincipalUser},
//	}), getOrder) // iamfiber.Caller(c)
//
// The caller side needs no adapter: (*iam.Caller).HTTPClient is a standard
// *http.Client.
package iamfiber

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/internal/webflow"
)

// ErrorHandler writes the response for a request the SDK refused.
type ErrorHandler func(c *fiber.Ctx, err error) error

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

type (
	userKey   struct{}
	callerKey struct{}
)

// LoginHandlers are the Fiber entry points of user sign-in with the built-in
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
func (h *LoginHandlers) Start(c *fiber.Ctx) error {
	return h.write(c, h.engine.Start(c.UserContext(), request(c)))
}

// Callback handles the redirect back from IAM. Mount it on the path of the
// registered callback address. It validates the response, redeems the code,
// validates the ID token, creates the local session and returns to the page
// the sign-in started from.
func (h *LoginHandlers) Callback(c *fiber.Ctx) error {
	return h.write(c, h.engine.Callback(c.UserContext(), request(c)))
}

// Logout ends the local session, revokes the refresh token and redirects to
// IAM's logout endpoint.
func (h *LoginHandlers) Logout(c *fiber.Ctx) error {
	return h.write(c, h.engine.Logout(c.UserContext(), request(c)))
}

// Require returns middleware that only lets signed-in users through. A page
// request without a session is redirected to the login path and comes back
// afterwards; an API request gets 401 and no redirect. Handlers behind it
// read the user with User.
func (h *LoginHandlers) Require() fiber.Handler {
	return func(c *fiber.Ctx) error {
		user, refuse := h.engine.Authenticate(c.UserContext(), request(c), h.opts.loginPath)
		if refuse != nil {
			return h.write(c, refuse)
		}
		u := user.(*iam.User)
		c.Locals(userKey{}, u)
		c.SetUserContext(iam.ContextWithUser(c.UserContext(), u))
		return c.Next()
	}
}

// User returns the signed-in user of a request that passed Require, or nil.
func User(c *fiber.Ctx) *iam.User {
	u, _ := c.Locals(userKey{}).(*iam.User)
	return u
}

func (h *LoginHandlers) write(c *fiber.Ctx, res *webflow.Response) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	for _, ck := range res.Cookies {
		// Fiber's own cookie type has no "delete" notion; the standard
		// library renders the attributes exactly as the SDK set them.
		c.Append(fiber.HeaderSetCookie, ck.String())
	}
	switch {
	case res.Err != nil && h.opts.onError != nil:
		return h.opts.onError(c, res.Err)
	case res.Err != nil:
		return c.Status(res.Status).JSON(fiber.Map{"error": res.Code, "error_description": res.Description})
	case res.Location != "":
		return c.Redirect(res.Location, res.Status)
	default:
		return c.SendStatus(res.Status)
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
func (g *GuardMiddleware) Require(rule iam.Rule) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id, err := g.verifier.VerifyHeader(c.UserContext(), c.Get(fiber.HeaderAuthorization), rule)
		if err != nil {
			return g.refuse(c, err)
		}
		c.Locals(callerKey{}, id)
		c.SetUserContext(iam.ContextWithIdentity(c.UserContext(), id))
		return c.Next()
	}
}

// Caller returns the verified caller of a request that passed Require, or
// nil.
func Caller(c *fiber.Ctx) *iam.Identity {
	id, _ := c.Locals(callerKey{}).(*iam.Identity)
	return id
}

func (g *GuardMiddleware) refuse(c *fiber.Ctx, err error) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	var be *iam.BearerError
	if !errors.As(err, &be) {
		switch {
		case g.opts.onError != nil && errors.Is(err, iam.ErrDenied):
			return g.opts.onError(c, err)
		case errors.Is(err, iam.ErrDenied):
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "access_denied", "error_description": "the application refused this caller"})
		default:
			// The check itself could not be carried out (request cancelled).
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "temporarily_unavailable", "error_description": "the token could not be verified"})
		}
	}
	challenge := be.WWWAuthenticate()
	fix := func() {
		c.Status(be.Status)
		if challenge != "" {
			c.Set(fiber.HeaderWWWAuthenticate, challenge)
		}
		if be.Status == fiber.StatusServiceUnavailable {
			c.Set(fiber.HeaderRetryAfter, "30")
		}
	}
	fix()
	if g.opts.onError != nil {
		// The application formats the body; status and challenge stay.
		herr := g.opts.onError(c, err)
		fix()
		return herr
	}
	if be.Code == "" {
		return nil
	}
	return c.JSON(fiber.Map{"error": be.Code, "error_description": be.Description})
}

// request copies what the sign-in flow reads out of the Fiber context.
// Strings are cloned: Fiber reuses the underlying buffers after the handler
// returns.
func request(c *fiber.Ctx) *webflow.Request {
	return &webflow.Request{
		Method:   strings.Clone(c.Method()),
		Path:     strings.Clone(string(c.Request().URI().PathOriginal())),
		RawQuery: strings.Clone(string(c.Request().URI().QueryString())),
		Header:   func(name string) string { return strings.Clone(c.Get(name)) },
		Cookie:   func(name string) string { return strings.Clone(c.Cookies(name)) },
	}
}

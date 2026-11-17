package iamfiber_test

import (
	"net"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamfiber"
	"github.com/nixuw/iam-go-sdk/internal/adaptertest"
)

func serve(t *testing.T, ln net.Listener, app *fiber.App) {
	go func() { _ = app.Listener(ln) }()
	// A bounded shutdown: connections the test's HTTP client opened but never
	// used would otherwise keep a graceful shutdown waiting.
	t.Cleanup(func() { _ = app.ShutdownWithTimeout(time.Second) })
}

func custom(onError func(error)) iamfiber.Option {
	return iamfiber.WithErrorHandler(func(c *fiber.Ctx, err error) error {
		onError(err)
		return c.Status(fiber.StatusTeapot).SendString("custom")
	})
}

func TestLogin(t *testing.T) {
	adaptertest.Login(t, func(t *testing.T, ln net.Listener, routes adaptertest.LoginRoutes) {
		var opts []iamfiber.Option
		if routes.Custom {
			opts = append(opts, custom(routes.OnError))
		}
		auth := iamfiber.Login(routes.Login, opts...)
		me := func(c *fiber.Ctx) error {
			if iam.UserFromContext(c.UserContext()) != iamfiber.User(c) {
				t.Error("the user must also be in the request context")
			}
			c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			return c.Send(adaptertest.UserJSON(iamfiber.User(c)))
		}
		app := fiber.New(fiber.Config{DisableStartupMessage: true})
		app.Get("/login", auth.Start)
		app.Get("/callback", auth.Callback)
		app.Get("/logout", auth.Logout)
		app.All("/profile", auth.Require(), me)
		app.All("/api/me", auth.Require(), me)
		app.Get("/bye", func(c *fiber.Ctx) error { return c.SendString("bye") })
		serve(t, ln, app)
	})
}

func TestGuard(t *testing.T) {
	adaptertest.Guard(t, func(t *testing.T, ln net.Listener, routes adaptertest.GuardRoutes) {
		var opts []iamfiber.Option
		if routes.Custom {
			opts = append(opts, custom(routes.OnError))
		}
		guard := iamfiber.Guard(routes.Verifier, opts...)
		who := func(c *fiber.Ctx) error {
			if iam.IdentityFromContext(c.UserContext()) != iamfiber.Caller(c) {
				t.Error("the caller must also be in the request context")
			}
			c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			return c.Send(adaptertest.CallerJSON(iamfiber.Caller(c)))
		}
		app := fiber.New(fiber.Config{DisableStartupMessage: true})
		app.Get("/orders", guard.Require(adaptertest.ReadRule), who)
		app.Post("/orders", guard.Require(adaptertest.WriteRule), who)
		app.Get("/closed", guard.Require(iam.Rule{}), who)
		app.Get("/public", func(c *fiber.Ctx) error { return c.SendString("public") })
		serve(t, ln, app)
	})
}

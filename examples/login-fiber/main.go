// Command login-fiber shows user sign-in with IAM in a Fiber v2 application.
//
//	IAM_ISSUER=https://iam.example.com \
//	IAM_CLIENT_ID=<client id of the OIDC application> IAM_CLIENT_SECRET=... \
//	APP_BASE_URL=https://portal.example.com APP_SESSION_KEY=<at least 32 random bytes> \
//	go run ./examples/login-fiber
//
// Register https://portal.example.com/callback as the redirect URI and
// https://portal.example.com/ as the post-logout redirect URI of the OIDC
// application (type "Web backend") in the IAM console.
package main

import (
	"context"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamfiber"
)

func main() {
	app, err := newApp(context.Background(), loadConfig())
	if err != nil {
		log.Fatal(err) // names the configuration field that is missing or invalid
	}
	log.Fatal(app.Listen(envOr("LISTEN_ADDR", "127.0.0.1:8080")))
}

// loadConfig reads the configuration from the environment. Where the values
// come from is the application's business; the SDK reads nothing by itself.
func loadConfig() iam.LoginConfig {
	base := os.Getenv("APP_BASE_URL")
	// For a local integration environment over plain http only.
	insecure := os.Getenv("IAM_ALLOW_INSECURE") == "true"
	return iam.LoginConfig{
		Issuer:                os.Getenv("IAM_ISSUER"),
		ClientID:              os.Getenv("IAM_CLIENT_ID"),
		Credential:            iam.ClientSecret(os.Getenv("IAM_CLIENT_SECRET")),
		RedirectURL:           base + "/callback",
		PostLogoutRedirectURL: base + "/",
		Scopes:                []string{"openid", "profile", "email"},
		SessionKey:            []byte(os.Getenv("APP_SESSION_KEY")),
		AllowInsecureIssuer:   insecure,
		AllowInsecureCookie:   insecure,
	}
}

func newApp(ctx context.Context, cfg iam.LoginConfig) (*fiber.App, error) {
	// iam:start
	login, err := iam.NewLogin(ctx, cfg)
	if err != nil {
		return nil, err
	}
	auth := iamfiber.Login(login)

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/login", auth.Start)       // redirects to IAM
	app.Get("/callback", auth.Callback) // validates, creates the local session, returns to the page
	app.Get("/logout", auth.Logout)     // ends the local session, then IAM's
	app.Get("/profile", auth.Require(), func(c *fiber.Ctx) error {
		user := iamfiber.User(c)
		// user.Issuer + user.Subject is the unique key to map a local account by.
		return c.JSON(fiber.Map{"iss": user.Issuer, "sub": user.Subject, "name": user.Name, "email": user.Email})
	})
	// iam:end

	app.Get("/", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
		return c.SendString(`<a href="/profile">profile</a> · <a href="/logout">sign out</a>`)
	})
	return app, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

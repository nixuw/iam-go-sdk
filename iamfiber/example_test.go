package iamfiber_test

import (
	"context"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamfiber"
)

// User sign-in: three routes and a middleware.
func ExampleLogin() {
	login, err := iam.NewLogin(context.Background(), iam.LoginConfig{
		Issuer:      os.Getenv("IAM_ISSUER"),
		ClientID:    os.Getenv("IAM_CLIENT_ID"),
		Credential:  iam.ClientSecret(os.Getenv("IAM_CLIENT_SECRET")),
		RedirectURL: os.Getenv("APP_CALLBACK_URL"),
		SessionKey:  []byte(os.Getenv("APP_SESSION_KEY")),
	})
	if err != nil {
		log.Fatal(err) // names the configuration field that is missing or invalid
	}
	auth := iamfiber.Login(login)

	app := fiber.New()
	app.Get("/login", auth.Start)
	app.Get("/callback", auth.Callback)
	app.Get("/logout", auth.Logout)
	app.Get("/profile", auth.Require(), func(c *fiber.Ctx) error {
		user := iamfiber.User(c)
		return c.JSON(fiber.Map{"sub": user.Subject, "name": user.Name, "email": user.Email})
	})
	log.Fatal(app.Listen(":8080"))
}

// The provider side: every endpoint declares the permissions it requires and
// the principal types it accepts.
func ExampleGuard() {
	verifier, err := iam.NewVerifier(context.Background(), iam.VerifierConfig{
		Issuer:   os.Getenv("IAM_ISSUER"),
		Audience: os.Getenv("IAM_RESOURCE"),
	})
	if err != nil {
		log.Fatal(err)
	}
	guard := iamfiber.Guard(verifier)

	app := fiber.New()
	app.Get("/api/orders/:id",
		guard.Require(iam.Rule{
			Scopes:     []string{"order.read"},
			Principals: []string{iam.PrincipalService, iam.PrincipalUser},
		}),
		func(c *fiber.Ctx) error {
			who := iamfiber.Caller(c)
			return c.JSON(fiber.Map{"id": c.Params("id"), "client_id": who.ClientID, "principal_type": who.PrincipalType})
		})
	app.Post("/api/orders",
		guard.Require(iam.Rule{
			Scopes:     []string{"order.write"},
			Principals: []string{iam.PrincipalService}, // system calls only
		}),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusCreated) })
	log.Fatal(app.Listen(":8080"))
}

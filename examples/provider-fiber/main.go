// Command provider-fiber shows a Fiber v2 application that accepts access
// tokens issued by IAM for its API.
//
//	IAM_ISSUER=https://iam.example.com IAM_RESOURCE=urn:iam:app:order \
//	go run ./examples/provider-fiber
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
		log.Fatal(err)
	}
	log.Fatal(app.Listen(envOr("LISTEN_ADDR", "127.0.0.1:8081")))
}

func loadConfig() iam.VerifierConfig {
	return iam.VerifierConfig{
		Issuer:   os.Getenv("IAM_ISSUER"),
		Audience: os.Getenv("IAM_RESOURCE"), // this application's resource identifier, as shown in the IAM console
		// For a local integration environment over plain http only.
		AllowInsecureIssuer: os.Getenv("IAM_ALLOW_INSECURE") == "true",
	}
}

func newApp(ctx context.Context, cfg iam.VerifierConfig) (*fiber.App, error) {
	// iam:start
	verifier, err := iam.NewVerifier(ctx, cfg)
	if err != nil {
		return nil, err
	}
	guard := iamfiber.Guard(verifier)

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	// Every endpoint declares the permissions it requires and the principal
	// types it accepts.
	app.Get("/api/orders/:id",
		guard.Require(iam.Rule{Scopes: []string{"order.read"}, Principals: []string{iam.PrincipalService, iam.PrincipalUser}}),
		getOrder)
	app.Post("/api/orders",
		guard.Require(iam.Rule{Scopes: []string{"order.write"}, Principals: []string{iam.PrincipalService}}),
		createOrder)
	// iam:end
	return app, nil
}

func getOrder(c *fiber.Ctx) error {
	who := iamfiber.Caller(c) // the verified caller
	owner := who.ClientID     // a system calling as itself
	if who.PrincipalType == iam.PrincipalUser {
		owner = who.Subject // a user; who.ClientID is the application acting for them
	}
	// From here on it is the application's own business: tenant, data scope,
	// business rules.
	return c.JSON(fiber.Map{"id": c.Params("id"), "requested_by": owner, "principal_type": who.PrincipalType})
}

func createOrder(c *fiber.Ctx) error {
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"created_by": iamfiber.Caller(c).ClientID})
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

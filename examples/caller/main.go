// Command caller shows a system calling another application's HTTP API as
// itself, with a system token from IAM.
//
//	IAM_ISSUER=https://iam.example.com \
//	IAM_SVC_CLIENT_ID=<client id of the service credential> IAM_SVC_CLIENT_SECRET=... \
//	ORDER_RESOURCE=urn:iam:app:order ORDER_API_URL=https://order.example.com \
//	go run ./examples/caller
//
// With a private_key_jwt credential, set IAM_SVC_KEY_ID and
// IAM_SVC_PRIVATE_KEY_FILE instead of IAM_SVC_CLIENT_SECRET.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	iam "github.com/nixuw/iam-go-sdk"
)

type config struct {
	caller        iam.CallerConfig
	orderResource string // resource identifier of the target application
	orderURL      string // where its API lives
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	if err := run(context.Background(), cfg, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func loadConfig() (config, error) {
	// For a local integration environment over plain http only.
	insecure := os.Getenv("IAM_ALLOW_INSECURE") == "true"
	cfg := config{
		orderResource: os.Getenv("ORDER_RESOURCE"),
		orderURL:      os.Getenv("ORDER_API_URL"),
		caller: iam.CallerConfig{
			Issuer:                 os.Getenv("IAM_ISSUER"),
			ClientID:               os.Getenv("IAM_SVC_CLIENT_ID"), // the service credential, not the login client
			Credential:             iam.ClientSecret(os.Getenv("IAM_SVC_CLIENT_SECRET")),
			AllowInsecureIssuer:    insecure,
			AllowInsecureTransport: insecure,
		},
	}
	if file := os.Getenv("IAM_SVC_PRIVATE_KEY_FILE"); file != "" {
		pem, err := os.ReadFile(file)
		if err != nil {
			return cfg, err
		}
		key, err := iam.ParsePrivateKeyPEM(pem)
		if err != nil {
			return cfg, err
		}
		cfg.caller.Credential = iam.PrivateKeyJWT(os.Getenv("IAM_SVC_KEY_ID"), key)
	}
	return cfg, nil
}

func run(ctx context.Context, cfg config, out io.Writer) error {
	// iam:start
	// Create the caller once and keep it: it caches and renews the tokens.
	caller, err := iam.NewCaller(ctx, cfg.caller)
	if err != nil {
		return err
	}
	// One outbound client per target. It only ever sends this target's token.
	orders := caller.HTTPClient(iam.Target{
		Resource: cfg.orderResource,
		Scopes:   []string{"order.read"}, // the least privilege this call needs
		BaseURL:  cfg.orderURL,
	})
	resp, err := orders.Get(cfg.orderURL + "/api/orders/42")
	// iam:end
	if err != nil {
		var oe *iam.OAuthError
		switch {
		case errors.As(err, &oe):
			// IAM refused to issue the token, e.g. invalid_target (no grant).
			// The request ID locates the request in IAM's token request log.
			return fmt.Errorf("token request refused: %s (request id %s)", oe.Code, oe.RequestID)
		case errors.Is(err, iam.ErrInsufficientScope):
			return fmt.Errorf("the target requires a permission the grant does not include: %w", err)
		}
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "HTTP %d %s\n", resp.StatusCode, body)
	return err
}

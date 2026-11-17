// Command provider-nethttp shows a net/http application that accepts access
// tokens issued by IAM for its API. The same middleware works with chi and
// other routers built on http.Handler.
//
//	IAM_ISSUER=https://iam.example.com IAM_RESOURCE=urn:iam:app:order \
//	go run ./examples/provider-nethttp
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamhttp"
)

func main() {
	handler, err := newHandler(context.Background(), loadConfig())
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServe(envOr("LISTEN_ADDR", "127.0.0.1:8082"), handler))
}

func loadConfig() iam.VerifierConfig {
	return iam.VerifierConfig{
		Issuer:   os.Getenv("IAM_ISSUER"),
		Audience: os.Getenv("IAM_RESOURCE"), // this application's resource identifier, as shown in the IAM console
		// For a local integration environment over plain http only.
		AllowInsecureIssuer: os.Getenv("IAM_ALLOW_INSECURE") == "true",
	}
}

func newHandler(ctx context.Context, cfg iam.VerifierConfig) (http.Handler, error) {
	// iam:start
	verifier, err := iam.NewVerifier(ctx, cfg)
	if err != nil {
		return nil, err
	}
	guard := iamhttp.Guard(verifier)

	mux := http.NewServeMux()
	// Every endpoint declares the permissions it requires and the principal
	// types it accepts.
	read := guard.Require(iam.Rule{Scopes: []string{"order.read"}, Principals: []string{iam.PrincipalService, iam.PrincipalUser}})
	write := guard.Require(iam.Rule{Scopes: []string{"order.write"}, Principals: []string{iam.PrincipalService}})
	mux.Handle("GET /api/orders/{id}", read(http.HandlerFunc(getOrder)))
	mux.Handle("POST /api/orders", write(http.HandlerFunc(createOrder)))
	// iam:end
	return mux, nil
}

func getOrder(w http.ResponseWriter, r *http.Request) {
	who := iamhttp.Caller(r) // the verified caller
	owner := who.ClientID    // a system calling as itself
	if who.PrincipalType == iam.PrincipalUser {
		owner = who.Subject // a user; who.ClientID is the application acting for them
	}
	// From here on it is the application's own business: tenant, data scope,
	// business rules.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": r.PathValue("id"), "requested_by": owner, "principal_type": who.PrincipalType})
}

func createOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"created_by": iamhttp.Caller(r).ClientID})
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

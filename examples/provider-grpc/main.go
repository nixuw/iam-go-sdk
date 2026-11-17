// Command provider-grpc shows a gRPC server that accepts access tokens
// issued by IAM for its methods.
//
//	IAM_ISSUER=https://iam.example.com IAM_RESOURCE=urn:iam:app:order \
//	go run ./examples/provider-grpc
//
// The server listens without TLS, as behind a mesh or a TLS-terminating
// proxy. Tokens must not cross an untrusted network in clear text.
package main

import (
	"context"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamgrpc"
	"github.com/nixuw/iam-go-sdk/internal/orderv1" // stands in for your generated code
)

func main() {
	srv, err := newServer(context.Background(), loadConfig())
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", envOr("LISTEN_ADDR", "127.0.0.1:8083"))
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.Serve(ln))
}

func loadConfig() iam.VerifierConfig {
	return iam.VerifierConfig{
		Issuer:   os.Getenv("IAM_ISSUER"),
		Audience: os.Getenv("IAM_RESOURCE"), // this application's resource identifier, as shown in the IAM console
		// For a local integration environment over plain http only.
		AllowInsecureIssuer: os.Getenv("IAM_ALLOW_INSECURE") == "true",
	}
}

func newServer(ctx context.Context, cfg iam.VerifierConfig) (*grpc.Server, error) {
	// iam:start
	verifier, err := iam.NewVerifier(ctx, cfg)
	if err != nil {
		return nil, err
	}
	// The access rule of every method. A method that is not listed refuses
	// every call.
	rules := iamgrpc.Rules{
		orderv1.GetOrderMethod:    {Scopes: []string{"order.read"}, Principals: []string{iam.PrincipalService, iam.PrincipalUser}},
		orderv1.CreateOrderMethod: {Scopes: []string{"order.write"}, Principals: []string{iam.PrincipalService}},
	}
	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(iamgrpc.UnaryServerInterceptor(verifier, rules)),
		grpc.ChainStreamInterceptor(iamgrpc.StreamServerInterceptor(verifier, rules)),
	)
	// iam:end
	orderv1.RegisterOrderServiceServer(srv, orderService{})
	return srv, nil
}

type orderService struct {
	orderv1.UnimplementedOrderServiceServer
}

func (orderService) GetOrder(ctx context.Context, id *orderv1.Text) (*orderv1.Text, error) {
	who := iamgrpc.Caller(ctx) // the verified caller
	owner := who.ClientID      // a system calling as itself
	if who.PrincipalType == iam.PrincipalUser {
		owner = who.Subject // a user; who.ClientID is the application acting for them
	}
	// From here on it is the application's own business: tenant, data scope,
	// business rules.
	return orderv1.NewText("order " + id.GetValue() + " requested by " + owner), nil
}

func (orderService) CreateOrder(ctx context.Context, _ *orderv1.Text) (*orderv1.Text, error) {
	return orderv1.NewText("created by " + iamgrpc.Caller(ctx).ClientID), nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// Command caller-grpc shows a system calling another application's gRPC API
// as itself, with a system token from IAM.
//
//	IAM_ISSUER=https://iam.example.com \
//	IAM_SVC_CLIENT_ID=<client id of the service credential> IAM_SVC_CLIENT_SECRET=... \
//	ORDER_RESOURCE=urn:iam:app:order ORDER_GRPC_ADDR=order.example.com:443 \
//	go run ./examples/caller-grpc
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamgrpc"
	"github.com/nixuw/iam-go-sdk/internal/orderv1" // stands in for your generated code
)

type config struct {
	caller        iam.CallerConfig
	orderResource string // resource identifier of the target application
	orderAddr     string // where its gRPC API lives
	transport     credentials.TransportCredentials
}

func main() {
	if err := run(context.Background(), loadConfig(), os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func loadConfig() config {
	cfg := config{
		orderResource: os.Getenv("ORDER_RESOURCE"),
		orderAddr:     os.Getenv("ORDER_GRPC_ADDR"),
		transport:     credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}),
		caller: iam.CallerConfig{
			Issuer:     os.Getenv("IAM_ISSUER"),
			ClientID:   os.Getenv("IAM_SVC_CLIENT_ID"), // the service credential, not the login client
			Credential: iam.ClientSecret(os.Getenv("IAM_SVC_CLIENT_SECRET")),
		},
	}
	// For a local integration environment, or inside a cluster whose mesh
	// encrypts the traffic: the application must say so explicitly.
	if os.Getenv("IAM_ALLOW_INSECURE") == "true" {
		cfg.caller.AllowInsecureIssuer, cfg.caller.AllowInsecureTransport = true, true
		cfg.transport = insecure.NewCredentials()
	}
	return cfg
}

func run(ctx context.Context, cfg config, out io.Writer) error {
	// iam:start
	caller, err := iam.NewCaller(ctx, cfg.caller)
	if err != nil {
		return err
	}
	// The connection is bound to one target: every call carries its token.
	target := iam.Target{Resource: cfg.orderResource, Scopes: []string{"order.read"}}
	conn, err := grpc.NewClient(cfg.orderAddr,
		grpc.WithTransportCredentials(cfg.transport),
		grpc.WithPerRPCCredentials(iamgrpc.Credentials(caller, target)),
		grpc.WithChainUnaryInterceptor(iamgrpc.UnaryClientInterceptor(caller, target)),
	)
	// iam:end
	if err != nil {
		return err
	}
	defer conn.Close()
	order, err := orderv1.NewOrderServiceClient(conn).GetOrder(ctx, orderv1.NewText("42"))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, order.GetValue())
	return err
}

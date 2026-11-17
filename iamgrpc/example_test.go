package iamgrpc_test

import (
	"crypto/tls"
	"log"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamgrpc"
)

// The caller side: a connection bound to one target.
func ExampleCredentials() {
	var caller *iam.Caller // from iam.NewCaller
	target := iam.Target{Resource: os.Getenv("ORDER_RESOURCE"), Scopes: []string{"order.read"}}
	conn, err := grpc.NewClient(os.Getenv("ORDER_GRPC_ADDR"),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})),
		grpc.WithPerRPCCredentials(iamgrpc.Credentials(caller, target)),
		grpc.WithChainUnaryInterceptor(iamgrpc.UnaryClientInterceptor(caller, target)),
		grpc.WithChainStreamInterceptor(iamgrpc.StreamClientInterceptor(caller, target)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}

// The provider side: an access rule per method; methods that are not listed
// are closed.
func ExampleUnaryServerInterceptor() {
	var verifier *iam.Verifier // from iam.NewVerifier
	rules := iamgrpc.Rules{
		"/order.v1.OrderService/GetOrder": {
			Scopes:     []string{"order.read"},
			Principals: []string{iam.PrincipalService, iam.PrincipalUser},
		},
		"/order.v1.OrderService/CreateOrder": {
			Scopes:     []string{"order.write"},
			Principals: []string{iam.PrincipalService},
		},
	}
	public := iamgrpc.WithPublicMethods("/grpc.health.v1.Health/Check")
	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(iamgrpc.UnaryServerInterceptor(verifier, rules, public)),
		grpc.ChainStreamInterceptor(iamgrpc.StreamServerInterceptor(verifier, rules, public)),
	)
	_ = srv // register services, then Serve; handlers read iamgrpc.Caller(ctx)
}

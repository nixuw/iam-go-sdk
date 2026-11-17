package main

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamgrpc"
	"github.com/nixuw/iam-go-sdk/iamtest"
	"github.com/nixuw/iam-go-sdk/internal/orderv1"
)

const resource = "urn:example:app:order"

type orderService struct {
	orderv1.UnimplementedOrderServiceServer
}

func (orderService) GetOrder(ctx context.Context, id *orderv1.Text) (*orderv1.Text, error) {
	return orderv1.NewText("order " + id.GetValue() + " for " + iamgrpc.Caller(ctx).ClientID), nil
}

func TestExample(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	iss.AddServiceClient(iamtest.ServiceClient{ID: "svc_example_caller", Secrets: []string{"ssk_example_secret"}})
	iss.Grant("svc_example_caller", resource, "order.read")

	// A target that verifies the token with the SDK.
	verifier, err := iam.NewVerifier(context.Background(), iam.VerifierConfig{Issuer: iss.URL(), Audience: resource, HTTPClient: iss.HTTPClient()})
	if err != nil {
		t.Fatal(err)
	}
	rules := iamgrpc.Rules{orderv1.GetOrderMethod: {Scopes: []string{"order.read"}, Principals: []string{iam.PrincipalService}}}
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(iamgrpc.UnaryServerInterceptor(verifier, rules)))
	orderv1.RegisterOrderServiceServer(srv, orderService{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Stop()

	t.Setenv("IAM_ISSUER", iss.URL())
	t.Setenv("IAM_SVC_CLIENT_ID", "svc_example_caller")
	t.Setenv("IAM_SVC_CLIENT_SECRET", "ssk_example_secret")
	t.Setenv("ORDER_RESOURCE", resource)
	t.Setenv("ORDER_GRPC_ADDR", ln.Addr().String())
	t.Setenv("IAM_ALLOW_INSECURE", "true") // the test target speaks plaintext on loopback
	cfg := loadConfig()
	cfg.caller.HTTPClient = iss.HTTPClient() // trust the fake issuer's certificate
	var out bytes.Buffer
	if err := run(context.Background(), cfg, &out); err != nil || out.String() != "order 42 for svc_example_caller\n" {
		t.Fatalf("call: %q %v", out.String(), err)
	}
	// Without the explicit permission, a token is not sent in clear text.
	t.Setenv("IAM_ALLOW_INSECURE", "")
	strict := loadConfig()
	strict.caller.HTTPClient = iss.HTTPClient()
	if err := run(context.Background(), strict, &out); err == nil || !strings.Contains(err.Error(), "authentication handshake failed") && !strings.Contains(err.Error(), "tls") && !strings.Contains(err.Error(), "transport") {
		t.Fatalf("TLS is the default: %v", err)
	}
}

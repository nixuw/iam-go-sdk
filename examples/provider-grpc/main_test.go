package main

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/nixuw/iam-go-sdk/iamtest"
	"github.com/nixuw/iam-go-sdk/internal/orderv1"
)

const resource = "urn:example:app:order"

func TestExample(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	t.Setenv("IAM_ISSUER", iss.URL())
	t.Setenv("IAM_RESOURCE", resource)
	cfg := loadConfig()
	cfg.HTTPClient = iss.HTTPClient() // trust the fake issuer's certificate
	srv, err := newServer(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Stop()
	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := orderv1.NewOrderServiceClient(conn)
	with := func(token string) context.Context {
		if token == "" {
			return context.Background()
		}
		return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token)
	}
	read := iss.ServiceToken(resource, "svc_example_caller", "order.read")
	user := iss.UserToken(resource, "app_example_portal", "user-1", "order.read", "order.write")

	if _, err := client.GetOrder(with(""), orderv1.NewText("42")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no token: %v", err)
	}
	if out, err := client.GetOrder(with(read), orderv1.NewText("42")); err != nil || out.GetValue() != "order 42 requested by svc_example_caller" {
		t.Fatalf("system token: %v %v", out, err)
	}
	if out, err := client.GetOrder(with(user), orderv1.NewText("42")); err != nil || out.GetValue() != "order 42 requested by user-1" {
		t.Fatalf("user-delegated token: %v %v", out, err)
	}
	if _, err := client.CreateOrder(with(read), orderv1.NewText("x")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("missing permission: %v", err)
	}
	// CancelOrder has no access rule: it is closed.
	if _, err := client.CancelOrder(with(read), orderv1.NewText("42")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("method without a rule: %v", err)
	}
}

package iamgrpc_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	iam "github.com/nixuw/iam-go-sdk"
	"github.com/nixuw/iam-go-sdk/iamgrpc"
	"github.com/nixuw/iam-go-sdk/iamtest"
	"github.com/nixuw/iam-go-sdk/internal/hooks"
	"github.com/nixuw/iam-go-sdk/internal/orderv1"
)

const (
	resource = "urn:example:app:orders"
	svcID    = "svc_example_caller"
)

var (
	ctx   = context.Background()
	rules = iamgrpc.Rules{
		orderv1.GetOrderMethod:    {Scopes: []string{"order.read"}, Principals: []string{iam.PrincipalService, iam.PrincipalUser}},
		orderv1.CreateOrderMethod: {Scopes: []string{"order.write"}, Principals: []string{iam.PrincipalService}},
		orderv1.WatchOrdersMethod: {Scopes: []string{"order.read"}, Principals: []string{iam.PrincipalService}},
		// CancelOrder has no rule on purpose.
	}
)

// orders answers with the identity the interceptor put into the context.
type orders struct {
	orderv1.UnimplementedOrderServiceServer
}

func who(ctx context.Context) string {
	id := iamgrpc.Caller(ctx)
	if id == nil {
		return "anonymous"
	}
	return id.PrincipalType + ":" + id.ClientID + ":" + id.Subject
}

func (orders) GetOrder(ctx context.Context, _ *orderv1.Text) (*orderv1.Text, error) {
	return orderv1.NewText(who(ctx)), nil
}

func (orders) CreateOrder(ctx context.Context, _ *orderv1.Text) (*orderv1.Text, error) {
	return orderv1.NewText(who(ctx)), nil
}

func (orders) CancelOrder(ctx context.Context, _ *orderv1.Text) (*orderv1.Text, error) {
	return orderv1.NewText(who(ctx)), nil
}

func (orders) WatchOrders(_ *orderv1.Text, stream grpc.ServerStreamingServer[orderv1.Text]) error {
	for i := 0; i < 2; i++ {
		if err := stream.Send(orderv1.NewText(who(stream.Context()))); err != nil {
			return err
		}
	}
	return nil
}

// startServer runs the order service behind the SDK's interceptors.
func startServer(t *testing.T, v *iam.Verifier, extra []grpc.UnaryServerInterceptor, opts ...iamgrpc.ServerOption) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(append(extra, iamgrpc.UnaryServerInterceptor(v, rules, opts...))...),
		grpc.ChainStreamInterceptor(iamgrpc.StreamServerInterceptor(v, rules, opts...)),
	)
	orderv1.RegisterOrderServiceServer(srv, orders{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return ln.Addr().String()
}

func newVerifier(t *testing.T, iss *iamtest.Issuer, mutate ...func(*iam.VerifierConfig)) *iam.Verifier {
	t.Helper()
	cfg := iam.VerifierConfig{Issuer: iss.URL(), Audience: resource, HTTPClient: iss.HTTPClient()}
	for _, m := range mutate {
		m(&cfg)
	}
	v, err := iam.NewVerifier(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func dial(t *testing.T, addr string, opts ...grpc.DialOption) orderv1.OrderServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(addr, append([]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return orderv1.NewOrderServiceClient(conn)
}

// static attaches a fixed authorization value to every call.
type static string

func (s static) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": string(s)}, nil
}
func (static) RequireTransportSecurity() bool { return false }

var _ credentials.PerRPCCredentials = static("")

func newIssuer(t *testing.T) *iamtest.Issuer {
	iss := iamtest.NewIssuer(t)
	iss.AddServiceClient(iamtest.ServiceClient{ID: svcID, Secrets: []string{"ssk_example_secret"}})
	iss.Grant(svcID, resource, "order.read")
	return iss
}

func newCaller(t *testing.T, iss *iamtest.Issuer, plaintext bool) *iam.Caller {
	t.Helper()
	c, err := iam.NewCaller(ctx, iam.CallerConfig{
		Issuer: iss.URL(), ClientID: svcID, Credential: iam.ClientSecret("ssk_example_secret"), HTTPClient: iss.HTTPClient(),
		AllowInsecureTransport: plaintext,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestCallerToProvider is AC-13: per-RPC credentials on the caller side,
// interceptors on the provider side, end to end.
func TestCallerToProvider(t *testing.T) {
	iss := newIssuer(t)
	addr := startServer(t, newVerifier(t, iss), nil)
	caller := newCaller(t, iss, true)
	target := iam.Target{Resource: resource, Scopes: []string{"order.read"}}
	client := dial(t, addr,
		grpc.WithPerRPCCredentials(iamgrpc.Credentials(caller, target)),
		grpc.WithChainUnaryInterceptor(iamgrpc.UnaryClientInterceptor(caller, target)),
		grpc.WithChainStreamInterceptor(iamgrpc.StreamClientInterceptor(caller, target)),
	)
	for i := 0; i < 5; i++ {
		out, err := client.GetOrder(ctx, orderv1.NewText("42"))
		if err != nil || out.Value != "service:"+svcID+":"+svcID {
			t.Fatalf("GetOrder: %v %v", out, err)
		}
	}
	if n := iss.Requests(iamtest.PathToken); n != 1 {
		t.Fatalf("%d token requests for 5 calls, want 1", n)
	}
	// Streaming: verified when the stream opens; the handler sees the caller.
	stream, err := client.WatchOrders(ctx, orderv1.NewText(""))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		msg, err := stream.Recv()
		if err != nil || msg.Value != "service:"+svcID+":"+svcID {
			t.Fatalf("stream message %d: %v %v", i, msg, err)
		}
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("end of stream: %v", err)
	}
	// The token lacks order.write: PermissionDenied, and no retry.
	before := iss.Requests(iamtest.PathToken)
	if _, err := client.CreateOrder(ctx, orderv1.NewText("x")); status.Code(err) != codes.PermissionDenied || iss.Requests(iamtest.PathToken) != before {
		t.Fatalf("missing permission: %v", err)
	}
	// A token request that IAM refuses fails the call without reaching the
	// provider.
	noGrant := dial(t, addr, grpc.WithPerRPCCredentials(iamgrpc.Credentials(caller, iam.Target{Resource: "urn:example:app:billing"})))
	if _, err := noGrant.GetOrder(ctx, orderv1.NewText("42")); err == nil || !strings.Contains(err.Error(), "invalid_target") {
		t.Fatalf("no grant: %v", err)
	}
}

// TestStatusCodes is the error mapping of ADAPT-03.
func TestStatusCodes(t *testing.T) {
	iss := newIssuer(t)
	addr := startServer(t, newVerifier(t, iss), nil)
	read := iss.ServiceToken(resource, svcID, "order.read")
	user := iss.UserToken(resource, "app_example_portal", "user-1", "order.read", "order.write")
	expired := iss.AccessToken(iamtest.Token{Subject: svcID, ClientID: svcID, Audience: resource, Principal: "service", Scopes: []string{"order.read"}, IssuedAt: time.Now().Add(-time.Hour)})

	type call func(orderv1.OrderServiceClient, ...grpc.CallOption) error
	get := func(c orderv1.OrderServiceClient, o ...grpc.CallOption) error {
		_, err := c.GetOrder(ctx, orderv1.NewText("1"), o...)
		return err
	}
	create := func(c orderv1.OrderServiceClient, o ...grpc.CallOption) error {
		_, err := c.CreateOrder(ctx, orderv1.NewText("1"), o...)
		return err
	}
	cancel := func(c orderv1.OrderServiceClient, o ...grpc.CallOption) error {
		_, err := c.CancelOrder(ctx, orderv1.NewText("1"), o...)
		return err
	}
	watch := func(c orderv1.OrderServiceClient, o ...grpc.CallOption) error {
		stream, err := c.WatchOrders(ctx, orderv1.NewText(""), o...)
		if err != nil {
			return err
		}
		_, err = stream.Recv()
		return err
	}
	for _, tc := range []struct {
		name      string
		auth      string
		call      call
		code      codes.Code
		challenge string
	}{
		{"no token", "", get, codes.Unauthenticated, `Bearer realm="` + resource + `"`},
		{"not a bearer token", "Basic abc", get, codes.Unauthenticated, `Bearer realm="` + resource + `"`},
		{"invalid token", "Bearer garbage", get, codes.Unauthenticated, `error="invalid_token"`},
		{"expired token", "Bearer " + expired, get, codes.Unauthenticated, `error_description="token expired"`},
		{"token for another application", "Bearer " + iss.ServiceToken("urn:example:app:billing", svcID, "order.read"), get, codes.Unauthenticated, `error="invalid_token"`},
		{"missing permission", "Bearer " + read, create, codes.PermissionDenied, `scope="order.write"`},
		{"principal type not accepted", "Bearer " + user, create, codes.PermissionDenied, `error="insufficient_scope"`},
		{"method without a rule, valid token", "Bearer " + read, cancel, codes.PermissionDenied, `error="insufficient_scope"`},
		{"method without a rule, no token", "", cancel, codes.Unauthenticated, `Bearer realm=`},
		{"stream without a token", "", watch, codes.Unauthenticated, `Bearer realm=`},
		{"stream with a user token", "Bearer " + user, watch, codes.PermissionDenied, `error="insufficient_scope"`},
		{"valid", "Bearer " + read, get, codes.OK, ""},
		{"valid user token", "Bearer " + user, get, codes.OK, ""},
		{"valid stream", "Bearer " + read, watch, codes.OK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts []grpc.DialOption
			if tc.auth != "" {
				opts = append(opts, grpc.WithPerRPCCredentials(static(tc.auth)))
			}
			var trailer metadata.MD
			err := tc.call(dial(t, addr, opts...), grpc.Trailer(&trailer))
			if status.Code(err) != tc.code {
				t.Fatalf("status %v, want %v (%v)", status.Code(err), tc.code, err)
			}
			got := strings.Join(trailer.Get("www-authenticate"), "")
			if tc.challenge != "" && !strings.Contains(got, tc.challenge) || tc.challenge == "" && got != "" {
				t.Fatalf("www-authenticate trailer %q, want it to contain %q", got, tc.challenge)
			}
			if err != nil && tc.auth != "" && strings.Contains(err.Error()+got, strings.TrimPrefix(tc.auth, "Bearer ")) {
				t.Fatal("the error echoes the token")
			}
		})
	}

	t.Run("no signing key: Unavailable", func(t *testing.T) {
		iss.SetDown(true)
		defer iss.SetDown(false)
		v := newVerifier(t, iss, func(c *iam.VerifierConfig) { c.TolerateStartupFailure = true })
		down := dial(t, startServer(t, v, nil), grpc.WithPerRPCCredentials(static("Bearer "+read)))
		if err := get(down); status.Code(err) != codes.Unavailable {
			t.Fatalf("no keys: %v", err)
		}
	})

	t.Run("public methods", func(t *testing.T) {
		open := dial(t, startServer(t, newVerifier(t, iss), nil, iamgrpc.WithPublicMethods(orderv1.CancelOrderMethod)))
		out, err := open.CancelOrder(ctx, orderv1.NewText("1"))
		if err != nil || out.Value != "anonymous" {
			t.Fatalf("public method: %v %v", out, err)
		}
		if err := get(open); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("the other methods stay protected: %v", err)
		}
	})

	t.Run("the application's own refusal", func(t *testing.T) {
		quota := status.Error(codes.ResourceExhausted, "quota used up")
		v := newVerifier(t, iss, func(c *iam.VerifierConfig) {
			c.Authorize = func(_ context.Context, id *iam.Identity) error {
				switch id.ClientID {
				case "svc_over_quota":
					return quota
				case "svc_suspended":
					return errors.New("suspended")
				}
				return nil
			}
		})
		addr := startServer(t, v, nil)
		over := dial(t, addr, grpc.WithPerRPCCredentials(static("Bearer "+iss.ServiceToken(resource, "svc_over_quota", "order.read"))))
		if err := get(over); status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("a status returned by Authorize must be kept: %v", err)
		}
		suspended := dial(t, addr, grpc.WithPerRPCCredentials(static("Bearer "+iss.ServiceToken(resource, "svc_suspended", "order.read"))))
		if err := get(suspended); status.Code(err) != codes.PermissionDenied || strings.Contains(err.Error(), "insufficient_scope") {
			t.Fatalf("plain error from Authorize: %v", err)
		}
	})
}

// CALL-05 and CALL-07 for gRPC.
func TestClientSide(t *testing.T) {
	iss := newIssuer(t)
	target := iam.Target{Resource: resource, Scopes: []string{"order.read"}}

	t.Run("tokens need a secure transport unless allowed", func(t *testing.T) {
		strict := newCaller(t, iss, false)
		creds := iamgrpc.Credentials(strict, target)
		if !creds.RequireTransportSecurity() || iamgrpc.Credentials(newCaller(t, iss, true), target).RequireTransportSecurity() {
			t.Fatal("RequireTransportSecurity must follow AllowInsecureTransport")
		}
		if _, err := grpc.NewClient("127.0.0.1:1", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithPerRPCCredentials(creds)); err == nil {
			t.Fatal("gRPC must refuse to combine these credentials with a plaintext connection")
		}
	})

	t.Run("Unauthenticated: new token, one retry", func(t *testing.T) {
		var calls atomic.Int32
		// The provider refuses the first call as if the token had become
		// invalid (for example its signing key was retired).
		flaky := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if calls.Add(1) == 1 {
				return nil, status.Error(codes.Unauthenticated, "invalid_token: signing key not found")
			}
			return handler(ctx, req)
		}
		addr := startServer(t, newVerifier(t, iss), []grpc.UnaryServerInterceptor{flaky})
		caller := newCaller(t, iss, true)
		client := dial(t, addr,
			grpc.WithPerRPCCredentials(iamgrpc.Credentials(caller, target)),
			grpc.WithChainUnaryInterceptor(iamgrpc.UnaryClientInterceptor(caller, target)),
		)
		before := iss.Requests(iamtest.PathToken)
		if _, err := client.GetOrder(ctx, orderv1.NewText("42")); err != nil {
			t.Fatalf("the call must succeed on the retry: %v", err)
		}
		if calls.Load() != 2 || iss.Requests(iamtest.PathToken)-before != 2 {
			t.Fatalf("%d calls, %d token requests; want 2 and 2", calls.Load(), iss.Requests(iamtest.PathToken)-before)
		}
	})

	t.Run("Unauthenticated twice: the error, no loop", func(t *testing.T) {
		var calls atomic.Int32
		always := func(context.Context, any, *grpc.UnaryServerInfo, grpc.UnaryHandler) (any, error) {
			calls.Add(1)
			return nil, status.Error(codes.Unauthenticated, "invalid_token: audience is not this resource")
		}
		addr := startServer(t, newVerifier(t, iss), []grpc.UnaryServerInterceptor{always})
		caller := newCaller(t, iss, true)
		client := dial(t, addr,
			grpc.WithPerRPCCredentials(iamgrpc.Credentials(caller, target)),
			grpc.WithChainUnaryInterceptor(iamgrpc.UnaryClientInterceptor(caller, target)),
		)
		if _, err := client.GetOrder(ctx, orderv1.NewText("42")); status.Code(err) != codes.Unauthenticated || calls.Load() != 2 {
			t.Fatalf("persistent refusal: %v after %d calls", err, calls.Load())
		}
	})

	t.Run("a refused stream drops the cached token", func(t *testing.T) {
		v := newVerifier(t, iss)
		clock := time.Now()
		hooks.SetClock(v, func() time.Time { return clock })
		addr := startServer(t, v, nil)
		caller := newCaller(t, iss, true)
		client := dial(t, addr,
			grpc.WithPerRPCCredentials(iamgrpc.Credentials(caller, target)),
			grpc.WithChainStreamInterceptor(iamgrpc.StreamClientInterceptor(caller, target)),
		)
		first, _ := caller.Token(ctx, target)
		clock = clock.Add(time.Hour) // for the provider, the token has expired
		stream, err := client.WatchOrders(ctx, orderv1.NewText(""))
		if err == nil {
			_, err = stream.Recv()
		}
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expired token on a stream: %v", err)
		}
		if next, _ := caller.Token(ctx, target); next == first {
			t.Fatal("the refused token is still cached")
		}
	})
}

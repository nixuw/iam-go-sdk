// Package iamgrpc adapts the IAM SDK to gRPC.
//
// Provider side: server interceptors verify the bearer token of every call
// against the access rule declared for the method. Methods without a rule
// are refused.
//
//	rules := iamgrpc.Rules{
//		"/order.v1.OrderService/GetOrder": {
//			Scopes:     []string{"order.read"},
//			Principals: []string{iam.PrincipalService, iam.PrincipalUser},
//		},
//	}
//	srv := grpc.NewServer(
//		grpc.ChainUnaryInterceptor(iamgrpc.UnaryServerInterceptor(verifier, rules)),
//		grpc.ChainStreamInterceptor(iamgrpc.StreamServerInterceptor(verifier, rules)),
//	)
//	// in a handler: iamgrpc.Caller(ctx)
//
// Caller side: per-RPC credentials attach a token for one target to every
// call; the client interceptors renew a token the target refused.
//
//	conn, err := grpc.NewClient(addr,
//		grpc.WithTransportCredentials(tlsCredentials),
//		grpc.WithPerRPCCredentials(iamgrpc.Credentials(caller, target)),
//		grpc.WithChainUnaryInterceptor(iamgrpc.UnaryClientInterceptor(caller, target)),
//	)
//
// # Conventions on the wire
//
// The token travels in the "authorization" metadata as "Bearer <token>".
// Refusals map to status codes as follows, and the trailer metadata
// "www-authenticate" carries the same challenge an HTTP provider would send
// (RFC 6750):
//
//   - no token, or the token is invalid: Unauthenticated
//   - a permission is missing, the principal type is not accepted, or the
//     method has no access rule: PermissionDenied
//   - no signing key is available: Unavailable
package iamgrpc

import (
	"context"
	"errors"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	iam "github.com/nixuw/iam-go-sdk"
)

const (
	authorizationKey = "authorization"
	challengeKey     = "www-authenticate"
)

// Rules declares the access rule of each method, keyed by the full method
// name ("/package.Service/Method"). A method that is not listed, and is not
// declared public with WithPublicMethods, refuses every call.
type Rules map[string]iam.Rule

// ServerOption customises the server interceptors.
type ServerOption func(*serverOptions)

type serverOptions struct {
	public map[string]bool
}

// WithPublicMethods exempts methods from token verification, for example
// "/grpc.health.v1.Health/Check". Calls to them reach the handler without a
// caller identity.
func WithPublicMethods(methods ...string) ServerOption {
	return func(o *serverOptions) {
		for _, m := range methods {
			o.public[m] = true
		}
	}
}

type guard struct {
	verifier *iam.Verifier
	rules    Rules
	public   map[string]bool
}

func newGuard(v *iam.Verifier, rules Rules, opts []ServerOption) *guard {
	o := serverOptions{public: map[string]bool{}}
	for _, opt := range opts {
		opt(&o)
	}
	return &guard{verifier: v, rules: rules, public: o.public}
}

// check verifies the call. It returns the context for the handler, or the
// status error to answer with and the challenge to put in the trailer.
func (g *guard) check(ctx context.Context, method string) (context.Context, metadata.MD, error) {
	if g.public[method] {
		return ctx, nil, nil
	}
	authorization := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get(authorizationKey); len(values) > 0 {
			authorization = values[0]
		}
	}
	// An unlisted method has the zero Rule, which declares nothing and is
	// therefore refused once the token itself has been checked.
	id, err := g.verifier.VerifyHeader(ctx, authorization, g.rules[method])
	if err == nil {
		return iam.ContextWithIdentity(ctx, id), nil, nil
	}
	var be *iam.BearerError
	switch {
	case errors.As(err, &be):
		var trailer metadata.MD
		if challenge := be.WWWAuthenticate(); challenge != "" {
			trailer = metadata.Pairs(challengeKey, challenge)
		}
		message := be.Code
		if message == "" {
			message = "no bearer token"
		} else if be.Description != "" {
			message += ": " + be.Description
		}
		switch {
		case errors.Is(err, iam.ErrInsufficientScope):
			return nil, trailer, status.Error(codes.PermissionDenied, message)
		case errors.Is(err, iam.ErrUnavailable):
			return nil, trailer, status.Error(codes.Unavailable, message)
		default:
			return nil, trailer, status.Error(codes.Unauthenticated, message)
		}
	case errors.Is(err, iam.ErrDenied):
		// The application's own decision: keep its status if it gave one.
		if s, ok := statusIn(err); ok {
			return nil, nil, s.Err()
		}
		return nil, nil, status.Error(codes.PermissionDenied, "the application refused this caller")
	default:
		return nil, nil, status.FromContextError(err).Err()
	}
}

// statusIn finds a gRPC status in an error joined with others.
func statusIn(err error) (*status.Status, bool) {
	var holder interface{ GRPCStatus() *status.Status }
	if errors.As(err, &holder) {
		return holder.GRPCStatus(), true
	}
	return nil, false
}

// UnaryServerInterceptor verifies unary calls. Handlers read the caller
// with Caller.
func UnaryServerInterceptor(v *iam.Verifier, rules Rules, opts ...ServerOption) grpc.UnaryServerInterceptor {
	g := newGuard(v, rules, opts)
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx2, trailer, err := g.check(ctx, info.FullMethod)
		if err != nil {
			if trailer != nil {
				_ = grpc.SetTrailer(ctx, trailer)
			}
			return nil, err
		}
		return handler(ctx2, req)
	}
}

// StreamServerInterceptor verifies streaming calls when the stream is
// opened. Handlers read the caller with Caller(stream.Context()).
func StreamServerInterceptor(v *iam.Verifier, rules Rules, opts ...ServerOption) grpc.StreamServerInterceptor {
	g := newGuard(v, rules, opts)
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, trailer, err := g.check(ss.Context(), info.FullMethod)
		if err != nil {
			if trailer != nil {
				ss.SetTrailer(trailer)
			}
			return err
		}
		return handler(srv, &serverStream{ServerStream: ss, ctx: ctx})
	}
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStream) Context() context.Context { return s.ctx }

// Caller returns the verified caller of a call that passed a server
// interceptor, or nil (public method).
func Caller(ctx context.Context) *iam.Identity { return iam.IdentityFromContext(ctx) }

// Credentials returns per-RPC credentials that attach a token for the
// target to every call on a connection. The connection is thereby bound to
// that one target. Tokens are only sent over a secure transport unless
// CallerConfig.AllowInsecureTransport is set.
func Credentials(c *iam.Caller, t iam.Target) credentials.PerRPCCredentials {
	return &perRPC{caller: c, target: t}
}

type perRPC struct {
	caller *iam.Caller
	target iam.Target
}

// sentKey marks a context in which the token attached to the call is to be
// recorded, for the client interceptors.
type sentKey struct{}

type sentToken struct {
	mu    sync.Mutex
	value string
}

func (s *sentToken) set(token string) {
	s.mu.Lock()
	s.value = token
	s.mu.Unlock()
}

func (s *sentToken) get() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value
}

func (p *perRPC) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	token, err := p.caller.Token(ctx, p.target)
	if err != nil {
		return nil, err
	}
	if sent, ok := ctx.Value(sentKey{}).(*sentToken); ok {
		sent.set(token)
	}
	return map[string]string{authorizationKey: "Bearer " + token}, nil
}

func (p *perRPC) RequireTransportSecurity() bool { return !p.caller.InsecureTransportAllowed() }

// UnaryClientInterceptor handles a target that refuses the token of a unary
// call with Unauthenticated: the cached token is dropped and the call is
// repeated once with a new token. A unary call is safe to repeat because the
// target refused it before running it. PermissionDenied is never retried: it
// is a matter of grants. Use it together with Credentials for the same
// target.
func UnaryClientInterceptor(c *iam.Caller, t iam.Target) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		sent := &sentToken{}
		err := invoker(context.WithValue(ctx, sentKey{}, sent), method, req, reply, cc, opts...)
		refused := sent.get()
		if status.Code(err) != codes.Unauthenticated || refused == "" {
			return err
		}
		c.Invalidate(t, refused)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// StreamClientInterceptor drops the cached token when the target refuses
// the token of a streaming call with Unauthenticated, so that the next call
// obtains a new one. A stream is not repeated automatically.
func StreamClientInterceptor(c *iam.Caller, t iam.Target) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		sent := &sentToken{}
		drop := func(err error) {
			if refused := sent.get(); status.Code(err) == codes.Unauthenticated && refused != "" {
				c.Invalidate(t, refused)
			}
		}
		cs, err := streamer(context.WithValue(ctx, sentKey{}, sent), desc, cc, method, opts...)
		if err != nil {
			drop(err)
			return nil, err
		}
		return &clientStream{ClientStream: cs, drop: drop}, nil
	}
}

type clientStream struct {
	grpc.ClientStream
	drop func(error)
}

func (s *clientStream) RecvMsg(m any) error {
	err := s.ClientStream.RecvMsg(m)
	if err != nil {
		s.drop(err)
	}
	return err
}

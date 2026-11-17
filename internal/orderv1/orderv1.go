// Package orderv1 is a small gRPC service, order.v1.OrderService, written by
// hand in the shape protoc-gen-go-grpc would generate. The tests and the
// examples of this module use it so that neither needs protoc. In a real
// application this package is generated code.
package orderv1

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Full method names, as used in access rules.
const (
	GetOrderMethod    = "/order.v1.OrderService/GetOrder"
	CreateOrderMethod = "/order.v1.OrderService/CreateOrder"
	CancelOrderMethod = "/order.v1.OrderService/CancelOrder"
	WatchOrdersMethod = "/order.v1.OrderService/WatchOrders"
)

// Text is the only message type of the service: one string.
type Text = wrapperspb.StringValue

// NewText wraps a string in a message.
func NewText(s string) *Text { return wrapperspb.String(s) }

// OrderServiceServer is the server API.
type OrderServiceServer interface {
	GetOrder(context.Context, *Text) (*Text, error)
	CreateOrder(context.Context, *Text) (*Text, error)
	CancelOrder(context.Context, *Text) (*Text, error)
	WatchOrders(*Text, grpc.ServerStreamingServer[Text]) error
}

// UnimplementedOrderServiceServer answers every method with Unimplemented.
type UnimplementedOrderServiceServer struct{}

func (UnimplementedOrderServiceServer) GetOrder(context.Context, *Text) (*Text, error) {
	return nil, status.Error(codes.Unimplemented, "method GetOrder not implemented")
}

func (UnimplementedOrderServiceServer) CreateOrder(context.Context, *Text) (*Text, error) {
	return nil, status.Error(codes.Unimplemented, "method CreateOrder not implemented")
}

func (UnimplementedOrderServiceServer) CancelOrder(context.Context, *Text) (*Text, error) {
	return nil, status.Error(codes.Unimplemented, "method CancelOrder not implemented")
}

func (UnimplementedOrderServiceServer) WatchOrders(*Text, grpc.ServerStreamingServer[Text]) error {
	return status.Error(codes.Unimplemented, "method WatchOrders not implemented")
}

// RegisterOrderServiceServer registers the service on a gRPC server.
func RegisterOrderServiceServer(s grpc.ServiceRegistrar, srv OrderServiceServer) {
	s.RegisterService(&serviceDesc, srv)
}

func unary(method string, call func(OrderServiceServer, context.Context, *Text) (*Text, error)) grpc.MethodDesc {
	return grpc.MethodDesc{
		MethodName: method[len("/order.v1.OrderService/"):],
		Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
			in := new(Text)
			if err := dec(in); err != nil {
				return nil, err
			}
			if interceptor == nil {
				return call(srv.(OrderServiceServer), ctx, in)
			}
			info := &grpc.UnaryServerInfo{Server: srv, FullMethod: method}
			return interceptor(ctx, in, info, func(ctx context.Context, req any) (any, error) {
				return call(srv.(OrderServiceServer), ctx, req.(*Text))
			})
		},
	}
}

var serviceDesc = grpc.ServiceDesc{
	ServiceName: "order.v1.OrderService",
	HandlerType: (*OrderServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		unary(GetOrderMethod, OrderServiceServer.GetOrder),
		unary(CreateOrderMethod, OrderServiceServer.CreateOrder),
		unary(CancelOrderMethod, OrderServiceServer.CancelOrder),
	},
	Streams: []grpc.StreamDesc{{
		StreamName:    "WatchOrders",
		ServerStreams: true,
		Handler: func(srv any, stream grpc.ServerStream) error {
			in := new(Text)
			if err := stream.RecvMsg(in); err != nil {
				return err
			}
			return srv.(OrderServiceServer).WatchOrders(in, &grpc.GenericServerStream[Text, Text]{ServerStream: stream})
		},
	}},
	Metadata: "order/v1/order.proto",
}

// OrderServiceClient is the client API.
type OrderServiceClient interface {
	GetOrder(ctx context.Context, in *Text, opts ...grpc.CallOption) (*Text, error)
	CreateOrder(ctx context.Context, in *Text, opts ...grpc.CallOption) (*Text, error)
	CancelOrder(ctx context.Context, in *Text, opts ...grpc.CallOption) (*Text, error)
	WatchOrders(ctx context.Context, in *Text, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Text], error)
}

type orderServiceClient struct{ cc grpc.ClientConnInterface }

// NewOrderServiceClient returns a client for the service.
func NewOrderServiceClient(cc grpc.ClientConnInterface) OrderServiceClient {
	return &orderServiceClient{cc: cc}
}

func (c *orderServiceClient) invoke(ctx context.Context, method string, in *Text, opts []grpc.CallOption) (*Text, error) {
	out := new(Text)
	if err := c.cc.Invoke(ctx, method, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *orderServiceClient) GetOrder(ctx context.Context, in *Text, opts ...grpc.CallOption) (*Text, error) {
	return c.invoke(ctx, GetOrderMethod, in, opts)
}

func (c *orderServiceClient) CreateOrder(ctx context.Context, in *Text, opts ...grpc.CallOption) (*Text, error) {
	return c.invoke(ctx, CreateOrderMethod, in, opts)
}

func (c *orderServiceClient) CancelOrder(ctx context.Context, in *Text, opts ...grpc.CallOption) (*Text, error) {
	return c.invoke(ctx, CancelOrderMethod, in, opts)
}

func (c *orderServiceClient) WatchOrders(ctx context.Context, in *Text, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Text], error) {
	stream, err := c.cc.NewStream(ctx, &serviceDesc.Streams[0], WatchOrdersMethod, opts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[Text, Text]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

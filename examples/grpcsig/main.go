// Example grpcsig shows per-message proofs of origin over gRPC: the client
// interceptor mints a token per unary call binding the full method and the
// request message, the server interceptor verifies it offline against the
// operator public key, and a captured token fails when replayed at another
// method or with a tampered message. Runs self-contained over an in-memory
// connection.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/nats-io/nkeys"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpccreds "google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"valiss.dev/valiss"
	"valiss.dev/valiss/contrib/grpcsig"
	"valiss.dev/valiss/creds"
)

func main() {
	// Operator side: the trust anchor plus a tenant account and a delegated
	// user for the emitting service, all stamped with the domain epoch.
	const epoch = 1
	operator, err := nkeys.CreateOperator()
	check(err)
	operatorPub, err := operator.PublicKey()
	check(err)
	account, err := nkeys.CreateAccount()
	check(err)
	accountPub, err := account.PublicKey()
	check(err)
	user, err := nkeys.CreateUser()
	check(err)
	userPub, err := user.PublicKey()
	check(err)
	userSeed, err := user.Seed()
	check(err)

	accountToken, err := valiss.IssueAccount(operator, accountPub, valiss.WithName("acme"),
		valiss.WithEpoch(epoch), valiss.WithTTL(time.Hour))
	check(err)
	userToken, err := valiss.IssueUser(account, userPub, valiss.WithName("event-emitter"),
		valiss.WithEpoch(epoch), valiss.WithTTL(time.Hour))
	check(err)

	// Server side: the operator public key is all the interceptor needs.
	// logOrigin shows a handler-side interceptor reading the verified claims.
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(
		grpcsig.UnaryServerInterceptor(operatorPub), logOrigin))
	healthpb.RegisterHealthServer(srv, health.NewServer())

	lis := bufconn.Listen(1 << 20)
	go func() { check(srv.Serve(lis)) }()
	defer srv.Stop()

	// Client side: bundle creds (chain tokens + user seed) drive the client
	// interceptor, which mints one short-lived proof per call.
	bundle := creds.Creds{AccountToken: accountToken, UserToken: userToken, Seed: userSeed}
	ci, err := grpcsig.UnaryClientInterceptor(bundle)
	check(err)
	conn := dial(lis, grpc.WithUnaryInterceptor(ci))
	defer conn.Close()

	resp, err := healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{})
	check(err)
	fmt.Println("signed call accepted as expected, health status:", resp.Status)

	// An unsigned call carries no proof and is rejected.
	bare := dial(lis)
	defer bare.Close()
	_, err = healthpb.NewHealthClient(bare).Check(context.Background(), &healthpb.HealthCheckRequest{})
	if status.Code(err) != codes.Unauthenticated {
		log.Fatalf("expected Unauthenticated for the unsigned call, got: %v", err)
	}
	fmt.Printf("unsigned call rejected as expected: %s (%s)\n",
		status.Code(err), status.Convert(err).Message())

	// A captured token is bound to its method: replayed at another method it
	// fails the audience check, and with a different message the checksum.
	var captured string
	tapCI, err := grpcsig.UnaryClientInterceptor(bundle)
	check(err)
	tap := dial(lis, grpc.WithChainUnaryInterceptor(tapCI, captureToken(&captured)))
	defer tap.Close()
	_, err = healthpb.NewHealthClient(tap).Check(context.Background(), &healthpb.HealthCheckRequest{})
	check(err)

	replay := metadata.AppendToOutgoingContext(context.Background(), valiss.HeaderMessageToken, captured)
	err = bare.Invoke(replay, healthpb.Health_List_FullMethodName, &healthpb.HealthListRequest{}, &healthpb.HealthListResponse{})
	if status.Code(err) != codes.Unauthenticated {
		log.Fatalf("expected Unauthenticated for the cross-method replay, got: %v", err)
	}
	fmt.Printf("cross-method replay rejected as expected: %s (%s)\n",
		status.Code(err), status.Convert(err).Message())

	err = bare.Invoke(replay, healthpb.Health_Check_FullMethodName,
		&healthpb.HealthCheckRequest{Service: "tampered"}, &healthpb.HealthCheckResponse{})
	if status.Code(err) != codes.Unauthenticated {
		log.Fatalf("expected Unauthenticated for the tampered message, got: %v", err)
	}
	fmt.Printf("tampered message rejected as expected: %s (%s)\n",
		status.Code(err), status.Convert(err).Message())
}

func dial(lis *bufconn.Listener, opts ...grpc.DialOption) *grpc.ClientConn {
	conn, err := grpc.NewClient("passthrough:///bufnet",
		append([]grpc.DialOption{
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(grpccreds.NewCredentials()),
		}, opts...)...,
	)
	check(err)
	return conn
}

// captureToken records the minted message token so the demo can replay it.
func captureToken(dst *string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if md, ok := metadata.FromOutgoingContext(ctx); ok {
			if v := md.Get(valiss.HeaderMessageToken); len(v) > 0 {
				*dst = v[0]
			}
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// logOrigin shows how a handler-side interceptor reads the verified message
// claims for attribution.
func logOrigin(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if c, ok := valiss.MessageFromContext(ctx); ok {
		log.Printf("message from tenant %q, user %q at %s", c.Account.Name, c.User.Name, info.FullMethod)
	}
	return handler(ctx, req)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

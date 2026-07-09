// Example grpcauth shows the full tenant-auth wiring for gRPC: an operator
// issues a scoped account token, the server installs the auth interceptors,
// and the client attaches the credential to every call. It then demos the
// user level: the account delegates a narrower scope to an end user, who
// calls with the token chain. Runs self-contained over an in-memory
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
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/mikluko/valiss/pkg/creds"
	"github.com/mikluko/valiss/pkg/grpcauth"
	"github.com/mikluko/valiss/pkg/token"
)

func main() {
	// Operator side: mint the trust anchor, a tenant account key, and a
	// scoped account token. In production the valiss CLI does this and hands
	// the client a creds file (see pkg/creds).
	operator, err := nkeys.CreateOperator()
	check(err)
	operatorPub, err := operator.PublicKey()
	check(err)
	account, err := nkeys.CreateAccount()
	check(err)
	accountPub, err := account.PublicKey()
	check(err)
	accountSeed, err := account.Seed()
	check(err)

	checkScope := grpcauth.ScopeForMethod(healthpb.Health_Check_FullMethodName)
	listScope := grpcauth.ScopeForMethod(healthpb.Health_List_FullMethodName)
	tok, err := token.Issue(operator, "acme", accountPub, []string{checkScope, listScope}, token.WithTTL(time.Hour))
	check(err)
	claims, err := token.Verify(tok, operatorPub)
	check(err)

	// Server side: the operator public key and the allowlist are all the
	// server needs; it never sees any seeds.
	auth := grpcauth.NewAuthenticator(
		token.NewVerifier(operatorPub, token.NewStaticAllowlist(claims.ID)),
		grpcauth.WithMethodScope(),
	)
	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(auth.UnaryInterceptor(), logTenant),
		grpc.StreamInterceptor(auth.StreamInterceptor()),
	)
	healthpb.RegisterHealthServer(srv, health.NewServer())

	lis := bufconn.Listen(1 << 20)
	go func() { check(srv.Serve(lis)) }()
	defer srv.Stop()

	// Client side, account level: per-RPC credentials sign every call with
	// the account seed. AllowInsecure only because the in-memory pipe has no
	// TLS.
	conn := dial(lis, creds.Creds{AccountToken: tok, Seed: accountSeed})
	defer conn.Close()

	resp, err := healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{})
	check(err)
	fmt.Println("account call allowed as expected, health status:", resp.Status)

	// User level: the account delegates only the Check method to alice. Her
	// credential carries the token chain and her own fresh key.
	user, err := nkeys.CreateUser()
	check(err)
	userPub, err := user.PublicKey()
	check(err)
	userSeed, err := user.Seed()
	check(err)
	userTok, err := token.IssueUser(account, "alice", userPub, []string{checkScope}, token.WithTTL(time.Hour))
	check(err)

	userConn := dial(lis, creds.Creds{AccountToken: tok, UserToken: userTok, Seed: userSeed})
	defer userConn.Close()

	resp, err = healthpb.NewHealthClient(userConn).Check(context.Background(), &healthpb.HealthCheckRequest{})
	check(err)
	fmt.Println("user call within delegated scope allowed, health status:", resp.Status)

	// A call outside the user's delegated scope is denied, although the
	// account itself holds it.
	_, err = healthpb.NewHealthClient(userConn).List(context.Background(), &healthpb.HealthListRequest{})
	if status.Code(err) != codes.PermissionDenied {
		log.Fatalf("expected PermissionDenied for the out-of-scope user call, got: %v", err)
	}
	fmt.Printf("out-of-scope user call denied as expected: %s (%s)\n",
		status.Code(err), status.Convert(err).Message())
}

func dial(lis *bufconn.Listener, b creds.Creds) *grpc.ClientConn {
	c, err := grpcauth.NewCredentials(b)
	check(err)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(grpccreds.NewCredentials()),
		grpc.WithPerRPCCredentials(c.AllowInsecure()),
	)
	check(err)
	return conn
}

// logTenant shows how a handler-side interceptor reads the authenticated
// identity for data segmentation.
func logTenant(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if claims, ok := token.TenantFromContext(ctx); ok {
		if claims.UserID != "" {
			log.Printf("tenant %q user %q calls %s", claims.TenantID, claims.UserID, info.FullMethod)
		} else {
			log.Printf("tenant %q calls %s", claims.TenantID, info.FullMethod)
		}
	}
	return handler(ctx, req)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

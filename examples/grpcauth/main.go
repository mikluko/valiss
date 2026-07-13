// Example grpcauth shows the full tenant-auth wiring for gRPC: an operator
// issues an account token, the server installs the auth interceptors, and
// the client attaches the credential to every call. It then demos the user
// level: the account delegates to an end user with a gRPC extension that
// permits only the Check method. Runs self-contained over an in-memory
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

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/contrib/grpcauth"
	"github.com/mikluko/valiss/creds"
)

func main() {
	// Operator side: mint the trust anchor, a tenant account key, and an
	// account token. In production the valiss CLI example does this and
	// hands the client a creds file (see the creds package).
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

	// Enforcement is fail-closed: every token must carry the gRPC extension,
	// and allow-all is the explicit wildcard.
	tok, err := valiss.Issue(operator, accountPub,
		valiss.WithName("acme"),
		valiss.WithExtension(grpcauth.Ext{Methods: []string{"*"}}),
		valiss.WithTTL(time.Hour),
	)
	check(err)
	claims, err := valiss.VerifyAccount(tok, operatorPub)
	check(err)

	// Server side: the operator public key and the allowlist are all the
	// server needs; it never sees any seeds.
	auth := grpcauth.NewAuthenticator(
		valiss.NewVerifier(operatorPub, valiss.NewStaticAllowlist(claims.ID)),
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
	// the account seed. The account token's wildcard extension opens every
	// method to it. AllowInsecure only because the in-memory pipe has no
	// TLS.
	conn := dial(lis, creds.Creds{AccountToken: tok, Seed: accountSeed})
	defer conn.Close()

	resp, err := healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{})
	check(err)
	fmt.Println("account call allowed as expected, health status:", resp.Status)

	// User level: the account delegates to alice with a gRPC extension that
	// permits only the Check method. Her credential carries the token chain
	// and her own fresh key.
	user, err := nkeys.CreateUser()
	check(err)
	userPub, err := user.PublicKey()
	check(err)
	userSeed, err := user.Seed()
	check(err)
	userTok, err := valiss.IssueUser(account, userPub,
		valiss.WithName("alice"),
		valiss.WithExtension(grpcauth.Ext{Methods: []string{healthpb.Health_Check_FullMethodName}}),
		valiss.WithTTL(time.Hour),
	)
	check(err)

	userConn := dial(lis, creds.Creds{AccountToken: tok, UserToken: userTok, Seed: userSeed})
	defer userConn.Close()

	resp, err = healthpb.NewHealthClient(userConn).Check(context.Background(), &healthpb.HealthCheckRequest{})
	check(err)
	fmt.Println("user call within the extension allowed, health status:", resp.Status)

	// A method outside the user's gRPC extension is denied, although the
	// account itself may call it.
	_, err = healthpb.NewHealthClient(userConn).List(context.Background(), &healthpb.HealthListRequest{})
	if status.Code(err) != codes.PermissionDenied {
		log.Fatalf("expected PermissionDenied for the out-of-extension user call, got: %v", err)
	}
	fmt.Printf("out-of-extension user call denied as expected: %s (%s)\n",
		status.Code(err), status.Convert(err).Message())
}

func dial(lis *bufconn.Listener, c creds.Creds) *grpc.ClientConn {
	rpcCreds, err := grpcauth.NewCredentials(c)
	check(err)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(grpccreds.NewCredentials()),
		grpc.WithPerRPCCredentials(rpcCreds.AllowInsecure()),
	)
	check(err)
	return conn
}

// logTenant shows how a handler-side interceptor reads the verified
// identity for data segmentation.
func logTenant(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if id, ok := valiss.IdentityFromContext(ctx); ok {
		if id.User != nil {
			log.Printf("tenant %q user %q calls %s", id.Account.Name, id.User.Name, info.FullMethod)
		} else {
			log.Printf("tenant %q calls %s", id.Account.Name, info.FullMethod)
		}
	}
	return handler(ctx, req)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

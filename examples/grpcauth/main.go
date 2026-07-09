// Example grpcauth shows the full tenant-auth wiring for gRPC: an issuer
// issues a scoped token, the server installs the auth interceptors, and the
// client attaches the credential to every call. Runs self-contained over an
// in-memory connection.
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

	"github.com/mikluko/valiss/pkg/grpcauth"
	"github.com/mikluko/valiss/pkg/token"
)

func main() {
	// Issuer side: mint the trust anchor, a tenant key, and a scoped token.
	// In production the valiss CLI does this and hands the client a creds
	// bundle (see pkg/creds).
	issuer, err := nkeys.CreateOperator()
	check(err)
	issuerPub, err := issuer.PublicKey()
	check(err)
	tenant, err := nkeys.CreateAccount()
	check(err)
	tenantPub, err := tenant.PublicKey()
	check(err)
	tenantSeed, err := tenant.Seed()
	check(err)

	scope := grpcauth.ScopeForMethod(healthpb.Health_Check_FullMethodName)
	tok, err := token.Issue(issuer, "acme", tenantPub, []string{scope}, time.Hour)
	check(err)
	claims, err := token.Verify(tok, issuerPub)
	check(err)

	// Server side: the issuer public key and the allowlist are all the
	// server needs; it never sees any seeds.
	auth := grpcauth.NewAuthenticator(
		token.NewVerifier(issuerPub, token.NewStaticAllowlist(claims.ID)),
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

	// Client side: per-RPC credentials sign every call with the tenant seed.
	// AllowInsecure only because the in-memory pipe has no TLS.
	creds, err := grpcauth.NewCredentials(tok, tenantSeed)
	check(err)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(grpccreds.NewCredentials()),
		grpc.WithPerRPCCredentials(creds.AllowInsecure()),
	)
	check(err)
	defer conn.Close()

	resp, err := healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{})
	check(err)
	fmt.Println("in-scope call allowed as expected, health status:", resp.Status)

	// A call outside the granted scope is denied.
	_, err = healthpb.NewHealthClient(conn).List(context.Background(), &healthpb.HealthListRequest{})
	if status.Code(err) != codes.PermissionDenied {
		log.Fatalf("expected PermissionDenied for the out-of-scope call, got: %v", err)
	}
	fmt.Printf("out-of-scope call denied as expected: %s (%s)\n",
		status.Code(err), status.Convert(err).Message())
}

// logTenant shows how a handler-side interceptor reads the authenticated
// tenant for data segmentation.
func logTenant(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if claims, ok := token.TenantFromContext(ctx); ok {
		log.Printf("tenant %q calls %s", claims.TenantID, info.FullMethod)
	}
	return handler(ctx, req)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

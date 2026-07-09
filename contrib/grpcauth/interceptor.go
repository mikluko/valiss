// Package grpcauth wires the tenant authentication scheme into gRPC: server
// interceptors that verify the per-request credential and enforce the gRPC
// extension claim (Ext), and a client per-RPC credential that attaches the
// credential. Handlers read the authenticated tenant with
// valiss.TenantFromContext.
package grpcauth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/mikluko/valiss"
)

// Authenticator verifies the per-request tenant credential and enforces the
// tokens' gRPC extensions.
type Authenticator struct {
	verifier *valiss.Verifier
}

func NewAuthenticator(verifier *valiss.Verifier) *Authenticator {
	return &Authenticator{verifier: verifier}
}

// authenticate verifies the credential and authorizes the method, returning
// the tenant-bearing context.
func (a *Authenticator) authenticate(ctx context.Context, fullMethod string) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing request metadata")
	}
	req := valiss.Request{
		AccountToken: first(md, valiss.HeaderAccountToken),
		UserToken:    first(md, valiss.HeaderUserToken),
		Timestamp:    first(md, valiss.HeaderTimestamp),
		Signature:    first(md, valiss.HeaderSignature),
	}
	if req.AccountToken == "" && req.UserToken == "" {
		return nil, status.Error(codes.Unauthenticated, "missing credentials")
	}
	claims, err := a.verifier.VerifyRequest(req)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if err := authorizeExt(claims, fullMethod); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	return valiss.ContextWithTenant(ctx, claims), nil
}

// UnaryInterceptor authenticates and authorizes unary RPCs.
func (a *Authenticator) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := a.authenticate(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamInterceptor authenticates and authorizes streaming RPCs.
func (a *Authenticator) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := a.authenticate(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &authStream{ServerStream: ss, ctx: ctx})
	}
}

// authStream carries the tenant-bearing context to the stream handler.
type authStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authStream) Context() context.Context { return s.ctx }

func first(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}

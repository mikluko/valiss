// Package grpcauth wires the tenant authentication scheme into gRPC: server
// interceptors that verify the per-request credential and a client per-RPC
// credential that attaches it. Handlers read the authenticated tenant with
// token.TenantFromContext.
package grpcauth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/mikluko/valiss/pkg/token"
)

// ScopeForMethod is the per-call scope a tenant must hold when method-scope
// enforcement is enabled: "call:" joined with the gRPC full method, e.g.
// "call:/example.v1.WidgetService/CreateWidget".
func ScopeForMethod(fullMethod string) string {
	return "call:" + fullMethod
}

// Authenticator verifies the per-request tenant credential and, optionally,
// per-method authorization.
type Authenticator struct {
	verifier       *token.Verifier
	scopeForMethod func(fullMethod string) string
}

// Option configures an Authenticator.
type Option func(*Authenticator)

// WithMethodScope requires the tenant to hold ScopeForMethod(fullMethod) for
// every call; without the scope the request is denied (PermissionDenied).
func WithMethodScope() Option {
	return func(a *Authenticator) { a.scopeForMethod = ScopeForMethod }
}

// WithScopeMapper requires a custom per-method scope instead of the default.
func WithScopeMapper(fn func(fullMethod string) string) Option {
	return func(a *Authenticator) { a.scopeForMethod = fn }
}

func NewAuthenticator(verifier *token.Verifier, opts ...Option) *Authenticator {
	a := &Authenticator{verifier: verifier}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// authenticate verifies the credential and authorizes the method, returning
// the tenant-bearing context.
func (a *Authenticator) authenticate(ctx context.Context, fullMethod string) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing request metadata")
	}
	cred := token.Credential{
		AccountToken: first(md, token.HeaderAccountToken),
		UserToken:    first(md, token.HeaderUserToken),
		Timestamp:    first(md, token.HeaderTimestamp),
		Signature:    first(md, token.HeaderSignature),
	}
	if cred.AccountToken == "" && cred.UserToken == "" {
		return nil, status.Error(codes.Unauthenticated, "missing credentials")
	}
	claims, err := a.verifier.VerifyCredential(cred)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if a.scopeForMethod != nil {
		scope := a.scopeForMethod(fullMethod)
		if !claims.Authorizes(scope) {
			return nil, status.Errorf(codes.PermissionDenied, "tenant lacks scope %q", scope)
		}
	}
	return token.ContextWithTenant(ctx, claims), nil
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

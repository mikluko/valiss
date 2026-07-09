package tokenator

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Metadata header keys carrying the tenant credential on each request.
const (
	MetadataToken     = "up2-tenant-token"
	MetadataTimestamp = "up2-tenant-timestamp"
	MetadataSignature = "up2-tenant-signature"
)

// DefaultSkew bounds request-timestamp drift and token-expiry slack.
const DefaultSkew = 2 * time.Minute

type tenantKey struct{}

// TenantFromContext returns the authenticated tenant claims a handler uses to
// segment data. The bool is false on unauthenticated contexts.
func TenantFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(tenantKey{}).(*Claims)
	return c, ok
}

// ScopeForMethod is the per-call scope a tenant must hold when method-scope
// enforcement is enabled: "call:" joined with the gRPC full method, e.g.
// "call:/up2.monitoring.v1beta8.SchedulerService/CreateCheckConfig".
func ScopeForMethod(fullMethod string) string {
	return "call:" + fullMethod
}

// Authenticator verifies the per-request tenant credential and, optionally,
// per-method authorization.
type Authenticator struct {
	operatorPubKey string
	allowlist      Allowlist
	skew           time.Duration
	now            func() time.Time
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

func NewAuthenticator(operatorPubKey string, allowlist Allowlist, opts ...Option) *Authenticator {
	a := &Authenticator{
		operatorPubKey: operatorPubKey,
		allowlist:      allowlist,
		skew:           DefaultSkew,
		now:            time.Now,
	}
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
	token := first(md, MetadataToken)
	timestamp := first(md, MetadataTimestamp)
	signature := first(md, MetadataSignature)
	if token == "" || timestamp == "" || signature == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant credential")
	}

	claims, err := Verify(token, a.operatorPubKey)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	now := a.now()
	if claims.Expired(now, a.skew) {
		return nil, status.Error(codes.Unauthenticated, "tenant token expired")
	}
	if !a.allowlist.Allowed(claims.ID) {
		return nil, status.Error(codes.Unauthenticated, "tenant token not recognized")
	}
	if err := VerifyRequest(claims.PubKey, timestamp, signature, now, a.skew); err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if a.scopeForMethod != nil {
		scope := a.scopeForMethod(fullMethod)
		if !claims.Authorizes(scope) {
			return nil, status.Errorf(codes.PermissionDenied, "tenant lacks scope %q", scope)
		}
	}
	return context.WithValue(ctx, tenantKey{}, claims), nil
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

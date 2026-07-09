package valiss

import "context"

type tenantKey struct{}

// ContextWithTenant returns a context carrying authenticated tenant claims.
// Transport middlewares call this after verification.
func ContextWithTenant(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, tenantKey{}, c)
}

// TenantFromContext returns the authenticated tenant claims a handler uses to
// segment data. The bool is false on unauthenticated contexts.
func TenantFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(tenantKey{}).(*Claims)
	return c, ok
}

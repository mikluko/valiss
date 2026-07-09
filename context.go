package valiss

import "context"

type identityKey struct{}

// ContextWithIdentity returns a context carrying the verified identity.
// Transport middlewares call this after verification.
func ContextWithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFromContext returns the verified identity a handler uses to
// segment data. The bool is false on unauthenticated contexts.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(*Identity)
	return id, ok
}

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

type messageKey struct{}

// ContextWithMessage returns a context carrying verified message claims.
// Receiving transports call this after VerifyMessage.
func ContextWithMessage(ctx context.Context, c *MessageClaims) context.Context {
	return context.WithValue(ctx, messageKey{}, c)
}

// MessageFromContext returns the verified message claims a handler uses to
// attribute an incoming message to its emitter. The bool is false when no
// message token was verified. Message claims prove origin only; they are
// not an identity and grant nothing.
func MessageFromContext(ctx context.Context) (*MessageClaims, bool) {
	c, ok := ctx.Value(messageKey{}).(*MessageClaims)
	return c, ok
}

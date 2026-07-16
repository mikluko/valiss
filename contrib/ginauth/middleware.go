// Package ginauth wires the tenant authentication scheme into Gin: a
// middleware that verifies the per-request credential and enforces the HTTP
// extension claim (httpauth.Ext), built on httpauth's verification core.
// Handlers read the verified identity with IdentityFrom (or
// valiss.IdentityFromContext on the request context). The client side is
// framework-agnostic: use httpauth.NewTransport.
package ginauth

import (
	"github.com/gin-gonic/gin"

	"valiss.dev/valiss"
	"valiss.dev/valiss/contrib/httpauth"
)

// NewMiddleware returns a Gin middleware that authenticates every request
// against the verifier and enforces the tokens' HTTP extensions,
// fail-closed: tokens without the extension are denied unless
// httpauth.AllowMissingExtension is passed. Unauthenticated requests are
// aborted with 401, requests outside an extension's bounds with 403.
func NewMiddleware(verifier *valiss.Verifier, opts ...httpauth.Option) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := httpauth.Authenticate(verifier, c.Request, opts...)
		if err != nil {
			c.String(httpauth.StatusOf(err), "%s", err.Error())
			c.Abort()
			return
		}
		c.Request = c.Request.WithContext(valiss.ContextWithIdentity(c.Request.Context(), id))
		c.Next()
	}
}

// IdentityFrom returns the verified identity for the request. The bool is
// false when the middleware did not authenticate the request.
func IdentityFrom(c *gin.Context) (*valiss.Identity, bool) {
	return valiss.IdentityFromContext(c.Request.Context())
}

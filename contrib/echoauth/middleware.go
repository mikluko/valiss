// Package echoauth wires the tenant authentication scheme into Echo: a
// middleware that verifies the per-request credential and enforces the HTTP
// extension claim (httpauth.Ext), built on httpauth's verification core.
// Handlers read the verified identity with IdentityFrom (or
// valiss.IdentityFromContext on the request context). The client side is
// framework-agnostic: use httpauth.NewTransport.
package echoauth

import (
	"github.com/labstack/echo/v4"

	"valiss.dev/valiss"
	"valiss.dev/valiss/contrib/httpauth"
)

// NewMiddleware returns an Echo middleware that authenticates every request
// against the verifier and enforces the tokens' HTTP extensions,
// fail-closed: tokens without the extension are denied unless
// httpauth.AllowMissingExtension is passed. Rejections surface as
// *echo.HTTPError — 401 for unauthenticated requests, 403 for requests
// outside an extension's bounds — so the app's error handler renders them.
func NewMiddleware(verifier *valiss.Verifier, opts ...httpauth.Option) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			id, err := httpauth.Authenticate(verifier, c.Request(), opts...)
			if err != nil {
				return echo.NewHTTPError(httpauth.StatusOf(err), err.Error())
			}
			r := c.Request()
			c.SetRequest(r.WithContext(valiss.ContextWithIdentity(r.Context(), id)))
			return next(c)
		}
	}
}

// IdentityFrom returns the verified identity for the request. The bool is
// false when the middleware did not authenticate the request.
func IdentityFrom(c echo.Context) (*valiss.Identity, bool) {
	return valiss.IdentityFromContext(c.Request().Context())
}

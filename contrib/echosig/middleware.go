// Package echosig wires per-message proofs of origin (valiss message
// tokens) into Echo: a middleware that verifies the token on every incoming
// request, built on httpsig's receiving core, including the receiving side
// of chain negotiation. Handlers read the verified claims with MessageFrom
// (or valiss.MessageFromContext on the request context). The emitting side
// is framework-agnostic: use httpsig.NewTransport.
package echosig

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	"valiss.dev/valiss"
	"valiss.dev/valiss/contrib/httpsig"
)

// NewMiddleware returns an Echo middleware that requires every request to
// carry a message token proving the origin of its exact body at this
// destination, verified against the operator public key (see
// httpsig.NewMiddleware). Rejections surface as *echo.HTTPError — 401 (400
// for an unreadable body) — answering chainless tokens with the
// valiss-chain: required response header so a negotiating transport
// retransmits with the chain.
func NewMiddleware(operatorPubKey string, opts ...httpsig.MiddlewareOption) echo.MiddlewareFunc {
	return handle(httpsig.NewReceiver(operatorPubKey, opts...))
}

// NewKeyringMiddleware is NewMiddleware for a receiver trusting several
// operators: each message verifies against the keyring entry its chain
// names, and handlers tell trust domains apart by MessageClaims.Operator.
func NewKeyringMiddleware(keyring *valiss.Keyring, opts ...httpsig.MiddlewareOption) echo.MiddlewareFunc {
	return handle(httpsig.NewKeyringReceiver(keyring, opts...))
}

func handle(rc *httpsig.Receiver) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, err := rc.Verify(c.Request())
			if err != nil {
				if errors.Is(err, valiss.ErrNoChain) {
					httpsig.RequireChain(c.Response().Header())
					return echo.NewHTTPError(http.StatusUnauthorized, "message token chain required")
				}
				return echo.NewHTTPError(httpsig.StatusOf(err), err.Error())
			}
			r := c.Request()
			c.SetRequest(r.WithContext(valiss.ContextWithMessage(r.Context(), claims)))
			return next(c)
		}
	}
}

// MessageFrom returns the verified message claims for the request. The bool
// is false when the middleware did not verify the request.
func MessageFrom(c echo.Context) (*valiss.MessageClaims, bool) {
	return valiss.MessageFromContext(c.Request().Context())
}

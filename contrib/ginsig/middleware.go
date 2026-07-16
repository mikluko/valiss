// Package ginsig wires per-message proofs of origin (valiss message tokens)
// into Gin: a middleware that verifies the token on every incoming request,
// built on httpsig's receiving core, including the receiving side of chain
// negotiation. Handlers read the verified claims with MessageFrom (or
// valiss.MessageFromContext on the request context). The emitting side is
// framework-agnostic: use httpsig.NewTransport.
package ginsig

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"valiss.dev/valiss"
	"valiss.dev/valiss/contrib/httpsig"
)

// NewMiddleware returns a Gin middleware that requires every request to
// carry a message token proving the origin of its exact body at this
// destination, verified against the operator public key (see
// httpsig.NewMiddleware). Failures abort with 401 (400 for an unreadable
// body), answering chainless tokens with the valiss-chain: required
// response header so a negotiating transport retransmits with the chain.
func NewMiddleware(operatorPubKey string, opts ...httpsig.MiddlewareOption) gin.HandlerFunc {
	return handle(httpsig.NewReceiver(operatorPubKey, opts...))
}

// NewKeyringMiddleware is NewMiddleware for a receiver trusting several
// operators: each message verifies against the keyring entry its chain
// names, and handlers tell trust domains apart by MessageClaims.Operator.
func NewKeyringMiddleware(keyring *valiss.Keyring, opts ...httpsig.MiddlewareOption) gin.HandlerFunc {
	return handle(httpsig.NewKeyringReceiver(keyring, opts...))
}

func handle(rc *httpsig.Receiver) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := rc.Verify(c.Request)
		if err != nil {
			if errors.Is(err, valiss.ErrNoChain) {
				httpsig.RequireChain(c.Writer.Header())
				c.String(http.StatusUnauthorized, "message token chain required")
			} else {
				c.String(httpsig.StatusOf(err), "%s", err.Error())
			}
			c.Abort()
			return
		}
		c.Request = c.Request.WithContext(valiss.ContextWithMessage(c.Request.Context(), claims))
		c.Next()
	}
}

// MessageFrom returns the verified message claims for the request. The bool
// is false when the middleware did not verify the request.
func MessageFrom(c *gin.Context) (*valiss.MessageClaims, bool) {
	return valiss.MessageFromContext(c.Request.Context())
}

// Package httpauth wires the tenant authentication scheme into net/http: a
// server middleware that verifies the per-request credential and enforces
// the HTTP extension claim (Ext), and a client http.RoundTripper that
// attaches the credential. Handlers read the verified identity with
// valiss.IdentityFromContext.
package httpauth

import (
	"net/http"

	"github.com/mikluko/valiss"
)

type middleware struct {
	verifier     *valiss.Verifier
	allowMissing bool
	next         http.Handler
}

// Option configures the middleware.
type Option func(*middleware)

// AllowMissingExtension accepts tokens that carry no HTTP extension,
// imposing no constraint on them. Without it every token in the chain must
// carry the extension. Use only when authorization is handled entirely
// outside the transport.
func AllowMissingExtension() Option {
	return func(m *middleware) { m.allowMissing = true }
}

// NewMiddleware returns a middleware that authenticates every request
// against the verifier and enforces the tokens' HTTP extensions,
// fail-closed: tokens without the extension are denied unless
// AllowMissingExtension is set. Unauthenticated requests get 401, requests
// outside an extension's bounds get 403.
func NewMiddleware(verifier *valiss.Verifier, opts ...Option) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		m := &middleware{verifier: verifier, next: next}
		for _, opt := range opts {
			opt(m)
		}
		return m
	}
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	nonce := r.Header.Get(valiss.HeaderNonce)
	req := valiss.Request{
		AccountToken: r.Header.Get(valiss.HeaderAccountToken),
		UserToken:    r.Header.Get(valiss.HeaderUserToken),
		Timestamp:    r.Header.Get(valiss.HeaderTimestamp),
		Signature:    r.Header.Get(valiss.HeaderSignature),
		Context:      requestContext(r, nonce),
		Nonce:        nonce,
	}
	if req.AccountToken == "" && req.UserToken == "" {
		http.Error(w, "missing credentials", http.StatusUnauthorized)
		return
	}
	id, err := m.verifier.VerifyRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := authorizeExt(id, r, m.allowMissing); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	m.next.ServeHTTP(w, r.WithContext(valiss.ContextWithIdentity(r.Context(), id)))
}

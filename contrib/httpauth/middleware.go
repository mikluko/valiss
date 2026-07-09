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
	verifier *valiss.Verifier
	next     http.Handler
}

// NewMiddleware returns a middleware that authenticates every request
// against the verifier and enforces the tokens' HTTP extensions.
// Unauthenticated requests get 401, requests outside an extension's bounds
// get 403.
func NewMiddleware(verifier *valiss.Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &middleware{verifier: verifier, next: next}
	}
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req := valiss.Request{
		AccountToken: r.Header.Get(valiss.HeaderAccountToken),
		UserToken:    r.Header.Get(valiss.HeaderUserToken),
		Timestamp:    r.Header.Get(valiss.HeaderTimestamp),
		Signature:    r.Header.Get(valiss.HeaderSignature),
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
	if err := authorizeExt(id, r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	m.next.ServeHTTP(w, r.WithContext(valiss.ContextWithIdentity(r.Context(), id)))
}

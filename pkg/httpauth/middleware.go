// Package httpauth wires the tenant authentication scheme into net/http: a
// server middleware that verifies the per-request credential and a client
// http.RoundTripper that attaches it. Handlers read the authenticated tenant
// with token.TenantFromContext.
package httpauth

import (
	"net/http"

	"github.com/mikluko/valiss/pkg/token"
)

// ScopeForRequest is the per-call scope a tenant must hold when path-scope
// enforcement is enabled: "call:" joined with the request path, e.g.
// "call:/v1/widgets".
func ScopeForRequest(r *http.Request) string {
	return "call:" + r.URL.Path
}

// Option configures the middleware.
type Option func(*middleware)

// WithPathScope requires the tenant to hold ScopeForRequest(r) for every
// request; without the scope the request is denied (403).
func WithPathScope() Option {
	return func(m *middleware) { m.scopeForRequest = ScopeForRequest }
}

// WithScopeMapper requires a custom per-request scope instead of the default.
func WithScopeMapper(fn func(*http.Request) string) Option {
	return func(m *middleware) { m.scopeForRequest = fn }
}

type middleware struct {
	verifier        *token.Verifier
	scopeForRequest func(*http.Request) string
	next            http.Handler
}

// NewMiddleware returns a middleware that authenticates every request against
// the verifier and, optionally, authorizes it per scope. Unauthenticated
// requests get 401, unauthorized ones 403.
func NewMiddleware(verifier *token.Verifier, opts ...Option) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		m := &middleware{verifier: verifier, next: next}
		for _, opt := range opts {
			opt(m)
		}
		return m
	}
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req := token.Request{
		AccountToken: r.Header.Get(token.HeaderAccountToken),
		UserToken:    r.Header.Get(token.HeaderUserToken),
		Timestamp:    r.Header.Get(token.HeaderTimestamp),
		Signature:    r.Header.Get(token.HeaderSignature),
	}
	if req.AccountToken == "" && req.UserToken == "" {
		http.Error(w, "missing credentials", http.StatusUnauthorized)
		return
	}
	claims, err := m.verifier.VerifyRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if m.scopeForRequest != nil {
		scope := m.scopeForRequest(r)
		if !claims.Authorizes(scope) {
			http.Error(w, "tenant lacks scope "+scope, http.StatusForbidden)
			return
		}
	}
	m.next.ServeHTTP(w, r.WithContext(token.ContextWithTenant(r.Context(), claims)))
}

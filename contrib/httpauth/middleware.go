// Package httpauth wires the tenant authentication scheme into net/http: a
// server middleware that verifies the per-request credential and enforces
// the HTTP extension claim (Ext), and a client http.RoundTripper that
// attaches the credential. Handlers read the verified identity with
// valiss.IdentityFromContext. Framework adapters (contrib/ginauth,
// contrib/echoauth) build on the same verification core via Authenticate.
package httpauth

import (
	"errors"
	"net/http"

	"valiss.dev/valiss"
)

type config struct {
	allowMissing bool
}

// Option configures the verification.
type Option func(*config)

// AllowMissingExtension accepts tokens that carry no HTTP extension,
// imposing no constraint on them. Without it every token in the chain must
// carry the extension. Use only when authorization is handled entirely
// outside the transport.
func AllowMissingExtension() Option {
	return func(c *config) { c.allowMissing = true }
}

// Error is the rejection returned by Authenticate: the cause plus the HTTP
// status it maps to — 401 for authentication failures, 403 for extension
// denials. Framework adapters read Status to abort with the right code;
// errors.Is/As reach the wrapped cause.
type Error struct {
	Status int
	Err    error
}

func (e *Error) Error() string { return e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }

// StatusOf maps an Authenticate rejection to its HTTP status. Unknown errors
// map to 401: verification failures must never widen access.
func StatusOf(err error) int {
	if aerr, ok := errors.AsType[*Error](err); ok {
		return aerr.Status
	}
	return http.StatusUnauthorized
}

// Authenticate extracts the valiss credential from r, verifies it against
// the verifier, and enforces the tokens' HTTP extensions fail-closed:
// tokens without the extension are denied unless AllowMissingExtension is
// set. It is the verification core behind NewMiddleware and the framework
// adapters. A non-nil error is always an *Error; StatusOf maps it to the
// response status.
func Authenticate(verifier *valiss.Verifier, r *http.Request, opts ...Option) (*valiss.Identity, error) {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}
	return authenticate(verifier, r, cfg)
}

func authenticate(verifier *valiss.Verifier, r *http.Request, cfg config) (*valiss.Identity, error) {
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
		return nil, &Error{Status: http.StatusUnauthorized, Err: errors.New("missing credentials")}
	}
	id, err := verifier.VerifyRequest(req)
	if err != nil {
		return nil, &Error{Status: http.StatusUnauthorized, Err: err}
	}
	if err := authorizeExt(id, r, cfg.allowMissing); err != nil {
		return nil, &Error{Status: http.StatusForbidden, Err: err}
	}
	return id, nil
}

type middleware struct {
	verifier *valiss.Verifier
	cfg      config
	next     http.Handler
}

// NewMiddleware returns a middleware that authenticates every request
// against the verifier and enforces the tokens' HTTP extensions,
// fail-closed: tokens without the extension are denied unless
// AllowMissingExtension is set. Unauthenticated requests get 401, requests
// outside an extension's bounds get 403.
func NewMiddleware(verifier *valiss.Verifier, opts ...Option) func(http.Handler) http.Handler {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return &middleware{verifier: verifier, cfg: cfg, next: next}
	}
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := authenticate(m.verifier, r, m.cfg)
	if err != nil {
		http.Error(w, err.Error(), StatusOf(err))
		return
	}
	m.next.ServeHTTP(w, r.WithContext(valiss.ContextWithIdentity(r.Context(), id)))
}

package httpsig

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"valiss.dev/valiss"
)

type middleware struct {
	verify     func(token string, opts ...valiss.VerifyMessageOption) (*valiss.MessageClaims, error)
	verifyOpts []valiss.VerifyMessageOption
	cache      valiss.ChainCache
	next       http.Handler
}

// MiddlewareOption configures NewMiddleware.
type MiddlewareOption func(*middleware)

// WithVerifyOptions passes extra options to every valiss.VerifyMessage
// call, e.g. valiss.WithOperatorPolicy to enforce the domain epoch or
// valiss.WithChainTokens to pin a single emitter's chain in configuration.
// A pinned chain takes precedence over negotiated chain material; the
// middleware's audience and payload bindings are applied after these
// options and cannot be weakened by them.
func WithVerifyOptions(opts ...valiss.VerifyMessageOption) MiddlewareOption {
	return func(m *middleware) { m.verifyOpts = append(m.verifyOpts, opts...) }
}

// WithChainCache stores negotiated chains between requests, so an emitter
// pays the chain retransmit once instead of on every message. Only chains
// that survived full verification are stored; an entry that later fails
// (e.g. after a domain rotation) is dropped and the chain re-negotiated.
// valiss.NewMemoryChainCache is a process-local implementation.
func WithChainCache(cache valiss.ChainCache) MiddlewareOption {
	return func(m *middleware) { m.cache = cache }
}

// NewMiddleware returns a middleware that requires every request to carry a
// message token (valiss-message-token header) proving the origin of its
// exact body at this destination: the token is verified against the
// operator public key with the audience pinned to the incoming host and
// path (Audience) and the checksum compared to the received bytes.
// Failures get 401. Handlers read the verified claims with
// valiss.MessageFromContext and the body as usual.
//
// The middleware speaks the receiving side of chain negotiation: detached
// chain headers (valiss-chain-account-token, valiss-chain-user-token) on
// the request supply the chain for a chainless token, and a chainless
// token whose chain is not otherwise known is rejected with the
// valiss-chain: required response header, asking the transport to
// retransmit with the chain attached. WithChainCache remembers negotiated
// chains so the retransmit happens once per emitter, not per message.
func NewMiddleware(operatorPubKey string, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	verify := func(token string, verifyOpts ...valiss.VerifyMessageOption) (*valiss.MessageClaims, error) {
		return valiss.VerifyMessage(token, operatorPubKey, verifyOpts...)
	}
	return newMiddleware(verify, opts)
}

// NewKeyringMiddleware is NewMiddleware for a receiver trusting several
// operators: each message verifies against the keyring entry its chain
// names (valiss.VerifyMessageKeyring), and handlers tell trust domains
// apart by MessageClaims.Operator.
func NewKeyringMiddleware(keyring *valiss.Keyring, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	verify := func(token string, verifyOpts ...valiss.VerifyMessageOption) (*valiss.MessageClaims, error) {
		return valiss.VerifyMessageKeyring(token, keyring, verifyOpts...)
	}
	return newMiddleware(verify, opts)
}

func newMiddleware(verify func(string, ...valiss.VerifyMessageOption) (*valiss.MessageClaims, error), opts []MiddlewareOption) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		m := &middleware{verify: verify, next: next}
		for _, opt := range opts {
			opt(m)
		}
		return m
	}
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get(valiss.HeaderMessageToken)
	if tok == "" {
		http.Error(w, "missing message token", http.StatusUnauthorized)
		return
	}
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading request body", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	// Resolve negotiated chain material: detached headers outrank the
	// cache; a pinned chain in the verify options outranks both (it is
	// applied later, so it wins inside VerifyMessage).
	chainAccount := r.Header.Get(valiss.HeaderChainAccountToken)
	chainUser := r.Header.Get(valiss.HeaderChainUserToken)
	detached := chainAccount != "" && chainUser != ""
	cached := false
	var cacheKey string
	if !detached && m.cache != nil {
		if c, err := valiss.Decode(tok); err == nil {
			cacheKey = c.Issuer
			chainAccount, chainUser, cached = m.cache.Get(cacheKey)
		}
	}

	verify := func(withChain bool) (*valiss.MessageClaims, error) {
		opts := make([]valiss.VerifyMessageOption, 0, len(m.verifyOpts)+3)
		if withChain {
			opts = append(opts, valiss.WithChainTokens(chainAccount, chainUser))
		}
		opts = append(opts, m.verifyOpts...)
		opts = append(opts, valiss.ExpectAudience(Audience(r)), valiss.WithPayload(body))
		return m.verify(tok, opts...)
	}

	claims, err := verify(detached || cached)
	if err != nil && cached {
		// Attribute the failure before evicting: without the cached chain a
		// self-contained token settles it on its own, and only a chainless
		// token leaves the cached entry as the suspect.
		claims, err = verify(false)
		if err == nil || errors.Is(err, valiss.ErrNoChain) {
			m.cache.Del(cacheKey)
		}
	}
	if err != nil {
		if errors.Is(err, valiss.ErrNoChain) {
			chainRequired(w)
		} else {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}
		return
	}
	if detached && m.cache != nil {
		m.cache.Put(claims.Subject, chainAccount, chainUser)
	}
	m.next.ServeHTTP(w, r.WithContext(valiss.ContextWithMessage(r.Context(), claims)))
}

// chainRequired rejects a request while asking the emitting transport to
// retransmit with its provenance chain attached.
func chainRequired(w http.ResponseWriter) {
	w.Header().Set(valiss.HeaderChain, valiss.ChainRequired)
	http.Error(w, "message token chain required", http.StatusUnauthorized)
}

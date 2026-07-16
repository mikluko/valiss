package httpsig

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"valiss.dev/valiss"
)

// Receiver is the receiving-side verification core behind NewMiddleware,
// shared by framework adapters (contrib/ginsig, contrib/echosig): message
// token extraction, body binding, chain-negotiation state, and
// verification over a plain *http.Request.
type Receiver struct {
	verify     func(token string, opts ...valiss.VerifyMessageOption) (*valiss.MessageClaims, error)
	verifyOpts []valiss.VerifyMessageOption
	cache      valiss.ChainCache
}

// MiddlewareOption configures the verification.
type MiddlewareOption func(*Receiver)

// WithVerifyOptions passes extra options to every valiss.VerifyMessage
// call, e.g. valiss.WithOperatorPolicy to enforce the domain epoch or
// valiss.WithChainTokens to pin a single emitter's chain in configuration.
// A pinned chain takes precedence over negotiated chain material; the
// middleware's audience and payload bindings are applied after these
// options and cannot be weakened by them.
func WithVerifyOptions(opts ...valiss.VerifyMessageOption) MiddlewareOption {
	return func(rc *Receiver) { rc.verifyOpts = append(rc.verifyOpts, opts...) }
}

// WithChainCache stores negotiated chains between requests, so an emitter
// pays the chain retransmit once instead of on every message. Only chains
// that survived full verification are stored; an entry that later fails
// (e.g. after a domain rotation) is dropped and the chain re-negotiated.
// valiss.NewMemoryChainCache is a process-local implementation.
func WithChainCache(cache valiss.ChainCache) MiddlewareOption {
	return func(rc *Receiver) { rc.cache = cache }
}

// Error is the rejection returned by Receiver.Verify: the cause plus the
// HTTP status it maps to — 400 for an unreadable body, 401 otherwise.
// errors.Is/As reach the wrapped cause, so valiss.ErrNoChain remains
// detectable for chain-negotiation signaling.
type Error struct {
	Status int
	Err    error
}

func (e *Error) Error() string { return e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }

// StatusOf maps a Verify rejection to its HTTP status. Unknown errors map
// to 401: verification failures must never widen access.
func StatusOf(err error) int {
	if verr, ok := errors.AsType[*Error](err); ok {
		return verr.Status
	}
	return http.StatusUnauthorized
}

// RequireChain stamps the chain-negotiation signal on response headers,
// asking the emitting transport to retransmit with its provenance chain
// attached. Framework adapters set it before rejecting when Verify fails
// with valiss.ErrNoChain; the net/http middleware does this internally.
func RequireChain(h http.Header) {
	h.Set(valiss.HeaderChain, valiss.ChainRequired)
}

// NewReceiver returns the verification core for receivers trusting a single
// operator. Most servers want NewMiddleware instead; framework adapters
// build on the Receiver directly.
func NewReceiver(operatorPubKey string, opts ...MiddlewareOption) *Receiver {
	verify := func(token string, verifyOpts ...valiss.VerifyMessageOption) (*valiss.MessageClaims, error) {
		return valiss.VerifyMessage(token, operatorPubKey, verifyOpts...)
	}
	return newReceiver(verify, opts)
}

// NewKeyringReceiver is NewReceiver for a receiver trusting several
// operators: each message verifies against the keyring entry its chain
// names (valiss.VerifyMessageKeyring), and handlers tell trust domains
// apart by MessageClaims.Operator.
func NewKeyringReceiver(keyring *valiss.Keyring, opts ...MiddlewareOption) *Receiver {
	verify := func(token string, verifyOpts ...valiss.VerifyMessageOption) (*valiss.MessageClaims, error) {
		return valiss.VerifyMessageKeyring(token, keyring, verifyOpts...)
	}
	return newReceiver(verify, opts)
}

func newReceiver(verify func(string, ...valiss.VerifyMessageOption) (*valiss.MessageClaims, error), opts []MiddlewareOption) *Receiver {
	rc := &Receiver{verify: verify}
	for _, opt := range opts {
		opt(rc)
	}
	return rc
}

// Verify checks that r carries a message token proving the origin of its
// exact body at this destination: the token is verified with the audience
// pinned to the incoming host and path (Audience) and the checksum compared
// to the received bytes. The body is read in full and restored, so handlers
// read it as usual. A non-nil error is always an *Error; StatusOf maps it
// to the response status, and a wrapped valiss.ErrNoChain means the caller
// must reject with RequireChain on the response headers so the emitter
// retransmits with its chain.
func (rc *Receiver) Verify(r *http.Request) (*valiss.MessageClaims, error) {
	tok := r.Header.Get(valiss.HeaderMessageToken)
	if tok == "" {
		return nil, &Error{Status: http.StatusUnauthorized, Err: errors.New("missing message token")}
	}
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, &Error{Status: http.StatusBadRequest, Err: errors.New("reading request body")}
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
	if !detached && rc.cache != nil {
		if c, err := valiss.Decode(tok); err == nil {
			cacheKey = c.Issuer
			chainAccount, chainUser, cached = rc.cache.Get(cacheKey)
		}
	}

	verify := func(withChain bool) (*valiss.MessageClaims, error) {
		opts := make([]valiss.VerifyMessageOption, 0, len(rc.verifyOpts)+3)
		if withChain {
			opts = append(opts, valiss.WithChainTokens(chainAccount, chainUser))
		}
		opts = append(opts, rc.verifyOpts...)
		opts = append(opts, valiss.ExpectAudience(Audience(r)), valiss.WithPayload(body))
		return rc.verify(tok, opts...)
	}

	claims, err := verify(detached || cached)
	if err != nil && cached {
		// Attribute the failure before evicting: without the cached chain a
		// self-contained token settles it on its own, and only a chainless
		// token leaves the cached entry as the suspect.
		claims, err = verify(false)
		if err == nil || errors.Is(err, valiss.ErrNoChain) {
			rc.cache.Del(cacheKey)
		}
	}
	if err != nil {
		return nil, &Error{Status: http.StatusUnauthorized, Err: err}
	}
	if detached && rc.cache != nil {
		rc.cache.Put(claims.Subject, chainAccount, chainUser)
	}
	return claims, nil
}

type middleware struct {
	rc   *Receiver
	next http.Handler
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
	return middlewareOf(NewReceiver(operatorPubKey, opts...))
}

// NewKeyringMiddleware is NewMiddleware for a receiver trusting several
// operators: each message verifies against the keyring entry its chain
// names (valiss.VerifyMessageKeyring), and handlers tell trust domains
// apart by MessageClaims.Operator.
func NewKeyringMiddleware(keyring *valiss.Keyring, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	return middlewareOf(NewKeyringReceiver(keyring, opts...))
}

func middlewareOf(rc *Receiver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &middleware{rc: rc, next: next}
	}
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims, err := m.rc.Verify(r)
	if err != nil {
		if errors.Is(err, valiss.ErrNoChain) {
			chainRequired(w)
		} else {
			http.Error(w, err.Error(), StatusOf(err))
		}
		return
	}
	m.next.ServeHTTP(w, r.WithContext(valiss.ContextWithMessage(r.Context(), claims)))
}

// chainRequired rejects a request while asking the emitting transport to
// retransmit with its provenance chain attached.
func chainRequired(w http.ResponseWriter) {
	RequireChain(w.Header())
	http.Error(w, "message token chain required", http.StatusUnauthorized)
}

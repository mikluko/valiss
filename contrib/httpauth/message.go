package httpauth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/creds"
)

// MessageAudience is the canonical destination identity of an HTTP request
// a message token is bound to: host and path, query excluded. The emitting
// transport (absolute URL) and the receiving middleware (Host header +
// path) must derive identical bytes, so the host is taken from r.Host with
// a fallback to the URL, and the scheme is excluded (unknowable behind TLS
// terminators).
func MessageAudience(r *http.Request) string {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return host + r.URL.Path
}

// MessageTransport is an http.RoundTripper that mints a fresh message token
// per outgoing request (valiss.IssueMessage): a proof of origin bound to the
// destination (MessageAudience) and the request body, carried in the
// valiss-message-token header, with the provenance chain embedded. The
// receiver verifies it offline with NewMessageMiddleware or
// valiss.VerifyMessage. Set it as (or wrap it around)
// http.Client.Transport on webhook emitters.
type MessageTransport struct {
	base         http.RoundTripper
	accountToken string
	userToken    string
	user         nkeys.KeyPair
	epoch        uint64
	ttl          time.Duration
}

// MessageTransportOption configures a MessageTransport.
type MessageTransportOption func(*MessageTransport)

// WithMessageTTL overrides the valiss.DefaultMessageTTL validity window of
// minted message tokens.
func WithMessageTTL(d time.Duration) MessageTransportOption {
	return func(t *MessageTransport) { t.ttl = d }
}

// NewMessageTransport builds an emitting transport from parsed creds, which
// must be a bundle holding the user seed: the account token, the user
// token, and the seed that signs the message tokens. The trust-domain epoch
// is taken from the chain tokens, which must agree on it. A nil base means
// http.DefaultTransport.
func NewMessageTransport(b creds.Creds, base http.RoundTripper, opts ...MessageTransportOption) (*MessageTransport, error) {
	user, epoch, err := messageMinter(b)
	if err != nil {
		return nil, err
	}
	t := &MessageTransport{
		base:         base,
		accountToken: b.AccountToken,
		userToken:    b.UserToken,
		user:         user,
		epoch:        epoch,
		ttl:          valiss.DefaultMessageTTL,
	}
	for _, opt := range opts {
		opt(t)
	}
	return t, nil
}

func (t *MessageTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// RoundTrippers must not mutate the caller's request.
	req = req.Clone(req.Context())
	body, err := drainBody(req)
	if err != nil {
		return nil, fmt.Errorf("valiss: message transport: read request body: %w", err)
	}
	tok, err := valiss.IssueMessage(t.user,
		valiss.WithAudience(MessageAudience(req)),
		valiss.WithChecksum(valiss.Checksum(body)),
		valiss.WithTTL(t.ttl),
		valiss.WithEpoch(t.epoch),
		valiss.WithChain(t.accountToken, t.userToken),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set(valiss.HeaderMessageToken, tok)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

var _ http.RoundTripper = (*MessageTransport)(nil)

// drainBody reads a request body in full and restores it (Body and GetBody)
// so the request remains sendable and retryable. A nil body is an empty
// payload.
func drainBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(req.Body)
	if closeErr := req.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	req.ContentLength = int64(len(body))
	return body, nil
}

type messageMiddleware struct {
	operatorPubKey string
	opts           []valiss.VerifyMessageOption
	next           http.Handler
}

// NewMessageMiddleware returns a middleware that requires every request to
// carry a message token (valiss-message-token header) proving the origin of
// its exact body at this destination: the token is verified against the
// operator public key with the audience pinned to the incoming host and
// path (MessageAudience) and the checksum compared to the received bytes.
// Failures get 401. Handlers read the verified claims with
// valiss.MessageFromContext and the body as usual.
//
// The audience and payload bindings are appended after opts, so they cannot
// be weakened; pass options like valiss.WithOperatorPolicy or
// valiss.WithChainTokens to tighten or supply out-of-band material. A
// message token proves origin only — this middleware authenticates the
// message, not a caller, and grants no identity.
func NewMessageMiddleware(operatorPubKey string, opts ...valiss.VerifyMessageOption) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &messageMiddleware{operatorPubKey: operatorPubKey, opts: opts, next: next}
	}
}

func (m *messageMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	opts := append(append([]valiss.VerifyMessageOption{}, m.opts...),
		valiss.ExpectAudience(MessageAudience(r)),
		valiss.WithPayload(body),
	)
	claims, err := valiss.VerifyMessage(tok, m.operatorPubKey, opts...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	m.next.ServeHTTP(w, r.WithContext(valiss.ContextWithMessage(r.Context(), claims)))
}

// messageMinter validates emitter creds and derives the mint parameters: the
// user keypair from the seed and the trust-domain epoch from the chain
// tokens, which must agree on it (VerifyMessage requires all levels to).
func messageMinter(b creds.Creds) (nkeys.KeyPair, uint64, error) {
	if b.AccountToken == "" || b.UserToken == "" || len(b.Seed) == 0 {
		return nil, 0, errors.New("valiss: message signing requires bundle creds: account token, user token, and seed")
	}
	user, err := nkeys.FromSeed(b.Seed)
	if err != nil {
		return nil, 0, fmt.Errorf("valiss: creds seed: %w", err)
	}
	accountIssuer, err := valiss.IssuerOf(b.AccountToken)
	if err != nil {
		return nil, 0, fmt.Errorf("valiss: creds account token: %w", err)
	}
	account, err := valiss.VerifyAccount(b.AccountToken, accountIssuer)
	if err != nil {
		return nil, 0, fmt.Errorf("valiss: creds account token: %w", err)
	}
	userClaims, err := valiss.VerifyUser(b.UserToken, account.Subject)
	if err != nil {
		return nil, 0, fmt.Errorf("valiss: creds user token: %w", err)
	}
	if account.Epoch != userClaims.Epoch {
		return nil, 0, fmt.Errorf("valiss: creds chain epochs disagree: account %d, user %d", account.Epoch, userClaims.Epoch)
	}
	return user, userClaims.Epoch, nil
}

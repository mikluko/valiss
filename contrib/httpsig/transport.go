package httpsig

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/creds"
)

// Transport is an http.RoundTripper that mints a fresh message token per
// outgoing request (valiss.IssueMessage): a proof of origin bound to the
// destination (Audience) and the request body, carried in the
// valiss-message-token header, with the provenance chain embedded. The
// receiver verifies it offline with NewMiddleware or valiss.VerifyMessage.
// Set it as (or wrap it around) http.Client.Transport on webhook emitters.
type Transport struct {
	base         http.RoundTripper
	accountToken string
	userToken    string
	user         nkeys.KeyPair
	epoch        uint64
	ttl          time.Duration
}

// TransportOption configures a Transport.
type TransportOption func(*Transport)

// WithTTL overrides the valiss.DefaultMessageTTL validity window of minted
// message tokens.
func WithTTL(d time.Duration) TransportOption {
	return func(t *Transport) { t.ttl = d }
}

// NewTransport builds an emitting transport from parsed creds, which must
// be a bundle holding the user seed: the account token, the user token, and
// the seed that signs the message tokens. The trust-domain epoch is taken
// from the chain tokens, which must agree on it. A nil base means
// http.DefaultTransport.
func NewTransport(b creds.Creds, base http.RoundTripper, opts ...TransportOption) (*Transport, error) {
	user, epoch, err := minter(b)
	if err != nil {
		return nil, err
	}
	t := &Transport{
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

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// RoundTrippers must not mutate the caller's request.
	req = req.Clone(req.Context())
	body, err := drainBody(req)
	if err != nil {
		return nil, fmt.Errorf("valiss: message transport: read request body: %w", err)
	}
	tok, err := valiss.IssueMessage(t.user,
		valiss.WithAudience(Audience(req)),
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

var _ http.RoundTripper = (*Transport)(nil)

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

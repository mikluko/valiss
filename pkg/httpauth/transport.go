package httpauth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/mikluko/valiss/pkg/token"
)

// Transport is an http.RoundTripper that attaches the tenant token and a
// fresh per-call signature to every request. Set it as (or wrap it around)
// http.Client.Transport.
type Transport struct {
	base   http.RoundTripper
	token  string
	tenant nkeys.KeyPair
	now    func() time.Time
}

// NewTransport builds a client transport from the issuer-signed token and
// the tenant seed that matches the token's bound key. A nil base means
// http.DefaultTransport.
func NewTransport(tok string, tenantSeed []byte, base http.RoundTripper) (*Transport, error) {
	tenant, err := nkeys.FromSeed(tenantSeed)
	if err != nil {
		return nil, fmt.Errorf("valiss: tenant seed: %w", err)
	}
	return &Transport{base: base, token: tok, tenant: tenant, now: time.Now}, nil
}

// NewBearerTransport builds a client transport that attaches the token alone,
// without per-request signatures; no seed is needed. The server accepts such
// requests only when the token grants token.ScopeBearer. A nil base means
// http.DefaultTransport.
func NewBearerTransport(tok string, base http.RoundTripper) *Transport {
	return &Transport{base: base, token: tok, now: time.Now}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// RoundTrippers must not mutate the caller's request.
	req = req.Clone(req.Context())
	req.Header.Set(token.HeaderToken, t.token)
	if t.tenant != nil {
		timestamp, signature, err := token.SignRequest(t.tenant, t.now())
		if err != nil {
			return nil, err
		}
		req.Header.Set(token.HeaderTimestamp, timestamp)
		req.Header.Set(token.HeaderSignature, signature)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

var _ http.RoundTripper = (*Transport)(nil)

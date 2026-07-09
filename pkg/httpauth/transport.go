package httpauth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/mikluko/valiss/pkg/creds"
	"github.com/mikluko/valiss/pkg/token"
)

// Transport is an http.RoundTripper that attaches the creds' tokens and,
// when the creds hold a seed, a fresh per-request signature. Creds without
// a seed are bearer credentials: the server accepts them only when the
// effective token grants token.ScopeBearer. Set it as (or wrap it around)
// http.Client.Transport.
type Transport struct {
	base      http.RoundTripper
	token     string
	userToken string
	subject   nkeys.KeyPair
	now       func() time.Time
}

// NewTransport builds a client transport from parsed creds: the tokens
// they carry and the seed matching the effective token's bound key (nil
// for bearer creds). A nil base means http.DefaultTransport.
func NewTransport(b creds.Creds, base http.RoundTripper) (*Transport, error) {
	t := &Transport{base: base, token: b.Token, userToken: b.UserToken, now: time.Now}
	if len(b.Seed) > 0 {
		subject, err := nkeys.FromSeed(b.Seed)
		if err != nil {
			return nil, fmt.Errorf("valiss: creds seed: %w", err)
		}
		t.subject = subject
	}
	return t, nil
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// RoundTrippers must not mutate the caller's request.
	req = req.Clone(req.Context())
	if t.token != "" {
		req.Header.Set(token.HeaderToken, t.token)
	}
	if t.userToken != "" {
		req.Header.Set(token.HeaderUserToken, t.userToken)
	}
	if t.subject != nil {
		timestamp, signature, err := token.SignRequest(t.subject, t.now())
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

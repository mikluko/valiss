package httpauth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/nats-io/nkeys"

	"valiss.dev/valiss"
	"valiss.dev/valiss/creds"
)

// Transport is an http.RoundTripper that attaches the creds' tokens and,
// when the creds hold a seed, a fresh per-request signature. Creds without
// a seed are bearer credentials: the server accepts them only when the
// effective token is a bearer user token. Set it as (or wrap it around)
// http.Client.Transport.
type Transport struct {
	base         http.RoundTripper
	accountToken string
	userToken    string
	subject      nkeys.KeyPair
	now          func() time.Time
	nonce        func() string
}

// TransportOption configures a Transport.
type TransportOption func(*Transport)

// WithNonce attaches a fresh per-request nonce (folded into the signature)
// so a server built with valiss.WithReplayCache can suppress replays. Enable
// it on the client whenever the server has a replay cache.
func WithNonce() TransportOption {
	return func(t *Transport) { t.nonce = valiss.NewNonce }
}

// NewTransport builds a client transport from parsed creds: the tokens
// they carry and the seed matching the effective token's bound key (nil
// for bearer creds). A nil base means http.DefaultTransport.
func NewTransport(b creds.Creds, base http.RoundTripper, opts ...TransportOption) (*Transport, error) {
	t := &Transport{base: base, accountToken: b.AccountToken, userToken: b.UserToken, now: time.Now}
	if len(b.Seed) > 0 {
		subject, err := nkeys.FromSeed(b.Seed)
		if err != nil {
			return nil, fmt.Errorf("valiss: creds seed: %w", err)
		}
		t.subject = subject
	}
	for _, opt := range opts {
		opt(t)
	}
	return t, nil
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// RoundTrippers must not mutate the caller's request.
	req = req.Clone(req.Context())
	if t.accountToken != "" {
		req.Header.Set(valiss.HeaderAccountToken, t.accountToken)
	}
	if t.userToken != "" {
		req.Header.Set(valiss.HeaderUserToken, t.userToken)
	}
	if t.subject != nil {
		nonce := ""
		if t.nonce != nil {
			nonce = t.nonce()
			req.Header.Set(valiss.HeaderNonce, nonce)
		}
		timestamp, signature, err := valiss.SignRequest(t.subject, t.now(), requestContext(req, nonce))
		if err != nil {
			return nil, err
		}
		req.Header.Set(valiss.HeaderTimestamp, timestamp)
		req.Header.Set(valiss.HeaderSignature, signature)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

var _ http.RoundTripper = (*Transport)(nil)

// requestContext is the canonical request-context bytes the signature is
// bound to: method, host, path, and the per-request nonce. The client
// (RoundTrip, absolute URL) and the server (ServeHTTP, Host header + path)
// must derive identical bytes, so the host is taken from r.Host with a
// fallback to the URL, and the query is excluded. Method and path are
// matched exactly. The nonce is empty when replay suppression is not in use.
func requestContext(r *http.Request, nonce string) []byte {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return []byte("http\n" + r.Method + "\n" + host + "\n" + r.URL.Path + "\n" + nonce)
}

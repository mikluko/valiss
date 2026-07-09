package token

import (
	"errors"
	"time"
)

// Header field names carrying the tenant credential on each request. Used as
// gRPC metadata keys and HTTP header names alike.
const (
	HeaderToken     = "valiss-tenant-token"
	HeaderTimestamp = "valiss-tenant-timestamp"
	HeaderSignature = "valiss-tenant-signature"
)

// ScopeBearer is the scope a token must carry for the tenant to make bearer
// requests: the token alone, without the per-request signature. Bearer tokens
// are replayable until they expire or leave the allowlist, so grant this only
// to tenants that cannot sign (no seed distribution) and pair it with TLS and
// short TTLs.
const ScopeBearer = "bearer"

// Verifier checks the full per-request credential triple: token signature and
// issuer, expiry, allowlist membership, and the request signature within the
// skew window. Requests without a signature pass only when the token grants
// ScopeBearer. Transport layers (gRPC interceptor, HTTP middleware) wrap it
// with header extraction and error mapping.
type Verifier struct {
	issuerPubKey string
	allowlist    Allowlist
	skew         time.Duration
	now          func() time.Time
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithSkew overrides the DefaultSkew window for timestamp drift and token
// expiry slack.
func WithSkew(d time.Duration) VerifierOption {
	return func(v *Verifier) { v.skew = d }
}

// WithClock overrides the time source; for tests.
func WithClock(now func() time.Time) VerifierOption {
	return func(v *Verifier) { v.now = now }
}

func NewVerifier(issuerPubKey string, allowlist Allowlist, opts ...VerifierOption) *Verifier {
	v := &Verifier{
		issuerPubKey: issuerPubKey,
		allowlist:    allowlist,
		skew:         DefaultSkew,
		now:          time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// VerifyCredential authenticates a request credential and returns the tenant
// claims. Any error means the request must be rejected as unauthenticated. An
// empty timestamp and signature is a bearer request, accepted only when the
// token grants ScopeBearer.
func (v *Verifier) VerifyCredential(token, timestamp, signature string) (*Claims, error) {
	claims, err := Verify(token, v.issuerPubKey)
	if err != nil {
		return nil, err
	}
	now := v.now()
	if claims.Expired(now, v.skew) {
		return nil, errors.New("valiss: tenant token expired")
	}
	if !v.allowlist.Allowed(claims.ID) {
		return nil, errors.New("valiss: tenant token not recognized")
	}
	if timestamp == "" && signature == "" {
		if !claims.HasScope(ScopeBearer) {
			return nil, errors.New("valiss: request signature required: token does not grant the bearer scope")
		}
		return claims, nil
	}
	if err := VerifyRequest(claims.PubKey, timestamp, signature, now, v.skew); err != nil {
		return nil, err
	}
	return claims, nil
}

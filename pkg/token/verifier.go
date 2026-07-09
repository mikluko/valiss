package token

import (
	"errors"
	"time"
)

// Header field names carrying the tenant credential on each request. Used as
// gRPC metadata keys and HTTP header names alike.
const (
	HeaderAccountToken = "valiss-account-token"
	HeaderUserToken    = "valiss-user-token"
	HeaderTimestamp    = "valiss-timestamp"
	HeaderSignature    = "valiss-signature"
)

// ScopeBearer is the scope a token must carry for its holder to make bearer
// requests: the token alone, without the per-request signature. Bearer tokens
// are replayable until they expire or leave the allowlist, so grant this only
// to holders that cannot sign (no seed distribution) and pair it with TLS and
// short TTLs.
const ScopeBearer = "bearer"

// Credential is the per-request material a transport extracts from headers.
type Credential struct {
	// AccountToken is the operator-signed account token.
	AccountToken string
	// UserToken is the account-signed user token on chain credentials; empty
	// when the tenant itself makes the request.
	UserToken string
	// Timestamp and Signature are the per-request signing proof; both empty
	// on bearer requests.
	Timestamp string
	Signature string
}

// ClaimsValidator is custom validation logic injected into the Verifier. It
// runs after the token chain is verified and the effective claims are
// assembled, and before the request signature check. A non-nil error rejects
// the request as unauthenticated.
type ClaimsValidator func(cred Credential, claims *Claims) error

// AccountTokenResolver supplies the operator-signed account token for an
// account public key, serving requests that carry only a user token (the
// default creds shape). The resolved token goes through the full
// verification: operator signature, expiry, allowlist.
type AccountTokenResolver func(accountPubKey string) (string, error)

// StaticAccountTokens builds a resolver over a fixed token set, e.g. from
// server configuration. Tokens are indexed by their bound account key; their
// signatures are checked here, their trust is established per request.
func StaticAccountTokens(tokens ...string) (AccountTokenResolver, error) {
	byKey := make(map[string]string, len(tokens))
	for _, tok := range tokens {
		issuer, err := IssuerOf(tok)
		if err != nil {
			return nil, err
		}
		claims, err := Verify(tok, issuer)
		if err != nil {
			return nil, err
		}
		byKey[claims.PubKey] = tok
	}
	return func(accountPubKey string) (string, error) {
		tok, ok := byKey[accountPubKey]
		if !ok {
			return "", errors.New("valiss: no account token configured for the user token's account")
		}
		return tok, nil
	}, nil
}

// Verifier checks the full per-request credential: account token signature
// against the pinned operator key, expiry, allowlist membership, the optional
// user-token chain, and the request signature within the skew window.
// Requests without a signature pass only when the effective token grants
// ScopeBearer. Transport layers (gRPC interceptor, HTTP middleware) wrap it
// with header extraction and error mapping.
type Verifier struct {
	operatorPubKey string
	allowlist      Allowlist
	skew           time.Duration
	now            func() time.Time
	validators     []ClaimsValidator
	resolver       AccountTokenResolver
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

// WithClaimsValidator injects custom validation into the verification
// pipeline. Validators run in registration order; the first error wins.
func WithClaimsValidator(fn ClaimsValidator) VerifierOption {
	return func(v *Verifier) { v.validators = append(v.validators, fn) }
}

// WithAccountTokenResolver accepts requests that carry only a user token,
// resolving the account token server-side. Without it such requests are
// rejected.
func WithAccountTokenResolver(fn AccountTokenResolver) VerifierOption {
	return func(v *Verifier) { v.resolver = fn }
}

func NewVerifier(operatorPubKey string, allowlist Allowlist, opts ...VerifierOption) *Verifier {
	v := &Verifier{
		operatorPubKey: operatorPubKey,
		allowlist:      allowlist,
		skew:           DefaultSkew,
		now:            time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// VerifyCredential authenticates a request credential and returns the
// effective claims. Any error means the request must be rejected as
// unauthenticated.
//
// A credential with a user token is verified as a chain: the account token
// against the operator key and the allowlist, then the user token against
// the account token's bound key. The effective scopes are the user's
// scopes clamped to those the tenant holds, so a tenant can never delegate
// more than it has; ScopeBearer passes through unclamped because it selects
// an authentication mode, not an authorization grant.
//
// An empty timestamp and signature is a bearer request, accepted only when
// the effective token grants ScopeBearer.
func (v *Verifier) VerifyCredential(cred Credential) (*Claims, error) {
	if cred.AccountToken == "" {
		if cred.UserToken == "" {
			return nil, errors.New("valiss: missing credentials")
		}
		if v.resolver == nil {
			return nil, errors.New("valiss: request carries no account token and the server has no account token resolver")
		}
		accountPubKey, err := IssuerOf(cred.UserToken)
		if err != nil {
			return nil, err
		}
		tok, err := v.resolver(accountPubKey)
		if err != nil {
			return nil, err
		}
		cred.AccountToken = tok
	}
	claims, err := Verify(cred.AccountToken, v.operatorPubKey)
	if err != nil {
		return nil, err
	}
	now := v.now()
	if claims.Expired(now, v.skew) {
		return nil, errors.New("valiss: account token expired")
	}
	if !v.allowlist.Allowed(claims.ID) {
		return nil, errors.New("valiss: account token not recognized")
	}
	if cred.UserToken != "" {
		user, err := Verify(cred.UserToken, claims.PubKey)
		if err != nil {
			return nil, err
		}
		if user.Expired(now, v.skew) {
			return nil, errors.New("valiss: user token expired")
		}
		scopes := make([]string, 0, len(user.Scopes))
		for _, s := range user.Scopes {
			if s == ScopeBearer || Covered(claims.Scopes, s) {
				scopes = append(scopes, s)
			}
		}
		claims = &Claims{
			TenantID:  claims.TenantID,
			UserID:    user.TenantID,
			PubKey:    user.PubKey,
			Scopes:    scopes,
			ID:        claims.ID,
			Issuer:    claims.Issuer,
			ExpiresAt: minExpiry(claims.ExpiresAt, user.ExpiresAt),
		}
	}
	for _, validate := range v.validators {
		if err := validate(cred, claims); err != nil {
			return nil, err
		}
	}
	if cred.Timestamp == "" && cred.Signature == "" {
		if !claims.HasScope(ScopeBearer) {
			return nil, errors.New("valiss: request signature required: token does not grant the bearer scope")
		}
		return claims, nil
	}
	if claims.PubKey == "" {
		return nil, errors.New("valiss: request signature present but token binds no key")
	}
	if err := VerifyRequest(claims.PubKey, cred.Timestamp, cred.Signature, now, v.skew); err != nil {
		return nil, err
	}
	return claims, nil
}

// minExpiry returns the earlier of two expiries, ignoring zero values.
func minExpiry(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case b.Before(a):
		return b
	default:
		return a
	}
}

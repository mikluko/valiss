package valiss

import (
	"errors"
	"fmt"
	"time"
)

// Header field names carrying the credential on each request. Used as gRPC
// metadata keys and HTTP header names alike.
const (
	HeaderAccountToken = "valiss-account-token"
	HeaderUserToken    = "valiss-user-token"
	HeaderTimestamp    = "valiss-timestamp"
	HeaderSignature    = "valiss-signature"
)

// Request is the per-request material a transport extracts from headers.
type Request struct {
	// AccountToken is the operator-signed account token.
	AccountToken string
	// UserToken is the account-signed user token on chain credentials; empty
	// when the tenant itself makes the request.
	UserToken string
	// Timestamp and Signature are the per-request signing proof; both empty
	// on bearer requests.
	Timestamp string
	Signature string
	// Context is the transport's canonical description of the request (e.g.
	// method and path) that the signature is bound to. The transport fills
	// it from the incoming request and the client signs the identical bytes;
	// a mismatch fails the signature. Nil binds nothing beyond the timestamp.
	Context []byte
}

// Identity is the verified result of a request.
type Identity struct {
	// Account is the tenant the request acts under; always present.
	Account *AccountClaims
	// User is the delegated end user; nil for account-level requests.
	User *UserClaims
}

// ClaimsValidator is custom validation logic injected into the Verifier. It
// runs after the token chain is verified, the identity is assembled, and the
// request signature has proven possession of the subject seed (a bearer user
// token waives the signature). A non-nil error rejects the request as
// unauthenticated. Running post-possession means an expensive validator is
// never triggered by a party that merely captured a token but cannot sign.
type ClaimsValidator func(req Request, id *Identity) error

// ExtValidator adapts a typed validator over the extension claim named by
// T's zero value into a ClaimsValidator: the extension is decoded from both
// the account and user tokens before fn runs. Missing extensions pass zero
// values.
func ExtValidator[T Extension](fn func(req Request, id *Identity, acct, user T) error) ClaimsValidator {
	return func(req Request, id *Identity) error {
		acct, _, err := ExtOf[T](id.Account.Ext)
		if err != nil {
			return err
		}
		var user T
		if id.User != nil {
			if user, _, err = ExtOf[T](id.User.Ext); err != nil {
				return err
			}
		}
		return fn(req, id, acct, user)
	}
}

// AccountTokenResolver supplies the operator-signed account token for an
// account public key, serving requests that carry only a user token (the
// default creds shape). The resolved token goes through the full
// verification: operator signature, expiry, allowlist.
type AccountTokenResolver func(accountPubKey string) (string, error)

// StaticAccountTokens builds a resolver over a fixed token set, e.g. from
// server configuration. Tokens are indexed by their subject account key;
// their signatures are checked here, their trust is established per request.
func StaticAccountTokens(tokens ...string) (AccountTokenResolver, error) {
	byKey := make(map[string]string, len(tokens))
	for _, tok := range tokens {
		issuer, err := IssuerOf(tok)
		if err != nil {
			return nil, err
		}
		claims, err := VerifyAccount(tok, issuer)
		if err != nil {
			return nil, err
		}
		byKey[claims.Subject] = tok
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
// against the pinned operator key, expiry and activation, allowlist
// membership, the optional user-token chain, registered extension types,
// custom validators, and the request signature within the skew window.
// Requests without a signature pass only when the effective token is a
// bearer user token. Transport layers (gRPC interceptor, HTTP middleware)
// wrap it with header extraction and error mapping.
type Verifier struct {
	operatorPubKey string
	allowlist      Allowlist
	skew           time.Duration
	now            func() time.Time
	validators     []ClaimsValidator
	extChecks      []func(Extensions) error
	resolver       AccountTokenResolver
	operator       *OperatorClaims
	operatorErr    error
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

// WithExtensionType registers an extension type for eager validation: when
// either token carries the extension named by T's zero value, it must decode
// into T or the request is rejected. Retrieval via ExtOf never requires
// registration; this only moves malformed-extension failures to auth time.
func WithExtensionType[T Extension]() VerifierOption {
	check := func(exts Extensions) error {
		_, _, err := ExtOf[T](exts)
		return err
	}
	return func(v *Verifier) { v.extChecks = append(v.extChecks, check) }
}

// WithAccountTokenResolver accepts requests that carry only a user token,
// resolving the account token server-side. Without it such requests are
// rejected.
func WithAccountTokenResolver(fn AccountTokenResolver) VerifierOption {
	return func(v *Verifier) { v.resolver = fn }
}

// WithOperatorToken supplies the trust domain's self-signed operator token
// and enforces its policy on every request: the operator token must be
// within its own validity window, and every account and user token must
// echo its epoch. Bumping the epoch in a fresh operator token therefore
// revokes everything minted in earlier epochs at once. The pinned operator
// public key remains the trust anchor; a token not self-signed by it poisons
// the verifier so every request fails rather than silently skipping policy.
func WithOperatorToken(token string) VerifierOption {
	return func(v *Verifier) {
		v.operator, v.operatorErr = VerifyOperator(token, v.operatorPubKey)
	}
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

// VerifyRequest authenticates a request credential and returns the verified
// identity. Any error means the request must be rejected as unauthenticated.
//
// A credential with a user token is verified as a chain: the account token
// against the operator key and the allowlist, then the user token against
// the account token's subject key. An empty timestamp and signature is a
// bearer request, accepted only when the effective token is a bearer user
// token; account-level requests must always sign.
func (v *Verifier) VerifyRequest(req Request) (*Identity, error) {
	if v.operatorErr != nil {
		return nil, fmt.Errorf("valiss: operator token misconfigured: %w", v.operatorErr)
	}
	if req.AccountToken == "" {
		if req.UserToken == "" {
			return nil, errors.New("valiss: missing credentials")
		}
		if v.resolver == nil {
			return nil, errors.New("valiss: request carries no account token and the server has no account token resolver")
		}
		accountPubKey, err := IssuerOf(req.UserToken)
		if err != nil {
			return nil, err
		}
		tok, err := v.resolver(accountPubKey)
		if err != nil {
			return nil, err
		}
		req.AccountToken = tok
	}
	account, err := VerifyAccount(req.AccountToken, v.operatorPubKey)
	if err != nil {
		return nil, err
	}
	now := v.now()
	if v.operator != nil {
		if v.operator.Expired(now, v.skew) {
			return nil, errors.New("valiss: operator token expired: the trust domain is closed")
		}
		if v.operator.NotYetValid(now, v.skew) {
			return nil, errors.New("valiss: operator token not yet valid")
		}
		if account.Epoch != v.operator.Epoch {
			return nil, fmt.Errorf("valiss: account token epoch %d, trust domain epoch %d", account.Epoch, v.operator.Epoch)
		}
	}
	if account.Expired(now, v.skew) {
		return nil, errors.New("valiss: account token expired")
	}
	if account.NotYetValid(now, v.skew) {
		return nil, errors.New("valiss: account token not yet valid")
	}
	if !v.allowlist.Allowed(account.ID) {
		return nil, errors.New("valiss: account token not recognized")
	}
	id := &Identity{Account: account}
	if req.UserToken != "" {
		user, err := VerifyUser(req.UserToken, account.Subject)
		if err != nil {
			return nil, err
		}
		if v.operator != nil && user.Epoch != v.operator.Epoch {
			return nil, fmt.Errorf("valiss: user token epoch %d, trust domain epoch %d", user.Epoch, v.operator.Epoch)
		}
		if user.Expired(now, v.skew) {
			return nil, errors.New("valiss: user token expired")
		}
		if user.NotYetValid(now, v.skew) {
			return nil, errors.New("valiss: user token not yet valid")
		}
		id.User = user
	}
	// Prove possession of the subject seed before running any
	// consumer-supplied hook, so extension checks and validators only ever
	// see requests whose sender holds the key (a bearer user token waives
	// the signature by design).
	subject := id.Account.Subject
	if id.User != nil {
		subject = id.User.Subject
	}
	if req.Timestamp == "" && req.Signature == "" {
		if id.User == nil || !id.User.Bearer {
			return nil, errors.New("valiss: request signature required: not a bearer token")
		}
	} else if err := VerifySignature(subject, req.Timestamp, req.Signature, req.Context, now, v.skew); err != nil {
		return nil, err
	}
	for _, check := range v.extChecks {
		if err := check(id.Account.Ext); err != nil {
			return nil, err
		}
		if id.User != nil {
			if err := check(id.User.Ext); err != nil {
				return nil, err
			}
		}
	}
	for _, validate := range v.validators {
		if err := validate(req, id); err != nil {
			return nil, err
		}
	}
	return id, nil
}

// Package valiss implements the core of the tenant authentication scheme,
// a three-level chain of Ed25519 keys:
//
//   - An operator holds an Ed25519 nkey; its public key is the trust anchor
//     servers pin.
//   - The operator signs each tenant an account token that the tenant's own
//     account nkey must back. Issued account tokens are recorded in a
//     server-side allowlist.
//   - A tenant may delegate: it signs user tokens with its account seed.
//   - The subject signs every request with its nkey; the server verifies the
//     token chain up to the pinned operator key, the request signature
//     against the token's subject key, and the account token against the
//     allowlist, then hands the verified identity to the handler for data
//     segmentation.
//
// Tokens are this scheme's own typed claims carried in an nkey-signed JWT:
// the sub claim is the subject's public key and name carries the
// human-readable label. Key levels are strict: operator keys
// (SO.../O...) sign account tokens for account keys (SA.../A...), account
// keys sign user tokens for user keys (SU.../U...).
//
// A user key may additionally mint per-message tokens (IssueMessage): a
// fourth, optional chain level binding a token to a destination and payload
// checksum, offline-verifiable by anyone holding the operator public key
// (VerifyMessage). Message tokens are proofs of origin, never credentials:
// possession grants nothing, and the request Verifier does not accept them.
//
// Authorization rides named extension claims (Extension, WithExtension):
// typed payloads the scheme signs and transports but assigns no meaning.
// The contrib transports enforce their extensions (HTTP hosts/methods/paths,
// gRPC methods); consumers add domain extensions the same way and read them
// back in handlers with ExtOf.
package valiss

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
)

// Claims is the verified RFC 7519 registered-claims content of a token.
// Level-specific data lives on AccountClaims and UserClaims, which embed it.
type Claims struct {
	// ID is the token's unique identifier (jti), the allowlist key for
	// account tokens.
	ID string
	// Issuer is the issuer public key that signed the token (iss).
	Issuer string
	// Subject is the subject's nkey public key (sub) that must sign
	// requests.
	Subject string
	// IssuedAt is the token mint time (iat).
	IssuedAt time.Time
	// ExpiresAt is the token expiry (exp); zero means the token never
	// expires.
	ExpiresAt time.Time
	// NotBefore is the token activation time (nbf); zero means immediately
	// valid.
	NotBefore time.Time
}

// OperatorClaims is the verified content of a self-signed operator token:
// the trust domain's policy statement, signed by the pinned anchor key.
type OperatorClaims struct {
	Claims
	// Name is the trust domain's human-readable label. It is asserted by
	// the operator about itself: a consumer trusting several operators must
	// not assume names are unique across domains. Falls back to the
	// operator public key when the token carries no name.
	Name string
	// Epoch is the trust domain's current epoch. A verifier configured with
	// the operator token accepts only account and user tokens that echo it.
	Epoch uint64
	// Ext carries the named extension claims (WithExtension).
	Ext Extensions
}

// AccountClaims is the verified content of an account (tenant) token.
type AccountClaims struct {
	Claims
	// Name is the tenant's human-readable label; it segments all stored
	// data. Falls back to the subject key when the token carries no name.
	Name string
	// Epoch is the trust-domain epoch the token was issued in (WithEpoch).
	Epoch uint64
	// Ext carries the named extension claims (WithExtension).
	Ext Extensions
}

// UserClaims is the verified content of a user token.
type UserClaims struct {
	Claims
	// Name is the user's human-readable label. Falls back to the subject
	// key when the token carries no name.
	Name string
	// Epoch is the trust-domain epoch the token was issued in (WithEpoch).
	Epoch uint64
	// Bearer marks a token whose holder authenticates by the token alone,
	// without per-request signatures.
	Bearer bool
	// Ext carries the named extension claims (WithExtension).
	Ext Extensions
}

// Extension is a named claim payload carried in a token's ext field.
// Implementations are value struct types whose zero value reports the name.
type Extension interface {
	ExtensionName() string
}

// issueConfig collects IssueOption effects.
type issueConfig struct {
	name      string
	expires   int64
	notBefore int64
	epoch     uint64
	bearer    bool
	audience  string
	checksum  string
	chain     *messageChain
	ext       Extensions
	err       error
}

// IssueOption customizes a minted token. Without a WithTTL or WithExpiry
// option the token never expires.
type IssueOption func(*issueConfig)

// WithName labels the minted entity with a human-readable name: the trust
// domain on an operator token, the tenant on an account token, the user on
// a user token. Names are optional; an unnamed entity is represented by its
// public key. Names are asserted by their issuer, and nothing at issuance
// checks uniqueness: collections that hold several entities side by side
// (an anchor keyring, a tenant directory) own the uniqueness of names in
// their scope. Message tokens carry no name.
func WithName(name string) IssueOption {
	return func(c *issueConfig) { c.name = name }
}

// WithTTL makes the token expire ttl from now (the JWT exp claim).
func WithTTL(ttl time.Duration) IssueOption {
	return func(c *issueConfig) { c.expires = time.Now().Add(ttl).Unix() }
}

// WithExpiry makes the token expire at t (the JWT exp claim).
func WithExpiry(t time.Time) IssueOption {
	return func(c *issueConfig) { c.expires = t.Unix() }
}

// WithNotBefore makes the token invalid before t (the JWT nbf claim).
func WithNotBefore(t time.Time) IssueOption {
	return func(c *issueConfig) { c.notBefore = t.Unix() }
}

// WithBearer marks a user token as a bearer token: the server accepts it
// without per-request signatures. Bearer tokens are replayable until they
// expire or their account leaves the allowlist, so pair them with TLS and a
// short validity window. Only IssueUser accepts this option.
func WithBearer() IssueOption {
	return func(c *issueConfig) { c.bearer = true }
}

// WithAudience binds a message token to its destination (the JWT aud
// claim): a URL, queue name, or recipient id. Receivers that verify with
// ExpectAudience reject tokens minted for anywhere else, closing
// cross-destination replay. Only IssueMessage accepts this option.
func WithAudience(aud string) IssueOption {
	return func(c *issueConfig) { c.audience = aud }
}

// WithChecksum embeds the lowercase-hex SHA-256 of the message payload
// exactly as delivered (see Checksum), binding the token to the bytes.
// Receivers compare it via WithPayload or read it from MessageClaims. Only
// IssueMessage accepts this option.
func WithChecksum(sum string) IssueOption {
	return func(c *issueConfig) {
		if !isHexSHA256(sum) {
			c.err = errors.New("valiss: checksum must be the lowercase-hex SHA-256 of the payload")
			return
		}
		c.checksum = sum
	}
}

// WithChain embeds the emitter's provenance chain — the operator-signed
// account token and the account-signed user token — into the message token,
// so a receiver needs nothing but the operator public key (see also the
// verify-side WithChainTokens for out-of-band delivery). Only IssueMessage
// accepts this option.
func WithChain(accountToken, userToken string) IssueOption {
	return func(c *issueConfig) { c.chain = &messageChain{Account: accountToken, User: userToken} }
}

// WithEpoch stamps the trust-domain epoch on the token. On an operator
// token it declares the domain's current epoch; on account and user tokens
// it must echo it. Verifiers configured with the operator token reject
// tokens from any other epoch, so bumping the epoch and re-minting rotates
// the whole domain at once. Unstamped tokens are epoch 0.
func WithEpoch(epoch uint64) IssueOption {
	return func(c *issueConfig) { c.epoch = epoch }
}

// WithExtension embeds a named extension claim into the token's ext field;
// the name comes from the value's ExtensionName. Repeat the option for
// multiple extensions; a duplicate name is an error. The scheme signs and
// transports the value untouched; servers read it back with ExtOf or
// validate it with an ExtValidator.
func WithExtension(v Extension) IssueOption {
	return func(c *issueConfig) {
		name := v.ExtensionName()
		if name == "" {
			c.err = errors.New("valiss: extension name must not be empty")
			return
		}
		if _, dup := c.ext[name]; dup {
			c.err = fmt.Errorf("valiss: duplicate extension %q", name)
			return
		}
		raw, err := json.Marshal(v)
		if err != nil {
			c.err = fmt.Errorf("valiss: encode extension %q: %w", name, err)
			return
		}
		if c.ext == nil {
			c.ext = Extensions{}
		}
		c.ext[name] = raw
	}
}

// rejectMessageOptions guards the identity-token issuers against options
// that carry meaning only on message tokens.
func (c *issueConfig) rejectMessageOptions() error {
	if c.audience != "" || c.checksum != "" || c.chain != nil {
		return errors.New("valiss: audience, checksum, and chain apply only to message tokens")
	}
	return nil
}

// IssueOperator mints the self-signed operator token: the trust domain's
// policy statement (epoch, validity window, extensions), signed by the
// operator key over its own public key. WithName labels the trust domain
// the way account and user names label theirs. Servers configured with the
// token via WithOperatorToken enforce the policy on every request; the
// pinned public key remains the trust anchor.
func IssueOperator(operator nkeys.KeyPair, opts ...IssueOption) (string, error) {
	pub, err := operator.PublicKey()
	if err != nil || !nkeys.IsValidPublicOperatorKey(pub) {
		return "", errors.New("valiss: operator tokens must be signed by an operator-type nkey (expected an SO... seed)")
	}
	var cfg issueConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.err != nil {
		return "", cfg.err
	}
	if cfg.bearer {
		return "", errors.New("valiss: bearer applies only to user tokens")
	}
	if err := cfg.rejectMessageOptions(); err != nil {
		return "", err
	}
	return encodeToken(operator, &wire[operatorBody]{
		Name:      cfg.name,
		Subject:   pub,
		Expires:   cfg.expires,
		NotBefore: cfg.notBefore,
		Valiss:    operatorBody{Type: operatorType, Epoch: cfg.epoch, Ext: cfg.ext},
	})
}

// Issue mints an account token signed by the operator key. The token
// subject is the tenant's account public key and WithName carries the
// tenant id; the tenant signs requests with the seed matching the subject
// key.
func Issue(operator nkeys.KeyPair, tenantPubKey string, opts ...IssueOption) (string, error) {
	if pub, err := operator.PublicKey(); err != nil || !nkeys.IsValidPublicOperatorKey(pub) {
		return "", errors.New("valiss: account tokens must be signed by an operator-type nkey (expected an SO... seed)")
	}
	if !nkeys.IsValidPublicAccountKey(tenantPubKey) {
		return "", errors.New("valiss: invalid tenant public key (expected an A... nkey)")
	}
	var cfg issueConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.err != nil {
		return "", cfg.err
	}
	if cfg.bearer {
		return "", errors.New("valiss: bearer applies only to user tokens")
	}
	if err := cfg.rejectMessageOptions(); err != nil {
		return "", err
	}
	return encodeToken(operator, &wire[accountBody]{
		Name:      cfg.name,
		Subject:   tenantPubKey,
		Expires:   cfg.expires,
		NotBefore: cfg.notBefore,
		Valiss:    accountBody{Type: accountType, Epoch: cfg.epoch, Ext: cfg.ext},
	})
}

// IssueUser mints a user token signed by a tenant's account key, delegating
// to an end user. The token subject is the user's public key and WithName
// carries the user id. WithBearer produces a token the server accepts
// without per-request signatures.
func IssueUser(account nkeys.KeyPair, userPubKey string, opts ...IssueOption) (string, error) {
	if pub, err := account.PublicKey(); err != nil || !nkeys.IsValidPublicAccountKey(pub) {
		return "", errors.New("valiss: user tokens must be signed by an account-type nkey (expected an SA... seed)")
	}
	if !nkeys.IsValidPublicUserKey(userPubKey) {
		return "", errors.New("valiss: invalid user public key (expected a U... nkey)")
	}
	var cfg issueConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.err != nil {
		return "", cfg.err
	}
	if err := cfg.rejectMessageOptions(); err != nil {
		return "", err
	}
	return encodeToken(account, &wire[userBody]{
		Name:      cfg.name,
		Subject:   userPubKey,
		Expires:   cfg.expires,
		NotBefore: cfg.notBefore,
		Valiss:    userBody{Type: userType, Epoch: cfg.epoch, Bearer: cfg.bearer, Ext: cfg.ext},
	})
}

// VerifyOperator decodes a self-signed operator token, checks its type and
// that it is signed by the pinned operator key over itself, and returns the
// claims. Expiry and activation checks belong to the Verifier.
func VerifyOperator(token, operatorPubKey string) (*OperatorClaims, error) {
	c, err := decodeToken[operatorBody](token)
	if err != nil {
		return nil, err
	}
	if c.Valiss.Type != operatorType {
		return nil, fmt.Errorf("valiss: not an operator token (type %q)", c.Valiss.Type)
	}
	if c.Issuer != operatorPubKey || c.Subject != operatorPubKey {
		return nil, errors.New("valiss: operator token not self-signed by the expected operator")
	}
	if !nkeys.IsValidPublicOperatorKey(c.Subject) {
		return nil, errors.New("valiss: operator token subject is not an operator public key")
	}
	return &OperatorClaims{
		Claims: claimsOf(c.ID, c.Issuer, c.Subject, c.IssuedAt, c.Expires, c.NotBefore),
		Name:   nameOf(c.Name, c.Subject),
		Epoch:  c.Valiss.Epoch,
		Ext:    c.Valiss.Ext,
	}, nil
}

// VerifyAccount decodes an account token, checks its type, signature, and
// issuer, and returns the claims. It does NOT check expiry, activation, or
// the allowlist; the Verifier layers those so callers get precise errors.
func VerifyAccount(token, operatorPubKey string) (*AccountClaims, error) {
	c, err := decodeToken[accountBody](token)
	if err != nil {
		return nil, err
	}
	if c.Valiss.Type != accountType {
		return nil, fmt.Errorf("valiss: not an account token (type %q)", c.Valiss.Type)
	}
	if c.Issuer != operatorPubKey {
		return nil, errors.New("valiss: account token not signed by the expected issuer")
	}
	if !nkeys.IsValidPublicAccountKey(c.Subject) {
		return nil, errors.New("valiss: account token subject is not an account public key")
	}
	return &AccountClaims{
		Claims: claimsOf(c.ID, c.Issuer, c.Subject, c.IssuedAt, c.Expires, c.NotBefore),
		Name:   nameOf(c.Name, c.Subject),
		Epoch:  c.Valiss.Epoch,
		Ext:    c.Valiss.Ext,
	}, nil
}

// VerifyUser decodes a user token, checks its type, signature, and issuer
// (the account public key that delegated it), and returns the claims.
// Expiry and activation checks belong to the Verifier.
func VerifyUser(token, accountPubKey string) (*UserClaims, error) {
	c, err := decodeToken[userBody](token)
	if err != nil {
		return nil, err
	}
	if c.Valiss.Type != userType {
		return nil, fmt.Errorf("valiss: not a user token (type %q)", c.Valiss.Type)
	}
	if c.Issuer != accountPubKey {
		return nil, errors.New("valiss: user token not signed by the expected account")
	}
	if !nkeys.IsValidPublicUserKey(c.Subject) {
		return nil, errors.New("valiss: user token subject is not a user public key")
	}
	return &UserClaims{
		Claims: claimsOf(c.ID, c.Issuer, c.Subject, c.IssuedAt, c.Expires, c.NotBefore),
		Name:   nameOf(c.Name, c.Subject),
		Epoch:  c.Valiss.Epoch,
		Bearer: c.Valiss.Bearer,
		Ext:    c.Valiss.Ext,
	}, nil
}

// Decode parses a token of either level without establishing trust: the
// signature is checked against the token's own embedded issuer only. For
// inspection and tooling; servers must use VerifyAccount or VerifyUser.
func Decode(token string) (*Claims, error) {
	c, err := decodeToken[struct{}](token)
	if err != nil {
		return nil, err
	}
	claims := claimsOf(c.ID, c.Issuer, c.Subject, c.IssuedAt, c.Expires, c.NotBefore)
	return &claims, nil
}

// claimsOf builds the RFC claims set from wire fields.
func claimsOf(id, issuer, subject string, issuedAt, expires, notBefore int64) Claims {
	c := Claims{ID: id, Issuer: issuer, Subject: subject}
	if issuedAt != 0 {
		c.IssuedAt = time.Unix(issuedAt, 0)
	}
	if expires != 0 {
		c.ExpiresAt = time.Unix(expires, 0)
	}
	if notBefore != 0 {
		c.NotBefore = time.Unix(notBefore, 0)
	}
	return c
}

// nameOf falls back to the subject key when a token carries no name.
func nameOf(name, subject string) string {
	if name != "" {
		return name
	}
	return subject
}

// Expired reports whether the token has passed its expiry (with skew slack).
func (c *Claims) Expired(now time.Time, skew time.Duration) bool {
	return !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt.Add(skew))
}

// NotYetValid reports whether the token's not-before still lies in the
// future (with skew slack).
func (c *Claims) NotYetValid(now time.Time, skew time.Duration) bool {
	return !c.NotBefore.IsZero() && now.Add(skew).Before(c.NotBefore)
}

// IssuerOf returns the public key that signed a token, after checking the
// token's own signature against it. It does not establish trust: the caller
// must still verify the issuer's place in the chain.
func IssuerOf(token string) (string, error) {
	c, err := decodeToken[struct{}](token)
	if err != nil {
		return "", err
	}
	return c.Issuer, nil
}

// ExtOf decodes the extension claim named by T's zero value. An absent name
// yields the zero value and false.
func ExtOf[T Extension](exts Extensions) (T, bool, error) {
	var v T
	raw, ok := exts[v.ExtensionName()]
	if !ok {
		return v, false, nil
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, false, fmt.Errorf("valiss: decode extension %q: %w", v.ExtensionName(), err)
	}
	return v, true, nil
}

// Covered reports whether any granted pattern covers the required value,
// honoring trailing-"*" prefix wildcards. Transport extensions use it for
// paths and methods.
func Covered(granted []string, required string) bool {
	for _, g := range granted {
		if scopeMatch(g, required) {
			return true
		}
	}
	return false
}

func scopeMatch(granted, required string) bool {
	if prefix, ok := strings.CutSuffix(granted, "*"); ok {
		return strings.HasPrefix(required, prefix)
	}
	return granted == required
}

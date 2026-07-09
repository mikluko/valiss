// Package valiss implements the core of the tenant authentication scheme,
// modeled on NATS operator/account/user credentials:
//
//   - An operator holds an Ed25519 nkey; its public key is the trust anchor
//     servers pin.
//   - The operator signs each tenant a scoped account token that the
//     tenant's own account nkey must back. Issued account tokens are
//     recorded in a server-side allowlist.
//   - A tenant may delegate: it signs user tokens with its account seed,
//     granting end users a subset of its scopes.
//   - The subject signs every request with its nkey; the server verifies the
//     token chain up to the pinned operator key, the request signature
//     against the token's subject key, and the account token against the
//     allowlist, then hands the tenant (and user) identity to the handler
//     for data segmentation.
//
// Tokens are this scheme's own typed claims carried in an nkey-signed JWT:
// the sub claim is the subject's public key and name carries the
// human-readable label, as in NATS. Key levels are strict: operator keys
// (SO.../O...) sign account tokens for account keys (SA.../A...), account
// keys sign user tokens for user keys (SU.../U...).
package valiss

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
)

// Claims is the verified content of a token.
type Claims struct {
	// TenantID identifies the tenant; it segments all stored data.
	TenantID string
	// UserID identifies the end user on chain-verified requests, where an
	// account-signed user token accompanies the account token. Empty when
	// the tenant itself made the request.
	UserID string
	// PubKey is the subject's nkey public key (the JWT sub claim) that must
	// sign requests.
	PubKey string
	// Scopes granted to the subject.
	Scopes []string
	// Bearer marks a user token whose holder authenticates by the token
	// alone, without per-request signatures.
	Bearer bool
	// ID is the token's unique identifier (jti), the allowlist key.
	ID string
	// Issuer is the issuer public key that signed the token.
	Issuer string
	// ExpiresAt is the token expiry; zero means the token never expires.
	ExpiresAt time.Time
	// NotBefore is the token activation time; zero means immediately valid.
	NotBefore time.Time
	// AccountExt and UserExt carry the named extension claims of the account
	// and user tokens (WithExtension), verbatim. Decode them with Ext or
	// validate them with ExtValidator.
	AccountExt Extensions
	UserExt    Extensions
}

// issueConfig collects IssueOption effects.
type issueConfig struct {
	expires   int64
	notBefore int64
	bearer    bool
	ext       Extensions
	err       error
}

// IssueOption customizes a minted token. Without a WithTTL or WithExpiry
// option the token never expires, matching nsc's default.
type IssueOption func(*issueConfig)

// WithTTL makes the token expire ttl from now (the JWT exp claim).
func WithTTL(ttl time.Duration) IssueOption {
	return func(c *issueConfig) { c.expires = time.Now().Add(ttl).Unix() }
}

// WithExpiry makes the token expire at t (the JWT exp claim).
func WithExpiry(t time.Time) IssueOption {
	return func(c *issueConfig) { c.expires = t.Unix() }
}

// WithNotBefore makes the token invalid before t (the JWT nbf claim), like
// nsc's --start.
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

// WithExtension embeds a named extension claim into the token's ext field.
// Repeat the option for multiple extensions; a duplicate name is an error.
// The scheme signs and transports the value untouched; servers read it back
// via Claims.AccountExt/UserExt, the Ext helper, or an ExtValidator.
func WithExtension(name string, v any) IssueOption {
	return func(c *issueConfig) {
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

// Issue mints an account token signed by the operator key. As in NATS, the
// token subject is the tenant's account public key and name carries the
// tenant id; the tenant signs requests with the seed matching the subject
// key.
func Issue(operator nkeys.KeyPair, tenantID, tenantPubKey string, scopes []string, opts ...IssueOption) (string, error) {
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
	return encodeToken(operator, &wire[accountBody]{
		Name:      tenantID,
		Subject:   tenantPubKey,
		Expires:   cfg.expires,
		NotBefore: cfg.notBefore,
		Valiss:    accountBody{Type: accountType, Scopes: scopes, Ext: cfg.ext},
	})
}

// IssueUser mints a user token signed by a tenant's account key, delegating
// a subset of the tenant's access to an end user. As in NATS, the token
// subject is the user's public key and name carries the user id. WithBearer
// produces a token the server accepts without per-request signatures.
func IssueUser(account nkeys.KeyPair, userID, userPubKey string, scopes []string, opts ...IssueOption) (string, error) {
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
	return encodeToken(account, &wire[userBody]{
		Name:      userID,
		Subject:   userPubKey,
		Expires:   cfg.expires,
		NotBefore: cfg.notBefore,
		Valiss:    userBody{Type: userType, Scopes: scopes, Bearer: cfg.bearer, Ext: cfg.ext},
	})
}

// VerifyAccount decodes an account token, checks its type, signature, and
// issuer, and returns the claims. It does NOT check expiry, activation, or
// the allowlist; the Verifier layers those so callers get precise errors.
func VerifyAccount(token, operatorPubKey string) (*Claims, error) {
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
	claims := claimsOf(c, c.Valiss.Scopes, false)
	claims.AccountExt = c.Valiss.Ext
	return claims, nil
}

// VerifyUser decodes a user token, checks its type, signature, and issuer
// (the account public key that delegated it), and returns the claims.
// Expiry and activation checks belong to the Verifier.
func VerifyUser(token, accountPubKey string) (*Claims, error) {
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
	claims := claimsOf(c, c.Valiss.Scopes, c.Valiss.Bearer)
	claims.UserExt = c.Valiss.Ext
	return claims, nil
}

// Decode parses a token of either level without establishing trust: the
// signature is checked against the token's own embedded issuer only. For
// inspection and tooling; servers must use VerifyAccount or VerifyUser.
func Decode(token string) (*Claims, error) {
	c, err := decodeToken[anyBody](token)
	if err != nil {
		return nil, err
	}
	claims := claimsOf(c, c.Valiss.Scopes, c.Valiss.Bearer)
	switch c.Valiss.Type {
	case accountType:
		claims.AccountExt = c.Valiss.Ext
	case userType:
		claims.UserExt = c.Valiss.Ext
	}
	return claims, nil
}

// Ext decodes a named extension claim into T. An absent name yields the
// zero value.
func Ext[T any](exts Extensions, name string) (T, error) {
	var v T
	raw, ok := exts[name]
	if !ok {
		return v, nil
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("valiss: decode extension %q: %w", name, err)
	}
	return v, nil
}

func claimsOf[B any](c *wire[B], scopes []string, bearer bool) *Claims {
	name := c.Name
	if name == "" {
		name = c.Subject
	}
	claims := &Claims{
		TenantID: name,
		PubKey:   c.Subject,
		Scopes:   scopes,
		Bearer:   bearer,
		ID:       c.ID,
		Issuer:   c.Issuer,
	}
	if c.Expires != 0 {
		claims.ExpiresAt = time.Unix(c.Expires, 0)
	}
	if c.NotBefore != 0 {
		claims.NotBefore = time.Unix(c.NotBefore, 0)
	}
	return claims
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

// HasScope reports whether the subject holds an exact scope grant.
func (c *Claims) HasScope(scope string) bool {
	return slices.Contains(c.Scopes, scope)
}

// Authorizes reports whether any granted scope covers the required scope. A
// grant ending in "*" is a prefix wildcard, so "call:/svc/*" covers every
// method of that service and "call:*" covers every call.
func (c *Claims) Authorizes(required string) bool {
	return Covered(c.Scopes, required)
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

// Covered reports whether any granted scope covers the required scope,
// honoring trailing-"*" prefix wildcards.
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

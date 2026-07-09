// Package token implements the core of the tenant authentication scheme,
// modeled on NATS operator/account credentials:
//
//   - An issuer holds an Ed25519 nkey; its public key is the trust anchor
//     servers pin.
//   - The issuer signs each tenant a scoped, time-limited JWT that binds the
//     tenant's own nkey public key. Issued tokens are recorded in a
//     server-side allowlist.
//   - The tenant signs every request with its nkey; the server verifies the
//     token against the issuer key, the request signature against the
//     token's bound key, and the token against the allowlist, then hands the
//     tenant identity to the handler for data segmentation.
//
// In nkeys terms the issuer key is an operator-type key (SO... seed, O...
// public key) and the tenant key is an account-type key (SA.../A...),
// mirroring the NATS Operator -> Account levels; "issuer" and "tenant" are
// this scheme's names for the roles. The mapping leaves room for a future
// Account -> User level where a tenant signs scoped user tokens with its
// account seed, so tenant keys must stay account-type and the tenant public
// key stays required even for bearer-scoped tokens.
package token

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// Scopes carried in the token's custom claims. The subject's public key
// needs no custom claim: as in NATS, the JWT sub claim is the key itself and
// the human-readable label lives in the name field.
const scopesClaim = "scopes"

// Claims is the verified content of a token.
type Claims struct {
	// TenantID identifies the tenant; it segments all stored data.
	TenantID string
	// UserID identifies the end user on chain-verified requests, where an
	// account-signed user token accompanies the account token. Empty when the
	// tenant itself made the request.
	UserID string
	// PubKey is the tenant's nkey public key that must sign requests.
	PubKey string
	// Scopes granted to the tenant.
	Scopes []string
	// ID is the token's unique identifier (jti), the allowlist key.
	ID string
	// Issuer is the issuer public key that signed the token.
	Issuer string
	// ExpiresAt is the token expiry; zero means the token never expires.
	ExpiresAt time.Time
	// NotBefore is the token activation time; zero means immediately valid.
	NotBefore time.Time
}

// IssueOption customizes a minted token. Without a WithTTL or WithExpiry
// option the token never expires, matching nsc's default.
type IssueOption func(*jwt.GenericClaims)

// WithTTL makes the token expire ttl from now (the JWT exp claim).
func WithTTL(ttl time.Duration) IssueOption {
	return func(gc *jwt.GenericClaims) { gc.Expires = time.Now().Add(ttl).Unix() }
}

// WithExpiry makes the token expire at t (the JWT exp claim).
func WithExpiry(t time.Time) IssueOption {
	return func(gc *jwt.GenericClaims) { gc.Expires = t.Unix() }
}

// WithNotBefore makes the token invalid before t (the JWT nbf claim), like
// nsc's --start.
func WithNotBefore(t time.Time) IssueOption {
	return func(gc *jwt.GenericClaims) { gc.NotBefore = t.Unix() }
}

// Issue mints an account token signed by the operator key. As in NATS, the
// token subject is the tenant's public key and name carries the tenant id;
// the tenant signs requests with the seed matching the subject key. Validity
// comes from IssueOptions; without one the token never expires.
func Issue(operator nkeys.KeyPair, tenantID, tenantPubKey string, scopes []string, opts ...IssueOption) (string, error) {
	if pub, err := operator.PublicKey(); err != nil || !nkeys.IsValidPublicOperatorKey(pub) {
		return "", fmt.Errorf("valiss: account tokens must be signed by an operator-type nkey (expected an SO... seed)")
	}
	if !nkeys.IsValidPublicUserKey(tenantPubKey) && !nkeys.IsValidPublicAccountKey(tenantPubKey) {
		return "", fmt.Errorf("valiss: invalid tenant public key")
	}
	gc := jwt.NewGenericClaims(tenantPubKey)
	gc.Name = tenantID
	gc.Data[scopesClaim] = scopes
	for _, opt := range opts {
		opt(gc)
	}
	token, err := gc.Encode(operator)
	if err != nil {
		return "", fmt.Errorf("valiss: encode token: %w", err)
	}
	return token, nil
}

// IssueUser mints a user token signed by a tenant's account key, delegating
// a subset of the tenant's access to an end user. As in NATS, the token
// subject is the user's public key and name carries the user id. userPubKey
// may be empty only when scopes grant ScopeBearer, producing a token-only
// credential for users that cannot sign requests. Validity comes from
// IssueOptions; without one the token never expires.
func IssueUser(account nkeys.KeyPair, userID, userPubKey string, scopes []string, opts ...IssueOption) (string, error) {
	if pub, err := account.PublicKey(); err != nil || !nkeys.IsValidPublicAccountKey(pub) {
		return "", fmt.Errorf("valiss: user tokens must be signed by an account-type nkey (expected an SA... seed)")
	}
	if userPubKey == "" {
		if !slices.Contains(scopes, ScopeBearer) {
			return "", fmt.Errorf("valiss: user token without a key requires the %q scope", ScopeBearer)
		}
	} else if !nkeys.IsValidPublicUserKey(userPubKey) && !nkeys.IsValidPublicAccountKey(userPubKey) {
		return "", fmt.Errorf("valiss: invalid user public key")
	}
	// Keyless bearer tokens have nothing to put in sub but the name.
	sub := userPubKey
	if sub == "" {
		sub = userID
	}
	gc := jwt.NewGenericClaims(sub)
	gc.Name = userID
	gc.Data[scopesClaim] = scopes
	for _, opt := range opts {
		opt(gc)
	}
	token, err := gc.Encode(account)
	if err != nil {
		return "", fmt.Errorf("valiss: encode user token: %w", err)
	}
	return token, nil
}

// Verify decodes a token, checks its signature and issuer, and returns the
// claims. The claims' TenantID carries the token subject, whichever level the
// token is for. Verify does NOT check expiry or the allowlist; the Verifier
// layers those so callers get precise errors. A token may omit the bound key
// only when its scopes grant ScopeBearer.
func Verify(token, issuerPubKey string) (*Claims, error) {
	gc, err := jwt.DecodeGeneric(token)
	if err != nil {
		return nil, fmt.Errorf("valiss: %w", err)
	}
	if gc.Issuer != issuerPubKey {
		return nil, fmt.Errorf("valiss: token not signed by the expected issuer")
	}
	var pubKey string
	if nkeys.IsValidPublicAccountKey(gc.Subject) || nkeys.IsValidPublicUserKey(gc.Subject) {
		pubKey = gc.Subject
	}
	scopes := toStrings(gc.Data[scopesClaim])
	if pubKey == "" && !slices.Contains(scopes, ScopeBearer) {
		return nil, errors.New("valiss: token subject is not a key and scopes do not grant bearer")
	}
	name := gc.Name
	if name == "" {
		name = gc.Subject
	}
	claims := &Claims{
		TenantID: name,
		PubKey:   pubKey,
		Scopes:   scopes,
		ID:       gc.ID,
		Issuer:   gc.Issuer,
	}
	if gc.Expires != 0 {
		claims.ExpiresAt = time.Unix(gc.Expires, 0)
	}
	if gc.NotBefore != 0 {
		claims.NotBefore = time.Unix(gc.NotBefore, 0)
	}
	return claims, nil
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

// HasScope reports whether the tenant holds an exact scope grant.
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
	gc, err := jwt.DecodeGeneric(token)
	if err != nil {
		return "", fmt.Errorf("valiss: %w", err)
	}
	return gc.Issuer, nil
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

func toStrings(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

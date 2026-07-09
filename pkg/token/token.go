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

// Scopes carried in the token's custom claims.
const (
	scopesClaim = "scopes"
	pubKeyClaim = "tenant_key"
)

// Claims is the verified content of a tenant token.
type Claims struct {
	// TenantID identifies the tenant; it segments all stored data.
	TenantID string
	// UserID identifies the end user on chain-verified requests, where an
	// account-signed user token accompanies the tenant token. Empty when the
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
	// ExpiresAt is the token expiry.
	ExpiresAt time.Time
}

// Issue mints a tenant token signed by the operator key. tenantPubKey is the
// tenant's nkey public key; the tenant signs requests with the matching seed.
func Issue(operator nkeys.KeyPair, tenantID, tenantPubKey string, scopes []string, ttl time.Duration) (string, error) {
	if pub, err := operator.PublicKey(); err != nil || !nkeys.IsValidPublicOperatorKey(pub) {
		return "", fmt.Errorf("valiss: tenant tokens must be signed by an operator-type nkey (expected an SO... seed)")
	}
	if !nkeys.IsValidPublicUserKey(tenantPubKey) && !nkeys.IsValidPublicAccountKey(tenantPubKey) {
		return "", fmt.Errorf("valiss: invalid tenant public key")
	}
	if ttl <= 0 {
		return "", fmt.Errorf("valiss: ttl must be positive")
	}
	gc := jwt.NewGenericClaims(tenantID)
	gc.Expires = time.Now().Add(ttl).Unix()
	gc.Data[pubKeyClaim] = tenantPubKey
	gc.Data[scopesClaim] = scopes
	token, err := gc.Encode(operator)
	if err != nil {
		return "", fmt.Errorf("valiss: encode token: %w", err)
	}
	return token, nil
}

// IssueUser mints a user token signed by a tenant's account key, delegating a
// subset of the tenant's access to an end user. userPubKey is the user's nkey
// public key; it may be empty only when scopes grant ScopeBearer, producing a
// token-only credential for users that cannot sign requests.
func IssueUser(account nkeys.KeyPair, userID, userPubKey string, scopes []string, ttl time.Duration) (string, error) {
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
	if ttl <= 0 {
		return "", fmt.Errorf("valiss: ttl must be positive")
	}
	gc := jwt.NewGenericClaims(userID)
	gc.Expires = time.Now().Add(ttl).Unix()
	if userPubKey != "" {
		gc.Data[pubKeyClaim] = userPubKey
	}
	gc.Data[scopesClaim] = scopes
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
	pubKey, _ := gc.Data[pubKeyClaim].(string)
	scopes := toStrings(gc.Data[scopesClaim])
	if pubKey == "" && !slices.Contains(scopes, ScopeBearer) {
		return nil, errors.New("valiss: token missing tenant key")
	}
	claims := &Claims{
		TenantID: gc.Subject,
		PubKey:   pubKey,
		Scopes:   scopes,
		ID:       gc.ID,
		Issuer:   gc.Issuer,
	}
	if gc.Expires != 0 {
		claims.ExpiresAt = time.Unix(gc.Expires, 0)
	}
	return claims, nil
}

// Expired reports whether the token has passed its expiry (with skew slack).
func (c *Claims) Expired(now time.Time, skew time.Duration) bool {
	return !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt.Add(skew))
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

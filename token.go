// Package tokenator implements the tenant authentication scheme for the
// v1beta8 gRPC services, modeled on NATS operator/user credentials:
//
//   - An operator holds an Ed25519 nkey (the trust anchor).
//   - The operator issues each tenant a scoped, time-limited JWT that binds
//     the tenant's own nkey public key. Issued tokens are recorded in a
//     server-side allowlist.
//   - The tenant signs every request with its nkey; the server verifies the
//     token against the operator key, the request signature against the
//     token's bound key, and the token against the allowlist, then hands the
//     tenant identity to the handler for data segmentation.
package tokenator

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
	// PubKey is the tenant's nkey public key that must sign requests.
	PubKey string
	// Scopes granted to the tenant.
	Scopes []string
	// ID is the token's unique identifier (jti), the allowlist key.
	ID string
	// Issuer is the operator public key that signed the token.
	Issuer string
	// ExpiresAt is the token expiry.
	ExpiresAt time.Time
}

// Issue mints a tenant token signed by the operator key. tenantPubKey is the
// tenant's nkey public key; the tenant signs requests with the matching seed.
func Issue(operator nkeys.KeyPair, tenantID, tenantPubKey string, scopes []string, ttl time.Duration) (string, error) {
	if !nkeys.IsValidPublicUserKey(tenantPubKey) && !nkeys.IsValidPublicAccountKey(tenantPubKey) {
		return "", fmt.Errorf("tokenator: invalid tenant public key")
	}
	if ttl <= 0 {
		return "", fmt.Errorf("tokenator: ttl must be positive")
	}
	gc := jwt.NewGenericClaims(tenantID)
	gc.Expires = time.Now().Add(ttl).Unix()
	gc.Data[pubKeyClaim] = tenantPubKey
	gc.Data[scopesClaim] = scopes
	token, err := gc.Encode(operator)
	if err != nil {
		return "", fmt.Errorf("tokenator: encode token: %w", err)
	}
	return token, nil
}

// Verify decodes a token, checks its operator signature and issuer, and
// returns the claims. It does NOT check expiry or the allowlist; the
// interceptor layers those so callers get precise errors.
func Verify(token, operatorPubKey string) (*Claims, error) {
	gc, err := jwt.DecodeGeneric(token)
	if err != nil {
		return nil, fmt.Errorf("tokenator: %w", err)
	}
	if gc.Issuer != operatorPubKey {
		return nil, fmt.Errorf("tokenator: token not signed by the expected operator")
	}
	pubKey, _ := gc.Data[pubKeyClaim].(string)
	if pubKey == "" {
		return nil, errors.New("tokenator: token missing tenant key")
	}
	claims := &Claims{
		TenantID: gc.Subject,
		PubKey:   pubKey,
		Scopes:   toStrings(gc.Data[scopesClaim]),
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
	for _, granted := range c.Scopes {
		if scopeMatch(granted, required) {
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

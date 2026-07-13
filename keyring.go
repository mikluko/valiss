package valiss

import (
	"fmt"
)

// Keyring is the set of trusted operators a multi-producer consumer
// verifies against. Every entry is a full self-signed operator token —
// never a bare public key — so each trust domain always carries a name, an
// epoch, and a validity window, and per-domain policy is enforced on every
// verification.
//
// Entries are selected by issuer, not by trial: an incoming chain names its
// operator (the account token's issuer) and its epoch, and verification
// runs against exactly the entry registered under that (key, epoch) pair.
// An unknown pair fails immediately.
//
// One operator key may hold entries at several epochs, which is how a
// receiver grants a rotation grace period: register the new-epoch token
// next to the old one, let producers re-mint at their own pace, and drop
// (or simply let expire) the old entry. Whether and how long two epochs
// coexist is always the receiver's choice.
//
// A Keyring is immutable after construction and safe for concurrent use.
type Keyring struct {
	entries map[keyringKey]*OperatorClaims
	names   map[string]string // name -> operator public key
	jtis    map[string]struct{}
}

type keyringKey struct {
	operator string
	epoch    uint64
}

// NewKeyring builds a keyring from self-signed operator tokens. Identical
// tokens (same jti) collapse into one entry. Registration fails on: a
// different token for an already-occupied (operator key, epoch) pair, two
// operator keys sharing a name, or one operator key naming itself
// differently across entries. Unnamed operators are represented by their
// public key.
func NewKeyring(operatorTokens ...string) (*Keyring, error) {
	k := &Keyring{
		entries: make(map[keyringKey]*OperatorClaims, len(operatorTokens)),
		names:   make(map[string]string, len(operatorTokens)),
		jtis:    make(map[string]struct{}, len(operatorTokens)),
	}
	for i, tok := range operatorTokens {
		issuer, err := IssuerOf(tok)
		if err != nil {
			return nil, fmt.Errorf("valiss: keyring: operator token %d: %w", i, err)
		}
		claims, err := VerifyOperator(tok, issuer)
		if err != nil {
			return nil, fmt.Errorf("valiss: keyring: operator token %d: %w", i, err)
		}
		if _, dup := k.jtis[claims.ID]; dup {
			continue
		}
		key := keyringKey{operator: claims.Subject, epoch: claims.Epoch}
		if _, occupied := k.entries[key]; occupied {
			return nil, fmt.Errorf("valiss: keyring: duplicate entry for operator %s epoch %d", claims.Subject, claims.Epoch)
		}
		if owner, taken := k.names[claims.Name]; taken && owner != claims.Subject {
			return nil, fmt.Errorf("valiss: keyring: operator name %q already names a different operator", claims.Name)
		}
		for kk, existing := range k.entries {
			if kk.operator == claims.Subject && existing.Name != claims.Name {
				return nil, fmt.Errorf("valiss: keyring: operator %s entries disagree on name (%q vs %q)", claims.Subject, existing.Name, claims.Name)
			}
		}
		k.entries[key] = claims
		k.names[claims.Name] = claims.Subject
		k.jtis[claims.ID] = struct{}{}
	}
	if len(k.entries) == 0 {
		return nil, fmt.Errorf("valiss: keyring: no operator tokens")
	}
	return k, nil
}

// lookup returns the entry registered for an operator key at an epoch.
func (k *Keyring) lookup(operatorPubKey string, epoch uint64) (*OperatorClaims, bool) {
	c, ok := k.entries[keyringKey{operator: operatorPubKey, epoch: epoch}]
	return c, ok
}

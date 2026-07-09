package valiss

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
)

// Wire format: a JWT signed with an nkey, NATS style ("ed25519-nkey"
// algorithm, jti derived from the claims hash). Standard claims follow RFC
// 7519; the valiss section carries this scheme's own claim bodies, typed by
// its type field.
const (
	tokenHeader = `{"typ":"JWT","alg":"ed25519-nkey"}`

	accountType = "account"
	userType    = "user"
)

// Extensions is the named extension claims of a token: consumer- or
// transport-defined claim bodies keyed by extension name. This scheme signs
// and transports them; meaning is assigned by whoever registered the name
// (e.g. the httpauth and grpcauth packages, or the library consumer).
type Extensions map[string]json.RawMessage

// accountBody is the valiss section of an account token.
type accountBody struct {
	// Type discriminates the claim body; always "account".
	Type string `json:"type"`
	// Ext carries the named extension claims (WithExtension).
	Ext Extensions `json:"ext,omitempty"`
}

// userBody is the valiss section of a user token.
type userBody struct {
	// Type discriminates the claim body; always "user".
	Type string `json:"type"`
	// Bearer marks a token the server accepts without per-request
	// signatures.
	Bearer bool `json:"bearer,omitempty"`
	// Ext carries the named extension claims (WithExtension).
	Ext Extensions `json:"ext,omitempty"`
}

// wire is the JWT claims document. Standard fields use their RFC 7519 names
// on the wire; the field order is fixed, keeping the jti hash deterministic.
type wire[B any] struct {
	ID        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Name      string `json:"name,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Expires   int64  `json:"exp,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Valiss    B      `json:"valiss"`
}

// encodeToken stamps iat, derives the jti from the claims hash, and signs
// the token with the issuer key pair.
func encodeToken[B any](issuer nkeys.KeyPair, c *wire[B]) (string, error) {
	pub, err := issuer.PublicKey()
	if err != nil {
		return "", fmt.Errorf("valiss: issuer key: %w", err)
	}
	c.Issuer = pub
	c.IssuedAt = time.Now().Unix()
	c.ID = ""
	unhashed, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("valiss: encode claims: %w", err)
	}
	digest := sha256.Sum256(unhashed)
	c.ID = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("valiss: encode claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(tokenHeader)) +
		"." + base64.RawURLEncoding.EncodeToString(payload)
	sig, err := issuer.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("valiss: sign token: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// decodeToken parses a token and verifies its signature against the issuer
// key embedded in the claims. Trust is NOT established here: the caller must
// check the issuer's place in the chain.
func decodeToken[B any](token string) (*wire[B], error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("valiss: malformed token")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("valiss: token header: %w", err)
	}
	var header struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return nil, fmt.Errorf("valiss: token header: %w", err)
	}
	if header.Typ != "JWT" || header.Alg != "ed25519-nkey" {
		return nil, fmt.Errorf("valiss: unsupported token type %s/%s", header.Typ, header.Alg)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("valiss: token claims: %w", err)
	}
	var c wire[B]
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("valiss: token claims: %w", err)
	}
	issuer, err := nkeys.FromPublicKey(c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("valiss: token issuer: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("valiss: token signature: %w", err)
	}
	if err := issuer.Verify([]byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, errors.New("valiss: token signature verification failed")
	}
	return &c, nil
}

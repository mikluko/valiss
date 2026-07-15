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

// Wire format: a JWT signed with an nkey ("ed25519-nkey" algorithm, jti
// derived from the claims hash). Standard claims follow RFC 7519; the valiss
// section carries this scheme's own claim bodies, typed by its type field.
//
// The header carries an explicit wire-format version (ver). peekVersion reads
// it before the payload is parsed, so decodeToken can dispatch to the matching
// per-version decoder (decodeV1, and any future decodeVN) or reject an unknown
// version cleanly, rather than mis-parsing it under the wrong layout. Every
// per-version decoder verifies the signature regardless of version. Adding a
// version is additive: a new set of wireVN types, a decodeVN that normalizes
// into decoded, and one case in decodeToken. Nothing outside that set changes.
//
// tokenHeaderV1 is the frozen, byte-exact header for wireVersion 1 and must
// stay in sync with wireVersion. Tokens are always minted at the current
// version; any supported version can be read.
const (
	wireVersion   = 1
	tokenHeaderV1 = `{"typ":"JWT","alg":"ed25519-nkey","ver":1}`

	operatorType = "operator"
	accountType  = "account"
	userType     = "user"
	messageType  = "message"
)

// operatorBodyV1 is the valiss section of a self-signed operator token: the
// trust domain's policy statement.
type operatorBodyV1 struct {
	// Type discriminates the claim body; always "operator".
	Type string `json:"type"`
	// Epoch is the trust domain's current epoch; account and user tokens
	// must echo it when the verifier is configured with the operator token.
	Epoch uint64 `json:"epoch,omitempty"`
	// Ext carries the named extension claims (WithExtension).
	Ext Extensions `json:"ext,omitempty"`
}

// Extensions is the named extension claims of a token: consumer- or
// transport-defined claim bodies keyed by extension name. This scheme signs
// and transports them; meaning is assigned by whoever registered the name
// (e.g. the httpauth and grpcauth packages, or the library consumer).
type Extensions map[string]json.RawMessage

// accountBodyV1 is the valiss section of an account token.
type accountBodyV1 struct {
	// Type discriminates the claim body; always "account".
	Type string `json:"type"`
	// Epoch is the trust-domain epoch the token was issued in.
	Epoch uint64 `json:"epoch,omitempty"`
	// Ext carries the named extension claims (WithExtension).
	Ext Extensions `json:"ext,omitempty"`
}

// userBodyV1 is the valiss section of a user token.
type userBodyV1 struct {
	// Type discriminates the claim body; always "user".
	Type string `json:"type"`
	// Epoch is the trust-domain epoch the token was issued in.
	Epoch uint64 `json:"epoch,omitempty"`
	// Bearer marks a token the server accepts without per-request
	// signatures.
	Bearer bool `json:"bearer,omitempty"`
	// Ext carries the named extension claims (WithExtension).
	Ext Extensions `json:"ext,omitempty"`
}

// messageChainV1 is the provenance chain embedded in a message token
// (WithChain): everything a receiver needs to walk the chain up to the
// pinned operator key without fetching anything.
type messageChainV1 struct {
	// Account is the operator-signed account token.
	Account string `json:"account,omitempty"`
	// User is the account-signed user token of the emitter.
	User string `json:"user,omitempty"`
}

// messageBodyV1 is the valiss section of a message token: a per-message proof
// of origin signed by a user key.
type messageBodyV1 struct {
	// Type discriminates the claim body; always "message".
	Type string `json:"type"`
	// Epoch is the trust-domain epoch the token was issued in.
	Epoch uint64 `json:"epoch,omitempty"`
	// Checksum is the lowercase-hex SHA-256 of the message payload exactly
	// as delivered, binding the token to the bytes.
	Checksum string `json:"checksum,omitempty"`
	// Chain carries the embedded provenance chain (WithChain).
	Chain *messageChainV1 `json:"chain,omitempty"`
	// Ext carries the named extension claims (WithExtension).
	Ext Extensions `json:"ext,omitempty"`
}

// wireV1 is the version-1 JWT claims document. Standard fields use their RFC
// 7519 names on the wire; the field order is fixed, keeping the jti hash
// deterministic. Every standard field except the valiss section is omitempty,
// so a level that never sets a field (e.g. aud outside message tokens) leaves
// the byte stream, and therefore the jti derivation, of other levels
// untouched. Generic over the typed body so each level mints exactly its own
// fields.
type wireV1[B any] struct {
	ID        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Name      string `json:"name,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	Expires   int64  `json:"exp,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Valiss    B      `json:"valiss"`
}

// decoded is a version-neutral view of a parsed, signature-verified token.
// Per-version decoders normalize their own wire layout into it, so the public
// Verify* and Decode paths never depend on a wire version. Body fields are the
// union across the four levels; a level leaves the ones it does not use zero.
type decoded struct {
	ID        string
	Issuer    string
	Subject   string
	Name      string
	Audience  string
	IssuedAt  int64
	Expires   int64
	NotBefore int64

	Type     string
	Epoch    uint64
	Bearer   bool
	Checksum string
	Chain    *messageChainV1
	Ext      Extensions
}

// encodeV1 mints a version-1 token: it stamps iat, derives the jti from the
// claims hash, and signs the header-and-payload with the issuer key pair.
func encodeV1[B any](issuer nkeys.KeyPair, c *wireV1[B]) (string, error) {
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
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(tokenHeaderV1)) +
		"." + base64.RawURLEncoding.EncodeToString(payload)
	sig, err := issuer.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("valiss: sign token: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// peekVersion reads the wire-format version from a token's header without
// decoding its payload, and returns the version and the three JWS segments.
// It is version-agnostic: it only checks the envelope shape (three parts,
// JSON header, JWT/ed25519-nkey) common to all versions, so it never changes
// as versions are added.
func peekVersion(token string) (int, [3]string, error) {
	var zero [3]string
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, zero, errors.New("valiss: malformed token")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, zero, fmt.Errorf("valiss: token header: %w", err)
	}
	var header struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		Ver int    `json:"ver"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return 0, zero, fmt.Errorf("valiss: token header: %w", err)
	}
	if header.Typ != "JWT" || header.Alg != "ed25519-nkey" {
		return 0, zero, fmt.Errorf("valiss: unsupported token type %s/%s", header.Typ, header.Alg)
	}
	return header.Ver, [3]string{parts[0], parts[1], parts[2]}, nil
}

// decodeToken parses a token, verifies its signature against the issuer key
// embedded in the claims, and returns a version-neutral view. It dispatches on
// the wire version read from the header. Trust is NOT established here: the
// caller must check the issuer's place in the chain.
func decodeToken(token string) (*decoded, error) {
	ver, parts, err := peekVersion(token)
	if err != nil {
		return nil, err
	}
	switch ver {
	case wireVersion:
		return decodeV1(parts)
	default:
		return nil, fmt.Errorf("valiss: unsupported wire version %d", ver)
	}
}

// decodeV1 parses a version-1 payload, verifies the signature, and normalizes
// into decoded. The valiss body is read through a union of every level's
// fields; a level's absent fields stay zero.
func decodeV1(parts [3]string) (*decoded, error) {
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("valiss: token claims: %w", err)
	}
	var c wireV1[struct {
		Type     string          `json:"type"`
		Epoch    uint64          `json:"epoch"`
		Bearer   bool            `json:"bearer"`
		Checksum string          `json:"checksum"`
		Chain    *messageChainV1 `json:"chain"`
		Ext      Extensions      `json:"ext"`
	}]
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
	return &decoded{
		ID:        c.ID,
		Issuer:    c.Issuer,
		Subject:   c.Subject,
		Name:      c.Name,
		Audience:  c.Audience,
		IssuedAt:  c.IssuedAt,
		Expires:   c.Expires,
		NotBefore: c.NotBefore,
		Type:      c.Valiss.Type,
		Epoch:     c.Valiss.Epoch,
		Bearer:    c.Valiss.Bearer,
		Checksum:  c.Valiss.Checksum,
		Chain:     c.Valiss.Chain,
		Ext:       c.Valiss.Ext,
	}, nil
}

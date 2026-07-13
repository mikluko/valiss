package valiss

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nkeys"
)

// DefaultMessageTTL is the validity window the contrib transports mint
// message tokens with: long enough for delivery latency and clock drift,
// short enough to bound capture exposure.
const DefaultMessageTTL = 30 * time.Second

// ErrNoChain reports a message token that neither embeds a provenance chain
// nor had one supplied (WithChainTokens). Receiving transports match it
// with errors.Is to drive chain negotiation: it is the one verification
// failure a retransmit with the chain can cure.
var ErrNoChain = errors.New("valiss: message token carries no chain and none was supplied (WithChainTokens)")

// MessageClaims is the verified content of a message token: a per-message
// proof of origin, together with the verified chain identities it was
// checked against. A message token is a proof, not a credential: possession
// grants nothing, and Verifier.VerifyRequest never accepts one.
type MessageClaims struct {
	Claims
	// Audience is the destination the token was minted for (aud); empty
	// when the token is unbound.
	Audience string
	// Checksum is the lowercase-hex SHA-256 of the payload the token was
	// minted over; empty when the token carries no payload binding.
	Checksum string
	// Epoch is the trust-domain epoch the token was issued in (WithEpoch).
	Epoch uint64
	// Ext carries the named extension claims (WithExtension).
	Ext Extensions
	// Account is the verified tenant identity from the chain. Offline
	// receivers hold no allowlist; an online receiver that wants revocation
	// checks Account.ID against its own Allowlist.
	Account *AccountClaims
	// User is the verified emitter identity from the chain; its subject key
	// signed the message token.
	User *UserClaims
	// Operator is the trust domain the message verified under: the keyring
	// entry on VerifyMessageKeyring, the policy token on VerifyMessage with
	// WithOperatorPolicy, nil otherwise. Consumers trusting several
	// operators segment by Operator.Name — the keyring guarantees a name
	// maps to exactly one operator key.
	Operator *OperatorClaims
}

// Checksum returns the lowercase-hex SHA-256 of a payload exactly as
// delivered: the value WithChecksum embeds and WithPayload compares.
func Checksum(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// isHexSHA256 reports whether s is a lowercase-hex SHA-256 digest.
func isHexSHA256(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// IssueMessage mints a per-message proof-of-origin token signed by the
// emitter's user key over itself (iss == sub). WithAudience binds it to a
// destination, WithChecksum to the payload bytes, and WithChain embeds the
// provenance chain so a receiver verifies offline with only the operator
// public key (VerifyMessage). Message tokens must carry an expiry: they are
// short-lived proofs, and an eternal proof of origin only widens capture
// exposure.
func IssueMessage(user nkeys.KeyPair, opts ...IssueOption) (string, error) {
	pub, err := user.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(pub) {
		return "", errors.New("valiss: message tokens must be signed by a user-type nkey (expected an SU... seed)")
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
	if cfg.name != "" {
		return "", errors.New("valiss: name applies only to operator, account, and user tokens")
	}
	if cfg.expires == 0 {
		return "", errors.New("valiss: message tokens must carry an expiry (WithTTL or WithExpiry)")
	}
	if cfg.chain != nil {
		if err := checkChain(cfg.chain, pub); err != nil {
			return "", err
		}
	}
	return encodeToken(user, &wire[messageBody]{
		Subject:   pub,
		Audience:  cfg.audience,
		Expires:   cfg.expires,
		NotBefore: cfg.notBefore,
		Valiss: messageBody{
			Type:     messageType,
			Epoch:    cfg.epoch,
			Checksum: cfg.checksum,
			Chain:    cfg.chain,
			Ext:      cfg.ext,
		},
	})
}

// checkChain fails a mint fast when the embedded chain is structurally
// broken. No trust anchor is available at mint time, so the account token is
// only checked for self-consistency; VerifyMessage roots the chain in the
// operator key.
func checkChain(ch *messageChain, emitterPub string) error {
	issuer, err := IssuerOf(ch.Account)
	if err != nil {
		return fmt.Errorf("valiss: chain account token: %w", err)
	}
	account, err := VerifyAccount(ch.Account, issuer)
	if err != nil {
		return fmt.Errorf("valiss: chain account token: %w", err)
	}
	user, err := VerifyUser(ch.User, account.Subject)
	if err != nil {
		return fmt.Errorf("valiss: chain user token: %w", err)
	}
	if user.Subject != emitterPub {
		return errors.New("valiss: chain user token is not for the minting user key")
	}
	return nil
}

// verifyMessageConfig collects VerifyMessageOption effects.
type verifyMessageConfig struct {
	at            time.Time
	skew          time.Duration
	audience      string
	requireSum    bool
	payload       []byte
	hasPayload    bool
	operatorToken string
	hasOperator   bool
	chain         *messageChain
}

// VerifyMessageOption customizes VerifyMessage.
type VerifyMessageOption func(*verifyMessageConfig)

// At evaluates the validity windows and operator policy as of the supplied
// instant instead of now, so stored messages verify after their tokens
// expire. Callers keeping key and epoch history pass the instant the message
// was received.
func At(t time.Time) VerifyMessageOption {
	return func(c *verifyMessageConfig) { c.at = t }
}

// WithMessageSkew overrides the DefaultSkew slack applied to the validity
// windows of the message token and its chain.
func WithMessageSkew(d time.Duration) VerifyMessageOption {
	return func(c *verifyMessageConfig) { c.skew = d }
}

// ExpectAudience requires the message token to be bound to exactly this
// destination; a token minted for anywhere else — or bound to no audience at
// all — is rejected. This is the receiver's lever against cross-destination
// replay; every receiver that knows its own identity should set it.
func ExpectAudience(aud string) VerifyMessageOption {
	return func(c *verifyMessageConfig) { c.audience = aud }
}

// RequireChecksum rejects message tokens that carry no checksum claim, for
// receivers that insist every message is payload-bound. Comparison against
// the actual bytes still requires WithPayload.
func RequireChecksum() VerifyMessageOption {
	return func(c *verifyMessageConfig) { c.requireSum = true }
}

// WithPayload hashes the payload exactly as received and requires the
// token's checksum claim to match; a token without a checksum claim is
// rejected. This is the receiver's lever against payload tampering.
func WithPayload(payload []byte) VerifyMessageOption {
	return func(c *verifyMessageConfig) {
		c.payload = payload
		c.hasPayload = true
	}
}

// WithOperatorPolicy supplies the trust domain's self-signed operator token
// (the same token WithOperatorToken takes on a Verifier) and enforces its
// policy: the operator token must be within its own validity window at the
// verification instant, and the message token must echo the domain epoch.
func WithOperatorPolicy(operatorToken string) VerifyMessageOption {
	return func(c *verifyMessageConfig) {
		c.operatorToken = operatorToken
		c.hasOperator = true
	}
}

// WithChainTokens supplies the provenance chain out-of-band for message
// tokens minted without WithChain, trading self-containment for smaller
// tokens. A token that embeds a chain must embed this exact chain; a
// mismatch is an error.
func WithChainTokens(accountToken, userToken string) VerifyMessageOption {
	return func(c *verifyMessageConfig) {
		c.chain = &messageChain{Account: accountToken, User: userToken}
	}
}

// VerifyMessage verifies a per-message proof of origin against the pinned
// operator public key: it walks the chain operator → account → user →
// message, requires all chain levels to agree on the epoch, checks every
// validity window at the verification instant (At; default now), and
// enforces the audience and checksum bindings the options request. On
// success the returned claims carry the verified tenant and emitter
// identities alongside the message bindings.
//
// A verified message token proves origin only. It is not a credential:
// grant nothing for possession of one.
func VerifyMessage(token, operatorPubKey string, opts ...VerifyMessageOption) (*MessageClaims, error) {
	return verifyMessage(token, opts, func(cfg *verifyMessageConfig, chainAccount string) (*AccountClaims, *OperatorClaims, error) {
		account, err := VerifyAccount(chainAccount, operatorPubKey)
		if err != nil {
			return nil, nil, err
		}
		if !cfg.hasOperator {
			return account, nil, nil
		}
		operator, err := VerifyOperator(cfg.operatorToken, operatorPubKey)
		if err != nil {
			return nil, nil, err
		}
		return account, operator, nil
	})
}

// VerifyMessageKeyring verifies a per-message proof of origin against a set
// of trusted operators (see Keyring). The chain names its trust domain —
// the account token's issuer and epoch select exactly one keyring entry —
// and verification then runs as VerifyMessage does under that entry's
// always-enforced policy: the entry token's validity window at the
// verification instant and its exact epoch. A chain from an unknown
// operator, or a known operator at an unregistered epoch, fails
// immediately. The returned claims carry the matched entry as Operator.
//
// WithOperatorPolicy does not combine with a keyring: entries carry the
// policy.
func VerifyMessageKeyring(token string, keyring *Keyring, opts ...VerifyMessageOption) (*MessageClaims, error) {
	return verifyMessage(token, opts, func(cfg *verifyMessageConfig, chainAccount string) (*AccountClaims, *OperatorClaims, error) {
		if cfg.hasOperator {
			return nil, nil, errors.New("valiss: operator policy applies to single-anchor verification; keyring entries carry policy")
		}
		issuer, err := IssuerOf(chainAccount)
		if err != nil {
			return nil, nil, err
		}
		account, err := VerifyAccount(chainAccount, issuer)
		if err != nil {
			return nil, nil, err
		}
		operator, ok := keyring.lookup(issuer, account.Epoch)
		if !ok {
			return nil, nil, fmt.Errorf("valiss: no trusted operator %s at epoch %d", issuer, account.Epoch)
		}
		return account, operator, nil
	})
}

// verifyMessage is the shared verification core; anchor resolves and
// trust-checks the chain's account token and returns the operator policy to
// enforce (nil for none). Window and epoch checks on whatever anchor
// returns stay in the core, so anchors never need the instant.
func verifyMessage(token string, opts []VerifyMessageOption, anchor func(cfg *verifyMessageConfig, chainAccount string) (*AccountClaims, *OperatorClaims, error)) (*MessageClaims, error) {
	cfg := verifyMessageConfig{skew: DefaultSkew}
	for _, opt := range opts {
		opt(&cfg)
	}
	c, err := decodeToken[messageBody](token)
	if err != nil {
		return nil, err
	}
	if c.Valiss.Type != messageType {
		return nil, fmt.Errorf("valiss: not a message token (type %q)", c.Valiss.Type)
	}
	if c.Issuer != c.Subject {
		return nil, errors.New("valiss: message token not self-signed by its user key")
	}
	if !nkeys.IsValidPublicUserKey(c.Subject) {
		return nil, errors.New("valiss: message token subject is not a user public key")
	}
	chain := c.Valiss.Chain
	switch {
	case chain == nil && cfg.chain == nil:
		return nil, ErrNoChain
	case chain == nil:
		chain = cfg.chain
	case cfg.chain != nil && (cfg.chain.Account != chain.Account || cfg.chain.User != chain.User):
		return nil, errors.New("valiss: message token embeds a chain that differs from the supplied chain")
	}
	at := cfg.at
	if at.IsZero() {
		at = time.Now()
	}
	account, operator, err := anchor(&cfg, chain.Account)
	if err != nil {
		return nil, err
	}
	user, err := VerifyUser(chain.User, account.Subject)
	if err != nil {
		return nil, err
	}
	if user.Subject != c.Issuer {
		return nil, errors.New("valiss: message token not signed by the chain's user key")
	}
	if operator != nil {
		if operator.Expired(at, cfg.skew) {
			return nil, errors.New("valiss: operator token expired: the trust domain is closed")
		}
		if operator.NotYetValid(at, cfg.skew) {
			return nil, errors.New("valiss: operator token not yet valid")
		}
		if c.Valiss.Epoch != operator.Epoch {
			return nil, fmt.Errorf("valiss: message token epoch %d, trust domain epoch %d", c.Valiss.Epoch, operator.Epoch)
		}
	}
	if c.Valiss.Epoch != account.Epoch {
		return nil, fmt.Errorf("valiss: message token epoch %d, account token epoch %d", c.Valiss.Epoch, account.Epoch)
	}
	if c.Valiss.Epoch != user.Epoch {
		return nil, fmt.Errorf("valiss: message token epoch %d, user token epoch %d", c.Valiss.Epoch, user.Epoch)
	}
	claims := MessageClaims{
		Claims:   claimsOf(c.ID, c.Issuer, c.Subject, c.IssuedAt, c.Expires, c.NotBefore),
		Audience: c.Audience,
		Checksum: c.Valiss.Checksum,
		Epoch:    c.Valiss.Epoch,
		Ext:      c.Valiss.Ext,
		Account:  account,
		User:     user,
		Operator: operator,
	}
	if account.Expired(at, cfg.skew) {
		return nil, errors.New("valiss: account token expired")
	}
	if account.NotYetValid(at, cfg.skew) {
		return nil, errors.New("valiss: account token not yet valid")
	}
	if user.Expired(at, cfg.skew) {
		return nil, errors.New("valiss: user token expired")
	}
	if user.NotYetValid(at, cfg.skew) {
		return nil, errors.New("valiss: user token not yet valid")
	}
	if claims.Expired(at, cfg.skew) {
		return nil, errors.New("valiss: message token expired")
	}
	if claims.NotYetValid(at, cfg.skew) {
		return nil, errors.New("valiss: message token not yet valid")
	}
	if cfg.audience != "" && claims.Audience != cfg.audience {
		return nil, fmt.Errorf("valiss: message token audience %q, expected %q", claims.Audience, cfg.audience)
	}
	if cfg.hasPayload {
		if claims.Checksum == "" {
			return nil, errors.New("valiss: message token carries no checksum")
		}
		if claims.Checksum != Checksum(cfg.payload) {
			return nil, errors.New("valiss: payload checksum mismatch")
		}
	} else if cfg.requireSum && claims.Checksum == "" {
		return nil, errors.New("valiss: message token carries no checksum")
	}
	return &claims, nil
}

package valiss

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/nats-io/nkeys"
)

// DefaultSkew bounds request-timestamp drift and token-expiry slack.
const DefaultSkew = 2 * time.Minute

// requestPrefixV1 is the version tag bound into the version-1 request-signature
// material. Because it is part of the signed bytes, a verifier that
// reconstructs v1 bytes fails closed on a request signed under any other
// version (the signatures cannot match) rather than mis-verifying it. A future
// version would add signedPayloadV2 and dispatch on a transport-carried
// version; v1 needs no such signal because it fails closed.
const requestPrefixV1 = "valiss-req-v1\n"

// NewNonce returns a fresh random per-request nonce (128 bits, hex). Client
// transports use it when a replay cache is in play; see WithReplayCache.
func NewNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("valiss: nonce entropy: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// signedPayloadV1 is the canonical version-1 byte string a subject signs per
// request: a version tag, then the timestamp bound to a hash of the request
// context. Binding the context (the transport's canonical method/path) stops a
// captured signature from authorizing a different operation; the timestamp and
// skew window bound replay of the same operation. Rendered deterministically so
// both sides derive identical bytes.
func signedPayloadV1(ts time.Time, reqContext []byte) []byte {
	sum := sha256.Sum256(reqContext)
	return []byte(requestPrefixV1 + ts.UTC().Format(time.RFC3339Nano) + "\n" + hex.EncodeToString(sum[:]))
}

// SignRequest produces the timestamp and base64 signature a subject attaches
// to a request, signing the timestamp bound to reqContext with its nkey seed.
// reqContext is the transport's canonical description of the request (e.g.
// method and path); the server must reconstruct identical bytes. Pass nil to
// bind nothing beyond the timestamp.
func SignRequest(subject nkeys.KeyPair, now time.Time, reqContext []byte) (timestamp, signature string, err error) {
	sig, err := subject.Sign(signedPayloadV1(now, reqContext))
	if err != nil {
		return "", "", fmt.Errorf("valiss: sign request: %w", err)
	}
	return now.UTC().Format(time.RFC3339Nano), base64.StdEncoding.EncodeToString(sig), nil
}

// VerifySignature checks a request signature against the subject public key,
// bounds the timestamp to a symmetric skew window around now, and confirms it
// was signed over reqContext. reqContext must match the bytes the client
// signed (see SignRequest).
func VerifySignature(subjectPubKey, timestamp, signature string, reqContext []byte, now time.Time, skew time.Duration) error {
	ts, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return fmt.Errorf("valiss: bad request timestamp: %w", err)
	}
	if d := now.Sub(ts); d > skew || d < -skew {
		return fmt.Errorf("valiss: request timestamp outside the %s skew window", skew)
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("valiss: bad request signature encoding: %w", err)
	}
	pub, err := nkeys.FromPublicKey(subjectPubKey)
	if err != nil {
		return fmt.Errorf("valiss: bad subject public key: %w", err)
	}
	if err := pub.Verify(signedPayloadV1(ts, reqContext), sig); err != nil {
		return fmt.Errorf("valiss: request signature verification failed: %w", err)
	}
	return nil
}

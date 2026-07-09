package tokenator

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/nats-io/nkeys"
)

// signedPayload is the canonical byte string a tenant signs per request. It
// is just the timestamp: the token binds the tenant key, the allowlist bounds
// validity, and the skew window bounds replay. Rendered as RFC3339Nano.
func signedPayload(ts time.Time) []byte {
	return []byte(ts.UTC().Format(time.RFC3339Nano))
}

// SignRequest produces the timestamp and base64 signature a tenant attaches
// to a request, signing with its nkey seed.
func SignRequest(tenant nkeys.KeyPair, now time.Time) (timestamp, signature string, err error) {
	sig, err := tenant.Sign(signedPayload(now))
	if err != nil {
		return "", "", fmt.Errorf("tokenator: sign request: %w", err)
	}
	return now.UTC().Format(time.RFC3339Nano), base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyRequest checks a request signature against the tenant public key and
// bounds the timestamp to a symmetric skew window around now.
func VerifyRequest(tenantPubKey, timestamp, signature string, now time.Time, skew time.Duration) error {
	ts, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return fmt.Errorf("tokenator: bad request timestamp: %w", err)
	}
	if d := now.Sub(ts); d > skew || d < -skew {
		return fmt.Errorf("tokenator: request timestamp outside the %s skew window", skew)
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("tokenator: bad request signature encoding: %w", err)
	}
	pub, err := nkeys.FromPublicKey(tenantPubKey)
	if err != nil {
		return fmt.Errorf("tokenator: bad tenant public key: %w", err)
	}
	if err := pub.Verify(signedPayload(ts), sig); err != nil {
		return fmt.Errorf("tokenator: request signature verification failed: %w", err)
	}
	return nil
}

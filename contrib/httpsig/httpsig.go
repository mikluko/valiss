// Package httpsig wires per-message proofs of origin (valiss message
// tokens) into net/http: a client Transport that mints a token per outgoing
// request and a server middleware that verifies it offline against the
// operator public key. Handlers read the verified claims with
// valiss.MessageFromContext.
//
// A message token proves origin only — it authenticates the message, not a
// caller, and grants no identity. Pair with contrib/httpauth when the
// caller must also authenticate.
package httpsig

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/nats-io/nkeys"

	"valiss.dev/valiss"
	"valiss.dev/valiss/creds"
)

// Audience is the canonical destination identity of an HTTP request a
// message token is bound to: host and path, query excluded. The emitting
// Transport (absolute URL) and the receiving middleware (Host header +
// path) must derive identical bytes, so the host is taken from r.Host with
// a fallback to the URL, and the scheme is excluded (unknowable behind TLS
// terminators).
func Audience(r *http.Request) string {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return host + r.URL.Path
}

// minter validates emitter creds and derives the mint parameters: the user
// keypair from the seed and the trust-domain epoch from the chain tokens,
// which must agree on it (valiss.VerifyMessage requires all levels to).
func minter(b creds.Creds) (nkeys.KeyPair, uint64, error) {
	if b.AccountToken == "" || b.UserToken == "" || len(b.Seed) == 0 {
		return nil, 0, errors.New("valiss: message signing requires bundle creds: account token, user token, and seed")
	}
	user, err := nkeys.FromSeed(b.Seed)
	if err != nil {
		return nil, 0, fmt.Errorf("valiss: creds seed: %w", err)
	}
	accountIssuer, err := valiss.IssuerOf(b.AccountToken)
	if err != nil {
		return nil, 0, fmt.Errorf("valiss: creds account token: %w", err)
	}
	account, err := valiss.VerifyAccount(b.AccountToken, accountIssuer)
	if err != nil {
		return nil, 0, fmt.Errorf("valiss: creds account token: %w", err)
	}
	userClaims, err := valiss.VerifyUser(b.UserToken, account.Subject)
	if err != nil {
		return nil, 0, fmt.Errorf("valiss: creds user token: %w", err)
	}
	if account.Epoch != userClaims.Epoch {
		return nil, 0, fmt.Errorf("valiss: creds chain epochs disagree: account %d, user %d", account.Epoch, userClaims.Epoch)
	}
	return user, userClaims.Epoch, nil
}

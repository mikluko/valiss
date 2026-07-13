// Package grpcsig wires per-message proofs of origin (valiss message
// tokens) into gRPC: a client unary interceptor that mints a token per call
// and a server unary interceptor that verifies it offline against the
// operator public key. Handlers read the verified claims with
// valiss.MessageFromContext.
//
// A message token proves origin only — it authenticates the message, not a
// caller, and grants no identity. Pair with contrib/grpcauth when the
// caller must also authenticate.
//
// The checksum is bound to the request message's deterministic protobuf
// encoding (the wire bytes are not available inside interceptors, so both
// ends re-marshal deterministically); keep the protobuf runtime versions of
// emitter and receiver in step.
package grpcsig

import (
	"errors"
	"fmt"

	"github.com/nats-io/nkeys"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/creds"
)

// payload is the canonical byte string a message token's checksum is bound
// to for a gRPC message: its deterministic protobuf encoding.
func payload(msg any) ([]byte, error) {
	m, ok := msg.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("valiss: message checksum requires a proto.Message, got %T", msg)
	}
	p, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("valiss: message checksum: marshal: %w", err)
	}
	return p, nil
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

func first(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}

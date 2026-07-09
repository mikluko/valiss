package grpcauth

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nkeys"
	"google.golang.org/grpc/credentials"

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/creds"
)

// Credentials is a grpc.PerRPCCredentials that attaches the creds' tokens
// and, when the creds hold a seed, a fresh per-call signature. Creds
// without a seed are bearer credentials: the server accepts them only when
// the effective token is a bearer user token. Use
// grpc.WithPerRPCCredentials on the client.
type Credentials struct {
	accountToken string
	userToken    string
	subject      nkeys.KeyPair
	now          func() time.Time
	// requireTLS mirrors the transport: gRPC refuses to send per-RPC
	// credentials over an insecure connection unless this is false.
	requireTLS bool
}

// NewCredentials builds client credentials from parsed creds: the tokens
// they carry and the seed matching the effective token's bound key (nil
// for bearer creds).
func NewCredentials(b creds.Creds) (*Credentials, error) {
	c := &Credentials{accountToken: b.AccountToken, userToken: b.UserToken, now: time.Now, requireTLS: true}
	if len(b.Seed) > 0 {
		subject, err := nkeys.FromSeed(b.Seed)
		if err != nil {
			return nil, fmt.Errorf("valiss: creds seed: %w", err)
		}
		c.subject = subject
	}
	return c, nil
}

// AllowInsecure permits sending the credential over a non-TLS connection,
// e.g. a local API-server port-forward tunnel that is already encrypted.
func (c *Credentials) AllowInsecure() *Credentials {
	c.requireTLS = false
	return c
}

func (c *Credentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	md := map[string]string{}
	if c.accountToken != "" {
		md[valiss.HeaderAccountToken] = c.accountToken
	}
	if c.userToken != "" {
		md[valiss.HeaderUserToken] = c.userToken
	}
	if c.subject != nil {
		timestamp, signature, err := valiss.SignRequest(c.subject, c.now())
		if err != nil {
			return nil, err
		}
		md[valiss.HeaderTimestamp] = timestamp
		md[valiss.HeaderSignature] = signature
	}
	return md, nil
}

func (c *Credentials) RequireTransportSecurity() bool { return c.requireTLS }

var _ credentials.PerRPCCredentials = (*Credentials)(nil)

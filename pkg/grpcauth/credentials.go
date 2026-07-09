package grpcauth

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nkeys"
	"google.golang.org/grpc/credentials"

	"github.com/mikluko/valiss/pkg/creds"
	"github.com/mikluko/valiss/pkg/token"
)

// Credentials is a grpc.PerRPCCredentials that attaches the credential
// bundle's tokens and, when the bundle holds a seed, a fresh per-call
// signature. Bundles without a seed are bearer credentials: the server
// accepts them only when the effective token grants token.ScopeBearer. Use
// grpc.WithPerRPCCredentials on the client.
type Credentials struct {
	token     string
	userToken string
	subject   nkeys.KeyPair
	now       func() time.Time
	// requireTLS mirrors the transport: gRPC refuses to send per-RPC
	// credentials over an insecure connection unless this is false.
	requireTLS bool
}

// NewCredentials builds client credentials from a creds bundle: the tenant
// token, the optional user token, and the seed matching the effective
// token's bound key (nil for bearer bundles).
func NewCredentials(b creds.Bundle) (*Credentials, error) {
	c := &Credentials{token: b.Token, userToken: b.UserToken, now: time.Now, requireTLS: true}
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
	md := map[string]string{token.HeaderToken: c.token}
	if c.userToken != "" {
		md[token.HeaderUserToken] = c.userToken
	}
	if c.subject != nil {
		timestamp, signature, err := token.SignRequest(c.subject, c.now())
		if err != nil {
			return nil, err
		}
		md[token.HeaderTimestamp] = timestamp
		md[token.HeaderSignature] = signature
	}
	return md, nil
}

func (c *Credentials) RequireTransportSecurity() bool { return c.requireTLS }

var _ credentials.PerRPCCredentials = (*Credentials)(nil)

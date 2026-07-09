package tokenator

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nkeys"
	"google.golang.org/grpc/credentials"
)

// Credentials is a grpc.PerRPCCredentials that attaches the tenant token and
// a fresh per-call signature. Use grpc.WithPerRPCCredentials on the client.
type Credentials struct {
	token  string
	tenant nkeys.KeyPair
	now    func() time.Time
	// requireTLS mirrors the transport: gRPC refuses to send per-RPC
	// credentials over an insecure connection unless this is false.
	requireTLS bool
}

// NewCredentials builds client credentials from the operator-issued token and
// the tenant seed that matches the token's bound key.
func NewCredentials(token string, tenantSeed []byte) (*Credentials, error) {
	tenant, err := nkeys.FromSeed(tenantSeed)
	if err != nil {
		return nil, fmt.Errorf("tokenator: tenant seed: %w", err)
	}
	return &Credentials{token: token, tenant: tenant, now: time.Now, requireTLS: true}, nil
}

// AllowInsecure permits sending the credential over a non-TLS connection,
// e.g. a local API-server port-forward tunnel that is already encrypted.
func (c *Credentials) AllowInsecure() *Credentials {
	c.requireTLS = false
	return c
}

func (c *Credentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	timestamp, signature, err := SignRequest(c.tenant, c.now())
	if err != nil {
		return nil, err
	}
	return map[string]string{
		MetadataToken:     c.token,
		MetadataTimestamp: timestamp,
		MetadataSignature: signature,
	}, nil
}

func (c *Credentials) RequireTransportSecurity() bool { return c.requireTLS }

var _ credentials.PerRPCCredentials = (*Credentials)(nil)

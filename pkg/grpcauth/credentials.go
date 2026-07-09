package grpcauth

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nkeys"
	"google.golang.org/grpc/credentials"

	"github.com/mikluko/valiss/pkg/token"
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

// NewCredentials builds client credentials from the issuer-signed token and
// the tenant seed that matches the token's bound key.
func NewCredentials(tok string, tenantSeed []byte) (*Credentials, error) {
	tenant, err := nkeys.FromSeed(tenantSeed)
	if err != nil {
		return nil, fmt.Errorf("valiss: tenant seed: %w", err)
	}
	return &Credentials{token: tok, tenant: tenant, now: time.Now, requireTLS: true}, nil
}

// NewBearerCredentials builds client credentials that attach the token alone,
// without per-call signatures; no seed is needed. The server accepts such
// requests only when the token grants token.ScopeBearer.
func NewBearerCredentials(tok string) *Credentials {
	return &Credentials{token: tok, now: time.Now, requireTLS: true}
}

// AllowInsecure permits sending the credential over a non-TLS connection,
// e.g. a local API-server port-forward tunnel that is already encrypted.
func (c *Credentials) AllowInsecure() *Credentials {
	c.requireTLS = false
	return c
}

func (c *Credentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	if c.tenant == nil {
		return map[string]string{token.HeaderToken: c.token}, nil
	}
	timestamp, signature, err := token.SignRequest(c.tenant, c.now())
	if err != nil {
		return nil, err
	}
	return map[string]string{
		token.HeaderToken:     c.token,
		token.HeaderTimestamp: timestamp,
		token.HeaderSignature: signature,
	}, nil
}

func (c *Credentials) RequireTransportSecurity() bool { return c.requireTLS }

var _ credentials.PerRPCCredentials = (*Credentials)(nil)

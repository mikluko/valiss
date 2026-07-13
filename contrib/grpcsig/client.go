package grpcsig

import (
	"context"
	"time"

	"github.com/nats-io/nkeys"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/creds"
)

// signer mints per-call message tokens for the client interceptor.
type signer struct {
	accountToken string
	userToken    string
	user         nkeys.KeyPair
	epoch        uint64
	ttl          time.Duration
}

// ClientOption configures UnaryClientInterceptor.
type ClientOption func(*signer)

// WithTTL overrides the valiss.DefaultMessageTTL validity window of minted
// message tokens.
func WithTTL(d time.Duration) ClientOption {
	return func(s *signer) { s.ttl = d }
}

// UnaryClientInterceptor mints a fresh message token per unary call
// (valiss.IssueMessage): a proof of origin bound to the full method and the
// request message bytes, carried in the valiss-message-token metadata with
// the provenance chain embedded. The creds must be a bundle holding the
// user seed: the account token, the user token, and the seed that signs the
// message tokens; the trust-domain epoch is taken from the chain tokens,
// which must agree on it.
func UnaryClientInterceptor(b creds.Creds, opts ...ClientOption) (grpc.UnaryClientInterceptor, error) {
	user, epoch, err := minter(b)
	if err != nil {
		return nil, err
	}
	s := &signer{
		accountToken: b.AccountToken,
		userToken:    b.UserToken,
		user:         user,
		epoch:        epoch,
		ttl:          valiss.DefaultMessageTTL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, callOpts ...grpc.CallOption) error {
		p, err := payload(req)
		if err != nil {
			return err
		}
		tok, err := valiss.IssueMessage(s.user,
			valiss.WithAudience(method),
			valiss.WithChecksum(valiss.Checksum(p)),
			valiss.WithTTL(s.ttl),
			valiss.WithEpoch(s.epoch),
			valiss.WithChain(s.accountToken, s.userToken),
		)
		if err != nil {
			return err
		}
		ctx = metadata.AppendToOutgoingContext(ctx, valiss.HeaderMessageToken, tok)
		return invoker(ctx, method, req, reply, cc, callOpts...)
	}, nil
}

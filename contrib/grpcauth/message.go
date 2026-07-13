package grpcauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nkeys"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/creds"
)

// messageSigner mints per-call message tokens for the client interceptor.
type messageSigner struct {
	accountToken string
	userToken    string
	user         nkeys.KeyPair
	epoch        uint64
	ttl          time.Duration
}

// MessageClientOption configures MessageUnaryClientInterceptor.
type MessageClientOption func(*messageSigner)

// WithMessageTTL overrides the valiss.DefaultMessageTTL validity window of
// minted message tokens.
func WithMessageTTL(d time.Duration) MessageClientOption {
	return func(s *messageSigner) { s.ttl = d }
}

// MessageUnaryClientInterceptor mints a fresh message token per unary call
// (valiss.IssueMessage): a proof of origin bound to the full method and the
// request message bytes, carried in the valiss-message-token metadata with
// the provenance chain embedded. The creds must be a bundle holding the
// user seed: the account token, the user token, and the seed that signs the
// message tokens; the trust-domain epoch is taken from the chain tokens,
// which must agree on it.
//
// The checksum is computed over the request message's deterministic
// protobuf encoding (see messagePayload); both ends must derive identical
// bytes, so keep the protobuf runtime versions of emitter and receiver in
// step.
func MessageUnaryClientInterceptor(b creds.Creds, opts ...MessageClientOption) (grpc.UnaryClientInterceptor, error) {
	s, err := newMessageSigner(b)
	if err != nil {
		return nil, err
	}
	for _, opt := range opts {
		opt(s)
	}
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, callOpts ...grpc.CallOption) error {
		payload, err := messagePayload(req)
		if err != nil {
			return err
		}
		tok, err := valiss.IssueMessage(s.user,
			valiss.WithAudience(method),
			valiss.WithChecksum(valiss.Checksum(payload)),
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

// MessageUnaryServerInterceptor requires every unary call to carry a
// message token (valiss-message-token metadata) proving the origin of its
// exact request message at this method: the token is verified against the
// operator public key with the audience pinned to the full method and the
// checksum compared to the received message's deterministic encoding.
// Failures get Unauthenticated. Handlers read the verified claims with
// valiss.MessageFromContext.
//
// The audience and payload bindings are appended after opts, so they cannot
// be weakened; pass options like valiss.WithOperatorPolicy or
// valiss.WithChainTokens to tighten or supply out-of-band material. A
// message token proves origin only — this interceptor authenticates the
// message, not a caller, and grants no identity; combine it with an
// Authenticator when the caller must also authenticate.
func MessageUnaryServerInterceptor(operatorPubKey string, opts ...valiss.VerifyMessageOption) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing request metadata")
		}
		tok := first(md, valiss.HeaderMessageToken)
		if tok == "" {
			return nil, status.Error(codes.Unauthenticated, "missing message token")
		}
		payload, err := messagePayload(req)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		verifyOpts := append(append([]valiss.VerifyMessageOption{}, opts...),
			valiss.ExpectAudience(info.FullMethod),
			valiss.WithPayload(payload),
		)
		claims, err := valiss.VerifyMessage(tok, operatorPubKey, verifyOpts...)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		return handler(valiss.ContextWithMessage(ctx, claims), req)
	}
}

// messagePayload is the canonical byte string a message token's checksum is
// bound to for a gRPC message: its deterministic protobuf encoding. The
// wire bytes themselves are not available inside interceptors, so both ends
// re-marshal deterministically and must derive identical bytes.
func messagePayload(msg any) ([]byte, error) {
	m, ok := msg.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("valiss: message checksum requires a proto.Message, got %T", msg)
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("valiss: message checksum: marshal: %w", err)
	}
	return payload, nil
}

// newMessageSigner validates emitter creds and derives the mint parameters:
// the user keypair from the seed and the trust-domain epoch from the chain
// tokens, which must agree on it (VerifyMessage requires all levels to).
func newMessageSigner(b creds.Creds) (*messageSigner, error) {
	if b.AccountToken == "" || b.UserToken == "" || len(b.Seed) == 0 {
		return nil, errors.New("valiss: message signing requires bundle creds: account token, user token, and seed")
	}
	user, err := nkeys.FromSeed(b.Seed)
	if err != nil {
		return nil, fmt.Errorf("valiss: creds seed: %w", err)
	}
	accountIssuer, err := valiss.IssuerOf(b.AccountToken)
	if err != nil {
		return nil, fmt.Errorf("valiss: creds account token: %w", err)
	}
	account, err := valiss.VerifyAccount(b.AccountToken, accountIssuer)
	if err != nil {
		return nil, fmt.Errorf("valiss: creds account token: %w", err)
	}
	userClaims, err := valiss.VerifyUser(b.UserToken, account.Subject)
	if err != nil {
		return nil, fmt.Errorf("valiss: creds user token: %w", err)
	}
	if account.Epoch != userClaims.Epoch {
		return nil, fmt.Errorf("valiss: creds chain epochs disagree: account %d, user %d", account.Epoch, userClaims.Epoch)
	}
	return &messageSigner{
		accountToken: b.AccountToken,
		userToken:    b.UserToken,
		user:         user,
		epoch:        userClaims.Epoch,
		ttl:          valiss.DefaultMessageTTL,
	}, nil
}

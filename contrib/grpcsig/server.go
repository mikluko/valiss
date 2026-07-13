package grpcsig

import (
	"context"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/mikluko/valiss"
)

type server struct {
	verify     func(token string, opts ...valiss.VerifyMessageOption) (*valiss.MessageClaims, error)
	verifyOpts []valiss.VerifyMessageOption
	cache      valiss.ChainCache
}

// ServerOption configures UnaryServerInterceptor.
type ServerOption func(*server)

// WithVerifyOptions passes extra options to every valiss.VerifyMessage
// call, e.g. valiss.WithOperatorPolicy to enforce the domain epoch or
// valiss.WithChainTokens to pin a single emitter's chain in configuration.
// A pinned chain takes precedence over negotiated chain material; the
// interceptor's audience and payload bindings are applied after these
// options and cannot be weakened by them.
func WithVerifyOptions(opts ...valiss.VerifyMessageOption) ServerOption {
	return func(s *server) { s.verifyOpts = append(s.verifyOpts, opts...) }
}

// WithChainCache stores negotiated chains between calls, so an emitter pays
// the chain retransmit once instead of on every message. Only chains that
// survived full verification are stored; an entry that later fails (e.g.
// after a domain rotation) is dropped and the chain re-negotiated.
// valiss.NewMemoryChainCache is a process-local implementation.
func WithChainCache(cache valiss.ChainCache) ServerOption {
	return func(s *server) { s.cache = cache }
}

// UnaryServerInterceptor requires every unary call to carry a message token
// (valiss-message-token metadata) proving the origin of its exact request
// message at this method: the token is verified against the operator public
// key with the audience pinned to the full method and the checksum compared
// to the received message's deterministic encoding. Failures get
// Unauthenticated. Handlers read the verified claims with
// valiss.MessageFromContext.
//
// The interceptor speaks the receiving side of chain negotiation: detached
// chain metadata (valiss-chain-account-token, valiss-chain-user-token)
// supplies the chain for a chainless token, and a chainless token whose
// chain is not otherwise known is rejected with the valiss-chain: required
// trailer, asking the client interceptor to retry once with the chain
// attached. WithChainCache remembers negotiated chains so the retransmit
// happens once per emitter, not per call.
func UnaryServerInterceptor(operatorPubKey string, opts ...ServerOption) grpc.UnaryServerInterceptor {
	verify := func(token string, verifyOpts ...valiss.VerifyMessageOption) (*valiss.MessageClaims, error) {
		return valiss.VerifyMessage(token, operatorPubKey, verifyOpts...)
	}
	return newServerInterceptor(verify, opts)
}

// KeyringUnaryServerInterceptor is UnaryServerInterceptor for a receiver
// trusting several operators: each call verifies against the keyring entry
// its chain names (valiss.VerifyMessageKeyring), and handlers tell trust
// domains apart by MessageClaims.Operator.
func KeyringUnaryServerInterceptor(keyring *valiss.Keyring, opts ...ServerOption) grpc.UnaryServerInterceptor {
	verify := func(token string, verifyOpts ...valiss.VerifyMessageOption) (*valiss.MessageClaims, error) {
		return valiss.VerifyMessageKeyring(token, keyring, verifyOpts...)
	}
	return newServerInterceptor(verify, opts)
}

func newServerInterceptor(verify func(string, ...valiss.VerifyMessageOption) (*valiss.MessageClaims, error), opts []ServerOption) grpc.UnaryServerInterceptor {
	s := &server{verify: verify}
	for _, opt := range opts {
		opt(s)
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing request metadata")
		}
		tok := first(md, valiss.HeaderMessageToken)
		if tok == "" {
			return nil, status.Error(codes.Unauthenticated, "missing message token")
		}
		p, err := payload(req)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		// Resolve negotiated chain material: detached metadata outranks the
		// cache; a pinned chain in the verify options outranks both (it is
		// applied later, so it wins inside VerifyMessage).
		chainAccount := first(md, valiss.HeaderChainAccountToken)
		chainUser := first(md, valiss.HeaderChainUserToken)
		detached := chainAccount != "" && chainUser != ""
		cached := false
		var cacheKey string
		if !detached && s.cache != nil {
			if c, err := valiss.Decode(tok); err == nil {
				cacheKey = c.Issuer
				chainAccount, chainUser, cached = s.cache.Get(cacheKey)
			}
		}

		verify := func(withChain bool) (*valiss.MessageClaims, error) {
			verifyOpts := make([]valiss.VerifyMessageOption, 0, len(s.verifyOpts)+3)
			if withChain {
				verifyOpts = append(verifyOpts, valiss.WithChainTokens(chainAccount, chainUser))
			}
			verifyOpts = append(verifyOpts, s.verifyOpts...)
			verifyOpts = append(verifyOpts, valiss.ExpectAudience(info.FullMethod), valiss.WithPayload(p))
			return s.verify(tok, verifyOpts...)
		}

		claims, err := verify(detached || cached)
		if err != nil && cached {
			// Attribute the failure before evicting: without the cached
			// chain a self-contained token settles it on its own, and only
			// a chainless token leaves the cached entry as the suspect.
			claims, err = verify(false)
			if err == nil || errors.Is(err, valiss.ErrNoChain) {
				s.cache.Del(cacheKey)
			}
		}
		if err != nil {
			if errors.Is(err, valiss.ErrNoChain) {
				return nil, chainRequired(ctx)
			}
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		if detached && s.cache != nil {
			s.cache.Put(claims.Subject, chainAccount, chainUser)
		}
		return handler(valiss.ContextWithMessage(ctx, claims), req)
	}
}

// chainRequired rejects a call while asking the client interceptor to retry
// with the provenance chain attached, via the valiss-chain trailer.
func chainRequired(ctx context.Context) error {
	_ = grpc.SetTrailer(ctx, metadata.Pairs(valiss.HeaderChain, valiss.ChainRequired))
	return status.Error(codes.Unauthenticated, "message token chain required")
}

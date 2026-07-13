package grpcsig

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/mikluko/valiss"
)

// UnaryServerInterceptor requires every unary call to carry a message token
// (valiss-message-token metadata) proving the origin of its exact request
// message at this method: the token is verified against the operator public
// key with the audience pinned to the full method and the checksum compared
// to the received message's deterministic encoding. Failures get
// Unauthenticated. Handlers read the verified claims with
// valiss.MessageFromContext.
//
// The audience and payload bindings are appended after opts, so they cannot
// be weakened; pass options like valiss.WithOperatorPolicy or
// valiss.WithChainTokens to tighten or supply out-of-band material.
func UnaryServerInterceptor(operatorPubKey string, opts ...valiss.VerifyMessageOption) grpc.UnaryServerInterceptor {
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
		verifyOpts := append(append([]valiss.VerifyMessageOption{}, opts...),
			valiss.ExpectAudience(info.FullMethod),
			valiss.WithPayload(p),
		)
		claims, err := valiss.VerifyMessage(tok, operatorPubKey, verifyOpts...)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		return handler(valiss.ContextWithMessage(ctx, claims), req)
	}
}

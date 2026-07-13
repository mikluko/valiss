package grpcsig

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/creds"
)

// chainAt mints a full chain at epoch and returns the operator keypair, the
// operator public key, and emitter bundle creds.
func chainAt(t *testing.T, epoch uint64) (nkeys.KeyPair, string, creds.Creds) {
	t.Helper()
	op, err := nkeys.CreateOperator()
	require.NoError(t, err)
	opPub, err := op.PublicKey()
	require.NoError(t, err)
	account, err := nkeys.CreateAccount()
	require.NoError(t, err)
	accountPub, err := account.PublicKey()
	require.NoError(t, err)
	user, err := nkeys.CreateUser()
	require.NoError(t, err)
	userPub, err := user.PublicKey()
	require.NoError(t, err)
	userSeed, err := user.Seed()
	require.NoError(t, err)
	acctTok, err := valiss.Issue(op, "acme", accountPub, valiss.WithEpoch(epoch), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := valiss.IssueUser(account, "alice", userPub, valiss.WithEpoch(epoch), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	return op, opPub, creds.Creds{AccountToken: acctTok, UserToken: userTok, Seed: userSeed}
}

// mintedToken runs the client interceptor for a call and returns the message
// token it attached to the outgoing metadata.
func mintedToken(t *testing.T, b creds.Creds, method string, req any) string {
	t.Helper()
	ci, err := UnaryClientInterceptor(b)
	require.NoError(t, err)
	var tok string
	err = ci(context.Background(), method, req, nil, nil,
		func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			md, ok := metadata.FromOutgoingContext(ctx)
			require.True(t, ok)
			tok = first(md, valiss.HeaderMessageToken)
			return nil
		})
	require.NoError(t, err)
	return tok
}

// incoming builds the incoming-metadata context the server interceptor sees.
func incoming(tok string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.New(map[string]string{valiss.HeaderMessageToken: tok}))
}

func unaryInfo(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: method}
}

func TestInterceptors(t *testing.T) {
	op, opPub, b := chainAt(t, 1)
	req := wrapperspb.String("widget.created")
	tok := mintedToken(t, b, "/svc/Emit", req)
	si := UnaryServerInterceptor(opPub)

	t.Run("end to end injects the claims", func(t *testing.T) {
		var got *valiss.MessageClaims
		_, err := si(incoming(tok), req, unaryInfo("/svc/Emit"),
			func(ctx context.Context, _ any) (any, error) {
				c, ok := valiss.MessageFromContext(ctx)
				require.True(t, ok)
				got = c
				return nil, nil
			})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "acme", got.Account.Name)
		assert.Equal(t, "alice", got.User.Name)
		assert.Equal(t, uint64(1), got.Epoch)
		assert.Equal(t, "/svc/Emit", got.Audience)
	})

	handler := func(context.Context, any) (any, error) { return nil, nil }

	t.Run("missing token rejected", func(t *testing.T) {
		_, err := si(metadata.NewIncomingContext(context.Background(), metadata.MD{}), req, unaryInfo("/svc/Emit"), handler)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "missing message token")
	})

	t.Run("cross-method replay rejected", func(t *testing.T) {
		_, err := si(incoming(tok), req, unaryInfo("/svc/Other"), handler)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "audience")
	})

	t.Run("tampered message rejected", func(t *testing.T) {
		_, err := si(incoming(tok), wrapperspb.String("widget.deleted"), unaryInfo("/svc/Emit"), handler)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "checksum mismatch")
	})

	t.Run("non-proto message rejected", func(t *testing.T) {
		_, err := si(incoming(tok), "not a proto", unaryInfo("/svc/Emit"), handler)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "requires a proto.Message")
	})

	t.Run("operator policy enforced", func(t *testing.T) {
		bumped, err := valiss.IssueOperator(op, valiss.WithEpoch(2))
		require.NoError(t, err)
		strict := UnaryServerInterceptor(opPub, WithVerifyOptions(valiss.WithOperatorPolicy(bumped)))
		_, err = strict(incoming(tok), req, unaryInfo("/svc/Emit"), handler)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "trust domain epoch 2")
	})
}

func TestClientInterceptorRejections(t *testing.T) {
	_, _, b := chainAt(t, 0)

	t.Run("missing chain material rejected", func(t *testing.T) {
		for _, broken := range []creds.Creds{
			{UserToken: b.UserToken, Seed: b.Seed},
			{AccountToken: b.AccountToken, Seed: b.Seed},
			{AccountToken: b.AccountToken, UserToken: b.UserToken},
		} {
			_, err := UnaryClientInterceptor(broken)
			assert.ErrorContains(t, err, "requires bundle creds")
		}
	})

	t.Run("non-proto request fails the call", func(t *testing.T) {
		ci, err := UnaryClientInterceptor(b)
		require.NoError(t, err)
		err = ci(context.Background(), "/svc/Emit", "not a proto", nil, nil,
			func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error { return nil })
		assert.ErrorContains(t, err, "requires a proto.Message")
	})
}

package grpcsig

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpccreds "google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/mikluko/valiss"
)

// negotiationHarness runs a real bufconn server so trailer semantics are
// exercised end to end, counting attempts that reach the server.
type negotiationHarness struct {
	lis      *bufconn.Listener
	srv      *grpc.Server
	attempts atomic.Int64
}

func newNegotiationHarness(t *testing.T, opPub string, opts ...ServerOption) *negotiationHarness {
	t.Helper()
	h := &negotiationHarness{lis: bufconn.Listen(1 << 20)}
	counting := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		h.attempts.Add(1)
		return handler(ctx, req)
	}
	h.srv = grpc.NewServer(grpc.ChainUnaryInterceptor(counting, UnaryServerInterceptor(opPub, opts...)))
	healthpb.RegisterHealthServer(h.srv, health.NewServer())
	go func() { _ = h.srv.Serve(h.lis) }()
	t.Cleanup(h.srv.Stop)
	return h
}

func (h *negotiationHarness) dial(t *testing.T, opts ...grpc.DialOption) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		append([]grpc.DialOption{
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return h.lis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(grpccreds.NewCredentials()),
		}, opts...)...,
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestChainNegotiation(t *testing.T) {
	_, opPub, b := chainAt(t, 1)
	cache := valiss.NewMemoryChainCache()
	h := newNegotiationHarness(t, opPub, WithChainCache(cache))

	ci, err := UnaryClientInterceptor(b, WithChainNegotiation())
	require.NoError(t, err)
	client := healthpb.NewHealthClient(h.dial(t, grpc.WithUnaryInterceptor(ci)))

	t.Run("cold cache costs one retry, then steady state is chainless", func(t *testing.T) {
		_, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{})
		require.NoError(t, err)
		assert.EqualValues(t, 2, h.attempts.Load(), "first call: chainless attempt + chain retry")

		_, err = client.Check(context.Background(), &healthpb.HealthCheckRequest{})
		require.NoError(t, err)
		assert.EqualValues(t, 3, h.attempts.Load(), "second call: single chainless attempt")
	})

	t.Run("stale cached chain is evicted and re-negotiated", func(t *testing.T) {
		_, _, foreign := chainAt(t, 1)
		emitterKey, err := valiss.Decode(b.UserToken)
		require.NoError(t, err)
		cache.Put(emitterKey.Subject, foreign.AccountToken, foreign.UserToken)

		before := h.attempts.Load()
		_, err = client.Check(context.Background(), &healthpb.HealthCheckRequest{})
		require.NoError(t, err)
		assert.EqualValues(t, before+2, h.attempts.Load(), "stale entry: rejected attempt + chain retry")

		_, err = client.Check(context.Background(), &healthpb.HealthCheckRequest{})
		require.NoError(t, err)
		assert.EqualValues(t, before+3, h.attempts.Load(), "cache healthy again")
	})

	t.Run("cacheless server still works statelessly", func(t *testing.T) {
		stateless := newNegotiationHarness(t, opPub)
		c := healthpb.NewHealthClient(stateless.dial(t, grpc.WithUnaryInterceptor(ci)))
		_, err := c.Check(context.Background(), &healthpb.HealthCheckRequest{})
		require.NoError(t, err)
		assert.EqualValues(t, 2, stateless.attempts.Load())
		_, err = c.Check(context.Background(), &healthpb.HealthCheckRequest{})
		require.NoError(t, err)
		assert.EqualValues(t, 4, stateless.attempts.Load(), "every call pays the retry without a cache")
	})

	t.Run("non-negotiating client keeps embedding and needs no retry", func(t *testing.T) {
		plainCI, err := UnaryClientInterceptor(b)
		require.NoError(t, err)
		c := healthpb.NewHealthClient(h.dial(t, grpc.WithUnaryInterceptor(plainCI)))
		before := h.attempts.Load()
		_, err = c.Check(context.Background(), &healthpb.HealthCheckRequest{})
		require.NoError(t, err)
		assert.EqualValues(t, before+1, h.attempts.Load())
	})

	t.Run("unsigned call is rejected without negotiation signal loop", func(t *testing.T) {
		bare := healthpb.NewHealthClient(h.dial(t))
		_, err := bare.Check(context.Background(), &healthpb.HealthCheckRequest{})
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "missing message token")
	})
}

func TestNegotiationPinnedConfigWins(t *testing.T) {
	_, opPub, b := chainAt(t, 0)
	h := newNegotiationHarness(t, opPub,
		WithVerifyOptions(valiss.WithChainTokens(b.AccountToken, b.UserToken)))

	ci, err := UnaryClientInterceptor(b, WithChainNegotiation())
	require.NoError(t, err)
	client := healthpb.NewHealthClient(h.dial(t, grpc.WithUnaryInterceptor(ci)))
	_, err = client.Check(context.Background(), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.EqualValues(t, 1, h.attempts.Load(), "pinned chain answers on the first attempt")
}

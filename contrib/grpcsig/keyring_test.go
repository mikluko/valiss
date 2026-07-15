package grpcsig

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"valiss.dev/valiss"
	"valiss.dev/valiss/creds"
)

// namedChainAt mints a full trust domain and returns the operator token
// plus emitter bundle creds.
func namedChainAt(t *testing.T, name string, epoch uint64) (string, creds.Creds) {
	t.Helper()
	op, err := nkeys.CreateOperator()
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
	opTok, err := valiss.IssueOperator(op, valiss.WithName(name), valiss.WithEpoch(epoch))
	require.NoError(t, err)
	acctTok, err := valiss.IssueAccount(op, accountPub, valiss.WithName("acme"), valiss.WithEpoch(epoch), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := valiss.IssueUser(account, userPub, valiss.WithName("alice"), valiss.WithEpoch(epoch), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	return opTok, creds.Creds{AccountToken: acctTok, UserToken: userTok, Seed: userSeed}
}

func TestKeyringInterceptor(t *testing.T) {
	opTokA, bundleA := namedChainAt(t, "prod-us", 4)
	opTokB, bundleB := namedChainAt(t, "on-prem", 0)
	k, err := valiss.NewKeyring(opTokA, opTokB)
	require.NoError(t, err)

	var seen []string
	si := KeyringUnaryServerInterceptor(k, WithChainCache(valiss.NewMemoryChainCache()))
	handler := func(ctx context.Context, _ any) (any, error) {
		c, ok := valiss.MessageFromContext(ctx)
		require.True(t, ok)
		require.NotNil(t, c.Operator)
		seen = append(seen, c.Operator.Name+"/"+c.Account.Name)
		return nil, nil
	}

	call := func(b creds.Creds) error {
		t.Helper()
		req := &healthpb.HealthCheckRequest{}
		tok := mintedToken(t, b, "/svc/Emit", req)
		_, err := si(incoming(tok), req, unaryInfo("/svc/Emit"), handler)
		return err
	}

	require.NoError(t, call(bundleA))
	require.NoError(t, call(bundleB))
	assert.Equal(t, []string{"prod-us/acme", "on-prem/acme"}, seen,
		"same tenant name segments by operator name")

	t.Run("unknown producer rejected", func(t *testing.T) {
		_, stranger := namedChainAt(t, "stranger", 0)
		err := call(stranger)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "no trusted operator")
	})
}

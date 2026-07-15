package grpcauth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"valiss.dev/valiss"
)

// TestKeyringVerifier proves the interceptor serves credentials from
// several trust domains through a keyring verifier, exposing the matched
// operator to handlers.
func TestKeyringVerifier(t *testing.T) {
	newDomain := func(name string) (operatorToken string, req valiss.Request) {
		t.Helper()
		op, _ := issuerKeys(t)
		account, accountPub, _ := tenantKeys(t)
		operatorToken, err := valiss.IssueOperator(op, valiss.WithName(name), valiss.WithEpoch(1))
		require.NoError(t, err)
		accountToken, err := valiss.IssueAccount(op, accountPub, valiss.WithName("acme"), valiss.WithEpoch(1), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		ts, sig, err := valiss.SignRequest(account, time.Now(), methodContext("/svc/M", ""))
		require.NoError(t, err)
		return operatorToken, valiss.Request{AccountToken: accountToken, Timestamp: ts, Signature: sig}
	}

	opTokA, reqA := newDomain("prod-us")
	opTokB, reqB := newDomain("on-prem")
	k, err := valiss.NewKeyring(opTokA, opTokB)
	require.NoError(t, err)
	auth := NewAuthenticator(valiss.NewKeyringVerifier(k, valiss.AllowAll{}), AllowMissingExtension())

	var seen []string
	handler := func(ctx context.Context, _ any) (any, error) {
		id, ok := valiss.IdentityFromContext(ctx)
		require.True(t, ok)
		require.NotNil(t, id.Operator)
		seen = append(seen, id.Operator.Name+"/"+id.Account.Name)
		return nil, nil
	}

	_, err = auth.UnaryInterceptor()(authContext(reqA), nil, unaryInfo("/svc/M"), handler)
	require.NoError(t, err)
	_, err = auth.UnaryInterceptor()(authContext(reqB), nil, unaryInfo("/svc/M"), handler)
	require.NoError(t, err)
	assert.Equal(t, []string{"prod-us/acme", "on-prem/acme"}, seen,
		"same tenant name segments by operator name")

	t.Run("unknown producer rejected", func(t *testing.T) {
		_, stranger := newDomain("stranger")
		_, err := auth.UnaryInterceptor()(authContext(stranger), nil, unaryInfo("/svc/M"),
			func(context.Context, any) (any, error) { return nil, nil })
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "no trusted operator")
	})
}

package httpsig

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func TestKeyringMiddleware(t *testing.T) {
	opTokA, bundleA := namedChainAt(t, "prod-us", 4)
	opTokB, bundleB := namedChainAt(t, "on-prem", 0)
	k, err := valiss.NewKeyring(opTokA, opTokB)
	require.NoError(t, err)

	var seen []string
	mw := NewKeyringMiddleware(k, WithChainCache(valiss.NewMemoryChainCache()))
	srv := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := valiss.MessageFromContext(r.Context())
		require.True(t, ok)
		require.NotNil(t, c.Operator)
		seen = append(seen, c.Operator.Name+"/"+c.Account.Name)
	})))
	defer srv.Close()

	post := func(b creds.Creds) int {
		t.Helper()
		tr, err := NewTransport(b, nil, WithChainNegotiation())
		require.NoError(t, err)
		resp, err := (&http.Client{Transport: tr}).Post(srv.URL+"/hook", "application/json", bytes.NewReader([]byte(`{}`)))
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusOK, post(bundleA))
	assert.Equal(t, http.StatusOK, post(bundleB))
	assert.Equal(t, []string{"prod-us/acme", "on-prem/acme"}, seen,
		"same tenant name segments by operator name")

	t.Run("unknown producer rejected", func(t *testing.T) {
		_, stranger := namedChainAt(t, "stranger", 0)
		assert.Equal(t, http.StatusUnauthorized, post(stranger))
	})
}

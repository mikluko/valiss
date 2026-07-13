package httpsig

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	acctTok, err := valiss.Issue(op, accountPub, valiss.WithName("acme"), valiss.WithEpoch(epoch), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := valiss.IssueUser(account, userPub, valiss.WithName("alice"), valiss.WithEpoch(epoch), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	return op, opPub, creds.Creds{AccountToken: acctTok, UserToken: userTok, Seed: userSeed}
}

func newTransport(t *testing.T, b creds.Creds, base http.RoundTripper) *Transport {
	t.Helper()
	tr, err := NewTransport(b, base)
	require.NoError(t, err)
	return tr
}

// captureToken is a base RoundTripper that records the minted message token
// instead of sending the request, for replay tests.
func captureToken(dst *string) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		*dst = r.Header.Get(valiss.HeaderMessageToken)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTransportMiddleware(t *testing.T) {
	_, opPub, b := chainAt(t, 1)
	payload := []byte(`{"event":"widget.created"}`)

	var gotClaims *valiss.MessageClaims
	var gotBody []byte
	mw := NewMiddleware(opPub)
	srv := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := valiss.MessageFromContext(r.Context())
		require.True(t, ok)
		gotClaims = c
		var err error
		gotBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)
	})))
	defer srv.Close()

	client := &http.Client{Transport: newTransport(t, b, nil)}

	resp, err := client.Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, gotClaims)
	assert.Equal(t, "acme", gotClaims.Account.Name)
	assert.Equal(t, "alice", gotClaims.User.Name)
	assert.Equal(t, uint64(1), gotClaims.Epoch)
	assert.Equal(t, valiss.Checksum(payload), gotClaims.Checksum)
	assert.Equal(t, payload, gotBody, "the handler still reads the body")

	t.Run("bodyless request round-trips", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/hook")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("missing token rejected", func(t *testing.T) {
		resp, err := http.Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("tampered body rejected", func(t *testing.T) {
		var tok string
		capture := &http.Client{Transport: newTransport(t, b, captureToken(&tok))}
		_, err := capture.Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/hook", bytes.NewReader([]byte(`{"event":"widget.deleted"}`)))
		require.NoError(t, err)
		req.Header.Set(valiss.HeaderMessageToken, tok)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("cross-destination replay rejected", func(t *testing.T) {
		var tok string
		capture := &http.Client{Transport: newTransport(t, b, captureToken(&tok))}
		_, err := capture.Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/other", bytes.NewReader(payload))
		require.NoError(t, err)
		req.Header.Set(valiss.HeaderMessageToken, tok)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestMiddlewareOperatorPolicy(t *testing.T) {
	op, opPub, b := chainAt(t, 1)
	bumped, err := valiss.IssueOperator(op, valiss.WithEpoch(2))
	require.NoError(t, err)
	mw := NewMiddleware(opPub, WithVerifyOptions(valiss.WithOperatorPolicy(bumped)))
	srv := httptest.NewServer(mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	defer srv.Close()

	client := &http.Client{Transport: newTransport(t, b, nil)}
	resp, err := client.Post(srv.URL+"/hook", "application/json", bytes.NewReader([]byte("x")))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "stale epoch rejected under operator policy")
}

func TestNewTransportRejections(t *testing.T) {
	_, _, b := chainAt(t, 0)

	t.Run("missing chain material rejected", func(t *testing.T) {
		for _, broken := range []creds.Creds{
			{UserToken: b.UserToken, Seed: b.Seed},
			{AccountToken: b.AccountToken, Seed: b.Seed},
			{AccountToken: b.AccountToken, UserToken: b.UserToken},
		} {
			_, err := NewTransport(broken, nil)
			assert.ErrorContains(t, err, "requires bundle creds")
		}
	})

	t.Run("chain epoch disagreement rejected", func(t *testing.T) {
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
		acctTok, err := valiss.Issue(op, accountPub, valiss.WithName("acme"), valiss.WithEpoch(1), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		userTok, err := valiss.IssueUser(account, userPub, valiss.WithName("alice"), valiss.WithEpoch(2), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = NewTransport(creds.Creds{AccountToken: acctTok, UserToken: userTok, Seed: userSeed}, nil)
		assert.ErrorContains(t, err, "chain epochs disagree")
	})

	t.Run("non-user seed fails at mint", func(t *testing.T) {
		account, err := nkeys.CreateAccount()
		require.NoError(t, err)
		accountSeed, err := account.Seed()
		require.NoError(t, err)
		tr, err := NewTransport(creds.Creds{AccountToken: b.AccountToken, UserToken: b.UserToken, Seed: accountSeed}, nil)
		require.NoError(t, err, "seed level is enforced by IssueMessage per request")
		req, err := http.NewRequest(http.MethodPost, "http://example.com/hook", bytes.NewReader([]byte("x")))
		require.NoError(t, err)
		_, err = tr.RoundTrip(req)
		assert.ErrorContains(t, err, "user-type nkey")
	})
}

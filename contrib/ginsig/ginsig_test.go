package ginsig

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"valiss.dev/valiss"
	"valiss.dev/valiss/contrib/httpsig"
	"valiss.dev/valiss/creds"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// chain mints a full chain and returns the operator public key and emitter
// bundle creds.
func chain(t *testing.T) (string, creds.Creds) {
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
	acctTok, err := valiss.IssueAccount(op, accountPub, valiss.WithName("acme"), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := valiss.IssueUser(account, userPub, valiss.WithName("alice"), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	return opPub, creds.Creds{AccountToken: acctTok, UserToken: userTok, Seed: userSeed}
}

// newServer builds a Gin engine with the middleware and a handler capturing
// the verified claims and body.
func newServer(t *testing.T, opPub string, claims **valiss.MessageClaims, body *[]byte, opts ...httpsig.MiddlewareOption) *httptest.Server {
	t.Helper()
	e := gin.New()
	e.Use(NewMiddleware(opPub, opts...))
	e.POST("/*path", func(c *gin.Context) {
		got, ok := MessageFrom(c)
		require.True(t, ok)
		*claims = got
		b, err := io.ReadAll(c.Request.Body)
		require.NoError(t, err)
		*body = b
	})
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)
	return srv
}

func TestMiddleware(t *testing.T) {
	opPub, b := chain(t)
	payload := []byte(`{"event":"widget.created"}`)

	var gotClaims *valiss.MessageClaims
	var gotBody []byte
	srv := newServer(t, opPub, &gotClaims, &gotBody)

	transport, err := httpsig.NewTransport(b, nil)
	require.NoError(t, err)
	client := &http.Client{Transport: transport}

	t.Run("verified message reaches handler with claims and body", func(t *testing.T) {
		resp, err := client.Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		require.NotNil(t, gotClaims)
		assert.Equal(t, "acme", gotClaims.Account.Name)
		assert.Equal(t, "alice", gotClaims.User.Name)
		assert.Equal(t, valiss.Checksum(payload), gotClaims.Checksum)
		assert.Equal(t, payload, gotBody, "the handler still reads the body")
	})

	t.Run("missing token aborted with 401", func(t *testing.T) {
		resp, err := http.Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, string(body), "missing message token")
	})

	t.Run("tampered body aborted with 401", func(t *testing.T) {
		var tok string
		capture, err := httpsig.NewTransport(b, roundTripFunc(func(r *http.Request) (*http.Response, error) {
			tok = r.Header.Get(valiss.HeaderMessageToken)
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
		}))
		require.NoError(t, err)
		_, err = (&http.Client{Transport: capture}).Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, srv.URL+"/hook", bytes.NewReader([]byte(`{"event":"widget.deleted"}`)))
		require.NoError(t, err)
		req.Header.Set(valiss.HeaderMessageToken, tok)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// TestChainNegotiation proves the chain-required signal travels through the
// Gin abort path: a negotiating transport gets the valiss-chain: required
// answer, retransmits with the detached chain, and lands on 200.
func TestChainNegotiation(t *testing.T) {
	opPub, b := chain(t)
	payload := []byte(`{"event":"widget.created"}`)

	var gotClaims *valiss.MessageClaims
	var gotBody []byte
	srv := newServer(t, opPub, &gotClaims, &gotBody, httpsig.WithChainCache(valiss.NewMemoryChainCache()))

	transport, err := httpsig.NewTransport(b, nil, httpsig.WithChainNegotiation())
	require.NoError(t, err)
	client := &http.Client{Transport: transport}

	resp, err := client.Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, gotClaims)
	assert.Equal(t, "alice", gotClaims.User.Name)
	assert.Equal(t, payload, gotBody)

	t.Run("steady state serves the bare token from the cache", func(t *testing.T) {
		gotClaims = nil
		resp, err := client.Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		require.NotNil(t, gotClaims)
	})

	t.Run("unknown bare token rejected with the signal", func(t *testing.T) {
		// A fresh server has no cached chain for this emitter, so a directly
		// minted chainless token must bounce with the negotiation header
		// through the Gin abort path.
		fresh := gin.New()
		fresh.Use(NewMiddleware(opPub, httpsig.WithChainCache(valiss.NewMemoryChainCache())))
		fresh.POST("/*path", func(c *gin.Context) {})
		fsrv := httptest.NewServer(fresh)
		defer fsrv.Close()

		user, err := nkeys.FromSeed(b.Seed)
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, fsrv.URL+"/hook", bytes.NewReader(payload))
		require.NoError(t, err)
		tok, err := valiss.IssueMessage(user,
			valiss.WithAudience(httpsig.Audience(req)),
			valiss.WithChecksum(valiss.Checksum(payload)),
			valiss.WithTTL(time.Minute))
		require.NoError(t, err)
		req.Header.Set(valiss.HeaderMessageToken, tok)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, valiss.ChainRequired, resp.Header.Get(valiss.HeaderChain), "abort path carries the negotiation signal")
		assert.Contains(t, string(body), "chain required")
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

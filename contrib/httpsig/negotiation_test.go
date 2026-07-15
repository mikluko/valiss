package httpsig

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"valiss.dev/valiss"
)

// countingTransport counts attempts that actually reach the network path.
type countingTransport struct {
	n atomic.Int64
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return http.DefaultTransport.RoundTrip(r)
}

func TestChainNegotiation(t *testing.T) {
	_, opPub, b := chainAt(t, 1)
	payload := []byte(`{"event":"widget.created"}`)

	var served atomic.Int64
	cache := valiss.NewMemoryChainCache()
	mw := NewMiddleware(opPub, WithChainCache(cache))
	srv := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		c, ok := valiss.MessageFromContext(r.Context())
		require.True(t, ok)
		assert.Equal(t, "alice", c.User.Name)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, payload, body)
	})))
	defer srv.Close()

	counter := &countingTransport{}
	tr, err := NewTransport(b, counter, WithChainNegotiation())
	require.NoError(t, err)
	client := &http.Client{Transport: tr}

	post := func() *http.Response {
		resp, err := client.Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
		require.NoError(t, err)
		resp.Body.Close()
		return resp
	}

	t.Run("cold cache costs one retransmit, then steady state is chainless", func(t *testing.T) {
		resp := post()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.EqualValues(t, 2, counter.n.Load(), "first message: chainless attempt + chain retransmit")
		assert.EqualValues(t, 1, served.Load())

		resp = post()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.EqualValues(t, 3, counter.n.Load(), "second message: single chainless attempt")
		assert.EqualValues(t, 2, served.Load())
	})

	t.Run("stale cached chain is evicted and re-negotiated", func(t *testing.T) {
		// Plant a chain from a different trust domain under this emitter's
		// key: verification against it fails, the entry is dropped, and the
		// retransmit re-establishes the real chain.
		_, _, foreign := chainAt(t, 1)
		emitterKey, err := valiss.Decode(b.UserToken)
		require.NoError(t, err)
		cache.Put(emitterKey.Subject, foreign.AccountToken, foreign.UserToken)

		before := counter.n.Load()
		resp := post()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.EqualValues(t, before+2, counter.n.Load(), "stale entry: rejected attempt + chain retransmit")

		resp = post()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.EqualValues(t, before+3, counter.n.Load(), "cache healthy again")
	})

	t.Run("negotiation against a cacheless receiver still works statelessly", func(t *testing.T) {
		stateless := httptest.NewServer(NewMiddleware(opPub)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
		defer stateless.Close()
		before := counter.n.Load()
		resp, err := client.Post(stateless.URL+"/hook", "application/json", bytes.NewReader(payload))
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.EqualValues(t, before+2, counter.n.Load(), "every message pays the retransmit without a cache")
	})

	t.Run("genuine failures are not converted into negotiation", func(t *testing.T) {
		// A tampered replay with detached chain headers fails checksum and
		// must get a plain 401 without the chain-required signal.
		var tok string
		capture, err := NewTransport(b, captureToken(&tok))
		require.NoError(t, err)
		_, err = (&http.Client{Transport: capture}).Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, srv.URL+"/hook", bytes.NewReader([]byte("tampered")))
		require.NoError(t, err)
		req.Header.Set(valiss.HeaderMessageToken, tok)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Empty(t, resp.Header.Get(valiss.HeaderChain), "embedded-chain failure carries no negotiation signal")
	})
}

func TestNegotiationPinnedConfigWins(t *testing.T) {
	_, opPub, b := chainAt(t, 0)

	// The receiver pins the emitter's chain in configuration: chainless
	// tokens verify on the first attempt, no negotiation round-trip.
	mw := NewMiddleware(opPub, WithVerifyOptions(valiss.WithChainTokens(b.AccountToken, b.UserToken)))
	srv := httptest.NewServer(mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	defer srv.Close()

	counter := &countingTransport{}
	tr, err := NewTransport(b, counter, WithChainNegotiation())
	require.NoError(t, err)
	resp, err := (&http.Client{Transport: tr}).Post(srv.URL+"/hook", "application/json", bytes.NewReader([]byte("x")))
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.EqualValues(t, 1, counter.n.Load(), "pinned chain answers on the first attempt")
}

func TestNegotiationBodylessRetry(t *testing.T) {
	_, opPub, b := chainAt(t, 0)
	mw := NewMiddleware(opPub, WithChainCache(valiss.NewMemoryChainCache()))
	srv := httptest.NewServer(mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	defer srv.Close()

	tr, err := NewTransport(b, nil, WithChainNegotiation())
	require.NoError(t, err)
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL + "/hook")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GET negotiates and retries without a body")
}

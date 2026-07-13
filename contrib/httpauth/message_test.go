package httpauth

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/creds"
)

// messageBundle mints a full chain at epoch and returns emitter creds plus
// the operator public key.
func messageBundle(t *testing.T, epoch uint64) (creds.Creds, string) {
	t.Helper()
	op, opPub := issuerKeys(t)
	account, accountPub, _ := tenantKeys(t)
	_, userPub, userSeed := userKeys(t)
	acctTok, err := valiss.Issue(op, "acme", accountPub, valiss.WithEpoch(epoch), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := valiss.IssueUser(account, "alice", userPub, valiss.WithEpoch(epoch), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	return creds.Creds{AccountToken: acctTok, UserToken: userTok, Seed: userSeed}, opPub
}

func TestMessageTransportMiddleware(t *testing.T) {
	b, opPub := messageBundle(t, 1)
	payload := []byte(`{"event":"widget.created"}`)

	var gotClaims *valiss.MessageClaims
	var gotBody []byte
	mw := NewMessageMiddleware(opPub)
	srv := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := valiss.MessageFromContext(r.Context())
		require.True(t, ok)
		gotClaims = c
		var err error
		gotBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)
	})))
	defer srv.Close()

	transport, err := NewMessageTransport(b, nil)
	require.NoError(t, err)
	client := &http.Client{Transport: transport}

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
		var hdr http.Header
		capture := &http.Client{Transport: mustMessageTransport(t, b, captureInto(&hdr))}
		_, err := capture.Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/hook", bytes.NewReader([]byte(`{"event":"widget.deleted"}`)))
		require.NoError(t, err)
		req.Header.Set(valiss.HeaderMessageToken, hdr.Get(valiss.HeaderMessageToken))
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("cross-destination replay rejected", func(t *testing.T) {
		var hdr http.Header
		capture := &http.Client{Transport: mustMessageTransport(t, b, captureInto(&hdr))}
		_, err := capture.Post(srv.URL+"/hook", "application/json", bytes.NewReader(payload))
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/other", bytes.NewReader(payload))
		require.NoError(t, err)
		req.Header.Set(valiss.HeaderMessageToken, hdr.Get(valiss.HeaderMessageToken))
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestMessageMiddlewareOperatorPolicy(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub, _ := tenantKeys(t)
	_, userPub, userSeed := userKeys(t)
	acctTok, err := valiss.Issue(op, "acme", accountPub, valiss.WithEpoch(1), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := valiss.IssueUser(account, "alice", userPub, valiss.WithEpoch(1), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	b := creds.Creds{AccountToken: acctTok, UserToken: userTok, Seed: userSeed}

	bumped, err := valiss.IssueOperator(op, valiss.WithEpoch(2))
	require.NoError(t, err)
	mw := NewMessageMiddleware(opPub, valiss.WithOperatorPolicy(bumped))
	srv := httptest.NewServer(mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	defer srv.Close()

	client := &http.Client{Transport: mustMessageTransport(t, b, nil)}
	resp, err := client.Post(srv.URL+"/hook", "application/json", bytes.NewReader([]byte("x")))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "stale epoch rejected under operator policy")
}

func TestNewMessageTransportRejections(t *testing.T) {
	b, _ := messageBundle(t, 0)

	t.Run("missing chain material rejected", func(t *testing.T) {
		for _, broken := range []creds.Creds{
			{UserToken: b.UserToken, Seed: b.Seed},
			{AccountToken: b.AccountToken, Seed: b.Seed},
			{AccountToken: b.AccountToken, UserToken: b.UserToken},
		} {
			_, err := NewMessageTransport(broken, nil)
			assert.ErrorContains(t, err, "requires bundle creds")
		}
	})

	t.Run("chain epoch disagreement rejected", func(t *testing.T) {
		op, _ := issuerKeys(t)
		account, accountPub, _ := tenantKeys(t)
		_, userPub, userSeed := userKeys(t)
		acctTok, err := valiss.Issue(op, "acme", accountPub, valiss.WithEpoch(1), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		userTok, err := valiss.IssueUser(account, "alice", userPub, valiss.WithEpoch(2), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = NewMessageTransport(creds.Creds{AccountToken: acctTok, UserToken: userTok, Seed: userSeed}, nil)
		assert.ErrorContains(t, err, "chain epochs disagree")
	})

	t.Run("account seed rejected at first mint", func(t *testing.T) {
		_, _, accountSeed := tenantKeys(t)
		wrong := creds.Creds{AccountToken: b.AccountToken, UserToken: b.UserToken, Seed: accountSeed}
		_, err := NewMessageTransport(wrong, nil)
		require.NoError(t, err, "seed level is enforced by IssueMessage per request")
		tr, err := NewMessageTransport(wrong, nil)
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, "http://example.com/hook", bytes.NewReader([]byte("x")))
		require.NoError(t, err)
		_, err = tr.RoundTrip(req)
		assert.ErrorContains(t, err, "user-type nkey")
	})
}

func mustMessageTransport(t *testing.T, b creds.Creds, base http.RoundTripper) *MessageTransport {
	t.Helper()
	tr, err := NewMessageTransport(b, base)
	require.NoError(t, err)
	return tr
}

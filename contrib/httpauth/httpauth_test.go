package httpauth

import (
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

func issuerKeys(t *testing.T) (nkeys.KeyPair, string) {
	t.Helper()
	op, err := nkeys.CreateOperator()
	require.NoError(t, err)
	pub, err := op.PublicKey()
	require.NoError(t, err)
	return op, pub
}

func tenantKeys(t *testing.T) (nkeys.KeyPair, string, []byte) {
	t.Helper()
	tp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	pub, err := tp.PublicKey()
	require.NoError(t, err)
	seed, err := tp.Seed()
	require.NoError(t, err)
	return tp, pub, seed
}

func userKeys(t *testing.T) (nkeys.KeyPair, string, []byte) {
	t.Helper()
	up, err := nkeys.CreateUser()
	require.NoError(t, err)
	pub, err := up.PublicKey()
	require.NoError(t, err)
	seed, err := up.Seed()
	require.NoError(t, err)
	return up, pub, seed
}

// echoTenant writes the authenticated tenant name back to the client.
func echoTenant(w http.ResponseWriter, r *http.Request) {
	id, ok := valiss.IdentityFromContext(r.Context())
	if !ok {
		http.Error(w, "no identity in context", http.StatusInternalServerError)
		return
	}
	io.WriteString(w, id.Account.Name)
}

func newClient(t *testing.T, b creds.Creds) *http.Client {
	t.Helper()
	transport, err := NewTransport(b, nil)
	require.NoError(t, err)
	return &http.Client{Transport: transport}
}

func TestMiddlewareTransport(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub, seed := tenantKeys(t)
	tok, err := valiss.Issue(op, "acme", tenantPub, valiss.WithTTL(time.Hour))
	require.NoError(t, err)

	// Authentication is the focus here; extension enforcement is off.
	mw := NewMiddleware(valiss.NewVerifier(opPub, valiss.AllowAll{}), AllowMissingExtension())
	srv := httptest.NewServer(mw(http.HandlerFunc(echoTenant)))
	defer srv.Close()

	client := newClient(t, creds.Creds{AccountToken: tok, Seed: seed})

	t.Run("authenticated request reaches handler with the identity", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/v1/checks")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "acme", string(body))
	})

	t.Run("missing credential denied", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/v1/checks")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestExtEnforcement(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub, seed := tenantKeys(t)
	tok, err := valiss.Issue(op, "acme", tenantPub,
		valiss.WithExtension(Ext{Methods: []string{"GET"}, Paths: []string{"/v1/*"}}),
		valiss.WithTTL(time.Hour))
	require.NoError(t, err)

	mw := NewMiddleware(valiss.NewVerifier(opPub, valiss.AllowAll{}))
	srv := httptest.NewServer(mw(http.HandlerFunc(echoTenant)))
	defer srv.Close()

	client := newClient(t, creds.Creds{AccountToken: tok, Seed: seed})

	t.Run("request inside the extension allowed", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/v1/checks")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("path outside the extension denied", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/admin")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("method outside the extension denied", func(t *testing.T) {
		resp, err := client.Post(srv.URL+"/v1/checks", "text/plain", nil)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("host outside the extension denied", func(t *testing.T) {
		bound, err := valiss.Issue(op, "acme", tenantPub,
			valiss.WithExtension(Ext{Hosts: []string{"api.example.com"}}), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		resp, err := newClient(t, creds.Creds{AccountToken: bound, Seed: seed}).Get(srv.URL + "/v1/checks")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("account extension clamps the user", func(t *testing.T) {
		account, accountPub, _ := tenantKeys(t)
		acctTok, err := valiss.Issue(op, "acme", accountPub,
			valiss.WithExtension(Ext{Paths: []string{"/v1/*"}}), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		_, userPub, userSeed := userKeys(t)
		wide, err := valiss.IssueUser(account, "mallory", userPub,
			valiss.WithExtension(Ext{Paths: []string{"/admin/*"}}), valiss.WithTTL(time.Hour))
		require.NoError(t, err)

		resp, err := newClient(t, creds.Creds{AccountToken: acctTok, UserToken: wide, Seed: userSeed}).Get(srv.URL + "/admin/panel")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "user extension cannot escape the account extension")
	})

	t.Run("token without extension denied by default", func(t *testing.T) {
		open, err := valiss.Issue(op, "acme", tenantPub, valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		resp, err := newClient(t, creds.Creds{AccountToken: open, Seed: seed}).Get(srv.URL + "/v1/checks")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Contains(t, string(body), "no http extension")
	})

	t.Run("zero-value extension grants nothing", func(t *testing.T) {
		none, err := valiss.Issue(op, "acme", tenantPub,
			valiss.WithExtension(Ext{}), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		resp, err := newClient(t, creds.Creds{AccountToken: none, Seed: seed}).Get(srv.URL + "/v1/checks")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("wildcard path grants everything explicitly", func(t *testing.T) {
		all, err := valiss.Issue(op, "acme", tenantPub,
			valiss.WithExtension(Ext{Paths: []string{"*"}}), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		resp, err := newClient(t, creds.Creds{AccountToken: all, Seed: seed}).Get(srv.URL + "/anything")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestBearerTransport(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub, _ := tenantKeys(t)
	_, userPub, _ := userKeys(t)

	acctTok, err := valiss.Issue(op, "acme", accountPub, valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	mw := NewMiddleware(valiss.NewVerifier(opPub, valiss.AllowAll{}), AllowMissingExtension())
	srv := httptest.NewServer(mw(http.HandlerFunc(echoTenant)))
	defer srv.Close()

	t.Run("bearer user token allows token-only request", func(t *testing.T) {
		bearerTok, err := valiss.IssueUser(account, "carol", userPub, valiss.WithBearer(), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		client := newClient(t, creds.Creds{AccountToken: acctTok, UserToken: bearerTok})
		resp, err := client.Get(srv.URL)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "acme", string(body))
	})

	t.Run("plain token denies token-only request", func(t *testing.T) {
		client := newClient(t, creds.Creds{AccountToken: acctTok})
		resp, err := client.Get(srv.URL)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, string(body), "not a bearer token")
	})
}

func TestMiddlewareRejections(t *testing.T) {
	op, opPub := issuerKeys(t)
	tenant, tenantPub, seed := tenantKeys(t)
	tok, err := valiss.Issue(op, "acme", tenantPub, valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	claims, err := valiss.VerifyAccount(tok, opPub)
	require.NoError(t, err)

	mw := NewMiddleware(valiss.NewVerifier(opPub, valiss.NewStaticAllowlist(claims.ID)), AllowMissingExtension())
	srv := httptest.NewServer(mw(http.HandlerFunc(echoTenant)))
	defer srv.Close()

	t.Run("token not in allowlist", func(t *testing.T) {
		strict := NewMiddleware(valiss.NewVerifier(opPub, valiss.NewStaticAllowlist("other")), AllowMissingExtension())
		srv2 := httptest.NewServer(strict(http.HandlerFunc(echoTenant)))
		defer srv2.Close()
		resp, err := newClient(t, creds.Creds{AccountToken: tok, Seed: seed}).Get(srv2.URL)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, string(body), "not recognized")
	})

	t.Run("stale request signature", func(t *testing.T) {
		// The stale timestamp fails the skew window before the bound context
		// matters, so nil context is fine here.
		ts, sig, err := valiss.SignRequest(tenant, time.Now().Add(-time.Hour), nil)
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		require.NoError(t, err)
		req.Header.Set(valiss.HeaderAccountToken, tok)
		req.Header.Set(valiss.HeaderTimestamp, ts)
		req.Header.Set(valiss.HeaderSignature, sig)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("transport does not mutate caller request", func(t *testing.T) {
		transport, err := NewTransport(creds.Creds{AccountToken: tok, Seed: seed}, nil)
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Empty(t, req.Header.Get(valiss.HeaderAccountToken))
	})

	t.Run("captured headers do not replay against a different path", func(t *testing.T) {
		// Sign a real GET /a request, then replay its exact valiss-* headers
		// against POST /b. The signature is bound to the original method and
		// path, so the replay fails.
		signReq, err := http.NewRequest(http.MethodGet, srv.URL+"/a", nil)
		require.NoError(t, err)
		var captured http.Header
		transport, err := NewTransport(creds.Creds{AccountToken: tok, Seed: seed}, captureInto(&captured))
		require.NoError(t, err)
		_, _ = transport.RoundTrip(signReq)

		replay, err := http.NewRequest(http.MethodPost, srv.URL+"/b", nil)
		require.NoError(t, err)
		for _, h := range []string{valiss.HeaderAccountToken, valiss.HeaderTimestamp, valiss.HeaderSignature} {
			replay.Header.Set(h, captured.Get(h))
		}
		resp, err := http.DefaultClient.Do(replay)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "signature verification failed")
	})
}

func TestReplaySuppression(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub, seed := tenantKeys(t)
	tok, err := valiss.Issue(op, "acme", tenantPub,
		valiss.WithExtension(Ext{Paths: []string{"*"}}), valiss.WithTTL(time.Hour))
	require.NoError(t, err)

	mw := NewMiddleware(valiss.NewVerifier(opPub, valiss.AllowAll{}, valiss.WithReplayCache(valiss.NewMemoryReplayCache())))
	srv := httptest.NewServer(mw(http.HandlerFunc(echoTenant)))
	defer srv.Close()

	t.Run("nonce-enabled client passes once, replay rejected", func(t *testing.T) {
		var captured http.Header
		transport, err := NewTransport(creds.Creds{AccountToken: tok, Seed: seed}, captureInto(&captured), WithNonce())
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/x", nil)
		require.NoError(t, err)
		_, _ = transport.RoundTrip(req)

		send := func() int {
			replay, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/x", nil)
			require.NoError(t, err)
			for _, h := range []string{valiss.HeaderAccountToken, valiss.HeaderTimestamp, valiss.HeaderSignature, valiss.HeaderNonce} {
				replay.Header.Set(h, captured.Get(h))
			}
			resp, err := http.DefaultClient.Do(replay)
			require.NoError(t, err)
			resp.Body.Close()
			return resp.StatusCode
		}
		assert.Equal(t, http.StatusOK, send(), "first presentation accepted")
		assert.Equal(t, http.StatusUnauthorized, send(), "replay rejected")
	})

	t.Run("client without a nonce is rejected by a cache-enabled server", func(t *testing.T) {
		resp, err := newClient(t, creds.Creds{AccountToken: tok, Seed: seed}).Get(srv.URL + "/v1/x")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, string(body), "nonce required")
	})
}

// roundTripCapture is a base RoundTripper that records the outgoing request
// headers instead of sending them, for replay tests.
type roundTripCapture func(*http.Request) (*http.Response, error)

func (f roundTripCapture) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func captureInto(dst *http.Header) roundTripCapture {
	return func(r *http.Request) (*http.Response, error) {
		*dst = r.Header.Clone()
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
	}
}

// TestUserChain proves user-level creds authenticate through the middleware
// with the delegated identity.
func TestUserChain(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub, _ := tenantKeys(t)
	_, userPub, userSeed := userKeys(t)

	acctTok, err := valiss.Issue(op, "acme", accountPub,
		valiss.WithExtension(Ext{Paths: []string{"/v1/*"}}), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := valiss.IssueUser(account, "alice", userPub,
		valiss.WithExtension(Ext{Paths: []string{"/v1/checks"}}), valiss.WithTTL(time.Hour))
	require.NoError(t, err)

	// Strict default: both chain levels carry the extension.
	mw := NewMiddleware(valiss.NewVerifier(opPub, valiss.AllowAll{}))
	srv := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := valiss.IdentityFromContext(r.Context())
		require.True(t, ok)
		require.NotNil(t, id.User)
		io.WriteString(w, id.Account.Name+"/"+id.User.Name)
	})))
	defer srv.Close()

	client := newClient(t, creds.Creds{AccountToken: acctTok, UserToken: userTok, Seed: userSeed})

	t.Run("delegated path allowed with user identity", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/v1/checks")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "acme/alice", string(body))
	})

	t.Run("path beyond the delegation denied", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/v1/admin")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("user-only creds against a resolver-configured server", func(t *testing.T) {
		resolver, err := valiss.StaticAccountTokens(acctTok)
		require.NoError(t, err)
		rmw := NewMiddleware(valiss.NewVerifier(opPub, valiss.AllowAll{}, valiss.WithAccountTokenResolver(resolver)))
		rsrv := httptest.NewServer(rmw(http.HandlerFunc(echoTenant)))
		defer rsrv.Close()

		lean := newClient(t, creds.Creds{UserToken: userTok, Seed: userSeed})
		resp, err := lean.Get(rsrv.URL + "/v1/checks")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "acme", string(body))

		// The same creds against a server without a resolver are rejected.
		plain := NewMiddleware(valiss.NewVerifier(opPub, valiss.AllowAll{}))
		psrv := httptest.NewServer(plain(http.HandlerFunc(echoTenant)))
		defer psrv.Close()
		resp, err = lean.Get(psrv.URL + "/v1/checks")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

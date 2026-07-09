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

	"github.com/mikluko/valiss/pkg/creds"
	"github.com/mikluko/valiss/pkg/token"
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

// echoTenant writes the authenticated tenant id back to the client.
func echoTenant(w http.ResponseWriter, r *http.Request) {
	claims, ok := token.TenantFromContext(r.Context())
	if !ok {
		http.Error(w, "no tenant in context", http.StatusInternalServerError)
		return
	}
	io.WriteString(w, claims.TenantID)
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
	tok, err := token.Issue(op, "acme", tenantPub, []string{"call:*"}, time.Hour)
	require.NoError(t, err)

	mw := NewMiddleware(token.NewVerifier(opPub, token.AllowAll{}), WithPathScope())
	srv := httptest.NewServer(mw(http.HandlerFunc(echoTenant)))
	defer srv.Close()

	client := newClient(t, creds.Creds{AccountToken: tok, Seed: seed})

	t.Run("authenticated request reaches handler with tenant", func(t *testing.T) {
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

func TestMiddlewareScope(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub, seed := tenantKeys(t)
	tok, err := token.Issue(op, "acme", tenantPub, []string{"call:/v1/checks"}, time.Hour)
	require.NoError(t, err)

	mw := NewMiddleware(token.NewVerifier(opPub, token.AllowAll{}), WithPathScope())
	srv := httptest.NewServer(mw(http.HandlerFunc(echoTenant)))
	defer srv.Close()

	client := newClient(t, creds.Creds{AccountToken: tok, Seed: seed})

	t.Run("granted path allowed", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/v1/checks")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("other path denied", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/v1/admin")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

func TestBearerTransport(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub, _ := tenantKeys(t)
	mw := NewMiddleware(token.NewVerifier(opPub, token.AllowAll{}))
	srv := httptest.NewServer(mw(http.HandlerFunc(echoTenant)))
	defer srv.Close()

	t.Run("bearer scope allows token-only request", func(t *testing.T) {
		tok, err := token.Issue(op, "acme", tenantPub, []string{token.ScopeBearer}, time.Hour)
		require.NoError(t, err)
		client := newClient(t, creds.Creds{AccountToken: tok})
		resp, err := client.Get(srv.URL)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "acme", string(body))
	})

	t.Run("no bearer scope denies token-only request", func(t *testing.T) {
		tok, err := token.Issue(op, "acme", tenantPub, []string{"call:*"}, time.Hour)
		require.NoError(t, err)
		client := newClient(t, creds.Creds{AccountToken: tok})
		resp, err := client.Get(srv.URL)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, string(body), "bearer scope")
	})
}

func TestMiddlewareRejections(t *testing.T) {
	op, opPub := issuerKeys(t)
	tenant, tenantPub, seed := tenantKeys(t)
	tok, err := token.Issue(op, "acme", tenantPub, nil, time.Hour)
	require.NoError(t, err)
	claims, err := token.Verify(tok, opPub)
	require.NoError(t, err)

	mw := NewMiddleware(token.NewVerifier(opPub, token.NewStaticAllowlist(claims.ID)))
	srv := httptest.NewServer(mw(http.HandlerFunc(echoTenant)))
	defer srv.Close()

	t.Run("token not in allowlist", func(t *testing.T) {
		strict := NewMiddleware(token.NewVerifier(opPub, token.NewStaticAllowlist("other")))
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
		ts, sig, err := token.SignRequest(tenant, time.Now().Add(-time.Hour))
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		require.NoError(t, err)
		req.Header.Set(token.HeaderAccountToken, tok)
		req.Header.Set(token.HeaderTimestamp, ts)
		req.Header.Set(token.HeaderSignature, sig)
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
		assert.Empty(t, req.Header.Get(token.HeaderAccountToken))
	})
}

// TestUserChain proves user-level creds authenticate through the
// middleware with the delegated identity.
func TestUserChain(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub, _ := tenantKeys(t)
	user, err := nkeys.CreateUser()
	require.NoError(t, err)
	userPub, err := user.PublicKey()
	require.NoError(t, err)
	userSeed, err := user.Seed()
	require.NoError(t, err)

	acctTok, err := token.Issue(op, "acme", accountPub, []string{"call:*"}, time.Hour)
	require.NoError(t, err)
	userTok, err := token.IssueUser(account, "alice", userPub, []string{"call:/v1/checks"}, time.Hour)
	require.NoError(t, err)

	mw := NewMiddleware(token.NewVerifier(opPub, token.AllowAll{}), WithPathScope())
	srv := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := token.TenantFromContext(r.Context())
		require.True(t, ok)
		io.WriteString(w, claims.TenantID+"/"+claims.UserID)
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
		resolver, err := token.StaticAccountTokens(acctTok)
		require.NoError(t, err)
		rmw := NewMiddleware(token.NewVerifier(opPub, token.AllowAll{}, token.WithAccountTokenResolver(resolver)))
		rsrv := httptest.NewServer(rmw(http.HandlerFunc(echoTenant)))
		defer rsrv.Close()

		lean := newClient(t, creds.Creds{UserToken: userTok, Seed: userSeed})
		resp, err := lean.Get(rsrv.URL)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "acme", string(body))

		// The same creds against a server without a resolver are rejected.
		plain := NewMiddleware(token.NewVerifier(opPub, token.AllowAll{}))
		psrv := httptest.NewServer(plain(http.HandlerFunc(echoTenant)))
		defer psrv.Close()
		resp, err = lean.Get(psrv.URL)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

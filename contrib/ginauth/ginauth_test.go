package ginauth

import (
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
	"valiss.dev/valiss/contrib/httpauth"
	"valiss.dev/valiss/creds"
)

func init() {
	gin.SetMode(gin.TestMode)
}

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

func newClient(t *testing.T, b creds.Creds) *http.Client {
	t.Helper()
	transport, err := httpauth.NewTransport(b, nil)
	require.NoError(t, err)
	return &http.Client{Transport: transport}
}

// newServer builds a Gin engine with the middleware and a handler echoing
// the authenticated identity through IdentityFrom.
func newServer(t *testing.T, verifier *valiss.Verifier, opts ...httpauth.Option) *httptest.Server {
	t.Helper()
	e := gin.New()
	e.Use(NewMiddleware(verifier, opts...))
	echoIdentity := func(c *gin.Context) {
		id, ok := IdentityFrom(c)
		if !ok {
			c.String(http.StatusInternalServerError, "no identity in context")
			return
		}
		name := id.Account.Name
		if id.User != nil {
			name += "/" + id.User.Name
		}
		c.String(http.StatusOK, "%s", name)
	}
	e.GET("/*path", echoIdentity)
	e.POST("/*path", echoIdentity)
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)
	return srv
}

func TestMiddleware(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub, seed := tenantKeys(t)
	tok, err := valiss.IssueAccount(op, tenantPub, valiss.WithName("acme"), valiss.WithTTL(time.Hour))
	require.NoError(t, err)

	srv := newServer(t, valiss.NewVerifier(opPub, valiss.AllowAll{}), httpauth.AllowMissingExtension())
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

	t.Run("missing credential aborts with 401", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/v1/checks")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, string(body), "missing credentials")
	})
}

func TestExtEnforcement(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub, seed := tenantKeys(t)
	tok, err := valiss.IssueAccount(op, tenantPub, valiss.WithName("acme"),
		valiss.WithExtension(httpauth.Ext{Methods: []string{"GET"}, Paths: []string{"/v1/*"}}),
		valiss.WithTTL(time.Hour))
	require.NoError(t, err)

	srv := newServer(t, valiss.NewVerifier(opPub, valiss.AllowAll{}))
	client := newClient(t, creds.Creds{AccountToken: tok, Seed: seed})

	t.Run("request inside the extension allowed", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/v1/checks")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("path outside the extension aborted with 403", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/admin")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("method outside the extension aborted with 403", func(t *testing.T) {
		resp, err := client.Post(srv.URL+"/v1/checks", "text/plain", nil)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("token without extension denied by default", func(t *testing.T) {
		open, err := valiss.IssueAccount(op, tenantPub, valiss.WithName("acme"), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		resp, err := newClient(t, creds.Creds{AccountToken: open, Seed: seed}).Get(srv.URL + "/v1/checks")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Contains(t, string(body), "no http extension")
	})
}

func TestUserChain(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub, _ := tenantKeys(t)
	_, userPub, userSeed := userKeys(t)

	acctTok, err := valiss.IssueAccount(op, accountPub, valiss.WithName("acme"),
		valiss.WithExtension(httpauth.Ext{Paths: []string{"/v1/*"}}), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := valiss.IssueUser(account, userPub, valiss.WithName("alice"),
		valiss.WithExtension(httpauth.Ext{Paths: []string{"/v1/checks"}}), valiss.WithTTL(time.Hour))
	require.NoError(t, err)

	srv := newServer(t, valiss.NewVerifier(opPub, valiss.AllowAll{}))
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

	t.Run("path beyond the delegation aborted", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/v1/admin")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

// TestAbortStopsChain proves a rejection prevents downstream handlers from
// running, not just from being reached by the response.
func TestAbortStopsChain(t *testing.T) {
	_, opPub := issuerKeys(t)

	var reached bool
	e := gin.New()
	e.Use(NewMiddleware(valiss.NewVerifier(opPub, valiss.AllowAll{})))
	e.GET("/", func(c *gin.Context) { reached = true })
	srv := httptest.NewServer(e)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.False(t, reached, "handler must not run after abort")
}

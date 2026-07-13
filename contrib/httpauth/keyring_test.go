package httpauth

import (
	"fmt"
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

// TestKeyringVerifier proves the middleware serves credentials from
// several trust domains through a keyring verifier, exposing the matched
// operator to handlers.
func TestKeyringVerifier(t *testing.T) {
	newDomain := func(name string) (operatorToken string, b creds.Creds) {
		t.Helper()
		op, _ := issuerKeys(t)
		_, accountPub, accountSeed := tenantKeys(t)
		operatorToken, err := valiss.IssueOperator(op, valiss.WithName(name), valiss.WithEpoch(1))
		require.NoError(t, err)
		accountToken, err := valiss.IssueAccount(op, accountPub, valiss.WithName("acme"), valiss.WithEpoch(1), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		return operatorToken, creds.Creds{AccountToken: accountToken, Seed: accountSeed}
	}

	opTokA, credsA := newDomain("prod-us")
	opTokB, credsB := newDomain("on-prem")
	k, err := valiss.NewKeyring(opTokA, opTokB)
	require.NoError(t, err)

	mw := NewMiddleware(valiss.NewKeyringVerifier(k, valiss.AllowAll{}), AllowMissingExtension())
	srv := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := valiss.IdentityFromContext(r.Context())
		require.True(t, ok)
		require.NotNil(t, id.Operator)
		fmt.Fprintf(w, "%s/%s", id.Operator.Name, id.Account.Name)
	})))
	defer srv.Close()

	get := func(b creds.Creds) (int, string) {
		t.Helper()
		resp, err := newClient(t, b).Get(srv.URL + "/v1/data")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, string(body)
	}

	code, body := get(credsA)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "prod-us/acme", body)
	code, body = get(credsB)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "on-prem/acme", body, "same tenant name segments by operator name")

	t.Run("unknown producer rejected", func(t *testing.T) {
		_, stranger := newDomain("stranger")
		code, _ := get(stranger)
		assert.Equal(t, http.StatusUnauthorized, code)
	})
}

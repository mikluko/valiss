package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyCredentialBearer(t *testing.T) {
	op, opPub := issuerKeys(t)
	tenant, tenantPub := tenantKeys(t)

	bearerTok, err := Issue(op, "acme", tenantPub, []string{ScopeBearer, "read"}, time.Hour)
	require.NoError(t, err)
	signedOnlyTok, err := Issue(op, "acme", tenantPub, []string{"read"}, time.Hour)
	require.NoError(t, err)

	v := NewVerifier(opPub, AllowAll{})

	t.Run("bearer scope allows unsigned request", func(t *testing.T) {
		claims, err := v.VerifyCredential(bearerTok, "", "")
		require.NoError(t, err)
		assert.Equal(t, "acme", claims.TenantID)
	})

	t.Run("no bearer scope rejects unsigned request", func(t *testing.T) {
		_, err := v.VerifyCredential(signedOnlyTok, "", "")
		assert.ErrorContains(t, err, "bearer scope")
	})

	t.Run("signature still verified when present on a bearer token", func(t *testing.T) {
		ts, sig, err := SignRequest(tenant, time.Now())
		require.NoError(t, err)
		_, err = v.VerifyCredential(bearerTok, ts, sig)
		assert.NoError(t, err)

		_, err = v.VerifyCredential(bearerTok, ts, "AAAA")
		assert.Error(t, err, "bad signature must not fall back to bearer")
	})

	t.Run("partial credential is not bearer", func(t *testing.T) {
		ts, _, err := SignRequest(tenant, time.Now())
		require.NoError(t, err)
		_, err = v.VerifyCredential(bearerTok, ts, "")
		assert.Error(t, err, "timestamp without signature must fail")
	})

	t.Run("bearer wildcard not implied by call wildcard", func(t *testing.T) {
		callAll, err := Issue(op, "acme", tenantPub, []string{"call:*"}, time.Hour)
		require.NoError(t, err)
		_, err = v.VerifyCredential(callAll, "", "")
		assert.ErrorContains(t, err, "bearer scope")
	})
}

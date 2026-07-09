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
		claims, err := v.VerifyCredential(Credential{Token: bearerTok})
		require.NoError(t, err)
		assert.Equal(t, "acme", claims.TenantID)
	})

	t.Run("no bearer scope rejects unsigned request", func(t *testing.T) {
		_, err := v.VerifyCredential(Credential{Token: signedOnlyTok})
		assert.ErrorContains(t, err, "bearer scope")
	})

	t.Run("signature still verified when present on a bearer token", func(t *testing.T) {
		ts, sig, err := SignRequest(tenant, time.Now())
		require.NoError(t, err)
		_, err = v.VerifyCredential(Credential{Token: bearerTok, Timestamp: ts, Signature: sig})
		assert.NoError(t, err)

		_, err = v.VerifyCredential(Credential{Token: bearerTok, Timestamp: ts, Signature: "AAAA"})
		assert.Error(t, err, "bad signature must not fall back to bearer")
	})

	t.Run("partial credential is not bearer", func(t *testing.T) {
		ts, _, err := SignRequest(tenant, time.Now())
		require.NoError(t, err)
		_, err = v.VerifyCredential(Credential{Token: bearerTok, Timestamp: ts})
		assert.Error(t, err, "timestamp without signature must fail")
	})

	t.Run("bearer wildcard not implied by call wildcard", func(t *testing.T) {
		callAll, err := Issue(op, "acme", tenantPub, []string{"call:*"}, time.Hour)
		require.NoError(t, err)
		_, err = v.VerifyCredential(Credential{Token: callAll})
		assert.ErrorContains(t, err, "bearer scope")
	})
}

func TestVerifyCredentialChain(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	user, userPub := userKeys(t)

	acctTok, err := Issue(op, "acme", accountPub, []string{"call:/svc/*"}, time.Hour)
	require.NoError(t, err)
	userTok, err := IssueUser(account, "alice", userPub, []string{"call:/svc/Get"}, time.Hour)
	require.NoError(t, err)

	v := NewVerifier(opPub, AllowAll{})
	ts, sig, err := SignRequest(user, time.Now())
	require.NoError(t, err)

	t.Run("valid chain authenticates the user", func(t *testing.T) {
		claims, err := v.VerifyCredential(Credential{Token: acctTok, UserToken: userTok, Timestamp: ts, Signature: sig})
		require.NoError(t, err)
		assert.Equal(t, "acme", claims.TenantID)
		assert.Equal(t, "alice", claims.UserID)
		assert.Equal(t, userPub, claims.PubKey)
		assert.True(t, claims.Authorizes("call:/svc/Get"))
		assert.False(t, claims.Authorizes("call:/svc/Delete"))
	})

	t.Run("account signature does not pass for a chain request", func(t *testing.T) {
		acctTS, acctSig, err := SignRequest(account, time.Now())
		require.NoError(t, err)
		_, err = v.VerifyCredential(Credential{Token: acctTok, UserToken: userTok, Timestamp: acctTS, Signature: acctSig})
		assert.ErrorContains(t, err, "signature verification failed")
	})

	t.Run("user token signed by a foreign account rejected", func(t *testing.T) {
		other, _ := tenantKeys(t)
		foreign, err := IssueUser(other, "alice", userPub, []string{"call:/svc/Get"}, time.Hour)
		require.NoError(t, err)
		_, err = v.VerifyCredential(Credential{Token: acctTok, UserToken: foreign, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "expected issuer")
	})

	t.Run("scope escalation clamped to the account grants", func(t *testing.T) {
		escalated, err := IssueUser(account, "alice", userPub, []string{"call:/svc/Get", "call:/other/*"}, time.Hour)
		require.NoError(t, err)
		claims, err := v.VerifyCredential(Credential{Token: acctTok, UserToken: escalated, Timestamp: ts, Signature: sig})
		require.NoError(t, err)
		assert.True(t, claims.Authorizes("call:/svc/Get"))
		assert.False(t, claims.Authorizes("call:/other/Get"), "scopes beyond the account grants must be clamped")
	})

	t.Run("bearer user makes token-only requests", func(t *testing.T) {
		bearer, err := IssueUser(account, "carol", "", []string{ScopeBearer, "call:/svc/Get"}, time.Hour)
		require.NoError(t, err)
		claims, err := v.VerifyCredential(Credential{Token: acctTok, UserToken: bearer})
		require.NoError(t, err)
		assert.Equal(t, "carol", claims.UserID)
		assert.True(t, claims.HasScope(ScopeBearer), "bearer scope must survive clamping")
	})

	t.Run("signing user cannot go token-only", func(t *testing.T) {
		_, err := v.VerifyCredential(Credential{Token: acctTok, UserToken: userTok})
		assert.ErrorContains(t, err, "bearer scope")
	})

	t.Run("signed request with a keyless bearer token rejected", func(t *testing.T) {
		bearer, err := IssueUser(account, "carol", "", []string{ScopeBearer}, time.Hour)
		require.NoError(t, err)
		_, err = v.VerifyCredential(Credential{Token: acctTok, UserToken: bearer, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "binds no key")
	})

	t.Run("expired user token rejected", func(t *testing.T) {
		short, err := IssueUser(account, "alice", userPub, []string{"call:/svc/Get"}, time.Second)
		require.NoError(t, err)
		late := NewVerifier(opPub, AllowAll{}, WithClock(func() time.Time { return time.Now().Add(10 * time.Minute) }), WithSkew(0))
		_, err = late.VerifyCredential(Credential{Token: acctTok, UserToken: short})
		assert.ErrorContains(t, err, "user token expired")
	})

	t.Run("expiry is the earlier of the two tokens", func(t *testing.T) {
		short, err := IssueUser(account, "alice", userPub, []string{"call:/svc/Get"}, time.Minute)
		require.NoError(t, err)
		claims, err := v.VerifyCredential(Credential{Token: acctTok, UserToken: short, Timestamp: ts, Signature: sig})
		require.NoError(t, err)
		acct, err := Verify(acctTok, opPub)
		require.NoError(t, err)
		assert.True(t, claims.ExpiresAt.Before(acct.ExpiresAt))
	})

	t.Run("revoking the account token cuts off its users", func(t *testing.T) {
		strict := NewVerifier(opPub, NewStaticAllowlist("other"))
		_, err := strict.VerifyCredential(Credential{Token: acctTok, UserToken: userTok, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "not recognized")
	})
}

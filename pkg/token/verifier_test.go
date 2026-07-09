package token

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyCredentialBearer(t *testing.T) {
	op, opPub := issuerKeys(t)
	tenant, tenantPub := tenantKeys(t)

	bearerTok, err := Issue(op, "acme", tenantPub, []string{ScopeBearer, "read"}, WithTTL(time.Hour))
	require.NoError(t, err)
	signedOnlyTok, err := Issue(op, "acme", tenantPub, []string{"read"}, WithTTL(time.Hour))
	require.NoError(t, err)

	v := NewVerifier(opPub, AllowAll{})

	t.Run("bearer scope allows unsigned request", func(t *testing.T) {
		claims, err := v.VerifyRequest(Request{AccountToken: bearerTok})
		require.NoError(t, err)
		assert.Equal(t, "acme", claims.TenantID)
	})

	t.Run("no bearer scope rejects unsigned request", func(t *testing.T) {
		_, err := v.VerifyRequest(Request{AccountToken: signedOnlyTok})
		assert.ErrorContains(t, err, "bearer scope")
	})

	t.Run("signature still verified when present on a bearer token", func(t *testing.T) {
		ts, sig, err := SignRequest(tenant, time.Now())
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: bearerTok, Timestamp: ts, Signature: sig})
		assert.NoError(t, err)

		_, err = v.VerifyRequest(Request{AccountToken: bearerTok, Timestamp: ts, Signature: "AAAA"})
		assert.Error(t, err, "bad signature must not fall back to bearer")
	})

	t.Run("partial credential is not bearer", func(t *testing.T) {
		ts, _, err := SignRequest(tenant, time.Now())
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: bearerTok, Timestamp: ts})
		assert.Error(t, err, "timestamp without signature must fail")
	})

	t.Run("bearer wildcard not implied by call wildcard", func(t *testing.T) {
		callAll, err := Issue(op, "acme", tenantPub, []string{"call:*"}, WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: callAll})
		assert.ErrorContains(t, err, "bearer scope")
	})
}

func TestClaimsValidator(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	user, userPub := userKeys(t)

	acctTok, err := Issue(op, "acme", accountPub, []string{"call:*"}, WithTTL(time.Hour))
	require.NoError(t, err)
	acctTS, acctSig, err := SignRequest(account, time.Now())
	require.NoError(t, err)

	t.Run("validator sees the effective claims", func(t *testing.T) {
		userTok, err := IssueUser(account, "alice", userPub, []string{"call:/svc/Get"}, WithTTL(time.Hour))
		require.NoError(t, err)
		ts, sig, err := SignRequest(user, time.Now())
		require.NoError(t, err)

		var seen *Claims
		v := NewVerifier(opPub, AllowAll{}, WithClaimsValidator(func(_ Request, c *Claims) error {
			seen = c
			return nil
		}))
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, UserToken: userTok, Timestamp: ts, Signature: sig})
		require.NoError(t, err)
		require.NotNil(t, seen)
		assert.Equal(t, "acme", seen.TenantID)
		assert.Equal(t, "alice", seen.UserID, "validator runs after chain assembly")
	})

	t.Run("validator error rejects the request", func(t *testing.T) {
		banned := errors.New("tenant suspended")
		v := NewVerifier(opPub, AllowAll{}, WithClaimsValidator(func(_ Request, c *Claims) error {
			if c.TenantID == "acme" {
				return banned
			}
			return nil
		}))
		_, err := v.VerifyRequest(Request{AccountToken: acctTok, Timestamp: acctTS, Signature: acctSig})
		assert.ErrorIs(t, err, banned)
	})

	t.Run("validators run in order, first error wins", func(t *testing.T) {
		first := errors.New("first")
		var secondRan bool
		v := NewVerifier(opPub, AllowAll{},
			WithClaimsValidator(func(Request, *Claims) error { return first }),
			WithClaimsValidator(func(Request, *Claims) error { secondRan = true; return nil }),
		)
		_, err := v.VerifyRequest(Request{AccountToken: acctTok, Timestamp: acctTS, Signature: acctSig})
		assert.ErrorIs(t, err, first)
		assert.False(t, secondRan)
	})

	t.Run("validator runs before the bearer gate", func(t *testing.T) {
		// A rejected bearer request reports the validator's error, not the
		// missing-signature one.
		custom := errors.New("nope")
		v := NewVerifier(opPub, AllowAll{}, WithClaimsValidator(func(Request, *Claims) error { return custom }))
		_, err := v.VerifyRequest(Request{AccountToken: acctTok})
		assert.ErrorIs(t, err, custom)
	})
}

func TestValidityWindow(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub := tenantKeys(t)

	t.Run("token without expiry never expires", func(t *testing.T) {
		tok, err := Issue(op, "acme", tenantPub, []string{ScopeBearer})
		require.NoError(t, err)
		claims, err := Verify(tok, opPub)
		require.NoError(t, err)
		assert.True(t, claims.ExpiresAt.IsZero())

		farFuture := NewVerifier(opPub, AllowAll{}, WithClock(func() time.Time { return time.Now().Add(100 * 365 * 24 * time.Hour) }))
		_, err = farFuture.VerifyRequest(Request{AccountToken: tok})
		assert.NoError(t, err)
	})

	t.Run("not-before gates the token", func(t *testing.T) {
		start := time.Now().Add(time.Hour)
		tok, err := Issue(op, "acme", tenantPub, []string{ScopeBearer}, WithTTL(2*time.Hour), WithNotBefore(start))
		require.NoError(t, err)

		early := NewVerifier(opPub, AllowAll{}, WithSkew(0))
		_, err = early.VerifyRequest(Request{AccountToken: tok})
		assert.ErrorContains(t, err, "not yet valid")

		inWindow := NewVerifier(opPub, AllowAll{}, WithSkew(0), WithClock(func() time.Time { return start.Add(time.Minute) }))
		_, err = inWindow.VerifyRequest(Request{AccountToken: tok})
		assert.NoError(t, err)
	})

	t.Run("user token not-before gates the chain", func(t *testing.T) {
		account, accountPub := tenantKeys(t)
		acctTok, err := Issue(op, "acme", accountPub, []string{"call:*"}, WithTTL(time.Hour))
		require.NoError(t, err)
		userTok, err := IssueUser(account, "carol", "", []string{ScopeBearer}, WithNotBefore(time.Now().Add(time.Hour)))
		require.NoError(t, err)
		v := NewVerifier(opPub, AllowAll{}, WithSkew(0))
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, UserToken: userTok})
		assert.ErrorContains(t, err, "user token not yet valid")
	})
}

func TestAccountTokenResolver(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	user, userPub := userKeys(t)

	acctTok, err := Issue(op, "acme", accountPub, []string{"call:*"}, WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := IssueUser(account, "alice", userPub, []string{"call:/svc/Get"}, WithTTL(time.Hour))
	require.NoError(t, err)
	ts, sig, err := SignRequest(user, time.Now())
	require.NoError(t, err)

	resolver, err := StaticAccountTokens(acctTok)
	require.NoError(t, err)

	t.Run("user-only credential resolves the account token", func(t *testing.T) {
		v := NewVerifier(opPub, AllowAll{}, WithAccountTokenResolver(resolver))
		claims, err := v.VerifyRequest(Request{UserToken: userTok, Timestamp: ts, Signature: sig})
		require.NoError(t, err)
		assert.Equal(t, "acme", claims.TenantID)
		assert.Equal(t, "alice", claims.UserID)
	})

	t.Run("no resolver rejects user-only credentials", func(t *testing.T) {
		v := NewVerifier(opPub, AllowAll{})
		_, err := v.VerifyRequest(Request{UserToken: userTok, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "no account token resolver")
	})

	t.Run("unknown account rejected", func(t *testing.T) {
		other, _ := tenantKeys(t)
		foreignUserTok, err := IssueUser(other, "mallory", userPub, []string{"call:/svc/Get"}, WithTTL(time.Hour))
		require.NoError(t, err)
		v := NewVerifier(opPub, AllowAll{}, WithAccountTokenResolver(resolver))
		_, err = v.VerifyRequest(Request{UserToken: foreignUserTok, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "no account token configured")
	})

	t.Run("resolved token still passes the allowlist", func(t *testing.T) {
		v := NewVerifier(opPub, NewStaticAllowlist("other"), WithAccountTokenResolver(resolver))
		_, err := v.VerifyRequest(Request{UserToken: userTok, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "not recognized")
	})

	t.Run("empty credential still rejected", func(t *testing.T) {
		v := NewVerifier(opPub, AllowAll{}, WithAccountTokenResolver(resolver))
		_, err := v.VerifyRequest(Request{})
		assert.ErrorContains(t, err, "missing credentials")
	})

	t.Run("tampered user token rejected before resolution", func(t *testing.T) {
		v := NewVerifier(opPub, AllowAll{}, WithAccountTokenResolver(resolver))
		_, err := v.VerifyRequest(Request{UserToken: userTok[:len(userTok)-2] + "xx", Timestamp: ts, Signature: sig})
		assert.Error(t, err)
	})
}

func TestVerifyCredentialChain(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	user, userPub := userKeys(t)

	acctTok, err := Issue(op, "acme", accountPub, []string{"call:/svc/*"}, WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := IssueUser(account, "alice", userPub, []string{"call:/svc/Get"}, WithTTL(time.Hour))
	require.NoError(t, err)

	v := NewVerifier(opPub, AllowAll{})
	ts, sig, err := SignRequest(user, time.Now())
	require.NoError(t, err)

	t.Run("valid chain authenticates the user", func(t *testing.T) {
		claims, err := v.VerifyRequest(Request{AccountToken: acctTok, UserToken: userTok, Timestamp: ts, Signature: sig})
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
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, UserToken: userTok, Timestamp: acctTS, Signature: acctSig})
		assert.ErrorContains(t, err, "signature verification failed")
	})

	t.Run("user token signed by a foreign account rejected", func(t *testing.T) {
		other, _ := tenantKeys(t)
		foreign, err := IssueUser(other, "alice", userPub, []string{"call:/svc/Get"}, WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, UserToken: foreign, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "expected issuer")
	})

	t.Run("scope escalation clamped to the account grants", func(t *testing.T) {
		escalated, err := IssueUser(account, "alice", userPub, []string{"call:/svc/Get", "call:/other/*"}, WithTTL(time.Hour))
		require.NoError(t, err)
		claims, err := v.VerifyRequest(Request{AccountToken: acctTok, UserToken: escalated, Timestamp: ts, Signature: sig})
		require.NoError(t, err)
		assert.True(t, claims.Authorizes("call:/svc/Get"))
		assert.False(t, claims.Authorizes("call:/other/Get"), "scopes beyond the account grants must be clamped")
	})

	t.Run("bearer user makes token-only requests", func(t *testing.T) {
		bearer, err := IssueUser(account, "carol", "", []string{ScopeBearer, "call:/svc/Get"}, WithTTL(time.Hour))
		require.NoError(t, err)
		claims, err := v.VerifyRequest(Request{AccountToken: acctTok, UserToken: bearer})
		require.NoError(t, err)
		assert.Equal(t, "carol", claims.UserID)
		assert.True(t, claims.HasScope(ScopeBearer), "bearer scope must survive clamping")
	})

	t.Run("signing user cannot go token-only", func(t *testing.T) {
		_, err := v.VerifyRequest(Request{AccountToken: acctTok, UserToken: userTok})
		assert.ErrorContains(t, err, "bearer scope")
	})

	t.Run("signed request with a keyless bearer token rejected", func(t *testing.T) {
		bearer, err := IssueUser(account, "carol", "", []string{ScopeBearer}, WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, UserToken: bearer, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "binds no key")
	})

	t.Run("expired user token rejected", func(t *testing.T) {
		short, err := IssueUser(account, "alice", userPub, []string{"call:/svc/Get"}, WithTTL(time.Second))
		require.NoError(t, err)
		late := NewVerifier(opPub, AllowAll{}, WithClock(func() time.Time { return time.Now().Add(10 * time.Minute) }), WithSkew(0))
		_, err = late.VerifyRequest(Request{AccountToken: acctTok, UserToken: short})
		assert.ErrorContains(t, err, "user token expired")
	})

	t.Run("expiry is the earlier of the two tokens", func(t *testing.T) {
		short, err := IssueUser(account, "alice", userPub, []string{"call:/svc/Get"}, WithTTL(time.Minute))
		require.NoError(t, err)
		claims, err := v.VerifyRequest(Request{AccountToken: acctTok, UserToken: short, Timestamp: ts, Signature: sig})
		require.NoError(t, err)
		acct, err := Verify(acctTok, opPub)
		require.NoError(t, err)
		assert.True(t, claims.ExpiresAt.Before(acct.ExpiresAt))
	})

	t.Run("revoking the account token cuts off its users", func(t *testing.T) {
		strict := NewVerifier(opPub, NewStaticAllowlist("other"))
		_, err := strict.VerifyRequest(Request{AccountToken: acctTok, UserToken: userTok, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "not recognized")
	})
}

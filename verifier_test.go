package valiss

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyRequestBearer(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	user, userPub := userKeys(t)

	acctTok, err := IssueAccount(op, accountPub, WithName("acme"), WithTTL(time.Hour))
	require.NoError(t, err)
	bearerTok, err := IssueUser(account, userPub, WithName("carol"), WithBearer(), WithTTL(time.Hour))
	require.NoError(t, err)
	plainTok, err := IssueUser(account, userPub, WithName("alice"), WithTTL(time.Hour))
	require.NoError(t, err)

	v := NewVerifier(opPub, AllowAll{})

	t.Run("bearer user token allows unsigned request", func(t *testing.T) {
		id, err := v.VerifyRequest(Request{AccountToken: acctTok, UserToken: bearerTok})
		require.NoError(t, err)
		assert.Equal(t, "acme", id.Account.Name)
		require.NotNil(t, id.User)
		assert.Equal(t, "carol", id.User.Name)
		assert.True(t, id.User.Bearer)
	})

	t.Run("plain user token rejects unsigned request", func(t *testing.T) {
		_, err := v.VerifyRequest(Request{AccountToken: acctTok, UserToken: plainTok})
		assert.ErrorContains(t, err, "not a bearer token")
	})

	t.Run("account token alone rejects unsigned request", func(t *testing.T) {
		_, err := v.VerifyRequest(Request{AccountToken: acctTok})
		assert.ErrorContains(t, err, "not a bearer token")
	})

	t.Run("signature still verified when present on a bearer token", func(t *testing.T) {
		ts, sig, err := SignRequest(user, time.Now(), nil)
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, UserToken: bearerTok, Timestamp: ts, Signature: sig})
		assert.NoError(t, err)

		_, err = v.VerifyRequest(Request{AccountToken: acctTok, UserToken: bearerTok, Timestamp: ts, Signature: "AAAA"})
		assert.Error(t, err, "bad signature must not fall back to bearer")
	})

	t.Run("partial credential is not bearer", func(t *testing.T) {
		ts, _, err := SignRequest(user, time.Now(), nil)
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, UserToken: bearerTok, Timestamp: ts})
		assert.Error(t, err, "timestamp without signature must fail")
	})
}

func TestClaimsValidator(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	user, userPub := userKeys(t)

	acctTok, err := IssueAccount(op, accountPub, WithName("acme"), WithTTL(time.Hour))
	require.NoError(t, err)
	acctTS, acctSig, err := SignRequest(account, time.Now(), nil)
	require.NoError(t, err)

	t.Run("validator sees the assembled identity", func(t *testing.T) {
		userTok, err := IssueUser(account, userPub, WithName("alice"), WithTTL(time.Hour))
		require.NoError(t, err)
		ts, sig, err := SignRequest(user, time.Now(), nil)
		require.NoError(t, err)

		var seen *Identity
		v := NewVerifier(opPub, AllowAll{}, WithClaimsValidator(func(_ Request, id *Identity) error {
			seen = id
			return nil
		}))
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, UserToken: userTok, Timestamp: ts, Signature: sig})
		require.NoError(t, err)
		require.NotNil(t, seen)
		assert.Equal(t, "acme", seen.Account.Name)
		require.NotNil(t, seen.User)
		assert.Equal(t, "alice", seen.User.Name, "validator runs after chain assembly")
	})

	t.Run("validator error rejects the request", func(t *testing.T) {
		banned := errors.New("tenant suspended")
		v := NewVerifier(opPub, AllowAll{}, WithClaimsValidator(func(_ Request, id *Identity) error {
			if id.Account.Name == "acme" {
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
			WithClaimsValidator(func(Request, *Identity) error { return first }),
			WithClaimsValidator(func(Request, *Identity) error { secondRan = true; return nil }),
		)
		_, err := v.VerifyRequest(Request{AccountToken: acctTok, Timestamp: acctTS, Signature: acctSig})
		assert.ErrorIs(t, err, first)
		assert.False(t, secondRan)
	})

	t.Run("validators run only after possession is proven", func(t *testing.T) {
		var ran bool
		v := NewVerifier(opPub, AllowAll{}, WithClaimsValidator(func(Request, *Identity) error {
			ran = true
			return nil
		}))
		// An unsigned account request is rejected at the possession gate
		// before the validator can run.
		_, err := v.VerifyRequest(Request{AccountToken: acctTok})
		assert.ErrorContains(t, err, "not a bearer token")
		assert.False(t, ran, "validator must not run before possession is proven")

		// A signature failure likewise short-circuits before the validator.
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, Timestamp: acctTS, Signature: "AAAA"})
		assert.Error(t, err)
		assert.False(t, ran)

		// With a valid signature the validator runs.
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, Timestamp: acctTS, Signature: acctSig})
		require.NoError(t, err)
		assert.True(t, ran)
	})

	t.Run("typed extension validator", func(t *testing.T) {
		extTok, err := IssueAccount(op, accountPub, WithName("acme"), WithExtension(domainClaims{Plan: "pro"}))
		require.NoError(t, err)
		extUserTok, err := IssueUser(account, userPub, WithName("alice"), WithExtension(domainClaims{Plan: "basic"}))
		require.NoError(t, err)
		ts, sig, err := SignRequest(user, time.Now(), nil)
		require.NoError(t, err)

		var gotAcct, gotUser domainClaims
		v := NewVerifier(opPub, AllowAll{}, WithClaimsValidator(
			ExtValidator(func(_ Request, _ *Identity, acct, user domainClaims) error {
				gotAcct, gotUser = acct, user
				return nil
			}),
		))
		_, err = v.VerifyRequest(Request{AccountToken: extTok, UserToken: extUserTok, Timestamp: ts, Signature: sig})
		require.NoError(t, err)
		assert.Equal(t, "pro", gotAcct.Plan)
		assert.Equal(t, "basic", gotUser.Plan)
	})
}

// brokenExt collides with domainClaims' shape check: its name matches a
// payload minted as a bare string, which cannot decode into a struct.
type stringExt string

func (stringExt) ExtensionName() string { return "acme.example" }

func TestExtensionTypeRegistration(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)

	t.Run("well-formed extension passes", func(t *testing.T) {
		tok, err := IssueAccount(op, accountPub, WithName("acme"), WithExtension(domainClaims{Plan: "pro"}))
		require.NoError(t, err)
		ts, sig, err := SignRequest(account, time.Now(), nil)
		require.NoError(t, err)
		v := NewVerifier(opPub, AllowAll{}, WithExtensionType[domainClaims]())
		_, err = v.VerifyRequest(Request{AccountToken: tok, Timestamp: ts, Signature: sig})
		assert.NoError(t, err)
	})

	t.Run("malformed extension rejected at auth time", func(t *testing.T) {
		// Mint the payload as a string under the same name; decoding it into
		// the registered struct type must fail.
		tok, err := IssueAccount(op, accountPub, WithName("acme"), WithExtension(stringExt("not-a-struct")))
		require.NoError(t, err)
		ts, sig, err := SignRequest(account, time.Now(), nil)
		require.NoError(t, err)
		v := NewVerifier(opPub, AllowAll{}, WithExtensionType[domainClaims]())
		_, err = v.VerifyRequest(Request{AccountToken: tok, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, `decode extension "acme.example"`)
	})

	t.Run("absent extension is not required", func(t *testing.T) {
		tok, err := IssueAccount(op, accountPub, WithName("acme"))
		require.NoError(t, err)
		ts, sig, err := SignRequest(account, time.Now(), nil)
		require.NoError(t, err)
		v := NewVerifier(opPub, AllowAll{}, WithExtensionType[domainClaims]())
		_, err = v.VerifyRequest(Request{AccountToken: tok, Timestamp: ts, Signature: sig})
		assert.NoError(t, err)
	})
}

func TestValidityWindow(t *testing.T) {
	op, opPub := issuerKeys(t)
	tenant, tenantPub := tenantKeys(t)

	t.Run("token without expiry never expires", func(t *testing.T) {
		tok, err := IssueAccount(op, tenantPub, WithName("acme"))
		require.NoError(t, err)
		claims, err := VerifyAccount(tok, opPub)
		require.NoError(t, err)
		assert.True(t, claims.ExpiresAt.IsZero())

		future := time.Now().Add(100 * 365 * 24 * time.Hour)
		ts, sig, err := SignRequest(tenant, future, nil)
		require.NoError(t, err)
		farFuture := NewVerifier(opPub, AllowAll{}, WithClock(func() time.Time { return future }))
		_, err = farFuture.VerifyRequest(Request{AccountToken: tok, Timestamp: ts, Signature: sig})
		assert.NoError(t, err)
	})

	t.Run("not-before gates the token", func(t *testing.T) {
		start := time.Now().Add(time.Hour)
		tok, err := IssueAccount(op, tenantPub, WithName("acme"), WithTTL(2*time.Hour), WithNotBefore(start))
		require.NoError(t, err)

		now := time.Now()
		ts, sig, err := SignRequest(tenant, now, nil)
		require.NoError(t, err)
		early := NewVerifier(opPub, AllowAll{}, WithSkew(0), WithClock(func() time.Time { return now }))
		_, err = early.VerifyRequest(Request{AccountToken: tok, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "not yet valid")

		later := start.Add(time.Minute)
		ts, sig, err = SignRequest(tenant, later, nil)
		require.NoError(t, err)
		inWindow := NewVerifier(opPub, AllowAll{}, WithSkew(0), WithClock(func() time.Time { return later }))
		_, err = inWindow.VerifyRequest(Request{AccountToken: tok, Timestamp: ts, Signature: sig})
		assert.NoError(t, err)
	})

	t.Run("user token not-before gates the chain", func(t *testing.T) {
		account, accountPub := tenantKeys(t)
		_, userPub := userKeys(t)
		acctTok, err := IssueAccount(op, accountPub, WithName("acme"), WithTTL(time.Hour))
		require.NoError(t, err)
		userTok, err := IssueUser(account, userPub, WithName("carol"), WithBearer(), WithNotBefore(time.Now().Add(time.Hour)))
		require.NoError(t, err)
		v := NewVerifier(opPub, AllowAll{}, WithSkew(0))
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, UserToken: userTok})
		assert.ErrorContains(t, err, "user token not yet valid")
	})
}

func TestReplayCache(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	acctTok, err := IssueAccount(op, accountPub, WithName("acme"), WithTTL(time.Hour))
	require.NoError(t, err)

	signed := func(nonce string) Request {
		ctx := []byte("op\n" + nonce)
		ts, sig, err := SignRequest(account, time.Now(), ctx)
		require.NoError(t, err)
		return Request{AccountToken: acctTok, Timestamp: ts, Signature: sig, Context: ctx, Nonce: nonce}
	}

	t.Run("first use passes, replay rejected", func(t *testing.T) {
		v := NewVerifier(opPub, AllowAll{}, WithReplayCache(NewMemoryReplayCache()))
		req := signed(NewNonce())
		_, err := v.VerifyRequest(req)
		require.NoError(t, err)
		_, err = v.VerifyRequest(req)
		assert.ErrorContains(t, err, "replay")
	})

	t.Run("distinct nonces both pass", func(t *testing.T) {
		v := NewVerifier(opPub, AllowAll{}, WithReplayCache(NewMemoryReplayCache()))
		_, err := v.VerifyRequest(signed(NewNonce()))
		require.NoError(t, err)
		_, err = v.VerifyRequest(signed(NewNonce()))
		assert.NoError(t, err)
	})

	t.Run("missing nonce rejected when a cache is configured", func(t *testing.T) {
		v := NewVerifier(opPub, AllowAll{}, WithReplayCache(NewMemoryReplayCache()))
		ts, sig, err := SignRequest(account, time.Now(), nil)
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "nonce required")
	})

	t.Run("no cache ignores nonces", func(t *testing.T) {
		v := NewVerifier(opPub, AllowAll{})
		req := signed(NewNonce())
		_, err := v.VerifyRequest(req)
		require.NoError(t, err)
		_, err = v.VerifyRequest(req)
		assert.NoError(t, err, "without a cache the same request replays freely")
	})
}

func TestOperatorToken(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	user, userPub := userKeys(t)

	opTok, err := IssueOperator(op, WithEpoch(2))
	require.NoError(t, err)
	acctTok, err := IssueAccount(op, accountPub, WithName("acme"), WithEpoch(2), WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := IssueUser(account, userPub, WithName("alice"), WithEpoch(2), WithTTL(time.Hour))
	require.NoError(t, err)
	ts, sig, err := SignRequest(user, time.Now(), nil)
	require.NoError(t, err)
	acctTS, acctSig, err := SignRequest(account, time.Now(), nil)
	require.NoError(t, err)

	v := NewVerifier(opPub, AllowAll{}, WithOperatorToken(opTok))

	t.Run("matching epoch passes, both levels", func(t *testing.T) {
		_, err := v.VerifyRequest(Request{AccountToken: acctTok, UserToken: userTok, Timestamp: ts, Signature: sig})
		assert.NoError(t, err)
	})

	t.Run("stale account token rejected", func(t *testing.T) {
		old, err := IssueAccount(op, accountPub, WithName("acme"), WithEpoch(1), WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: old, Timestamp: acctTS, Signature: acctSig})
		assert.ErrorContains(t, err, "epoch 1, trust domain epoch 2")
	})

	t.Run("unstamped account token rejected", func(t *testing.T) {
		unstamped, err := IssueAccount(op, accountPub, WithName("acme"), WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: unstamped, Timestamp: acctTS, Signature: acctSig})
		assert.ErrorContains(t, err, "epoch 0, trust domain epoch 2")
	})

	t.Run("stale user token rejected even under a current account", func(t *testing.T) {
		oldUser, err := IssueUser(account, userPub, WithName("alice"), WithEpoch(1), WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, UserToken: oldUser, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "user token epoch 1")
	})

	t.Run("resolved account token is subject to the epoch too", func(t *testing.T) {
		old, err := IssueAccount(op, accountPub, WithName("acme"), WithEpoch(1), WithTTL(time.Hour))
		require.NoError(t, err)
		resolver, err := StaticAccountTokens(old)
		require.NoError(t, err)
		rv := NewVerifier(opPub, AllowAll{}, WithOperatorToken(opTok), WithAccountTokenResolver(resolver))
		_, err = rv.VerifyRequest(Request{UserToken: userTok, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "epoch 1, trust domain epoch 2")
	})

	t.Run("without an operator token epochs are ignored", func(t *testing.T) {
		lax := NewVerifier(opPub, AllowAll{})
		old, err := IssueAccount(op, accountPub, WithName("acme"), WithEpoch(1), WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = lax.VerifyRequest(Request{AccountToken: old, Timestamp: acctTS, Signature: acctSig})
		assert.NoError(t, err)
	})

	t.Run("expired operator token closes the domain", func(t *testing.T) {
		shortOp, err := IssueOperator(op, WithEpoch(2), WithTTL(time.Second))
		require.NoError(t, err)
		closed := NewVerifier(opPub, AllowAll{}, WithOperatorToken(shortOp), WithSkew(0),
			WithClock(func() time.Time { return time.Now().Add(time.Hour) }))
		_, err = closed.VerifyRequest(Request{AccountToken: acctTok, Timestamp: acctTS, Signature: acctSig})
		assert.ErrorContains(t, err, "trust domain is closed")
	})

	t.Run("operator token not yet valid closes the domain until activation", func(t *testing.T) {
		futureOp, err := IssueOperator(op, WithEpoch(2), WithNotBefore(time.Now().Add(time.Hour)))
		require.NoError(t, err)
		early := NewVerifier(opPub, AllowAll{}, WithOperatorToken(futureOp), WithSkew(0))
		_, err = early.VerifyRequest(Request{AccountToken: acctTok, Timestamp: acctTS, Signature: acctSig})
		assert.ErrorContains(t, err, "operator token not yet valid")

		longAcct, err := IssueAccount(op, accountPub, WithName("acme"), WithEpoch(2), WithTTL(3*time.Hour))
		require.NoError(t, err)
		activeAt := time.Now().Add(2 * time.Hour)
		lateTS, lateSig, err := SignRequest(account, activeAt, nil)
		require.NoError(t, err)
		active := NewVerifier(opPub, AllowAll{}, WithOperatorToken(futureOp), WithSkew(0),
			WithClock(func() time.Time { return activeAt }))
		_, err = active.VerifyRequest(Request{AccountToken: longAcct, Timestamp: lateTS, Signature: lateSig})
		assert.NoError(t, err, "domain opens once the operator token activates")
	})

	t.Run("foreign operator token poisons the verifier", func(t *testing.T) {
		other, _ := issuerKeys(t)
		foreign, err := IssueOperator(other, WithEpoch(2))
		require.NoError(t, err)
		bad := NewVerifier(opPub, AllowAll{}, WithOperatorToken(foreign))
		_, err = bad.VerifyRequest(Request{AccountToken: acctTok, Timestamp: acctTS, Signature: acctSig})
		assert.ErrorContains(t, err, "operator token misconfigured")
	})

	t.Run("account token rejected as operator token", func(t *testing.T) {
		bad := NewVerifier(opPub, AllowAll{}, WithOperatorToken(acctTok))
		_, err := bad.VerifyRequest(Request{AccountToken: acctTok, Timestamp: acctTS, Signature: acctSig})
		assert.ErrorContains(t, err, "misconfigured")
	})
}

func TestIssueOperator(t *testing.T) {
	op, opPub := issuerKeys(t)

	tok, err := IssueOperator(op, WithName("prod-us"), WithEpoch(7), WithTTL(time.Hour))
	require.NoError(t, err)
	claims, err := VerifyOperator(tok, opPub)
	require.NoError(t, err)
	assert.Equal(t, opPub, claims.Subject)
	assert.Equal(t, opPub, claims.Issuer)
	assert.Equal(t, "prod-us", claims.Name)
	assert.Equal(t, uint64(7), claims.Epoch)
	assert.False(t, claims.ExpiresAt.IsZero())

	t.Run("name falls back to the operator key", func(t *testing.T) {
		unnamed, err := IssueOperator(op)
		require.NoError(t, err)
		c, err := VerifyOperator(unnamed, opPub)
		require.NoError(t, err)
		assert.Equal(t, opPub, c.Name)
	})

	t.Run("non-operator signer rejected", func(t *testing.T) {
		account, _ := tenantKeys(t)
		_, err := IssueOperator(account)
		assert.ErrorContains(t, err, "operator-type nkey")
	})

	t.Run("bearer rejected", func(t *testing.T) {
		_, err := IssueOperator(op, WithBearer())
		assert.ErrorContains(t, err, "bearer applies only to user tokens")
	})

	t.Run("wrong pinned key rejected", func(t *testing.T) {
		_, otherPub := issuerKeys(t)
		_, err := VerifyOperator(tok, otherPub)
		assert.ErrorContains(t, err, "not self-signed by the expected operator")
	})

	t.Run("operator token is not an account token", func(t *testing.T) {
		_, err := VerifyAccount(tok, opPub)
		assert.ErrorContains(t, err, "not an account token")
	})
}

func TestAccountTokenResolver(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	user, userPub := userKeys(t)

	acctTok, err := IssueAccount(op, accountPub, WithName("acme"), WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := IssueUser(account, userPub, WithName("alice"), WithTTL(time.Hour))
	require.NoError(t, err)
	ts, sig, err := SignRequest(user, time.Now(), nil)
	require.NoError(t, err)

	resolver, err := StaticAccountTokens(acctTok)
	require.NoError(t, err)

	t.Run("user-only credential resolves the account token", func(t *testing.T) {
		v := NewVerifier(opPub, AllowAll{}, WithAccountTokenResolver(resolver))
		id, err := v.VerifyRequest(Request{UserToken: userTok, Timestamp: ts, Signature: sig})
		require.NoError(t, err)
		assert.Equal(t, "acme", id.Account.Name)
		require.NotNil(t, id.User)
		assert.Equal(t, "alice", id.User.Name)
	})

	t.Run("no resolver rejects user-only credentials", func(t *testing.T) {
		v := NewVerifier(opPub, AllowAll{})
		_, err := v.VerifyRequest(Request{UserToken: userTok, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "no account token resolver")
	})

	t.Run("unknown account rejected", func(t *testing.T) {
		other, _ := tenantKeys(t)
		foreignUserTok, err := IssueUser(other, userPub, WithName("mallory"), WithTTL(time.Hour))
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

func TestVerifyRequestChain(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	user, userPub := userKeys(t)

	acctTok, err := IssueAccount(op, accountPub, WithName("acme"), WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := IssueUser(account, userPub, WithName("alice"), WithTTL(time.Hour))
	require.NoError(t, err)

	v := NewVerifier(opPub, AllowAll{})
	ts, sig, err := SignRequest(user, time.Now(), nil)
	require.NoError(t, err)

	t.Run("valid chain authenticates the user", func(t *testing.T) {
		id, err := v.VerifyRequest(Request{AccountToken: acctTok, UserToken: userTok, Timestamp: ts, Signature: sig})
		require.NoError(t, err)
		assert.Equal(t, "acme", id.Account.Name)
		assert.Equal(t, accountPub, id.Account.Subject)
		require.NotNil(t, id.User)
		assert.Equal(t, "alice", id.User.Name)
		assert.Equal(t, userPub, id.User.Subject)
	})

	t.Run("account signature does not pass for a chain request", func(t *testing.T) {
		acctTS, acctSig, err := SignRequest(account, time.Now(), nil)
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, UserToken: userTok, Timestamp: acctTS, Signature: acctSig})
		assert.ErrorContains(t, err, "signature verification failed")
	})

	t.Run("user token signed by a foreign account rejected", func(t *testing.T) {
		other, _ := tenantKeys(t)
		foreign, err := IssueUser(other, userPub, WithName("alice"), WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: acctTok, UserToken: foreign, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "expected account")
	})

	t.Run("expired user token rejected", func(t *testing.T) {
		short, err := IssueUser(account, userPub, WithName("alice"), WithTTL(time.Second))
		require.NoError(t, err)
		late := NewVerifier(opPub, AllowAll{}, WithClock(func() time.Time { return time.Now().Add(10 * time.Minute) }), WithSkew(0))
		_, err = late.VerifyRequest(Request{AccountToken: acctTok, UserToken: short})
		assert.ErrorContains(t, err, "user token expired")
	})

	t.Run("revoking the account token cuts off its users", func(t *testing.T) {
		strict := NewVerifier(opPub, NewStaticAllowlist("other"))
		_, err := strict.VerifyRequest(Request{AccountToken: acctTok, UserToken: userTok, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "not recognized")
	})
}

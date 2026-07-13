package valiss

import (
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// messageChainFixture is the full mint-side setup for message-token tests:
// operator, account, and user keys plus the chain tokens issued at epoch.
type messageChainFixture struct {
	op, account, user          nkeys.KeyPair
	opPub, accountPub, userPub string
	accountToken, userToken    string
}

func newMessageChain(t *testing.T, epoch uint64) messageChainFixture {
	t.Helper()
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	user, userPub := userKeys(t)
	acctTok, err := Issue(op, "acme", accountPub, WithEpoch(epoch), WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := IssueUser(account, "alice", userPub, WithEpoch(epoch), WithTTL(time.Hour))
	require.NoError(t, err)
	return messageChainFixture{
		op: op, account: account, user: user,
		opPub: opPub, accountPub: accountPub, userPub: userPub,
		accountToken: acctTok, userToken: userTok,
	}
}

func TestChecksum(t *testing.T) {
	// Known vector: SHA-256 of the empty string.
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Checksum(nil))
	assert.Len(t, Checksum([]byte("payload")), 64)
}

func TestIssueMessage(t *testing.T) {
	f := newMessageChain(t, 3)
	payload := []byte(`{"event":"widget.created"}`)

	tok, err := IssueMessage(f.user,
		WithAudience("https://receiver.example/hook"),
		WithChecksum(Checksum(payload)),
		WithTTL(30*time.Second),
		WithEpoch(3),
		WithChain(f.accountToken, f.userToken),
		WithExtension(domainClaims{Plan: "pro", Quota: 42}),
	)
	require.NoError(t, err)

	claims, err := VerifyMessage(tok, f.opPub)
	require.NoError(t, err)
	assert.Equal(t, "https://receiver.example/hook", claims.Audience)
	assert.Equal(t, Checksum(payload), claims.Checksum)
	assert.Equal(t, uint64(3), claims.Epoch)
	assert.Equal(t, f.userPub, claims.Subject)
	assert.Equal(t, f.userPub, claims.Issuer, "message tokens are self-signed")
	assert.False(t, claims.ExpiresAt.IsZero())
	require.NotNil(t, claims.Account)
	assert.Equal(t, "acme", claims.Account.Name)
	require.NotNil(t, claims.User)
	assert.Equal(t, "alice", claims.User.Name)
	got, ok, err := ExtOf[domainClaims](claims.Ext)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, domainClaims{Plan: "pro", Quota: 42}, got)

	t.Run("non-user signer rejected", func(t *testing.T) {
		_, err := IssueMessage(f.account, WithTTL(time.Minute))
		assert.ErrorContains(t, err, "user-type nkey (expected an SU... seed)")
		_, err = IssueMessage(f.op, WithTTL(time.Minute))
		assert.ErrorContains(t, err, "user-type nkey (expected an SU... seed)")
	})

	t.Run("bearer rejected", func(t *testing.T) {
		_, err := IssueMessage(f.user, WithTTL(time.Minute), WithBearer())
		assert.ErrorContains(t, err, "bearer applies only to user tokens")
	})

	t.Run("missing expiry rejected", func(t *testing.T) {
		_, err := IssueMessage(f.user, WithAudience("x"))
		assert.ErrorContains(t, err, "must carry an expiry")
	})

	t.Run("malformed checksum rejected", func(t *testing.T) {
		for _, sum := range []string{
			"abc",
			"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
			"zzb0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		} {
			_, err := IssueMessage(f.user, WithTTL(time.Minute), WithChecksum(sum))
			assert.ErrorContains(t, err, "lowercase-hex SHA-256", sum)
		}
	})

	t.Run("message options rejected by identity issuers", func(t *testing.T) {
		for _, opt := range []IssueOption{
			WithAudience("x"),
			WithChecksum(Checksum(nil)),
			WithChain(f.accountToken, f.userToken),
		} {
			_, err := Issue(f.op, "acme", f.accountPub, opt)
			assert.ErrorContains(t, err, "apply only to message tokens")
			_, err = IssueUser(f.account, "alice", f.userPub, opt)
			assert.ErrorContains(t, err, "apply only to message tokens")
			_, err = IssueOperator(f.op, opt)
			assert.ErrorContains(t, err, "apply only to message tokens")
		}
	})

	t.Run("chain for another user rejected at mint", func(t *testing.T) {
		other, _ := userKeys(t)
		_, err := IssueMessage(other, WithTTL(time.Minute), WithChain(f.accountToken, f.userToken))
		assert.ErrorContains(t, err, "chain user token is not for the minting user key")
	})

	t.Run("garbage chain rejected at mint", func(t *testing.T) {
		_, err := IssueMessage(f.user, WithTTL(time.Minute), WithChain("garbage", f.userToken))
		assert.ErrorContains(t, err, "chain account token")
		_, err = IssueMessage(f.user, WithTTL(time.Minute), WithChain(f.accountToken, "garbage"))
		assert.ErrorContains(t, err, "chain user token")
	})
}

func TestVerifyMessageChain(t *testing.T) {
	f := newMessageChain(t, 0)

	embedded, err := IssueMessage(f.user, WithTTL(time.Minute), WithChain(f.accountToken, f.userToken))
	require.NoError(t, err)
	chainless, err := IssueMessage(f.user, WithTTL(time.Minute))
	require.NoError(t, err)

	t.Run("out-of-band chain verifies a chainless token", func(t *testing.T) {
		claims, err := VerifyMessage(chainless, f.opPub, WithChainTokens(f.accountToken, f.userToken))
		require.NoError(t, err)
		assert.Equal(t, "acme", claims.Account.Name)
	})

	t.Run("chainless token without supplied chain rejected", func(t *testing.T) {
		_, err := VerifyMessage(chainless, f.opPub)
		assert.ErrorContains(t, err, "carries no chain")
	})

	t.Run("embedded chain with matching supplied chain passes", func(t *testing.T) {
		_, err := VerifyMessage(embedded, f.opPub, WithChainTokens(f.accountToken, f.userToken))
		assert.NoError(t, err)
	})

	t.Run("embedded chain differing from supplied chain rejected", func(t *testing.T) {
		other := newMessageChain(t, 0)
		_, err := VerifyMessage(embedded, f.opPub, WithChainTokens(other.accountToken, other.userToken))
		assert.ErrorContains(t, err, "differs from the supplied chain")
	})

	t.Run("wrong operator key rejected", func(t *testing.T) {
		_, otherOpPub := issuerKeys(t)
		_, err := VerifyMessage(embedded, otherOpPub)
		assert.ErrorContains(t, err, "expected issuer")
	})

	t.Run("chain user key must match the message issuer", func(t *testing.T) {
		// A chain whose user token names a different user key than the one
		// that signed the message token.
		other, otherPub := userKeys(t)
		otherUserTok, err := IssueUser(f.account, "mallory", otherPub, WithTTL(time.Hour))
		require.NoError(t, err)
		tok, err := IssueMessage(other, WithTTL(time.Minute))
		require.NoError(t, err)
		_, err = VerifyMessage(tok, f.opPub, WithChainTokens(f.accountToken, f.userToken))
		assert.ErrorContains(t, err, "not signed by the chain's user key")
		_, err = VerifyMessage(tok, f.opPub, WithChainTokens(f.accountToken, otherUserTok))
		assert.NoError(t, err)
	})

	t.Run("tampered token rejected", func(t *testing.T) {
		_, err := VerifyMessage(embedded[:len(embedded)-2]+"xx", f.opPub)
		assert.Error(t, err)
	})

	t.Run("identity tokens are not message tokens", func(t *testing.T) {
		_, err := VerifyMessage(f.userToken, f.opPub)
		assert.ErrorContains(t, err, "not a message token")
	})
}

func TestVerifyMessageEpoch(t *testing.T) {
	f := newMessageChain(t, 2)

	t.Run("all levels agree without an operator token", func(t *testing.T) {
		tok, err := IssueMessage(f.user, WithTTL(time.Minute), WithEpoch(2), WithChain(f.accountToken, f.userToken))
		require.NoError(t, err)
		claims, err := VerifyMessage(tok, f.opPub)
		require.NoError(t, err)
		assert.Equal(t, uint64(2), claims.Epoch)
	})

	t.Run("message epoch differing from the chain rejected", func(t *testing.T) {
		tok, err := IssueMessage(f.user, WithTTL(time.Minute), WithEpoch(1), WithChain(f.accountToken, f.userToken))
		require.NoError(t, err)
		_, err = VerifyMessage(tok, f.opPub)
		assert.ErrorContains(t, err, "message token epoch 1, account token epoch 2")
	})

	t.Run("user token epoch differing rejected", func(t *testing.T) {
		staleUserTok, err := IssueUser(f.account, "alice", f.userPub, WithEpoch(1), WithTTL(time.Hour))
		require.NoError(t, err)
		tok, err := IssueMessage(f.user, WithTTL(time.Minute), WithEpoch(2), WithChain(f.accountToken, staleUserTok))
		require.NoError(t, err)
		_, err = VerifyMessage(tok, f.opPub)
		assert.ErrorContains(t, err, "message token epoch 2, user token epoch 1")
	})

	t.Run("operator policy enforces the domain epoch", func(t *testing.T) {
		tok, err := IssueMessage(f.user, WithTTL(time.Minute), WithEpoch(2), WithChain(f.accountToken, f.userToken))
		require.NoError(t, err)

		current, err := IssueOperator(f.op, WithEpoch(2))
		require.NoError(t, err)
		_, err = VerifyMessage(tok, f.opPub, WithOperatorPolicy(current))
		assert.NoError(t, err)

		bumped, err := IssueOperator(f.op, WithEpoch(3))
		require.NoError(t, err)
		_, err = VerifyMessage(tok, f.opPub, WithOperatorPolicy(bumped))
		assert.ErrorContains(t, err, "message token epoch 2, trust domain epoch 3")
	})

	t.Run("operator policy enforces the operator window at the instant", func(t *testing.T) {
		tok, err := IssueMessage(f.user, WithTTL(time.Minute), WithEpoch(2), WithChain(f.accountToken, f.userToken))
		require.NoError(t, err)
		opTok, err := IssueOperator(f.op, WithEpoch(2), WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = VerifyMessage(tok, f.opPub, WithOperatorPolicy(opTok),
			At(time.Now().Add(2*time.Hour)), WithMessageSkew(0))
		assert.ErrorContains(t, err, "trust domain is closed")
	})

	t.Run("operator token not self-signed poisons verification", func(t *testing.T) {
		tok, err := IssueMessage(f.user, WithTTL(time.Minute), WithEpoch(2), WithChain(f.accountToken, f.userToken))
		require.NoError(t, err)
		other := newMessageChain(t, 2)
		foreignOp, err := IssueOperator(other.op, WithEpoch(2))
		require.NoError(t, err)
		_, err = VerifyMessage(tok, f.opPub, WithOperatorPolicy(foreignOp))
		assert.ErrorContains(t, err, "not self-signed by the expected operator")
	})
}

func TestVerifyMessageWindows(t *testing.T) {
	f := newMessageChain(t, 0)
	now := time.Now()

	tok, err := IssueMessage(f.user, WithTTL(30*time.Second), WithChain(f.accountToken, f.userToken))
	require.NoError(t, err)

	t.Run("verifies at mint time and within skew slack after expiry", func(t *testing.T) {
		_, err := VerifyMessage(tok, f.opPub, At(now))
		assert.NoError(t, err)
		_, err = VerifyMessage(tok, f.opPub, At(now.Add(time.Minute)))
		assert.NoError(t, err, "expired by less than DefaultSkew passes")
	})

	t.Run("expired message token rejected", func(t *testing.T) {
		_, err := VerifyMessage(tok, f.opPub, At(now.Add(time.Minute)), WithMessageSkew(0))
		assert.ErrorContains(t, err, "message token expired")
	})

	t.Run("not-yet-valid message token rejected", func(t *testing.T) {
		later, err := IssueMessage(f.user, WithTTL(time.Hour),
			WithNotBefore(now.Add(30*time.Minute)), WithChain(f.accountToken, f.userToken))
		require.NoError(t, err)
		_, err = VerifyMessage(later, f.opPub, At(now), WithMessageSkew(0))
		assert.ErrorContains(t, err, "message token not yet valid")
		_, err = VerifyMessage(later, f.opPub, At(now.Add(31*time.Minute)), WithMessageSkew(0))
		assert.NoError(t, err)
	})

	t.Run("expired chain tokens rejected at the instant", func(t *testing.T) {
		_, err := VerifyMessage(tok, f.opPub, At(now.Add(2*time.Hour)), WithMessageSkew(0))
		assert.ErrorContains(t, err, "account token expired", "chain windows checked chain-first")
	})

	t.Run("expired user token rejected", func(t *testing.T) {
		shortUserTok, err := IssueUser(f.account, "alice", f.userPub, WithTTL(time.Minute))
		require.NoError(t, err)
		tok, err := IssueMessage(f.user, WithTTL(time.Hour), WithChain(f.accountToken, shortUserTok))
		require.NoError(t, err)
		_, err = VerifyMessage(tok, f.opPub, At(now.Add(30*time.Minute)), WithMessageSkew(0))
		assert.ErrorContains(t, err, "user token expired")
	})
}

func TestVerifyMessageBindings(t *testing.T) {
	f := newMessageChain(t, 0)
	payload := []byte(`{"event":"widget.created"}`)

	bound, err := IssueMessage(f.user, WithTTL(time.Minute),
		WithAudience("https://receiver.example/hook"),
		WithChecksum(Checksum(payload)),
		WithChain(f.accountToken, f.userToken))
	require.NoError(t, err)
	unbound, err := IssueMessage(f.user, WithTTL(time.Minute), WithChain(f.accountToken, f.userToken))
	require.NoError(t, err)

	t.Run("audience match passes, mismatch and absence fail", func(t *testing.T) {
		_, err := VerifyMessage(bound, f.opPub, ExpectAudience("https://receiver.example/hook"))
		assert.NoError(t, err)
		_, err = VerifyMessage(bound, f.opPub, ExpectAudience("https://other.example/hook"))
		assert.ErrorContains(t, err, `expected "https://other.example/hook"`)
		_, err = VerifyMessage(unbound, f.opPub, ExpectAudience("https://receiver.example/hook"))
		assert.ErrorContains(t, err, "expected", "a token bound to no audience must not pass an audience check")
	})

	t.Run("payload match passes, tampered payload fails", func(t *testing.T) {
		_, err := VerifyMessage(bound, f.opPub, WithPayload(payload))
		assert.NoError(t, err)
		_, err = VerifyMessage(bound, f.opPub, WithPayload([]byte(`{"event":"widget.deleted"}`)))
		assert.ErrorContains(t, err, "payload checksum mismatch")
	})

	t.Run("checksum-less token fails WithPayload and RequireChecksum", func(t *testing.T) {
		_, err := VerifyMessage(unbound, f.opPub, WithPayload(payload))
		assert.ErrorContains(t, err, "carries no checksum")
		_, err = VerifyMessage(unbound, f.opPub, RequireChecksum())
		assert.ErrorContains(t, err, "carries no checksum")
	})

	t.Run("checksum claim passes through without enforcement options", func(t *testing.T) {
		claims, err := VerifyMessage(bound, f.opPub)
		require.NoError(t, err)
		assert.Equal(t, Checksum(payload), claims.Checksum)
	})
}

func TestMessageTokenIsNotACredential(t *testing.T) {
	f := newMessageChain(t, 0)
	tok, err := IssueMessage(f.user, WithTTL(time.Minute), WithChain(f.accountToken, f.userToken))
	require.NoError(t, err)

	t.Run("VerifyUser rejects a message token", func(t *testing.T) {
		_, err := VerifyUser(tok, f.accountPub)
		assert.ErrorContains(t, err, "not a user token")
	})

	t.Run("VerifyRequest rejects a message token as the user token", func(t *testing.T) {
		v := NewVerifier(f.opPub, AllowAll{})
		ts, sig, err := SignRequest(f.user, time.Now(), nil)
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{
			AccountToken: f.accountToken,
			UserToken:    tok,
			Timestamp:    ts,
			Signature:    sig,
		})
		assert.ErrorContains(t, err, "not a user token")
	})

	t.Run("Decode still inspects a message token", func(t *testing.T) {
		c, err := Decode(tok)
		require.NoError(t, err)
		assert.Equal(t, f.userPub, c.Subject)
		assert.Equal(t, f.userPub, c.Issuer)
	})
}

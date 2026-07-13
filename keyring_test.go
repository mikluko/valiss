package valiss

import (
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyring(t *testing.T) {
	opA, opAPub := issuerKeys(t)
	opB, opBPub := issuerKeys(t)

	tokA4, err := IssueOperator(opA, WithName("prod-us"), WithEpoch(4))
	require.NoError(t, err)
	tokA5, err := IssueOperator(opA, WithName("prod-us"), WithEpoch(5))
	require.NoError(t, err)
	tokB, err := IssueOperator(opB, WithName("on-prem"), WithEpoch(0))
	require.NoError(t, err)

	t.Run("entries select by key and epoch", func(t *testing.T) {
		k, err := NewKeyring(tokA4, tokA5, tokB)
		require.NoError(t, err)

		e, ok := k.lookup(opAPub, 4)
		require.True(t, ok)
		assert.Equal(t, "prod-us", e.Name)
		_, ok = k.lookup(opAPub, 5)
		assert.True(t, ok, "grace period: same key at two epochs")
		_, ok = k.lookup(opAPub, 6)
		assert.False(t, ok, "unregistered epoch")
		_, ok = k.lookup(opBPub, 0)
		assert.True(t, ok)
		_, ok = k.lookup("OUNKNOWN", 0)
		assert.False(t, ok)
	})

	t.Run("identical token collapses to one entry", func(t *testing.T) {
		k, err := NewKeyring(tokA4, tokA4)
		require.NoError(t, err)
		assert.Len(t, k.entries, 1)
	})

	t.Run("different token for an occupied key and epoch rejected", func(t *testing.T) {
		reissued, err := IssueOperator(opA, WithName("prod-us"), WithEpoch(4), WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = NewKeyring(tokA4, reissued)
		assert.ErrorContains(t, err, "duplicate entry for operator")
	})

	t.Run("two operators sharing a name rejected", func(t *testing.T) {
		impostor, err := IssueOperator(opB, WithName("prod-us"))
		require.NoError(t, err)
		_, err = NewKeyring(tokA4, impostor)
		assert.ErrorContains(t, err, `name "prod-us" already names a different operator`)
	})

	t.Run("one operator disagreeing on its name rejected", func(t *testing.T) {
		renamed, err := IssueOperator(opA, WithName("prod-eu"), WithEpoch(5))
		require.NoError(t, err)
		_, err = NewKeyring(tokA4, renamed)
		assert.ErrorContains(t, err, "entries disagree on name")
	})

	t.Run("unnamed operator represented by its key", func(t *testing.T) {
		op, opPub := issuerKeys(t)
		bare, err := IssueOperator(op)
		require.NoError(t, err)
		k, err := NewKeyring(bare)
		require.NoError(t, err)
		e, ok := k.lookup(opPub, 0)
		require.True(t, ok)
		assert.Equal(t, opPub, e.Name)
	})

	t.Run("empty keyring rejected", func(t *testing.T) {
		_, err := NewKeyring()
		assert.ErrorContains(t, err, "no operator tokens")
	})

	t.Run("garbage token rejected", func(t *testing.T) {
		_, err := NewKeyring("garbage")
		assert.ErrorContains(t, err, "operator token 0")
	})

	t.Run("non-operator token rejected", func(t *testing.T) {
		_, accountPub := tenantKeys(t)
		acctTok, err := IssueAccount(opA, accountPub, WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = NewKeyring(acctTok)
		assert.ErrorContains(t, err, "not an operator token")
	})
}

func TestVerifyMessageKeyring(t *testing.T) {
	// Two independent trust domains, both with a tenant named "acme".
	a := newMessageChainAt(t, "prod-us", 4)
	b := newMessageChainAt(t, "on-prem", 0)
	k, err := NewKeyring(a.operatorToken, b.operatorToken)
	require.NoError(t, err)

	mint := func(f keyringFixture) string {
		t.Helper()
		tok, err := IssueMessage(f.user, WithTTL(time.Minute), WithEpoch(f.epoch),
			WithChain(f.accountToken, f.userToken))
		require.NoError(t, err)
		return tok
	}

	t.Run("chains from both domains verify and name their operator", func(t *testing.T) {
		ca, err := VerifyMessageKeyring(mint(a), k)
		require.NoError(t, err)
		require.NotNil(t, ca.Operator)
		assert.Equal(t, "prod-us", ca.Operator.Name)
		assert.Equal(t, "acme", ca.Account.Name)

		cb, err := VerifyMessageKeyring(mint(b), k)
		require.NoError(t, err)
		assert.Equal(t, "on-prem", cb.Operator.Name)
		assert.Equal(t, "acme", cb.Account.Name, "same tenant name, distinguished by Operator.Name")
	})

	t.Run("unknown operator rejected", func(t *testing.T) {
		c := newMessageChainAt(t, "stranger", 0)
		_, err := VerifyMessageKeyring(mint(c), k)
		assert.ErrorContains(t, err, "no trusted operator")
	})

	t.Run("known operator at unregistered epoch rejected", func(t *testing.T) {
		// Same operator key as a, chain re-minted at epoch 5, keyring only
		// holds epoch 4.
		next := a.reissueAt(t, 5)
		_, err := VerifyMessageKeyring(mint(next), k)
		assert.ErrorContains(t, err, "at epoch 5")
	})

	t.Run("grace period accepts both epochs, then the old entry closes", func(t *testing.T) {
		next := a.reissueAt(t, 5)
		graceful, err := NewKeyring(a.operatorToken, next.operatorToken)
		require.NoError(t, err)
		_, err = VerifyMessageKeyring(mint(a), graceful)
		assert.NoError(t, err, "old-epoch chain accepted during grace")
		_, err = VerifyMessageKeyring(mint(next), graceful)
		assert.NoError(t, err, "new-epoch chain accepted during grace")

		// A short-lived old-epoch entry closes the grace window on its own.
		bounded, err := IssueOperator(a.op, WithName(a.name), WithEpoch(a.epoch), WithTTL(time.Minute))
		require.NoError(t, err)
		closing, err := NewKeyring(bounded, next.operatorToken)
		require.NoError(t, err)
		_, err = VerifyMessageKeyring(mint(a), closing, At(time.Now().Add(time.Hour)), WithMessageSkew(0))
		assert.ErrorContains(t, err, "trust domain is closed")
	})

	t.Run("entry window enforced at the instant", func(t *testing.T) {
		bounded, err := IssueOperator(b.op, WithName(b.name), WithTTL(time.Minute))
		require.NoError(t, err)
		kb, err := NewKeyring(bounded)
		require.NoError(t, err)
		_, err = VerifyMessageKeyring(mint(b), kb)
		assert.NoError(t, err)
		_, err = VerifyMessageKeyring(mint(b), kb, At(time.Now().Add(time.Hour)), WithMessageSkew(0))
		assert.ErrorContains(t, err, "trust domain is closed")
	})

	t.Run("operator policy option rejected with a keyring", func(t *testing.T) {
		_, err := VerifyMessageKeyring(mint(a), k, WithOperatorPolicy(a.operatorToken))
		assert.ErrorContains(t, err, "keyring entries carry policy")
	})

	t.Run("single-anchor VerifyMessage exposes the policy operator", func(t *testing.T) {
		c, err := VerifyMessage(mint(a), a.opPub, WithOperatorPolicy(a.operatorToken))
		require.NoError(t, err)
		require.NotNil(t, c.Operator)
		assert.Equal(t, "prod-us", c.Operator.Name)

		plain, err := VerifyMessage(mint(a), a.opPub)
		require.NoError(t, err)
		assert.Nil(t, plain.Operator, "no policy, no operator claims")
	})
}

func TestKeyringVerifier(t *testing.T) {
	a := newMessageChainAt(t, "prod-us", 4)
	b := newMessageChainAt(t, "on-prem", 0)
	k, err := NewKeyring(a.operatorToken, b.operatorToken)
	require.NoError(t, err)
	v := NewKeyringVerifier(k, AllowAll{})

	request := func(f keyringFixture) Request {
		t.Helper()
		ts, sig, err := SignRequest(f.user, time.Now(), nil)
		require.NoError(t, err)
		return Request{AccountToken: f.accountToken, UserToken: f.userToken, Timestamp: ts, Signature: sig}
	}

	t.Run("credentials from both domains authenticate and name their operator", func(t *testing.T) {
		ida, err := v.VerifyRequest(request(a))
		require.NoError(t, err)
		require.NotNil(t, ida.Operator)
		assert.Equal(t, "prod-us", ida.Operator.Name)
		assert.Equal(t, "acme", ida.Account.Name)
		assert.Equal(t, "alice", ida.User.Name)

		idb, err := v.VerifyRequest(request(b))
		require.NoError(t, err)
		assert.Equal(t, "on-prem", idb.Operator.Name)
		assert.Equal(t, "acme", idb.Account.Name, "same tenant name, distinguished by Operator.Name")
	})

	t.Run("unknown operator rejected", func(t *testing.T) {
		c := newMessageChainAt(t, "stranger", 0)
		_, err := v.VerifyRequest(request(c))
		assert.ErrorContains(t, err, "no trusted operator")
	})

	t.Run("known operator at unregistered epoch rejected", func(t *testing.T) {
		next := a.reissueAt(t, 5)
		_, err := v.VerifyRequest(request(next))
		assert.ErrorContains(t, err, "at epoch 5")
	})

	t.Run("grace period accepts both epochs", func(t *testing.T) {
		next := a.reissueAt(t, 5)
		graceful := NewKeyringVerifier(mustKeyring(t, a.operatorToken, next.operatorToken), AllowAll{})
		_, err := graceful.VerifyRequest(request(a))
		assert.NoError(t, err)
		_, err = graceful.VerifyRequest(request(next))
		assert.NoError(t, err)
	})

	t.Run("entry window enforced", func(t *testing.T) {
		bounded, err := IssueOperator(b.op, WithName(b.name), WithTTL(time.Minute))
		require.NoError(t, err)
		later := time.Now().Add(time.Hour)
		vb := NewKeyringVerifier(mustKeyring(t, bounded), AllowAll{},
			WithClock(func() time.Time { return later }), WithSkew(0))
		ts, sig, err := SignRequest(b.user, later, nil)
		require.NoError(t, err)
		_, err = vb.VerifyRequest(Request{AccountToken: b.accountToken, UserToken: b.userToken, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "trust domain is closed")
	})

	t.Run("user token epoch must echo the entry", func(t *testing.T) {
		userPub, err := a.user.PublicKey()
		require.NoError(t, err)
		stale, err := IssueUser(a.account, userPub, WithName("alice"), WithEpoch(3), WithTTL(time.Hour))
		require.NoError(t, err)
		ts, sig, err := SignRequest(a.user, time.Now(), nil)
		require.NoError(t, err)
		_, err = v.VerifyRequest(Request{AccountToken: a.accountToken, UserToken: stale, Timestamp: ts, Signature: sig})
		assert.ErrorContains(t, err, "user token epoch 3, trust domain epoch 4")
	})

	t.Run("operator token option rejected with a keyring", func(t *testing.T) {
		poisoned := NewKeyringVerifier(k, AllowAll{}, WithOperatorToken(a.operatorToken))
		_, err := poisoned.VerifyRequest(request(a))
		assert.ErrorContains(t, err, "keyring entries carry policy")
	})

	t.Run("allowlist is shared across domains", func(t *testing.T) {
		acctA, err := VerifyAccount(a.accountToken, a.opPub)
		require.NoError(t, err)
		strict := NewKeyringVerifier(k, NewStaticAllowlist(acctA.ID))
		_, err = strict.VerifyRequest(request(a))
		assert.NoError(t, err)
		_, err = strict.VerifyRequest(request(b))
		assert.ErrorContains(t, err, "not recognized")
	})

	t.Run("user-token-only requests resolve through the keyring", func(t *testing.T) {
		resolver, err := StaticAccountTokens(a.accountToken, b.accountToken)
		require.NoError(t, err)
		vr := NewKeyringVerifier(k, AllowAll{}, WithAccountTokenResolver(resolver))
		ts, sig, err := SignRequest(a.user, time.Now(), nil)
		require.NoError(t, err)
		id, err := vr.VerifyRequest(Request{UserToken: a.userToken, Timestamp: ts, Signature: sig})
		require.NoError(t, err)
		assert.Equal(t, "prod-us", id.Operator.Name)
	})

	t.Run("single-anchor verifier exposes the policy operator", func(t *testing.T) {
		single := NewVerifier(a.opPub, AllowAll{}, WithOperatorToken(a.operatorToken))
		id, err := single.VerifyRequest(request(a))
		require.NoError(t, err)
		require.NotNil(t, id.Operator)
		assert.Equal(t, "prod-us", id.Operator.Name)

		plain := NewVerifier(a.opPub, AllowAll{})
		id, err = plain.VerifyRequest(request(a))
		require.NoError(t, err)
		assert.Nil(t, id.Operator, "no policy, no operator claims")
	})
}

func mustKeyring(t *testing.T, tokens ...string) *Keyring {
	t.Helper()
	k, err := NewKeyring(tokens...)
	require.NoError(t, err)
	return k
}

// keyringFixture is a full trust domain: keys, chain tokens, and the
// operator token, all at one epoch.
type keyringFixture struct {
	op, account, user       nkeys.KeyPair
	opPub                   string
	name                    string
	epoch                   uint64
	operatorToken           string
	accountToken, userToken string
}

func newMessageChainAt(t *testing.T, name string, epoch uint64) keyringFixture {
	t.Helper()
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	user, userPub := userKeys(t)
	opTok, err := IssueOperator(op, WithName(name), WithEpoch(epoch))
	require.NoError(t, err)
	acctTok, err := IssueAccount(op, accountPub, WithName("acme"), WithEpoch(epoch), WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := IssueUser(account, userPub, WithName("alice"), WithEpoch(epoch), WithTTL(time.Hour))
	require.NoError(t, err)
	return keyringFixture{
		op: op, account: account, user: user, opPub: opPub, name: name, epoch: epoch,
		operatorToken: opTok, accountToken: acctTok, userToken: userTok,
	}
}

// reissueAt re-mints the fixture's operator token and chain at a new epoch,
// keeping the same keys and names: a domain rotation.
func (f keyringFixture) reissueAt(t *testing.T, epoch uint64) keyringFixture {
	t.Helper()
	accountPub, err := f.account.PublicKey()
	require.NoError(t, err)
	userPub, err := f.user.PublicKey()
	require.NoError(t, err)
	opTok, err := IssueOperator(f.op, WithName(f.name), WithEpoch(epoch))
	require.NoError(t, err)
	acctTok, err := IssueAccount(f.op, accountPub, WithName("acme"), WithEpoch(epoch), WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := IssueUser(f.account, userPub, WithName("alice"), WithEpoch(epoch), WithTTL(time.Hour))
	require.NoError(t, err)
	out := f
	out.epoch = epoch
	out.operatorToken = opTok
	out.accountToken = acctTok
	out.userToken = userTok
	return out
}

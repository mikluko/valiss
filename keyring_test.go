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

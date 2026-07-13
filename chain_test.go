package valiss

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrNoChain(t *testing.T) {
	f := newMessageChain(t, 0)
	tok, err := IssueMessage(f.user, WithTTL(time.Minute))
	require.NoError(t, err)
	_, err = VerifyMessage(tok, f.opPub)
	assert.ErrorIs(t, err, ErrNoChain)

	t.Run("other failures are not ErrNoChain", func(t *testing.T) {
		embedded, err := IssueMessage(f.user, WithTTL(time.Minute), WithChain(f.accountToken, f.userToken))
		require.NoError(t, err)
		_, err = VerifyMessage(embedded, f.opPub, ExpectAudience("elsewhere"))
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrNoChain))
	})
}

func TestMemoryChainCache(t *testing.T) {
	c := NewMemoryChainCache()

	_, _, ok := c.Get("absent")
	assert.False(t, ok)

	c.Put("U1", "acct-1", "user-1")
	acct, user, ok := c.Get("U1")
	assert.True(t, ok)
	assert.Equal(t, "acct-1", acct)
	assert.Equal(t, "user-1", user)

	t.Run("put overwrites", func(t *testing.T) {
		c.Put("U1", "acct-2", "user-2")
		acct, _, ok := c.Get("U1")
		assert.True(t, ok)
		assert.Equal(t, "acct-2", acct)
	})

	t.Run("del drops the entry", func(t *testing.T) {
		c.Del("U1")
		_, _, ok := c.Get("U1")
		assert.False(t, ok)
	})

	t.Run("cap bounds the cache", func(t *testing.T) {
		full := NewMemoryChainCache()
		for i := range memoryChainCacheCap + 10 {
			full.Put(fmt.Sprintf("U%d", i), "a", "u")
		}
		assert.LessOrEqual(t, len(full.entries), memoryChainCacheCap)
	})
}

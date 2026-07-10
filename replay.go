package valiss

import (
	"sync"
	"time"
)

// MemoryReplayCache is an in-memory ReplayCache that retains each nonce until
// its expiry and prunes lazily. It is process-local: for exactly-once across
// multiple server instances, back WithReplayCache with shared storage
// instead. Safe for concurrent use.
type MemoryReplayCache struct {
	now func() time.Time
	mu  sync.Mutex
	m   map[string]time.Time
}

// NewMemoryReplayCache returns an empty in-memory replay cache.
func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{now: time.Now, m: make(map[string]time.Time)}
}

// SeenBefore records nonce with the given expiry and reports whether a
// still-valid entry was already present.
func (c *MemoryReplayCache) SeenBefore(nonce string, expiry time.Time) bool {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.m {
		if !exp.After(now) {
			delete(c.m, k)
		}
	}
	if exp, ok := c.m[nonce]; ok && exp.After(now) {
		return true
	}
	c.m[nonce] = expiry
	return false
}

var _ ReplayCache = (*MemoryReplayCache)(nil)

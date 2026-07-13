package valiss

import "sync"

// ChainCache stores verified provenance chains keyed by the emitter's user
// public key, serving the receiving side of chain negotiation: an emitter
// sends chainless message tokens, the receiver caches the chain from the
// one retransmit that carried it, and every later message verifies against
// the cached copy. Implementations must be safe for concurrent use and may
// be backed by memory or shared storage. Store only chains that survived a
// full VerifyMessage, so the cache never holds material an attacker could
// plant.
type ChainCache interface {
	// Get returns the cached chain tokens for an emitter's user public key.
	Get(userPubKey string) (accountToken, userToken string, ok bool)
	// Put stores the chain tokens for an emitter's user public key.
	Put(userPubKey, accountToken, userToken string)
	// Del drops the entry, e.g. when verification against it fails after a
	// domain rotation.
	Del(userPubKey string)
}

// memoryChainCacheCap bounds MemoryChainCache; when full, an arbitrary
// entry is evicted. An evicted emitter just re-negotiates its chain.
const memoryChainCacheCap = 1024

// MemoryChainCache is a process-local ChainCache. For fewer warmup
// round-trips across multiple receiver instances, back ChainCache with
// shared storage instead.
type MemoryChainCache struct {
	mu      sync.RWMutex
	entries map[string]chainEntry
}

type chainEntry struct {
	accountToken string
	userToken    string
}

func NewMemoryChainCache() *MemoryChainCache {
	return &MemoryChainCache{entries: make(map[string]chainEntry)}
}

func (c *MemoryChainCache) Get(userPubKey string) (string, string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[userPubKey]
	return e.accountToken, e.userToken, ok
}

func (c *MemoryChainCache) Put(userPubKey, accountToken, userToken string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[userPubKey]; !exists && len(c.entries) >= memoryChainCacheCap {
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[userPubKey] = chainEntry{accountToken: accountToken, userToken: userToken}
}

func (c *MemoryChainCache) Del(userPubKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, userPubKey)
}

var _ ChainCache = (*MemoryChainCache)(nil)

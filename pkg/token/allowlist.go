package token

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Allowlist decides whether an issued token (by jti) is still accepted. Only
// tokens the issuer explicitly deposited server-side pass, so a token can
// be revoked by removing it even before expiry.
type Allowlist interface {
	Allowed(jti string) bool
}

// StaticAllowlist is an in-memory set of accepted token IDs.
type StaticAllowlist struct {
	mu  sync.RWMutex
	ids map[string]struct{}
}

func NewStaticAllowlist(ids ...string) *StaticAllowlist {
	a := &StaticAllowlist{ids: make(map[string]struct{}, len(ids))}
	for _, id := range ids {
		a.ids[id] = struct{}{}
	}
	return a
}

func (a *StaticAllowlist) Allowed(jti string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.ids[jti]
	return ok
}

// Set replaces the accepted set, e.g. after reloading the file.
func (a *StaticAllowlist) Set(ids []string) {
	next := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		next[id] = struct{}{}
	}
	a.mu.Lock()
	a.ids = next
	a.mu.Unlock()
}

// LoadAllowlistFile reads a newline-delimited allowlist file of token IDs.
// Blank lines and lines beginning with '#' are ignored.
func LoadAllowlistFile(path string) (*StaticAllowlist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("valiss: open allowlist: %w", err)
	}
	defer f.Close()

	var ids []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ids = append(ids, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("valiss: read allowlist: %w", err)
	}
	return NewStaticAllowlist(ids...), nil
}

// AllowAll accepts every token; for local development where no allowlist is
// configured. The token signature and expiry still gate access.
type AllowAll struct{}

func (AllowAll) Allowed(string) bool { return true }

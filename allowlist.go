package valiss

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

// FloorList is an optional capability an Allowlist may also provide: a
// per-entity generation floor keyed by the entity's public key. A Verifier
// under WithGenerationFloors reads floors from its allowlist when the allowlist
// implements this interface, keeping the allowlist the single artifact a server
// consumes for both per-jti revocation and wholesale generation floors.
//
// Floor reports the floor set for entity and whether one exists; an entity with
// no floor imposes no constraint. A floor of N rejects a stamped token from
// that entity whose generation is below N, turning a key rotation or removal
// into one floor bump instead of an enumeration over every affected jti.
type FloorList interface {
	Floor(entity string) (gen uint64, ok bool)
}

// StaticAllowlist is an in-memory set of accepted token IDs, optionally
// carrying per-entity generation floors (FloorList).
type StaticAllowlist struct {
	mu     sync.RWMutex
	ids    map[string]struct{}
	floors map[string]uint64
}

func NewStaticAllowlist(ids ...string) *StaticAllowlist {
	a := &StaticAllowlist{
		ids:    make(map[string]struct{}, len(ids)),
		floors: make(map[string]uint64),
	}
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

// SetFloor sets the generation floor for an entity (its public key): a stamped
// token from that entity whose generation is below gen is rejected by a
// verifier enforcing floors. Setting a floor of 0 clears the constraint, since
// no generation is below 0.
func (a *StaticAllowlist) SetFloor(entity string, gen uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if gen == 0 {
		delete(a.floors, entity)
		return
	}
	a.floors[entity] = gen
}

// SetFloors replaces the whole floor set, e.g. after reloading the allowlist
// artifact. Entries with a zero floor are dropped.
func (a *StaticAllowlist) SetFloors(floors map[string]uint64) {
	next := make(map[string]uint64, len(floors))
	for entity, gen := range floors {
		if gen != 0 {
			next[entity] = gen
		}
	}
	a.mu.Lock()
	a.floors = next
	a.mu.Unlock()
}

// Floor reports the generation floor set for entity, satisfying FloorList.
func (a *StaticAllowlist) Floor(entity string) (uint64, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	gen, ok := a.floors[entity]
	return gen, ok
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

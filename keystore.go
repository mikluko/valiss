package tokenator

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nats-io/nkeys"
)

// Keystore persists the operator key and per-tenant keys on disk, so an
// operator can manage tenants across invocations (nsc-style). Layout:
//
//	<dir>/operator.seed          the operator key (trust anchor)
//	<dir>/tenants/<id>.seed      per-tenant keys
//	<dir>/allowlist.txt          issued token ids the server accepts
type Keystore struct {
	dir string
}

// OpenKeystore roots a keystore at dir, creating it if absent.
func OpenKeystore(dir string) (*Keystore, error) {
	if err := os.MkdirAll(filepath.Join(dir, "tenants"), 0o700); err != nil {
		return nil, fmt.Errorf("tokenator: keystore: %w", err)
	}
	return &Keystore{dir: dir}, nil
}

func (k *Keystore) operatorPath() string { return filepath.Join(k.dir, "operator.seed") }
func (k *Keystore) tenantPath(id string) string {
	return filepath.Join(k.dir, "tenants", id+".seed")
}
func (k *Keystore) tokenPath(id string) string {
	return filepath.Join(k.dir, "tenants", id+".token")
}

// WriteToken stores the most recently issued token for a tenant.
func (k *Keystore) WriteToken(id, token string) error {
	return os.WriteFile(k.tokenPath(id), []byte(strings.TrimSpace(token)+"\n"), 0o600)
}

// Token returns the stored token for a tenant.
func (k *Keystore) Token(id string) (string, error) {
	raw, err := os.ReadFile(k.tokenPath(id))
	if err != nil {
		return "", fmt.Errorf("tokenator: no issued token for %q; run `tokenator issue %s`: %w", id, id, err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// AllowlistPath is the server-side allowlist file the operator maintains.
func (k *Keystore) AllowlistPath() string { return filepath.Join(k.dir, "allowlist.txt") }

// InitOperator creates the operator key if absent and returns it. Idempotent.
func (k *Keystore) InitOperator() (nkeys.KeyPair, error) {
	if kp, err := k.Operator(); err == nil {
		return kp, nil
	}
	kp, err := nkeys.CreateOperator()
	if err != nil {
		return nil, err
	}
	if err := writeSeed(k.operatorPath(), kp); err != nil {
		return nil, err
	}
	return kp, nil
}

// Operator loads the operator key.
func (k *Keystore) Operator() (nkeys.KeyPair, error) {
	return readSeed(k.operatorPath())
}

// CreateTenant generates and stores a tenant key, failing if one exists.
func (k *Keystore) CreateTenant(id string) (nkeys.KeyPair, error) {
	if _, err := os.Stat(k.tenantPath(id)); err == nil {
		return nil, fmt.Errorf("tokenator: tenant %q already exists", id)
	}
	kp, err := nkeys.CreateAccount()
	if err != nil {
		return nil, err
	}
	if err := writeSeed(k.tenantPath(id), kp); err != nil {
		return nil, err
	}
	return kp, nil
}

// Tenant loads a tenant key.
func (k *Keystore) Tenant(id string) (nkeys.KeyPair, error) {
	return readSeed(k.tenantPath(id))
}

// Tenants lists known tenant ids.
func (k *Keystore) Tenants() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(k.dir, "tenants"))
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".seed"); ok {
			ids = append(ids, name)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// AppendAllowlist adds a token id to the allowlist file.
func (k *Keystore) AppendAllowlist(jti string) error {
	f, err := os.OpenFile(k.AllowlistPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("tokenator: allowlist: %w", err)
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, jti)
	return err
}

func writeSeed(path string, kp nkeys.KeyPair) error {
	seed, err := kp.Seed()
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(seed, '\n'), 0o600)
}

func readSeed(path string) (nkeys.KeyPair, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return nkeys.FromSeed([]byte(strings.TrimSpace(string(raw))))
}

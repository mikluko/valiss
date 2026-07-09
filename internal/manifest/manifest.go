// Package manifest reads the valiss.yaml token manifest: the public,
// non-secret description of the credential tree (operator public keys,
// accounts with their public keys and scopes, users under each account).
// Seeds never appear here; the creds command resolves them from
// VALISS_SEED_<PUBKEY> environment variables.
package manifest

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nkeys"
	"gopkg.in/yaml.v3"

	"github.com/mikluko/valiss/pkg/token"
)

// Default TTLs for entries without an explicit ttl.
const (
	DefaultAccountTTL = 30 * 24 * time.Hour
	DefaultUserTTL    = time.Hour
)

// Duration is a time.Duration that unmarshals from YAML strings like "720h".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	dur, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("ttl: %w", err)
	}
	*d = Duration(dur)
	return nil
}

// User describes one end user under an account. A user entry either binds a
// key (present in the manifest or generated at mint time) or is an explicit
// bearer entry whose token-only credential cannot sign requests.
type User struct {
	// ID identifies the user within its account.
	ID string `yaml:"id"`
	// Key is the user's nkey public key; its seed must then be supplied via
	// VALISS_SEED_<key>. Absent means a fresh key pair is generated at mint
	// time. Mutually exclusive with Bearer.
	Key string `yaml:"key,omitempty"`
	// Bearer marks a keyless token-only user; the minted token grants the
	// bearer scope and the credential cannot sign requests.
	Bearer bool `yaml:"bearer,omitempty"`
	// Scopes granted to the user; each must be covered by the account's
	// scopes.
	Scopes []string `yaml:"scopes,omitempty"`
	// TTL is the user token time-to-live; DefaultUserTTL when omitted.
	TTL Duration `yaml:"ttl,omitempty"`
}

// TTLOrDefault returns the user's ttl, falling back to DefaultUserTTL.
func (u User) TTLOrDefault() time.Duration {
	if u.TTL == 0 {
		return DefaultUserTTL
	}
	return time.Duration(u.TTL)
}

// Account describes one tenant under an operator.
type Account struct {
	// ID is the tenant id the token binds; it segments all stored data.
	ID string `yaml:"id"`
	// Key is the account's nkey public key; its seed must then be supplied
	// via VALISS_SEED_<key>. Absent means a fresh key pair is generated at
	// mint time (such an account cannot have users minted against the
	// manifest, as the signing seed has no stable name).
	Key string `yaml:"key,omitempty"`
	// Scopes granted to the account, e.g. "call:/pkg.Svc/*".
	Scopes []string `yaml:"scopes,omitempty"`
	// TTL is the account token time-to-live; DefaultAccountTTL when omitted.
	TTL Duration `yaml:"ttl,omitempty"`
	// Users are the end users the account delegates access to.
	Users []User `yaml:"users,omitempty"`
}

// TTLOrDefault returns the account's ttl, falling back to DefaultAccountTTL.
func (a Account) TTLOrDefault() time.Duration {
	if a.TTL == 0 {
		return DefaultAccountTTL
	}
	return time.Duration(a.TTL)
}

// User returns the user entry with the given id.
func (a Account) User(id string) (User, bool) {
	for _, u := range a.Users {
		if u.ID == id {
			return u, true
		}
	}
	return User{}, false
}

// Operator is one trust domain: an operator public key and the accounts it
// issues.
type Operator struct {
	// Operator is the operator's nkey public key: the trust anchor servers
	// pin and the name of the VALISS_SEED_ variable holding the signing seed.
	Operator string    `yaml:"operator"`
	Accounts []Account `yaml:"accounts"`
}

// Manifest is the valiss.yaml document: a list of operator blocks.
type Manifest []Operator

// FindAccount resolves an account id across all operator blocks. It errors
// when the id is absent or appears under more than one operator.
func (m Manifest) FindAccount(id string) (Operator, Account, error) {
	var (
		found bool
		op    Operator
		acct  Account
	)
	for _, o := range m {
		for _, a := range o.Accounts {
			if a.ID != id {
				continue
			}
			if found {
				return Operator{}, Account{}, fmt.Errorf("account %q is ambiguous: defined under operators %s and %s", id, op.Operator, o.Operator)
			}
			found, op, acct = true, o, a
		}
	}
	if !found {
		return Operator{}, Account{}, fmt.Errorf("account %q not found in the manifest", id)
	}
	return op, acct, nil
}

// Load reads and validates a token manifest.
func Load(path string) (Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("%s: no operators defined", path)
	}
	for i, o := range m {
		if !nkeys.IsValidPublicOperatorKey(o.Operator) {
			return nil, fmt.Errorf("%s: operators[%d]: operator is not a valid operator public key (expected an O... nkey)", path, i)
		}
		if len(o.Accounts) == 0 {
			return nil, fmt.Errorf("%s: operator %s: no accounts defined", path, o.Operator)
		}
		seen := make(map[string]bool, len(o.Accounts))
		for j, a := range o.Accounts {
			if a.ID == "" {
				return nil, fmt.Errorf("%s: operator %s: accounts[%d]: id is required", path, o.Operator, j)
			}
			if seen[a.ID] {
				return nil, fmt.Errorf("%s: operator %s: duplicate account id %q", path, o.Operator, a.ID)
			}
			seen[a.ID] = true
			if err := validateAccount(a); err != nil {
				return nil, fmt.Errorf("%s: account %q: %w", path, a.ID, err)
			}
		}
	}
	return m, nil
}

func validateAccount(a Account) error {
	if a.Key != "" && !nkeys.IsValidPublicAccountKey(a.Key) {
		return fmt.Errorf("key is not a valid account public key (expected an A... nkey)")
	}
	seen := make(map[string]bool, len(a.Users))
	for i, u := range a.Users {
		if u.ID == "" {
			return fmt.Errorf("users[%d]: id is required", i)
		}
		if seen[u.ID] {
			return fmt.Errorf("duplicate user id %q", u.ID)
		}
		seen[u.ID] = true
		if u.Bearer && u.Key != "" {
			return fmt.Errorf("user %q: bearer and key are mutually exclusive", u.ID)
		}
		if u.Key != "" && !nkeys.IsValidPublicUserKey(u.Key) && !nkeys.IsValidPublicAccountKey(u.Key) {
			return fmt.Errorf("user %q: key is not a valid user public key", u.ID)
		}
		for _, s := range u.Scopes {
			if s == token.ScopeBearer {
				continue
			}
			if !token.Covered(a.Scopes, s) {
				return fmt.Errorf("user %q: scope %q is not covered by the account scopes", u.ID, s)
			}
		}
	}
	return nil
}

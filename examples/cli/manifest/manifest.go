// Package manifest reads the valiss.yaml token manifest: the public,
// non-secret description of the credential tree (operator public key,
// accounts with their public keys and scopes, users under each account).
// Seeds never appear here; the creds command resolves them from
// VALISS_SEED_<PUBKEY> environment variables.
//
// The manifest is deterministic: validity boundaries are absolute RFC3339
// timestamps (expires, not_before), so re-minting against the same manifest
// yields the same validity window. An entry without expires never expires,
// matching nsc's default.
package manifest

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nkeys"
	"gopkg.in/yaml.v3"

	"github.com/mikluko/valiss"
)

// User describes one end user under an account. A user entry either binds a
// key (present in the manifest or generated at mint time) or is an explicit
// bearer entry whose token-only credential cannot sign requests.
type User struct {
	// Name identifies the user within its account (the JWT name field; the
	// sub claim carries the key).
	Name string `yaml:"name"`
	// Key is the user's nkey public key; its seed must then be supplied via
	// VALISS_SEED_<key>. Absent means a fresh key pair is generated at mint
	// time. Mutually exclusive with Bearer.
	Key string `yaml:"key,omitempty"`
	// Bearer marks a token-only user: the server accepts its token without
	// per-request signatures and the creds carry no seed. A user without a
	// key gets a throwaway pair at mint time.
	Bearer bool `yaml:"bearer,omitempty"`
	// Scopes granted to the user; each must be covered by the account's
	// scopes.
	Scopes []string `yaml:"scopes,omitempty"`
	// Expires is the token expiry (the JWT exp claim), absolute RFC3339.
	// Absent means the token never expires.
	Expires time.Time `yaml:"expires,omitempty"`
	// NotBefore is the token activation time (the JWT nbf claim), absolute
	// RFC3339. Absent means immediately valid.
	NotBefore time.Time `yaml:"not_before,omitempty"`
}

// Account describes one tenant under an operator.
type Account struct {
	// Name is the tenant id the token binds (the JWT name field; the sub
	// claim carries the key); it segments all stored data.
	Name string `yaml:"name"`
	// Key is the account's nkey public key; its seed must then be supplied
	// via VALISS_SEED_<key>. Absent means a fresh key pair is generated at
	// mint time (such an account cannot have users minted against the
	// manifest, as the signing seed has no stable name).
	Key string `yaml:"key,omitempty"`
	// Scopes granted to the account, e.g. "call:/pkg.Svc/*".
	Scopes []string `yaml:"scopes,omitempty"`
	// Expires is the token expiry (the JWT exp claim), absolute RFC3339.
	// Absent means the token never expires.
	Expires time.Time `yaml:"expires,omitempty"`
	// NotBefore is the token activation time (the JWT nbf claim), absolute
	// RFC3339. Absent means immediately valid.
	NotBefore time.Time `yaml:"not_before,omitempty"`
	// Users are the end users the account delegates access to.
	Users []User `yaml:"users,omitempty"`
}

// User returns the user entry with the given name.
func (a Account) User(name string) (User, bool) {
	for _, u := range a.Users {
		if u.Name == name {
			return u, true
		}
	}
	return User{}, false
}

// Manifest is the valiss.yaml document: one trust domain, an operator public
// key and the accounts it issues.
type Manifest struct {
	// Operator is the operator's nkey public key: the trust anchor servers
	// pin and the name of the VALISS_SEED_ variable holding the signing seed.
	Operator string    `yaml:"operator"`
	Accounts []Account `yaml:"accounts"`
}

// FindAccount resolves an account name.
func (m *Manifest) FindAccount(name string) (Account, error) {
	for _, a := range m.Accounts {
		if a.Name == name {
			return a, nil
		}
	}
	return Account{}, fmt.Errorf("account %q not found in the manifest", name)
}

// Load reads and validates a token manifest.
func Load(path string) (*Manifest, error) {
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
	if !nkeys.IsValidPublicOperatorKey(m.Operator) {
		return nil, fmt.Errorf("%s: operator is not a valid operator public key (expected an O... nkey)", path)
	}
	if len(m.Accounts) == 0 {
		return nil, fmt.Errorf("%s: no accounts defined", path)
	}
	seen := make(map[string]bool, len(m.Accounts))
	for i, a := range m.Accounts {
		if a.Name == "" {
			return nil, fmt.Errorf("%s: accounts[%d]: name is required", path, i)
		}
		if seen[a.Name] {
			return nil, fmt.Errorf("%s: duplicate account name %q", path, a.Name)
		}
		seen[a.Name] = true
		if err := validateAccount(a); err != nil {
			return nil, fmt.Errorf("%s: account %q: %w", path, a.Name, err)
		}
	}
	return &m, nil
}

func validateAccount(a Account) error {
	if a.Key != "" && !nkeys.IsValidPublicAccountKey(a.Key) {
		return fmt.Errorf("key is not a valid account public key (expected an A... nkey)")
	}
	if err := validateWindow(a.Expires, a.NotBefore); err != nil {
		return err
	}
	seen := make(map[string]bool, len(a.Users))
	for i, u := range a.Users {
		if u.Name == "" {
			return fmt.Errorf("users[%d]: name is required", i)
		}
		if seen[u.Name] {
			return fmt.Errorf("duplicate user name %q", u.Name)
		}
		seen[u.Name] = true
		if u.Key != "" && !nkeys.IsValidPublicUserKey(u.Key) {
			return fmt.Errorf("user %q: key is not a valid user public key (expected a U... nkey)", u.Name)
		}
		if err := validateWindow(u.Expires, u.NotBefore); err != nil {
			return fmt.Errorf("user %q: %w", u.Name, err)
		}
		for _, s := range u.Scopes {
			if !valiss.Covered(a.Scopes, s) {
				return fmt.Errorf("user %q: scope %q is not covered by the account scopes", u.Name, s)
			}
		}
	}
	return nil
}

// validateWindow rejects a validity window that is empty on its face.
func validateWindow(expires, notBefore time.Time) error {
	if !expires.IsZero() && !notBefore.IsZero() && !expires.After(notBefore) {
		return fmt.Errorf("expires %s is not after not_before %s", expires.Format(time.RFC3339), notBefore.Format(time.RFC3339))
	}
	return nil
}

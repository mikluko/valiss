// Package manifest reads the valiss.yaml token manifest: the public,
// non-secret description of every token to issue (issuer public key, tenant
// ids and public keys, scopes, ttls). Seeds never appear here.
package manifest

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nkeys"
	"gopkg.in/yaml.v3"
)

// DefaultTTL applies to entries without an explicit ttl.
const DefaultTTL = 30 * 24 * time.Hour

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

// Entry describes one token to issue.
type Entry struct {
	// ID is the tenant id the token binds; it segments all stored data.
	ID string `yaml:"id"`
	// Key is the tenant's nkey public key that must sign requests.
	Key string `yaml:"key"`
	// Scopes granted to the tenant, e.g. "call:/pkg.Svc/*".
	Scopes []string `yaml:"scopes"`
	// TTL is the token time-to-live; DefaultTTL when omitted.
	TTL Duration `yaml:"ttl"`
}

// TTLOrDefault returns the entry's ttl, falling back to DefaultTTL.
func (e Entry) TTLOrDefault() time.Duration {
	if e.TTL == 0 {
		return DefaultTTL
	}
	return time.Duration(e.TTL)
}

// Manifest is the valiss.yaml document.
type Manifest struct {
	// Issuer is the issuer's nkey public key: the trust anchor the tokens
	// must be signed by. The issue command refuses seeds that do not match
	// it.
	Issuer string  `yaml:"issuer"`
	Tokens []Entry `yaml:"tokens"`
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
	if !nkeys.IsValidPublicOperatorKey(m.Issuer) {
		return nil, fmt.Errorf("%s: issuer is not a valid issuer public key (expected an O... operator-type nkey)", path)
	}
	if len(m.Tokens) == 0 {
		return nil, fmt.Errorf("%s: no tokens defined", path)
	}
	for i, e := range m.Tokens {
		if e.ID == "" {
			return nil, fmt.Errorf("%s: tokens[%d]: id is required", path, i)
		}
		if !nkeys.IsValidPublicAccountKey(e.Key) && !nkeys.IsValidPublicUserKey(e.Key) {
			return nil, fmt.Errorf("%s: tokens[%d] (%s): key is not a valid tenant public key", path, i, e.ID)
		}
	}
	return &m, nil
}

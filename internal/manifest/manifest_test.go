package manifest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tenantPub(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	pub, err := kp.PublicKey()
	require.NoError(t, err)
	return pub
}

func issuerPub(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateOperator()
	require.NoError(t, err)
	pub, err := kp.PublicKey()
	require.NoError(t, err)
	return pub
}

func write(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "valiss.yaml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestLoad(t *testing.T) {
	pub := tenantPub(t)
	opPub := issuerPub(t)
	m, err := Load(write(t, `
issuer: `+opPub+`
tokens:
  - id: acme
    key: `+pub+`
    scopes: ["call:/pkg.Svc/*", "call:/pkg.Other/M"]
    ttl: 168h
  - id: beta
    key: `+pub+`
`))
	require.NoError(t, err)
	assert.Equal(t, opPub, m.Issuer)
	require.Len(t, m.Tokens, 2)

	acme := m.Tokens[0]
	assert.Equal(t, "acme", acme.ID)
	assert.Equal(t, pub, acme.Key)
	assert.Equal(t, []string{"call:/pkg.Svc/*", "call:/pkg.Other/M"}, acme.Scopes)
	assert.Equal(t, 168*time.Hour, acme.TTLOrDefault())

	beta := m.Tokens[1]
	assert.Empty(t, beta.Scopes)
	assert.Equal(t, DefaultTTL, beta.TTLOrDefault())
}

func TestLoadRejects(t *testing.T) {
	pub := tenantPub(t)
	iss := "issuer: " + issuerPub(t) + "\n"

	t.Run("missing file", func(t *testing.T) {
		_, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
		assert.ErrorContains(t, err, "read manifest")
	})

	t.Run("missing issuer", func(t *testing.T) {
		_, err := Load(write(t, "tokens:\n  - id: acme\n    key: "+pub+"\n"))
		assert.ErrorContains(t, err, "issuer is not a valid")
	})

	t.Run("bad issuer", func(t *testing.T) {
		_, err := Load(write(t, "issuer: "+pub+"\ntokens:\n  - id: acme\n    key: "+pub+"\n"))
		assert.ErrorContains(t, err, "issuer is not a valid")
	})

	t.Run("no tokens", func(t *testing.T) {
		_, err := Load(write(t, iss+"tokens: []\n"))
		assert.ErrorContains(t, err, "no tokens")
	})

	t.Run("missing id", func(t *testing.T) {
		_, err := Load(write(t, iss+"tokens:\n  - key: "+pub+"\n"))
		assert.ErrorContains(t, err, "id is required")
	})

	t.Run("bad key", func(t *testing.T) {
		_, err := Load(write(t, iss+"tokens:\n  - id: acme\n    key: garbage\n"))
		assert.ErrorContains(t, err, "not a valid tenant public key")
	})

	t.Run("unknown field", func(t *testing.T) {
		_, err := Load(write(t, iss+"tokens:\n  - id: acme\n    key: "+pub+"\n    scope: [x]\n"))
		assert.ErrorContains(t, err, "field scope not found")
	})

	t.Run("bad ttl", func(t *testing.T) {
		_, err := Load(write(t, iss+"tokens:\n  - id: acme\n    key: "+pub+"\n    ttl: tomorrow\n"))
		assert.ErrorContains(t, err, "ttl")
	})
}

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

func pubKey(t *testing.T, create func() (nkeys.KeyPair, error)) string {
	t.Helper()
	kp, err := create()
	require.NoError(t, err)
	pub, err := kp.PublicKey()
	require.NoError(t, err)
	return pub
}

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "valiss.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestLoad(t *testing.T) {
	opPub := pubKey(t, nkeys.CreateOperator)
	acctPub := pubKey(t, nkeys.CreateAccount)
	userPub := pubKey(t, nkeys.CreateUser)

	m, err := Load(write(t, `
operator: `+opPub+`
accounts:
  - name: acme
    key: `+acctPub+`
    scopes: ["call:/svc/*"]
    expires: 2027-01-01T00:00:00Z
    users:
      - name: alice
        key: `+userPub+`
        scopes: ["call:/svc/Get"]
        expires: 2026-08-01T00:00:00Z
        not_before: 2026-07-01T00:00:00Z
      - name: carol
        bearer: true
        scopes: ["call:/svc/Get"]
  - name: globex
    scopes: ["call:*"]
`))
	require.NoError(t, err)
	assert.Equal(t, opPub, m.Operator)

	acct, err := m.FindAccount("acme")
	require.NoError(t, err)
	assert.Equal(t, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), acct.Expires.UTC())
	assert.True(t, acct.NotBefore.IsZero())

	alice, ok := acct.User("alice")
	require.True(t, ok)
	assert.Equal(t, userPub, alice.Key)
	assert.Equal(t, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), alice.NotBefore.UTC())

	carol, ok := acct.User("carol")
	require.True(t, ok)
	assert.True(t, carol.Bearer)
	assert.True(t, carol.Expires.IsZero(), "no expires means never expires")

	globex, err := m.FindAccount("globex")
	require.NoError(t, err)
	assert.Empty(t, globex.Key)
	assert.True(t, globex.Expires.IsZero())

	_, err = m.FindAccount("initech")
	assert.ErrorContains(t, err, "not found")
}

func TestLoadRejects(t *testing.T) {
	opPub := pubKey(t, nkeys.CreateOperator)
	acctPub := pubKey(t, nkeys.CreateAccount)
	userPub := pubKey(t, nkeys.CreateUser)

	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "empty document",
			yaml:    "{}",
			wantErr: "operator public key",
		},
		{
			name: "bad operator key",
			yaml: `
operator: not-a-key
accounts: [{name: acme}]`,
			wantErr: "operator public key",
		},
		{
			name: "operator without accounts",
			yaml: `
operator: ` + opPub,
			wantErr: "no accounts",
		},
		{
			name: "account without name",
			yaml: `
operator: ` + opPub + `
accounts: [{scopes: ["call:*"]}]`,
			wantErr: "name is required",
		},
		{
			name: "duplicate account name",
			yaml: `
operator: ` + opPub + `
accounts: [{name: acme}, {name: acme}]`,
			wantErr: "duplicate account name",
		},
		{
			name: "bad account key",
			yaml: `
operator: ` + opPub + `
accounts: [{name: acme, key: ` + userPub + `}]`,
			wantErr: "account public key",
		},
		{
			name: "relative ttl rejected",
			yaml: `
operator: ` + opPub + `
accounts: [{name: acme, expires: 720h}]`,
			wantErr: "parse",
		},
		{
			name: "string scopes rejected",
			yaml: `
operator: ` + opPub + `
accounts: [{name: acme, scopes: "call:*"}]`,
			wantErr: "parse",
		},
		{
			name: "unknown field rejected",
			yaml: `
operator: ` + opPub + `
accounts: [{name: acme, ttl: 720h}]`,
			wantErr: "parse",
		},
		{
			name: "empty validity window",
			yaml: `
operator: ` + opPub + `
accounts:
  - name: acme
    expires: 2026-01-01T00:00:00Z
    not_before: 2026-06-01T00:00:00Z`,
			wantErr: "not after",
		},
		{
			name: "account key rejected as user key",
			yaml: `
operator: ` + opPub + `
accounts:
  - name: acme
    key: ` + acctPub + `
    scopes: ["call:*"]
    users: [{name: alice, key: ` + acctPub + `}]`,
			wantErr: "user public key",
		},
		{
			name: "duplicate user name",
			yaml: `
operator: ` + opPub + `
accounts:
  - name: acme
    scopes: ["call:*"]
    users: [{name: alice, bearer: true}, {name: alice, bearer: true}]`,
			wantErr: "duplicate user name",
		},
		{
			name: "user scope beyond the account scopes",
			yaml: `
operator: ` + opPub + `
accounts:
  - name: acme
    key: ` + acctPub + `
    scopes: ["call:/svc/*"]
    users: [{name: alice, key: ` + userPub + `, scopes: ["call:/other/Get"]}]`,
			wantErr: "not covered",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(write(t, tt.yaml))
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

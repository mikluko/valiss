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
- operator: `+opPub+`
  accounts:
    - id: acme
      key: `+acctPub+`
      scopes: ["call:/svc/*"]
      ttl: 48h
      users:
        - id: alice
          key: `+userPub+`
          scopes: ["call:/svc/Get"]
        - id: carol
          bearer: true
          scopes: ["call:/svc/Get"]
    - id: globex
      scopes: ["call:*"]
`))
	require.NoError(t, err)
	require.Len(t, m, 1)

	op, acct, err := m.FindAccount("acme")
	require.NoError(t, err)
	assert.Equal(t, opPub, op.Operator)
	assert.Equal(t, 48*time.Hour, acct.TTLOrDefault())

	alice, ok := acct.User("alice")
	require.True(t, ok)
	assert.Equal(t, DefaultUserTTL, alice.TTLOrDefault())
	assert.Equal(t, userPub, alice.Key)

	carol, ok := acct.User("carol")
	require.True(t, ok)
	assert.True(t, carol.Bearer)
	assert.Empty(t, carol.Key)

	_, globex, err := m.FindAccount("globex")
	require.NoError(t, err)
	assert.Empty(t, globex.Key)
	assert.Equal(t, DefaultAccountTTL, globex.TTLOrDefault())

	_, _, err = m.FindAccount("initech")
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
			yaml:    "[]",
			wantErr: "no operators",
		},
		{
			name: "bad operator key",
			yaml: `
- operator: not-a-key
  accounts: [{id: acme}]`,
			wantErr: "operator public key",
		},
		{
			name: "operator without accounts",
			yaml: `
- operator: ` + opPub,
			wantErr: "no accounts",
		},
		{
			name: "account without id",
			yaml: `
- operator: ` + opPub + `
  accounts: [{scopes: ["call:*"]}]`,
			wantErr: "id is required",
		},
		{
			name: "duplicate account id",
			yaml: `
- operator: ` + opPub + `
  accounts: [{id: acme}, {id: acme}]`,
			wantErr: "duplicate account id",
		},
		{
			name: "bad account key",
			yaml: `
- operator: ` + opPub + `
  accounts: [{id: acme, key: ` + userPub + `}]`,
			wantErr: "account public key",
		},
		{
			name: "string scopes rejected",
			yaml: `
- operator: ` + opPub + `
  accounts: [{id: acme, scopes: "call:*"}]`,
			wantErr: "parse",
		},
		{
			name: "unknown field rejected",
			yaml: `
- operator: ` + opPub + `
  accounts: [{id: acme, sopes: ["call:*"]}]`,
			wantErr: "parse",
		},
		{
			name: "bearer and key mutually exclusive",
			yaml: `
- operator: ` + opPub + `
  accounts:
    - id: acme
      key: ` + acctPub + `
      scopes: ["call:*"]
      users: [{id: alice, key: ` + userPub + `, bearer: true}]`,
			wantErr: "mutually exclusive",
		},
		{
			name: "duplicate user id",
			yaml: `
- operator: ` + opPub + `
  accounts:
    - id: acme
      scopes: ["call:*"]
      users: [{id: alice, bearer: true}, {id: alice, bearer: true}]`,
			wantErr: "duplicate user id",
		},
		{
			name: "user scope beyond the account scopes",
			yaml: `
- operator: ` + opPub + `
  accounts:
    - id: acme
      key: ` + acctPub + `
      scopes: ["call:/svc/*"]
      users: [{id: alice, key: ` + userPub + `, scopes: ["call:/other/Get"]}]`,
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

func TestFindAccountAmbiguous(t *testing.T) {
	op1 := pubKey(t, nkeys.CreateOperator)
	op2 := pubKey(t, nkeys.CreateOperator)
	m, err := Load(write(t, `
- operator: `+op1+`
  accounts: [{id: acme}]
- operator: `+op2+`
  accounts: [{id: acme}]`))
	require.NoError(t, err)
	_, _, err = m.FindAccount("acme")
	assert.ErrorContains(t, err, "ambiguous")
}

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/mikluko/valiss/pkg/token"
)

// keygenPair runs cmdKeygen and parses its stdout back into a pair.
func keygenPair(t *testing.T, kind string) (pub, seed string) {
	t.Helper()
	var out, msg bytes.Buffer
	require.NoError(t, cmdKeygen(&out, &msg, []string{kind}))
	for line := range strings.SplitSeq(out.String(), "\n") {
		if v, ok := strings.CutPrefix(line, "public: "); ok {
			pub = v
		}
		if v, ok := strings.CutPrefix(line, "seed: "); ok {
			seed = v
		}
	}
	require.NotEmpty(t, pub)
	require.NotEmpty(t, seed)
	assert.NotEmpty(t, msg.String(), "handling guidance goes to the message stream")
	return pub, seed
}

func TestKeygen(t *testing.T) {
	opPub, opSeed := keygenPair(t, "issuer")
	assert.True(t, nkeys.IsValidPublicOperatorKey(opPub))
	kp, err := nkeys.FromSeed([]byte(opSeed))
	require.NoError(t, err)
	gotPub, err := kp.PublicKey()
	require.NoError(t, err)
	assert.Equal(t, opPub, gotPub, "seed and public key form a pair")

	tenPub, _ := keygenPair(t, "tenant")
	assert.True(t, nkeys.IsValidPublicAccountKey(tenPub))

	t.Run("unknown type", func(t *testing.T) {
		err := cmdKeygen(&bytes.Buffer{}, &bytes.Buffer{}, []string{"wizard"})
		assert.ErrorContains(t, err, "unknown key type")
	})
}

func TestIssue(t *testing.T) {
	opPub, opSeed := keygenPair(t, "issuer")
	tenPub, _ := keygenPair(t, "tenant")

	dir := t.TempDir()
	seedPath := filepath.Join(dir, "issuer.seed")
	require.NoError(t, os.WriteFile(seedPath, []byte(opSeed+"\n"), 0o600))
	cfgPath := filepath.Join(dir, "valiss.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
issuer: `+opPub+`
tokens:
  - id: acme
    key: `+tenPub+`
    scopes: ["call:/pkg.Svc/*"]
    ttl: 168h
  - id: beta
    key: `+tenPub+`
`), 0o600))

	var out bytes.Buffer
	require.NoError(t, cmdIssue(&out, []string{"-f", cfgPath, "-seed-file", seedPath}))

	var doc struct {
		Tokens []issuedToken `yaml:"tokens"`
	}
	require.NoError(t, yaml.Unmarshal(out.Bytes(), &doc))
	require.Len(t, doc.Tokens, 2)

	acme := doc.Tokens[0]
	assert.Equal(t, "acme", acme.ID)
	claims, err := token.Verify(acme.Token, opPub)
	require.NoError(t, err)
	assert.Equal(t, "acme", claims.TenantID)
	assert.Equal(t, tenPub, claims.PubKey)
	assert.Equal(t, acme.JTI, claims.ID, "output jti matches the token for the server allowlist")
	assert.True(t, claims.Authorizes("call:/pkg.Svc/M"))

	expires, err := time.Parse(time.RFC3339, acme.Expires)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(168*time.Hour), expires, time.Minute)

	t.Run("seed from env", func(t *testing.T) {
		t.Setenv("VALISS_ISSUER_SEED", opSeed)
		var out bytes.Buffer
		require.NoError(t, cmdIssue(&out, []string{"-f", cfgPath}))
		assert.Contains(t, out.String(), "id: acme")
	})

	t.Run("no seed", func(t *testing.T) {
		t.Setenv("VALISS_ISSUER_SEED", "")
		err := cmdIssue(&bytes.Buffer{}, []string{"-f", cfgPath})
		assert.ErrorContains(t, err, "issuer seed required")
	})

	t.Run("seed not matching manifest issuer", func(t *testing.T) {
		_, otherSeed := keygenPair(t, "issuer")
		t.Setenv("VALISS_ISSUER_SEED", otherSeed)
		err := cmdIssue(&bytes.Buffer{}, []string{"-f", cfgPath})
		assert.ErrorContains(t, err, "does not match the manifest issuer")
	})

	t.Run("tenant seed rejected as issuer", func(t *testing.T) {
		_, tenSeed := keygenPair(t, "tenant")
		t.Setenv("VALISS_ISSUER_SEED", tenSeed)
		err := cmdIssue(&bytes.Buffer{}, []string{"-f", cfgPath})
		assert.Error(t, err)
	})
}

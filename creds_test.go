package tokenator

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredsRoundTrip(t *testing.T) {
	ks, err := OpenKeystore(t.TempDir())
	require.NoError(t, err)
	op, err := ks.InitOperator()
	require.NoError(t, err)
	tenant, err := ks.CreateTenant("acme")
	require.NoError(t, err)
	pub, err := tenant.PublicKey()
	require.NoError(t, err)
	seed, err := tenant.Seed()
	require.NoError(t, err)

	token, err := Issue(op, "acme", pub, []string{"call:*"}, time.Hour)
	require.NoError(t, err)

	creds := FormatCreds(token, seed)
	gotToken, gotSeed, err := ParseCreds(creds)
	require.NoError(t, err)
	assert.Equal(t, token, gotToken)
	assert.Equal(t, string(seed), string(gotSeed))

	// The parsed creds authenticate a request end to end.
	c, err := NewCredentials(gotToken, gotSeed)
	require.NoError(t, err)
	md, err := c.GetRequestMetadata(t.Context())
	require.NoError(t, err)
	opPub, err := op.PublicKey()
	require.NoError(t, err)
	claims, err := Verify(md[MetadataToken], opPub)
	require.NoError(t, err)
	assert.NoError(t, VerifyRequest(claims.PubKey, md[MetadataTimestamp], md[MetadataSignature], time.Now(), DefaultSkew))
}

func TestKeystore(t *testing.T) {
	dir := t.TempDir()
	ks, err := OpenKeystore(dir)
	require.NoError(t, err)

	op1, err := ks.InitOperator()
	require.NoError(t, err)
	op2, err := ks.InitOperator()
	require.NoError(t, err)
	p1, _ := op1.PublicKey()
	p2, _ := op2.PublicKey()
	assert.Equal(t, p1, p2, "init is idempotent")

	_, err = ks.CreateTenant("acme")
	require.NoError(t, err)
	_, err = ks.CreateTenant("acme")
	assert.ErrorContains(t, err, "already exists")

	_, err = ks.CreateTenant("beta")
	require.NoError(t, err)
	ids, err := ks.Tenants()
	require.NoError(t, err)
	assert.Equal(t, []string{"acme", "beta"}, ids)

	require.NoError(t, ks.AppendAllowlist("jti-1"))
	require.NoError(t, ks.AppendAllowlist("jti-2"))
	al, err := LoadAllowlistFile(ks.AllowlistPath())
	require.NoError(t, err)
	assert.True(t, al.Allowed("jti-1"))
	assert.True(t, al.Allowed("jti-2"))

	assert.Equal(t, filepath.Join(dir, "allowlist.txt"), ks.AllowlistPath())
}

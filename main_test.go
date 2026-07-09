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

	"github.com/mikluko/valiss/pkg/creds"
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
	opPub, opSeed := keygenPair(t, "operator")
	assert.True(t, nkeys.IsValidPublicOperatorKey(opPub))
	kp, err := nkeys.FromSeed([]byte(opSeed))
	require.NoError(t, err)
	gotPub, err := kp.PublicKey()
	require.NoError(t, err)
	assert.Equal(t, opPub, gotPub, "seed and public key form a pair")

	acctPub, _ := keygenPair(t, "account")
	assert.True(t, nkeys.IsValidPublicAccountKey(acctPub))

	userPub, _ := keygenPair(t, "user")
	assert.True(t, nkeys.IsValidPublicUserKey(userPub))

	t.Run("unknown type", func(t *testing.T) {
		err := cmdKeygen(&bytes.Buffer{}, &bytes.Buffer{}, []string{"wizard"})
		assert.ErrorContains(t, err, "unknown key type")
	})
}

// fixture is a manifest with an operator, a keyed account with users, and a
// keyless account, alongside the generated seeds.
type fixture struct {
	cfgPath  string
	opPub    string
	opSeed   string
	acctPub  string
	acctSeed string
	userPub  string
	userSeed string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{}
	f.opPub, f.opSeed = keygenPair(t, "operator")
	f.acctPub, f.acctSeed = keygenPair(t, "account")
	f.userPub, f.userSeed = keygenPair(t, "user")
	f.cfgPath = filepath.Join(t.TempDir(), "valiss.yaml")
	require.NoError(t, os.WriteFile(f.cfgPath, []byte(`
operator: `+f.opPub+`
accounts:
  - id: acme
    key: `+f.acctPub+`
    scopes: ["call:/pkg.Svc/*"]
    ttl: 168h
    users:
      - id: alice
        key: `+f.userPub+`
        scopes: ["call:/pkg.Svc/Get"]
      - id: bob
        scopes: ["call:/pkg.Svc/Get"]
        ttl: 30m
      - id: carol
        bearer: true
        scopes: ["call:/pkg.Svc/Get"]
  - id: globex
    scopes: ["call:*"]
    users:
      - id: eve
        bearer: true
        scopes: ["call:*"]
`), 0o600))
	return f
}

func runCreds(t *testing.T, f fixture, path string) (creds.Bundle, credsMeta) {
	t.Helper()
	var out, msg bytes.Buffer
	require.NoError(t, cmdCreds(&out, &msg, []string{"-f", f.cfgPath, path}))
	bundle, err := creds.Parse(out.String())
	require.NoError(t, err)
	var meta credsMeta
	require.NoError(t, yaml.Unmarshal(msg.Bytes(), &meta))
	return bundle, meta
}

func TestCredsAccount(t *testing.T) {
	f := newFixture(t)
	t.Setenv("VALISS_SEED_"+f.opPub, f.opSeed)
	t.Setenv("VALISS_SEED_"+f.acctPub, f.acctSeed)

	bundle, meta := runCreds(t, f, "acme")
	assert.Empty(t, bundle.UserToken)
	assert.Equal(t, f.acctSeed, string(bundle.Seed), "bundle carries the env-provided account seed")

	claims, err := token.Verify(bundle.Token, f.opPub)
	require.NoError(t, err)
	assert.Equal(t, "acme", claims.TenantID)
	assert.Equal(t, f.acctPub, claims.PubKey)
	assert.True(t, claims.Authorizes("call:/pkg.Svc/M"))

	assert.Equal(t, claims.ID, meta.Account.JTI, "metadata jti matches the token for the server allowlist")
	assert.False(t, meta.Account.Generated)
	expires, err := time.Parse(time.RFC3339, meta.Account.Expires)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(168*time.Hour), expires, time.Minute)
	assert.Nil(t, meta.User)
}

func TestCredsGeneratedAccount(t *testing.T) {
	f := newFixture(t)
	t.Setenv("VALISS_SEED_"+f.opPub, f.opSeed)

	bundle, meta := runCreds(t, f, "globex")
	require.NotEmpty(t, bundle.Seed)
	kp, err := nkeys.FromSeed(bundle.Seed)
	require.NoError(t, err)
	pub, err := kp.PublicKey()
	require.NoError(t, err)

	claims, err := token.Verify(bundle.Token, f.opPub)
	require.NoError(t, err)
	assert.Equal(t, pub, claims.PubKey, "token binds the freshly generated key")
	assert.True(t, meta.Account.Generated)
	assert.Equal(t, pub, meta.Account.Key)

	t.Run("each invocation generates a fresh pair", func(t *testing.T) {
		again, _ := runCreds(t, f, "globex")
		assert.NotEqual(t, string(bundle.Seed), string(again.Seed))
	})
}

func TestCredsUser(t *testing.T) {
	f := newFixture(t)
	t.Setenv("VALISS_SEED_"+f.opPub, f.opSeed)
	t.Setenv("VALISS_SEED_"+f.acctPub, f.acctSeed)
	t.Setenv("VALISS_SEED_"+f.userPub, f.userSeed)

	bundle, meta := runCreds(t, f, "acme/alice")
	assert.Equal(t, f.userSeed, string(bundle.Seed))

	acct, err := token.Verify(bundle.Token, f.opPub)
	require.NoError(t, err)
	user, err := token.Verify(bundle.UserToken, f.acctPub)
	require.NoError(t, err)
	assert.Equal(t, "alice", user.TenantID)
	assert.Equal(t, f.userPub, user.PubKey)

	require.NotNil(t, meta.User)
	assert.Equal(t, acct.ID, meta.Account.JTI)
	assert.Equal(t, user.ID, meta.User.JTI)

	// The whole chain passes the verifier.
	v := token.NewVerifier(f.opPub, token.NewStaticAllowlist(acct.ID))
	kp, err := nkeys.FromSeed(bundle.Seed)
	require.NoError(t, err)
	ts, sig, err := token.SignRequest(kp, time.Now())
	require.NoError(t, err)
	claims, err := v.VerifyCredential(token.Credential{Token: bundle.Token, UserToken: bundle.UserToken, Timestamp: ts, Signature: sig})
	require.NoError(t, err)
	assert.Equal(t, "acme", claims.TenantID)
	assert.Equal(t, "alice", claims.UserID)
}

func TestCredsGeneratedUser(t *testing.T) {
	f := newFixture(t)
	t.Setenv("VALISS_SEED_"+f.opPub, f.opSeed)
	t.Setenv("VALISS_SEED_"+f.acctPub, f.acctSeed)

	bundle, meta := runCreds(t, f, "acme/bob")
	require.NotEmpty(t, bundle.Seed)
	assert.True(t, meta.User.Generated)

	user, err := token.Verify(bundle.UserToken, f.acctPub)
	require.NoError(t, err)
	kp, err := nkeys.FromSeed(bundle.Seed)
	require.NoError(t, err)
	pub, err := kp.PublicKey()
	require.NoError(t, err)
	assert.Equal(t, pub, user.PubKey)

	expires, err := time.Parse(time.RFC3339, meta.User.Expires)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(30*time.Minute), expires, time.Minute)
}

func TestCredsBearerUser(t *testing.T) {
	f := newFixture(t)
	t.Setenv("VALISS_SEED_"+f.opPub, f.opSeed)
	t.Setenv("VALISS_SEED_"+f.acctPub, f.acctSeed)

	bundle, meta := runCreds(t, f, "acme/carol")
	assert.Empty(t, bundle.Seed, "bearer bundle carries no seed")
	assert.Empty(t, meta.User.Key)

	user, err := token.Verify(bundle.UserToken, f.acctPub)
	require.NoError(t, err)
	assert.True(t, user.HasScope(token.ScopeBearer), "bearer scope is appended automatically")

	acct, err := token.Verify(bundle.Token, f.opPub)
	require.NoError(t, err)
	v := token.NewVerifier(f.opPub, token.NewStaticAllowlist(acct.ID))
	claims, err := v.VerifyCredential(token.Credential{Token: bundle.Token, UserToken: bundle.UserToken})
	require.NoError(t, err)
	assert.Equal(t, "carol", claims.UserID)
}

func TestCredsFailures(t *testing.T) {
	f := newFixture(t)

	run := func(path string) error {
		return cmdCreds(&bytes.Buffer{}, &bytes.Buffer{}, []string{"-f", f.cfgPath, path})
	}

	t.Run("missing operator seed names the variable", func(t *testing.T) {
		err := run("acme")
		assert.ErrorContains(t, err, "VALISS_SEED_"+f.opPub)
	})

	t.Run("missing subject seed names the variable", func(t *testing.T) {
		t.Setenv("VALISS_SEED_"+f.opPub, f.opSeed)
		err := run("acme")
		assert.ErrorContains(t, err, "VALISS_SEED_"+f.acctPub)
	})

	t.Run("seed not matching its variable rejected", func(t *testing.T) {
		_, otherSeed := keygenPair(t, "operator")
		t.Setenv("VALISS_SEED_"+f.opPub, otherSeed)
		err := run("acme")
		assert.ErrorContains(t, err, "derives")
	})

	t.Run("unknown account", func(t *testing.T) {
		t.Setenv("VALISS_SEED_"+f.opPub, f.opSeed)
		err := run("initech")
		assert.ErrorContains(t, err, "not found")
	})

	t.Run("unknown user", func(t *testing.T) {
		t.Setenv("VALISS_SEED_"+f.opPub, f.opSeed)
		err := run("acme/mallory")
		assert.ErrorContains(t, err, `user "mallory" not found`)
	})

	t.Run("user under a keyless account", func(t *testing.T) {
		t.Setenv("VALISS_SEED_"+f.opPub, f.opSeed)
		err := run("globex/eve")
		assert.ErrorContains(t, err, "has no key")
	})

	t.Run("bad entity path", func(t *testing.T) {
		assert.ErrorContains(t, run("acme/"), "bad entity path")
		assert.ErrorContains(t, run("/alice"), "bad entity path")
	})
}

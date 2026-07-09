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

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/creds"
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
	cfgPath     string
	opPub       string
	opSeed      string
	acctPub     string
	acctSeed    string
	userPub     string
	userSeed    string
	acctExpires time.Time
	bobExpires  time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{}
	f.opPub, f.opSeed = keygenPair(t, "operator")
	f.acctPub, f.acctSeed = keygenPair(t, "account")
	f.userPub, f.userSeed = keygenPair(t, "user")
	f.acctExpires = time.Now().Add(168 * time.Hour).UTC().Truncate(time.Second)
	f.bobExpires = time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	f.cfgPath = filepath.Join(t.TempDir(), "valiss.yaml")
	require.NoError(t, os.WriteFile(f.cfgPath, []byte(`
operator: `+f.opPub+`
accounts:
  - name: acme
    key: `+f.acctPub+`
    expires: `+f.acctExpires.Format(time.RFC3339)+`
    users:
      - name: alice
        key: `+f.userPub+`
      - name: bob
        expires: `+f.bobExpires.Format(time.RFC3339)+`
      - name: carol
        bearer: true
  - name: globex
    users:
      - name: eve
        bearer: true
`), 0o600))
	return f
}

func runCreds(t *testing.T, f fixture, path string, flags ...string) (creds.Creds, credsMeta) {
	t.Helper()
	var out, msg bytes.Buffer
	args := append([]string{"-f", f.cfgPath}, flags...)
	args = append(args, path)
	require.NoError(t, cmdCreds(&out, &msg, args))
	parsed, err := creds.Parse(out.String())
	require.NoError(t, err)
	var meta credsMeta
	require.NoError(t, yaml.Unmarshal(msg.Bytes(), &meta))
	return parsed, meta
}

func TestCredsAccount(t *testing.T) {
	f := newFixture(t)
	t.Setenv("VALISS_SEED_"+f.opPub, f.opSeed)
	t.Setenv("VALISS_SEED_"+f.acctPub, f.acctSeed)

	parsed, meta := runCreds(t, f, "acme")
	assert.Empty(t, parsed.UserToken)
	assert.Equal(t, f.acctSeed, string(parsed.Seed), "bundle carries the env-provided account seed")

	claims, err := valiss.VerifyAccount(parsed.AccountToken, f.opPub)
	require.NoError(t, err)
	assert.Equal(t, "acme", claims.Name)
	assert.Equal(t, f.acctPub, claims.Subject)

	assert.Equal(t, claims.ID, meta.Account.JTI, "metadata jti matches the token for the server allowlist")
	assert.False(t, meta.Account.Generated)
	expires, err := time.Parse(time.RFC3339, meta.Account.Expires)
	require.NoError(t, err)
	assert.True(t, expires.Equal(f.acctExpires), "expiry is exactly the manifest boundary: %s != %s", expires, f.acctExpires)
	assert.Nil(t, meta.User)
}

func TestCredsGeneratedAccount(t *testing.T) {
	f := newFixture(t)
	t.Setenv("VALISS_SEED_"+f.opPub, f.opSeed)

	parsed, meta := runCreds(t, f, "globex")
	require.NotEmpty(t, parsed.Seed)
	kp, err := nkeys.FromSeed(parsed.Seed)
	require.NoError(t, err)
	pub, err := kp.PublicKey()
	require.NoError(t, err)

	claims, err := valiss.VerifyAccount(parsed.AccountToken, f.opPub)
	require.NoError(t, err)
	assert.Equal(t, pub, claims.Subject, "token binds the freshly generated key")
	assert.True(t, meta.Account.Generated)
	assert.Equal(t, pub, meta.Account.Key)

	t.Run("each invocation generates a fresh pair", func(t *testing.T) {
		again, _ := runCreds(t, f, "globex")
		assert.NotEqual(t, string(parsed.Seed), string(again.Seed))
	})
}

func TestCredsUser(t *testing.T) {
	f := newFixture(t)
	// Only the account and user seeds: plain user creds carry no
	// account token and needs no operator seed.
	t.Setenv("VALISS_SEED_"+f.acctPub, f.acctSeed)
	t.Setenv("VALISS_SEED_"+f.userPub, f.userSeed)

	parsed, meta := runCreds(t, f, "acme/alice")
	assert.Equal(t, f.userSeed, string(parsed.Seed))
	assert.Empty(t, parsed.AccountToken, "account token omitted by default")

	user, err := valiss.VerifyUser(parsed.UserToken, f.acctPub)
	require.NoError(t, err)
	assert.Equal(t, "alice", user.Name)
	assert.Equal(t, f.userPub, user.Subject)

	assert.Nil(t, meta.Account)
	require.NotNil(t, meta.User)
	assert.Equal(t, user.ID, meta.User.JTI)

	// A server with the account token in static configuration accepts it.
	acctTok, err := valiss.Issue(mustKey(t, f.opSeed), "acme", f.acctPub, valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	acct, err := valiss.VerifyAccount(acctTok, f.opPub)
	require.NoError(t, err)
	resolver, err := valiss.StaticAccountTokens(acctTok)
	require.NoError(t, err)
	v := valiss.NewVerifier(f.opPub, valiss.NewStaticAllowlist(acct.ID), valiss.WithAccountTokenResolver(resolver))

	kp, err := nkeys.FromSeed(parsed.Seed)
	require.NoError(t, err)
	ts, sig, err := valiss.SignRequest(kp, time.Now())
	require.NoError(t, err)
	id, err := v.VerifyRequest(valiss.Request{UserToken: parsed.UserToken, Timestamp: ts, Signature: sig})
	require.NoError(t, err)
	assert.Equal(t, "acme", id.Account.Name)
	require.NotNil(t, id.User)
	assert.Equal(t, "alice", id.User.Name)
}

func TestCredsUserBundle(t *testing.T) {
	f := newFixture(t)
	t.Setenv("VALISS_SEED_"+f.opPub, f.opSeed)
	t.Setenv("VALISS_SEED_"+f.acctPub, f.acctSeed)
	t.Setenv("VALISS_SEED_"+f.userPub, f.userSeed)

	parsed, meta := runCreds(t, f, "acme/alice", "-bundle")
	assert.Equal(t, f.userSeed, string(parsed.Seed))

	acct, err := valiss.VerifyAccount(parsed.AccountToken, f.opPub)
	require.NoError(t, err)
	user, err := valiss.VerifyUser(parsed.UserToken, f.acctPub)
	require.NoError(t, err)

	require.NotNil(t, meta.Account)
	require.NotNil(t, meta.User)
	assert.Equal(t, acct.ID, meta.Account.JTI)
	assert.Equal(t, user.ID, meta.User.JTI)

	// The embedded chain passes the verifier without a resolver.
	v := valiss.NewVerifier(f.opPub, valiss.NewStaticAllowlist(acct.ID))
	kp, err := nkeys.FromSeed(parsed.Seed)
	require.NoError(t, err)
	ts, sig, err := valiss.SignRequest(kp, time.Now())
	require.NoError(t, err)
	id, err := v.VerifyRequest(valiss.Request{AccountToken: parsed.AccountToken, UserToken: parsed.UserToken, Timestamp: ts, Signature: sig})
	require.NoError(t, err)
	assert.Equal(t, "acme", id.Account.Name)
	require.NotNil(t, id.User)
	assert.Equal(t, "alice", id.User.Name)

	t.Run("requires the operator seed", func(t *testing.T) {
		t.Setenv("VALISS_SEED_"+f.opPub, "")
		err := cmdCreds(&bytes.Buffer{}, &bytes.Buffer{}, []string{"-f", f.cfgPath, "-bundle", "acme/alice"})
		assert.ErrorContains(t, err, "VALISS_SEED_"+f.opPub)
	})

	t.Run("rejected for account-level creds", func(t *testing.T) {
		err := cmdCreds(&bytes.Buffer{}, &bytes.Buffer{}, []string{"-f", f.cfgPath, "-bundle", "acme"})
		assert.ErrorContains(t, err, "applies only to user credentials")
	})
}

func mustKey(t *testing.T, seed string) nkeys.KeyPair {
	t.Helper()
	kp, err := nkeys.FromSeed([]byte(seed))
	require.NoError(t, err)
	return kp
}

func TestCredsGeneratedUser(t *testing.T) {
	f := newFixture(t)
	t.Setenv("VALISS_SEED_"+f.acctPub, f.acctSeed)

	parsed, meta := runCreds(t, f, "acme/bob")
	require.NotEmpty(t, parsed.Seed)
	assert.True(t, meta.User.Generated)

	user, err := valiss.VerifyUser(parsed.UserToken, f.acctPub)
	require.NoError(t, err)
	kp, err := nkeys.FromSeed(parsed.Seed)
	require.NoError(t, err)
	pub, err := kp.PublicKey()
	require.NoError(t, err)
	assert.Equal(t, pub, user.Subject)

	expires, err := time.Parse(time.RFC3339, meta.User.Expires)
	require.NoError(t, err)
	assert.True(t, expires.Equal(f.bobExpires), "expiry is exactly the manifest boundary")
}

func TestCredsBearerUser(t *testing.T) {
	f := newFixture(t)
	t.Setenv("VALISS_SEED_"+f.opPub, f.opSeed)
	t.Setenv("VALISS_SEED_"+f.acctPub, f.acctSeed)

	parsed, meta := runCreds(t, f, "acme/carol", "-bundle")
	assert.Empty(t, parsed.Seed, "bearer creds carry no seed even for a generated pair")
	assert.NotEmpty(t, meta.User.Key, "the throwaway key still names the token subject")
	assert.True(t, meta.User.Generated)

	user, err := valiss.VerifyUser(parsed.UserToken, f.acctPub)
	require.NoError(t, err)
	assert.True(t, user.Bearer, "bearer flag set on the token")

	acct, err := valiss.VerifyAccount(parsed.AccountToken, f.opPub)
	require.NoError(t, err)
	v := valiss.NewVerifier(f.opPub, valiss.NewStaticAllowlist(acct.ID))
	id, err := v.VerifyRequest(valiss.Request{AccountToken: parsed.AccountToken, UserToken: parsed.UserToken})
	require.NoError(t, err)
	require.NotNil(t, id.User)
	assert.Equal(t, "carol", id.User.Name)
	assert.True(t, id.User.Bearer)
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
	path := filepath.Join(t.TempDir(), "minter.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestManifestLoad(t *testing.T) {
	opPub := pubKey(t, nkeys.CreateOperator)
	acctPub := pubKey(t, nkeys.CreateAccount)
	userPub := pubKey(t, nkeys.CreateUser)

	m, err := loadManifest(write(t, `
operator: `+opPub+`
accounts:
  - name: acme
    key: `+acctPub+`
    expires: 2027-01-01T00:00:00Z
    users:
      - name: alice
        key: `+userPub+`
        expires: 2026-08-01T00:00:00Z
        not_before: 2026-07-01T00:00:00Z
      - name: carol
        bearer: true
  - name: globex
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

func TestManifestLoadRejects(t *testing.T) {
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
accounts: [{key: ` + acctPub + `}]`,
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
    users: [{name: alice, key: ` + acctPub + `}]`,
			wantErr: "user public key",
		},
		{
			name: "duplicate user name",
			yaml: `
operator: ` + opPub + `
accounts:
  - name: acme
    users: [{name: alice, bearer: true}, {name: alice, bearer: true}]`,
			wantErr: "duplicate user name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadManifest(write(t, tt.yaml))
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

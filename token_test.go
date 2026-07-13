package valiss

import (
	"os"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func issuerKeys(t *testing.T) (nkeys.KeyPair, string) {
	t.Helper()
	op, err := nkeys.CreateOperator()
	require.NoError(t, err)
	pub, err := op.PublicKey()
	require.NoError(t, err)
	return op, pub
}

func tenantKeys(t *testing.T) (nkeys.KeyPair, string) {
	t.Helper()
	tp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	pub, err := tp.PublicKey()
	require.NoError(t, err)
	return tp, pub
}

func userKeys(t *testing.T) (nkeys.KeyPair, string) {
	t.Helper()
	up, err := nkeys.CreateUser()
	require.NoError(t, err)
	pub, err := up.PublicKey()
	require.NoError(t, err)
	return up, pub
}

func TestIssueVerify(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub := tenantKeys(t)

	token, err := IssueAccount(op, tenantPub, WithName("acme"), WithTTL(time.Hour))
	require.NoError(t, err)

	claims, err := VerifyAccount(token, opPub)
	require.NoError(t, err)
	assert.Equal(t, "acme", claims.Name)
	assert.Equal(t, tenantPub, claims.Subject)
	assert.Equal(t, opPub, claims.Issuer)
	assert.NotEmpty(t, claims.ID)
	assert.False(t, claims.IssuedAt.IsZero())
	assert.False(t, claims.Expired(time.Now(), 0))

	t.Run("wrong issuer rejected", func(t *testing.T) {
		_, otherPub := issuerKeys(t)
		_, err := VerifyAccount(token, otherPub)
		assert.ErrorContains(t, err, "expected issuer")
	})

	t.Run("tampered token rejected", func(t *testing.T) {
		_, err := VerifyAccount(token[:len(token)-2]+"xx", opPub)
		assert.Error(t, err)
	})

	t.Run("non-operator-type signer rejected", func(t *testing.T) {
		account, _ := tenantKeys(t)
		_, err := IssueAccount(account, tenantPub, WithName("acme"), WithTTL(time.Hour))
		assert.ErrorContains(t, err, "operator-type nkey")
	})

	t.Run("expired", func(t *testing.T) {
		short, err := IssueAccount(op, tenantPub, WithName("acme"), WithTTL(time.Second))
		require.NoError(t, err)
		c, err := VerifyAccount(short, opPub)
		require.NoError(t, err)
		assert.True(t, c.Expired(c.ExpiresAt.Add(time.Minute), 0))
	})

	t.Run("account token is not a user token", func(t *testing.T) {
		_, err := VerifyUser(token, opPub)
		assert.ErrorContains(t, err, "not a user token")
	})

	t.Run("bearer option rejected", func(t *testing.T) {
		_, err := IssueAccount(op, tenantPub, WithName("acme"), WithBearer())
		assert.ErrorContains(t, err, "bearer applies only to user tokens")
	})

	t.Run("deprecated Issue alias still mints", func(t *testing.T) {
		tok, err := Issue(op, tenantPub, WithName("acme"), WithTTL(time.Hour))
		require.NoError(t, err)
		c, err := VerifyAccount(tok, opPub)
		require.NoError(t, err)
		assert.Equal(t, "acme", c.Name)
	})

	t.Run("name falls back to the subject key", func(t *testing.T) {
		unnamed, err := IssueAccount(op, tenantPub)
		require.NoError(t, err)
		c, err := VerifyAccount(unnamed, opPub)
		require.NoError(t, err)
		assert.Equal(t, tenantPub, c.Name)
	})
}

func TestIssueUser(t *testing.T) {
	account, accountPub := tenantKeys(t)
	_, userPub := userKeys(t)

	tok, err := IssueUser(account, userPub, WithName("alice"), WithTTL(time.Hour))
	require.NoError(t, err)
	claims, err := VerifyUser(tok, accountPub)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims.Name)
	assert.Equal(t, userPub, claims.Subject)
	assert.False(t, claims.Bearer)

	t.Run("non-account-type signer rejected", func(t *testing.T) {
		op, _ := issuerKeys(t)
		_, err := IssueUser(op, userPub, WithName("alice"), WithTTL(time.Hour))
		assert.ErrorContains(t, err, "account-type nkey")
	})

	t.Run("keyless rejected", func(t *testing.T) {
		_, err := IssueUser(account, "", WithName("carol"), WithTTL(time.Hour))
		assert.ErrorContains(t, err, "invalid user public key")
	})

	t.Run("bearer flag round-trips", func(t *testing.T) {
		tok, err := IssueUser(account, userPub, WithName("carol"), WithBearer(), WithTTL(time.Hour))
		require.NoError(t, err)
		claims, err := VerifyUser(tok, accountPub)
		require.NoError(t, err)
		assert.True(t, claims.Bearer)
	})

	t.Run("user token is not an account token", func(t *testing.T) {
		_, err := VerifyAccount(tok, accountPub)
		assert.ErrorContains(t, err, "not an account token")
	})

	t.Run("account key rejected as user key", func(t *testing.T) {
		_, otherAcctPub := tenantKeys(t)
		_, err := IssueUser(account, otherAcctPub, WithName("alice"), WithTTL(time.Hour))
		assert.ErrorContains(t, err, "invalid user public key")
	})
}

// domainClaims is a consumer-defined extension used across the tests.
type domainClaims struct {
	Plan  string `json:"plan"`
	Quota int    `json:"quota"`
}

func (domainClaims) ExtensionName() string { return "acme.example" }

// otherExt exercises multiple extensions on one token.
type otherExt struct {
	K string `json:"k"`
}

func (otherExt) ExtensionName() string { return "other" }

// unnamedExt has an empty name and must be rejected at issue.
type unnamedExt struct{}

func (unnamedExt) ExtensionName() string { return "" }

// clashingExt shares domainClaims' name to trigger the duplicate error.
type clashingExt struct{}

func (clashingExt) ExtensionName() string { return "acme.example" }

func TestExtension(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub := tenantKeys(t)

	tok, err := IssueAccount(op, tenantPub,
		WithName("acme"),
		WithExtension(domainClaims{Plan: "pro", Quota: 42}),
		WithExtension(otherExt{K: "v"}),
	)
	require.NoError(t, err)
	claims, err := VerifyAccount(tok, opPub)
	require.NoError(t, err)

	got, ok, err := ExtOf[domainClaims](claims.Ext)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, domainClaims{Plan: "pro", Quota: 42}, got)

	other, ok, err := ExtOf[otherExt](claims.Ext)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, otherExt{K: "v"}, other)

	t.Run("absent extension decodes to zero value", func(t *testing.T) {
		plain, err := IssueAccount(op, tenantPub, WithName("acme"))
		require.NoError(t, err)
		claims, err := VerifyAccount(plain, opPub)
		require.NoError(t, err)
		got, ok, err := ExtOf[domainClaims](claims.Ext)
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Zero(t, got)
	})

	t.Run("duplicate extension name rejected", func(t *testing.T) {
		_, err := IssueAccount(op, tenantPub, WithName("acme"),
			WithExtension(domainClaims{}), WithExtension(clashingExt{}))
		assert.ErrorContains(t, err, `duplicate extension "acme.example"`)
	})

	t.Run("empty extension name rejected", func(t *testing.T) {
		_, err := IssueAccount(op, tenantPub, WithName("acme"), WithExtension(unnamedExt{}))
		assert.ErrorContains(t, err, "name must not be empty")
	})
}

func TestDecode(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	_, userPub := userKeys(t)

	acctTok, err := IssueAccount(op, accountPub, WithName("acme"), WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := IssueUser(account, userPub, WithName("alice"), WithBearer())
	require.NoError(t, err)

	acct, err := Decode(acctTok)
	require.NoError(t, err)
	assert.Equal(t, opPub, acct.Issuer)
	assert.Equal(t, accountPub, acct.Subject)
	assert.NotEmpty(t, acct.ID)
	assert.False(t, acct.ExpiresAt.IsZero())

	user, err := Decode(userTok)
	require.NoError(t, err)
	assert.Equal(t, accountPub, user.Issuer)
	assert.Equal(t, userPub, user.Subject)
	assert.True(t, user.ExpiresAt.IsZero(), "no expiry set")
}

func TestSignVerifyRequest(t *testing.T) {
	tenant, tenantPub := tenantKeys(t)
	now := time.Now()
	ctx := []byte("GET\napi.example.com\n/v1/widgets")

	ts, sig, err := SignRequest(tenant, now, ctx)
	require.NoError(t, err)
	assert.NoError(t, VerifySignature(tenantPub, ts, sig, ctx, now, DefaultSkew))

	t.Run("outside skew window", func(t *testing.T) {
		err := VerifySignature(tenantPub, ts, sig, ctx, now.Add(5*time.Minute), DefaultSkew)
		assert.ErrorContains(t, err, "skew window")
	})

	t.Run("wrong key", func(t *testing.T) {
		_, otherPub := tenantKeys(t)
		err := VerifySignature(otherPub, ts, sig, ctx, now, DefaultSkew)
		assert.ErrorContains(t, err, "signature verification failed")
	})

	t.Run("tampered timestamp breaks signature", func(t *testing.T) {
		other := now.Add(30 * time.Second)
		err := VerifySignature(tenantPub, other.UTC().Format(time.RFC3339Nano), sig, ctx, other, DefaultSkew)
		assert.ErrorContains(t, err, "signature verification failed")
	})

	t.Run("different request context breaks signature", func(t *testing.T) {
		other := []byte("POST\napi.example.com\n/v1/widgets")
		err := VerifySignature(tenantPub, ts, sig, other, now, DefaultSkew)
		assert.ErrorContains(t, err, "signature verification failed",
			"a signature must not authorize a different request")
	})

	t.Run("nil context binds only the timestamp", func(t *testing.T) {
		ts, sig, err := SignRequest(tenant, now, nil)
		require.NoError(t, err)
		assert.NoError(t, VerifySignature(tenantPub, ts, sig, nil, now, DefaultSkew))
	})
}

func TestAllowlist(t *testing.T) {
	a := NewStaticAllowlist("jti-1", "jti-2")
	assert.True(t, a.Allowed("jti-1"))
	assert.False(t, a.Allowed("jti-3"))
	a.Set([]string{"jti-3"})
	assert.False(t, a.Allowed("jti-1"))
	assert.True(t, a.Allowed("jti-3"))
	assert.True(t, AllowAll{}.Allowed("anything"))
}

func TestLoadAllowlistFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/allowlist.txt"
	require.NoError(t, os.WriteFile(path, []byte("# tenants\njti-1\n\njti-2\n"), 0o600))
	a, err := LoadAllowlistFile(path)
	require.NoError(t, err)
	assert.True(t, a.Allowed("jti-1"))
	assert.True(t, a.Allowed("jti-2"))
	assert.False(t, a.Allowed("# tenants"))
}

func TestCovered(t *testing.T) {
	svcAll := []string{"/example.v1.WidgetService/*"}
	assert.True(t, Covered(svcAll, "/example.v1.WidgetService/GetWidget"))
	assert.False(t, Covered(svcAll, "/example.v1.GadgetService/GetGadget"))

	assert.True(t, Covered([]string{"*"}, "/anything/Method"))

	exact := []string{"/svc/Method"}
	assert.True(t, Covered(exact, "/svc/Method"))
	assert.False(t, Covered(exact, "/svc/Other"))
}

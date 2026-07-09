package token

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

func TestIssueVerify(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub := tenantKeys(t)

	token, err := Issue(op, "acme", tenantPub, []string{"read", "write"}, WithTTL(time.Hour))
	require.NoError(t, err)

	claims, err := VerifyAccount(token, opPub)
	require.NoError(t, err)
	assert.Equal(t, "acme", claims.TenantID)
	assert.Equal(t, tenantPub, claims.PubKey)
	assert.True(t, claims.HasScope("read"))
	assert.False(t, claims.HasScope("admin"))
	assert.NotEmpty(t, claims.ID)
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
		_, err := Issue(account, "acme", tenantPub, nil, WithTTL(time.Hour))
		assert.ErrorContains(t, err, "operator-type nkey")
	})

	t.Run("expired", func(t *testing.T) {
		short, err := Issue(op, "acme", tenantPub, nil, WithTTL(time.Second))
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
		_, err := Issue(op, "acme", tenantPub, nil, WithBearer())
		assert.ErrorContains(t, err, "bearer applies only to user tokens")
	})
}

func userKeys(t *testing.T) (nkeys.KeyPair, string) {
	t.Helper()
	up, err := nkeys.CreateUser()
	require.NoError(t, err)
	pub, err := up.PublicKey()
	require.NoError(t, err)
	return up, pub
}

func TestIssueUser(t *testing.T) {
	account, accountPub := tenantKeys(t)
	_, userPub := userKeys(t)

	tok, err := IssueUser(account, "alice", userPub, []string{"read"}, WithTTL(time.Hour))
	require.NoError(t, err)
	claims, err := VerifyUser(tok, accountPub)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims.TenantID)
	assert.Equal(t, userPub, claims.PubKey)
	assert.True(t, claims.HasScope("read"))
	assert.False(t, claims.Bearer)

	t.Run("non-account-type signer rejected", func(t *testing.T) {
		op, _ := issuerKeys(t)
		_, err := IssueUser(op, "alice", userPub, nil, WithTTL(time.Hour))
		assert.ErrorContains(t, err, "account-type nkey")
	})

	t.Run("keyless rejected", func(t *testing.T) {
		_, err := IssueUser(account, "carol", "", []string{"read"}, WithTTL(time.Hour))
		assert.ErrorContains(t, err, "invalid user public key")
	})

	t.Run("bearer flag round-trips", func(t *testing.T) {
		tok, err := IssueUser(account, "carol", userPub, []string{"read"}, WithBearer(), WithTTL(time.Hour))
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
		_, err := IssueUser(account, "alice", otherAcctPub, nil, WithTTL(time.Hour))
		assert.ErrorContains(t, err, "invalid user public key")
	})
}

func TestExtension(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub := tenantKeys(t)

	type domainClaims struct {
		Plan  string `json:"plan"`
		Quota int    `json:"quota"`
	}

	tok, err := Issue(op, "acme", tenantPub, nil, WithExtension(domainClaims{Plan: "pro", Quota: 42}))
	require.NoError(t, err)
	claims, err := VerifyAccount(tok, opPub)
	require.NoError(t, err)
	got, err := Ext[domainClaims](claims.AccountExt)
	require.NoError(t, err)
	assert.Equal(t, domainClaims{Plan: "pro", Quota: 42}, got)

	t.Run("absent extension decodes to zero value", func(t *testing.T) {
		plain, err := Issue(op, "acme", tenantPub, nil)
		require.NoError(t, err)
		claims, err := VerifyAccount(plain, opPub)
		require.NoError(t, err)
		got, err := Ext[domainClaims](claims.AccountExt)
		require.NoError(t, err)
		assert.Zero(t, got)
	})

	t.Run("unmarshalable extension rejected at issue", func(t *testing.T) {
		_, err := Issue(op, "acme", tenantPub, nil, WithExtension(func() {}))
		assert.ErrorContains(t, err, "encode extension")
	})
}

func TestDecode(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub := tenantKeys(t)
	_, userPub := userKeys(t)

	acctTok, err := Issue(op, "acme", accountPub, []string{"call:*"}, WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := IssueUser(account, "alice", userPub, nil, WithBearer())
	require.NoError(t, err)

	acct, err := Decode(acctTok)
	require.NoError(t, err)
	assert.Equal(t, "acme", acct.TenantID)
	assert.Equal(t, opPub, acct.Issuer)
	assert.False(t, acct.ExpiresAt.IsZero())

	user, err := Decode(userTok)
	require.NoError(t, err)
	assert.Equal(t, "alice", user.TenantID)
	assert.True(t, user.Bearer)
}

func TestSignVerifyRequest(t *testing.T) {
	tenant, tenantPub := tenantKeys(t)
	now := time.Now()

	ts, sig, err := SignRequest(tenant, now)
	require.NoError(t, err)
	assert.NoError(t, VerifySignature(tenantPub, ts, sig, now, DefaultSkew))

	t.Run("outside skew window", func(t *testing.T) {
		err := VerifySignature(tenantPub, ts, sig, now.Add(5*time.Minute), DefaultSkew)
		assert.ErrorContains(t, err, "skew window")
	})

	t.Run("wrong key", func(t *testing.T) {
		_, otherPub := tenantKeys(t)
		err := VerifySignature(otherPub, ts, sig, now, DefaultSkew)
		assert.ErrorContains(t, err, "signature verification failed")
	})

	t.Run("tampered timestamp breaks signature", func(t *testing.T) {
		other := now.Add(30 * time.Second)
		err := VerifySignature(tenantPub, other.UTC().Format(time.RFC3339Nano), sig, other, DefaultSkew)
		assert.ErrorContains(t, err, "signature verification failed")
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

func TestAuthorizesWildcard(t *testing.T) {
	svcAll := &Claims{Scopes: []string{"call:/example.v1.WidgetService/*"}}
	assert.True(t, svcAll.Authorizes("call:/example.v1.WidgetService/GetWidget"))
	assert.False(t, svcAll.Authorizes("call:/example.v1.GadgetService/GetGadget"))

	all := &Claims{Scopes: []string{"call:*"}}
	assert.True(t, all.Authorizes("call:/anything/Method"))

	exact := &Claims{Scopes: []string{"call:/svc/Method"}}
	assert.True(t, exact.Authorizes("call:/svc/Method"))
	assert.False(t, exact.Authorizes("call:/svc/Other"))
	assert.False(t, exact.HasScope("call:/svc/Other"))
}

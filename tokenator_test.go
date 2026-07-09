package tokenator

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func operatorKeys(t *testing.T) (nkeys.KeyPair, string) {
	t.Helper()
	op, err := nkeys.CreateOperator()
	require.NoError(t, err)
	pub, err := op.PublicKey()
	require.NoError(t, err)
	return op, pub
}

func tenantKeys(t *testing.T) (nkeys.KeyPair, string, []byte) {
	t.Helper()
	tp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	pub, err := tp.PublicKey()
	require.NoError(t, err)
	seed, err := tp.Seed()
	require.NoError(t, err)
	return tp, pub, seed
}

func TestIssueVerify(t *testing.T) {
	op, opPub := operatorKeys(t)
	_, tenantPub, _ := tenantKeys(t)

	token, err := Issue(op, "acme", tenantPub, []string{"read", "write"}, time.Hour)
	require.NoError(t, err)

	claims, err := Verify(token, opPub)
	require.NoError(t, err)
	assert.Equal(t, "acme", claims.TenantID)
	assert.Equal(t, tenantPub, claims.PubKey)
	assert.True(t, claims.HasScope("read"))
	assert.False(t, claims.HasScope("admin"))
	assert.NotEmpty(t, claims.ID)
	assert.False(t, claims.Expired(time.Now(), 0))

	t.Run("wrong operator rejected", func(t *testing.T) {
		_, otherPub := operatorKeys(t)
		_, err := Verify(token, otherPub)
		assert.ErrorContains(t, err, "expected operator")
	})

	t.Run("tampered token rejected", func(t *testing.T) {
		_, err := Verify(token[:len(token)-2]+"xx", opPub)
		assert.Error(t, err)
	})

	t.Run("expired", func(t *testing.T) {
		short, err := Issue(op, "acme", tenantPub, nil, time.Second)
		require.NoError(t, err)
		c, err := Verify(short, opPub)
		require.NoError(t, err)
		assert.True(t, c.Expired(c.ExpiresAt.Add(time.Minute), 0))
	})
}

func TestSignVerifyRequest(t *testing.T) {
	tenant, tenantPub, _ := tenantKeys(t)
	now := time.Now()

	ts, sig, err := SignRequest(tenant, now)
	require.NoError(t, err)
	assert.NoError(t, VerifyRequest(tenantPub, ts, sig, now, DefaultSkew))

	t.Run("outside skew window", func(t *testing.T) {
		err := VerifyRequest(tenantPub, ts, sig, now.Add(5*time.Minute), DefaultSkew)
		assert.ErrorContains(t, err, "skew window")
	})

	t.Run("wrong key", func(t *testing.T) {
		_, otherPub, _ := tenantKeys(t)
		err := VerifyRequest(otherPub, ts, sig, now, DefaultSkew)
		assert.ErrorContains(t, err, "signature verification failed")
	})

	t.Run("tampered timestamp breaks signature", func(t *testing.T) {
		other := now.Add(30 * time.Second)
		err := VerifyRequest(tenantPub, other.UTC().Format(time.RFC3339Nano), sig, other, DefaultSkew)
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

// authContext builds an incoming-metadata context as the interceptor sees it.
func authContext(token, ts, sig string) context.Context {
	md := metadata.New(map[string]string{
		MetadataToken:     token,
		MetadataTimestamp: ts,
		MetadataSignature: sig,
	})
	return metadata.NewIncomingContext(context.Background(), md)
}

func unaryInfo(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: method}
}

func TestMethodScope(t *testing.T) {
	op, opPub := operatorKeys(t)
	tenant, tenantPub, _ := tenantKeys(t)
	method := "/up2.monitoring.v1beta8.SchedulerService/CreateCheckConfig"
	token, err := Issue(op, "acme", tenantPub, []string{ScopeForMethod(method)}, time.Hour)
	require.NoError(t, err)

	now := time.Now()
	auth := NewAuthenticator(opPub, AllowAll{}, WithMethodScope())
	auth.now = func() time.Time { return now }
	ts, sig, err := SignRequest(tenant, now)
	require.NoError(t, err)

	handler := func(context.Context, any) (any, error) { return nil, nil }

	t.Run("granted method allowed", func(t *testing.T) {
		_, err := auth.UnaryInterceptor()(authContext(token, ts, sig), nil, unaryInfo(method), handler)
		assert.NoError(t, err)
	})

	t.Run("other method denied", func(t *testing.T) {
		_, err := auth.UnaryInterceptor()(authContext(token, ts, sig), nil,
			unaryInfo("/up2.monitoring.v1beta8.SchedulerService/DeleteCheckConfig"), handler)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})
}

func TestAuthenticate(t *testing.T) {
	op, opPub := operatorKeys(t)
	tenant, tenantPub, _ := tenantKeys(t)
	token, err := Issue(op, "acme", tenantPub, []string{"read"}, time.Hour)
	require.NoError(t, err)
	claims, err := Verify(token, opPub)
	require.NoError(t, err)

	now := time.Now()
	auth := NewAuthenticator(opPub, NewStaticAllowlist(claims.ID))
	auth.now = func() time.Time { return now }

	ts, sig, err := SignRequest(tenant, now)
	require.NoError(t, err)

	t.Run("authenticated request injects tenant", func(t *testing.T) {
		var got *Claims
		_, err := auth.UnaryInterceptor()(authContext(token, ts, sig), nil, unaryInfo("/svc/M"),
			func(ctx context.Context, _ any) (any, error) {
				c, ok := TenantFromContext(ctx)
				assert.True(t, ok)
				got = c
				return nil, nil
			})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "acme", got.TenantID)
		assert.True(t, got.HasScope("read"))
	})

	call := func(ctx context.Context) error {
		_, err := auth.UnaryInterceptor()(ctx, nil, unaryInfo("/svc/M"),
			func(context.Context, any) (any, error) { return nil, nil })
		return err
	}

	t.Run("missing credential", func(t *testing.T) {
		err := call(context.Background())
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("token not in allowlist", func(t *testing.T) {
		strict := NewAuthenticator(opPub, NewStaticAllowlist("other"))
		strict.now = func() time.Time { return now }
		_, err := strict.UnaryInterceptor()(authContext(token, ts, sig), nil, unaryInfo("/svc/M"),
			func(context.Context, any) (any, error) { return nil, nil })
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "not recognized")
	})

	t.Run("stale request signature", func(t *testing.T) {
		staleTS, staleSig, err := SignRequest(tenant, now.Add(-time.Hour))
		require.NoError(t, err)
		err = call(authContext(token, staleTS, staleSig))
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

func TestCredentials(t *testing.T) {
	op, opPub := operatorKeys(t)
	tenant, tenantPub, seed := tenantKeys(t)
	_ = tenant
	token, err := Issue(op, "acme", tenantPub, nil, time.Hour)
	require.NoError(t, err)

	creds, err := NewCredentials(token, seed)
	require.NoError(t, err)
	md, err := creds.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	auth := NewAuthenticator(opPub, AllowAll{})
	ctx := authContext(md[MetadataToken], md[MetadataTimestamp], md[MetadataSignature])
	_, err = auth.UnaryInterceptor()(ctx, nil, unaryInfo("/svc/M"),
		func(ctx context.Context, _ any) (any, error) {
			_, ok := TenantFromContext(ctx)
			assert.True(t, ok)
			return nil, nil
		})
	assert.NoError(t, err)
	assert.True(t, creds.RequireTransportSecurity())
	assert.False(t, creds.AllowInsecure().RequireTransportSecurity())
}

func TestAuthorizesWildcard(t *testing.T) {
	svcAll := &Claims{Scopes: []string{"call:/up2.monitoring.v1beta8.SchedulerService/*"}}
	assert.True(t, svcAll.Authorizes("call:/up2.monitoring.v1beta8.SchedulerService/GetCheckConfig"))
	assert.False(t, svcAll.Authorizes("call:/up2.monitoring.v1beta8.ObserverService/GetCheckState"))

	all := &Claims{Scopes: []string{"call:*"}}
	assert.True(t, all.Authorizes("call:/anything/Method"))

	exact := &Claims{Scopes: []string{"call:/svc/Method"}}
	assert.True(t, exact.Authorizes("call:/svc/Method"))
	assert.False(t, exact.Authorizes("call:/svc/Other"))
	assert.False(t, exact.HasScope("call:/svc/Other"))
}

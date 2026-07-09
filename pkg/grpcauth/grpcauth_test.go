package grpcauth

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/mikluko/valiss/pkg/creds"
	"github.com/mikluko/valiss/pkg/token"
)

func issuerKeys(t *testing.T) (nkeys.KeyPair, string) {
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

// authContext builds an incoming-metadata context as the interceptor sees it.
func authContext(cred token.Request) context.Context {
	md := metadata.New(map[string]string{
		token.HeaderAccountToken: cred.AccountToken,
		token.HeaderUserToken:    cred.UserToken,
		token.HeaderTimestamp:    cred.Timestamp,
		token.HeaderSignature:    cred.Signature,
	})
	return metadata.NewIncomingContext(context.Background(), md)
}

func unaryInfo(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: method}
}

func TestMethodScope(t *testing.T) {
	op, opPub := issuerKeys(t)
	tenant, tenantPub, _ := tenantKeys(t)
	method := "/example.v1.WidgetService/CreateWidget"
	tok, err := token.Issue(op, "acme", tenantPub, []string{ScopeForMethod(method)}, token.WithTTL(time.Hour))
	require.NoError(t, err)

	now := time.Now()
	clock := token.WithClock(func() time.Time { return now })
	auth := NewAuthenticator(token.NewVerifier(opPub, token.AllowAll{}, clock), WithMethodScope())
	ts, sig, err := token.SignRequest(tenant, now)
	require.NoError(t, err)

	handler := func(context.Context, any) (any, error) { return nil, nil }

	t.Run("granted method allowed", func(t *testing.T) {
		_, err := auth.UnaryInterceptor()(authContext(token.Request{AccountToken: tok, Timestamp: ts, Signature: sig}), nil, unaryInfo(method), handler)
		assert.NoError(t, err)
	})

	t.Run("other method denied", func(t *testing.T) {
		_, err := auth.UnaryInterceptor()(authContext(token.Request{AccountToken: tok, Timestamp: ts, Signature: sig}), nil,
			unaryInfo("/example.v1.WidgetService/DeleteWidget"), handler)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})
}

func TestAuthenticate(t *testing.T) {
	op, opPub := issuerKeys(t)
	tenant, tenantPub, _ := tenantKeys(t)
	tok, err := token.Issue(op, "acme", tenantPub, []string{"read"}, token.WithTTL(time.Hour))
	require.NoError(t, err)
	claims, err := token.Verify(tok, opPub)
	require.NoError(t, err)

	now := time.Now()
	clock := token.WithClock(func() time.Time { return now })
	auth := NewAuthenticator(token.NewVerifier(opPub, token.NewStaticAllowlist(claims.ID), clock))

	ts, sig, err := token.SignRequest(tenant, now)
	require.NoError(t, err)

	t.Run("authenticated request injects tenant", func(t *testing.T) {
		var got *token.Claims
		_, err := auth.UnaryInterceptor()(authContext(token.Request{AccountToken: tok, Timestamp: ts, Signature: sig}), nil, unaryInfo("/svc/M"),
			func(ctx context.Context, _ any) (any, error) {
				c, ok := token.TenantFromContext(ctx)
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
		strict := NewAuthenticator(token.NewVerifier(opPub, token.NewStaticAllowlist("other"), clock))
		_, err := strict.UnaryInterceptor()(authContext(token.Request{AccountToken: tok, Timestamp: ts, Signature: sig}), nil, unaryInfo("/svc/M"),
			func(context.Context, any) (any, error) { return nil, nil })
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "not recognized")
	})

	t.Run("stale request signature", func(t *testing.T) {
		staleTS, staleSig, err := token.SignRequest(tenant, now.Add(-time.Hour))
		require.NoError(t, err)
		err = call(authContext(token.Request{AccountToken: tok, Timestamp: staleTS, Signature: staleSig}))
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

func TestCredentials(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub, seed := tenantKeys(t)
	tok, err := token.Issue(op, "acme", tenantPub, nil, token.WithTTL(time.Hour))
	require.NoError(t, err)

	c, err := NewCredentials(creds.Creds{AccountToken: tok, Seed: seed})
	require.NoError(t, err)
	md, err := c.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	auth := NewAuthenticator(token.NewVerifier(opPub, token.AllowAll{}))
	ctx := authContext(token.Request{AccountToken: md[token.HeaderAccountToken], Timestamp: md[token.HeaderTimestamp], Signature: md[token.HeaderSignature]})
	_, err = auth.UnaryInterceptor()(ctx, nil, unaryInfo("/svc/M"),
		func(ctx context.Context, _ any) (any, error) {
			_, ok := token.TenantFromContext(ctx)
			assert.True(t, ok)
			return nil, nil
		})
	assert.NoError(t, err)
	assert.True(t, c.RequireTransportSecurity())
	assert.False(t, c.AllowInsecure().RequireTransportSecurity())
}

func TestBearerCredentials(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub, _ := tenantKeys(t)
	auth := NewAuthenticator(token.NewVerifier(opPub, token.AllowAll{}))
	handler := func(context.Context, any) (any, error) { return nil, nil }

	t.Run("bearer scope allows token-only call", func(t *testing.T) {
		tok, err := token.Issue(op, "acme", tenantPub, []string{token.ScopeBearer}, token.WithTTL(time.Hour))
		require.NoError(t, err)
		c, err := NewCredentials(creds.Creds{AccountToken: tok})
		require.NoError(t, err)
		md, err := c.GetRequestMetadata(context.Background())
		require.NoError(t, err)
		assert.NotContains(t, md, token.HeaderSignature)
		_, err = auth.UnaryInterceptor()(authContext(token.Request{AccountToken: md[token.HeaderAccountToken]}), nil, unaryInfo("/svc/M"), handler)
		assert.NoError(t, err)
	})

	t.Run("no bearer scope denies token-only call", func(t *testing.T) {
		tok, err := token.Issue(op, "acme", tenantPub, []string{"call:*"}, token.WithTTL(time.Hour))
		require.NoError(t, err)
		_, err = auth.UnaryInterceptor()(authContext(token.Request{AccountToken: tok}), nil, unaryInfo("/svc/M"), handler)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "bearer scope")
	})
}

// TestCredsEndToEnd proves parsed creds authenticate a request.
func TestCredsEndToEnd(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub, seed := tenantKeys(t)
	tok, err := token.Issue(op, "acme", tenantPub, []string{"call:*"}, token.WithTTL(time.Hour))
	require.NoError(t, err)

	parsed, err := creds.Parse(creds.Format(creds.Creds{AccountToken: tok, Seed: seed}))
	require.NoError(t, err)

	c, err := NewCredentials(parsed)
	require.NoError(t, err)
	md, err := c.GetRequestMetadata(t.Context())
	require.NoError(t, err)
	claims, err := token.Verify(md[token.HeaderAccountToken], opPub)
	require.NoError(t, err)
	assert.NoError(t, token.VerifySignature(claims.PubKey, md[token.HeaderTimestamp], md[token.HeaderSignature], time.Now(), token.DefaultSkew))
}

// TestUserChain proves user-level creds authenticate through the
// interceptor with the delegated identity.
func TestUserChain(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub, _ := tenantKeys(t)
	user, err := nkeys.CreateUser()
	require.NoError(t, err)
	userPub, err := user.PublicKey()
	require.NoError(t, err)
	userSeed, err := user.Seed()
	require.NoError(t, err)

	acctTok, err := token.Issue(op, "acme", accountPub, []string{"call:*"}, token.WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := token.IssueUser(account, "alice", userPub, []string{"call:/svc/M"}, token.WithTTL(time.Hour))
	require.NoError(t, err)

	c, err := NewCredentials(creds.Creds{AccountToken: acctTok, UserToken: userTok, Seed: userSeed})
	require.NoError(t, err)
	md, err := c.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	auth := NewAuthenticator(token.NewVerifier(opPub, token.AllowAll{}), WithMethodScope())
	ctx := authContext(token.Request{
		AccountToken: md[token.HeaderAccountToken],
		UserToken:    md[token.HeaderUserToken],
		Timestamp:    md[token.HeaderTimestamp],
		Signature:    md[token.HeaderSignature],
	})
	_, err = auth.UnaryInterceptor()(ctx, nil, unaryInfo("/svc/M"),
		func(ctx context.Context, _ any) (any, error) {
			claims, ok := token.TenantFromContext(ctx)
			require.True(t, ok)
			assert.Equal(t, "acme", claims.TenantID)
			assert.Equal(t, "alice", claims.UserID)
			return nil, nil
		})
	assert.NoError(t, err)

	// The user's grant does not extend to methods only the account holds.
	_, err = auth.UnaryInterceptor()(ctx, nil, unaryInfo("/svc/Other"),
		func(context.Context, any) (any, error) { return nil, nil })
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

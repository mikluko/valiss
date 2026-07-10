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
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/creds"
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

func userKeys(t *testing.T) (nkeys.KeyPair, string, []byte) {
	t.Helper()
	up, err := nkeys.CreateUser()
	require.NoError(t, err)
	pub, err := up.PublicKey()
	require.NoError(t, err)
	seed, err := up.Seed()
	require.NoError(t, err)
	return up, pub, seed
}

// authContext builds an incoming-metadata context as the interceptor sees it.
func authContext(req valiss.Request) context.Context {
	md := metadata.New(map[string]string{
		valiss.HeaderAccountToken: req.AccountToken,
		valiss.HeaderUserToken:    req.UserToken,
		valiss.HeaderTimestamp:    req.Timestamp,
		valiss.HeaderSignature:    req.Signature,
	})
	return metadata.NewIncomingContext(context.Background(), md)
}

// signed returns an incoming-metadata context for a request signed by kp and
// bound to the given full method, as the interceptor invoked with that method
// will reconstruct and verify.
func signed(t *testing.T, kp nkeys.KeyPair, at time.Time, method string, req valiss.Request) context.Context {
	t.Helper()
	ts, sig, err := valiss.SignRequest(kp, at, methodContext(method))
	require.NoError(t, err)
	req.Timestamp, req.Signature = ts, sig
	return authContext(req)
}

// callerContext injects the gRPC RequestInfo (method) that per-RPC
// credentials read to bind the signature, mirroring what the framework does
// at real call time.
func callerContext(method string) context.Context {
	return credentials.NewContextWithRequestInfo(context.Background(), credentials.RequestInfo{Method: method})
}

func unaryInfo(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: method}
}

func TestExtEnforcement(t *testing.T) {
	op, opPub := issuerKeys(t)
	tenant, tenantPub, _ := tenantKeys(t)
	tok, err := valiss.Issue(op, "acme", tenantPub,
		valiss.WithExtension(Ext{Methods: []string{"/example.v1.WidgetService/*"}}),
		valiss.WithTTL(time.Hour))
	require.NoError(t, err)

	now := time.Now()
	clock := valiss.WithClock(func() time.Time { return now })
	auth := NewAuthenticator(valiss.NewVerifier(opPub, valiss.AllowAll{}, clock))
	handler := func(context.Context, any) (any, error) { return nil, nil }

	invoke := func(a *Authenticator, accountToken, method string) error {
		ctx := signed(t, tenant, now, method, valiss.Request{AccountToken: accountToken})
		_, err := a.UnaryInterceptor()(ctx, nil, unaryInfo(method), handler)
		return err
	}

	t.Run("method inside the extension allowed", func(t *testing.T) {
		assert.NoError(t, invoke(auth, tok, "/example.v1.WidgetService/CreateWidget"))
	})

	t.Run("method outside the extension denied", func(t *testing.T) {
		err := invoke(auth, tok, "/example.v1.GadgetService/CreateGadget")
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})

	t.Run("token without extension denied by default", func(t *testing.T) {
		open, err := valiss.Issue(op, "acme", tenantPub, valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		err = invoke(auth, open, "/anything/Method")
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "no grpc extension")
	})

	t.Run("token without extension passes with AllowMissingExtension", func(t *testing.T) {
		open, err := valiss.Issue(op, "acme", tenantPub, valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		lax := NewAuthenticator(valiss.NewVerifier(opPub, valiss.AllowAll{}, clock), AllowMissingExtension())
		assert.NoError(t, invoke(lax, open, "/anything/Method"))
	})

	t.Run("empty Methods grants nothing", func(t *testing.T) {
		none, err := valiss.Issue(op, "acme", tenantPub,
			valiss.WithExtension(Ext{}), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		err = invoke(auth, none, "/anything/Method")
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})

	t.Run("wildcard grants everything explicitly", func(t *testing.T) {
		all, err := valiss.Issue(op, "acme", tenantPub,
			valiss.WithExtension(Ext{Methods: []string{"*"}}), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		assert.NoError(t, invoke(auth, all, "/anything/Method"))
	})
}

func TestAuthenticate(t *testing.T) {
	op, opPub := issuerKeys(t)
	tenant, tenantPub, _ := tenantKeys(t)
	tok, err := valiss.Issue(op, "acme", tenantPub, valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	claims, err := valiss.VerifyAccount(tok, opPub)
	require.NoError(t, err)

	now := time.Now()
	clock := valiss.WithClock(func() time.Time { return now })
	// Authentication is the focus here; extension enforcement is off.
	auth := NewAuthenticator(valiss.NewVerifier(opPub, valiss.NewStaticAllowlist(claims.ID), clock), AllowMissingExtension())

	t.Run("authenticated request injects the identity", func(t *testing.T) {
		var got *valiss.Identity
		ctx := signed(t, tenant, now, "/svc/M", valiss.Request{AccountToken: tok})
		_, err := auth.UnaryInterceptor()(ctx, nil, unaryInfo("/svc/M"),
			func(ctx context.Context, _ any) (any, error) {
				id, ok := valiss.IdentityFromContext(ctx)
				assert.True(t, ok)
				got = id
				return nil, nil
			})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "acme", got.Account.Name)
		assert.Nil(t, got.User)
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
		strict := NewAuthenticator(valiss.NewVerifier(opPub, valiss.NewStaticAllowlist("other"), clock), AllowMissingExtension())
		ctx := signed(t, tenant, now, "/svc/M", valiss.Request{AccountToken: tok})
		_, err := strict.UnaryInterceptor()(ctx, nil, unaryInfo("/svc/M"),
			func(context.Context, any) (any, error) { return nil, nil })
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "not recognized")
	})

	t.Run("stale request signature", func(t *testing.T) {
		ctx := signed(t, tenant, now.Add(-time.Hour), "/svc/M", valiss.Request{AccountToken: tok})
		assert.Equal(t, codes.Unauthenticated, status.Code(call(ctx)))
	})

	t.Run("signature bound to a different method rejected", func(t *testing.T) {
		ctx := signed(t, tenant, now, "/svc/Other", valiss.Request{AccountToken: tok})
		err := call(ctx) // invoked as /svc/M
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "signature verification failed")
	})
}

func TestCredentials(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub, seed := tenantKeys(t)
	tok, err := valiss.Issue(op, "acme", tenantPub, valiss.WithTTL(time.Hour))
	require.NoError(t, err)

	c, err := NewCredentials(creds.Creds{AccountToken: tok, Seed: seed})
	require.NoError(t, err)
	md, err := c.GetRequestMetadata(callerContext("/svc/M"))
	require.NoError(t, err)

	auth := NewAuthenticator(valiss.NewVerifier(opPub, valiss.AllowAll{}), AllowMissingExtension())
	ctx := authContext(valiss.Request{AccountToken: md[valiss.HeaderAccountToken], Timestamp: md[valiss.HeaderTimestamp], Signature: md[valiss.HeaderSignature]})
	_, err = auth.UnaryInterceptor()(ctx, nil, unaryInfo("/svc/M"),
		func(ctx context.Context, _ any) (any, error) {
			_, ok := valiss.IdentityFromContext(ctx)
			assert.True(t, ok)
			return nil, nil
		})
	assert.NoError(t, err)
	assert.True(t, c.RequireTransportSecurity())
	assert.False(t, c.AllowInsecure().RequireTransportSecurity())
}

func TestBearerCredentials(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub, _ := tenantKeys(t)
	_, userPub, _ := userKeys(t)

	acctTok, err := valiss.Issue(op, "acme", accountPub, valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	auth := NewAuthenticator(valiss.NewVerifier(opPub, valiss.AllowAll{}), AllowMissingExtension())
	handler := func(context.Context, any) (any, error) { return nil, nil }

	t.Run("bearer user token allows token-only call", func(t *testing.T) {
		bearerTok, err := valiss.IssueUser(account, "carol", userPub, valiss.WithBearer(), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		c, err := NewCredentials(creds.Creds{AccountToken: acctTok, UserToken: bearerTok})
		require.NoError(t, err)
		md, err := c.GetRequestMetadata(callerContext("/svc/M"))
		require.NoError(t, err)
		assert.NotContains(t, md, valiss.HeaderSignature)
		_, err = auth.UnaryInterceptor()(authContext(valiss.Request{AccountToken: md[valiss.HeaderAccountToken], UserToken: md[valiss.HeaderUserToken]}), nil, unaryInfo("/svc/M"), handler)
		assert.NoError(t, err)
	})

	t.Run("plain token denies token-only call", func(t *testing.T) {
		_, err = auth.UnaryInterceptor()(authContext(valiss.Request{AccountToken: acctTok}), nil, unaryInfo("/svc/M"), handler)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "not a bearer token")
	})
}

// TestCredsEndToEnd proves parsed creds authenticate a request.
func TestCredsEndToEnd(t *testing.T) {
	op, opPub := issuerKeys(t)
	_, tenantPub, seed := tenantKeys(t)
	tok, err := valiss.Issue(op, "acme", tenantPub, valiss.WithTTL(time.Hour))
	require.NoError(t, err)

	parsed, err := creds.Parse(creds.Format(creds.Creds{AccountToken: tok, Seed: seed}))
	require.NoError(t, err)

	c, err := NewCredentials(parsed)
	require.NoError(t, err)
	md, err := c.GetRequestMetadata(callerContext("/svc/M"))
	require.NoError(t, err)
	claims, err := valiss.VerifyAccount(md[valiss.HeaderAccountToken], opPub)
	require.NoError(t, err)
	assert.NoError(t, valiss.VerifySignature(claims.Subject, md[valiss.HeaderTimestamp], md[valiss.HeaderSignature], methodContext("/svc/M"), time.Now(), valiss.DefaultSkew))
}

// TestUserChain proves user-level creds authenticate through the
// interceptor with the delegated identity.
func TestUserChain(t *testing.T) {
	op, opPub := issuerKeys(t)
	account, accountPub, _ := tenantKeys(t)
	_, userPub, userSeed := userKeys(t)

	acctTok, err := valiss.Issue(op, "acme", accountPub,
		valiss.WithExtension(Ext{Methods: []string{"/svc/*"}}), valiss.WithTTL(time.Hour))
	require.NoError(t, err)
	userTok, err := valiss.IssueUser(account, "alice", userPub,
		valiss.WithExtension(Ext{Methods: []string{"/svc/M"}}), valiss.WithTTL(time.Hour))
	require.NoError(t, err)

	c, err := NewCredentials(creds.Creds{AccountToken: acctTok, UserToken: userTok, Seed: userSeed})
	require.NoError(t, err)

	// Strict default: both chain levels carry the extension.
	auth := NewAuthenticator(valiss.NewVerifier(opPub, valiss.AllowAll{}))

	ctxFor := func(method string) context.Context {
		md, err := c.GetRequestMetadata(callerContext(method))
		require.NoError(t, err)
		return authContext(valiss.Request{
			AccountToken: md[valiss.HeaderAccountToken],
			UserToken:    md[valiss.HeaderUserToken],
			Timestamp:    md[valiss.HeaderTimestamp],
			Signature:    md[valiss.HeaderSignature],
		})
	}

	_, err = auth.UnaryInterceptor()(ctxFor("/svc/M"), nil, unaryInfo("/svc/M"),
		func(ctx context.Context, _ any) (any, error) {
			id, ok := valiss.IdentityFromContext(ctx)
			require.True(t, ok)
			assert.Equal(t, "acme", id.Account.Name)
			require.NotNil(t, id.User)
			assert.Equal(t, "alice", id.User.Name)
			return nil, nil
		})
	assert.NoError(t, err)

	// The user's extension does not extend to methods only the account's
	// extension covers.
	_, err = auth.UnaryInterceptor()(ctxFor("/svc/Other"), nil, unaryInfo("/svc/Other"),
		func(context.Context, any) (any, error) { return nil, nil })
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// Both levels bind: a user extension wider than the account's does not
	// escape the account bounds.
	t.Run("account extension clamps the user", func(t *testing.T) {
		wide, err := valiss.IssueUser(account, "mallory", userPub,
			valiss.WithExtension(Ext{Methods: []string{"/other/*"}}), valiss.WithTTL(time.Hour))
		require.NoError(t, err)
		wc, err := NewCredentials(creds.Creds{AccountToken: acctTok, UserToken: wide, Seed: userSeed})
		require.NoError(t, err)
		wmd, err := wc.GetRequestMetadata(callerContext("/other/Method"))
		require.NoError(t, err)
		_, err = auth.UnaryInterceptor()(authContext(valiss.Request{
			AccountToken: wmd[valiss.HeaderAccountToken],
			UserToken:    wmd[valiss.HeaderUserToken],
			Timestamp:    wmd[valiss.HeaderTimestamp],
			Signature:    wmd[valiss.HeaderSignature],
		}), nil, unaryInfo("/other/Method"), func(context.Context, any) (any, error) { return nil, nil })
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})
}

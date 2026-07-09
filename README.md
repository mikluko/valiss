# tokenator

Tenant authentication for gRPC services, modeled on NATS operator/user
credentials.

- An **operator** holds an Ed25519 nkey — the trust anchor.
- The operator issues each **tenant** a scoped, time-limited JWT that binds the
  tenant's own nkey public key. Issued token ids go in a server-side allowlist.
- The tenant **signs every request** with its nkey over a timestamp. The server
  verifies the token against the operator key, the signature against the bound
  key within a skew window, and the token id against the allowlist, then hands
  the tenant identity to the handler for data segmentation.

Per-method authorization: grant `call:<fullMethod>` scopes (prefix wildcards
like `call:/pkg.Service/*` and `call:*` supported) and enable
`WithMethodScope()` on the authenticator.

## Library

```go
auth := tokenator.NewAuthenticator(operatorPubKey, allowlist, tokenator.WithMethodScope())
srv := grpc.NewServer(
    grpc.UnaryInterceptor(auth.UnaryInterceptor()),
    grpc.StreamInterceptor(auth.StreamInterceptor()),
)
// in a handler:
claims, _ := tokenator.TenantFromContext(ctx) // claims.TenantID segments data

// client:
creds, _ := tokenator.NewCredentials(token, tenantSeed)
conn, _ := grpc.NewClient(addr, grpc.WithPerRPCCredentials(creds), ...)
```

## CLI

```
tokenator init                              # create the operator key
tokenator pub                               # operator public key (server trust anchor)
tokenator add acme -scope 'call:*' -ttl 168h
tokenator creds acme > acme.creds           # client credential bundle (token + seed)
tokenator issue acme -ttl 720h              # re-issue
tokenator list
tokenator allowlist                         # path of the server allowlist file
```

Keystore defaults to `$TOKENATOR_HOME` or `~/.tokenator`.

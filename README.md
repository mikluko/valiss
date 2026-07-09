# valiss

**VAL**idator-**ISS**uer: a Go library for tenant authentication in gRPC and
HTTP services, modeled on NATS operator/account/user credentials.

- An **operator** holds an Ed25519 nkey; its public key is the trust anchor.
- The operator signs each **account** (tenant) a time-limited token that
  binds the account's own nkey public key. Issued token ids go in a
  server-side allowlist.
- An account may delegate: it signs **user** tokens with its account seed.
  Servers verify the chain up to the pinned operator key; nothing else needs
  distribution.
- The client **signs every request** with its nkey over a timestamp. The
  server verifies the token (chain) against the operator key, the signature
  against the subject key within a skew window, and the account token id
  against the allowlist, then hands the tenant (and user) identity to the
  handler for data segmentation.

Key types map to nkeys directly: operator `SO...`/`O...`, account
`SA...`/`A...`, user `SU...`/`U...`. Tokens are valiss's own typed claims in
an nkey-signed JWT: `sub` is the subject's public key, `name` the
human-readable label, validity via optional absolute `exp`/`nbf` (absent
`exp` = never expires, as in nsc).

## Extensions

Tokens carry named extension claims — signed, typed payloads under the `ext`
field. Transport authorization is built on them:

- `contrib/httpauth` defines `Ext{Hosts, Methods, Paths}` (name `http`): the
  middleware rejects requests outside the extension's bounds with 403.
- `contrib/grpcauth` defines `Ext{Methods}` (name `grpc`): the interceptors
  reject methods outside the extension with PermissionDenied.

Extensions present on both chain levels are both enforced, so an
account-level extension bounds every user of the account. Consumers add
their own domain claims the same way:

```go
tok, _ := valiss.IssueUser(account, "alice", alicePub, nil,
    grpcauth.WithExt(grpcauth.Ext{Methods: []string{"/example.v1.Widgets/*"}}),
    valiss.WithExtension("acme.example", myClaims{Plan: "pro"}),
    valiss.WithTTL(time.Hour),
)

verifier := valiss.NewVerifier(operatorPub, allowlist,
    valiss.WithClaimsValidator(valiss.ExtValidator("acme.example",
        func(req valiss.Request, c *valiss.Claims, acct, user myClaims) error {
            // domain-specific checks
            return nil
        })),
)
```

Generic string scopes also exist (`Claims.Scopes`, user clamped to account);
the library assigns them no meaning beyond the subset rule.

Bearer credentials: a user token minted with `valiss.WithBearer()`
authenticates without a per-request signature (token-only, replayable);
pair with TLS and a short validity window. Accounts never get bearer tokens.

## Layout

- root (`github.com/mikluko/valiss`) — token issue/verify (account and user
  level), request sign/verify, allowlist, the request `Verifier`, extension
  plumbing, and `TenantFromContext`
- `creds` — client creds file (tokens + seed, nsc style)
- `contrib/httpauth` — net/http middleware, client transport, HTTP extension
- `contrib/grpcauth` — gRPC interceptors, per-RPC credentials, gRPC extension
- `examples/` — runnable end-to-end demos, including the manifest-driven
  `examples/cli` credential minting tool

## Library

Server (gRPC):

```go
verifier := valiss.NewVerifier(operatorPubKey, allowlist)
auth := grpcauth.NewAuthenticator(verifier)
srv := grpc.NewServer(
    grpc.UnaryInterceptor(auth.UnaryInterceptor()),
    grpc.StreamInterceptor(auth.StreamInterceptor()),
)
// in a handler:
claims, _ := valiss.TenantFromContext(ctx) // claims.TenantID segments data,
                                           // claims.UserID names the end user
```

Client (gRPC):

```go
c, _ := creds.Load("alice.creds")
rpcCreds, _ := grpcauth.NewCredentials(c)
conn, _ := grpc.NewClient(addr, grpc.WithPerRPCCredentials(rpcCreds), ...)
```

Server (HTTP):

```go
mw := httpauth.NewMiddleware(valiss.NewVerifier(operatorPubKey, allowlist))
srv := &http.Server{Handler: mw(mux)}
```

Client (HTTP):

```go
c, _ := creds.Load("alice.creds")
transport, _ := httpauth.NewTransport(c, nil)
client := &http.Client{Transport: transport}
```

Runnable versions: `go run ./examples/grpcauth`, `go run ./examples/httpauth`.

Servers that hold account tokens in configuration (NATS-resolver style)
accept user-token-only requests via
`valiss.WithAccountTokenResolver(valiss.StaticAccountTokens(...))`.

## Example CLI

`examples/cli` is a manifest-driven credential minting tool (and a worked
example of the issuance API). Stateless: key pairs print once and are never
stored; signing seeds come from `VALISS_SEED_<PUBKEY>` environment variables.

```
go run ./examples/cli keygen operator     # public key = server trust anchor
go run ./examples/cli keygen account      # per-tenant key pair
go run ./examples/cli keygen user         # per-end-user key pair
go run ./examples/cli creds ACCOUNT[/USER]  # mint creds for a manifest entry
```

`creds` reads `valiss.yaml` (see the annotated
[`examples/cli/valiss.example.yaml`](examples/cli/valiss.example.yaml)),
resolves seeds from the environment, and writes the creds to stdout with
metadata — including the allowlist jti — on stderr. User creds carry only
the user token by default; `-bundle` embeds a fresh account token for
servers without a resolver.

# valiss

**VAL**idator-**ISS**uer: tenant authentication for gRPC and HTTP services,
modeled on NATS operator/account/user credentials.

- An **operator** holds an Ed25519 nkey; its public key is the trust anchor.
- The operator signs each **account** (tenant) a scoped, time-limited JWT
  that binds the account's own nkey public key. Issued token ids go in a
  server-side allowlist.
- An account may delegate: it signs **user** tokens with its account seed,
  granting end users a subset of its scopes. Servers verify the chain up to
  the pinned operator key; nothing else needs distribution.
- The client **signs every request** with its nkey over a timestamp. The
  server verifies the token (chain) against the operator key, the signature
  against the bound key within a skew window, and the account token id
  against the allowlist, then hands the tenant (and user) identity to the
  handler for data segmentation.

Key types map to nkeys directly: operator `SO...`/`O...`, account
`SA...`/`A...`, user `SU...`/`U...`.

Per-method authorization: grant `call:<fullMethod>` scopes (prefix wildcards
like `call:/pkg.Service/*` and `call:*` supported) and enable
`WithMethodScope()` on the authenticator. User scopes are clamped to the
account's grants at verification, so a tenant can never delegate more than
it holds.

Bearer credentials: a user token minted with the bearer flag authenticates
without a per-request signature (token-only, replayable). Meant for user
entries marked `bearer: true`, where handing out a seed is impractical; pair
with TLS and a short validity window. Accounts never get bearer tokens.

Tokens carry valiss's own typed claims in an nkey-signed JWT; consumers can
embed domain-specific claims via `token.WithExtension(v)` and validate them
server-side with `token.ExtValidator` (typed) or `token.Ext[T]`.

## Layout

`main.go` at the root is the CLI; the consumable library lives under `pkg/`.

- `pkg/token` — token issue/verify (account and user level), request
  sign/verify, allowlist, the credential `Verifier`, and `TenantFromContext`
- `pkg/creds` — client creds file (tokens + seed)
- `pkg/grpcauth` — gRPC server interceptors and client per-RPC credentials
- `pkg/httpauth` — net/http server middleware and client transport
- `internal/manifest` — the valiss.yaml token manifest (CLI-only)
- `examples/` — runnable end-to-end demos for both transports

## Library

Server (gRPC):

```go
verifier := token.NewVerifier(operatorPubKey, allowlist)
auth := grpcauth.NewAuthenticator(verifier, grpcauth.WithMethodScope())
srv := grpc.NewServer(
    grpc.UnaryInterceptor(auth.UnaryInterceptor()),
    grpc.StreamInterceptor(auth.StreamInterceptor()),
)
// in a handler:
claims, _ := token.TenantFromContext(ctx) // claims.TenantID segments data,
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
mw := httpauth.NewMiddleware(token.NewVerifier(operatorPubKey, allowlist))
srv := &http.Server{Handler: mw(mux)}
```

Client (HTTP):

```go
c, _ := creds.Load("alice.creds")
transport, _ := httpauth.NewTransport(c, nil)
client := &http.Client{Transport: transport}
```

Runnable versions: `go run ./examples/grpcauth`, `go run ./examples/httpauth`.

## CLI

Stateless: key pairs are printed once at generation and never stored;
signing seeds are supplied via `VALISS_SEED_<PUBKEY>` environment variables
(a secrets manager that injects env fits naturally).

```
valiss keygen operator     # one-time: public key = server trust anchor
valiss keygen account      # per-tenant: public key goes in valiss.yaml
valiss keygen user         # per-end-user: public key goes in a user entry
valiss creds ACCOUNT[/USER]  # mint credentials for one entity
```

`creds` reads the token manifest (`valiss.yaml` in the working directory,
override with `-f FILE`), resolves the required seeds from the environment
(failing with the exact variable name when one is missing), and writes the
credentials to stdout and their metadata to stderr:

```console
$ export VALISS_SEED_OD25ZJ...=SOAI2X...   # operator seed
$ valiss creds acme > acme.creds
account:
  name: acme
  key: AC4JQU...
  jti: FVIENQPFQY...        # add to the server allowlist
  expires: 2026-08-08T09:00:00Z
```

Manifest entries without a `key` get a fresh pair generated per invocation;
the seed ships only inside the creds.

User creds carry only the user token and seed (NATS-resolver style):
the operator seed is not needed at mint time, so an account holder can
issue its users on its own. The server resolves account tokens itself,
e.g. from static configuration:

```console
$ export VALISS_SEED_AC4JQU...=SAAK7G...   # account seed
$ valiss creds acme/alice > alice.creds
user:
  name: alice
  key: UDKED...
  jti: NQLQXOWTGN...
  expires: 2026-07-09T13:00:00Z
```

```go
resolver, _ := token.StaticAccountTokens(acctTok1, acctTok2)
verifier := token.NewVerifier(operatorPubKey, allowlist,
    token.WithAccountTokenResolver(resolver))
```

Pass `-bundle` to mint a *bundle* instead: user creds that also embed a
freshly minted account token (requiring the operator seed), verifiable by
any server without a resolver. Each bundle mint yields a new account jti
for the allowlist.

An annotated template ships as [`valiss.example.yaml`](valiss.example.yaml):

```yaml
# valiss.yaml — public data only, safe to commit
operator: ODZ6U...          # trust anchor; seed from VALISS_SEED_<this key>
accounts:
  - name: acme
    key: ABPZ7...            # account public key from `valiss keygen account`
    scopes: ["call:/pkg.Svc/*"]
    expires: 2026-08-08T00:00:00Z   # optional; omitted = never expires
    users:
      - name: alice
        key: UDGH3...        # user public key; seed stays with the user
        scopes: ["call:/pkg.Svc/Get"]
        expires: 2026-07-16T00:00:00Z
        not_before: 2026-07-09T00:00:00Z  # optional activation time
      - name: carol
        bearer: true         # token-only credential, no seed handed out
        scopes: ["call:/pkg.Svc/List"]
```

# valiss

**VAL**idator-**ISS**uer: decentralized tenant authentication for Go
services, gRPC and HTTP, modeled on NATS operator/account/user credentials.

Most multi-tenant services end up with a central auth dependency: an OAuth
provider, a session store, a per-tenant key registry — something every
request has to consult and every deployment has to keep alive. valiss takes
the NATS approach instead. Trust is a single public key baked into the
server; everything else is self-contained signed credentials that verify
offline. There is no auth service to run, no token introspection endpoint to
call, and issuing credentials never touches production infrastructure.

Where it fits:

- **Multi-tenant APIs.** Each customer is an account with its own keypair.
  You sign one account credential per customer; they mint their own user and
  service credentials from it, scoped down as they see fit, without asking
  you.
- **Machine-to-machine auth.** Services and agents authenticate with keys
  and per-request signatures — no shared secrets, no password rotation, and
  a stolen token is useless without the key that signs requests.
- **Edge and on-prem.** Verifiers need only the operator public key (plus an
  allowlist and, optionally, account tokens in static config), so isolated
  deployments authenticate the same way as connected ones.
- **Browsers and other weak clients.** Short-lived bearer user tokens cover
  clients that cannot hold a key.

How it works, in one paragraph: an **operator** key signs **account**
(tenant) tokens; an account key signs **user** tokens; every request is
signed by the subject's own key over a timestamp. The server verifies the
chain against the pinned operator key, checks the account token against a
revocation allowlist, and hands the tenant (and user) identity to the
handler. Delegation is real: revoking one account cuts off everything under
it, and an account can never grant more than it holds.

Key types map to nkeys directly: operator `SO...`/`O...`, account
`SA...`/`A...`, user `SU...`/`U...`. Tokens are valiss's own typed claims in
an nkey-signed JWT: `sub` is the subject's public key, `name` the
human-readable label, validity via optional absolute `exp`/`nbf` (absent
`exp` = never expires, as in nsc).

## Extensions

All authorization rides named extension claims: signed, typed payloads under
the token's `ext` field. An extension is any struct with an
`ExtensionName() string` method; valiss signs and transports it opaquely,
and the same concrete type comes back out on the server. Transport
authorization is built on this mechanism:

- `contrib/httpauth` defines `Ext{Hosts, Methods, Paths}` (name `http`): the
  middleware rejects requests outside the extension's bounds with 403.
- `contrib/grpcauth` defines `Ext{Methods}` (name `grpc`): the interceptors
  reject methods outside the extension with PermissionDenied.

Extensions present on both chain levels are both enforced, so an
account-level extension bounds every user of the account.

Domain claims work the same way. Define the type, mint it into the token,
recover it in the handler:

```go
// The set of filters this application enforces on data queries.
type QueryFilters struct {
    Regions []string `json:"regions"`
}

func (QueryFilters) ExtensionName() string { return "acme.filters" }

// Mint: transport bounds plus domain claims, typed end to end.
tok, _ := valiss.IssueUser(account, "alice", alicePub,
    valiss.WithExtension(grpcauth.Ext{Methods: []string{"/example.v1.Widgets/*"}}),
    valiss.WithExtension(QueryFilters{Regions: []string{"eu"}}),
    valiss.WithTTL(time.Hour),
)

// Handler: the concrete type back, no string plumbing.
id, _ := valiss.IdentityFromContext(ctx)
filters, ok, err := valiss.ExtOf[QueryFilters](id.User.Ext)
```

Optionally validate extensions at auth time instead of in handlers:
`valiss.WithExtensionType[QueryFilters]()` on the verifier rejects requests
whose tokens carry a malformed `acme.filters` claim, and
`valiss.ExtValidator(func(req, id, acct, user QueryFilters) error { ... })`
runs typed domain checks inside the verification pipeline.

Bearer credentials: a user token minted with `valiss.WithBearer()`
authenticates without a per-request signature (token-only, replayable);
pair with TLS and a short validity window. Accounts never get bearer tokens.

## Layout

- root (`github.com/mikluko/valiss`) — token issue/verify (account and user
  level), request sign/verify, allowlist, the request `Verifier`, extension
  plumbing, and `IdentityFromContext`
- `creds` — client creds file (tokens + seed, nsc style)
- `contrib/httpauth` — net/http middleware, client transport, HTTP extension
- `contrib/grpcauth` — gRPC interceptors, per-RPC credentials, gRPC extension
- `examples/` — runnable end-to-end demos, including the manifest-driven
  `examples/minter` credential minting tool

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
id, _ := valiss.IdentityFromContext(ctx) // id.Account.Name segments data,
                                         // id.User names the end user (nil
                                         // for account-level requests)
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

## Minter

[`examples/minter`](examples/minter) is a manifest-driven credential minting
tool (and a worked example of the issuance API). Stateless: key pairs print
once and are never stored; signing seeds come from `VALISS_SEED_<PUBKEY>`
environment variables.

```
go run ./examples/minter keygen operator     # public key = server trust anchor
go run ./examples/minter keygen account      # per-tenant key pair
go run ./examples/minter keygen user         # per-end-user key pair
go run ./examples/minter creds ACCOUNT[/USER]  # mint creds for a manifest entry
```

`creds` reads `minter.yaml` (annotated example in the directory), resolves
seeds from the environment, and writes the creds to stdout with metadata —
including the allowlist jti — on stderr. User creds carry only the user
token by default; `-bundle` embeds a fresh account token for servers without
a resolver. See [`examples/minter/README.md`](examples/minter/README.md).

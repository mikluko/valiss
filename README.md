# valiss

**VAL**idator-**ISS**uer: decentralized tenant authentication for Go
services, gRPC and HTTP, built on a three-level chain of Ed25519 keys:
operator → account → user — with an optional fourth level of per-message
proof-of-origin tokens.

Most multi-tenant services end up with a central auth dependency: an OAuth
provider, a session store, a per-tenant key registry — something every
request has to consult and every deployment has to keep alive. valiss
inverts that. Trust is a single public key baked into the server;
everything else is self-contained signed credentials that verify offline.
There is no auth service to run, no token introspection endpoint to call,
and issuing credentials never touches production infrastructure.

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
`exp` = never expires).

## Rotation and mass revocation

The operator can publish a self-signed **operator token**: a policy
statement over the trust domain, carrying an **epoch** counter and an
optional validity window. Verifiers configured with it accept only account
and user tokens stamped with the current epoch:

```go
opTok, _ := valiss.IssueOperator(operator, valiss.WithEpoch(3))
acct, _  := valiss.Issue(operator, "acme", acctPub, valiss.WithEpoch(3), ...)

verifier := valiss.NewVerifier(operatorPub, allowlist,
    valiss.WithOperatorToken(opTok))
```

Bumping the epoch and re-minting rotates the whole domain: every token from
earlier epochs is rejected cryptographically, no allowlist edits. The
operator token's own `exp` bounds the entire domain, forcing a periodic
rotation ceremony. The pinned public key remains the trust anchor — the
operator token only carries policy signed by it. Selective revocation stays
with the allowlist; the two levers are complementary.

## Message tokens

A service that emits artifacts to third parties — webhooks, queue messages,
exported documents — can extend the chain one level further with **message
tokens**: a short-lived JWT minted with a user key, one per emitted message,
that any receiver can verify **offline** knowing only the published operator
public key. The token binds the destination (`aud`), the exact payload bytes
(a SHA-256 checksum claim), a short validity window, and the trust-domain
epoch:

```go
// Emitter: holds the user seed and its chain tokens.
payload := renderWebhook(event)
tok, _ := valiss.IssueMessage(userKP,
    valiss.WithAudience("https://receiver.example/hook"),
    valiss.WithChecksum(valiss.Checksum(payload)),
    valiss.WithTTL(30*time.Second),
    valiss.WithEpoch(epoch),
    valiss.WithChain(accountToken, userToken),
)

// Receiver: knows only the operator public key.
claims, err := valiss.VerifyMessage(tok, operatorPub,
    valiss.ExpectAudience("https://receiver.example/hook"),
    valiss.WithPayload(receivedBody),
)
// claims.Account.Name / claims.User.Name identify the emitter.
```

Verification walks the full chain operator → account → user → message and
requires every level to agree on the epoch; `WithOperatorPolicy(opTok)`
additionally enforces the current domain epoch and the operator token's own
window. `ExpectAudience` is the lever against cross-destination replay,
`WithPayload` against payload tampering — receivers should set both.
Stored messages verify after token expiry with `valiss.At(receivedAt)`,
which evaluates all windows and policy as of that instant.

The chain travels either embedded (`WithChain` at mint — the token is fully
self-contained at the cost of roughly three tokens of size) or out-of-band
(`WithChainTokens` on `VerifyMessage` — smaller tokens, but the receiver
must be handed the chain separately). A token that embeds a chain must match
any supplied one.

**Message tokens are proofs, not credentials.** Possession of one grants
nothing: the request `Verifier` never accepts them, and receivers must not
treat them as bearer credentials. Offline receivers hold no allowlist; an
online receiver that wants revocation checks `claims.Account.ID` against its
own allowlist.

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

Transport enforcement is fail-closed: every token in the chain must carry
the transport extension, the zero-value extension grants nothing, and
allow-all is the explicit wildcard (`Methods: ["*"]`, `Paths: ["*"]`).
Deployments that authorize entirely outside the transport can opt out with
`AllowMissingExtension()` on the authenticator/middleware. Extensions
present on both chain levels are both enforced, so an account-level
extension bounds every user of the account.

`httpauth.Ext` has three independent dimensions (hosts, methods, paths) and
each constrains only when populated: a dimension you leave empty imposes no
restriction on it. So `Ext{Paths: ["/admin/*"]}` permits `/admin/*` with
**any** method — to scope a read-only admin surface, name every dimension:
`Ext{Methods: ["GET"], Paths: ["/admin/*"]}`. (The single-dimension
`grpcauth.Ext` has no other dimensions to leave open.)

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

The per-request signature is bound to the transport's request context
(HTTP method/host/path, gRPC full method), so a captured signature cannot
authorize a different operation. To also suppress replay of the *same*
operation within the skew window, enable a replay cache on the server and a
nonce on the client:

```go
verifier := valiss.NewVerifier(operatorPub, allowlist,
    valiss.WithReplayCache(valiss.NewMemoryReplayCache()))
transport, _ := httpauth.NewTransport(c, nil, httpauth.WithNonce())
// gRPC: grpcauth.NewCredentials(c, grpcauth.WithNonce())
```

`NewMemoryReplayCache` is process-local; for exactly-once across multiple
server instances back `WithReplayCache` with shared storage keyed by nonce.

Bearer credentials: a user token minted with `valiss.WithBearer()`
authenticates without a per-request signature (token-only, replayable);
pair with TLS and a short validity window. Accounts never get bearer tokens.

## Layout

- root (`github.com/mikluko/valiss`) — token issue/verify (account, user,
  and message level), request sign/verify, allowlist, the request `Verifier`,
  extension plumbing, and `IdentityFromContext`
- `creds` — client creds file (tokens + seed in one marker-delimited file)
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

Servers that hold account tokens in static configuration accept
user-token-only requests via
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

## Prior art

valiss stands on well-trodden ground; these shaped it or solve neighboring
problems:

- [NATS JWT authentication](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/jwt)
  and [`nsc`](https://github.com/nats-io/nsc) — the operator/account/user
  delegation model and the creds-file format originate here; valiss adapts
  them to request/response services and strips the messaging-specific parts.
- [RFC 7519 (JWT)](https://www.rfc-editor.org/rfc/rfc7519) — the claims
  vocabulary (`iss`, `sub`, `exp`, `nbf`, `iat`, `jti`) and token framing.
- [RFC 8032 (Ed25519)](https://www.rfc-editor.org/rfc/rfc8032) — the
  signature scheme, via [`nkeys`](https://github.com/nats-io/nkeys).
- [golang-jwt](https://github.com/golang-jwt/jwt) — the embedded
  registered-claims struct pattern valiss's typed claims follow.
- [Biscuit](https://www.biscuitsec.org/) and
  [Macaroons](https://research.google/pubs/pub41892/) — offline attenuation
  and delegation of bearer credentials; valiss trades their in-token
  attenuation for a fixed two-hop chain plus typed extension claims.
- [SPIFFE/SPIRE](https://spiffe.io/) — workload identity with short-lived
  documents and trust-domain semantics; heavier machinery aimed at
  infrastructure identity rather than tenant credentials.

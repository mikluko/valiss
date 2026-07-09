# valiss

**VAL**idator-**ISS**uer: tenant authentication for gRPC and HTTP services,
modeled on NATS operator/user credentials.

- An **issuer** holds an Ed25519 nkey; its public key is the trust anchor.
- The issuer signs each **tenant** a scoped, time-limited JWT that binds the
  tenant's own nkey public key. Issued token ids go in a server-side allowlist.
- The tenant **signs every request** with its nkey over a timestamp. The server
  verifies the token against the issuer key, the signature against the bound
  key within a skew window, and the token id against the allowlist, then hands
  the tenant identity to the handler for data segmentation.

(In nkeys terms the issuer key is an operator-type key: `SO...` seed, `O...`
public key.)

Per-method authorization: grant `call:<fullMethod>` scopes (prefix wildcards
like `call:/pkg.Service/*` and `call:*` supported) and enable
`WithMethodScope()` on the authenticator.

## Layout

`main.go` at the root is the CLI; the consumable library lives under `pkg/`.

- `pkg/token` — token issue/verify, request sign/verify, allowlist, the
  credential `Verifier`, and `TenantFromContext`
- `pkg/creds` — client credential bundle file (token + seed)
- `pkg/grpcauth` — gRPC server interceptors and client per-RPC credentials
- `pkg/httpauth` — net/http server middleware and client transport
- `internal/manifest` — the valiss.yaml token manifest (CLI-only)
- `examples/` — runnable end-to-end demos for both transports

## Library

Server (gRPC):

```go
verifier := token.NewVerifier(issuerPubKey, allowlist)
auth := grpcauth.NewAuthenticator(verifier, grpcauth.WithMethodScope())
srv := grpc.NewServer(
    grpc.UnaryInterceptor(auth.UnaryInterceptor()),
    grpc.StreamInterceptor(auth.StreamInterceptor()),
)
// in a handler:
claims, _ := token.TenantFromContext(ctx) // claims.TenantID segments data
```

Client (gRPC):

```go
tok, seed, _ := creds.Load("acme.creds")
c, _ := grpcauth.NewCredentials(tok, seed)
conn, _ := grpc.NewClient(addr, grpc.WithPerRPCCredentials(c), ...)
```

Server (HTTP):

```go
mw := httpauth.NewMiddleware(token.NewVerifier(issuerPubKey, allowlist))
srv := &http.Server{Handler: mw(mux)}
```

Client (HTTP):

```go
tok, seed, _ := creds.Load("acme.creds")
transport, _ := httpauth.NewTransport(tok, seed, nil)
client := &http.Client{Transport: transport}
```

Runnable versions: `go run ./examples/grpcauth`, `go run ./examples/httpauth`.

## CLI

Stateless: seeds are printed once at generation and never stored; preserve
them securely (a secrets manager, not this repo).

```
valiss keygen issuer       # one-time: public key = server trust anchor
valiss keygen tenant       # per-tenant: public key goes in valiss.yaml
valiss issue               # mint a token per manifest entry, YAML to stdout
```

`issue` reads the token manifest (`valiss.yaml` in the working directory,
override with `-f FILE`) and signs with the issuer seed from `-seed-file
FILE` or `$VALISS_ISSUER_SEED`:

```yaml
# valiss.yaml — public data only, safe to commit
issuer: ODZ6U...        # issuer public key; issue refuses non-matching seeds
tokens:
  - id: acme
    key: ABPZ7...        # tenant public key from `valiss keygen tenant`
    scopes: ["call:/pkg.Svc/*"]
    ttl: 720h            # optional, defaults to 720h
```

An annotated template ships as [`valiss.example.yaml`](valiss.example.yaml).

Output carries everything both sides need: the token for the client, the jti
for the server-side allowlist:

```yaml
tokens:
  - id: acme
    jti: FVIENQPFQY...   # add to the server allowlist
    expires: 2026-08-08T09:00:00Z
    token: eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ...
```

# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

valiss (VALidator-ISSuer) is a Go library + CLI for tenant authentication in gRPC and HTTP services, modeled on NATS operator/user credentials. Module: `github.com/mikluko/valiss`. No Makefile or lint config; plain Go toolchain.

## Commands

```sh
go build ./...                          # build everything
go test ./...                          # full test suite
go test ./pkg/token -run TestVerifier  # single test (testify used throughout)
go vet ./...
go run . keygen issuer                 # run the CLI (main.go at repo root)
go run ./examples/grpcauth             # end-to-end demo (also ./examples/httpauth)
```

## Architecture

The auth scheme has three checks per request, all rooted in Ed25519 nkeys:

1. **Token**: an issuer (nkeys *operator* key, `SO...` seed) signs each tenant a scoped, time-limited JWT that embeds the tenant's own nkey public key (custom claims `tenant_key`, `scopes`). Verified against the pinned issuer public key.
2. **Allowlist**: the token's jti must be in a server-side `token.Allowlist`; removal revokes before expiry.
3. **Request signature**: the tenant signs an RFC3339Nano timestamp with its seed on every request, verified against the token-bound key within a skew window (`token.DefaultSkew`, 2m). Exception: tokens with the `bearer` scope may skip the signature (replayable; token-only auth).

Layering, bottom to top:

- `pkg/token` — the core. `Issue`/`Verify` (token), `SignRequest`/`VerifyRequest` (per-request signature), `Allowlist`, and `Verifier.VerifyCredential` which composes all three checks. `token.Verify` deliberately does NOT check expiry or allowlist; `Verifier` layers those so callers get precise errors. `TenantFromContext` retrieves authenticated `Claims` in handlers.
- `pkg/grpcauth`, `pkg/httpauth` — thin transport adapters over `token.Verifier`: header/metadata extraction, error mapping (gRPC status codes / HTTP 401/403), and client-side attachment (per-RPC credentials / `http.RoundTripper`). The credential travels in three headers shared by both transports: `valiss-tenant-token`, `valiss-tenant-timestamp`, `valiss-tenant-signature` (`token.Header*` constants).
- `pkg/creds` — client bundle file (token + tenant seed), nsc-creds-style markers.
- `internal/manifest` — `valiss.yaml` token manifest, CLI-only; holds public data only (issuer public key, tenant public keys, scopes, ttl).
- `main.go` — stateless CLI (`keygen issuer|tenant`, `issue`). Seeds are printed once and never stored anywhere; the manifest and all committed files contain only public keys.

Authorization is scope-based: `call:<gRPC full method>` or `call:<HTTP path>`, with trailing-`*` prefix wildcards (`Claims.Authorizes`). Enforcement is opt-in per transport: `grpcauth.WithMethodScope()`, `httpauth.WithPathScope()` / `WithScopeMapper()`.

## Conventions

- Error messages are prefixed `valiss:`.
- Key-type mapping: issuer = nkeys operator (`SO...`/`O...`), tenant = nkeys account key (created via `nkeys.CreateAccount`, though user keys also verify).
- Tests use `token.WithClock` to inject time; prefer that over sleeping.
- `keygen` writes the key pair to stdout and guidance to stderr so redirected output stays parseable; keep that separation.

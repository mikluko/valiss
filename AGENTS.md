# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

valiss (VALidator-ISSuer) is a Go library + CLI for tenant authentication in gRPC and HTTP services, modeled on NATS operator/account/user credentials. Module: `github.com/mikluko/valiss`. No Makefile or lint config; plain Go toolchain. Only real dependencies: nkeys, yaml, grpc; tokens are hand-rolled nkey-signed JWTs (no NATS jwt library).

## Commands

```sh
go build ./...                          # build everything
go test ./...                          # full test suite
go test ./pkg/token -run TestVerifier  # single test (testify used throughout)
go vet ./...
go run . keygen operator               # run the CLI (main.go at repo root)
go run ./examples/grpcauth             # end-to-end demo (also ./examples/httpauth)
```

## Architecture

Three-level trust chain modeled on NATS, all rooted in Ed25519 nkeys: an **operator** (`SO...`/`O...`) signs **account** (tenant, `SA...`/`A...`) tokens; an account may sign **user** (`SU...`/`U...`) tokens delegating a subset of its scopes. Servers pin only the operator public key.

Per-request verification (`token.Verifier.VerifyRequest`, takes a `token.Request` of the four header values):

1. **Account token**: operator-signed JWT with valiss's own typed claims (pkg/token/claims.go): standard RFC 7519 fields plus a `valiss` section (`type`, `scopes`, optional consumer `ext`). As in NATS, `sub` is the account's public key and `name` carries the tenant id. Checked against the pinned operator key, expiry (`exp`, optional: absent = never expires), and activation (`nbf`, optional).
2. **Allowlist**: the *account* token's jti must be in a server-side `token.Allowlist`; removal revokes before expiry. User tokens are not allowlisted — revocation is account-wide, user-level revocation relies on short TTLs.
3. **User token** (optional chain): account-signed, verified against the account token's subject key. Effective scopes = user scopes clamped to the account's grants. A request may carry only the user token (the default for user creds); the server then resolves the account token via `WithAccountTokenResolver` (`StaticAccountTokens` helper), and the resolved token goes through the same checks.
4. **Custom validators**: `WithClaimsValidator` hooks run here, after chain assembly and before the signature check, in registration order; first error rejects. This is the injection point for tenant-status lookups, audit, custom semantics.
5. **Request signature**: the client signs an RFC3339Nano timestamp with its seed, verified against the effective subject key within a skew window (`token.DefaultSkew`, 2m). User tokens minted with `WithBearer` (the `bearer` claim flag) may skip it (replayable, token-only); account tokens never may.

Layering, bottom to top:

- `pkg/token` — the core. `Issue` (operator→account) / `IssueUser` (account→user), `VerifyAccount`/`VerifyUser`/`Decode`, `SignRequest`/`VerifySignature`, `Allowlist`, `Verifier`, `TenantFromContext` (claims carry `TenantID` and, on chain requests, `UserID`). `VerifyAccount`/`VerifyUser` deliberately do NOT check expiry or allowlist; `Verifier` layers those so callers get precise errors.
- `pkg/grpcauth`, `pkg/httpauth` — thin transport adapters over `token.Verifier`: header/metadata extraction, error mapping (gRPC status codes / HTTP 401/403), and client-side attachment (per-RPC credentials / `http.RoundTripper`), both constructed from a `creds.Creds`. Headers shared by both transports: `valiss-account-token`, `valiss-user-token`, `valiss-timestamp`, `valiss-signature` (`token.Header*` constants).
- `pkg/creds` — client creds file (`Creds`: optional account token + optional user token + optional seed; at least one token), nsc-creds-style markers. A *bundle* is user creds that also embed the account token; bearer creds have no seed.
- `internal/manifest` — `valiss.yaml` manifest, CLI-only; one operator (trust domain) with nested accounts and users, public data only. Deterministic: validity boundaries are absolute RFC3339 `expires`/`not_before` fields (no relative TTLs); omitted expires = never expires. Scopes are list-only; user scopes must be covered by account scopes. `bearer: true` users mint token-only creds; without a `key` they get a throwaway pair whose seed is discarded.
- `main.go` — stateless CLI: `keygen operator|account|user`, `creds ACCOUNT[/USER]`. Signing seeds come from `VALISS_SEED_<PUBKEY>` env vars (missing var = hard error naming it); entries without a manifest `key` get a fresh pair per invocation, seed shipped only in the creds. Creds → stdout, metadata (allowlist jti) → stderr. User creds carry only the user token by default (needs just the account seed); `-bundle` embeds a fresh account token too (needs the operator seed, mints a new allowlist jti).

Authorization is scope-based: `call:<gRPC full method>` or `call:<HTTP path>`, with trailing-`*` prefix wildcards (`Claims.Authorizes`, `token.Covered`). Enforcement is opt-in per transport: `grpcauth.WithMethodScope()`, `httpauth.WithPathScope()` / `WithScopeMapper()`.

## Conventions

- Error messages are prefixed `valiss:`.
- Key levels are strict: operator keys sign account tokens, account keys sign user tokens and never the reverse; every token's `sub` is a key of the right type (no keyless subjects). Do not weaken account keys to user-type keys; delegation depends on every tenant holding an account key.
- Consumers extend tokens via `WithExtension(v)` (signed `ext` claim, opaque to valiss) and validate with `ExtValidator` or `Ext[T]` against `Claims.AccountExt`/`UserExt`.
- Terminology: *creds* = the credentials file (subject token + seed); *bundle* = user creds that also carry the upstream account token (`creds -bundle`). Each bundle mint signs a fresh account token and thus produces a new account jti for the allowlist; surface it in any tooling output.
- Tests use `token.WithClock` to inject time; prefer that over sleeping.
- `keygen` writes the key pair to stdout and guidance to stderr so redirected output stays parseable; keep that separation.

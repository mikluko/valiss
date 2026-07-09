# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

valiss (VALidator-ISSuer) is a Go library for tenant authentication in gRPC and HTTP services, modeled on NATS operator/account/user credentials. Module: `github.com/mikluko/valiss`, root package `valiss`. Library-first: there is no product binary, only `examples/`. No Makefile or lint config; plain Go toolchain. Only real dependencies: nkeys, yaml, grpc; tokens are hand-rolled nkey-signed JWTs (no NATS jwt library).

## Commands

```sh
go build ./...                       # build everything
go test ./...                       # full test suite
go test . -run TestVerifyRequest    # single test in the root package (testify throughout)
go vet ./...
go run ./examples/minter keygen operator  # the example CLI
go run ./examples/grpcauth             # end-to-end demo (also ./examples/httpauth)
```

## Architecture

Three-level trust chain modeled on NATS, all rooted in Ed25519 nkeys: an **operator** (`SO...`/`O...`) signs **account** (tenant, `SA...`/`A...`) tokens; an account may sign **user** (`SU...`/`U...`) tokens. Servers pin only the operator public key.

Tokens are valiss's own typed claims (claims.go): RFC 7519 standard fields plus a `valiss` section (`type`, `scopes`, `bearer`, and named `ext` extensions). As in NATS, `sub` is the subject's public key (no keyless subjects) and `name` carries the human label. Validity is absolute and optional: no `exp` = never expires (nsc default); `nbf` supported.

Per-request verification (`valiss.Verifier.VerifyRequest`, takes a `valiss.Request` of the four header values):

1. **Account token**: checked against the pinned operator key, expiry, activation, type, and subject key shape.
2. **Allowlist**: the *account* token's jti must be in a server-side `valiss.Allowlist`; removal revokes before expiry. User tokens are not allowlisted — revocation is account-wide, user-level revocation relies on short validity windows.
3. **User token** (optional chain): account-signed, verified against the account token's subject key. Effective scopes = user scopes clamped to the account's grants. A request may carry only the user token (the default for user creds); the server then resolves the account token via `WithAccountTokenResolver` (`StaticAccountTokens` helper) and runs the same checks.
4. **Custom validators**: `WithClaimsValidator` hooks run after chain assembly and before the signature check, in registration order; first error rejects. `ExtValidator(name, fn)` adapts a typed validator over a named extension.
5. **Request signature**: the client signs an RFC3339Nano timestamp with its seed, verified against the effective subject key within a skew window (`valiss.DefaultSkew`, 2m). User tokens minted with `WithBearer` may skip it (replayable, token-only); account tokens never may.

Extensions (`valiss.Extensions`, `WithExtension(name, v)`) are named, signed, opaque-to-core claim payloads on either token level. Transport authorization is built on them and enforced in the transports, not in the core: `contrib/httpauth.Ext` (hosts/methods/paths, name `http`) and `contrib/grpcauth.Ext` (methods, name `grpc`), each with a `WithExt` issuance sugar. Extensions present at both chain levels are both enforced (AND), so an account extension bounds all its users. Paths/methods use trailing-`*` prefix wildcards via `valiss.Covered`.

Layout:

- root — token issue/verify (`Issue`/`IssueUser`, `VerifyAccount`/`VerifyUser`/`Decode`), `SignRequest`/`VerifySignature`, `Allowlist`, `Verifier`, extension plumbing, `TenantFromContext`. `VerifyAccount`/`VerifyUser` deliberately do NOT check expiry or allowlist; `Verifier` layers those so callers get precise errors.
- `creds` — client creds file (`Creds`: optional account token + optional user token + optional seed; at least one token), nsc-creds-style markers. A *bundle* is user creds that also embed the account token; bearer creds have no seed.
- `contrib/httpauth`, `contrib/grpcauth` — transport adapters over `valiss.Verifier`: header extraction, error mapping (401/403, Unauthenticated/PermissionDenied), extension enforcement, client-side attachment, all constructed from a `creds.Creds`. Wire headers: `valiss-account-token`, `valiss-user-token`, `valiss-timestamp`, `valiss-signature` (`valiss.Header*` constants).
- `examples/minter` — the manifest-driven minting tool (single-file, manifest types included), an example rather than a product. Deterministic manifest (`minter.yaml`): one operator, nested accounts/users by `name`, absolute RFC3339 `expires`/`not_before`, seeds only from `VALISS_SEED_<PUBKEY>` env vars. Creds → stdout, metadata (allowlist jti) → stderr; `-bundle` embeds a fresh account token.

## Conventions

- Error messages are prefixed `valiss:`.
- Key levels are strict: operator keys sign account tokens, account keys sign user tokens, never the reverse; every token's `sub` is a key of the right type. Do not weaken account keys to user-type keys; delegation depends on every tenant holding an account key.
- Scopes are consumer-defined strings; the library only clamps user scopes to the account's. Transport authorization belongs in typed extensions, never in scope-string conventions.
- Terminology: *creds* = the credentials file (subject token + seed); *bundle* = user creds that also carry the upstream account token.
- Tests use `valiss.WithClock` to inject time; prefer that over sleeping.
- The example CLI's `keygen` writes the key pair to stdout and guidance to stderr so redirected output stays parseable; keep that separation.

# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

valiss (VALidator-ISSuer) is a Go library for decentralized tenant authentication in gRPC and HTTP services: a three-level chain of Ed25519 keys (operator → account → user). Module: `github.com/mikluko/valiss`, root package `valiss`. Library-first: there is no product binary, only `examples/`. No Makefile or lint config; plain Go toolchain. Only real dependencies: nkeys, yaml, grpc; tokens are hand-rolled nkey-signed JWTs.

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

Three-level trust chain rooted in Ed25519 nkeys: an **operator** (`SO...`/`O...`) signs **account** (tenant, `SA...`/`A...`) tokens; an account may sign **user** (`SU...`/`U...`) tokens. A user key may additionally mint per-message **message tokens** (`IssueMessage`/`VerifyMessage`, message.go): self-signed (`iss == sub`), expiry-mandatory proofs of origin binding a destination (`aud`), a payload checksum, and the epoch, offline-verifiable against the operator public key with the chain embedded (`WithChain`) or supplied out-of-band (`WithChainTokens`); `At(t)` verifies stored messages as of a past instant. Servers pin only the operator public key. The operator may additionally publish a self-signed **operator token** (`IssueOperator`) carrying domain policy: an `epoch` counter plus an optional validity window; `WithOperatorToken` on the verifier enforces that every account and user token echoes the current epoch (`WithEpoch` at mint), making an epoch bump + re-mint a cryptographic mass revocation, and the operator token's own `exp` a domain-wide expiry.

Tokens are valiss's own typed claims (claims.go): RFC 7519 standard fields plus a `valiss` section (`type`, `epoch`, `bearer`, and named `ext` extensions). `sub` is the subject's public key (no keyless subjects) and `name` carries the human label. Validity is absolute and optional: no `exp` = never expires; `nbf` supported. Go-side, the base `Claims` struct is RFC-only (jti/iss/sub/iat/exp/nbf); `OperatorClaims`, `AccountClaims{Claims, Name, Epoch, Ext}` and `UserClaims{Claims, Name, Epoch, Bearer, Ext}` embed it via the golang-jwt-style registered-claims pattern.

Per-request verification (`valiss.Verifier.VerifyRequest(Request) (*Identity, error)`, where `Identity{Account *AccountClaims, User *UserClaims}` and `User` is nil for account-level requests):

1. **Account token**: checked against the pinned operator key, expiry, activation, type, and subject key shape.
2. **Allowlist**: the *account* token's jti must be in a server-side `valiss.Allowlist`; removal revokes before expiry. User tokens are not allowlisted — revocation is account-wide, user-level revocation relies on short validity windows.
3. **User token** (optional chain): account-signed, verified against the account token's subject key. A request may carry only the user token (the default for user creds); the server then resolves the account token via `WithAccountTokenResolver` (`StaticAccountTokens` helper) and runs the same checks.
4. **Request signature (proof of possession)**: the client signs an RFC3339Nano timestamp bound to `Request.Context` — the transport's canonical request description — with its seed, verified against the effective subject key (user sub when the chain is present) within a skew window (`valiss.DefaultSkew`, 2m). Binding the context stops a captured signature from authorizing a different operation: `contrib/httpauth` binds `method\nhost\npath[\nnonce]`, `contrib/grpcauth` binds the full method (client reads it from `credentials.RequestInfoFromContext`, server from `info.FullMethod`). User tokens minted with `WithBearer` may skip the signature (replayable within the window, token-only); account tokens never may. This runs **before** the consumer hooks below, so a party that captured a token but cannot sign never triggers them. Optional same-request replay suppression: `WithReplayCache(ReplayCache)` on the verifier plus the transport's `WithNonce()` on the client; the nonce (`valiss-nonce` header) is folded into the signed context, and `NewMemoryReplayCache` is a process-local implementation (shared storage needed for multi-instance exactly-once).
5. **Registered extension types**: `WithExtensionType[T]()` eagerly decodes T's extension on both levels when present, rejecting malformed claims at auth time.
6. **Custom validators**: `WithClaimsValidator(func(Request, *Identity) error)` hooks run last, in registration order; first error rejects. `ExtValidator[T](fn)` adapts a typed validator over T's extension on both levels.

Extensions are self-naming: `Extension interface{ ExtensionName() string }`, minted with `WithExtension(v Extension)` (name from the value), recovered with `ExtOf[T Extension](exts) (T, bool, error)`. All authorization rides them — there are no scopes. Transport enforcement lives in the transports, not the core: `contrib/httpauth.Ext` (hosts/methods/paths, name `http`) and `contrib/grpcauth.Ext` (methods, name `grpc`), minted via plain `valiss.WithExtension(Ext{...})`. Enforcement is fail-closed (issue #2): every token in the chain must carry the transport extension unless `AllowMissingExtension()` is set on the authenticator/middleware; an empty grant (`grpcauth.Ext{}`, zero-value `httpauth.Ext{}`) grants nothing; allow-all is the explicit `"*"` wildcard. A non-zero `httpauth.Ext` leaves its empty dimensions unconstrained. Extensions present at both chain levels are both enforced (AND), so an account extension bounds all its users. Paths/methods use trailing-`*` prefix wildcards via `valiss.Covered`.

Layout:

- root — token issue/verify (`Issue`/`IssueUser`/`IssueMessage`, `VerifyAccount`/`VerifyUser`/`VerifyMessage`/`Decode`), `SignRequest`/`VerifySignature`, `Allowlist`, `Verifier`, extension plumbing, `IdentityFromContext`. `VerifyAccount`/`VerifyUser` deliberately do NOT check expiry or allowlist; `Verifier` layers those so callers get precise errors. `Decode` returns RFC-only `Claims` without establishing trust (tooling).
- `creds` — client creds file (`Creds`: optional account token + optional user token + optional seed; at least one token), marker-delimited text. A *bundle* is user creds that also embed the account token; bearer creds have no seed.
- `contrib/httpauth`, `contrib/grpcauth` — transport adapters over `valiss.Verifier`: header extraction, error mapping (401/403, Unauthenticated/PermissionDenied), extension enforcement, client-side attachment, all constructed from a `creds.Creds`. Wire headers: `valiss-account-token`, `valiss-user-token`, `valiss-timestamp`, `valiss-signature` (`valiss.Header*` constants). Each also carries the message-token pair (`valiss-message-token` header): httpauth `NewMessageTransport`/`NewMessageMiddleware` (audience = host + path, checksum over the body), grpcauth `MessageUnaryClientInterceptor`/`MessageUnaryServerInterceptor` (audience = full method, checksum over the deterministic protobuf encoding); emitters need bundle creds with the user seed, the epoch is derived from the chain tokens, and handlers read claims with `valiss.MessageFromContext`.
- `examples/minter` — the manifest-driven minting tool (single-file, manifest types included), an example rather than a product. Deterministic manifest (`minter.yaml`): one operator, nested accounts/users by `name`, absolute RFC3339 `expires`/`not_before`, seeds only from `VALISS_SEED_<PUBKEY>` env vars. Creds → stdout, metadata (allowlist jti) → stderr; `-bundle` embeds a fresh account token.

## Conventions

- Error messages are prefixed `valiss:`.
- Key levels are strict: operator keys sign account tokens, account keys sign user tokens, user keys sign message tokens, never the reverse; every token's `sub` is a key of the right type. Do not weaken account keys to user-type keys; delegation depends on every tenant holding an account key.
- Message tokens are proofs of origin, never credentials: possession grants nothing, `Verifier.VerifyRequest` does not accept them, and no verify path may treat one as bearer authentication.
- All authorization lives in typed extension claims (transport or domain); there is no scope-string mechanism. Base `Claims` stays RFC 7519-only; anything valiss-specific goes on the typed claim structs or into extensions.
- Terminology: *creds* = the credentials file (subject token + seed); *bundle* = user creds that also carry the upstream account token.
- Tests use `valiss.WithClock` to inject time; prefer that over sleeping.
- Influences (NATS/nsc, RFC 7519, golang-jwt, Biscuit/Macaroons, SPIFFE) are acknowledged in the README's Prior art section only; do not describe valiss as "NATS-like" or "modeled on NATS" in docs or comments.
- `CHANGELOG.md` (Keep a Changelog format) is the source of truth for release notes; add user-facing changes to its `[Unreleased]` section as you make them, flagging breaking changes with **Breaking** and a migration line. At release, rename the section to the version + date, add compare links, and paste that section as the GitHub Release body.
- The example CLI's `keygen` writes the key pair to stdout and guidance to stderr so redirected output stays parseable; keep that separation.

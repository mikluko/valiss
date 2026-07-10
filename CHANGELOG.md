# Changelog

All notable changes to valiss are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version is below 1.0 the API and wire format are not yet stable:
breaking changes may land in minor releases and are flagged **Breaking** below.

## [Unreleased]

## [0.7.0] - 2026-07-10

### Changed

- **Breaking.** The per-request signature is now bound to the transport's
  request context, not the timestamp alone: `SignRequest` and
  `VerifySignature` take a `context []byte`, and `valiss.Request` gains a
  `Context` field the transport fills. `contrib/httpauth` binds
  method/host/path; `contrib/grpcauth` binds the full method. A captured
  signature can no longer authorize a different operation.
  *Migration:* signatures from pre-Unreleased clients no longer verify;
  upgrade client and server together. (#6)

### Added

- Opt-in same-request replay suppression: `WithReplayCache(ReplayCache)` on
  the verifier plus the client transport's `WithNonce()`
  (`httpauth.NewTransport`, `grpcauth.NewCredentials`). The nonce
  (`valiss-nonce` header) is folded into the signed context. `ReplayCache` is
  the pluggable interface; `NewMemoryReplayCache` is a process-local
  implementation (shared storage needed for multi-instance exactly-once);
  `NewNonce` generates the client value. (#7)

### Fixed

- The creds file parser now requires each section's `END` marker: an empty,
  unclosed, or multi-line section is an error, so a truncated or mangled creds
  file fails at parse time instead of downstream as a confusing cryptographic
  error. (#5)

### Security

- Consumer validators (`WithClaimsValidator`) and eager extension checks now
  run **after** the request signature proves possession of the subject seed,
  so a party that captured a token but cannot sign never triggers them. (#4)
- Cross-endpoint / cross-method replay is closed by request-context binding
  (see Changed, #6).
- Same-request replay within the skew window can be suppressed with the
  optional nonce + replay cache (see Added, #7).

## [0.6.0] - 2026-07-10

### Added

- Self-signed operator tokens for domain rotation and mass revocation.
  `IssueOperator(operator, ...)` mints a policy statement signed by the anchor
  key over itself, carrying an explicit `epoch` counter (`WithEpoch`) and an
  optional validity window. `WithOperatorToken(token)` on the verifier
  requires every account and user token to echo the current epoch and bounds
  the whole domain by the operator token's own `exp`; bumping the epoch and
  re-minting revokes everything from earlier epochs with no allowlist edits.
  A misconfigured operator token fails every request loudly. Tokens without an
  epoch stamp are epoch 0, so existing setups keep working; epochs are ignored
  unless `WithOperatorToken` is configured. (#3)
- README "Prior art" section (NATS/nsc, RFC 7519, RFC 8032, golang-jwt,
  Biscuit/Macaroons, SPIFFE). The "modeled on NATS" framing was dropped from
  docs and comments.

## [0.5.1] - 2026-07-09

### Changed

- **Breaking.** Transport extension enforcement is fail-closed: every token in
  the chain must carry the transport extension (`http` / `grpc`) or the request
  is denied. An empty grant grants nothing (`grpcauth.Ext{}` and the zero-value
  `httpauth.Ext{}` deny everything); allow-all is the explicit wildcard
  (`Methods: ["*"]`, `Paths: ["*"]`). A non-zero `httpauth.Ext` still leaves its
  empty dimensions unconstrained.
  *Migration:* attach wildcard extensions, or set `AllowMissingExtension()` on
  `grpcauth.NewAuthenticator` / `httpauth.NewMiddleware` when authorization
  lives entirely outside the transport. (#2)

### Security

- Closes the previous fail-open behavior where a token without the transport
  extension authorized every request. (#2)

## [0.5.0] - 2026-07-09

### Changed

- **Breaking.** valiss is now a pure library. Core moved to the module root
  (package `valiss`), `creds/` sits beside it, transports moved to
  `contrib/httpauth` and `contrib/grpcauth`; the CLI became `examples/minter`.
- **Breaking.** The base `Claims` struct carries only RFC 7519 registered
  claims (`jti`, `iss`, `sub`, `iat`, `exp`, `nbf`); `AccountClaims` and
  `UserClaims` embed it. `VerifyRequest` returns `Identity{Account, User}`;
  handlers use `valiss.IdentityFromContext`.
- **Breaking.** Tokens are hand-rolled nkey-signed JWTs; the `nats-io/jwt`
  dependency was dropped, changing the token wire format.

### Added

- Named, self-describing extension claims carry all authorization. An
  extension is any struct with `ExtensionName() string`: mint with
  `valiss.WithExtension(v)`, recover with `ExtOf[T]`, validate with
  `ExtValidator[T]` or eagerly with `WithExtensionType[T]`. Transport
  extensions (`httpauth.Ext`, `grpcauth.Ext`) enforce at both chain levels.

### Removed

- **Breaking.** Scopes, the `call:` convention, `WithMethodScope`, and
  `WithPathScope`. Authorization lives entirely in typed extensions.
- The Homebrew formula is retired; install as a library with
  `go get github.com/mikluko/valiss` and run the example CLI via
  `go run ./examples/minter`.

*Migration:* reissue tokens (wire format changed); replace scope-based
authorization with typed extensions; update imports to the new layout.

## [0.4.0] - 2026-07-09

### Changed

- **Breaking.** Account-token naming made consistent across every layer: creds
  markers `BEGIN/END VALISS ACCOUNT TOKEN`; fields `creds.Creds.AccountToken`
  and `token.Request.AccountToken`; wire headers `valiss-account-token`,
  `valiss-user-token`, `valiss-timestamp`, `valiss-signature` (the `tenant-`
  prefix was wrong for user-signed requests); the bound-key JWT claim is
  `subject_key`. `token.Credential` → `token.Request`, verified by
  `Verifier.VerifyRequest`; the former signature-only `VerifyRequest` is
  `VerifySignature`.

*Migration:* wire header names, creds file format, and previously issued
tokens are all incompatible with 0.3.0; reissue tokens and creds.

## [0.3.0] - 2026-07-09

### Changed

- **Breaking.** `creds.Bundle` → `creds.Creds`; the account-token section is
  optional (at least one token required). User creds carry only the user token
  by default and are mintable with the account seed alone; `-bundle` opts into
  embedding a fresh account token. Transports omit the tenant-token header when
  absent and reject only when both tokens are missing.

### Added

- `WithAccountTokenResolver` (`StaticAccountTokens` helper) lets a server
  resolve account tokens from configuration and accept user-token-only
  requests; resolved tokens pass the same signature, expiry, and allowlist
  checks.

## [0.2.1] - 2026-07-09

### Changed

- **Breaking (manifest).** The manifest describes one trust domain: the top
  level is a mapping (`operator:` + `accounts:`) instead of a list of operator
  blocks. The library API is unchanged.

## [0.2.0] - 2026-07-09

### Added

- Three-level credentials: operator → account → user. Accounts sign scoped
  user tokens; servers verify the chain against the pinned operator key.
- Per-entity `valiss creds ACCOUNT[/USER]` minting from a manifest tree; seeds
  resolve from `VALISS_SEED_<PUBKEY>` environment variables.
- `valiss-user-token` header and bundle-carried user tokens.
- `WithClaimsValidator` for custom validation in the verification pipeline.

### Changed

- **Breaking.** `keygen issuer|tenant` → `keygen operator|account|user`;
  `VerifyCredential` takes a `Credential` struct; `creds.Format/Parse/Load`
  use `Bundle`; transport constructors are bundle-driven.

### Removed

- **Breaking.** The batch `issue` command (replaced by `creds`).

## [0.1.0] - 2026-07-09

### Added

- Initial release: NATS-style tenant authentication for gRPC and HTTP. An
  issuer nkey signs scoped, time-limited tenant tokens; tenants sign each
  request with their nkey; servers verify the token, allowlist membership, and
  request signature, then hand the tenant identity to the handler. Library
  under `pkg/` (token, creds, grpcauth, httpauth) with a stateless CLI.

[Unreleased]: https://github.com/mikluko/valiss/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/mikluko/valiss/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/mikluko/valiss/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/mikluko/valiss/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/mikluko/valiss/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/mikluko/valiss/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/mikluko/valiss/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/mikluko/valiss/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/mikluko/valiss/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mikluko/valiss/releases/tag/v0.1.0

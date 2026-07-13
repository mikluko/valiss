# Verifying valiss tokens without the library

valiss tokens are structurally JWTs but **not verifiable with stock JWT
libraries**: the algorithm identifier and key encoding are valiss-specific
(see the README's Interoperability section for why). This document is the
complete recipe for porting verification to another language. Everything
here is derivable from the Go source; the source is canonical if they ever
disagree.

## Wire format

A token is JWS Compact Serialization: `base64url(header) "."
base64url(payload) "." base64url(signature)`, no padding.

Header, byte-exact:

```json
{"typ":"JWT","alg":"ed25519-nkey"}
```

Payload is a JSON object with RFC 7519 field names, all optional except
`valiss`, serialized in this order:

| field | meaning |
|---|---|
| `jti` | content-derived token id (see below) |
| `iat` | mint time, Unix seconds |
| `iss` | issuer public key, nkey-encoded |
| `name` | optional human label of the subject |
| `sub` | subject public key, nkey-encoded |
| `aud` | destination identity (message tokens) |
| `exp` | expiry, Unix seconds; absent = never expires |
| `nbf` | not-before, Unix seconds; absent = immediately valid |
| `valiss` | the level-specific claim body |

The `valiss` section is discriminated by its `type` field:

- `operator` — `{type, epoch?, ext?}`; self-signed (`iss == sub`).
- `account` — `{type, epoch?, ext?}`; signed by an operator key.
- `user` — `{type, epoch?, bearer?, ext?}`; signed by an account key.
- `message` — `{type, epoch?, checksum?, chain?, ext?}`; self-signed by a
  user key. `checksum` is the lowercase-hex SHA-256 of the message payload.
  `chain` is `{account, user}`: the embedded provenance tokens, verbatim.

`ext` is an object of named, consumer-defined claim payloads; transport
carries them opaquely.

## Signature

Standard Ed25519 (RFC 8032) over the signing input
`base64url(header) "." base64url(payload)` — the ASCII bytes, exactly as
they appear in the token. The signature part is the raw 64-byte Ed25519
signature, base64url-encoded without padding. Any Ed25519 implementation
verifies it once you extract the raw public key from the nkey encoding.

## Decoding an nkey public key

`iss` and `sub` carry public keys in the NATS nkey text format:

```
base32( prefix_byte || raw_ed25519_public_key[32] || crc16_le[2] )
```

- Base32: RFC 4648 alphabet, uppercase, no padding.
- Prefix byte encodes the key role: operator `112` (renders as leading
  `O`), account `0` (`A`), user `160` (`U`).
- CRC16: CCITT/XMODEM (polynomial 0x1021, init 0x0000), computed over
  `prefix || key`, appended little-endian.

To decode: base32-decode, check length 35, verify the trailing CRC16 over
the first 33 bytes, check the prefix byte matches the role required by
context, take bytes 1..33 as the raw Ed25519 public key.

Role requirements are strict: an operator key signs account tokens, an
account key signs user tokens, a user key signs message tokens; operator
and message tokens are self-signed (`iss == sub`).

## jti derivation

`jti` is content-derived, not random: serialize the payload with `jti`
omitted (every field is omit-when-empty), SHA-256 the JSON bytes, and
base32-encode the digest (RFC 4648, uppercase, no padding). Reproducing it
requires byte-identical JSON: fields in the table's order, no whitespace,
and Go `encoding/json` escaping rules (which HTML-escape `<`, `>`, and
`&`) — re-deriving from a reparsed payload is only possible if your
serializer reproduces that exact shape. Two tokens with identical claims minted within the same
second therefore share a `jti`; the keyring's registration dedup relies on
this. Verifiers that only check signatures may treat `jti` as opaque.

## Verifying a token (one level)

1. Split on `.`; require exactly three parts.
2. Base64url-decode the header; require `typ == "JWT"` and
   `alg == "ed25519-nkey"`.
3. Base64url-decode the payload; parse JSON.
4. Decode the `iss` nkey; verify the Ed25519 signature over
   `part1 "." part2`.
5. Require `valiss.type` to match the expected level, `iss` to equal the
   expected issuer key (established by the level above, or pinned), and
   `sub` to be a valid nkey of the level's subject role.

This establishes authenticity only. Trust and freshness are chain-level
checks below. Validity windows: a token is expired when
`now > exp + skew`, not yet valid when `now + skew < nbf`; absent fields
impose nothing. valiss uses a default skew of 2 minutes.

## Verifying a message token (full chain)

Given a message token, the operator public key(s) you trust, and the
received payload bytes:

1. Verify the message token per above: `type == "message"`, `iss == sub`,
   `sub` is a user-role nkey.
2. Obtain the chain: `valiss.chain` embedded in the token, or supplied out
   of band. If both exist they must match byte-for-byte.
3. Verify the chain account token: `type == "account"`, signed by a
   trusted operator key, `sub` an account-role nkey.
4. Verify the chain user token: `type == "user"`, `iss` equal to the
   account token's `sub`, `sub` a user-role nkey.
5. Require the chain user token's `sub` to equal the message token's
   `iss` — the chain must delegate to exactly the key that signed the
   message.
6. Require all three tokens to agree on `valiss.epoch` (absent = 0). If
   you hold the domain's self-signed operator token, additionally require
   the message epoch to equal its epoch and the operator token to be
   within its own validity window.
7. Check all three validity windows at the verification instant — for
   stored messages, the instant of receipt, not now.
8. If the token carries `aud`, require it to equal the destination you are
   verifying for. Reject tokens without `aud` if you expect one.
9. Require `valiss.checksum` to equal the lowercase-hex SHA-256 of the
   payload exactly as received.

A verified message token proves origin only. It is not a credential:
grant nothing for possession of one.

## Verifying a request signature (httpauth/grpcauth)

Per-request proof of possession, separate from tokens. The client sends a
timestamp (RFC 3339 with nanoseconds, UTC) and a signature
(base64 **standard** encoding, unlike the token's base64url). The signed
payload is:

```
timestamp + "\n" + lowercase_hex(sha256(request_context))
```

where `request_context` is the transport's canonical request description:
`"http\n" method "\n" host "\n" path "\n" nonce` for HTTP,
`"grpc\n" full_method "\n" nonce` for gRPC (empty nonce when replay
suppression is off). Verify the Ed25519 signature against the effective
subject key (the user token's `sub` when a chain is present, else the
account token's `sub`) and bound the timestamp to a skew window around
now.

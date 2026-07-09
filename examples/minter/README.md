# minter

A manifest-driven credential minting tool for valiss, and a worked example
of the issuance API. It is stateless by design: key pairs are printed once
and never stored, signing seeds are supplied through environment variables,
and the manifest holds public data only, so it is safe to commit.

```sh
go run ./examples/minter <command>
# or: go build -o minter ./examples/minter
```

## Commands

```
minter keygen operator     # one-time: the trust anchor key pair
minter keygen account      # per-tenant key pair
minter keygen user         # per-end-user key pair
minter creds ACCOUNT[/USER]  # mint credentials for a manifest entry
    -f FILE                  # manifest path (default minter.yaml)
    -bundle                  # embed a fresh account token in user creds
```

`keygen` prints the pair to stdout and handling guidance to stderr, so
redirected output stays parseable. Seeds cannot be recovered: preserve them
in a secrets manager as `VALISS_SEED_<PUBLIC-KEY>` environment variables.

## Workflow

1. Generate the operator key and pin its public key in your servers:

   ```sh
   minter keygen operator
   export VALISS_SEED_O...=SO...
   ```

2. Generate a key pair per tenant and describe the tree in `minter.yaml`
   (annotated example in this directory):

   ```yaml
   operator: O...
   accounts:
     - name: acme
       key: A...
       scopes: ["widgets"]          # consumer-defined strings
       expires: 2026-12-31T00:00:00Z # optional; absent = never expires
       users:
         - name: alice              # no key: fresh pair minted every run
         - name: carol
           bearer: true             # token-only creds, no seed handed out
   ```

3. Mint credentials. The creds file goes to stdout; metadata — including
   the account token `jti` your server-side allowlist must accept — goes to
   stderr as YAML:

   ```sh
   minter creds acme          > acme.creds   # account-level creds
   minter creds acme/alice    > alice.creds  # user creds (lean: user token + seed)
   minter creds -bundle acme/alice           # + embedded account token
   ```

Lean user creds need only the account seed in the environment (`-bundle`
also needs the operator seed) and expect the server to resolve account
tokens itself — see `valiss.WithAccountTokenResolver`. Validity boundaries
are absolute timestamps, so re-minting against the same manifest yields the
same window.

## What it deliberately does not do

- No state: nothing is written anywhere, every invocation derives entirely
  from the manifest and the environment.
- No extension claims: typed extensions (`contrib/httpauth`,
  `contrib/grpcauth`, or your own) are a programmatic-issuance feature; see
  the grpcauth and httpauth examples.
- No key custody: seeds pass through the environment and the emitted creds
  files only.

# Architecture

This document describes the **Rust workspace** under `crates/`: the active
implementation of Daemon Wallet. The JavaScript tree under `packages/` is the
original proof of concept (POC) being ported from; it is the working reference,
not the forward path. See the README for the product-level picture (a
KeePassXC-style EVM wallet where keys live in a local daemon and every signature
is approved in the terminal).

The design intent for the not-yet-filled crates lives in the module
doc-comments (`//!`) in `crates/**/src/*.rs`; this document summarises it.

## The four crates

The workspace is edition 2024, resolver 3, and splits into four layers:

| Crate | Responsibility |
|---|---|
| `daemon-wallet-vault` | A byte-generic encrypted secret store. Maps an entry id to opaque secret bytes plus metadata. Knows nothing about wallets. **Done.** |
| `daemon-wallet-core` | Chain-agnostic wallet organisation and persistence: the group tree, seeds, imported keys, accounts, and the manifest. Depends only on the vault and serde. |
| `daemon-wallet-evm` | The EVM half: implements core's `Chain` trait, owns the alloy transaction/signature types, and hosts a pinned EVM chain-info registry. The only crate that names an alloy type. |
| `daemon-wallet-protocol` | The plug-in wire contract between the daemon and its clients (extension, CLI, app): request/response envelopes and DTOs, plus a typed client over a `Transport` trait. |

All crates are implemented and tested: the vault, the chain-agnostic core, the
EVM chain, the typed protocol wire with its unix-socket transport, and the
application layer (config, rpc, cli, tui, daemon). The daemon exposes both a
Chrome native-messaging host and a unix-socket control channel for the CLI.

## Dependency direction

```
  vault  ──▶  core  ──▶  evm  ──▶  protocol
(foundation)                        (edge)
```

Each crate depends only on the ones to its left; nothing points back. Concretely:

- `core` depends on `vault` and serde, and has **no** `alloy-primitives`
  dependency.
- `evm` depends on `core`, `vault`, and `alloy-primitives`. Core does not depend
  on `evm` or on alloy; the coupling points one way only.
- `protocol` sits at the edge and speaks in DTOs rather than internal domain
  types, so the domain can evolve without breaking the wire.

## Chain-agnostic core and the `Chain` seam

Core owns how a wallet is *organised* and *persisted* but knows nothing about how
any particular chain derives an address or shapes a signature. Everything
chain-specific is expressed through one narrow, **object-safe** trait and reached
through a registry:

```
         daemon-wallet-core                         daemon-wallet-evm
  ┌──────────────────────────────┐          ┌──────────────────────────────┐
  │  Wallet                      │          │  EvmChain : Chain            │
  │   ├─ Vault (secret bytes)    │          │   ├─ derive_address          │
  │   ├─ WalletManifest (meta)   │  dyn     │   ├─ import_address          │
  │   └─ ChainRegistry ──────────┼────────▶ │   ├─ sign                    │
  │        BTreeMap<ChainKind,   │ dispatch │   ├─ parse/format_address    │
  │          Box<dyn Chain>>     │          │   └─ (alloy types live here) │
  └──────────────────────────────┘          └──────────────────────────────┘
```

- **`Chain`** is deliberately object-safe: `&self` only, no generic methods, no
  `Self` by value, concrete argument/return types. That lets the registry store
  implementations as `Box<dyn Chain>` and dispatch at runtime.
- **`ChainRegistry`** is a `BTreeMap<ChainKind, Box<dyn Chain>>` dispatch table.
  The application builds one, registers each chain crate's implementation, and
  hands it to `Wallet::create` / `Wallet::open`. The wallet then routes every
  per-account derivation and signature through it.
- **`ChainKind`** is the routing key (currently just `Evm`). It is
  `#[non_exhaustive]` so that shipping a new family is a non-breaking change.

Adding a new chain family (say Solana or Bitcoin) touches **no core code**: it is
a sibling crate that implements `Chain` for its own type, converts to and from
the neutral address at its own boundary, and is registered at startup. A new
`ChainKind` variant is the only addition to core. `daemon-wallet-evm` is exactly
this pattern.

## The neutral/alloy boundary

Core never interprets address bytes. An account's address is the neutral
`ChainAddress`: a canonical **string** (a checksummed `0x…` for EVM, base58 for
a future Solana chain, etc.). This is the concrete reason core carries no
`alloy-primitives` dependency.

Conversion between that neutral string and alloy's native `Address` is confined
to `daemon-wallet-evm` (`evm_chain.rs`): `to_alloy_address` parses inbound,
`from_alloy_address` renders outbound (checksummed). Nothing above the evm crate
ever sees an alloy type. Similarly, signing requests cross as chain-tagged,
opaque `SigningPayload`s (a `ChainKind`, a `PayloadKind`, and a `body: Vec<u8>`
that core never parses) rather than typed transactions.

> Note: `evm` also hosts a separate `ChainInfoRegistry`: EVM *metadata* (chain
> id, name, symbol, RPC urls), distinct from core's `ChainRegistry`. It validates
> externally sourced chain lists (HTTPS-only RPCs; built-in ids are immutable so
> a hostile entry cannot rebind chain id `1`) but performs no network I/O itself.

## Manifest ↔ vault-entry mapping

A `Wallet` is persisted across several vault entries under a fixed naming scheme.
The manifest holds only metadata and the ids that route to secrets; the secret
bytes live in their own entries.

```
  Vault entries                              WalletManifest (CBOR, no secrets)
  ────────────────────────────────          ────────────────────────────────
  wallet/manifest  ─ CBOR manifest ───────▶  version
  seed/<SeedId>    ─ mnemonic bytes          group tree
  seed/<SeedId>    ─ mnemonic bytes          seeds:    BTreeMap<SeedId, SeedSource>
  key/<KeyId>      ─ private scalar          keys:     BTreeMap<KeyId, ImportedKey>
                                             accounts: BTreeMap<AccountId, Account>
```

- **One manifest entry** at the fixed id `wallet/manifest` holds the CBOR
  encoding of the whole organisational state (group tree, seeds, keys, accounts).
  It contains no secret material.
- **One secret entry per seed** (`seed/<id>`) holds that seed's mnemonic.
- **One secret entry per imported key** (`key/<id>`) holds that key's raw private
  scalar.

So a wallet with two seeds and one imported key occupies exactly four entries:
`wallet/manifest`, two `seed/<id>`, and one `key/<id>`. Secret entry ids are
deterministic in the seed/key id, so no separate index is needed. This split
keeps each secret independently addressable (fetch exactly the one key a
signature needs) while the bulky, frequently rewritten manifest travels as a
single blob that is cheap to re-encode on every save. The vault encrypts every
entry's secret bytes; an entry's id and metadata are treated as addressing, not
secret.

## Application layer and the two daemon channels

Above the libraries sit the binaries and their support crates:

- `daemon-wallet-config`: shared wallet-home/vault paths and the network list
  (look up a network by name or by chain id).
- `daemon-wallet-rpc`: a blocking JSON-RPC client plus EIP-1559 tx assembly and
  broadcast; the only app-layer crate (besides `evm`) that names an alloy type.
- `daemon-wallet-cli`: wallet management (create/import/derive/sign/send/export,
  with `send --chain`) and, via the `daemon` subcommands, a control client.
- `daemon-wallet-tui`: a ratatui console over the same core API.
- `daemon-wallet-daemon`: two channels over one core:
  - **native-messaging host** (default, how Chrome launches it): the
    4-byte-length + JSON wire the extension speaks, with terminal approval for
    every connect/sign/send. Sends route to the RPC for the request's `chainId`.
  - **control socket** (`serve`): a unix socket speaking the typed
    `daemon-wallet-protocol` wire (`UnixTransport` + `Client`), holding one
    long-lived unlocked session so the CLI can `status`/`unlock`/`lock`/`list`
    without re-unlocking each call.

`daemon-wallet-protocol` defines that typed wire (versioned envelopes, stable
DTOs, a `Transport` trait, and the unix-socket transport) and powers the CLI↔
daemon control channel. Secrets never cross argv: the CLI reads mnemonics, keys,
and passphrases from stdin or a hidden TTY prompt.

### Design note: two wire protocols, on purpose

There are deliberately two wires because the two clients have different needs:

- The **browser** speaks the ad-hoc Ethereum-provider JSON (`wallet_status`,
  `eth_sendTransaction`, `personal_sign`, …) that DApps and the extension already
  expect, framed as Chrome native messaging. Matching that de-facto contract
  matters more than type-safety there.
- The **CLI** speaks the typed `daemon-wallet-protocol` wire (versioned
  envelopes, Rust enums) over a unix socket, where both ends are ours and a
  stable, checked contract is worth more.

The typed wire's `Request`/`Response` enums intentionally cover the full
vocabulary (including the browser-approval variants) so a future typed browser
transport could reuse it, but the control `Client` only exposes the five
management methods the control server implements today. This is a known seam,
not an oversight: collapsing the two wires would either force the browser onto a
bespoke Rust protocol or strip the control channel of its type safety.

## Relationship to `packages/`

`packages/` is the original JS/TS POC (`core`, `cli`, `daemon`, `extension`,
`native-app`): a working end-to-end wallet over Chrome Native Messaging
(4-byte-length + JSON framing) with terminal approval. It is kept as the
reference being ported from. The Rust workspace reorganises the same product
behind the layered, chain-agnostic design above, and is the implementation under
active development.

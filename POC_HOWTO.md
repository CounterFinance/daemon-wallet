# Daemon Wallet: EVM POC quickstart

A working, local, EVM wallet you can drive from a CLI, a terminal UI, and a
background daemon. Keys live in an encrypted vault (Argon2id + XChaCha20-Poly1305);
the wallet derives EVM accounts (BIP44 `m/44'/60'/0'/0/i`), signs, and broadcasts.

> Alpha. Heavily vibecoded, not audited. Use throwaway keys and test networks.

## Build

```shell
cargo build --workspace            # or: cargo build --release --workspace
```

The CLI lands at `target/debug/daemon-wallet-cli`, the TUI at
`target/debug/daemon-wallet-tui`. Everything lives under `~/.daemon-wallet`
(override with `DAEMON_WALLET_HOME=/some/dir`: handy for throwaway wallets).

## CLI

```shell
alias dw='cargo run -q -p daemon-wallet-cli --'

dw create                      # new wallet: prompts a passphrase, prints a fresh mnemonic
# import reads the secret from stdin/prompt, never from argv (ps/history safe):
printf '%s\n%s\n' "<12/24 words>" "<passphrase>" | dw import
printf '%s\n%s\n' "0x<hex key>"   "<passphrase>" | dw import --private-key
dw list                        # accounts (table); --all shows hidden; --format addr|json
dw account-new                 # derive the next account from the primary seed
dw sign-message --account 0x.. --message "hello"       # EIP-191 personal_sign
dw balance --account 0x.. --rpc http://127.0.0.1:8545
dw send --account 0x.. --to 0x.. --value 1ether --chain local   # or --rpc <url>
dw export --seed               # reveal the mnemonic (re-enters passphrase)
dw export --account 0x..       # reveal an imported key
```

Secrets and passphrases are read hidden on a TTY, or line-by-line from stdin when
piped (for `import`: the secret line first, then the passphrase line). Nothing
secret is passed as a command-line argument.

## Daemon control (a long-running, unlocked session)

Instead of unlocking on every command, run a background daemon that holds the
unlocked wallet and talks to the CLI over a unix socket (the typed protocol wire):

```shell
dw daemon start                        # spawns `daemon-wallet-daemon serve`
dw daemon status                       # locked / accounts
printf '%s\n' "<passphrase>" | dw daemon unlock
dw daemon list                         # accounts, served from the live session
dw daemon stop                         # re-lock
```

This is a separate channel from the Chrome native-messaging host (below); the
daemon runs `serve` for the socket and, when launched by Chrome with no
subcommand, the native-messaging host.

## Try it against a local chain (anvil)

With foundry installed, one script proves the whole path: derivation matches
foundry, then a real 1 ETH transfer is signed and broadcast:

```shell
./scripts/dogfood-anvil.sh
```

Or by hand:

```shell
anvil --mnemonic "test test test test test test test test test test test junk" &
export DAEMON_WALLET_HOME="$(mktemp -d)"
printf 'test test test test test test test test test test test junk\nhunter2hunter2\n' | dw import
dw list --format addr           # -> 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 (anvil #0)
dw send --account 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
        --to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
        --value 1ether --rpc http://127.0.0.1:8545 --yes
```

## TUI

```shell
cargo run -p daemon-wallet-tui
```

Opens the wallet (masked passphrase), then: `up/down` or `j/k` to move, `n` to
derive a new account, `r` refresh, `u` lock, `a` approval panel, `q` quit.
(Deriving re-encrypts the vault with strong Argon2 params, so `n` takes a beat.)

## Browser extension + daemon (full flow)

The MV3 extension bridges a DApp's `window.ethereum` to the native wallet over
Chrome Native Messaging, and `daemon-wallet-daemon` is the host it connects to.
Wire it up:

```shell
# 1. build the extension and load it unpacked, note its extension id
cd packages/extension && npm install && npm run build
#    chrome://extensions -> Developer mode -> Load unpacked -> packages/extension/dist

# 2. build the daemon and register it as the native-messaging host
cargo build --release -p daemon-wallet-daemon
./scripts/install-native-host.sh <EXTENSION_ID>

# 3. run the daemon in a terminal (it uses that terminal for the hidden
#    passphrase prompt and the y/N approval of each sign/send), then restart Chrome
./target/release/daemon-wallet-daemon
```

With the host absent the extension falls back to a built-in dev stub so the
page → content → background flow is still demonstrable. See
`packages/extension/README.md`.

## What's real vs. stub

- Real: vault, account model, BIP44 derivation (matches foundry/ethers), EIP-191
  / EIP-712 / legacy + EIP-1559 signing, RLP encoding, JSON-RPC broadcast, the
  CLI, the TUI, and the native-messaging daemon (`wallet_status`, `wallet_unlock`,
  `eth_accounts`, `eth_requestAccounts`, `eth_sendTransaction`, `personal_sign`)
  with terminal approval.
- Manual step: loading the extension in Chrome and registering the host (above)
  is not automatable headlessly, so the daemon's wire protocol is verified by its
  own framing/dispatch tests rather than a live browser. See `ARCHITECTURE.md`.
```

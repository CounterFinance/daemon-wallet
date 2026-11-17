#!/usr/bin/env bash
# End-to-end dogfood of the EVM wallet POC against a local anvil node.
# Proves (1) BIP44 derivation matches foundry/ethers, (2) sign+RLP+broadcast works.
# Requires: anvil + cast (foundry), a built workspace. No network beyond localhost.
set -euo pipefail
cd "$(dirname "$0")/.."

RPC="http://127.0.0.1:8545"
MNEMONIC="test test test test test test test test test test test junk"
ACCT0="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"   # anvil #0
ACCT1="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"   # anvil #1
PASS="dogfood-pass-123456"

CLI_BIN="$(pwd)/target/release/daemon-wallet-cli"
[ -x "$CLI_BIN" ] || CLI_BIN="$(pwd)/target/debug/daemon-wallet-cli"
cli() { printf '%s\n' "$PASS" | "$CLI_BIN" "$@"; }

WALLET_DIR="$(mktemp -d)"
export DAEMON_WALLET_HOME="$WALLET_DIR"

echo ">> starting anvil (chainId 31337, known mnemonic)"
anvil --mnemonic "$MNEMONIC" --silent &
ANVIL_PID=$!
cleanup() { kill "$ANVIL_PID" 2>/dev/null || true; rm -rf "$WALLET_DIR"; }
trap cleanup EXIT
# wait for readiness
for _ in $(seq 1 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done

echo ">> [1/5] import anvil mnemonic into the wallet"
# Secret on stdin (never argv): mnemonic line first, passphrase line second.
printf '%s\n%s\n' "$MNEMONIC" "$PASS" | "$CLI_BIN" import >/dev/null

echo ">> [2/5] assert derived account 0 == foundry address"
DERIVED="$(cli list --format addr | head -1 | tr -d '[:space:]')"
echo "   derived: $DERIVED"
echo "   expect : $ACCT0"
if [ "${DERIVED,,}" != "${ACCT0,,}" ]; then echo "   FAIL: derivation mismatch"; exit 1; fi
echo "   PASS: derivation matches foundry/ethers"

echo ">> [3/5] balances before"
B0_BEFORE="$(cast balance "$ACCT0" --rpc-url "$RPC")"
B1_BEFORE="$(cast balance "$ACCT1" --rpc-url "$RPC")"
echo "   acct0: $(cast to-unit "$B0_BEFORE" ether) ETH   acct1: $(cast to-unit "$B1_BEFORE" ether) ETH"

echo ">> [4/5] send 1 ETH acct0 -> acct1"
SEND_OUT="$(cli send --account "$ACCT0" --to "$ACCT1" --value 1ether --rpc "$RPC" --yes)"
echo "$SEND_OUT" | sed 's/^/   /'
TXHASH="$(printf '%s' "$SEND_OUT" | grep -oiE '0x[0-9a-f]{64}' | head -1)"
if [ -z "$TXHASH" ]; then echo "   FAIL: no tx hash in send output"; exit 1; fi

echo ">> [5/5] verify on-chain effect"
cast receipt "$TXHASH" --rpc-url "$RPC" >/dev/null 2>&1 || true
B1_AFTER="$(cast balance "$ACCT1" --rpc-url "$RPC")"
echo "   acct1 before: $(cast to-unit "$B1_BEFORE" ether) ETH"
echo "   acct1 after : $(cast to-unit "$B1_AFTER" ether) ETH"
# acct1 must have gained exactly 1 ETH (it never pays gas here)
GAIN_WEI="$(python3 -c "print(int('$B1_AFTER') - int('$B1_BEFORE'))")"
if [ "$GAIN_WEI" != "1000000000000000000" ]; then echo "   FAIL: acct1 gain was $GAIN_WEI wei, expected 1e18"; exit 1; fi
echo "   PASS: acct1 received exactly 1 ETH"

echo ">> DOGFOOD PASSED"

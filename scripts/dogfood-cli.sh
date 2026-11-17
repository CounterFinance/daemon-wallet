#!/usr/bin/env bash
# Exhaustive CLI dogfood against a local anvil node. Tallies pass/fail (does not
# stop on first failure). Requires anvil + cast (foundry) and a built workspace.
cd "$(dirname "$0")/.."
CLI="target/debug/daemon-wallet-cli"
[ -x "$CLI" ] || CLI="target/release/daemon-wallet-cli"
RPC="http://127.0.0.1:8545"
MN="test test test test test test test test test test test junk"
A0="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"   # anvil #0
A1="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"   # anvil #1
A2="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"   # anvil #2
PK0="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # anvil #0 key
PASS="hunter2hunter2"
lc(){ tr 'A-F' 'a-f'; }
pass=0; fail=0
ck(){ if eval "$2"; then echo "  PASS: $1"; pass=$((pass+1)); else echo "  FAIL: $1"; fail=$((fail+1)); fi; }
cli(){ local h=$1; shift; printf '%s\n' "$PASS" | env DAEMON_WALLET_HOME="$h" "$CLI" "$@" 2>/dev/null; }

anvil --mnemonic "$MN" --silent & AP=$!
trap 'kill $AP 2>/dev/null' EXIT
for _ in $(seq 1 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done

echo "## Wallet A: mnemonic import, derive, sign, send, export"
HA=$(mktemp -d)
# Secret on stdin (never argv): mnemonic line first, passphrase line second.
printf '%s\n%s\n' "$MN" "$PASS" | env DAEMON_WALLET_HOME="$HA" "$CLI" import >/dev/null 2>&1
ck "import derives anvil #0"              '[ "$(cli "$HA" list --format addr | head -1 | tr -d "[:space:]" | lc)" = "$(echo $A0 | lc)" ]'
ck "create refuses on existing wallet"   '! printf "%s\n" "$PASS" | env DAEMON_WALLET_HOME="$HA" "$CLI" create >/dev/null 2>&1'
ck "wrong passphrase fails to open"       '! printf "nope-nope-nope\n" | env DAEMON_WALLET_HOME="$HA" "$CLI" list >/dev/null 2>&1'
cli "$HA" account-new >/dev/null; cli "$HA" account-new >/dev/null
ck "two account-new derive #1 and #2"     'cli "$HA" list --format addr | lc | grep -q "$(echo $A1|lc)" && cli "$HA" list --format addr | lc | grep -q "$(echo $A2|lc)"'
ck "list --format json has >=3 accounts"  'cli "$HA" list --format json | python3 -c "import sys,json;assert len(json.load(sys.stdin))>=3"'
ck "balance acct0 ~10000 ETH"             'cli "$HA" balance --account "$A0" --rpc "$RPC" | grep -q 10000'
SIG=$(cli "$HA" sign-message --account "$A0" --message "hello daemon" | grep -oiE "0x[0-9a-f]{130}" | head -1)
ck "sign-message is a 65-byte sig"        '[ ${#SIG} -eq 132 ]'
ck "cast recovers the signer == acct0"    'cast wallet verify --address "$A0" "hello daemon" "$SIG" >/dev/null 2>&1'
B1=$(cast balance "$A1" --rpc-url "$RPC")
TX1=$(cli "$HA" send --account "$A0" --to "$A1" --value 1ether --rpc "$RPC" --yes | grep -oiE "0x[0-9a-f]{64}" | head -1)
ck "send #1 broadcast"                    '[ -n "$TX1" ]'
ck "send #1 receipt status true"          '[ "$(cast receipt "$TX1" status --rpc-url "$RPC" 2>/dev/null)" = "true" ]'
TX2=$(cli "$HA" send --account "$A0" --to "$A2" --value 0.5ether --rpc "$RPC" --yes | grep -oiE "0x[0-9a-f]{64}" | head -1)
ck "send #2 (nonce+1) distinct tx"        '[ -n "$TX2" ] && [ "$TX2" != "$TX1" ]'
ck "acct1 gained exactly 1 ETH"           '[ "$(python3 -c "print(int(\"$(cast balance $A1 --rpc-url $RPC)\")-int(\"$B1\"))")" = "1000000000000000000" ]'
RAW=$(cli "$HA" sign-tx --account "$A0" --to "$A1" --value 0.1ether --rpc "$RPC" | grep -oiE "0x[0-9a-f]{100,}" | head -1)
ck "sign-tx emits a raw signed tx"        '[ -n "$RAW" ]'
ck "cast publishes the offline raw tx"    'cast publish "$RAW" --rpc-url "$RPC" >/dev/null 2>&1'
ck "export --seed reveals the mnemonic"   'cli "$HA" export --seed | grep -q "test test test"'
ck "export --account refuses derived"     '! printf "%s\n" "$PASS" | env DAEMON_WALLET_HOME="$HA" "$CLI" export --account "$A0" >/dev/null 2>&1'
ck "export wrong reauth is rejected"      '! printf "nope-nope-nope\n" | env DAEMON_WALLET_HOME="$HA" "$CLI" export --seed >/dev/null 2>&1'

echo "## Wallet B: private-key import + export round-trip"
HB=$(mktemp -d)
# Private key on stdin (never argv): key line first, passphrase line second.
printf '%s\n%s\n' "$PK0" "$PASS" | env DAEMON_WALLET_HOME="$HB" "$CLI" import --private-key >/dev/null 2>&1
ck "imported key yields acct0 address"    'cli "$HB" list --format addr | lc | grep -q "$(echo $A0|lc)"'
ck "export --account returns that key"     '[ "$(cli "$HB" export --account "$A0" | grep -oiE "[0-9a-f]{64}" | head -1 | lc)" = "$(echo $PK0 | sed s/0x// | lc)" ]'
ck "import of an invalid mnemonic fails"   '! printf "%s\n%s\n" "not a valid phrase at all nope nope" "$PASS" | env DAEMON_WALLET_HOME="$(mktemp -d)" "$CLI" import >/dev/null 2>&1'

rm -rf "$HA" "$HB"
echo; echo "==== $pass passed, $fail failed ===="
exit $fail

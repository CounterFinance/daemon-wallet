#!/usr/bin/env bash
#
# Register daemon-wallet-daemon as a Chrome Native Messaging host on Linux.
#
# It writes a `com.daemonwallet.host.json` manifest (name, description, the
# ABSOLUTE path to the built daemon binary, type=stdio, and the extension id in
# allowed_origins) into the NativeMessagingHosts directory of every Chrome /
# Chromium channel found on this machine. Chrome launches the binary named in
# `path` and talks the 4-byte-length-prefixed JSON protocol over its stdio.
#
# Usage:
#   scripts/install-native-host.sh <EXTENSION_ID> [DAEMON_BINARY_PATH]
#
#   <EXTENSION_ID>        The unpacked/published extension id Chrome shows on
#                         chrome://extensions (a 32-char a-p string).
#   [DAEMON_BINARY_PATH]  Path to the daemon binary. Defaults to
#                         target/release/daemon-wallet-daemon, falling back to
#                         target/debug/daemon-wallet-daemon.
#
# Build the binary first, e.g.:  cargo build --release -p daemon-wallet-daemon

set -euo pipefail

HOST_NAME="com.daemonwallet.host"

die() { echo "error: $*" >&2; exit 1; }

EXTENSION_ID="${1:-}"
[ -n "$EXTENSION_ID" ] || die "missing <EXTENSION_ID>. Usage: $0 <EXTENSION_ID> [DAEMON_BINARY_PATH]"
# A Chrome extension id is exactly 32 chars from a-p. Validating it both catches
# typos and prevents anything (quotes, etc.) from being injected into the manifest
# JSON built below.
[[ "$EXTENSION_ID" =~ ^[a-p]{32}$ ]] || die "invalid extension id '$EXTENSION_ID' (expected 32 chars a-p, as shown on chrome://extensions)"

# Resolve the repo root from this script's location so it works from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DAEMON_PATH="${2:-}"
if [ -z "$DAEMON_PATH" ]; then
  if [ -x "$REPO_ROOT/target/release/daemon-wallet-daemon" ]; then
    DAEMON_PATH="$REPO_ROOT/target/release/daemon-wallet-daemon"
  elif [ -x "$REPO_ROOT/target/debug/daemon-wallet-daemon" ]; then
    DAEMON_PATH="$REPO_ROOT/target/debug/daemon-wallet-daemon"
  else
    die "no daemon binary found; build it with 'cargo build --release -p daemon-wallet-daemon' or pass its path"
  fi
fi

# Native messaging requires an absolute path to an existing executable.
case "$DAEMON_PATH" in
  /*) : ;;
  *) DAEMON_PATH="$(cd "$(dirname "$DAEMON_PATH")" && pwd)/$(basename "$DAEMON_PATH")" ;;
esac
[ -x "$DAEMON_PATH" ] || die "daemon binary is not executable: $DAEMON_PATH"

# The browser NativeMessagingHosts directories to install into (those whose
# parent config dir exists).
CANDIDATES=(
  "$HOME/.config/google-chrome/NativeMessagingHosts"
  "$HOME/.config/google-chrome-beta/NativeMessagingHosts"
  "$HOME/.config/chromium/NativeMessagingHosts"
)

render_manifest() {
  # Emit the manifest JSON with the path and extension id substituted.
  cat <<EOF
{
  "name": "$HOST_NAME",
  "description": "Daemon Wallet Native Host",
  "path": "$DAEMON_PATH",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$EXTENSION_ID/"
  ]
}
EOF
}

installed_any=0
for base in "${CANDIDATES[@]}"; do
  parent="$(dirname "$base")"
  [ -d "$parent" ] || continue
  mkdir -p "$base"
  target="$base/$HOST_NAME.json"
  render_manifest > "$target"
  echo "installed $target"
  installed_any=1
done

if [ "$installed_any" -eq 0 ]; then
  # No browser config dir present yet: install into the Chrome location anyway
  # so a later browser launch picks it up.
  base="$HOME/.config/google-chrome/NativeMessagingHosts"
  mkdir -p "$base"
  target="$base/$HOST_NAME.json"
  render_manifest > "$target"
  echo "installed $target (no existing browser profile detected)"
fi

echo
echo "Native host '$HOST_NAME' registered."
echo "  binary:    $DAEMON_PATH"
echo "  extension: chrome-extension://$EXTENSION_ID/"
echo "Restart Chrome for the change to take effect."

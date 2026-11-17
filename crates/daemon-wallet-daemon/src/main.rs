//! `daemon-wallet-daemon`: the Chrome Native Messaging host.
//!
//! This binary is the server side of a KeePassXC-style EVM wallet. The Chrome
//! extension connects it over stdio and speaks the JSON wire defined in
//! `EXTENSION_INTEGRATION.md`: a 4-byte little-endian `u32` length prefix
//! followed by that many bytes of UTF-8 JSON.
//!
//! The binary itself is deliberately thin. All the logic that can be tested
//! without Chrome lives elsewhere:
//! - [`codec`] is the pure framing over any reader/writer,
//! - [`dispatch`] turns a request value into a response value, holding the
//!   unlocked wallet and gating actions behind an [`approval::Approver`], and
//! - [`approval`] holds the real terminal I/O (hidden passphrase entry and the
//!   y/N approval prompt), kept off the stdio wire by reading from `/dev/tty`.
//!
//! `main` only moves bytes: read a frame from stdin, hand the parsed JSON to the
//! dispatcher, write the response frame to stdout. The passphrase and every
//! approval are answered on the daemon's controlling terminal, never on the wire.
//!
//! # Subcommands
//!
//! With no subcommand — how Chrome launches it — or an explicit `native-host`,
//! the binary runs the stdio native-messaging loop above. `serve` instead binds
//! a unix control socket and speaks the typed [`daemon_wallet_protocol`] wire to
//! a local CLI (see [`serve`]). Chrome passes the extension origin (and, on
//! Windows, a parent-window handle) as a bare argument it never declared, so the
//! argument router treats only an explicit, recognized subcommand as one and
//! falls through to the native host for everything else.

mod approval;
mod codec;
mod dispatch;
mod serve;

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::Value;

use approval::{TerminalApprover, TerminalPassphrase};
use daemon_wallet_config::{self as config, Config};
use dispatch::Dispatcher;

/// The daemon's command surface.
#[derive(Parser)]
#[command(
    name = "daemon-wallet-daemon",
    version,
    about = "Daemon Wallet host: Chrome native-messaging (default) or a unix control socket (serve)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

/// What the binary should run.
#[derive(Subcommand)]
enum Command {
    /// Run the Chrome native-messaging host over stdio (the default when Chrome
    /// launches the binary with no subcommand).
    NativeHost,
    /// Serve the CLI<->daemon control channel over a unix socket.
    Serve {
        /// Socket path (default: `<wallet home>/daemon.sock`).
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    match command_from_args() {
        Command::Serve { socket } => serve::run(socket),
        Command::NativeHost => run_native_host(),
    }
}

/// Decide what to run from argv.
///
/// Clap owns the `serve` / `native-host` / `--help` / `--version` surface, but
/// Chrome starts the host with the extension origin as a bare argument. That
/// must not be mistaken for a bad subcommand, so anything other than an explicit
/// recognized token falls through to the native-messaging host — which is
/// exactly how Chrome launches the binary (no subcommand at all).
fn command_from_args() -> Command {
    match std::env::args().nth(1).as_deref() {
        Some("serve" | "native-host" | "-h" | "--help" | "-V" | "--version") => {
            Cli::parse().command.unwrap_or(Command::NativeHost)
        }
        _ => Command::NativeHost,
    }
}

/// The Chrome Native Messaging host: the original stdio framing loop.
fn run_native_host() -> Result<()> {
    eprintln!("daemon-wallet native host: waiting for Chrome extension connection on stdio...");

    let config = Config::load();
    let mut dispatcher = Dispatcher::new(
        config::wallet_file(),
        config,
        TerminalApprover,
        TerminalPassphrase,
    );

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        let frame = match codec::read_message(&mut reader) {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                eprintln!("peer closed the connection; exiting");
                break;
            }
            Err(err) => {
                eprintln!("framing error: {err}; exiting");
                break;
            }
        };

        let request: Value = match serde_json::from_slice(&frame) {
            Ok(value) => value,
            Err(err) => {
                // An unparseable frame carries no recoverable id, so reply with a
                // null id and keep the connection open.
                let response = serde_json::json!({
                    "id": Value::Null,
                    "error": { "code": -1, "message": format!("invalid JSON request: {err}") },
                });
                write_response(&mut writer, &response)?;
                continue;
            }
        };

        let response = dispatcher.handle(&request);
        write_response(&mut writer, &response)?;
    }

    Ok(())
}

/// Serialise and frame one response onto the wire.
fn write_response<W: Write>(writer: &mut W, response: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(response)?;
    codec::write_message(writer, &bytes)?;
    Ok(())
}

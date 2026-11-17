//! The `daemon` subcommand group: launch the background daemon and drive it
//! over its unix control socket.
//!
//! Each action connects a [`Client`] over a [`UnixTransport`] and calls the
//! matching typed method, so the CLI speaks the same wire contract as any other
//! client. `start` instead spawns `daemon-wallet-daemon serve` as a detached
//! child. The unlock passphrase is read through the shared stdin/tty helper,
//! never from argv.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use daemon_wallet_config as config;
use daemon_wallet_protocol::client::Client;
use daemon_wallet_protocol::{StatusDto, UnixTransport};

use crate::support::read_passphrase;

/// Resolve the control-socket path, matching the daemon's `serve` default.
fn socket_path(socket: Option<PathBuf>) -> PathBuf {
    socket.unwrap_or_else(|| config::wallet_home().join("daemon.sock"))
}

/// The pidfile that `serve` writes next to its socket: the socket path with
/// `.pid` appended. Must match `serve::pidfile_path` in the daemon crate.
fn pidfile_path(socket: &Path) -> PathBuf {
    let mut raw = socket.as_os_str().to_owned();
    raw.push(".pid");
    PathBuf::from(raw)
}

/// Is a process with `pid` still alive? `kill(pid, 0)` signals nothing but
/// performs the existence/permission check, so a `0` return means it is there.
fn process_alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Connect a typed client to the daemon's control socket.
fn connect(socket: Option<PathBuf>) -> Result<Client<UnixTransport>> {
    let path = socket_path(socket);
    let transport = UnixTransport::connect(&path).with_context(|| {
        format!(
            "could not connect to the daemon control socket at {} (is it running? try `daemon start`)",
            path.display()
        )
    })?;
    Ok(Client::new(transport))
}

/// Locate the daemon binary. Prefer one sitting next to this CLI (the usual
/// `cargo build` / install layout, where neither is on `PATH`), falling back to
/// the bare name resolved via `PATH`.
fn daemon_binary() -> std::ffi::OsString {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("daemon-wallet-daemon");
        if sibling.is_file() {
            return sibling.into_os_string();
        }
    }
    std::ffi::OsString::from("daemon-wallet-daemon")
}

/// Spawn `daemon-wallet-daemon serve` in the background.
pub fn start(socket: Option<PathBuf>) -> Result<()> {
    let path = socket_path(socket.clone());
    let mut command = Command::new(daemon_binary());
    command.arg("serve");
    if let Some(explicit) = &socket {
        command.arg("--socket").arg(explicit);
    }
    let child = command
        .spawn()
        .context("failed to spawn daemon-wallet-daemon (is it on PATH?)")?;
    println!("daemon started (pid {})", child.id());
    println!("socket: {}", path.display());
    Ok(())
}

/// Print the daemon's status.
pub fn status(socket: Option<PathBuf>) -> Result<()> {
    let mut client = connect(socket)?;
    let status = client.status()?;
    print_status(&status);
    Ok(())
}

/// Unlock the daemon's wallet, reading the passphrase off the tty/stdin.
pub fn unlock(socket: Option<PathBuf>) -> Result<()> {
    let passphrase = read_passphrase("Passphrase: ")?;
    let mut client = connect(socket)?;
    client.unlock(Some(passphrase))?;
    println!("wallet unlocked");
    print_status(&client.status()?);
    Ok(())
}

/// Lock the daemon's wallet.
pub fn lock(socket: Option<PathBuf>) -> Result<()> {
    let mut client = connect(socket)?;
    client.lock()?;
    println!("wallet locked");
    Ok(())
}

/// List the accounts the unlocked daemon holds.
pub fn list(socket: Option<PathBuf>) -> Result<()> {
    let mut client = connect(socket)?;
    let accounts = client.list_accounts()?;
    if accounts.is_empty() {
        println!("(no accounts)");
        return Ok(());
    }
    for account in &accounts {
        println!("{}  {}", account.address, account.label);
    }
    Ok(())
}

/// Stop the running `serve` daemon: read its pid from the pidfile next to the
/// socket, lock the wallet best-effort, send SIGTERM, then clean up the socket
/// and pidfile. Prints a plain "no running daemon" note (not an error) when
/// there is no pidfile or the process is already gone.
pub fn stop(socket: Option<PathBuf>) -> Result<()> {
    let socket = socket_path(socket);
    let pidfile = pidfile_path(&socket);

    let pid = match std::fs::read_to_string(&pidfile) {
        Ok(contents) => contents.trim().parse::<i32>().ok(),
        Err(_) => None,
    };
    let Some(pid) = pid else {
        println!("no running daemon (no pidfile at {})", pidfile.display());
        return Ok(());
    };

    if !process_alive(pid) {
        // Stale pidfile from a crashed daemon: tidy up and report, not an error.
        cleanup(&socket, &pidfile);
        println!("no running daemon (process {pid} already gone); cleaned up pidfile");
        return Ok(());
    }

    // Best-effort: ask the daemon to drop the unlocked wallet before we kill it.
    if let Ok(mut client) = connect(Some(socket.clone())) {
        let _ = client.lock();
    }

    // SIGTERM is caught by the daemon, which removes its own socket + pidfile and
    // exits. ESRCH (already gone) is fine; any other failure is a real error.
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(err).with_context(|| format!("sending SIGTERM to daemon pid {pid}"));
        }
    }

    // Wait briefly for the process to exit, then make sure nothing is left over.
    wait_for_exit(pid, Duration::from_secs(2));
    cleanup(&socket, &pidfile);
    println!("stopped daemon (pid {pid})");
    Ok(())
}

/// Poll until `pid` is gone or `timeout` elapses.
fn wait_for_exit(pid: i32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !process_alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Remove the socket and pidfile, ignoring "already gone" errors.
fn cleanup(socket: &Path, pidfile: &Path) {
    let _ = std::fs::remove_file(socket);
    let _ = std::fs::remove_file(pidfile);
}

/// Render a [`StatusDto`] as a few readable lines.
fn print_status(status: &StatusDto) {
    println!("locked:    {}", status.locked);
    println!("accounts:  {}", status.account_count);
    println!("protocol:  v{}", status.protocol_version);
    if !status.connected_origins.is_empty() {
        let origins: Vec<&str> = status
            .connected_origins
            .iter()
            .map(|origin| origin.0.as_str())
            .collect();
        println!("connected: {}", origins.join(", "));
    }
}

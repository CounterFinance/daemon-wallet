//! The `serve` subcommand: a CLI<->daemon control channel over a unix socket.
//!
//! Where the native-messaging host speaks the browser JSON wire over stdio to
//! one Chrome peer, `serve` binds a [`UnixListener`] under the wallet home and
//! answers the typed [`daemon_wallet_protocol`] contract to a local CLI. It
//! holds one long-lived [`Session`] — the unlocked [`Wallet`] plus [`Config`] —
//! so an `Unlock` on one connection is still unlocked on the next. Connections
//! are served serially, which is fine for a single-user local daemon.
//!
//! Only management requests belong here. A browser-approval or signing request
//! (`Connect` / `SignTransaction` / …) is answered with a clean protocol error
//! rather than served, so a process that reaches this socket cannot drive a
//! signature or fake a dapp connection.
//!
//! The per-connection loop is hand-rolled over the crate's framing-free
//! [`read_request`] / [`write_response`] helpers rather than
//! [`daemon_wallet_protocol::serve_connection`], because the handler here must
//! return a real `Err(Error)` envelope (the "not available on the control
//! socket" and unlock-failure cases), which a `Request -> Response` handler
//! cannot carry.

use std::fs;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process;
use std::thread;

use anyhow::{Context, Result};
use daemon_wallet_config::{self as config, Config};
use daemon_wallet_core::{ChainRegistry, Wallet};
use daemon_wallet_evm::EvmChain;
use daemon_wallet_protocol::{
    AccountDto, Error as WireError, GroupDto, PROTOCOL_VERSION, Request, Response,
    ResponseEnvelope, StatusDto, read_request, write_response,
};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

/// The long-lived control-socket session: config, the wallet file, and the
/// unlocked [`Wallet`] once an `Unlock` succeeds (or `None` while locked).
struct Session {
    wallet_path: PathBuf,
    /// Held as part of the long-lived session. The management requests served
    /// here need no RPC, so it is reserved for network-aware control operations
    /// rather than read today.
    #[allow(dead_code)]
    config: Config,
    wallet: Option<Wallet>,
}

impl Session {
    /// A fresh, locked session over the wallet file at `wallet_path`.
    fn new(wallet_path: PathBuf, config: Config) -> Self {
        Self {
            wallet_path,
            config,
            wallet: None,
        }
    }

    /// Map one [`Request`] to its [`Response`], or a protocol [`WireError`].
    ///
    /// This is the whole control-socket contract and is unit-tested directly.
    fn handle(&mut self, request: Request) -> Result<Response, WireError> {
        match request {
            Request::Unlock { password } => self.unlock(password),
            Request::Lock => {
                self.wallet = None;
                Ok(Response::Locked)
            }
            Request::Status => Ok(Response::Status(self.status())),
            Request::ListTree => {
                let wallet = self.wallet.as_ref().ok_or(WireError::Locked)?;
                Ok(Response::Tree(
                    wallet.tree().iter().map(GroupDto::from).collect(),
                ))
            }
            Request::ListAccounts => {
                let wallet = self.wallet.as_ref().ok_or(WireError::Locked)?;
                Ok(Response::Accounts(
                    wallet
                        .manifest()
                        .accounts
                        .values()
                        .map(AccountDto::from)
                        .collect(),
                ))
            }
            // Everything else — browser-approval / signing requests
            // (Connect/SignTransaction/…) and any future variant — has no place
            // on a management socket: refuse it cleanly instead of serving or
            // panicking.
            _ => Err(WireError::InvalidParams(
                "not available on the control socket".to_string(),
            )),
        }
    }

    /// Open the wallet from disk with `password` and keep it for later requests.
    fn unlock(&mut self, password: Option<String>) -> Result<Response, WireError> {
        let password = password.ok_or_else(|| {
            WireError::InvalidParams("unlock requires a password on the control socket".to_string())
        })?;
        let wallet = Wallet::open(&self.wallet_path, password.as_bytes(), None, evm_registry())
            .map_err(|_| WireError::InvalidParams("unlock failed".to_string()))?;
        self.wallet = Some(wallet);
        Ok(Response::Unlocked)
    }

    /// The current [`StatusDto`]: locked flag, account count, protocol version.
    fn status(&self) -> StatusDto {
        let account_count = self
            .wallet
            .as_ref()
            .map(|wallet| wallet.manifest().accounts.len())
            .unwrap_or(0);
        StatusDto {
            locked: self.wallet.is_none(),
            protocol_version: PROTOCOL_VERSION,
            account_count,
            connected_origins: Vec::new(),
        }
    }
}

/// The pidfile that tracks a running `serve` daemon, derived from the socket
/// path by appending `.pid` (so `daemon.sock` -> `daemon.sock.pid`). The CLI's
/// `daemon stop` derives the same path to find and signal the process.
pub fn pidfile_path(socket: &Path) -> PathBuf {
    let mut raw = socket.as_os_str().to_owned();
    raw.push(".pid");
    PathBuf::from(raw)
}

/// Bind the control socket and serve connections until the process is stopped.
pub fn run(socket: Option<PathBuf>) -> Result<()> {
    let home = config::wallet_home();
    fs::create_dir_all(&home).with_context(|| format!("creating wallet home {home:?}"))?;

    let socket_path = socket.unwrap_or_else(|| home.join("daemon.sock"));
    // A stale socket from a previous run would make bind() fail with "address in
    // use", so clear it first.
    if socket_path.exists() {
        fs::remove_file(&socket_path)
            .with_context(|| format!("removing stale socket {socket_path:?}"))?;
    }
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding control socket {socket_path:?}"))?;
    eprintln!(
        "daemon-wallet control socket listening on {}",
        socket_path.display()
    );

    // Record the pid next to the socket so `daemon stop` can find and signal us.
    let pidfile = pidfile_path(&socket_path);
    fs::write(&pidfile, process::id().to_string())
        .with_context(|| format!("writing pidfile {pidfile:?}"))?;
    eprintln!(
        "daemon-wallet pid {} ({})",
        process::id(),
        pidfile.display()
    );

    // A killed daemon (SIGTERM from `daemon stop`, or SIGINT) must still remove
    // its socket and pidfile. Wait on the signals in a dedicated thread and tear
    // the files down before exiting, so no stale socket/pidfile is left behind.
    install_signal_cleanup(socket_path.clone(), pidfile.clone())?;

    let mut session = Session::new(config::wallet_file(), Config::load());
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = serve_stream(stream, &mut session) {
                    eprintln!("control connection ended: {err}");
                }
            }
            Err(err) => eprintln!("control socket accept failed: {err}"),
        }
    }

    // Reached only if the accept loop ever ends on its own; clean up anyway.
    cleanup(&socket_path, &pidfile);
    Ok(())
}

/// Remove the socket and pidfile, ignoring "already gone" errors.
fn cleanup(socket_path: &Path, pidfile: &Path) {
    let _ = fs::remove_file(socket_path);
    let _ = fs::remove_file(pidfile);
}

/// Spawn a thread that waits for SIGTERM/SIGINT, removes the socket and pidfile,
/// then exits the process. This is the clean-shutdown path for `daemon stop`.
fn install_signal_cleanup(socket_path: PathBuf, pidfile: PathBuf) -> Result<()> {
    let mut signals =
        Signals::new([SIGTERM, SIGINT]).context("installing SIGTERM/SIGINT handler")?;
    thread::spawn(move || {
        if signals.forever().next().is_some() {
            cleanup(&socket_path, &pidfile);
            process::exit(0);
        }
    });
    Ok(())
}

/// Serve one connection until the peer hangs up, answering each framed request
/// against the shared `session`. Mirrors the crate's `serve_connection` framing
/// but keeps the `Err(Error)` channel the control socket needs.
fn serve_stream(stream: UnixStream, session: &mut Session) -> Result<(), WireError> {
    let mut reader = &stream;
    let mut writer = &stream;
    loop {
        let envelope = match read_request(&mut reader)? {
            Some(envelope) => envelope,
            None => return Ok(()),
        };
        let result = if envelope.protocol_version == PROTOCOL_VERSION {
            session.handle(envelope.request)
        } else {
            Err(WireError::UnsupportedVersion {
                got: envelope.protocol_version,
                expected: PROTOCOL_VERSION,
            })
        };
        let response = ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            id: envelope.id,
            result,
        };
        write_response(&mut writer, &response)?;
    }
}

/// Build a chain registry with the EVM family registered, for opening wallets.
fn evm_registry() -> ChainRegistry {
    let mut registry = ChainRegistry::new();
    registry.register(Box::new(EvmChain::new()));
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemon_wallet_core::{ChainKind, DerivationScheme};
    use daemon_wallet_protocol::client::Client;
    use daemon_wallet_protocol::{RequestId, UnixTransport};
    use daemon_wallet_vault::KdfParams;
    use std::thread;
    use tempfile::TempDir;

    const PASS: &str = "test-passphrase-123";

    /// A throwaway wallet seeded from the anvil mnemonic with one derived
    /// account, using fast KDF params so the test stays quick.
    fn test_wallet() -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wallet.vault");
        let mut wallet = Wallet::create(
            &path,
            PASS.as_bytes(),
            None,
            KdfParams::new(8, 1, 1),
            evm_registry(),
        )
        .expect("create wallet");
        let root = wallet.manifest().tree.root().clone();
        let phrase = "test test test test test test test test test test test junk";
        let normalized = bip39::Mnemonic::parse_normalized(phrase)
            .expect("parse mnemonic")
            .to_string();
        let seed = wallet
            .add_seed(
                ChainKind::Evm,
                "primary",
                DerivationScheme::Bip44Standard,
                false,
                normalized.as_bytes(),
            )
            .expect("add seed");
        wallet
            .derive_next_account(&seed, &root, "Account 0")
            .expect("derive account");
        wallet.save().expect("save wallet");
        (dir, path)
    }

    fn session_for(path: PathBuf) -> Session {
        Session::new(path, Config::default())
    }

    #[test]
    fn status_reports_locked_before_unlock() {
        let (_dir, path) = test_wallet();
        let mut session = session_for(path);
        match session.handle(Request::Status).unwrap() {
            Response::Status(status) => {
                assert!(status.locked);
                assert_eq!(status.account_count, 0);
                assert_eq!(status.protocol_version, PROTOCOL_VERSION);
            }
            other => panic!("expected status, got {other:?}"),
        }
    }

    #[test]
    fn unlock_then_status_lists_accounts_and_lock_clears_it() {
        let (_dir, path) = test_wallet();
        let mut session = session_for(path);

        assert!(matches!(
            session.handle(Request::Unlock {
                password: Some(PASS.to_string())
            }),
            Ok(Response::Unlocked)
        ));

        match session.handle(Request::Status).unwrap() {
            Response::Status(status) => {
                assert!(!status.locked);
                assert_eq!(status.account_count, 1);
            }
            other => panic!("expected status, got {other:?}"),
        }

        match session.handle(Request::ListAccounts).unwrap() {
            Response::Accounts(accounts) => assert_eq!(accounts.len(), 1),
            other => panic!("expected accounts, got {other:?}"),
        }
        match session.handle(Request::ListTree).unwrap() {
            Response::Tree(tree) => assert!(!tree.is_empty()),
            other => panic!("expected tree, got {other:?}"),
        }

        assert!(matches!(
            session.handle(Request::Lock),
            Ok(Response::Locked)
        ));
        match session.handle(Request::Status).unwrap() {
            Response::Status(status) => assert!(status.locked),
            other => panic!("expected status, got {other:?}"),
        }
        // Listing while locked is a clean protocol error, not a panic.
        assert_eq!(
            session.handle(Request::ListAccounts).unwrap_err(),
            WireError::Locked
        );
    }

    #[test]
    fn wrong_and_missing_password_are_clean_errors() {
        let (_dir, path) = test_wallet();
        let mut session = session_for(path);
        assert!(matches!(
            session.handle(Request::Unlock {
                password: Some("wrong-passphrase".to_string())
            }),
            Err(WireError::InvalidParams(_))
        ));
        assert!(matches!(
            session.handle(Request::Unlock { password: None }),
            Err(WireError::InvalidParams(_))
        ));
    }

    #[test]
    fn browser_requests_are_refused_on_the_control_socket() {
        let (_dir, path) = test_wallet();
        let mut session = session_for(path);
        let err = session
            .handle(Request::ApproveRequest { id: RequestId(1) })
            .unwrap_err();
        assert_eq!(
            err,
            WireError::InvalidParams("not available on the control socket".to_string())
        );
    }

    #[test]
    fn round_trips_status_unlock_list_over_a_socket() {
        let (_dir, path) = test_wallet();
        let (client_end, server_end) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let mut session = session_for(path);
            serve_stream(server_end, &mut session).unwrap();
        });

        let mut client = Client::new(UnixTransport::from_stream(client_end));
        assert!(client.status().unwrap().locked);
        client.unlock(Some(PASS.to_string())).unwrap();
        let status = client.status().unwrap();
        assert!(!status.locked);
        assert_eq!(status.account_count, 1);
        assert_eq!(client.list_accounts().unwrap().len(), 1);

        drop(client);
        server.join().unwrap();
    }
}

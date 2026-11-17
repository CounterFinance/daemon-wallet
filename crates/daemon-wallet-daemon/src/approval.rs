//! Human-in-the-loop abstractions: approval and passphrase entry.
//!
//! The stdin/stdout pair is the JSON wire to the Chrome extension, never a place
//! to read a human answer from. So every decision that needs a person — unlock a
//! wallet, connect a site, approve a transaction or a signature — is expressed
//! through the [`Approver`] and [`PassphraseSource`] traits and answered on the
//! daemon's *controlling terminal*, out of band from the wire.
//!
//! The [`Dispatcher`](crate::dispatch::Dispatcher) depends only on these traits,
//! so tests drive it with an [`AutoApprover`]/[`RejectingApprover`] and a canned
//! passphrase while the real [`TerminalApprover`]/[`TerminalPassphrase`] keep all
//! the `/dev/tty` and `rpassword` I/O confined here.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};

/// A request put to a human for a yes/no decision, carrying enough context for
/// the terminal prompt to describe exactly what is being approved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalRequest {
    /// A site is asking to connect and see the wallet's accounts.
    Connect {
        /// The requesting dapp origin, as reported by the extension.
        origin: String,
        /// The accounts that would be exposed on approval.
        accounts: Vec<String>,
    },
    /// A site is asking to sign and broadcast a transaction.
    SendTransaction {
        /// The requesting dapp origin.
        origin: String,
        /// The sending account.
        from: String,
        /// The recipient.
        to: String,
        /// The value in wei.
        value_wei: u128,
        /// The transaction calldata. Non-empty means a contract interaction whose
        /// effect is NOT captured by `to`/`value` (e.g. an ERC-20 `approve`), so it
        /// must be shown before the user can consent.
        data: Vec<u8>,
    },
    /// A site is asking for an off-chain message signature (personal_sign/eth_sign).
    SignMessage {
        /// The requesting dapp origin.
        origin: String,
        /// The signing account.
        from: String,
        /// The exact bytes that will be signed. Shown as text only when they are
        /// clean UTF-8; otherwise as hex, so a binary payload is never disguised
        /// as readable text (or hidden as mojibake) in the prompt.
        message: Vec<u8>,
    },
}

impl fmt::Display for ApprovalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalRequest::Connect { origin, accounts } => {
                writeln!(f, "Connect request")?;
                writeln!(f, "  origin:   {origin}")?;
                write!(f, "  accounts: {}", accounts.join(", "))
            }
            ApprovalRequest::SendTransaction {
                origin,
                from,
                to,
                value_wei,
                data,
            } => {
                writeln!(f, "Transaction approval request")?;
                writeln!(f, "  origin: {origin}")?;
                writeln!(f, "  from:   {from}")?;
                writeln!(f, "  to:     {to}")?;
                writeln!(f, "  value:  {value_wei} wei")?;
                if data.is_empty() {
                    write!(f, "  data:   (none - plain value transfer)")
                } else {
                    writeln!(
                        f,
                        "  !! CONTRACT INTERACTION - this calldata, not the value above,"
                    )?;
                    writeln!(
                        f,
                        "     determines what happens (e.g. a token approval/transfer):"
                    )?;
                    write!(f, "  data:   0x{}", hex::encode(data))
                }
            }
            ApprovalRequest::SignMessage {
                origin,
                from,
                message,
            } => {
                writeln!(f, "Message signature request")?;
                writeln!(f, "  origin:  {origin}")?;
                writeln!(f, "  from:    {from}")?;
                match std::str::from_utf8(message) {
                    Ok(text)
                        if text
                            .chars()
                            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t')) =>
                    {
                        write!(f, "  message: {text}")
                    }
                    _ => write!(
                        f,
                        "  message: 0x{} (binary - shown as hex)",
                        hex::encode(message)
                    ),
                }
            }
        }
    }
}

/// The yes/no gate on every account-exposing or signing operation.
pub trait Approver {
    /// Return `true` to approve the request, `false` to reject it (which the
    /// dispatcher maps to a `4001` user-rejection error).
    fn approve(&self, request: &ApprovalRequest) -> bool;
}

/// The source of the wallet passphrase for an unlock.
pub trait PassphraseSource {
    /// Acquire the passphrase. The returned string is treated as sensitive by the
    /// caller and dropped as soon as the wallet is opened.
    fn passphrase(&self) -> anyhow::Result<String>;
}

/// An approver that accepts everything. For tests only.
#[cfg(test)]
pub struct AutoApprover;

#[cfg(test)]
impl Approver for AutoApprover {
    fn approve(&self, _request: &ApprovalRequest) -> bool {
        true
    }
}

/// An approver that rejects everything. For tests only.
#[cfg(test)]
pub struct RejectingApprover;

#[cfg(test)]
impl Approver for RejectingApprover {
    fn approve(&self, _request: &ApprovalRequest) -> bool {
        false
    }
}

/// A passphrase source returning a fixed string. For tests only.
#[cfg(test)]
pub struct FixedPassphrase(pub String);

#[cfg(test)]
impl PassphraseSource for FixedPassphrase {
    fn passphrase(&self) -> anyhow::Result<String> {
        Ok(self.0.clone())
    }
}

/// The production approver: prints the request to the terminal and reads a y/N
/// answer from the controlling TTY (`/dev/tty`), so the wire's stdin stays
/// untouched.
pub struct TerminalApprover;

impl Approver for TerminalApprover {
    fn approve(&self, request: &ApprovalRequest) -> bool {
        // The prompt goes to stderr (never stdout, which is the wire).
        eprintln!("\n--- daemon-wallet approval ---\n{request}");
        match prompt_tty_yes_no("Approve? [y/N]: ") {
            Ok(answer) => answer,
            Err(err) => {
                eprintln!("could not read approval from terminal: {err}; denying");
                false
            }
        }
    }
}

/// The production passphrase source: reads a hidden line from the controlling
/// terminal via `rpassword`, which on Unix opens `/dev/tty` for both the prompt
/// and the hidden input and so leaves the stdio wire alone.
pub struct TerminalPassphrase;

impl PassphraseSource for TerminalPassphrase {
    fn passphrase(&self) -> anyhow::Result<String> {
        rpassword::prompt_password("Unlock wallet passphrase: ")
            .map_err(|err| anyhow::anyhow!("failed to read passphrase from terminal: {err}"))
    }
}

/// Write `prompt` to the controlling terminal and read a single y/N line back
/// from it. Uses `/dev/tty` directly so neither the prompt nor the answer can
/// collide with the native-messaging frames on stdin/stdout.
fn prompt_tty_yes_no(prompt: &str) -> std::io::Result<bool> {
    let mut tty_out = OpenOptions::new().write(true).open("/dev/tty")?;
    tty_out.write_all(prompt.as_bytes())?;
    tty_out.flush()?;

    let tty_in = OpenOptions::new().read(true).open("/dev/tty")?;
    let mut line = String::new();
    BufReader::new(tty_in).read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

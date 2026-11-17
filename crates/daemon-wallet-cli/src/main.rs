//! Daemon Wallet CLI — the management + dogfood surface for the EVM POC.
//!
//! The clap command surface below is the fixed contract (the anvil dogfood
//! script drives exactly these flags). The CLI never names an alloy type: it
//! drives the wallet via `daemon-wallet-core`, builds signing payloads via
//! `daemon-wallet-evm`'s neutral helpers, and assembles/broadcasts transactions
//! via `daemon-wallet-rpc`.

mod daemon;
mod support;

use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use daemon_wallet_config as config;
use daemon_wallet_core::{Account, AccountSource, ChainKind, DerivationScheme, SeedId, Wallet};
use daemon_wallet_evm as evm;
use daemon_wallet_rpc::RpcClient;
use daemon_wallet_vault::KdfParams;

use support::{
    PRIMARY_SEED_LABEL, confirm, danger_banner, evm_registry, parse_value_wei, read_new_passphrase,
    read_passphrase, read_reauth, read_secret_line, resolve_account, wei_to_eth_string,
};

#[derive(Parser)]
#[command(
    name = "daemon-wallet-cli",
    version,
    about = "Daemon Wallet CLI (EVM proof of concept)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new wallet (generates a fresh BIP39 mnemonic).
    Create,
    /// Import a wallet from a mnemonic phrase (default) or a raw private key
    /// (`--private-key`).
    ///
    /// The secret never appears in argv. When stdin is piped it is read as the
    /// FIRST line and the passphrase as the SECOND line
    /// (`printf '%s\n%s\n' "$SECRET" "$PASS" | … import`). On a TTY the mnemonic
    /// is prompted as a visible line, the private key hidden, then the new
    /// passphrase is prompted (with confirmation).
    Import {
        /// Import a raw hex private key instead of a mnemonic.
        #[arg(long)]
        private_key: bool,
    },
    /// List accounts.
    List {
        /// Include hidden accounts.
        #[arg(long)]
        all: bool,
        #[arg(long, value_enum, default_value = "table")]
        format: ListFormat,
    },
    /// Derive the next account from the primary seed.
    #[command(name = "account-new")]
    AccountNew {
        #[arg(long)]
        label: Option<String>,
    },
    /// Sign a message (EIP-191 personal_sign); prints the hex signature.
    SignMessage {
        #[arg(long)]
        account: String,
        #[arg(long)]
        message: String,
    },
    /// Sign a transaction offline; prints the raw signed transaction hex.
    SignTx {
        #[arg(long)]
        account: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        value: String,
        #[arg(long)]
        rpc: Option<String>,
    },
    /// Assemble, sign, and broadcast a value transfer.
    Send {
        #[arg(long)]
        account: String,
        #[arg(long)]
        to: String,
        /// Amount, e.g. `1ether`, `0.5eth`, or a plain wei integer.
        #[arg(long)]
        value: String,
        /// Select a configured network by name (overridden by `--rpc`).
        #[arg(long)]
        chain: Option<String>,
        #[arg(long)]
        rpc: Option<String>,
        /// Skip the interactive approval prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Show an account's balance.
    Balance {
        #[arg(long)]
        account: String,
        #[arg(long)]
        rpc: Option<String>,
    },
    /// Export a secret (requires re-entering the passphrase).
    Export {
        #[arg(long, conflicts_with = "seed")]
        account: Option<String>,
        #[arg(long)]
        seed: bool,
    },
    /// Talk to (or launch) the background daemon over its control socket.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
}

/// The `daemon` subcommand group: launch the daemon or drive it over its unix
/// control socket. Every action takes an optional `--socket` to override the
/// default path (`<wallet home>/daemon.sock`).
#[derive(Subcommand)]
enum DaemonAction {
    /// Spawn `daemon-wallet-daemon serve` in the background; print its pid and
    /// socket path.
    Start {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Show the daemon's status.
    Status {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Unlock the wallet the daemon holds (passphrase read from the tty/stdin,
    /// never argv).
    Unlock {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Lock the wallet the daemon holds.
    Lock {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// List the accounts the unlocked daemon holds.
    List {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Best-effort lock the daemon's wallet.
    Stop {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ListFormat {
    Table,
    Addr,
    Json,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Create => cmd_create(),
        Commands::Import { private_key } => cmd_import(private_key),
        Commands::List { all, format } => cmd_list(all, format),
        Commands::AccountNew { label } => cmd_account_new(label),
        Commands::SignMessage { account, message } => cmd_sign_message(account, message),
        Commands::SignTx {
            account,
            to,
            value,
            rpc,
        } => cmd_sign_tx(account, to, value, rpc),
        Commands::Send {
            account,
            to,
            value,
            chain,
            rpc,
            yes,
        } => cmd_send(account, to, value, chain, rpc, yes),
        Commands::Balance { account, rpc } => cmd_balance(account, rpc),
        Commands::Export { account, seed } => cmd_export(account, seed),
        Commands::Daemon { action } => match action {
            DaemonAction::Start { socket } => daemon::start(socket),
            DaemonAction::Status { socket } => daemon::status(socket),
            DaemonAction::Unlock { socket } => daemon::unlock(socket),
            DaemonAction::Lock { socket } => daemon::lock(socket),
            DaemonAction::List { socket } => daemon::list(socket),
            DaemonAction::Stop { socket } => daemon::stop(socket),
        },
    }
}

// --- helpers ----------------------------------------------------------------

/// Open the on-disk wallet, prompting for the passphrase, returning both the
/// wallet and the passphrase (needed for gated reveals).
fn open_wallet(prompt: &str) -> Result<(Wallet, String)> {
    if !config::wallet_exists() {
        bail!(
            "no wallet found at {}; run `create` or `import` first",
            config::wallet_file().display()
        );
    }
    let pass = read_passphrase(prompt)?;
    let wallet = Wallet::open(config::wallet_file(), pass.as_bytes(), None, evm_registry())
        .context("failed to open wallet (wrong passphrase?)")?;
    Ok((wallet, pass))
}

/// The id of the primary seed: the one labelled `primary`, else the first.
fn primary_seed_id(wallet: &Wallet) -> Result<SeedId> {
    let seeds = &wallet.manifest().seeds;
    if let Some((id, _)) = seeds.iter().find(|(_, s)| s.label == PRIMARY_SEED_LABEL) {
        return Ok(id.clone());
    }
    seeds
        .keys()
        .next()
        .cloned()
        .context("wallet has no seed to derive from")
}

/// Accounts in display order: derived accounts first by ascending index (so the
/// primary account 0 leads), then imported accounts. Used so the `addr` format's
/// first line is the primary account, which the dogfood greps.
fn ordered_accounts(wallet: &Wallet, include_hidden: bool) -> Vec<&Account> {
    let mut accounts: Vec<&Account> = wallet
        .manifest()
        .accounts
        .values()
        .filter(|a| include_hidden || !a.hidden)
        .collect();
    accounts.sort_by_key(|a| match &a.source {
        AccountSource::Derived { index, .. } => (0u8, u64::from(*index)),
        AccountSource::Imported { .. } => (1u8, 0),
    });
    accounts
}

fn account_index(account: &Account) -> Option<u32> {
    match &account.source {
        AccountSource::Derived { index, .. } => Some(*index),
        AccountSource::Imported { .. } => None,
    }
}

// --- commands ---------------------------------------------------------------

fn cmd_create() -> Result<()> {
    if config::wallet_exists() {
        bail!(
            "a wallet already exists at {}; refusing to overwrite",
            config::wallet_file().display()
        );
    }
    let pass = read_new_passphrase()?;
    let mnemonic = bip39::Mnemonic::generate(12).context("failed to generate mnemonic")?;
    let phrase = mnemonic.to_string();

    std::fs::create_dir_all(config::wallet_home()).context("failed to create wallet home")?;
    let mut wallet = Wallet::create(
        config::wallet_file(),
        pass.as_bytes(),
        None,
        KdfParams::RECOMMENDED,
        evm_registry(),
    )
    .context("failed to create wallet")?;

    let seed_id = wallet.add_seed(
        ChainKind::Evm,
        PRIMARY_SEED_LABEL,
        DerivationScheme::Bip44Standard,
        false,
        phrase.as_bytes(),
    )?;
    let root = wallet.manifest().tree.root().clone();
    let account_id = wallet.derive_next_account(&seed_id, &root, "Account 0")?;
    wallet.save()?;

    let address = wallet.manifest().accounts[&account_id].address.to_string();
    println!("Wallet created at {}", config::wallet_file().display());
    println!("Primary account: {address}");
    danger_banner("recovery mnemonic (write it down, offline)");
    println!("{phrase}");
    Ok(())
}

fn cmd_import(private_key: bool) -> Result<()> {
    if config::wallet_exists() {
        bail!(
            "a wallet already exists at {}; refusing to overwrite",
            config::wallet_file().display()
        );
    }
    // The secret is read from a dedicated source, never argv. Piped: secret line
    // first, passphrase line second. TTY: mnemonic visible, private key hidden.
    let secret = if private_key {
        read_secret_line("Private key: ", true)?
    } else {
        read_secret_line("Mnemonic: ", false)?
    };
    let pass = read_new_passphrase()?;
    std::fs::create_dir_all(config::wallet_home()).context("failed to create wallet home")?;
    let mut wallet = Wallet::create(
        config::wallet_file(),
        pass.as_bytes(),
        None,
        KdfParams::RECOMMENDED,
        evm_registry(),
    )
    .context("failed to create wallet")?;

    let root = wallet.manifest().tree.root().clone();
    let address = if private_key {
        let trimmed = secret.trim().strip_prefix("0x").unwrap_or(secret.trim());
        let key_bytes = hex::decode(trimmed).context("invalid private key hex")?;
        let account_id = wallet.import_key(ChainKind::Evm, "imported", &key_bytes, &root)?;
        wallet.manifest().accounts[&account_id].address.to_string()
    } else {
        let parsed =
            bip39::Mnemonic::parse_normalized(secret.trim()).context("invalid BIP39 mnemonic")?;
        let normalized = parsed.to_string();
        let seed_id = wallet.add_seed(
            ChainKind::Evm,
            PRIMARY_SEED_LABEL,
            DerivationScheme::Bip44Standard,
            false,
            normalized.as_bytes(),
        )?;
        let account_id = wallet.derive_next_account(&seed_id, &root, "Account 0")?;
        wallet.manifest().accounts[&account_id].address.to_string()
    };
    wallet.save()?;

    println!("Wallet created at {}", config::wallet_file().display());
    println!("Primary account: {address}");
    Ok(())
}

fn cmd_list(all: bool, format: ListFormat) -> Result<()> {
    let (wallet, _) = open_wallet("Passphrase: ")?;
    let accounts = ordered_accounts(&wallet, all);
    match format {
        ListFormat::Addr => {
            for account in &accounts {
                println!("{}", account.address);
            }
        }
        ListFormat::Table => {
            println!("{:<6} {:<16} {:<44} hidden", "index", "label", "address");
            for account in &accounts {
                let index = account_index(account)
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "{:<6} {:<16} {:<44} {}",
                    index, account.label, account.address, account.hidden
                );
            }
        }
        ListFormat::Json => {
            let rows: Vec<serde_json::Value> = accounts
                .iter()
                .map(|account| {
                    serde_json::json!({
                        "index": account_index(account),
                        "label": account.label,
                        "address": account.address.as_str(),
                        "hidden": account.hidden,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
    }
    Ok(())
}

fn cmd_account_new(label: Option<String>) -> Result<()> {
    let (mut wallet, _) = open_wallet("Passphrase: ")?;
    let seed_id = primary_seed_id(&wallet)?;
    let root = wallet.manifest().tree.root().clone();
    let label = label.unwrap_or_else(|| "Account".to_string());
    let account_id = wallet.derive_next_account(&seed_id, &root, label)?;
    wallet.save()?;
    let address = wallet.manifest().accounts[&account_id].address.to_string();
    println!("{address}");
    Ok(())
}

fn cmd_sign_message(account: String, message: String) -> Result<()> {
    let (wallet, _) = open_wallet("Passphrase: ")?;
    let account_id = resolve_account(wallet.manifest(), &account)?;
    let payload = evm::message_payload(message.as_bytes());
    let signature = wallet.sign(&account_id, &payload)?;
    println!("0x{}", hex::encode(signature));
    Ok(())
}

fn cmd_sign_tx(account: String, to: String, value: String, rpc: Option<String>) -> Result<()> {
    let wei = parse_value_wei(&value)?;
    let url = config::Config::load()
        .resolve_rpc(rpc.as_deref())
        .context("no RPC endpoint (pass --rpc or configure a default network)")?;
    let client = RpcClient::new(url);

    let (wallet, _) = open_wallet("Passphrase: ")?;
    let account_id = resolve_account(wallet.manifest(), &account)?;
    let from = wallet.manifest().accounts[&account_id].address.to_string();

    // One assembly path, shared with `send`: fill chain id/nonce/fees/gas, sign,
    // and RLP-encode. `sign-tx` just stops short of broadcasting.
    let raw = client
        .assemble_and_sign_eip1559(&from, to.trim(), wei, Vec::new(), |payload| {
            wallet.sign(&account_id, payload).map_err(|e| e.to_string())
        })
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    println!("0x{}", hex::encode(raw));
    Ok(())
}

fn cmd_send(
    account: String,
    to: String,
    value: String,
    chain: Option<String>,
    rpc: Option<String>,
    yes: bool,
) -> Result<()> {
    let wei = parse_value_wei(&value)?;
    let config = config::Config::load();
    // `--rpc` is the explicit override and wins; else `--chain` selects a
    // configured network by name; else the default network.
    let url = match (rpc.as_deref(), chain.as_deref()) {
        (Some(url), _) => url.to_string(),
        (None, Some(name)) => config
            .network(name)
            .map(|network| network.rpc.clone())
            .with_context(|| format!("unknown network '{name}'; add it to config or pass --rpc"))?,
        (None, None) => config
            .resolve_rpc(None)
            .context("no RPC endpoint (pass --rpc, --chain, or configure a default network)")?,
    };

    let (wallet, _) = open_wallet("Passphrase: ")?;
    let account_id = resolve_account(wallet.manifest(), &account)?;
    let from = wallet.manifest().accounts[&account_id].address.to_string();
    let to = to.trim().to_string();

    if !yes {
        println!("About to send:");
        println!("  from:  {from}");
        println!("  to:    {to}");
        println!("  value: {} ETH ({wei} wei)", wei_to_eth_string(wei));
        println!("  rpc:   {url}");
        if !confirm("Proceed?")? {
            println!("Aborted.");
            return Ok(());
        }
    }

    let client = RpcClient::new(url);
    let tx_hash = client
        .send_eip1559(&from, &to, wei, vec![], |payload| {
            wallet.sign(&account_id, payload).map_err(|e| e.to_string())
        })
        .context("broadcast failed")?;
    println!("tx hash: {tx_hash}");

    // Best-effort receipt poll; the transfer is already broadcast either way.
    for _ in 0..20 {
        match client.get_transaction_receipt(&tx_hash) {
            Ok(Some(receipt)) => {
                let status = if receipt.success {
                    "success"
                } else {
                    "reverted"
                };
                println!("mined in block {}: {status}", receipt.block_number);
                return Ok(());
            }
            Ok(None) => sleep(Duration::from_millis(500)),
            Err(_) => break,
        }
    }
    Ok(())
}

fn cmd_balance(account: String, rpc: Option<String>) -> Result<()> {
    let url = config::Config::load()
        .resolve_rpc(rpc.as_deref())
        .context("no RPC endpoint (pass --rpc or configure a default network)")?;
    let (wallet, _) = open_wallet("Passphrase: ")?;
    let account_id = resolve_account(wallet.manifest(), &account)?;
    let address = wallet.manifest().accounts[&account_id].address.to_string();

    let client = RpcClient::new(url);
    let wei = client.get_balance(&address)?;
    println!("{} ETH ({wei} wei)", wei_to_eth_string(wei));
    Ok(())
}

fn cmd_export(account: Option<String>, seed: bool) -> Result<()> {
    let (wallet, pass) = open_wallet("Passphrase: ")?;
    let reauth = read_reauth(&pass)?;

    if seed {
        let seed_id = primary_seed_id(&wallet)?;
        let secret = wallet.export_seed(&seed_id, reauth.as_bytes())?;
        let phrase = String::from_utf8(secret.as_slice().to_vec())
            .context("seed material is not valid UTF-8")?;
        danger_banner("seed mnemonic");
        println!("{phrase}");
        return Ok(());
    }

    let account = account.context("pass --account <address> or --seed")?;
    let account_id = resolve_account(wallet.manifest(), &account)?;
    match &wallet.manifest().accounts[&account_id].source {
        AccountSource::Imported { key } => {
            let secret = wallet.export_key(key, reauth.as_bytes())?;
            danger_banner("private key");
            println!("0x{}", hex::encode(secret.as_slice()));
        }
        AccountSource::Derived { .. } => {
            bail!(
                "account {account} is seed-derived; it has no standalone key. Use `export --seed` to reveal the mnemonic."
            );
        }
    }
    Ok(())
}

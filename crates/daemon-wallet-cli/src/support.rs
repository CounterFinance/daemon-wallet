//! Shared helpers for the CLI handlers: passphrase I/O, the EVM chain registry,
//! value parsing, address resolution, and small formatting utilities.
//!
//! None of this touches an alloy type (that is confined to the `sign-tx` path in
//! `main.rs`); it works on neutral `daemon-wallet-core` / `-config` surfaces.

use std::io::{IsTerminal, Write};

use anyhow::{Context, Result, bail};
use daemon_wallet_core::{AccountId, ChainRegistry, WalletManifest};
use daemon_wallet_evm::EvmChain;

/// The label the `create`/`import` flow gives the wallet's first seed.
pub const PRIMARY_SEED_LABEL: &str = "primary";

/// Build a chain registry with the EVM family registered. Every CLI command
/// that opens or creates a wallet hands one of these to the core.
pub fn evm_registry() -> ChainRegistry {
    let mut registry = ChainRegistry::new();
    registry.register(Box::new(EvmChain::new()));
    registry
}

/// Read a passphrase for opening an existing wallet.
///
/// On a TTY the input is hidden via `rpassword`. When stdin is piped (not a
/// TTY) a single line is read instead, so
/// `printf '%s\n' "$PASS" | daemon-wallet-cli …` works for the dogfood harness.
pub fn read_passphrase(prompt: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt).context("failed to read passphrase")
    } else {
        read_stdin_line()
    }
}

/// Read and confirm a passphrase for a *new* wallet, enforcing a 12-character
/// minimum. On a TTY the passphrase is entered twice and must match; when piped,
/// a single line is read (the harness cannot answer a second prompt).
pub fn read_new_passphrase() -> Result<String> {
    if std::io::stdin().is_terminal() {
        let first =
            rpassword::prompt_password("New passphrase: ").context("failed to read passphrase")?;
        enforce_min_len(&first)?;
        let second = rpassword::prompt_password("Confirm passphrase: ")
            .context("failed to read passphrase")?;
        if first != second {
            bail!("passphrases do not match");
        }
        Ok(first)
    } else {
        let pass = read_stdin_line()?;
        enforce_min_len(&pass)?;
        Ok(pass)
    }
}

/// Re-acquire the passphrase for a gated reveal. On a TTY the user is prompted
/// again (a deliberate speed-bump); when piped the already-entered passphrase is
/// reused, since only one line is available on stdin.
pub fn read_reauth(open_pass: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Re-enter passphrase to reveal secret: ")
            .context("failed to read passphrase")
    } else {
        Ok(open_pass.to_string())
    }
}

/// Read a secret (a mnemonic or a raw private key) for a *new* wallet import.
///
/// The secret never comes from argv. On a TTY the user is prompted: a mnemonic is
/// read as a visible line, a private key is read hidden via `rpassword` (pass
/// `hidden = true`). When stdin is piped (not a TTY) the secret is read as the
/// *first* line of stdin — the passphrase helper then reads the *second* line —
/// so the dogfood convention is `printf '%s\n%s\n' "$SECRET" "$PASS" | … import`.
/// The piped order is always: secret line, then passphrase line.
pub fn read_secret_line(prompt: &str, hidden: bool) -> Result<String> {
    if std::io::stdin().is_terminal() {
        if hidden {
            rpassword::prompt_password(prompt).context("failed to read secret")
        } else {
            print!("{prompt}");
            std::io::stdout().flush().ok();
            read_stdin_line()
        }
    } else {
        read_stdin_line()
    }
}

fn enforce_min_len(pass: &str) -> Result<()> {
    if pass.chars().count() < 12 {
        bail!("passphrase must be at least 12 characters");
    }
    Ok(())
}

fn read_stdin_line() -> Result<String> {
    use std::io::BufRead;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("failed to read passphrase from stdin")?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Print a `y/N` confirmation prompt and return whether the user accepted.
pub fn confirm(prompt: &str) -> Result<bool> {
    print!("{prompt} [y/N]: ");
    std::io::stdout().flush().ok();
    let answer = read_stdin_line()?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

/// Resolve a `--account` address string to an [`AccountId`] by scanning the
/// manifest's accounts, comparing addresses case-insensitively.
pub fn resolve_account(manifest: &WalletManifest, query: &str) -> Result<AccountId> {
    match_address(
        manifest
            .accounts
            .iter()
            .map(|(id, account)| (id, account.address.as_str())),
        query,
    )
    .ok_or_else(|| anyhow::anyhow!("no account matches address {query}"))
}

/// The address-matching core, split out so it can be unit-tested without a live
/// wallet. Returns the first account whose address equals `query` ignoring case
/// and surrounding whitespace.
pub fn match_address<'a, I>(accounts: I, query: &str) -> Option<AccountId>
where
    I: IntoIterator<Item = (&'a AccountId, &'a str)>,
{
    let query = query.trim();
    accounts
        .into_iter()
        .find(|(_, address)| address.eq_ignore_ascii_case(query))
        .map(|(id, _)| id.clone())
}

/// Parse an amount string into wei. Accepts `1ether`, `0.5eth`, `3gwei`,
/// `1000wei`, or a bare integer (treated as wei). Case-insensitive.
pub fn parse_value_wei(input: &str) -> Result<u128> {
    let lowered = input.trim().to_lowercase();
    if lowered.is_empty() {
        bail!("empty value");
    }
    let (number, decimals) = if let Some(rest) = lowered.strip_suffix("ether") {
        (rest.trim(), 18u32)
    } else if let Some(rest) = lowered.strip_suffix("eth") {
        (rest.trim(), 18)
    } else if let Some(rest) = lowered.strip_suffix("gwei") {
        (rest.trim(), 9)
    } else if let Some(rest) = lowered.strip_suffix("wei") {
        (rest.trim(), 0)
    } else {
        (lowered.as_str(), 0)
    };
    parse_fixed_point(number, decimals).with_context(|| format!("invalid amount: {input}"))
}

/// Parse a decimal number with a fixed number of fractional `decimals` into the
/// smallest integer unit, rejecting fractional input when `decimals == 0`.
fn parse_fixed_point(number: &str, decimals: u32) -> Result<u128> {
    let number = number.trim();
    if number.is_empty() {
        bail!("missing number");
    }
    let (int_part, frac_part) = match number.split_once('.') {
        Some((i, f)) => (i, f),
        None => (number, ""),
    };
    if decimals == 0 && !frac_part.is_empty() {
        bail!("a wei value cannot be fractional");
    }
    if frac_part.len() > decimals as usize {
        bail!("too many decimal places (max {decimals})");
    }
    let int_part = if int_part.is_empty() { "0" } else { int_part };
    for ch in int_part.chars().chain(frac_part.chars()) {
        if !ch.is_ascii_digit() {
            bail!("not a number: {number}");
        }
    }
    let scale = 10u128
        .checked_pow(decimals)
        .context("decimal scale overflow")?;
    let int_value: u128 = int_part.parse().context("integer part overflow")?;
    let mut frac_padded = frac_part.to_string();
    while frac_padded.len() < decimals as usize {
        frac_padded.push('0');
    }
    let frac_value: u128 = if frac_padded.is_empty() {
        0
    } else {
        frac_padded.parse().context("fractional part overflow")?
    };
    int_value
        .checked_mul(scale)
        .and_then(|v| v.checked_add(frac_value))
        .context("value overflow")
}

/// Render a wei amount as a decimal ether string (18 fractional digits, trailing
/// zeros trimmed, never empty).
pub fn wei_to_eth_string(wei: u128) -> String {
    const WEI_PER_ETH: u128 = 1_000_000_000_000_000_000;
    let whole = wei / WEI_PER_ETH;
    let frac = wei % WEI_PER_ETH;
    if frac == 0 {
        return whole.to_string();
    }
    let mut frac_str = format!("{frac:018}");
    while frac_str.ends_with('0') {
        frac_str.pop();
    }
    format!("{whole}.{frac_str}")
}

/// A prominent banner printed above any revealed secret.
pub fn danger_banner(what: &str) {
    eprintln!("────────────────────────────────────────────────────────");
    eprintln!("  DANGER: {what}");
    eprintln!("  Anyone with this value controls the funds. Never share");
    eprintln!("  it, paste it online, or store it unencrypted.");
    eprintln!("────────────────────────────────────────────────────────");
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemon_wallet_core::AccountId;

    #[test]
    fn parses_ether_units() {
        assert_eq!(
            parse_value_wei("1ether").unwrap(),
            1_000_000_000_000_000_000
        );
        assert_eq!(parse_value_wei("1eth").unwrap(), 1_000_000_000_000_000_000);
        assert_eq!(parse_value_wei("0.5eth").unwrap(), 500_000_000_000_000_000);
        assert_eq!(
            parse_value_wei("2.25ether").unwrap(),
            2_250_000_000_000_000_000
        );
    }

    #[test]
    fn parses_gwei_and_wei_suffixes() {
        assert_eq!(parse_value_wei("3gwei").unwrap(), 3_000_000_000);
        assert_eq!(parse_value_wei("1000wei").unwrap(), 1000);
    }

    #[test]
    fn parses_bare_integer_as_wei() {
        assert_eq!(parse_value_wei("12345").unwrap(), 12345);
        assert_eq!(
            parse_value_wei("1000000000000000000").unwrap(),
            1_000_000_000_000_000_000
        );
    }

    #[test]
    fn is_case_insensitive_and_trims() {
        assert_eq!(
            parse_value_wei("  1ETH ").unwrap(),
            1_000_000_000_000_000_000
        );
    }

    #[test]
    fn rejects_bad_values() {
        assert!(parse_value_wei("").is_err());
        assert!(parse_value_wei("abc").is_err());
        assert!(parse_value_wei("0.5").is_err()); // bare wei cannot be fractional
        assert!(parse_value_wei("1.0000000000gwei").is_err()); // too many decimals
    }

    #[test]
    fn formats_eth_from_wei() {
        assert_eq!(wei_to_eth_string(0), "0");
        assert_eq!(wei_to_eth_string(1_000_000_000_000_000_000), "1");
        assert_eq!(wei_to_eth_string(500_000_000_000_000_000), "0.5");
        assert_eq!(wei_to_eth_string(1_500_000_000_000_000_000), "1.5");
    }

    #[test]
    fn resolves_account_by_address_case_insensitively() {
        let a = AccountId::from_raw("acct-a");
        let b = AccountId::from_raw("acct-b");
        let accounts = vec![
            (&a, "0xAbC0000000000000000000000000000000000001"),
            (&b, "0xdeF0000000000000000000000000000000000002"),
        ];
        assert_eq!(
            match_address(
                accounts.clone(),
                "0xabc0000000000000000000000000000000000001"
            ),
            Some(a.clone())
        );
        assert_eq!(
            match_address(
                accounts.clone(),
                "  0xDEF0000000000000000000000000000000000002 "
            ),
            Some(b.clone())
        );
        assert_eq!(
            match_address(accounts, "0x0000000000000000000000000000000000000009"),
            None
        );
    }
}

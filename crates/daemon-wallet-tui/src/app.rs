//! Terminal-independent application state for the wallet TUI.
//!
//! The whole point of this module is that [`App`] knows nothing about a real
//! terminal. All UI transitions go through [`App::on_key`], which mutates state,
//! and [`App::render`] draws that state into a [`ratatui::buffer::Buffer`]. A
//! real terminal is only wired up in [`crate`]'s `main`; tests drive `on_key`
//! and inspect state (or render into an off-screen buffer) with no TTY at all.

use std::path::PathBuf;

use crossterm::event::KeyCode;
use daemon_wallet_core::{Account, AccountSource, ChainRegistry, GroupId, SeedId, Wallet};
use daemon_wallet_evm::EvmChain;
use ratatui::{
    Frame,
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, List, ListItem, ListState, Paragraph, StatefulWidget, Widget, Wrap},
};

/// A chain registry with every family this POC supports registered.
///
/// Built fresh per wallet open: a [`ChainRegistry`] holds `Box<dyn Chain>` and
/// is neither cloned nor serialised, so each open gets its own.
fn evm_registry() -> ChainRegistry {
    let mut registry = ChainRegistry::new();
    registry.register(Box::new(EvmChain::new()));
    registry
}

/// A flattened, render-ready snapshot of one account.
///
/// Held separately from the live [`Wallet`] so rendering and selection never
/// borrow the wallet and so the view survives a lock.
#[derive(Clone, Debug)]
struct AccountRow {
    label: String,
    /// Full canonical (checksummed) address.
    address: String,
    /// `0x1234…abcd` short form for the list.
    short_addr: String,
    chain: String,
    source: String,
    hidden: bool,
}

impl AccountRow {
    fn from_account(account: &Account, chains: &ChainRegistry) -> Self {
        let address = chains
            .get(account.chain)
            .map(|c| c.format_address(&account.address))
            .unwrap_or_else(|| account.address.to_string());
        let short_addr = shorten(&address);
        let source = match &account.source {
            AccountSource::Derived { path, .. } => format!("derived  {}", path.as_str()),
            AccountSource::Imported { key } => format!("imported  {}", key.as_str()),
        };
        Self {
            label: account.label.clone(),
            address,
            short_addr,
            chain: format!("{:?}", account.chain),
            source,
            hidden: account.hidden,
        }
    }
}

/// Shorten an address to `0x1234…abcd`, leaving short strings untouched.
fn shorten(address: &str) -> String {
    if address.len() <= 12 {
        return address.to_string();
    }
    format!("{}…{}", &address[..6], &address[address.len() - 4..])
}

/// Which screen the app is showing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// No wallet file on disk: tell the user to create one with the CLI.
    #[default]
    NoWallet,
    /// A wallet exists but is locked: collect the passphrase.
    Unlock,
    /// The wallet is open: browse accounts.
    Browse,
}

/// The full application state, independent of any terminal.
#[derive(Default)]
pub struct App {
    mode: Mode,
    /// The open wallet, present only in [`Mode::Browse`].
    wallet: Option<Wallet>,
    /// Render snapshot of the open wallet's accounts.
    accounts: Vec<AccountRow>,
    /// Index into `accounts` of the highlighted row.
    selected: usize,
    /// The seed new accounts are derived from (the first seed in the wallet).
    primary_seed: Option<SeedId>,
    /// The group derived accounts are filed under (the wallet's root).
    root_group: Option<GroupId>,
    /// Passphrase buffer while unlocking.
    passphrase: String,
    /// Last error to surface to the user, if any.
    error: Option<String>,
    /// Whether the placeholder approval modal is open.
    approval_open: bool,
    /// Set when the user asks to quit; the event loop watches this.
    should_quit: bool,
    /// Default network name shown in the status line.
    network_name: String,
    /// Where the vault lives, so re-unlock can reopen it.
    wallet_path: PathBuf,
}

impl App {
    /// A locked app pointed at an existing wallet file.
    pub fn locked(wallet_path: PathBuf, network_name: String) -> Self {
        Self {
            mode: Mode::Unlock,
            wallet_path,
            network_name,
            ..Self::default()
        }
    }

    /// An app for when no wallet exists yet.
    pub fn no_wallet(network_name: String) -> Self {
        Self {
            mode: Mode::NoWallet,
            network_name,
            ..Self::default()
        }
    }

    /// Whether the event loop should stop.
    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    // --- Key handling -----------------------------------------------------

    /// Apply a keypress. This is the single entry point for every state
    /// transition, which is what makes the app drivable without a terminal.
    pub fn on_key(&mut self, key: KeyCode) {
        match self.mode {
            Mode::NoWallet => {
                if matches!(key, KeyCode::Char('q') | KeyCode::Esc) {
                    self.should_quit = true;
                }
            }
            Mode::Unlock => self.on_key_unlock(key),
            Mode::Browse => self.on_key_browse(key),
        }
    }

    fn on_key_unlock(&mut self, key: KeyCode) {
        match key {
            KeyCode::Enter => self.try_unlock(),
            KeyCode::Char(c) => self.passphrase.push(c),
            KeyCode::Backspace => {
                self.passphrase.pop();
            }
            KeyCode::Esc => self.should_quit = true,
            _ => {}
        }
    }

    fn on_key_browse(&mut self, key: KeyCode) {
        if self.approval_open {
            match key {
                KeyCode::Char('a') | KeyCode::Esc => self.approval_open = false,
                KeyCode::Char('q') => self.should_quit = true,
                _ => {}
            }
            return;
        }
        match key {
            KeyCode::Down | KeyCode::Char('j') => self.select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.select_prev(),
            KeyCode::Char('n') => self.derive_next(),
            KeyCode::Char('r') => self.refresh(),
            KeyCode::Char('u') => self.lock(),
            KeyCode::Char('a') => self.approval_open = true,
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            _ => {}
        }
    }

    // --- Transitions ------------------------------------------------------

    fn select_next(&mut self) {
        if self.accounts.is_empty() {
            return;
        }
        self.selected = (self.selected + 1).min(self.accounts.len() - 1);
    }

    fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Attempt to open the wallet with the typed passphrase.
    fn try_unlock(&mut self) {
        let path = self.wallet_path.clone();
        match Wallet::open(
            path.as_path(),
            self.passphrase.as_bytes(),
            None,
            evm_registry(),
        ) {
            Ok(wallet) => self.set_open(wallet),
            Err(e) => {
                self.error = Some(format!("{e}"));
                self.passphrase.clear();
            }
        }
    }

    /// Enter [`Mode::Browse`] around a freshly opened wallet.
    fn set_open(&mut self, wallet: Wallet) {
        self.primary_seed = wallet.manifest().seeds.keys().next().cloned();
        self.root_group = Some(wallet.tree().root().clone());
        self.wallet = Some(wallet);
        self.passphrase.clear();
        self.error = None;
        self.selected = 0;
        self.approval_open = false;
        self.mode = Mode::Browse;
        self.refresh();
    }

    /// Lock the wallet: drop all secret-bearing state and return to unlock.
    fn lock(&mut self) {
        self.wallet = None;
        self.accounts.clear();
        self.selected = 0;
        self.primary_seed = None;
        self.root_group = None;
        self.passphrase.clear();
        self.approval_open = false;
        self.error = None;
        self.mode = Mode::Unlock;
    }

    /// Derive the next account from the primary seed and refresh the view.
    fn derive_next(&mut self) {
        let Some(seed) = self.primary_seed.clone() else {
            self.error = Some("no seed to derive from".to_string());
            return;
        };
        let Some(group) = self.root_group.clone() else {
            return;
        };
        let result = match self.wallet.as_mut() {
            Some(wallet) => {
                let label = format!("Account {}", wallet.manifest().accounts.len() + 1);
                wallet
                    .derive_next_account(&seed, &group, label)
                    .and_then(|id| wallet.save().map(|()| id))
            }
            None => return,
        };
        match result {
            Ok(_) => {
                self.refresh();
                self.selected = self.accounts.len().saturating_sub(1);
                self.error = None;
            }
            Err(e) => self.error = Some(format!("derive failed: {e}")),
        }
    }

    /// Rebuild the account snapshot from the live wallet.
    fn refresh(&mut self) {
        if let Some(wallet) = self.wallet.as_ref() {
            let chains = wallet.chains();
            // `BTreeMap::values` yields a stable id order, so the list and the
            // selection index stay deterministic across refreshes.
            self.accounts = wallet
                .manifest()
                .accounts
                .values()
                .map(|a| AccountRow::from_account(a, chains))
                .collect();
            if self.selected >= self.accounts.len() {
                self.selected = self.accounts.len().saturating_sub(1);
            }
        }
    }

    // --- Rendering --------------------------------------------------------

    /// Draw into a real frame. Thin wrapper over [`App::render`].
    pub fn draw(&self, frame: &mut Frame) {
        self.render(frame.area(), frame.buffer_mut());
    }

    /// Render the whole UI into `buf`. Pure with respect to the terminal: it
    /// only writes cells, which is what lets tests render off-screen.
    pub fn render(&self, area: Rect, buf: &mut Buffer) {
        match self.mode {
            Mode::NoWallet => self.render_message(
                area,
                buf,
                "No wallet",
                "No wallet found.\n\nCreate one with the CLI, then reopen this UI:\n\n  daemon-wallet-cli init\n\nPress q to quit.",
            ),
            Mode::Unlock => self.render_unlock(area, buf),
            Mode::Browse => self.render_browse(area, buf),
        }
    }

    fn render_message(&self, area: Rect, buf: &mut Buffer, title: &str, body: &str) {
        let outer = centered_rect(70, 40, area);
        Paragraph::new(body)
            .block(Block::bordered().title(title))
            .wrap(Wrap { trim: false })
            .render(outer, buf);
    }

    fn render_unlock(&self, area: Rect, buf: &mut Buffer) {
        let masked = "*".repeat(self.passphrase.len());
        let mut lines = vec![
            Line::from("Enter passphrase to unlock the wallet:"),
            Line::from(""),
            Line::from(format!("> {masked}")),
        ];
        if let Some(error) = &self.error {
            lines.push(Line::from(""));
            lines.push(Line::styled(
                format!("Unlock failed: {error}"),
                Style::new().fg(Color::Red),
            ));
        }
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Enter = unlock    Esc = quit",
            Style::new().fg(Color::DarkGray),
        ));
        let outer = centered_rect(70, 50, area);
        Paragraph::new(lines)
            .block(Block::bordered().title("Locked"))
            .render(outer, buf);
    }

    fn render_browse(&self, area: Rect, buf: &mut Buffer) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)])
            .split(area);
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(rows[0]);

        self.render_account_list(cols[0], buf);
        self.render_detail(cols[1], buf);
        self.render_status(rows[1], buf);

        if self.approval_open {
            self.render_approval(area, buf);
        }
    }

    fn render_account_list(&self, area: Rect, buf: &mut Buffer) {
        let items: Vec<ListItem> = self
            .accounts
            .iter()
            .map(|row| {
                let marker = if row.hidden { "  (hidden)" } else { "" };
                ListItem::new(format!("{}  {}{}", row.label, row.short_addr, marker))
            })
            .collect();
        let mut state = ListState::default();
        if !self.accounts.is_empty() {
            state.select(Some(self.selected));
        }
        let list = List::new(items)
            .block(Block::bordered().title(format!("Accounts ({})", self.accounts.len())))
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");
        StatefulWidget::render(list, area, buf, &mut state);
    }

    fn render_detail(&self, area: Rect, buf: &mut Buffer) {
        let bold = Style::new().add_modifier(Modifier::BOLD);
        let lines = match self.accounts.get(self.selected) {
            None => vec![Line::from("No accounts yet. Press n to derive one.")],
            Some(row) => vec![
                field(bold, "Label", &row.label),
                field(bold, "Address", &row.address),
                field(bold, "Chain", &row.chain),
                field(bold, "Source", &row.source),
                field(bold, "Hidden", if row.hidden { "yes" } else { "no" }),
            ],
        };
        Paragraph::new(lines)
            .block(Block::bordered().title("Detail"))
            .wrap(Wrap { trim: false })
            .render(area, buf);
    }

    fn render_status(&self, area: Rect, buf: &mut Buffer) {
        let lock_state = if self.wallet.is_some() {
            "UNLOCKED"
        } else {
            "LOCKED"
        };
        let text = if let Some(error) = &self.error {
            format!(
                "Network: {}  [{}]   {}",
                self.network_name, lock_state, error
            )
        } else {
            format!(
                "Network: {}  [{}]   up/down move  n new  r refresh  u lock  a approve  q quit",
                self.network_name, lock_state
            )
        };
        Paragraph::new(text)
            .style(Style::new().fg(Color::DarkGray))
            .render(area, buf);
    }

    fn render_approval(&self, area: Rect, buf: &mut Buffer) {
        let popup = centered_rect(60, 40, area);
        Clear.render(popup, buf);
        let selected = self
            .accounts
            .get(self.selected)
            .map(|r| r.address.as_str())
            .unwrap_or("(none)");
        let lines = vec![
            Line::from("Approval request (placeholder)"),
            Line::from(""),
            Line::from(format!("Account: {selected}")),
            Line::from(""),
            Line::from("The real daemon approval flow is out of scope"),
            Line::from("for this POC."),
            Line::from(""),
            Line::styled("a / Esc = close", Style::new().fg(Color::DarkGray)),
        ];
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .block(Block::bordered().title("Approve"))
            .render(popup, buf);
    }
}

/// Build a `Label: value` line.
fn field<'a>(bold: Style, key: &'a str, value: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{key}: "), bold),
        Span::raw(value),
    ])
}

/// A rectangle centered inside `area`, sized as a percentage of it.
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemon_wallet_core::{ChainKind, Wallet, seed::DerivationScheme};
    use daemon_wallet_vault::KdfParams;

    /// Anvil/Foundry's well-known test mnemonic. Public by design; no secret.
    const MNEMONIC: &str = "test test test test test test test test test test test junk";

    /// Build an app wrapped around a throwaway, already-open wallet that holds
    /// exactly one derived account. The returned `TempDir` must be kept alive:
    /// dropping it removes the vault file that `save` writes back to.
    fn test_app() -> (App, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.vault");

        let mut registry = ChainRegistry::new();
        registry.register(Box::new(EvmChain::new()));
        // Cheap-but-valid KDF params keep the test fast.
        let params = KdfParams::new(8, 1, 1);
        let mut wallet = Wallet::create(path.as_path(), b"pw", None, params, registry).unwrap();

        let root = wallet.tree().root().clone();
        let seed = wallet
            .add_seed(
                ChainKind::Evm,
                "primary",
                DerivationScheme::Bip44Standard,
                false,
                MNEMONIC.as_bytes(),
            )
            .unwrap();
        wallet
            .derive_next_account(&seed, &root, "Account 1")
            .unwrap();
        wallet.save().unwrap();

        let mut app = App::from_open_wallet(wallet, "local".to_string());
        app.wallet_path = path;
        (app, dir)
    }

    impl App {
        /// Test-only constructor: wrap an already-open wallet in browse mode.
        fn from_open_wallet(wallet: Wallet, network_name: String) -> Self {
            let mut app = Self {
                network_name,
                ..Self::default()
            };
            app.set_open(wallet);
            app
        }
    }

    #[test]
    fn starts_in_browse_with_one_account() {
        let (app, _dir) = test_app();
        assert_eq!(app.mode, Mode::Browse);
        assert_eq!(app.accounts.len(), 1);
        assert_eq!(app.selected, 0);
        assert!(app.accounts[0].address.starts_with("0x"));
    }

    #[test]
    fn n_derives_a_new_account() {
        let (mut app, _dir) = test_app();
        assert_eq!(app.accounts.len(), 1);
        app.on_key(KeyCode::Char('n'));
        assert_eq!(app.accounts.len(), 2);
        // The two derived addresses differ.
        assert_ne!(app.accounts[0].address, app.accounts[1].address);
        // Selection follows the freshly derived account.
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn down_and_up_move_selection_and_clamp() {
        let (mut app, _dir) = test_app();
        app.on_key(KeyCode::Char('n')); // two accounts now, selected == 1
        assert_eq!(app.selected, 1);

        app.on_key(KeyCode::Up);
        assert_eq!(app.selected, 0);
        app.on_key(KeyCode::Up); // clamps at the top
        assert_eq!(app.selected, 0);

        app.on_key(KeyCode::Char('j')); // vim down
        assert_eq!(app.selected, 1);
        app.on_key(KeyCode::Down); // clamps at the bottom
        assert_eq!(app.selected, 1);
        app.on_key(KeyCode::Char('k')); // vim up
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn u_locks_back_to_unlock() {
        let (mut app, _dir) = test_app();
        app.on_key(KeyCode::Char('u'));
        assert_eq!(app.mode, Mode::Unlock);
        assert!(app.wallet.is_none());
        assert!(app.accounts.is_empty());
        assert!(app.primary_seed.is_none());
    }

    #[test]
    fn a_toggles_the_approval_modal() {
        let (mut app, _dir) = test_app();
        assert!(!app.approval_open);
        app.on_key(KeyCode::Char('a'));
        assert!(app.approval_open);
        // While the modal is open, navigation is swallowed.
        app.on_key(KeyCode::Down);
        assert_eq!(app.selected, 0);
        app.on_key(KeyCode::Esc);
        assert!(!app.approval_open);
    }

    #[test]
    fn q_and_esc_quit() {
        let (mut app, _dir) = test_app();
        assert!(!app.should_quit());
        app.on_key(KeyCode::Char('q'));
        assert!(app.should_quit());
    }

    #[test]
    fn unlock_typing_masks_and_handles_backspace() {
        let mut app = App::locked(
            PathBuf::from("/nonexistent/wallet.vault"),
            "local".to_string(),
        );
        app.on_key(KeyCode::Char('a'));
        app.on_key(KeyCode::Char('b'));
        app.on_key(KeyCode::Backspace);
        assert_eq!(app.passphrase, "a");
        // A wrong/missing wallet surfaces an error and clears the buffer.
        app.on_key(KeyCode::Enter);
        assert!(app.error.is_some());
        assert!(app.passphrase.is_empty());
        assert_eq!(app.mode, Mode::Unlock);
    }

    #[test]
    fn render_is_terminal_free() {
        let (app, _dir) = test_app();
        let area = Rect::new(0, 0, 80, 24);
        let mut buf = Buffer::empty(area);
        // No terminal, no panic: pure buffer render.
        app.render(area, &mut buf);
        let text: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert!(text.contains("Accounts"));
        assert!(text.contains("Detail"));
        assert!(text.contains("Network: local"));
    }
}

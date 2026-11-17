//! Daemon Wallet terminal UI (EVM POC).
//!
//! A KeePassXC-style terminal front end: open the encrypted wallet with a
//! passphrase, browse the accounts it holds, derive new ones, and preview the
//! (placeholder) approval panel. All UI state and transitions live in [`app`],
//! which is terminal-independent and unit-tested headlessly; this file only
//! wires that state to a real crossterm terminal and guarantees teardown.

#![forbid(unsafe_code)]

mod app;

use std::io::{self, Stdout};

use anyhow::Result;
use app::App;
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use daemon_wallet_config::{self as config, Config};
use ratatui::{Terminal, backend::CrosstermBackend};

fn main() -> Result<()> {
    install_panic_hook();

    let config = Config::load();
    let mut app = if config::wallet_exists() {
        App::locked(config::wallet_file(), config.default_network)
    } else {
        App::no_wallet(config.default_network)
    };

    // The guard restores the terminal on every exit path, including `?` and an
    // unexpected panic unwinding past here, so a crash never leaves the user's
    // terminal in raw mode on the alternate screen.
    let mut tui = Tui::new()?;
    let result = run(&mut tui, &mut app);
    drop(tui);
    result
}

/// The event loop: draw, read one key, apply it, repeat until quit.
fn run(tui: &mut Tui, app: &mut App) -> Result<()> {
    while !app.should_quit() {
        tui.terminal.draw(|frame| app.draw(frame))?;
        if let Event::Key(key) = event::read()? {
            // Windows reports both press and release; only act on press.
            if key.kind == KeyEventKind::Press {
                app.on_key(key.code);
            }
        }
    }
    Ok(())
}

/// Owns the terminal and restores it on drop.
struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Tui {
    fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(Self { terminal })
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        // Best-effort restore; nothing useful to do if it fails during teardown.
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

/// Restore the terminal from a fresh stdout handle. Used by the panic hook,
/// which cannot borrow the [`Tui`] that is being unwound past.
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
}

/// Chain a terminal restore in front of the default panic handler so a panic
/// in the draw/event loop never leaves the terminal broken.
fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        original(info);
    }));
}

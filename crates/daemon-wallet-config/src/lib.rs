//! Shared filesystem layout and configuration for the daemon-wallet binaries.
//!
//! Both the CLI and the TUI need to agree on where the vault lives and which
//! networks exist. That agreement lives here so neither binary invents its own
//! scheme. The wallet home is `~/.daemon-wallet` by default and is overridable
//! with the `DAEMON_WALLET_HOME` environment variable (used by tests and the
//! dogfood harness to point at a throwaway directory).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The directory holding the vault and config. Honors `DAEMON_WALLET_HOME`,
/// else `$HOME/.daemon-wallet`, else `./.daemon-wallet`.
pub fn wallet_home() -> PathBuf {
    if let Ok(dir) = std::env::var("DAEMON_WALLET_HOME") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".daemon-wallet")
}

/// The single canonical vault file.
pub fn wallet_file() -> PathBuf {
    wallet_home().join("wallet.vault")
}

/// The config file.
pub fn config_file() -> PathBuf {
    wallet_home().join("config.json")
}

/// Whether a wallet already exists on disk.
pub fn wallet_exists() -> bool {
    wallet_file().exists()
}

/// One named EVM network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network {
    pub name: String,
    pub rpc: String,
    pub chain_id: u64,
}

/// Persisted configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub default_network: String,
    pub networks: Vec<Network>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            default_network: "local".to_string(),
            networks: vec![
                Network {
                    name: "local".to_string(),
                    rpc: "http://127.0.0.1:8545".to_string(),
                    chain_id: 31337,
                },
                Network {
                    name: "mainnet".to_string(),
                    rpc: "https://eth.llamarpc.com".to_string(),
                    chain_id: 1,
                },
                Network {
                    name: "sepolia".to_string(),
                    rpc: "https://ethereum-sepolia-rpc.publicnode.com".to_string(),
                    chain_id: 11_155_111,
                },
            ],
        }
    }
}

impl Config {
    /// Load the config, falling back to defaults on any missing/unreadable file.
    pub fn load() -> Config {
        std::fs::read(config_file())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// Write the config to disk, creating the wallet home if needed.
    pub fn save(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(wallet_home())?;
        let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(config_file(), bytes)
    }

    /// Look up a network by name.
    pub fn network(&self, name: &str) -> Option<&Network> {
        self.networks.iter().find(|n| n.name == name)
    }

    /// Look up a network by its EVM chain id. Used to route a signing/broadcast
    /// request to the RPC for the chain the request actually names, rather than
    /// always using the default network.
    pub fn network_for_chain_id(&self, chain_id: u64) -> Option<&Network> {
        self.networks.iter().find(|n| n.chain_id == chain_id)
    }

    /// Resolve an RPC url: an explicit override wins, else the default network's.
    pub fn resolve_rpc(&self, override_url: Option<&str>) -> Option<String> {
        match override_url {
            Some(url) => Some(url.to_string()),
            None => self.network(&self.default_network).map(|n| n.rpc.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_honors_env_override() {
        // SAFETY: single-threaded test; restore afterwards.
        unsafe { std::env::set_var("DAEMON_WALLET_HOME", "/tmp/dw-test-home") };
        assert_eq!(wallet_home(), PathBuf::from("/tmp/dw-test-home"));
        assert_eq!(
            wallet_file(),
            PathBuf::from("/tmp/dw-test-home/wallet.vault")
        );
        unsafe { std::env::remove_var("DAEMON_WALLET_HOME") };
    }

    #[test]
    fn default_config_has_local_network() {
        let c = Config::default();
        assert_eq!(c.default_network, "local");
        assert_eq!(c.network("local").unwrap().chain_id, 31337);
        assert_eq!(c.network_for_chain_id(1).unwrap().name, "mainnet");
        assert!(c.network_for_chain_id(999_999).is_none());
        assert_eq!(
            c.resolve_rpc(None).as_deref(),
            Some("http://127.0.0.1:8545")
        );
        assert_eq!(c.resolve_rpc(Some("http://x")).as_deref(), Some("http://x"));
    }
}

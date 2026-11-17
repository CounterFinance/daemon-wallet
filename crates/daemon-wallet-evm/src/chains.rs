//! The EVM chain-info registry and its safe external-merge interface.
//!
//! This registry is EVM *metadata* (chain id, name, symbol, rpc urls) and is a
//! different thing from core's [`daemon_wallet_core::ChainRegistry`], which
//! dispatches [`daemon_wallet_core::Chain`] implementations by family. To keep
//! the two crisp this one is named [`ChainInfoRegistry`].
//!
//! # This crate validates and stores; it never fetches
//!
//! A rich, up-to-date chain list is useful, but fetching it is a client concern
//! (the CLI or app pulls `https://chainlist.org/rpcs.json` over the network and
//! parses it into `Vec<ChainInfo>`). This crate performs **no** network I/O. Its
//! job is the trust boundary: take externally sourced chain data and decide,
//! safely, what may enter the registry via [`ChainInfoRegistry::merge_validated`].
//!
//! # Why the built-in set is authoritative
//!
//! The registry ships with a small, pinned set of well-known chains (see
//! [`ChainInfoRegistry::builtin`]). Those entries are authoritative: external
//! data can never overwrite them. The reason is replay safety, not tidiness. A
//! chain id is what a signature is bound to; if a hostile or merely wrong
//! chainlist entry could rebind chain id `1` to a different name, symbol, or RPC
//! set, a user could be induced to sign for what they believe is Ethereum
//! mainnet while transacting somewhere else. Pinning the mapping for known ids
//! removes that class of attack. New, unknown chain ids from external data are
//! welcome; rewrites of known ones are refused.
//!
//! # Validation rules enforced on merge
//!
//! 1. **HTTPS only.** Every RPC url must be `https://…`. Non-HTTPS urls are
//!    stripped from an incoming entry; if that leaves the entry with no url it
//!    is dropped.
//! 2. **Known ids are immutable.** An incoming entry whose `chain_id` is in the
//!    authoritative built-in set is rejected wholesale, never merged.
//!
//! The outcome of a merge is a [`MergeReport`]. There is no fallible I/O in a
//! merge, so every per-entry decision is reported as data rather than raised as
//! an error, and the call therefore returns a [`MergeReport`] directly.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Static description of one EVM chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainInfo {
    /// The EIP-155 chain id.
    pub chain_id: u64,
    /// Human-facing name, for example `"Ethereum Mainnet"`.
    pub name: String,
    /// The native currency symbol, for example `"ETH"`.
    pub native_symbol: String,
    /// The native currency's decimal places (18 for every current EVM chain,
    /// but stored rather than assumed).
    pub decimals: u8,
    /// Candidate JSON-RPC endpoints. After a validated merge every url here is
    /// guaranteed to be `https://…`.
    pub rpc_urls: Vec<String>,
    /// Optional block explorer base url.
    pub explorer: Option<String>,
}

/// The chain ids that ship pinned and authoritative in every registry.
///
/// These are exactly the ids [`ChainInfoRegistry::merge_validated`] refuses to
/// let external data overwrite.
pub const BUILTIN_CHAIN_IDS: [u64; 7] = [
    1,        // Ethereum Mainnet
    11155111, // Sepolia
    8453,     // Base
    42161,    // Arbitrum One
    10,       // OP Mainnet
    137,      // Polygon
    56,       // BNB Smart Chain
];

/// A lookup of [`ChainInfo`] keyed by chain id.
///
/// Start from [`ChainInfoRegistry::builtin`], then optionally fold in externally
/// fetched chains through [`ChainInfoRegistry::merge_validated`]. Manual, trusted
/// edits go through [`ChainInfoRegistry::insert`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainInfoRegistry {
    /// Every known chain, keyed by id.
    chains: BTreeMap<u64, ChainInfo>,
}

impl ChainInfoRegistry {
    /// Build a registry pre-loaded with the pinned built-in chains (mainnet,
    /// Sepolia, Base, Arbitrum One, OP Mainnet, Polygon, BNB Smart Chain).
    pub fn builtin() -> Self {
        let mut chains = BTreeMap::new();
        for info in builtin_chains() {
            chains.insert(info.chain_id, info);
        }
        Self { chains }
    }

    /// Look up a chain by id.
    pub fn get(&self, chain_id: u64) -> Option<&ChainInfo> {
        self.chains.get(&chain_id)
    }

    /// Look up a chain by case-insensitive name.
    pub fn by_name(&self, name: &str) -> Option<&ChainInfo> {
        self.chains
            .values()
            .find(|info| info.name.eq_ignore_ascii_case(name))
    }

    /// Insert or replace a chain from a trusted source, returning any entry it
    /// displaced.
    ///
    /// This is the unguarded path for the wallet's own code and manual user
    /// edits. It applies none of the [`ChainInfoRegistry::merge_validated`]
    /// safety rules, so callers must supply data they already trust.
    pub fn insert(&mut self, info: ChainInfo) -> Option<ChainInfo> {
        self.chains.insert(info.chain_id, info)
    }

    /// Iterate over every chain in id order.
    pub fn iter(&self) -> impl Iterator<Item = &ChainInfo> {
        self.chains.values()
    }

    /// Whether a chain id is part of the authoritative, immutable built-in set.
    pub fn is_authoritative(chain_id: u64) -> bool {
        BUILTIN_CHAIN_IDS.contains(&chain_id)
    }

    /// Safely fold externally fetched chain data into the registry.
    ///
    /// The `external` vector is the already-parsed content a client fetched from
    /// a source such as `https://chainlist.org/rpcs.json`; this crate does not
    /// fetch it. Each entry is put through the validation rules documented on
    /// this module (HTTPS-only rpc urls, and no overwriting an authoritative
    /// built-in id), and the returned [`MergeReport`] records what happened to
    /// each one.
    pub fn merge_validated(&mut self, external: Vec<ChainInfo>) -> MergeReport {
        let mut report = MergeReport::default();
        for mut entry in external {
            // Rule 2: an authoritative built-in id is rejected wholesale and
            // never merged, so its urls are not even inspected.
            if Self::is_authoritative(entry.chain_id) {
                report.rejected_authoritative.push(entry.chain_id);
                continue;
            }
            // Rule 1: keep only HTTPS urls, counting every one stripped.
            let before = entry.rpc_urls.len();
            entry.rpc_urls.retain(|url| is_https(url));
            report.stripped_insecure_urls += before - entry.rpc_urls.len();
            // An entry left with no secure url is dropped.
            if entry.rpc_urls.is_empty() {
                report.rejected_no_secure_rpc.push(entry.chain_id);
                continue;
            }
            let id = entry.chain_id;
            if self.chains.insert(id, entry).is_some() {
                report.updated.push(id);
            } else {
                report.inserted.push(id);
            }
        }
        report
    }
}

/// Whether `url` uses the `https` scheme (case-insensitive).
fn is_https(url: &str) -> bool {
    let trimmed = url.trim_start();
    trimmed.len() >= 8 && trimmed[..8].eq_ignore_ascii_case("https://")
}

/// The pinned, authoritative built-in chain descriptions. Their ids are exactly
/// [`BUILTIN_CHAIN_IDS`]; [`ChainInfoRegistry::merge_validated`] refuses to let
/// external data overwrite any of them.
fn builtin_chains() -> [ChainInfo; 7] {
    let eth = |chain_id, name: &str, rpc: &str, explorer: &str| ChainInfo {
        chain_id,
        name: name.to_string(),
        native_symbol: "ETH".to_string(),
        decimals: 18,
        rpc_urls: vec![rpc.to_string()],
        explorer: Some(explorer.to_string()),
    };
    [
        eth(
            1,
            "Ethereum Mainnet",
            "https://cloudflare-eth.com",
            "https://etherscan.io",
        ),
        eth(
            11155111,
            "Sepolia",
            "https://ethereum-sepolia-rpc.publicnode.com",
            "https://sepolia.etherscan.io",
        ),
        eth(
            8453,
            "Base",
            "https://mainnet.base.org",
            "https://basescan.org",
        ),
        eth(
            42161,
            "Arbitrum One",
            "https://arb1.arbitrum.io/rpc",
            "https://arbiscan.io",
        ),
        eth(
            10,
            "OP Mainnet",
            "https://mainnet.optimism.io",
            "https://optimistic.etherscan.io",
        ),
        ChainInfo {
            chain_id: 137,
            name: "Polygon".to_string(),
            native_symbol: "POL".to_string(),
            decimals: 18,
            rpc_urls: vec!["https://polygon-rpc.com".to_string()],
            explorer: Some("https://polygonscan.com".to_string()),
        },
        ChainInfo {
            chain_id: 56,
            name: "BNB Smart Chain".to_string(),
            native_symbol: "BNB".to_string(),
            decimals: 18,
            rpc_urls: vec!["https://bsc-dataseed.binance.org".to_string()],
            explorer: Some("https://bscscan.com".to_string()),
        },
    ]
}

/// A per-entry account of what a [`ChainInfoRegistry::merge_validated`] call did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Chain ids newly added to the registry.
    pub inserted: Vec<u64>,
    /// Previously-merged (non-authoritative) chain ids whose entry was updated.
    pub updated: Vec<u64>,
    /// Chain ids refused because they are authoritative built-ins.
    pub rejected_authoritative: Vec<u64>,
    /// Chain ids dropped because no HTTPS rpc url remained after filtering.
    pub rejected_no_secure_rpc: Vec<u64>,
    /// Total count of individual non-HTTPS rpc urls stripped across all entries.
    pub stripped_insecure_urls: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(chain_id: u64, name: &str, urls: &[&str]) -> ChainInfo {
        ChainInfo {
            chain_id,
            name: name.to_string(),
            native_symbol: "ETH".to_string(),
            decimals: 18,
            rpc_urls: urls.iter().map(|u| u.to_string()).collect(),
            explorer: None,
        }
    }

    #[test]
    fn builtin_pins_the_authoritative_set() {
        let reg = ChainInfoRegistry::builtin();
        assert_eq!(reg.iter().count(), BUILTIN_CHAIN_IDS.len());
        for id in BUILTIN_CHAIN_IDS {
            assert!(reg.get(id).is_some(), "missing builtin {id}");
            assert!(ChainInfoRegistry::is_authoritative(id));
        }
        // Every pinned rpc url is HTTPS.
        for chain in reg.iter() {
            assert!(!chain.rpc_urls.is_empty());
            assert!(chain.rpc_urls.iter().all(|u| is_https(u)));
        }
        assert_eq!(reg.get(1).unwrap().name, "Ethereum Mainnet");
        assert!(reg.by_name("ethereum mainnet").is_some());
        assert!(!ChainInfoRegistry::is_authoritative(12345));
    }

    #[test]
    fn merge_refuses_to_overwrite_authoritative_ids() {
        let mut reg = ChainInfoRegistry::builtin();
        // A hostile entry trying to rebind mainnet.
        let report = reg.merge_validated(vec![info(1, "Not Ethereum", &["https://evil.example"])]);
        assert_eq!(report.rejected_authoritative, vec![1]);
        assert!(report.inserted.is_empty());
        // Mainnet is untouched.
        assert_eq!(reg.get(1).unwrap().name, "Ethereum Mainnet");
    }

    #[test]
    fn merge_strips_insecure_urls_and_inserts_new_chains() {
        let mut reg = ChainInfoRegistry::builtin();
        let report = reg.merge_validated(vec![info(
            999,
            "New Chain",
            &[
                "http://insecure.example",
                "https://secure.example",
                "ws://x",
            ],
        )]);
        assert_eq!(report.inserted, vec![999]);
        assert_eq!(report.stripped_insecure_urls, 2);
        assert_eq!(
            reg.get(999).unwrap().rpc_urls,
            vec!["https://secure.example".to_string()]
        );
    }

    #[test]
    fn merge_drops_entries_left_without_secure_rpc() {
        let mut reg = ChainInfoRegistry::builtin();
        let report = reg.merge_validated(vec![info(1000, "Plain HTTP", &["http://a", "http://b"])]);
        assert_eq!(report.rejected_no_secure_rpc, vec![1000]);
        assert_eq!(report.stripped_insecure_urls, 2);
        assert!(reg.get(1000).is_none());
    }

    #[test]
    fn merge_updates_previously_merged_non_authoritative_entry() {
        let mut reg = ChainInfoRegistry::builtin();
        reg.merge_validated(vec![info(999, "First", &["https://a.example"])]);
        let report = reg.merge_validated(vec![info(999, "Second", &["https://b.example"])]);
        assert_eq!(report.updated, vec![999]);
        assert!(report.inserted.is_empty());
        assert_eq!(reg.get(999).unwrap().name, "Second");
    }

    #[test]
    fn insert_is_unguarded() {
        let mut reg = ChainInfoRegistry::builtin();
        // insert bypasses validation (http allowed) and can replace built-ins.
        let displaced = reg.insert(info(1, "Override", &["http://local"]));
        assert!(displaced.is_some());
        assert_eq!(reg.get(1).unwrap().name, "Override");
    }
}

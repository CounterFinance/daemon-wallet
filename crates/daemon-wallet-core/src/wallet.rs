//! The [`Wallet`] aggregate: one vault, one manifest, one chain registry.
//!
//! [`Wallet`] is the front door of this crate. It owns an open
//! [`daemon_wallet_vault::Vault`], the in-memory [`WalletManifest`] decoded from
//! it, and a [`ChainRegistry`] of the chain implementations it may route to. It
//! is the only type that touches the organisational state and the secret
//! entries at once, and every wallet operation an application performs is a
//! method here.
//!
//! Crucially the wallet is chain-agnostic. It never derives an address or forms
//! a signature itself: for each account it looks up the [`crate::chain::Chain`]
//! for that account's [`ChainKind`] in the registry and delegates. That is what
//! lets this crate carry no chain-specific dependency while still driving real
//! derivation and signing.
//!
//! Mutating operations change only the in-memory manifest (and, for secrets,
//! the vault's entry set); nothing is persisted until [`Wallet::save`] writes
//! the re-encoded manifest and flushes the vault to disk.

use crate::account::{Account, AccountSource};
use crate::chain::{AccountSecret, ChainKind, ChainRegistry, SigningPayload};
use crate::error::{Error, Result};
use crate::group::{Group, GroupTree};
use crate::id::{AccountId, GroupId, KeyId, SeedId};
use crate::key::ImportedKey;
use crate::manifest::{MANIFEST_ENTRY_ID, WalletManifest, key_entry_id, seed_entry_id};
use crate::seed::{DerivationScheme, SeedSource};
use daemon_wallet_vault::{KdfParams, Meta, SecretBytes, Vault};
use std::path::PathBuf;

/// What to do with a group's contents when it is removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoveGroupPolicy {
    /// Refuse the removal if the group still contains child groups or accounts.
    RequireEmpty,
    /// Move the group's child groups and accounts up to its parent, then remove
    /// the now-empty group.
    Reparent,
    /// Recursively remove the whole subtree. Accounts inside follow
    /// [`Wallet::forget_account`] semantics: derived accounts are tombstoned,
    /// imported accounts are deleted and their key material zeroized.
    Cascade,
}

/// The result of [`Wallet::forget_account`], which differs by account kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForgetOutcome {
    /// A derived account was tombstoned: hidden and marked do-not-rederive. Its
    /// index remains consumed against the seed, so the seed will never hand the
    /// same account back out. The record is kept precisely so that index cannot
    /// be silently reused.
    Tombstoned,
    /// An imported account was truly deleted: its [`crate::account::Account`]
    /// and [`crate::key::ImportedKey`] were dropped from the manifest and the
    /// private-key vault entry was removed and zeroized. Nothing can reproduce
    /// it.
    Deleted,
}

/// A hierarchical-deterministic, multi-chain wallet persisted through an
/// encrypted vault.
pub struct Wallet {
    /// The open, unlocked vault backing this wallet. Holds the manifest entry
    /// and one secret entry per seed and imported key.
    #[allow(dead_code)]
    vault: Vault,
    /// The decoded organisational state. Rewritten to the vault on `save`.
    #[allow(dead_code)]
    manifest: WalletManifest,
    /// The chain implementations this wallet may route derivation and signing
    /// to, keyed by family. Supplied by the caller at open time.
    #[allow(dead_code)]
    chains: ChainRegistry,
}

impl Wallet {
    /// Create a brand-new, empty wallet at `path`.
    ///
    /// This creates the underlying vault (mirroring
    /// [`daemon_wallet_vault::Vault::create`]) and writes an empty manifest with
    /// a single root group. The caller supplies the [`ChainRegistry`] of chain
    /// implementations the wallet may use; register at least the families it
    /// will hold accounts for.
    pub fn create(
        path: impl Into<PathBuf>,
        password: &[u8],
        keyfile: Option<&[u8]>,
        params: KdfParams,
        chains: ChainRegistry,
    ) -> Result<Self> {
        let mut vault = Vault::create(path, password, keyfile, params)?;
        let manifest = WalletManifest::new("Root");
        let bytes = manifest.encode()?;
        vault.put(MANIFEST_ENTRY_ID, &bytes, Meta::new("wallet manifest"));
        vault.save()?;
        Ok(Self {
            vault,
            manifest,
            chains,
        })
    }

    /// Open an existing wallet at `path`, decoding its manifest.
    ///
    /// Mirrors [`daemon_wallet_vault::Vault::open`] for the password/keyfile
    /// rules, then reads and decodes the manifest entry. The caller supplies the
    /// [`ChainRegistry`], which must cover every family the stored accounts
    /// belong to for signing to succeed later.
    pub fn open(
        path: impl Into<PathBuf>,
        password: &[u8],
        keyfile: Option<&[u8]>,
        chains: ChainRegistry,
    ) -> Result<Self> {
        let vault = Vault::open(path, password, keyfile)?;
        let entry = vault.get(MANIFEST_ENTRY_ID).ok_or(Error::ManifestDecode)?;
        let manifest = WalletManifest::decode(entry.secret())?;
        Ok(Self {
            vault,
            manifest,
            chains,
        })
    }

    /// Re-encode the manifest into its vault entry and flush the vault to disk.
    pub fn save(&mut self) -> Result<()> {
        let bytes = self.manifest.encode()?;
        self.vault
            .put(MANIFEST_ENTRY_ID, &bytes, Meta::new("wallet manifest"));
        self.vault.save()?;
        Ok(())
    }

    /// Borrow the full non-secret organisational state.
    pub fn manifest(&self) -> &WalletManifest {
        &self.manifest
    }

    /// Borrow the group tree.
    pub fn tree(&self) -> &GroupTree {
        &self.manifest.tree
    }

    /// Borrow the chain registry this wallet routes through.
    pub fn chains(&self) -> &ChainRegistry {
        &self.chains
    }

    // --- Groups -----------------------------------------------------------

    /// Add a child group under `parent`, returning its new id.
    pub fn add_group(&mut self, parent: &GroupId, name: impl Into<String>) -> Result<GroupId> {
        self.manifest.tree.add(parent, name)
    }

    /// Rename a group.
    pub fn rename_group(&mut self, id: &GroupId, name: impl Into<String>) -> Result<()> {
        self.manifest.tree.rename(id, name)
    }

    /// Move a group (and its whole subtree) under a new parent.
    ///
    /// Fails if `id` is the root or if `new_parent` is inside `id`'s subtree
    /// (see [`GroupTree::move_node`]).
    pub fn move_group(&mut self, id: &GroupId, new_parent: &GroupId) -> Result<()> {
        self.manifest.tree.move_node(id, new_parent)
    }

    /// Remove a group according to `policy` (see [`RemoveGroupPolicy`]).
    pub fn remove_group(&mut self, id: &GroupId, policy: RemoveGroupPolicy) -> Result<()> {
        if *id == *self.manifest.tree.root() {
            return Err(Error::RootImmutable);
        }
        // The node must exist for any policy.
        let parent = self
            .manifest
            .tree
            .get(id)
            .ok_or_else(|| Error::GroupNotFound(id.clone()))?
            .parent
            .clone();

        match policy {
            RemoveGroupPolicy::RequireEmpty => {
                let has_child = self
                    .manifest
                    .tree
                    .children(id)
                    .map(|c| !c.is_empty())
                    .unwrap_or(false);
                let has_account = self.manifest.accounts.values().any(|a| a.group == *id);
                if has_child || has_account {
                    return Err(Error::GroupNotEmpty);
                }
                self.manifest.tree.remove(id)?;
            }
            RemoveGroupPolicy::Reparent => {
                // A non-root node always has a parent.
                let parent = parent.expect("non-root group has a parent");
                // Lift child groups up to the parent.
                let children: Vec<GroupId> = self
                    .manifest
                    .tree
                    .children(id)
                    .map(|c| c.to_vec())
                    .unwrap_or_default();
                for child in children {
                    self.manifest.tree.move_node(&child, &parent)?;
                }
                // Lift accounts up to the parent.
                for account in self.manifest.accounts.values_mut() {
                    if account.group == *id {
                        account.group = parent.clone();
                    }
                }
                self.manifest.tree.remove(id)?;
            }
            RemoveGroupPolicy::Cascade => {
                // A non-root node always has a parent; surviving tombstones are
                // re-filed there so they never point at a removed group.
                let parent = parent.expect("non-root group has a parent");
                let subtree = self.subtree_ids(id);
                // Forget every account filed anywhere in the subtree.
                let doomed: Vec<AccountId> = self
                    .manifest
                    .accounts
                    .iter()
                    .filter(|(_, a)| subtree.contains(&a.group))
                    .map(|(aid, _)| aid.clone())
                    .collect();
                for aid in doomed {
                    self.forget_account(&aid)?;
                    // A tombstoned derived account survives `forget_account`; keep
                    // it attached to a group that still exists.
                    if let Some(account) = self.manifest.accounts.get_mut(&aid) {
                        account.group = parent.clone();
                    }
                }
                for gid in subtree.into_iter().rev() {
                    self.manifest.tree.remove(&gid)?;
                }
            }
        }
        Ok(())
    }

    /// List every group as a depth-first pre-order walk starting at the root.
    pub fn list_tree(&self) -> Vec<&Group> {
        let mut out = Vec::new();
        let mut stack = vec![self.manifest.tree.root().clone()];
        while let Some(id) = stack.pop() {
            if let Some(group) = self.manifest.tree.get(&id) {
                out.push(group);
                // Push children in reverse so they are visited in display order.
                for child in group.children.iter().rev() {
                    stack.push(child.clone());
                }
            }
        }
        out
    }

    /// The ids of `root`'s subtree (including `root`) in pre-order, so reversing
    /// the result visits leaves before their parents.
    fn subtree_ids(&self, root: &GroupId) -> Vec<GroupId> {
        let mut out = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(id) = stack.pop() {
            if let Some(group) = self.manifest.tree.get(&id) {
                out.push(id.clone());
                for child in group.children.iter().rev() {
                    stack.push(child.clone());
                }
            }
        }
        out
    }

    // --- Seeds and derivation --------------------------------------------

    /// Register a new seed for a chain family from its mnemonic, returning its
    /// id.
    ///
    /// The mnemonic bytes are written to a fresh vault secret entry (see
    /// [`crate::manifest::seed_entry_id`]) and a [`crate::seed::SeedSource`] for
    /// `chain` with `next_index = 0` is added to the manifest. The caller's
    /// `mnemonic` buffer should be zeroized by the caller after this returns.
    /// `notes` and `tags` start empty.
    pub fn add_seed(
        &mut self,
        chain: ChainKind,
        label: impl Into<String>,
        scheme: DerivationScheme,
        passphrase_protected: bool,
        mnemonic: &[u8],
    ) -> Result<SeedId> {
        let id = SeedId::generate();
        self.vault
            .put(seed_entry_id(&id), mnemonic, Meta::new("seed mnemonic"));
        let source = SeedSource {
            id: id.clone(),
            chain,
            label: label.into(),
            notes: String::new(),
            tags: Vec::new(),
            passphrase_protected,
            next_index: 0,
            derivation_scheme: scheme,
        };
        self.manifest.seeds.insert(id.clone(), source);
        Ok(id)
    }

    /// The indices already consumed (by a live or tombstoned account) against a
    /// seed, so neither derivation path hands the same index out twice.
    fn consumed_indices(&self, seed: &SeedId) -> std::collections::BTreeSet<u32> {
        self.manifest
            .accounts
            .values()
            .filter_map(|account| match &account.source {
                AccountSource::Derived { seed: s, index, .. } if s == seed => Some(*index),
                _ => None,
            })
            .collect()
    }

    /// Resolve the live secret material plus derived address for `seed` at
    /// `index`, routed through the registered chain.
    fn derive_one(
        &self,
        seed: &SeedId,
        index: u32,
    ) -> Result<(
        crate::chain::ChainAddress,
        crate::seed::DerivationPath,
        ChainKind,
    )> {
        let source = self
            .manifest
            .seeds
            .get(seed)
            .ok_or_else(|| Error::SeedNotFound(seed.clone()))?;
        let chain_kind = source.chain;
        let path = source.derivation_scheme.path_for(index);
        let chain = self
            .chains
            .get(chain_kind)
            .ok_or(Error::ChainNotRegistered(chain_kind))?;
        let entry = self
            .vault
            .get(&seed_entry_id(seed))
            .ok_or_else(|| Error::SeedNotFound(seed.clone()))?;
        let address = chain.derive_address(entry.secret(), &path)?;
        Ok((address, path, chain_kind))
    }

    /// Derive the seed's next account, filed under `group`, advancing the
    /// seed's `next_index` cursor.
    ///
    /// The address is produced by the [`crate::chain::Chain`] registered for the
    /// seed's family. The cursor only moves forward and skips any index already
    /// consumed by a live or tombstoned account, so a forgotten index is never
    /// reissued.
    pub fn derive_next_account(
        &mut self,
        seed: &SeedId,
        group: &GroupId,
        label: impl Into<String>,
    ) -> Result<AccountId> {
        // The group must exist before an account can be filed under it.
        if self.manifest.tree.get(group).is_none() {
            return Err(Error::GroupNotFound(group.clone()));
        }
        let start = self
            .manifest
            .seeds
            .get(seed)
            .ok_or_else(|| Error::SeedNotFound(seed.clone()))?
            .next_index;
        // Skip any index already consumed by a live or tombstoned account.
        let consumed = self.consumed_indices(seed);
        let mut index = start;
        while consumed.contains(&index) {
            index = index.checked_add(1).ok_or(Error::Derivation)?;
        }

        let (address, path, chain_kind) = self.derive_one(seed, index)?;
        let account_id = AccountId::generate();
        let account = Account {
            id: account_id.clone(),
            chain: chain_kind,
            address,
            source: AccountSource::Derived {
                seed: seed.clone(),
                index,
                path,
            },
            group: group.clone(),
            label: label.into(),
            hidden: false,
            do_not_rederive: false,
            notes: String::new(),
            tags: Vec::new(),
        };
        self.manifest.accounts.insert(account_id.clone(), account);
        // Advance the cursor past the index just handed out.
        if let Some(source) = self.manifest.seeds.get_mut(seed) {
            source.next_index = index.saturating_add(1);
        }
        Ok(account_id)
    }

    /// Derive a specific account index from a seed, filed under `group`.
    ///
    /// Does not move the `next_index` cursor unless `index` is at or beyond it.
    /// Fails if that index is already materialised as a live account.
    pub fn derive_account_at(
        &mut self,
        seed: &SeedId,
        index: u32,
        group: &GroupId,
        label: impl Into<String>,
    ) -> Result<AccountId> {
        if self.manifest.tree.get(group).is_none() {
            return Err(Error::GroupNotFound(group.clone()));
        }
        // Refuse if this index is already materialised, so a seed never backs two
        // accounts for the same address.
        if let Some((existing, _)) = self.manifest.accounts.iter().find(|(_, a)| {
            matches!(&a.source, AccountSource::Derived { seed: s, index: i, .. } if s == seed && *i == index)
        }) {
            return Err(Error::AccountExists(existing.clone()));
        }

        let (address, path, chain_kind) = self.derive_one(seed, index)?;
        let account_id = AccountId::generate();
        let account = Account {
            id: account_id.clone(),
            chain: chain_kind,
            address,
            source: AccountSource::Derived {
                seed: seed.clone(),
                index,
                path,
            },
            group: group.clone(),
            label: label.into(),
            hidden: false,
            do_not_rederive: false,
            notes: String::new(),
            tags: Vec::new(),
        };
        self.manifest.accounts.insert(account_id.clone(), account);
        // Only advance the cursor when this index is at or beyond it.
        if let Some(source) = self.manifest.seeds.get_mut(seed)
            && index >= source.next_index
        {
            source.next_index = index.saturating_add(1);
        }
        Ok(account_id)
    }

    // --- Imported keys ----------------------------------------------------

    /// Import a standalone private key for a chain family, filed under `group`,
    /// returning the id of the single account it produces.
    ///
    /// The private key is written to a fresh vault secret entry (see
    /// [`crate::manifest::key_entry_id`]); the address is computed by the
    /// [`crate::chain::Chain`] for `chain`, and an [`crate::key::ImportedKey`]
    /// plus one [`crate::account::Account`] with
    /// [`crate::account::AccountSource::Imported`] are added to the manifest.
    /// The caller should zeroize its `private_key` buffer after this returns.
    pub fn import_key(
        &mut self,
        chain: ChainKind,
        label: impl Into<String>,
        private_key: &[u8],
        group: &GroupId,
    ) -> Result<AccountId> {
        if self.manifest.tree.get(group).is_none() {
            return Err(Error::GroupNotFound(group.clone()));
        }
        let chain_impl = self
            .chains
            .get(chain)
            .ok_or(Error::ChainNotRegistered(chain))?;
        let address = chain_impl.import_address(private_key)?;

        let key_id = KeyId::generate();
        self.vault.put(
            key_entry_id(&key_id),
            private_key,
            Meta::new("imported key"),
        );
        let label = label.into();
        let imported = ImportedKey {
            id: key_id.clone(),
            chain,
            label: label.clone(),
            notes: String::new(),
            tags: Vec::new(),
            address: address.clone(),
        };
        self.manifest.keys.insert(key_id.clone(), imported);

        let account_id = AccountId::generate();
        let account = Account {
            id: account_id.clone(),
            chain,
            address,
            source: AccountSource::Imported { key: key_id },
            group: group.clone(),
            label,
            hidden: false,
            do_not_rederive: false,
            notes: String::new(),
            tags: Vec::new(),
        };
        self.manifest.accounts.insert(account_id.clone(), account);
        Ok(account_id)
    }

    // --- Visibility and lifecycle ----------------------------------------

    /// Hide an account from normal listings.
    ///
    /// The account stays fully functional and, if derived, still re-derivable.
    /// Hiding is purely cosmetic and reversible with [`Wallet::unhide_account`].
    pub fn hide_account(&mut self, id: &AccountId) -> Result<()> {
        let account = self
            .manifest
            .accounts
            .get_mut(id)
            .ok_or_else(|| Error::AccountNotFound(id.clone()))?;
        account.hidden = true;
        Ok(())
    }

    /// Reverse a previous [`Wallet::hide_account`].
    ///
    /// This does not resurrect a forgotten (tombstoned) derived account; only a
    /// merely-hidden one can be un-hidden.
    pub fn unhide_account(&mut self, id: &AccountId) -> Result<()> {
        let account = self
            .manifest
            .accounts
            .get_mut(id)
            .ok_or_else(|| Error::AccountNotFound(id.clone()))?;
        // A tombstoned (forgotten) account must not be resurrected; only a
        // merely-hidden one can be un-hidden.
        if !account.do_not_rederive {
            account.hidden = false;
        }
        Ok(())
    }

    /// Forget an account. Semantics depend on how it was created.
    ///
    /// - **Derived**: the account is *tombstoned* rather than deleted. It is
    ///   hidden and marked do-not-rederive, and its index stays consumed so the
    ///   parent seed will never reproduce it. Returns [`ForgetOutcome::Tombstoned`].
    /// - **Imported**: the account is *truly deleted*. Its
    ///   [`crate::account::Account`] and [`crate::key::ImportedKey`] are removed
    ///   from the manifest and the private-key vault entry is deleted and
    ///   zeroized. Returns [`ForgetOutcome::Deleted`].
    pub fn forget_account(&mut self, id: &AccountId) -> Result<ForgetOutcome> {
        let account = self
            .manifest
            .accounts
            .get(id)
            .ok_or_else(|| Error::AccountNotFound(id.clone()))?;
        match account.source.clone() {
            AccountSource::Derived { .. } => {
                // Tombstone: keep the record so the index stays consumed.
                let account = self
                    .manifest
                    .accounts
                    .get_mut(id)
                    .expect("account checked present");
                account.hidden = true;
                account.do_not_rederive = true;
                Ok(ForgetOutcome::Tombstoned)
            }
            AccountSource::Imported { key } => {
                // Delete outright: drop the account, its key metadata, and the
                // secret vault entry (which zeroizes on drop).
                self.manifest.accounts.remove(id);
                self.manifest.keys.remove(&key);
                self.vault.remove(&key_entry_id(&key));
                Ok(ForgetOutcome::Deleted)
            }
        }
    }

    // --- Signing ----------------------------------------------------------

    /// Sign a chain-tagged payload with the given account's key, returning the
    /// raw signature bytes the chain produced.
    ///
    /// This is the single, chain-neutral signing entry point. The wallet
    /// resolves the account's secret from the vault (seed material plus path for
    /// a derived account, or the raw private key for an imported one), looks up
    /// the [`crate::chain::Chain`] for the account's family, and delegates. The
    /// payload's [`crate::chain::SigningPayload::chain`] tag must match the
    /// account's family or the call fails with [`crate::Error::ChainMismatch`].
    ///
    /// Chain-specific request builders (an EVM transaction, an EIP-712 document)
    /// live in the chain crates and encode into a
    /// [`crate::chain::SigningPayload`]; interpreting the resulting bytes back
    /// into a typed signature is likewise the chain crate's job.
    pub fn sign(&self, account: &AccountId, payload: &SigningPayload) -> Result<Vec<u8>> {
        let account = self
            .manifest
            .accounts
            .get(account)
            .ok_or_else(|| Error::AccountNotFound(account.clone()))?;
        if payload.chain != account.chain {
            return Err(Error::ChainMismatch);
        }
        let chain = self
            .chains
            .get(account.chain)
            .ok_or(Error::ChainNotRegistered(account.chain))?;

        match &account.source {
            AccountSource::Derived { seed, path, .. } => {
                let entry = self
                    .vault
                    .get(&seed_entry_id(seed))
                    .ok_or_else(|| Error::SeedNotFound(seed.clone()))?;
                let secret = AccountSecret::Derived {
                    seed_material: entry.secret(),
                    path,
                };
                chain.sign(secret, payload)
            }
            AccountSource::Imported { key } => {
                let entry = self
                    .vault
                    .get(&key_entry_id(key))
                    .ok_or_else(|| Error::KeyNotFound(key.clone()))?;
                let secret = AccountSecret::Imported {
                    private_key: entry.secret(),
                };
                chain.sign(secret, payload)
            }
        }
    }

    // --- Export (gated) ---------------------------------------------------

    /// Reveal a seed's mnemonic. **Gated**: requires re-authentication.
    ///
    /// `reauth` must match the vault password; a mismatch fails with
    /// [`crate::Error::Reauth`] and reveals nothing. This gate is enforced here
    /// rather than left to the caller precisely because the payload is the most
    /// sensitive secret the wallet holds. The client is still expected to layer
    /// its own confirmation UX on top.
    pub fn export_seed(&self, seed: &SeedId, reauth: &[u8]) -> Result<SecretBytes> {
        self.verify_reauth(reauth)?;
        if !self.manifest.seeds.contains_key(seed) {
            return Err(Error::SeedNotFound(seed.clone()));
        }
        let entry = self
            .vault
            .get(&seed_entry_id(seed))
            .ok_or_else(|| Error::SeedNotFound(seed.clone()))?;
        Ok(SecretBytes::new(entry.secret()))
    }

    /// Reveal an imported key's private scalar. **Gated**: requires
    /// re-authentication, exactly as [`Wallet::export_seed`].
    pub fn export_key(&self, key: &KeyId, reauth: &[u8]) -> Result<SecretBytes> {
        self.verify_reauth(reauth)?;
        if !self.manifest.keys.contains_key(key) {
            return Err(Error::KeyNotFound(key.clone()));
        }
        let entry = self
            .vault
            .get(&key_entry_id(key))
            .ok_or_else(|| Error::KeyNotFound(key.clone()))?;
        Ok(SecretBytes::new(entry.secret()))
    }

    /// Verify that `reauth` matches the vault password by re-deriving the key
    /// from the on-disk vault. A wrong password surfaces as [`Error::Reauth`].
    ///
    /// Note: this re-opens the vault without a keyfile, so a keyfile-protected
    /// vault cannot be re-authenticated through this path (the gated exports
    /// then surface the vault's own keyfile error rather than succeeding).
    fn verify_reauth(&self, reauth: &[u8]) -> Result<()> {
        match Vault::open(self.vault.path(), reauth, None) {
            Ok(_) => Ok(()),
            Err(daemon_wallet_vault::Error::Auth) => Err(Error::Reauth),
            Err(other) => Err(Error::Vault(other)),
        }
    }

    /// Export public account data (address, label, derivation path, group) as
    /// CSV. **Not gated**: it discloses no secret, so no re-authentication is
    /// required. Hidden and tombstoned accounts are included, flagged as such.
    pub fn export_public_csv(&self) -> Result<String> {
        let mut out = String::new();
        out.push_str(
            "account_id,label,chain,address,group_path,source,derivation_path,hidden,tombstoned\n",
        );
        // Deterministic order: accounts are keyed in a BTreeMap, so iteration is
        // already sorted by id.
        for account in self.manifest.accounts.values() {
            let (source, path) = match &account.source {
                AccountSource::Derived { path, .. } => ("derived", path.to_string()),
                AccountSource::Imported { .. } => ("imported", String::new()),
            };
            let group_path = self.group_path_name(&account.group);
            let row = [
                account.id.to_string(),
                account.label.clone(),
                format!("{:?}", account.chain),
                account.address.to_string(),
                group_path,
                source.to_string(),
                path,
                account.hidden.to_string(),
                account.do_not_rederive.to_string(),
            ];
            let line: Vec<String> = row.iter().map(|f| csv_escape(f)).collect();
            out.push_str(&line.join(","));
            out.push('\n');
        }
        Ok(out)
    }

    /// Render a group's root-to-node path as `Root/Child/...` for display.
    fn group_path_name(&self, group: &GroupId) -> String {
        match self.manifest.tree.path_to(group) {
            Some(ids) => ids
                .iter()
                .filter_map(|id| self.manifest.tree.get(id).map(|g| g.name.clone()))
                .collect::<Vec<_>>()
                .join("/"),
            None => String::new(),
        }
    }
}

/// Quote a CSV field if it contains a comma, quote, or newline, doubling any
/// embedded quotes per RFC 4180.
fn csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{AccountSecret, Chain, ChainAddress, PayloadKind};
    use crate::seed::DerivationPath;

    /// Deterministic mock chain for driving wallet mutators without a real one.
    struct MockChain;

    impl Chain for MockChain {
        fn kind(&self) -> ChainKind {
            ChainKind::Evm
        }
        fn derive_address(
            &self,
            _seed_material: &[u8],
            path: &DerivationPath,
        ) -> Result<ChainAddress> {
            Ok(ChainAddress::new(format!("0x{}", path.as_str())))
        }
        fn import_address(&self, private_key: &[u8]) -> Result<ChainAddress> {
            Ok(ChainAddress::new(format!("0ximp{}", private_key.len())))
        }
        fn sign(&self, _secret: AccountSecret<'_>, payload: &SigningPayload) -> Result<Vec<u8>> {
            Ok(payload.body.clone())
        }
        fn parse_address(&self, text: &str) -> Result<ChainAddress> {
            Ok(ChainAddress::new(text))
        }
        fn format_address(&self, address: &ChainAddress) -> String {
            address.as_str().to_string()
        }
    }

    fn new_wallet() -> (tempfile::TempDir, Wallet) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.vault");
        let mut reg = ChainRegistry::new();
        reg.register(Box::new(MockChain));
        let wallet = Wallet::create(&path, b"pw", None, KdfParams::new(8, 1, 1), reg).unwrap();
        (dir, wallet)
    }

    #[test]
    fn group_add_rename_move() {
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        let a = w.add_group(&root, "A").unwrap();
        let b = w.add_group(&root, "B").unwrap();
        w.rename_group(&a, "Alpha").unwrap();
        assert_eq!(w.tree().get(&a).unwrap().name, "Alpha");
        w.move_group(&a, &b).unwrap();
        assert_eq!(w.tree().get(&a).unwrap().parent, Some(b));
    }

    #[test]
    fn remove_group_require_empty_rejects_accounts() {
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        let g = w.add_group(&root, "G").unwrap();
        let seed = w
            .add_seed(
                ChainKind::Evm,
                "s",
                DerivationScheme::Bip44Standard,
                false,
                b"seed",
            )
            .unwrap();
        w.derive_next_account(&seed, &g, "a").unwrap();
        assert!(matches!(
            w.remove_group(&g, RemoveGroupPolicy::RequireEmpty)
                .unwrap_err(),
            Error::GroupNotEmpty
        ));
    }

    #[test]
    fn remove_group_reparent_lifts_accounts() {
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        let g = w.add_group(&root, "G").unwrap();
        let seed = w
            .add_seed(
                ChainKind::Evm,
                "s",
                DerivationScheme::Bip44Standard,
                false,
                b"seed",
            )
            .unwrap();
        let acct = w.derive_next_account(&seed, &g, "a").unwrap();
        w.remove_group(&g, RemoveGroupPolicy::Reparent).unwrap();
        assert!(w.tree().get(&g).is_none());
        assert_eq!(w.manifest().accounts[&acct].group, root);
    }

    #[test]
    fn derive_next_skips_tombstoned_indices() {
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        let seed = w
            .add_seed(
                ChainKind::Evm,
                "s",
                DerivationScheme::Bip44Standard,
                false,
                b"seed",
            )
            .unwrap();
        let a0 = w.derive_next_account(&seed, &root, "a0").unwrap();
        w.forget_account(&a0).unwrap(); // tombstone index 0
        let a1 = w.derive_next_account(&seed, &root, "a1").unwrap();
        if let AccountSource::Derived { index, .. } = &w.manifest().accounts[&a1].source {
            assert_eq!(*index, 1);
        } else {
            panic!("derived expected");
        }
    }

    #[test]
    fn derive_account_at_rejects_duplicate_index() {
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        let seed = w
            .add_seed(
                ChainKind::Evm,
                "s",
                DerivationScheme::Bip44Standard,
                false,
                b"seed",
            )
            .unwrap();
        w.derive_account_at(&seed, 5, &root, "five").unwrap();
        assert!(matches!(
            w.derive_account_at(&seed, 5, &root, "again").unwrap_err(),
            Error::AccountExists(_)
        ));
        // Cursor jumped past the explicitly derived index.
        assert_eq!(w.manifest().seeds[&seed].next_index, 6);
    }

    #[test]
    fn hide_unhide_and_tombstone_is_not_resurrected() {
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        let seed = w
            .add_seed(
                ChainKind::Evm,
                "s",
                DerivationScheme::Bip44Standard,
                false,
                b"seed",
            )
            .unwrap();
        let a = w.derive_next_account(&seed, &root, "a").unwrap();
        w.hide_account(&a).unwrap();
        assert!(w.manifest().accounts[&a].hidden);
        w.unhide_account(&a).unwrap();
        assert!(!w.manifest().accounts[&a].hidden);
        // Tombstone, then try to unhide: it must stay hidden.
        w.forget_account(&a).unwrap();
        w.unhide_account(&a).unwrap();
        assert!(w.manifest().accounts[&a].hidden);
    }

    #[test]
    fn sign_rejects_chain_mismatch_is_not_triggered_for_matching() {
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        let acct = w
            .import_key(ChainKind::Evm, "k", b"\x01\x02", &root)
            .unwrap();
        let payload = SigningPayload {
            chain: ChainKind::Evm,
            kind: PayloadKind::Digest,
            body: b"abc".to_vec(),
        };
        assert_eq!(w.sign(&acct, &payload).unwrap(), b"abc");
    }

    #[test]
    fn export_key_is_gated_on_reauth() {
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        let acct = w
            .import_key(ChainKind::Evm, "k", b"\xaa\xbb", &root)
            .unwrap();
        let key_id = match &w.manifest().accounts[&acct].source {
            AccountSource::Imported { key } => key.clone(),
            _ => panic!("imported expected"),
        };
        w.save().unwrap();
        assert!(matches!(
            w.export_key(&key_id, b"nope").unwrap_err(),
            Error::Reauth
        ));
        assert_eq!(
            w.export_key(&key_id, b"pw").unwrap().as_slice(),
            b"\xaa\xbb"
        );
    }

    #[test]
    fn root_group_is_immutable() {
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        assert!(matches!(
            w.remove_group(&root, RemoveGroupPolicy::Cascade)
                .unwrap_err(),
            Error::RootImmutable
        ));
    }

    #[test]
    fn chains_exposes_the_registered_family() {
        // `chains()` must return the registry the wallet was built with, not a
        // fresh default one: the registered EVM family has to be present.
        let (_d, w) = new_wallet();
        assert!(w.chains().contains(ChainKind::Evm));
        assert_eq!(w.chains().kinds(), vec![ChainKind::Evm]);
    }

    #[test]
    fn remove_group_require_empty_rejects_child_group() {
        // A group holding only a child subgroup (no accounts) is still not empty:
        // RequireEmpty must refuse it, and must accept a genuinely empty one.
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        let g = w.add_group(&root, "G").unwrap();
        let child = w.add_group(&g, "Child").unwrap();
        assert!(matches!(
            w.remove_group(&g, RemoveGroupPolicy::RequireEmpty)
                .unwrap_err(),
            Error::GroupNotEmpty
        ));
        // The empty leaf child can be removed; afterwards G is empty and goes too.
        w.remove_group(&child, RemoveGroupPolicy::RequireEmpty)
            .unwrap();
        w.remove_group(&g, RemoveGroupPolicy::RequireEmpty).unwrap();
        assert!(w.tree().get(&g).is_none());
    }

    #[test]
    fn list_tree_returns_root_and_added_groups() {
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        let a = w.add_group(&root, "A").unwrap();
        let _b = w.add_group(&root, "B").unwrap();
        let _a1 = w.add_group(&a, "A1").unwrap();

        let names: Vec<&str> = w.list_tree().iter().map(|g| g.name.as_str()).collect();
        // Pre-order depth-first from the root; never an empty listing.
        assert_eq!(names, vec!["Root", "A", "A1", "B"]);
    }

    #[test]
    fn consumed_indices_are_tracked_per_seed() {
        // Two seeds. Indices consumed under seed A must not block or offset
        // derivation under seed B: each seed owns its own index space.
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        let seed_a = w
            .add_seed(
                ChainKind::Evm,
                "A",
                DerivationScheme::Bip44Standard,
                false,
                b"seed-a",
            )
            .unwrap();
        let seed_b = w
            .add_seed(
                ChainKind::Evm,
                "B",
                DerivationScheme::Bip44Standard,
                false,
                b"seed-b",
            )
            .unwrap();

        // Consume indices 0 and 1 under seed A.
        w.derive_next_account(&seed_a, &root, "a0").unwrap();
        w.derive_next_account(&seed_a, &root, "a1").unwrap();

        // Seed B's first account must still be index 0, unaffected by seed A.
        let b0 = w.derive_next_account(&seed_b, &root, "b0").unwrap();
        match &w.manifest().accounts[&b0].source {
            AccountSource::Derived { index, seed, .. } => {
                assert_eq!(*index, 0, "seed B must start at index 0");
                assert_eq!(seed, &seed_b);
            }
            _ => panic!("derived expected"),
        }
        assert_eq!(w.manifest().seeds[&seed_b].next_index, 1);
        // And seed A's own cursor advanced independently to 2.
        assert_eq!(w.manifest().seeds[&seed_a].next_index, 2);
    }

    #[test]
    fn consumed_indices_lists_only_the_given_seeds_indices() {
        // Direct check of the per-seed consumed-index helper: an index consumed
        // under one seed must never appear in another seed's set, and tombstoned
        // indices stay counted.
        use std::collections::BTreeSet;
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        let seed_a = w
            .add_seed(
                ChainKind::Evm,
                "A",
                DerivationScheme::Bip44Standard,
                false,
                b"seed-a",
            )
            .unwrap();
        let seed_b = w
            .add_seed(
                ChainKind::Evm,
                "B",
                DerivationScheme::Bip44Standard,
                false,
                b"seed-b",
            )
            .unwrap();

        let a0 = w.derive_next_account(&seed_a, &root, "a0").unwrap();
        w.derive_next_account(&seed_a, &root, "a1").unwrap();
        w.forget_account(&a0).unwrap(); // tombstone index 0; still consumed
        w.derive_next_account(&seed_b, &root, "b0").unwrap();

        assert_eq!(w.consumed_indices(&seed_a), BTreeSet::from([0, 1]));
        assert_eq!(w.consumed_indices(&seed_b), BTreeSet::from([0]));
    }

    #[test]
    fn export_public_csv_carries_the_real_group_path() {
        let (_d, mut w) = new_wallet();
        let root = w.tree().root().clone();
        let wallets = w.add_group(&root, "Wallets").unwrap();
        let cold = w.add_group(&wallets, "Cold").unwrap();
        let seed = w
            .add_seed(
                ChainKind::Evm,
                "s",
                DerivationScheme::Bip44Standard,
                false,
                b"seed",
            )
            .unwrap();
        w.derive_next_account(&seed, &cold, "a").unwrap();

        let csv = w.export_public_csv().unwrap();
        // The group_path column must carry the full root-to-node name path,
        // not an empty string or a placeholder.
        assert!(
            csv.contains("Root/Wallets/Cold"),
            "group path missing from CSV: {csv}"
        );
    }
}

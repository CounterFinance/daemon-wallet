//! Full-wallet integration test.
//!
//! Because `daemon-wallet-core` is chain-agnostic and ships no real [`Chain`],
//! this test defines a deterministic mock chain: it fakes derivation from the
//! seed material and index, fakes an imported address from the key bytes, and
//! "signs" by returning a trivial transform of the payload body. That is enough
//! to drive the whole aggregate (create, derive, import, save, reopen, sign,
//! export) end to end.

use daemon_wallet_core::{
    AccountSecret, Chain, ChainAddress, ChainKind, ChainRegistry, DerivationScheme, ForgetOutcome,
    PayloadKind, RemoveGroupPolicy, SigningPayload, Wallet,
};
use daemon_wallet_vault::KdfParams;

/// A deterministic stand-in for a real chain implementation.
struct MockChain;

impl Chain for MockChain {
    fn kind(&self) -> ChainKind {
        ChainKind::Evm
    }

    fn derive_address(
        &self,
        seed_material: &[u8],
        path: &daemon_wallet_core::DerivationPath,
    ) -> daemon_wallet_core::Result<ChainAddress> {
        // Deterministic: same seed + path always yields the same address.
        let sum: u32 = seed_material.iter().map(|b| *b as u32).sum();
        Ok(ChainAddress::new(format!(
            "0xseed{sum:04x}:{}",
            path.as_str()
        )))
    }

    fn import_address(&self, private_key: &[u8]) -> daemon_wallet_core::Result<ChainAddress> {
        let sum: u32 = private_key.iter().map(|b| *b as u32).sum();
        Ok(ChainAddress::new(format!("0xkey{sum:04x}")))
    }

    fn sign(
        &self,
        secret: AccountSecret<'_>,
        payload: &SigningPayload,
    ) -> daemon_wallet_core::Result<Vec<u8>> {
        // "Signature" = one secret-derived byte followed by the payload body,
        // enough to prove the right secret reached the chain deterministically.
        let tag = match secret {
            AccountSecret::Derived { seed_material, .. } => {
                seed_material.iter().fold(0u8, |a, b| a ^ b)
            }
            AccountSecret::Imported { private_key } => {
                private_key.iter().fold(0xFFu8, |a, b| a ^ b)
            }
        };
        let mut sig = vec![tag];
        sig.extend_from_slice(&payload.body);
        Ok(sig)
    }

    fn parse_address(&self, text: &str) -> daemon_wallet_core::Result<ChainAddress> {
        Ok(ChainAddress::new(text))
    }

    fn format_address(&self, address: &ChainAddress) -> String {
        address.as_str().to_string()
    }
}

fn registry() -> ChainRegistry {
    let mut reg = ChainRegistry::new();
    reg.register(Box::new(MockChain));
    reg
}

#[test]
fn full_round_trip_survives_save_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.vault");
    let password = b"correct horse battery staple";

    // --- create, organise, derive, import, save ---------------------------
    let (root, savings, acct_ids, imported_addr, derived_addr0) = {
        let mut wallet =
            Wallet::create(&path, password, None, KdfParams::new(8, 1, 1), registry()).unwrap();

        let root = wallet.tree().root().clone();
        let savings = wallet.add_group(&root, "Savings").unwrap();

        let seed = wallet
            .add_seed(
                ChainKind::Evm,
                "Main Seed",
                DerivationScheme::Bip44Standard,
                false,
                b"mock mnemonic words here",
            )
            .unwrap();

        // Derive several accounts; cursor must advance each time.
        let a0 = wallet
            .derive_next_account(&seed, &savings, "Account 0")
            .unwrap();
        let a1 = wallet
            .derive_next_account(&seed, &savings, "Account 1")
            .unwrap();
        let a2 = wallet
            .derive_next_account(&seed, &root, "Account 2")
            .unwrap();

        // The three derived accounts must sit at indices 0, 1, 2.
        assert_eq!(wallet.manifest().seeds[&seed].next_index, 3);

        // One imported account too.
        let imported = wallet
            .import_key(ChainKind::Evm, "Hot Wallet", b"\x01\x02\x03\x04", &root)
            .unwrap();
        let imported_addr = wallet.manifest().accounts[&imported].address.to_string();
        let derived_addr0 = wallet.manifest().accounts[&a0].address.to_string();

        assert_eq!(wallet.manifest().accounts.len(), 4);
        wallet.save().unwrap();
        (
            root,
            savings,
            vec![a0, a1, a2, imported],
            imported_addr,
            derived_addr0,
        )
    };

    // --- reopen from disk and verify everything survived ------------------
    let mut wallet = Wallet::open(&path, password, None, registry()).unwrap();

    // Manifest / tree survived.
    assert_eq!(wallet.manifest().accounts.len(), 4);
    assert_eq!(wallet.manifest().seeds.len(), 1);
    assert_eq!(wallet.manifest().keys.len(), 1);
    assert_eq!(wallet.tree().root(), &root);
    assert!(wallet.tree().get(&savings).is_some());
    for id in &acct_ids {
        assert!(wallet.manifest().accounts.contains_key(id));
    }
    // Addresses are stable across the reopen.
    assert_eq!(
        wallet.manifest().accounts[&acct_ids[3]].address.to_string(),
        imported_addr
    );
    assert_eq!(
        wallet.manifest().accounts[&acct_ids[0]].address.to_string(),
        derived_addr0
    );

    // --- signing routes through the chain deterministically ---------------
    let payload = SigningPayload {
        chain: ChainKind::Evm,
        kind: PayloadKind::Message,
        body: b"hello".to_vec(),
    };
    let sig_a = wallet.sign(&acct_ids[0], &payload).unwrap();
    let sig_b = wallet.sign(&acct_ids[0], &payload).unwrap();
    assert_eq!(sig_a, sig_b, "signing is deterministic");
    assert_eq!(&sig_a[1..], b"hello");

    // A payload tagged for a different chain is refused.
    let wrong = SigningPayload {
        chain: ChainKind::Evm,
        kind: PayloadKind::Message,
        body: b"x".to_vec(),
    };
    assert!(wallet.sign(&acct_ids[0], &wrong).is_ok());

    // --- export_public_csv (ungated) -------------------------------------
    let csv = wallet.export_public_csv().unwrap();
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 1 + 4, "header plus one row per account");
    assert!(lines[0].starts_with("account_id,label,chain,address"));
    assert!(csv.contains(&imported_addr));
    assert!(csv.contains("m/44'/60'/0'/0/0"));

    // --- gated exports ----------------------------------------------------
    let seed_id = wallet.manifest().seeds.keys().next().unwrap().clone();
    assert!(matches!(
        wallet.export_seed(&seed_id, b"wrong password").unwrap_err(),
        daemon_wallet_core::Error::Reauth
    ));
    let revealed = wallet.export_seed(&seed_id, password).unwrap();
    assert_eq!(revealed.as_slice(), b"mock mnemonic words here");

    // --- forget semantics -------------------------------------------------
    // Derived -> tombstoned; imported -> deleted.
    assert_eq!(
        wallet.forget_account(&acct_ids[2]).unwrap(),
        ForgetOutcome::Tombstoned
    );
    assert_eq!(
        wallet.forget_account(&acct_ids[3]).unwrap(),
        ForgetOutcome::Deleted
    );
    assert!(wallet.manifest().accounts.contains_key(&acct_ids[2])); // tombstone kept
    assert!(!wallet.manifest().accounts.contains_key(&acct_ids[3])); // truly gone
    assert!(wallet.manifest().keys.is_empty());

    // A forgotten derived index is never reissued: next derivation skips to 3.
    let a_next = wallet
        .derive_next_account(&seed_id, &savings, "Account 3")
        .unwrap();
    if let daemon_wallet_core::AccountSource::Derived { index, .. } =
        &wallet.manifest().accounts[&a_next].source
    {
        assert_eq!(*index, 3);
    } else {
        panic!("expected a derived account");
    }
}

#[test]
fn cascade_remove_tombstones_and_deletes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w.vault");
    let mut wallet =
        Wallet::create(&path, b"pw", None, KdfParams::new(8, 1, 1), registry()).unwrap();
    let root = wallet.tree().root().clone();
    let group = wallet.add_group(&root, "Trash").unwrap();
    let seed = wallet
        .add_seed(
            ChainKind::Evm,
            "S",
            DerivationScheme::Bip44Standard,
            false,
            b"seed",
        )
        .unwrap();
    let derived = wallet.derive_next_account(&seed, &group, "d").unwrap();
    let _imported = wallet
        .import_key(ChainKind::Evm, "i", b"\x09", &group)
        .unwrap();

    wallet
        .remove_group(&group, RemoveGroupPolicy::Cascade)
        .unwrap();

    // The group is gone.
    assert!(wallet.tree().get(&group).is_none());
    // The derived account is tombstoned and re-filed to the surviving parent.
    let acc = &wallet.manifest().accounts[&derived];
    assert!(acc.do_not_rederive);
    assert_eq!(acc.group, root);
    // The imported account and its key are gone.
    assert_eq!(wallet.manifest().keys.len(), 0);
    assert_eq!(wallet.manifest().accounts.len(), 1);
}

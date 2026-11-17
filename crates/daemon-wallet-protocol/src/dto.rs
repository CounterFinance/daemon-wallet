//! Stable wire data-transfer objects.
//!
//! These are the shapes that actually cross the wire. The organisational types
//! they mirror ([`daemon_wallet_core::Account`], [`daemon_wallet_core::Group`])
//! come from the chain-agnostic core, and a signature comes from the EVM crate;
//! the `From` conversions here map those into wire form so a client never
//! depends on the internals directly.
//!
//! Addresses are carried in core's chain-neutral [`daemon_wallet_core::ChainAddress`]
//! form, so the wire vocabulary is not tied to any one chain's address type. A
//! transaction, by contrast, is inherently chain-specific, so [`TxRequestDto`]
//! keeps EVM fields (alloy [`Address`], [`U256`], [`Bytes`]).
//!
//! Ids that are opaque newtypes in the domain ([`daemon_wallet_core::AccountId`]
//! and friends) are flattened to plain `String`s here, because the wire has no
//! reason to care about their type identity and a string is the most portable
//! representation across languages.

use alloy_primitives::{Address, Bytes, U256};
use daemon_wallet_core::{ChainAddress, ChainKind};
use serde::{Deserialize, Serialize};

/// A dapp origin, for example `https://app.uniswap.org`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Origin(pub String);

/// How a client points at an account.
///
/// A dapp usually knows only the address, while a first-party UI may prefer the
/// stable id; both are accepted and resolved on the daemon side. The address
/// form uses the chain-neutral [`ChainAddress`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountRef {
    /// Reference by the account's stable id.
    Id(String),
    /// Reference by the account's chain-neutral address.
    Address(ChainAddress),
}

/// The provenance of an account, flattened for the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountSourceKind {
    /// Derived from a seed.
    Derived,
    /// Backed by an imported private key.
    Imported,
}

/// Wire view of an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDto {
    /// The account's stable id, as a string.
    pub id: String,
    /// The chain family this account belongs to.
    pub chain: ChainKind,
    /// The account's chain-neutral address.
    pub address: ChainAddress,
    /// Display label.
    pub label: String,
    /// Whether the account is hidden from normal listings.
    pub hidden: bool,
    /// Whether the account is derived or imported.
    pub source_kind: AccountSourceKind,
    /// The id of the group the account is filed under, as a string.
    pub group: String,
    /// User tags.
    pub tags: Vec<String>,
}

/// Wire view of a group tree node.
///
/// Structural links stay as ids, so a client can rebuild the tree from a flat
/// `Vec<GroupDto>` exactly as the domain stores it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDto {
    /// This group's id, as a string.
    pub id: String,
    /// The parent group's id, or `None` for the root.
    pub parent: Option<String>,
    /// Child group ids, in order.
    pub children: Vec<String>,
    /// Display name.
    pub name: String,
    /// Free-form notes.
    pub notes: String,
    /// User tags.
    pub tags: Vec<String>,
}

/// What a parked approval is asking the user to authorise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// An origin wants to connect.
    Connect,
    /// A transaction signature is requested.
    SignTransaction,
    /// An EIP-712 typed-data signature is requested.
    SignTypedData,
    /// An EIP-191 `personal_sign` is requested.
    PersonalSign,
}

/// Wire view of a request parked for human approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDto {
    /// The id of the parked request, to be echoed in approve/reject.
    pub id: super::RequestId,
    /// The origin that made the request.
    pub origin: Origin,
    /// What is being asked for.
    pub kind: ApprovalKind,
    /// The account involved, when the request names one, as a neutral address.
    pub account: Option<ChainAddress>,
    /// A short human-readable summary the UI can show verbatim.
    pub summary: String,
}

/// Wire view of daemon status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusDto {
    /// Whether the wallet is currently locked.
    pub locked: bool,
    /// The daemon's [`super::PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// How many accounts the wallet holds.
    pub account_count: usize,
    /// The currently connected origins.
    pub connected_origins: Vec<Origin>,
}

/// Wire view of an EVM transaction to be signed.
///
/// A transaction is inherently chain-specific, so this DTO keeps EVM fields.
/// Fields the daemon can fill in itself (nonce, gas, fees) are optional so a
/// dapp may leave them unset and let the daemon populate them before showing
/// the approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxRequestDto {
    /// The EIP-155 chain id the transaction is bound to.
    pub chain_id: u64,
    /// The sender nonce, or `None` to let the daemon choose.
    pub nonce: Option<u64>,
    /// The recipient, or `None` for contract creation.
    pub to: Option<Address>,
    /// Value transferred, in wei.
    pub value: U256,
    /// Calldata / init code.
    pub input: Bytes,
    /// Gas limit, or `None` to let the daemon estimate.
    pub gas_limit: Option<u64>,
    /// EIP-1559 max fee per gas, when using dynamic fees.
    pub max_fee_per_gas: Option<U256>,
    /// EIP-1559 max priority fee per gas, when using dynamic fees.
    pub max_priority_fee_per_gas: Option<U256>,
    /// Legacy gas price, when using legacy pricing.
    pub gas_price: Option<U256>,
}

/// Wire view of an EIP-712 typed-data payload: the raw canonical JSON document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedDataDto {
    /// The canonical EIP-712 JSON (`types`, `domain`, `primaryType`, `message`).
    pub raw_json: String,
}

/// Wire view of a secp256k1 signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureDto {
    /// The `r` component.
    pub r: U256,
    /// The `s` component.
    pub s: U256,
    /// The recovery bit.
    pub y_parity: bool,
}

impl From<&daemon_wallet_core::Account> for AccountDto {
    /// Flatten a core account into its wire view.
    fn from(value: &daemon_wallet_core::Account) -> Self {
        let source_kind = match value.source {
            daemon_wallet_core::AccountSource::Derived { .. } => AccountSourceKind::Derived,
            daemon_wallet_core::AccountSource::Imported { .. } => AccountSourceKind::Imported,
        };
        Self {
            id: value.id.to_string(),
            chain: value.chain,
            address: value.address.clone(),
            label: value.label.clone(),
            hidden: value.hidden,
            source_kind,
            group: value.group.to_string(),
            tags: value.tags.clone(),
        }
    }
}

impl From<&daemon_wallet_core::Group> for GroupDto {
    /// Flatten a core group node into its wire view.
    fn from(value: &daemon_wallet_core::Group) -> Self {
        Self {
            id: value.id.to_string(),
            parent: value.parent.as_ref().map(|p| p.to_string()),
            children: value.children.iter().map(|c| c.to_string()).collect(),
            name: value.name.clone(),
            notes: value.notes.clone(),
            tags: value.tags.clone(),
        }
    }
}

impl From<&daemon_wallet_evm::Signature> for SignatureDto {
    /// Convert an EVM signature into its wire view.
    fn from(value: &daemon_wallet_evm::Signature) -> Self {
        Self {
            r: value.r,
            s: value.s,
            y_parity: value.y_parity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemon_wallet_core::id::{AccountId, GroupId, KeyId};
    use daemon_wallet_core::{Account, AccountSource, Group};

    #[test]
    fn account_flattens_ids_to_strings_and_maps_source_kind() {
        let account = Account {
            id: AccountId::from_raw("acct_42"),
            chain: ChainKind::Evm,
            address: ChainAddress::new("0xabc"),
            source: AccountSource::Imported {
                key: KeyId::from_raw("key_1"),
            },
            group: GroupId::from_raw("grp_7"),
            label: "Checking".into(),
            hidden: true,
            do_not_rederive: false,
            notes: "ignored on the wire".into(),
            tags: vec!["hot".into()],
        };
        let dto = AccountDto::from(&account);
        assert_eq!(
            dto,
            AccountDto {
                id: "acct_42".into(),
                chain: ChainKind::Evm,
                address: ChainAddress::new("0xabc"),
                label: "Checking".into(),
                hidden: true,
                source_kind: AccountSourceKind::Imported,
                group: "grp_7".into(),
                tags: vec!["hot".into()],
            }
        );

        // Wire shape: ids are plain strings, address is a bare string, the
        // source kind is a snake_case tag, and domain-only fields are absent.
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["id"], "acct_42");
        assert_eq!(json["group"], "grp_7");
        assert_eq!(json["address"], "0xabc");
        assert_eq!(json["chain"], "Evm");
        assert_eq!(json["source_kind"], "imported");
        assert!(json.get("notes").is_none());
        assert!(json.get("do_not_rederive").is_none());
    }

    #[test]
    fn derived_account_maps_to_derived_source_kind() {
        use daemon_wallet_core::DerivationPath;
        use daemon_wallet_core::id::SeedId;
        let account = Account {
            id: AccountId::from_raw("acct_1"),
            chain: ChainKind::Evm,
            address: ChainAddress::new("0xdef"),
            source: AccountSource::Derived {
                seed: SeedId::from_raw("seed_1"),
                index: 0,
                path: DerivationPath::from_raw("m/44'/60'/0'/0/0"),
            },
            group: GroupId::from_raw("grp_1"),
            label: "Acct".into(),
            hidden: false,
            do_not_rederive: false,
            notes: String::new(),
            tags: vec![],
        };
        assert_eq!(
            AccountDto::from(&account).source_kind,
            AccountSourceKind::Derived
        );
    }

    #[test]
    fn group_flattens_structural_ids_to_strings() {
        let group = Group {
            id: GroupId::from_raw("grp_root"),
            parent: Some(GroupId::from_raw("grp_parent")),
            children: vec![GroupId::from_raw("grp_a"), GroupId::from_raw("grp_b")],
            name: "Savings".into(),
            notes: "n".into(),
            tags: vec!["t".into()],
        };
        let dto = GroupDto::from(&group);
        assert_eq!(
            dto,
            GroupDto {
                id: "grp_root".into(),
                parent: Some("grp_parent".into()),
                children: vec!["grp_a".into(), "grp_b".into()],
                name: "Savings".into(),
                notes: "n".into(),
                tags: vec!["t".into()],
            }
        );
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["parent"], "grp_parent");
        assert_eq!(json["children"][0], "grp_a");
    }

    #[test]
    fn root_group_has_null_parent() {
        let group = Group {
            id: GroupId::from_raw("grp_root"),
            parent: None,
            children: vec![],
            name: "Root".into(),
            notes: String::new(),
            tags: vec![],
        };
        let dto = GroupDto::from(&group);
        assert_eq!(dto.parent, None);
        assert!(serde_json::to_value(&dto).unwrap()["parent"].is_null());
    }

    #[test]
    fn signature_copies_components() {
        let sig = daemon_wallet_evm::Signature {
            r: U256::from(123u64),
            s: U256::from(456u64),
            y_parity: true,
        };
        assert_eq!(
            SignatureDto::from(&sig),
            SignatureDto {
                r: U256::from(123u64),
                s: U256::from(456u64),
                y_parity: true,
            }
        );
    }
}

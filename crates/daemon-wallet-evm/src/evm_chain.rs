//! The EVM implementation of [`daemon_wallet_core::Chain`], plus the boundary
//! conversions between core's neutral types and alloy's.
//!
//! [`EvmChain`] is what makes an EVM account derivable and signable from the
//! chain-agnostic [`daemon_wallet_core::Wallet`]. The application constructs one
//! and registers it:
//!
//! ```no_run
//! use daemon_wallet_core::{ChainKind, ChainRegistry};
//! use daemon_wallet_evm::EvmChain;
//!
//! let mut chains = ChainRegistry::new();
//! chains.register(Box::new(EvmChain::new()));
//! assert!(chains.contains(ChainKind::Evm));
//! ```
//!
//! A future Solana or Bitcoin crate is the same pattern: implement
//! [`daemon_wallet_core::Chain`] for its own type, convert to and from
//! [`daemon_wallet_core::ChainAddress`] at its own boundary, and register it.
//! Core is never edited.
//!
//! # The neutral/alloy boundary
//!
//! Core stores addresses as the neutral [`daemon_wallet_core::ChainAddress`]
//! string. This module is the only place EVM addresses cross between that
//! neutral form and alloy's [`Address`]: [`to_alloy_address`] parses inbound,
//! [`from_alloy_address`] renders outbound (checksummed). Nothing above this
//! crate ever sees an alloy type.

use crate::error::{Error, Result as EvmResult};
use crate::signer::{
    EvmSigner, FeeParams, LocalSigner, Signature, TransactionRequest, TypedDataRequest,
};
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_signer_local::{MnemonicBuilder, coins_bip39::English};
use daemon_wallet_core::{
    AccountSecret, Chain, ChainAddress, ChainKind, DerivationPath, PayloadKind, Result,
    SigningPayload,
};
use daemon_wallet_vault::SecretBytes;
use serde::{Deserialize, Serialize};

/// The EVM family's [`Chain`] implementation.
///
/// It is stateless: derivation and signing depend only on the secret and path
/// passed in. It is registered as `Box<dyn Chain>` and dispatched on
/// [`ChainKind::Evm`].
#[derive(Clone, Copy, Debug, Default)]
pub struct EvmChain;

impl EvmChain {
    /// Construct the EVM chain implementation.
    pub fn new() -> Self {
        EvmChain
    }
}

impl Chain for EvmChain {
    fn kind(&self) -> ChainKind {
        ChainKind::Evm
    }

    fn derive_address(&self, seed_material: &[u8], path: &DerivationPath) -> Result<ChainAddress> {
        let signer = derive_signer(seed_material, path)?;
        Ok(from_alloy_address(&signer.address()))
    }

    fn import_address(&self, private_key: &[u8]) -> Result<ChainAddress> {
        let signer = signer_from_private_key(private_key)?;
        Ok(from_alloy_address(&signer.address()))
    }

    fn sign(&self, secret: AccountSecret<'_>, payload: &SigningPayload) -> Result<Vec<u8>> {
        let signer = signer_for(&secret)?;
        let signature = match payload.kind {
            PayloadKind::Digest => {
                if payload.body.len() != 32 {
                    return Err(Error::InvalidPayload.into());
                }
                signer.sign_hash(B256::from_slice(&payload.body))?
            }
            PayloadKind::Transaction => {
                let tx = decode_transaction(&payload.body)?;
                signer.sign_transaction(&tx)?
            }
            PayloadKind::Message => signer.sign_message(&payload.body)?,
            PayloadKind::TypedData => {
                let raw_json =
                    String::from_utf8(payload.body.clone()).map_err(|_| Error::InvalidPayload)?;
                signer.sign_typed_data(&TypedDataRequest { raw_json })?
            }
            // `PayloadKind` is `#[non_exhaustive]`; anything this crate does not
            // understand cannot be signed as EVM.
            _ => return Err(Error::InvalidPayload.into()),
        };
        Ok(signature.to_rsv().to_vec())
    }

    fn parse_address(&self, text: &str) -> Result<ChainAddress> {
        let address: Address = text.parse().map_err(|_| Error::InvalidAddress)?;
        Ok(from_alloy_address(&address))
    }

    fn format_address(&self, address: &ChainAddress) -> String {
        match to_alloy_address(address) {
            Ok(a) => a.to_checksum(None),
            // Should not happen for an address this crate produced, but never
            // panic in a formatter: fall back to the stored text.
            Err(_) => address.as_str().to_string(),
        }
    }
}

/// Resolve the per-account [`LocalSigner`] for a core [`AccountSecret`], whether
/// it is HD-derived from a mnemonic or a raw imported key.
fn signer_for(secret: &AccountSecret<'_>) -> EvmResult<LocalSigner> {
    match secret {
        AccountSecret::Derived {
            seed_material,
            path,
        } => derive_signer(seed_material, path),
        AccountSecret::Imported { private_key } => signer_from_private_key(private_key),
    }
}

/// Build a signer from a raw imported private key.
fn signer_from_private_key(private_key: &[u8]) -> EvmResult<LocalSigner> {
    let secret = SecretBytes::new(private_key);
    LocalSigner::from_secret(&secret)
}

/// Derive a signer by BIP-39/BIP-32 from the mnemonic phrase held in
/// `seed_material` (the UTF-8 phrase bytes core stores in the vault) at `path`
/// (`m/44'/60'/0'/0/i` for the standard scheme).
fn derive_signer(seed_material: &[u8], path: &DerivationPath) -> EvmResult<LocalSigner> {
    let phrase = std::str::from_utf8(seed_material).map_err(|_| Error::InvalidPrivateKey)?;
    let inner = MnemonicBuilder::<English>::default()
        .phrase(phrase)
        .derivation_path(path.as_str())
        .map_err(|_| Error::InvalidPrivateKey)?
        .build()
        .map_err(|_| Error::InvalidPrivateKey)?;
    Ok(LocalSigner::from_private_key_signer(inner))
}

/// Parse a neutral [`ChainAddress`] into an alloy [`Address`].
///
/// Fails with [`crate::Error::InvalidAddress`] if the text is not valid EVM hex.
pub fn to_alloy_address(address: &ChainAddress) -> EvmResult<Address> {
    address
        .as_str()
        .parse::<Address>()
        .map_err(|_| Error::InvalidAddress)
}

/// Render an alloy [`Address`] as a neutral, EIP-55 checksummed [`ChainAddress`].
pub fn from_alloy_address(address: &Address) -> ChainAddress {
    ChainAddress::new(address.to_checksum(None))
}

/// Encode a [`TransactionRequest`] into a chain-tagged [`SigningPayload`] with
/// [`daemon_wallet_core::PayloadKind::Transaction`], ready for
/// [`daemon_wallet_core::Wallet::sign`].
///
/// Fails with [`crate::Error::InvalidPayload`] if the transaction cannot be
/// encoded.
pub fn transaction_payload(tx: &TransactionRequest) -> EvmResult<SigningPayload> {
    let wire = TxWire::from(tx);
    let mut body = Vec::new();
    ciborium::into_writer(&wire, &mut body).map_err(|_| Error::InvalidPayload)?;
    Ok(SigningPayload {
        chain: ChainKind::Evm,
        kind: PayloadKind::Transaction,
        body,
    })
}

/// Wrap an arbitrary message as a [`SigningPayload`] with
/// [`daemon_wallet_core::PayloadKind::Message`] (EIP-191 `personal_sign`).
pub fn message_payload(message: &[u8]) -> SigningPayload {
    SigningPayload {
        chain: ChainKind::Evm,
        kind: PayloadKind::Message,
        body: message.to_vec(),
    }
}

/// Wrap an EIP-712 [`TypedDataRequest`] as a [`SigningPayload`] with
/// [`daemon_wallet_core::PayloadKind::TypedData`].
pub fn typed_data_payload(typed: &TypedDataRequest) -> SigningPayload {
    SigningPayload {
        chain: ChainKind::Evm,
        kind: PayloadKind::TypedData,
        body: typed.raw_json.clone().into_bytes(),
    }
}

/// Reconstruct a typed [`Signature`] from the raw bytes a
/// [`daemon_wallet_core::Wallet::sign`] call returned for an EVM account.
///
/// Fails with [`crate::Error::InvalidSignature`] if the bytes are not a
/// well-formed 65-byte `r ‖ s ‖ v` signature.
pub fn parse_signature(bytes: &[u8]) -> EvmResult<Signature> {
    if bytes.len() != 65 {
        return Err(Error::InvalidSignature);
    }
    let r = U256::from_be_slice(&bytes[0..32]);
    let s = U256::from_be_slice(&bytes[32..64]);
    let y_parity = match bytes[64] {
        0 | 27 => false,
        1 | 28 => true,
        _ => return Err(Error::InvalidSignature),
    };
    Ok(Signature { r, s, y_parity })
}

/// Decode the CBOR body of a [`PayloadKind::Transaction`] payload back into a
/// [`TransactionRequest`].
fn decode_transaction(body: &[u8]) -> EvmResult<TransactionRequest> {
    let wire: TxWire = ciborium::from_reader(body).map_err(|_| Error::InvalidPayload)?;
    Ok(TransactionRequest::from(wire))
}

/// A `serde`-friendly mirror of [`TransactionRequest`] using only plain byte
/// arrays, so a transaction can be carried opaquely through core's
/// [`SigningPayload`] body without core ever depending on an alloy type.
#[derive(Serialize, Deserialize)]
struct TxWire {
    chain_id: u64,
    nonce: u64,
    to: Option<[u8; 20]>,
    value: [u8; 32],
    input: Vec<u8>,
    gas_limit: u64,
    fee: FeeWire,
}

/// The `serde` mirror of [`FeeParams`].
#[derive(Serialize, Deserialize)]
enum FeeWire {
    Legacy {
        gas_price: [u8; 32],
    },
    Eip1559 {
        max_fee_per_gas: [u8; 32],
        max_priority_fee_per_gas: [u8; 32],
    },
}

impl From<&TransactionRequest> for TxWire {
    fn from(tx: &TransactionRequest) -> Self {
        let fee = match &tx.fee {
            FeeParams::Legacy { gas_price } => FeeWire::Legacy {
                gas_price: gas_price.to_be_bytes::<32>(),
            },
            FeeParams::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            } => FeeWire::Eip1559 {
                max_fee_per_gas: max_fee_per_gas.to_be_bytes::<32>(),
                max_priority_fee_per_gas: max_priority_fee_per_gas.to_be_bytes::<32>(),
            },
        };
        TxWire {
            chain_id: tx.chain_id,
            nonce: tx.nonce,
            to: tx.to.map(|addr| addr.into_array()),
            value: tx.value.to_be_bytes::<32>(),
            input: tx.input.to_vec(),
            gas_limit: tx.gas_limit,
            fee,
        }
    }
}

impl From<TxWire> for TransactionRequest {
    fn from(wire: TxWire) -> Self {
        let fee = match wire.fee {
            FeeWire::Legacy { gas_price } => FeeParams::Legacy {
                gas_price: U256::from_be_bytes(gas_price),
            },
            FeeWire::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            } => FeeParams::Eip1559 {
                max_fee_per_gas: U256::from_be_bytes(max_fee_per_gas),
                max_priority_fee_per_gas: U256::from_be_bytes(max_priority_fee_per_gas),
            },
        };
        TransactionRequest {
            chain_id: wire.chain_id,
            nonce: wire.nonce,
            to: wire.to.map(Address::from),
            value: U256::from_be_bytes(wire.value),
            input: Bytes::from(wire.input),
            gas_limit: wire.gas_limit,
            fee,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{FeeParams, LocalSigner};
    use alloy_consensus::TxEnvelope;
    use alloy_consensus::transaction::SignerRecoverable;
    use alloy_dyn_abi::TypedData;
    use alloy_eips::Decodable2718;
    use alloy_primitives::{Signature as AlloySignature, address, b256, keccak256};
    use daemon_wallet_vault::SecretBytes;

    /// The standard foundry/anvil test mnemonic.
    const ANVIL: &[u8] = b"test test test test test test test test test test test junk";

    #[test]
    fn derivation_anchor_matches_foundry_anvil() {
        let chain = EvmChain::new();
        // Account #0 and #1 of `anvil`, proving BIP44 m/44'/60'/0'/0/i derivation
        // matches ethers/foundry exactly.
        let a0 = chain
            .derive_address(ANVIL, &DerivationPath::from_raw("m/44'/60'/0'/0/0"))
            .unwrap();
        assert_eq!(a0.as_str(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let a1 = chain
            .derive_address(ANVIL, &DerivationPath::from_raw("m/44'/60'/0'/0/1"))
            .unwrap();
        assert_eq!(a1.as_str(), "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    }

    #[test]
    fn address_boundary_round_trips_checksummed() {
        let chain = EvmChain::new();
        // All-lowercase input is accepted and canonicalised to EIP-55.
        let addr = chain
            .parse_address("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
            .unwrap();
        assert_eq!(addr.as_str(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_eq!(
            chain.format_address(&addr),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
        let alloy = to_alloy_address(&addr).unwrap();
        assert_eq!(from_alloy_address(&alloy), addr);
        assert!(chain.parse_address("not-an-address").is_err());
    }

    /// The canonical EIP-712 "Mail" example from the EIP-712 specification.
    const MAIL_JSON: &str = r#"{
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"}
            ],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"}
            ]
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
        },
        "message": {
            "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!"
        }
    }"#;

    #[test]
    fn eip712_mail_example_hash_and_recovered_signer() {
        // Known-answer: the EIP-712 spec's documented signing hash for the Mail
        // example.
        let typed: TypedData = serde_json::from_str(MAIL_JSON).unwrap();
        let digest = typed.eip712_signing_hash().unwrap();
        assert_eq!(
            digest,
            b256!("0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2")
        );

        // The spec's signer key is keccak256("cow); signing the typed data and
        // recovering must land on the Cow wallet address.
        let cow = SecretBytes::new(keccak256(b"cow").as_slice());
        let signer = LocalSigner::from_secret(&cow).unwrap();
        let payload = typed_data_payload(&TypedDataRequest {
            raw_json: MAIL_JSON.to_string(),
        });
        let raw = EvmChain::new()
            .sign(
                AccountSecret::Imported {
                    private_key: cow.as_slice(),
                },
                &payload,
            )
            .unwrap();
        let sig = parse_signature(&raw).unwrap();
        let recovered = sig
            .to_alloy()
            .recover_address_from_prehash(&digest)
            .unwrap();
        assert_eq!(recovered, signer.address());
        assert_eq!(
            recovered,
            address!("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")
        );
    }

    #[test]
    fn personal_sign_eip191_recovers_signer() {
        let chain = EvmChain::new();
        let path = DerivationPath::from_raw("m/44'/60'/0'/0/0");
        let expected = chain.derive_address(ANVIL, &path).unwrap();

        let message = b"hello world";
        let payload = message_payload(message);
        let raw = chain
            .sign(
                AccountSecret::Derived {
                    seed_material: ANVIL,
                    path: &path,
                },
                &payload,
            )
            .unwrap();
        let sig = parse_signature(&raw).unwrap();

        // Independently rebuild the EIP-191 digest and recover.
        let digest = alloy_primitives::eip191_hash_message(message);
        let recovered = sig
            .to_alloy()
            .recover_address_from_prehash(&digest)
            .unwrap();
        assert_eq!(from_alloy_address(&recovered), expected);
    }

    fn roundtrip_tx(fee: FeeParams, expected_type: u8) {
        let chain = EvmChain::new();
        let path = DerivationPath::from_raw("m/44'/60'/0'/0/0");
        let from = to_alloy_address(&chain.derive_address(ANVIL, &path).unwrap()).unwrap();

        let tx = TransactionRequest {
            chain_id: 1,
            nonce: 7,
            to: Some(address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")),
            value: U256::from(1_000_000_000_000_000_000u128),
            input: Bytes::from_static(&[0x12, 0x34]),
            gas_limit: 21_000,
            fee,
        };

        // Encode -> sign through the neutral payload -> parse the raw signature.
        let payload = transaction_payload(&tx).unwrap();
        let raw = chain
            .sign(
                AccountSecret::Derived {
                    seed_material: ANVIL,
                    path: &path,
                },
                &payload,
            )
            .unwrap();
        let sig = parse_signature(&raw).unwrap();

        // RLP-encode the signed tx and recover the signer from the broadcast bytes.
        let encoded = crate::signer::encode_signed_transaction(&tx, &sig).unwrap();
        if expected_type == 0 {
            // Legacy: first byte is RLP list prefix (>= 0xc0), not a type id.
            assert!(encoded[0] >= 0xc0);
        } else {
            assert_eq!(encoded[0], expected_type);
        }
        let envelope = TxEnvelope::decode_2718(&mut encoded.as_slice()).unwrap();
        let recovered = envelope.recover_signer().unwrap();
        assert_eq!(recovered, from);
    }

    #[test]
    fn eip1559_sign_encode_recover_roundtrip() {
        roundtrip_tx(
            FeeParams::Eip1559 {
                max_fee_per_gas: U256::from(30_000_000_000u64),
                max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            },
            0x02,
        );
    }

    #[test]
    fn legacy_sign_encode_recover_roundtrip() {
        roundtrip_tx(
            FeeParams::Legacy {
                gas_price: U256::from(20_000_000_000u64),
            },
            0,
        );
    }

    #[test]
    fn imported_key_address_matches_derived() {
        let chain = EvmChain::new();
        // anvil account #0 private key.
        let pk = b256!("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let imported = chain.import_address(pk.as_slice()).unwrap();
        let derived = chain
            .derive_address(ANVIL, &DerivationPath::from_raw("m/44'/60'/0'/0/0"))
            .unwrap();
        assert_eq!(imported, derived);
    }

    #[test]
    fn signature_alloy_round_trips_and_digest_signing() {
        // A raw digest payload signs via sign_hash and recovers consistently.
        let chain = EvmChain::new();
        let path = DerivationPath::from_raw("m/44'/60'/0'/0/0");
        let from = to_alloy_address(&chain.derive_address(ANVIL, &path).unwrap()).unwrap();
        let digest = b256!("0x1122334455667788112233445566778811223344556677881122334455667788");
        let payload = SigningPayload {
            chain: ChainKind::Evm,
            kind: PayloadKind::Digest,
            body: digest.to_vec(),
        };
        let raw = chain
            .sign(
                AccountSecret::Derived {
                    seed_material: ANVIL,
                    path: &path,
                },
                &payload,
            )
            .unwrap();
        let sig: AlloySignature = parse_signature(&raw).unwrap().to_alloy();
        assert_eq!(sig.recover_address_from_prehash(&digest).unwrap(), from);
    }
}

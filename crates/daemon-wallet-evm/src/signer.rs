//! The EVM signing surface: transaction and signature types, plus the signer
//! trait and a concrete local signer.
//!
//! # Alloy surface
//!
//! The EVM layer uses `alloy-primitives` for value types only: [`Address`],
//! [`U256`], [`B256`], and [`Bytes`]. It does not pull in `alloy-consensus` or
//! the RPC stack. Actual signing is expressed through the [`EvmSigner`] trait;
//! [`LocalSigner`] is the concrete implementation an implementer wires
//! `alloy-signer-local` into, taking its key material as vault-held
//! [`daemon_wallet_vault::SecretBytes`].
//!
//! # The three signing modes
//!
//! - [`EvmSigner::sign_transaction`] over a [`TransactionRequest`].
//! - [`EvmSigner::sign_message`] over arbitrary bytes (EIP-191 `personal_sign`).
//! - [`EvmSigner::sign_typed_data`] over a [`TypedDataRequest`] (EIP-712).
//!
//! All three reduce to signing a 32-byte digest via [`EvmSigner::sign_hash`], so
//! the digest-construction rules live in one auditable place.

use crate::error::{Error, Result};
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_dyn_abi::TypedData;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{
    Address, B256, Bytes, Signature as AlloySignature, TxKind, U256, eip191_hash_message,
};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use daemon_wallet_vault::SecretBytes;

/// The gas/fee shape of a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeeParams {
    /// Pre-EIP-1559 legacy pricing.
    Legacy {
        /// The gas price the sender is willing to pay.
        gas_price: U256,
    },
    /// EIP-1559 dynamic-fee pricing.
    Eip1559 {
        /// Maximum total fee per gas.
        max_fee_per_gas: U256,
        /// Maximum priority (tip) fee per gas.
        max_priority_fee_per_gas: U256,
    },
}

/// A concrete EVM transaction to be signed.
///
/// This is the EVM layer's own transaction shape rather than an alloy consensus
/// type, so the crate depends only on `alloy-primitives`. The implementer maps
/// it onto a signed envelope when wiring the real signer. To sign it through a
/// [`daemon_wallet_core::Wallet`], encode it into a
/// [`daemon_wallet_core::SigningPayload`] with [`crate::transaction_payload`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionRequest {
    /// The EIP-155 chain id this transaction is bound to. Binding the chain id
    /// into every signature is what stops a signed transaction being replayed
    /// on a different chain.
    pub chain_id: u64,
    /// The sender's next nonce.
    pub nonce: u64,
    /// The recipient, or `None` for a contract-creation transaction.
    pub to: Option<Address>,
    /// The value transferred, in wei.
    pub value: U256,
    /// The calldata / init code.
    pub input: Bytes,
    /// The gas limit.
    pub gas_limit: u64,
    /// The fee pricing.
    pub fee: FeeParams,
}

/// An EIP-712 typed-data request.
///
/// The payload is carried as the raw JSON a dapp supplies. Parsing it and
/// computing the domain separator and struct hash is the signer backend's job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedDataRequest {
    /// The canonical EIP-712 JSON document (`types`, `domain`, `primaryType`,
    /// `message`).
    pub raw_json: String,
}

/// A secp256k1 signature over an EVM payload.
///
/// Stored in structured `(r, s, y_parity)` form. [`Signature::to_rsv`] renders
/// the 65-byte `r ‖ s ‖ v` layout most EVM tooling expects. This is the typed
/// form that [`crate::parse_signature`] reconstructs from the raw bytes a
/// [`daemon_wallet_core::Wallet::sign`] call returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The `r` component.
    pub r: U256,
    /// The `s` component.
    pub s: U256,
    /// The recovery bit (`v = 27 + y_parity` in legacy encodings).
    pub y_parity: bool,
}

impl Signature {
    /// Render the signature as 65 bytes: `r` (32) ‖ `s` (32) ‖ `v` (1), where
    /// `v` is `27` or `28`.
    pub fn to_rsv(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0..32].copy_from_slice(&self.r.to_be_bytes::<32>());
        out[32..64].copy_from_slice(&self.s.to_be_bytes::<32>());
        out[64] = 27 + u8::from(self.y_parity);
        out
    }

    /// Adapt an alloy `(r, s, y_parity)` signature into this crate's form.
    pub(crate) fn from_alloy(sig: AlloySignature) -> Self {
        Self {
            r: sig.r(),
            s: sig.s(),
            y_parity: sig.v(),
        }
    }

    /// Render this signature as alloy's `(r, s, y_parity)` form, for attaching
    /// to a consensus transaction or recovering a signer.
    pub(crate) fn to_alloy(self) -> AlloySignature {
        AlloySignature::new(self.r, self.s, self.y_parity)
    }
}

/// A signer bound to exactly one account's secret.
///
/// Implementations hold (or can reach) the private key for a single address and
/// know nothing about the wallet, the vault, or other accounts.
pub trait EvmSigner {
    /// The address this signer produces signatures for.
    fn address(&self) -> Address;

    /// Sign a raw 32-byte digest. The higher-level methods reduce to this.
    fn sign_hash(&self, hash: B256) -> Result<Signature>;

    /// Assemble, hash, and sign a transaction.
    fn sign_transaction(&self, tx: &TransactionRequest) -> Result<Signature>;

    /// Sign an arbitrary message under EIP-191 (`personal_sign`).
    fn sign_message(&self, message: &[u8]) -> Result<Signature>;

    /// Sign an EIP-712 typed-data payload.
    fn sign_typed_data(&self, typed: &TypedDataRequest) -> Result<Signature>;
}

/// A concrete [`EvmSigner`] backed by a private key held in vault memory.
///
/// This is the anchor for wiring `alloy-signer-local`: build one from the
/// secret bytes the wallet fetched from the vault, then sign. The key stays
/// inside the signer and is never exposed.
pub struct LocalSigner {
    /// The alloy local signer that actually holds the secp256k1 key and signs.
    inner: PrivateKeySigner,
    /// The address this signer controls, cached from the key.
    address: Address,
}

impl LocalSigner {
    /// Build a signer from vault-held secret key bytes.
    ///
    /// Fails with [`crate::Error::InvalidPrivateKey`] if the bytes are not a
    /// valid secp256k1 scalar.
    pub fn from_secret(secret: &SecretBytes) -> Result<Self> {
        let inner = PrivateKeySigner::from_slice(secret.as_slice())
            .map_err(|_| Error::InvalidPrivateKey)?;
        Ok(Self::from_private_key_signer(inner))
    }

    /// Wrap a concrete alloy [`PrivateKeySigner`] (for example one produced by
    /// HD derivation in [`crate::evm_chain`]).
    pub(crate) fn from_private_key_signer(inner: PrivateKeySigner) -> Self {
        let address = inner.address();
        Self { inner, address }
    }
}

impl EvmSigner for LocalSigner {
    fn address(&self) -> Address {
        self.address
    }

    fn sign_hash(&self, hash: B256) -> Result<Signature> {
        let sig = self
            .inner
            .sign_hash_sync(&hash)
            .map_err(|_| Error::Signer)?;
        Ok(Signature::from_alloy(sig))
    }

    fn sign_transaction(&self, tx: &TransactionRequest) -> Result<Signature> {
        let prepared = PreparedTx::try_from(tx)?;
        self.sign_hash(prepared.signature_hash())
    }

    fn sign_message(&self, message: &[u8]) -> Result<Signature> {
        // EIP-191 `personal_sign`: hash the "\x19Ethereum Signed Message:\n"
        // framed message, then sign that 32-byte digest.
        self.sign_hash(eip191_hash_message(message))
    }

    fn sign_typed_data(&self, typed: &TypedDataRequest) -> Result<Signature> {
        let hash = typed_data_hash(typed)?;
        self.sign_hash(hash)
    }
}

/// Compute the EIP-712 signing hash for a typed-data request.
///
/// Parses the canonical EIP-712 JSON and returns the 32-byte digest
/// `keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(message))`.
fn typed_data_hash(typed: &TypedDataRequest) -> Result<B256> {
    let data: TypedData =
        serde_json::from_str(&typed.raw_json).map_err(|_| Error::InvalidPayload)?;
    data.eip712_signing_hash()
        .map_err(|_| Error::InvalidPayload)
}

/// A [`TransactionRequest`] mapped onto the concrete alloy consensus transaction
/// it will be signed and broadcast as. Legacy and EIP-1559 are the two shapes
/// this crate builds; both reduce to one signable digest.
enum PreparedTx {
    /// A pre-EIP-1559 legacy transaction.
    Legacy(TxLegacy),
    /// An EIP-1559 dynamic-fee transaction.
    Eip1559(TxEip1559),
}

impl PreparedTx {
    /// The 32-byte digest to sign for this transaction.
    fn signature_hash(&self) -> B256 {
        match self {
            PreparedTx::Legacy(tx) => tx.signature_hash(),
            PreparedTx::Eip1559(tx) => tx.signature_hash(),
        }
    }

    /// Attach `signature` and fold into the broadcastable EIP-2718 envelope.
    fn into_envelope(self, signature: AlloySignature) -> TxEnvelope {
        match self {
            PreparedTx::Legacy(tx) => TxEnvelope::Legacy(tx.into_signed(signature)),
            PreparedTx::Eip1559(tx) => TxEnvelope::Eip1559(tx.into_signed(signature)),
        }
    }
}

impl TryFrom<&TransactionRequest> for PreparedTx {
    type Error = Error;

    fn try_from(tx: &TransactionRequest) -> Result<Self> {
        let to = match tx.to {
            Some(addr) => TxKind::Call(addr),
            None => TxKind::Create,
        };
        Ok(match &tx.fee {
            FeeParams::Legacy { gas_price } => PreparedTx::Legacy(TxLegacy {
                chain_id: Some(tx.chain_id),
                nonce: tx.nonce,
                gas_price: u256_to_u128(*gas_price)?,
                gas_limit: tx.gas_limit,
                to,
                value: tx.value,
                input: tx.input.clone(),
            }),
            FeeParams::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            } => PreparedTx::Eip1559(TxEip1559 {
                chain_id: tx.chain_id,
                nonce: tx.nonce,
                gas_limit: tx.gas_limit,
                max_fee_per_gas: u256_to_u128(*max_fee_per_gas)?,
                max_priority_fee_per_gas: u256_to_u128(*max_priority_fee_per_gas)?,
                to,
                value: tx.value,
                access_list: Default::default(),
                input: tx.input.clone(),
            }),
        })
    }
}

/// Narrow a fee value to the `u128` the consensus transaction types use, failing
/// with [`Error::InvalidPayload`] rather than panicking on an out-of-range value.
fn u256_to_u128(value: U256) -> Result<u128> {
    u128::try_from(value).map_err(|_| Error::InvalidPayload)
}

/// RLP-encode a *signed* transaction into the raw bytes to broadcast.
///
/// `tx` describes the transaction and `signature` is the result of signing its
/// [`EvmSigner::sign_transaction`] digest. The output is a ready-to-send EIP-2718
/// payload: a legacy transaction is plain RLP with an EIP-155 `v`, while an
/// EIP-1559 transaction is wrapped in its `0x02` typed envelope. This is what the
/// rpc layer hands to `eth_sendRawTransaction`.
///
/// Fails with [`crate::Error::InvalidPayload`] if the request cannot be encoded.
pub fn encode_signed_transaction(
    tx: &TransactionRequest,
    signature: &Signature,
) -> Result<Vec<u8>> {
    let prepared = PreparedTx::try_from(tx)?;
    let envelope = prepared.into_envelope(signature.to_alloy());
    Ok(envelope.encoded_2718())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_rsv_lays_out_r_s_v() {
        let sig = Signature {
            r: U256::from(1u8),
            s: U256::from(2u8),
            y_parity: true,
        };
        let rsv = sig.to_rsv();
        assert_eq!(rsv[31], 1);
        assert_eq!(rsv[63], 2);
        assert_eq!(rsv[64], 28);

        let even = Signature {
            y_parity: false,
            ..sig
        };
        assert_eq!(even.to_rsv()[64], 27);
    }

    #[test]
    fn alloy_signature_round_trips() {
        let original = AlloySignature::new(U256::from(123456u64), U256::from(789u64), true);
        let mine = Signature::from_alloy(original);
        assert_eq!(mine.to_alloy(), original);
    }
}

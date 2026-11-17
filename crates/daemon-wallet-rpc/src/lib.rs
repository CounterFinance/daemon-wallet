//! A minimal Ethereum JSON-RPC client plus EVM transaction assembly/broadcast.
//!
//! The public surface below is the fixed contract the CLI/TUI build against;
//! signatures use plain primitives (hex-string addresses, `u128` wei) so the
//! CLI never has to name an alloy type. The alloy-shaped transaction assembly is
//! confined to this crate and `daemon-wallet-evm`.
//!
//! The high-level [`RpcClient::send_eip1559`] takes a signing closure so the
//! wallet (which holds the keys) stays the only thing that can sign: it queries
//! chain id / nonce / fees, builds the EIP-1559 transaction, hands the signing
//! payload to the closure, encodes the returned signature onto the transaction,
//! and broadcasts the raw bytes.

use alloy_primitives::{Address, Bytes, U256};
use daemon_wallet_core::chain::SigningPayload;
use daemon_wallet_evm::{FeeParams, TransactionRequest};
use serde_json::{Value, json};
use thiserror::Error;

/// The intrinsic gas of a plain value transfer with empty calldata. Used as the
/// gas limit when `eth_estimateGas` is unavailable for an empty-data transfer.
const INTRINSIC_TRANSFER_GAS: u64 = 21_000;

/// Default priority tip (1 gwei) when the node offers no `eth_maxPriorityFeePerGas`.
const DEFAULT_PRIORITY_TIP_WEI: u128 = 1_000_000_000;

/// Errors from the RPC layer. No secret material ever appears here.
#[derive(Debug, Error)]
pub enum Error {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("json-rpc error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("decode error: {0}")]
    Decode(String),
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("evm error: {0}")]
    Evm(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Suggested EIP-1559 fee parameters (wei).
#[derive(Clone, Copy, Debug)]
pub struct Eip1559Fees {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

/// A transaction receipt, reduced to what the POC needs.
#[derive(Clone, Debug)]
pub struct Receipt {
    pub tx_hash: String,
    pub success: bool,
    pub block_number: u64,
    pub gas_used: u64,
}

/// A blocking JSON-RPC client bound to one endpoint.
pub struct RpcClient {
    url: String,
    agent: ureq::Agent,
}

impl RpcClient {
    /// Create a client for an HTTP(S) JSON-RPC endpoint.
    pub fn new(url: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(10))
            .timeout_read(std::time::Duration::from_secs(30))
            .build();
        Self {
            url: url.into(),
            agent,
        }
    }

    /// Perform one JSON-RPC 2.0 call and return the `result` field.
    fn rpc_call(&self, method: &str, params: Value) -> Result<Value> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response = match self.agent.post(&self.url).send_json(&request) {
            Ok(response) => response,
            // A JSON-RPC error is sometimes returned with a non-2xx status and
            // the error envelope in the body; recover it rather than discarding.
            Err(ureq::Error::Status(_, response)) => response,
            Err(err) => return Err(Error::Transport(err.to_string())),
        };
        let value: Value = response
            .into_json()
            .map_err(|err| Error::Transport(err.to_string()))?;
        extract_result(&value)
    }

    /// `eth_chainId`.
    pub fn chain_id(&self) -> Result<u64> {
        let value = self.rpc_call("eth_chainId", json!([]))?;
        parse_u64_hex(as_hex_str(&value)?)
    }

    /// `eth_getTransactionCount` (use `pending = true` for the next nonce).
    pub fn get_transaction_count(&self, address: &str, pending: bool) -> Result<u64> {
        let block = if pending { "pending" } else { "latest" };
        let value = self.rpc_call("eth_getTransactionCount", json!([address, block]))?;
        parse_u64_hex(as_hex_str(&value)?)
    }

    /// `eth_getBalance` in wei.
    pub fn get_balance(&self, address: &str) -> Result<u128> {
        let value = self.rpc_call("eth_getBalance", json!([address, "latest"]))?;
        parse_u128_hex(as_hex_str(&value)?)
    }

    /// `eth_gasPrice` in wei.
    pub fn gas_price(&self) -> Result<u128> {
        let value = self.rpc_call("eth_gasPrice", json!([]))?;
        parse_u128_hex(as_hex_str(&value)?)
    }

    /// Suggested EIP-1559 fees: `2 * baseFeePerGas + tip`, where `tip` is the
    /// node's `eth_maxPriorityFeePerGas` or a 1 gwei default.
    pub fn eip1559_fees(&self) -> Result<Eip1559Fees> {
        let block = self.rpc_call("eth_getBlockByNumber", json!(["latest", false]))?;
        let base_fee = match block.get("baseFeePerGas").and_then(Value::as_str) {
            Some(hex) => parse_u128_hex(hex)?,
            None => 0,
        };
        let tip = match self.rpc_call("eth_maxPriorityFeePerGas", json!([])) {
            Ok(value) => parse_u128_hex(as_hex_str(&value)?)?,
            Err(_) => DEFAULT_PRIORITY_TIP_WEI,
        };
        let max_fee_per_gas = base_fee.saturating_mul(2).saturating_add(tip);
        Ok(Eip1559Fees {
            max_fee_per_gas,
            max_priority_fee_per_gas: tip,
        })
    }

    /// `eth_estimateGas` for a simple value/data transfer.
    pub fn estimate_gas(&self, from: &str, to: &str, value_wei: u128, data: &[u8]) -> Result<u64> {
        let tx = json!({
            "from": from,
            "to": to,
            "value": format!("0x{value_wei:x}"),
            "data": format!("0x{}", hex::encode(data)),
        });
        let value = self.rpc_call("eth_estimateGas", json!([tx]))?;
        parse_u64_hex(as_hex_str(&value)?)
    }

    /// `eth_sendRawTransaction`; returns the transaction hash.
    pub fn send_raw_transaction(&self, raw: &[u8]) -> Result<String> {
        let raw_hex = format!("0x{}", hex::encode(raw));
        let value = self.rpc_call("eth_sendRawTransaction", json!([raw_hex]))?;
        Ok(as_hex_str(&value)?.to_string())
    }

    /// `eth_getTransactionReceipt`; `None` while still pending.
    pub fn get_transaction_receipt(&self, tx_hash: &str) -> Result<Option<Receipt>> {
        let value = self.rpc_call("eth_getTransactionReceipt", json!([tx_hash]))?;
        parse_receipt(&value, tx_hash)
    }

    /// Assemble and sign an EIP-1559 transfer, returning the raw EIP-2718 bytes
    /// ready to broadcast.
    ///
    /// Queries chain id, pending nonce, fees and gas, builds the transaction,
    /// calls `sign` with the EVM signing payload, and encodes the signature onto
    /// it. This is the single place a 1559 transaction is assembled — both offline
    /// signing (`sign-tx`) and broadcast (`send_eip1559`) go through it.
    pub fn assemble_and_sign_eip1559<F>(
        &self,
        from: &str,
        to: &str,
        value_wei: u128,
        data: Vec<u8>,
        sign: F,
    ) -> Result<Vec<u8>>
    where
        F: FnOnce(&SigningPayload) -> std::result::Result<Vec<u8>, String>,
    {
        let chain_id = self.chain_id()?;
        let nonce = self.get_transaction_count(from, true)?;
        let fees = self.eip1559_fees()?;
        let gas_limit = match self.estimate_gas(from, to, value_wei, &data) {
            Ok(gas) => gas,
            // Empty-data transfers have a known intrinsic cost; fall back to it
            // when estimation is unavailable, but surface failures otherwise.
            Err(_) if data.is_empty() => INTRINSIC_TRANSFER_GAS,
            Err(err) => return Err(err),
        };

        let to_addr = to
            .parse::<Address>()
            .map_err(|err| Error::Evm(format!("invalid `to` address {to:?}: {err}")))?;

        let tx = TransactionRequest {
            chain_id,
            nonce,
            to: Some(to_addr),
            value: U256::from(value_wei),
            input: Bytes::from(data),
            gas_limit,
            fee: FeeParams::Eip1559 {
                max_fee_per_gas: U256::from(fees.max_fee_per_gas),
                max_priority_fee_per_gas: U256::from(fees.max_priority_fee_per_gas),
            },
        };

        let payload = daemon_wallet_evm::transaction_payload(&tx)
            .map_err(|err| Error::Evm(err.to_string()))?;
        let sig_bytes = sign(&payload).map_err(Error::Signing)?;
        let sig = daemon_wallet_evm::parse_signature(&sig_bytes)
            .map_err(|err| Error::Evm(err.to_string()))?;
        daemon_wallet_evm::encode_signed_transaction(&tx, &sig)
            .map_err(|err| Error::Evm(err.to_string()))
    }

    /// Assemble, sign, and broadcast an EIP-1559 value transfer; returns the hash.
    pub fn send_eip1559<F>(
        &self,
        from: &str,
        to: &str,
        value_wei: u128,
        data: Vec<u8>,
        sign: F,
    ) -> Result<String>
    where
        F: FnOnce(&SigningPayload) -> std::result::Result<Vec<u8>, String>,
    {
        let raw = self.assemble_and_sign_eip1559(from, to, value_wei, data, sign)?;
        self.send_raw_transaction(&raw)
    }
}

/// Pull the `result` out of a JSON-RPC 2.0 response, mapping an `error`
/// envelope to [`Error::Rpc`]. Pure; unit-tested against canned frames.
fn extract_result(value: &Value) -> Result<Value> {
    if let Some(err) = value.get("error").filter(|e| !e.is_null()) {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let message = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown error")
            .to_string();
        return Err(Error::Rpc { code, message });
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| Error::Decode("response has neither `result` nor `error`".to_string()))
}

/// Interpret a JSON value as a hex-quantity/data string.
fn as_hex_str(value: &Value) -> Result<&str> {
    value
        .as_str()
        .ok_or_else(|| Error::Decode(format!("expected a hex string, got {value}")))
}

/// Strip an optional `0x`/`0X` prefix from a hex quantity.
fn strip_hex_prefix(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

/// Decode a `0x`-prefixed hex quantity into a `u64`.
fn parse_u64_hex(s: &str) -> Result<u64> {
    let digits = strip_hex_prefix(s);
    if digits.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(digits, 16)
        .map_err(|err| Error::Decode(format!("invalid u64 quantity {s:?}: {err}")))
}

/// Decode a `0x`-prefixed hex quantity into a `u128` (balances exceed `u64`).
fn parse_u128_hex(s: &str) -> Result<u128> {
    let digits = strip_hex_prefix(s);
    if digits.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(digits, 16)
        .map_err(|err| Error::Decode(format!("invalid u128 quantity {s:?}: {err}")))
}

/// Parse an `eth_getTransactionReceipt` result. `null` (still pending) yields
/// `None`. Pure; unit-tested against canned frames.
fn parse_receipt(value: &Value, fallback_hash: &str) -> Result<Option<Receipt>> {
    if value.is_null() {
        return Ok(None);
    }
    let obj = value
        .as_object()
        .ok_or_else(|| Error::Decode(format!("receipt is not an object: {value}")))?;

    // `status` is `0x1` success / `0x0` failure (post-Byzantium). Missing status
    // is treated as unsuccessful for safety.
    let success = obj
        .get("status")
        .and_then(Value::as_str)
        .map(parse_u64_hex)
        .transpose()?
        .map(|s| s == 1)
        .unwrap_or(false);

    let block_number = obj
        .get("blockNumber")
        .and_then(Value::as_str)
        .map(parse_u64_hex)
        .transpose()?
        .ok_or_else(|| Error::Decode("receipt missing blockNumber".to_string()))?;

    let gas_used = obj
        .get("gasUsed")
        .and_then(Value::as_str)
        .map(parse_u64_hex)
        .transpose()?
        .ok_or_else(|| Error::Decode("receipt missing gasUsed".to_string()))?;

    let tx_hash = obj
        .get("transactionHash")
        .and_then(Value::as_str)
        .unwrap_or(fallback_hash)
        .to_string();

    Ok(Some(Receipt {
        tx_hash,
        success,
        block_number,
        gas_used,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_u64_quantities() {
        assert_eq!(parse_u64_hex("0x0").unwrap(), 0);
        assert_eq!(parse_u64_hex("0x1").unwrap(), 1);
        assert_eq!(parse_u64_hex("0x5208").unwrap(), 21_000);
        assert_eq!(parse_u64_hex("0xaa36a7").unwrap(), 11_155_111);
        // Uppercase prefix and missing prefix both decode.
        assert_eq!(parse_u64_hex("0X10").unwrap(), 16);
        assert_eq!(parse_u64_hex("ff").unwrap(), 255);
        // Bare "0x" is tolerated as zero.
        assert_eq!(parse_u64_hex("0x").unwrap(), 0);
    }

    #[test]
    fn rejects_malformed_u64_quantity() {
        assert!(matches!(parse_u64_hex("0xzz"), Err(Error::Decode(_))));
    }

    #[test]
    fn parses_u128_balances_beyond_u64() {
        // 1_000_000 ETH in wei = 1e24, which overflows u64 (max ~1.8e19).
        let one_million_eth_wei = 1_000_000u128 * 10u128.pow(18);
        let hex = format!("0x{one_million_eth_wei:x}");
        assert_eq!(parse_u128_hex(&hex).unwrap(), one_million_eth_wei);
        // u128::MAX round-trips.
        let max_hex = format!("0x{:x}", u128::MAX);
        assert_eq!(parse_u128_hex(&max_hex).unwrap(), u128::MAX);
        // A value that fits u128 but not u64.
        assert_eq!(parse_u128_hex("0x10000000000000000").unwrap(), 1u128 << 64);
    }

    #[test]
    fn extracts_result_envelope() {
        let frame: Value =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"result":"0x5"}"#).unwrap();
        assert_eq!(extract_result(&frame).unwrap(), json!("0x5"));
    }

    #[test]
    fn extracts_error_envelope() {
        let frame: Value = serde_json::from_str(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}"#,
        )
        .unwrap();
        match extract_result(&frame) {
            Err(Error::Rpc { code, message }) => {
                assert_eq!(code, -32000);
                assert_eq!(message, "nonce too low");
            }
            other => panic!("expected Rpc error, got {other:?}"),
        }
    }

    #[test]
    fn missing_result_and_error_is_decode_error() {
        let frame: Value = serde_json::from_str(r#"{"jsonrpc":"2.0","id":1}"#).unwrap();
        assert!(matches!(extract_result(&frame), Err(Error::Decode(_))));
    }

    #[test]
    fn decodes_successful_receipt() {
        let result: Value = serde_json::from_str(
            r#"{
                "status":"0x1",
                "blockNumber":"0x10",
                "gasUsed":"0x5208",
                "transactionHash":"0xabc"
            }"#,
        )
        .unwrap();
        let receipt = parse_receipt(&result, "0xfallback").unwrap().unwrap();
        assert!(receipt.success);
        assert_eq!(receipt.block_number, 16);
        assert_eq!(receipt.gas_used, 21_000);
        assert_eq!(receipt.tx_hash, "0xabc");
    }

    #[test]
    fn decodes_failed_receipt() {
        let result: Value =
            serde_json::from_str(r#"{"status":"0x0","blockNumber":"0x2","gasUsed":"0x3"}"#)
                .unwrap();
        let receipt = parse_receipt(&result, "0xfallback").unwrap().unwrap();
        assert!(!receipt.success);
        // transactionHash falls back to the queried hash.
        assert_eq!(receipt.tx_hash, "0xfallback");
    }

    #[test]
    fn pending_receipt_is_none() {
        assert!(parse_receipt(&Value::Null, "0xabc").unwrap().is_none());
    }

    /// Hits a local node if one is running; ignored by default so `cargo test`
    /// never needs a network. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "requires a local node at 127.0.0.1:8545"]
    fn live_chain_id() {
        let client = RpcClient::new("http://127.0.0.1:8545");
        let id = client.chain_id().expect("chain_id");
        assert!(id > 0);
    }
}

//! The method dispatcher: the testable heart of the daemon.
//!
//! A [`Dispatcher`] turns one request [`Value`] into one response [`Value`],
//! holding the unlocked [`Wallet`] for the life of the session and routing every
//! human decision through the injected [`Approver`] and [`PassphraseSource`]. It
//! never touches stdin/stdout — the framing lives in [`crate::codec`] and the
//! real terminal I/O in [`crate::approval`] — so it can be exercised end to end
//! with an auto-approver and a throwaway wallet, no Chrome required.
//!
//! Wire shape (per `EXTENSION_INTEGRATION.md`):
//! request `{id, method, params}`; success `{id, result}`; error
//! `{id, error:{code, message}}`. A user rejection is code `4001`; any other
//! failure is code `-1`.

use daemon_wallet_config::Config;
use daemon_wallet_core::{Account, AccountId, AccountSource, ChainRegistry, Wallet};
use daemon_wallet_evm::{self as evm, EvmChain};
use daemon_wallet_rpc::RpcClient;
use serde_json::{Value, json};
use std::path::PathBuf;

use crate::approval::{ApprovalRequest, Approver, PassphraseSource};

/// An error destined for the wire's `{code, message}` envelope.
struct MethodError {
    code: i64,
    message: String,
}

impl MethodError {
    /// The user declined an approval prompt.
    fn rejected() -> Self {
        Self {
            code: 4001,
            message: "User rejected the request".to_string(),
        }
    }

    /// Any other failure.
    fn general(message: impl Into<String>) -> Self {
        Self {
            code: -1,
            message: message.into(),
        }
    }
}

/// The in-memory session: the unlocked wallet, or `None` while locked.
#[derive(Default)]
struct Session {
    wallet: Option<Wallet>,
}

/// Routes a request to its handler and holds the session state between requests.
pub struct Dispatcher<A: Approver, P: PassphraseSource> {
    wallet_path: PathBuf,
    config: Config,
    session: Session,
    approver: A,
    passphrase: P,
}

impl<A: Approver, P: PassphraseSource> Dispatcher<A, P> {
    /// Build a dispatcher over the wallet file at `wallet_path`, resolving RPC
    /// endpoints from `config`, and taking human decisions through `approver`
    /// and `passphrase`.
    pub fn new(wallet_path: PathBuf, config: Config, approver: A, passphrase: P) -> Self {
        Self {
            wallet_path,
            config,
            session: Session::default(),
            approver,
            passphrase,
        }
    }

    /// Handle one request and produce its response envelope. Never panics on
    /// malformed input: a missing/unknown method becomes a `-1` error carrying
    /// the request's `id` (or `null`).
    pub fn handle(&mut self, request: &Value) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        match self.dispatch(request) {
            Ok(result) => json!({ "id": id, "result": result }),
            Err(err) => json!({
                "id": id,
                "error": { "code": err.code, "message": err.message },
            }),
        }
    }

    fn dispatch(&mut self, request: &Value) -> Result<Value, MethodError> {
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| MethodError::general("request is missing a string `method`"))?;

        match method {
            "wallet_status" => self.wallet_status(),
            "wallet_unlock" => self.wallet_unlock(),
            "eth_accounts" => self.eth_accounts(),
            "eth_chainId" => self.eth_chain_id(),
            "eth_requestAccounts" => self.eth_request_accounts(request),
            "eth_sendTransaction" => self.eth_send_transaction(request),
            "personal_sign" | "eth_sign" => self.sign_message(request),
            other => Err(MethodError::general(format!("unsupported method: {other}"))),
        }
    }

    // --- Methods ----------------------------------------------------------

    fn wallet_status(&self) -> Result<Value, MethodError> {
        let (locked, accounts) = match &self.session.wallet {
            Some(wallet) => (false, visible_accounts(wallet)),
            None => (true, Vec::new()),
        };
        Ok(json!({
            "locked": locked,
            "accounts": accounts,
            "activeSessions": if locked { 0 } else { 1 },
            "hasKeystore": self.wallet_path.exists(),
        }))
    }

    fn wallet_unlock(&mut self) -> Result<Value, MethodError> {
        let passphrase = self
            .passphrase
            .passphrase()
            .map_err(|err| MethodError::general(err.to_string()))?;
        let wallet = Wallet::open(
            &self.wallet_path,
            passphrase.as_bytes(),
            None,
            evm_registry(),
        )
        .map_err(|err| MethodError::general(format!("unlock failed: {err}")))?;
        let accounts = visible_accounts(&wallet);
        self.session.wallet = Some(wallet);
        Ok(json!({ "success": true, "accounts": accounts }))
    }

    fn eth_accounts(&self) -> Result<Value, MethodError> {
        let wallet = self.require_wallet()?;
        Ok(json!(visible_accounts(wallet)))
    }

    fn eth_chain_id(&self) -> Result<Value, MethodError> {
        let chain_id = self
            .config
            .network(&self.config.default_network)
            .map(|network| network.chain_id)
            .unwrap_or(1);
        Ok(json!(format!("0x{chain_id:x}")))
    }

    fn eth_request_accounts(&mut self, request: &Value) -> Result<Value, MethodError> {
        let origin = extract_origin(request);
        let accounts = {
            let wallet = self.require_wallet()?;
            visible_accounts(wallet)
        };
        let approved = self.approver.approve(&ApprovalRequest::Connect {
            origin,
            accounts: accounts.clone(),
        });
        if !approved {
            return Err(MethodError::rejected());
        }
        Ok(json!(accounts))
    }

    fn sign_message(&mut self, request: &Value) -> Result<Value, MethodError> {
        let params = request
            .get("params")
            .and_then(Value::as_array)
            .ok_or_else(|| MethodError::general("expected an array of params"))?;
        let first = param_str(params, 0)?;
        let second = param_str(params, 1)?;
        // Tolerate either argument order (personal_sign is [message, address];
        // eth_sign is [address, message]) by picking whichever looks like an
        // address.
        let (address, message_raw) = if is_eth_address(&second) {
            (second, first)
        } else {
            (first, second)
        };
        if !is_eth_address(&address) {
            return Err(MethodError::general(
                "could not identify a signing address in the params",
            ));
        }
        let message_bytes = decode_message(&message_raw);

        let origin = extract_origin(request);
        let account_id = {
            let wallet = self.require_wallet()?;
            resolve_account(wallet, &address)?
        };
        let approved = self.approver.approve(&ApprovalRequest::SignMessage {
            origin,
            from: address,
            message: message_bytes.clone(),
        });
        if !approved {
            return Err(MethodError::rejected());
        }

        let wallet = self.require_wallet()?;
        let payload = evm::message_payload(&message_bytes);
        let signature = wallet
            .sign(&account_id, &payload)
            .map_err(|err| MethodError::general(format!("signing failed: {err}")))?;
        Ok(json!(format!("0x{}", hex::encode(signature))))
    }

    fn eth_send_transaction(&mut self, request: &Value) -> Result<Value, MethodError> {
        let params = request
            .get("params")
            .and_then(Value::as_array)
            .ok_or_else(|| MethodError::general("expected an array of params"))?;
        let tx = params
            .first()
            .and_then(Value::as_object)
            .ok_or_else(|| MethodError::general("expected a transaction object at params[0]"))?;

        let from = tx
            .get("from")
            .and_then(Value::as_str)
            .ok_or_else(|| MethodError::general("transaction is missing `from`"))?
            .to_string();
        let to = tx
            .get("to")
            .and_then(Value::as_str)
            .ok_or_else(|| MethodError::general("transaction is missing `to`"))?
            .to_string();
        let value_wei = match tx.get("value").and_then(Value::as_str) {
            Some(value) => parse_hex_u128(value)?,
            None => 0,
        };
        let data = match tx
            .get("data")
            .or_else(|| tx.get("input"))
            .and_then(Value::as_str)
        {
            Some(data) => decode_hex_bytes(data)?,
            None => Vec::new(),
        };

        let origin = extract_origin(request);
        let account_id = {
            let wallet = self.require_wallet()?;
            resolve_account(wallet, &from)?
        };
        // Show the exact calldata that will be signed: `to`/`value` do not capture
        // a contract interaction (e.g. an ERC-20 approve), so the user must see it.
        let approved = self.approver.approve(&ApprovalRequest::SendTransaction {
            origin,
            from: from.clone(),
            to: to.clone(),
            value_wei,
            data: data.clone(),
        });
        if !approved {
            return Err(MethodError::rejected());
        }

        // Route to the node for the chain the tx names, when it carries one, so a
        // send lands on the right network instead of always the default. The tx
        // is still signed for whatever chain id the chosen node reports, so this
        // only picks the endpoint; it introduces no replay risk.
        let chain_id: Option<u64> = match tx.get("chainId") {
            None | Some(Value::Null) => None,
            Some(Value::String(hex)) => Some(
                u64::try_from(parse_hex_u128(hex)?)
                    .map_err(|_| MethodError::general(format!("chainId {hex} is out of range")))?,
            ),
            Some(Value::Number(num)) => {
                Some(num.as_u64().ok_or_else(|| {
                    MethodError::general("chainId must be a non-negative integer")
                })?)
            }
            Some(other) => return Err(MethodError::general(format!("invalid chainId: {other}"))),
        };
        let url = match chain_id {
            Some(id) => self
                .config
                .network_for_chain_id(id)
                .map(|network| network.rpc.clone())
                .ok_or_else(|| {
                    MethodError::general(format!(
                        "unknown chain id {id}; configure it in ~/.daemon-wallet/config.json"
                    ))
                })?,
            None => self.config.resolve_rpc(None).ok_or_else(|| {
                MethodError::general("no RPC endpoint configured for the default network")
            })?,
        };
        let client = RpcClient::new(url);
        let wallet = self.require_wallet()?;
        let tx_hash = client
            .send_eip1559(&from, &to, value_wei, data, |payload| {
                wallet
                    .sign(&account_id, payload)
                    .map_err(|err| err.to_string())
            })
            .map_err(|err| MethodError::general(format!("broadcast failed: {err}")))?;
        Ok(json!(tx_hash))
    }

    // --- Helpers ----------------------------------------------------------

    fn require_wallet(&self) -> Result<&Wallet, MethodError> {
        self.session
            .wallet
            .as_ref()
            .ok_or_else(|| MethodError::general("wallet is locked; call wallet_unlock first"))
    }
}

/// Build a chain registry with the EVM family registered.
fn evm_registry() -> ChainRegistry {
    let mut registry = ChainRegistry::new();
    registry.register(Box::new(EvmChain::new()));
    registry
}

/// The visible (non-hidden) accounts' addresses, derived accounts first in index
/// order, then imported ones, so the first entry is the primary account.
fn visible_accounts(wallet: &Wallet) -> Vec<String> {
    let mut accounts: Vec<&Account> = wallet
        .manifest()
        .accounts
        .values()
        .filter(|account| !account.hidden)
        .collect();
    accounts.sort_by_key(|account| match &account.source {
        AccountSource::Derived { index, .. } => (0u8, *index),
        AccountSource::Imported { .. } => (1u8, 0),
    });
    accounts
        .iter()
        .map(|account| account.address.to_string())
        .collect()
}

/// Resolve an `0x…` address string to its [`AccountId`], case-insensitively.
fn resolve_account(wallet: &Wallet, address: &str) -> Result<AccountId, MethodError> {
    let query = address.trim();
    wallet
        .manifest()
        .accounts
        .iter()
        .find(|(_, account)| account.address.as_str().eq_ignore_ascii_case(query))
        .map(|(id, _)| id.clone())
        .ok_or_else(|| MethodError::general(format!("no account matches address {address}")))
}

/// The requesting dapp origin, used only to inform the human approving a request.
///
/// ONLY the top-level `origin` is honored, because the extension stamps it from
/// the trusted `sender.origin`. Any `origin` carried inside the page-controlled
/// `params` is deliberately ignored: a hostile page could set it to impersonate a
/// trusted site in the approval prompt. When the stamp is absent the origin is
/// shown as unverified rather than guessed.
fn extract_origin(request: &Value) -> String {
    request
        .get("origin")
        .and_then(Value::as_str)
        .filter(|origin| !origin.is_empty())
        .unwrap_or("unknown (unverified)")
        .to_string()
}

/// Whether `s` is a syntactically valid `0x`-prefixed 20-byte EVM address.
fn is_eth_address(s: &str) -> bool {
    let s = s.trim();
    s.len() == 42 && s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

/// Decode a `personal_sign` message: hex if it is a well-formed `0x…` byte
/// string, otherwise the raw UTF-8 bytes (both are valid dapp conventions).
fn decode_message(raw: &str) -> Vec<u8> {
    hex_message_bytes(raw).unwrap_or_else(|| raw.as_bytes().to_vec())
}

/// Interpret `raw` as a well-formed `0x…` hex byte string, or `None` if it is
/// not one (empty, odd length, non-hex, or not `0x`-prefixed).
fn hex_message_bytes(raw: &str) -> Option<Vec<u8>> {
    let body = raw.strip_prefix("0x")?;
    if body.is_empty() || body.len() % 2 != 0 {
        return None;
    }
    hex::decode(body).ok()
}

/// Parse an `0x`-prefixed (or bare) hex quantity into wei.
fn parse_hex_u128(s: &str) -> Result<u128, MethodError> {
    let trimmed = s.trim();
    let body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if body.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(body, 16)
        .map_err(|err| MethodError::general(format!("invalid hex quantity {s:?}: {err}")))
}

/// Decode `0x`-prefixed (or bare) hex calldata into bytes.
fn decode_hex_bytes(s: &str) -> Result<Vec<u8>, MethodError> {
    let trimmed = s.trim();
    let body = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if body.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(body).map_err(|err| MethodError::general(format!("invalid hex data: {err}")))
}

/// Pull a string param at `idx` out of a params array.
fn param_str(params: &[Value], idx: usize) -> Result<String, MethodError> {
    params
        .get(idx)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| MethodError::general(format!("expected a string param at index {idx}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{AutoApprover, FixedPassphrase, RejectingApprover};
    use daemon_wallet_core::{ChainKind, DerivationScheme};
    use daemon_wallet_vault::KdfParams;
    use tempfile::TempDir;

    const PASS: &str = "test-passphrase-123";
    // m/44'/60'/0'/0/0 of the anvil "test…junk" mnemonic.
    const ANVIL_ADDR0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    /// Create a throwaway wallet seeded from the anvil mnemonic with a single
    /// derived account, using fast KDF params so the test stays quick.
    fn test_wallet() -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wallet.vault");
        let mut wallet = Wallet::create(
            &path,
            PASS.as_bytes(),
            None,
            KdfParams::new(8, 1, 1),
            evm_registry(),
        )
        .expect("create wallet");
        let root = wallet.manifest().tree.root().clone();
        let phrase = "test test test test test test test test test test test junk";
        let normalized = bip39::Mnemonic::parse_normalized(phrase)
            .expect("parse mnemonic")
            .to_string();
        let seed = wallet
            .add_seed(
                ChainKind::Evm,
                "primary",
                DerivationScheme::Bip44Standard,
                false,
                normalized.as_bytes(),
            )
            .expect("add seed");
        wallet
            .derive_next_account(&seed, &root, "Account 0")
            .expect("derive account");
        wallet.save().expect("save wallet");
        (dir, path)
    }

    fn dispatcher<A: Approver>(path: PathBuf, approver: A) -> Dispatcher<A, FixedPassphrase> {
        Dispatcher::new(
            path,
            Config::default(),
            approver,
            FixedPassphrase(PASS.to_string()),
        )
    }

    #[test]
    fn send_transaction_approval_shows_calldata() {
        // ERC-20 approve(spender, amount) selector 0x095ea7b3 — the field that
        // decides what a "value: 0 wei" contract call actually does.
        let approval = ApprovalRequest::SendTransaction {
            origin: "https://evil.example".into(),
            from: ANVIL_ADDR0.into(),
            to: "0xToken".into(),
            value_wei: 0,
            data: vec![0x09, 0x5e, 0xa7, 0xb3],
        };
        let shown = approval.to_string();
        assert!(shown.contains("CONTRACT INTERACTION"), "{shown}");
        assert!(shown.contains("0x095ea7b3"), "{shown}");

        let plain = ApprovalRequest::SendTransaction {
            origin: "https://app.example".into(),
            from: ANVIL_ADDR0.into(),
            to: "0xabc".into(),
            value_wei: 1,
            data: vec![],
        };
        assert!(plain.to_string().contains("plain value transfer"));
    }

    #[test]
    fn extract_origin_ignores_page_supplied_params_origin() {
        // A page-controlled params origin must never be shown as the requester.
        let forged = json!({
            "id": 1, "method": "eth_requestAccounts",
            "params": [{ "origin": "https://app.uniswap.org" }]
        });
        assert_eq!(extract_origin(&forged), "unknown (unverified)");

        // Only the extension-stamped top-level origin is honored.
        let stamped = json!({
            "id": 1, "method": "eth_requestAccounts",
            "origin": "https://real.example",
            "params": [{ "origin": "https://app.uniswap.org" }]
        });
        assert_eq!(extract_origin(&stamped), "https://real.example");
    }

    #[test]
    fn sign_message_approval_shows_text_or_hex() {
        let text = ApprovalRequest::SignMessage {
            origin: "https://app.example".into(),
            from: ANVIL_ADDR0.into(),
            message: b"hello world".to_vec(),
        };
        assert!(text.to_string().contains("message: hello world"));

        // Binary (or hex) payloads must be shown as hex, not mojibake.
        let binary = ApprovalRequest::SignMessage {
            origin: "https://app.example".into(),
            from: ANVIL_ADDR0.into(),
            message: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let shown = binary.to_string();
        assert!(shown.contains("0xdeadbeef"), "{shown}");
        assert!(shown.contains("binary - shown as hex"), "{shown}");
    }

    /// The daemon's most dangerous path end to end: parse browser params, approve,
    /// sign, and broadcast. Needs a local anvil on 127.0.0.1:8545 started with the
    /// "test…junk" mnemonic. Run with `cargo test -p daemon-wallet-daemon -- --ignored`.
    #[test]
    #[ignore = "requires a local anvil node on 127.0.0.1:8545"]
    fn eth_send_transaction_broadcasts_against_anvil() {
        let (_dir, path) = test_wallet();
        let mut d = dispatcher(path, AutoApprover);

        let unlocked = d.handle(&json!({ "id": 1, "method": "wallet_unlock", "params": [] }));
        assert!(
            unlocked.get("result").is_some(),
            "unlock failed: {unlocked}"
        );

        let resp = d.handle(&json!({
            "id": 2,
            "method": "eth_sendTransaction",
            "params": [{
                "from": ANVIL_ADDR0,
                "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
                "value": "0xde0b6b3a7640000"
            }]
        }));
        let hash = resp
            .get("result")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no tx hash in response: {resp}"));
        assert!(
            hash.starts_with("0x") && hash.len() == 66,
            "not a tx hash: {hash}"
        );
    }

    #[test]
    fn eth_send_transaction_rejection_does_not_broadcast() {
        // A rejected approval must short-circuit to 4001 *before* any RPC/broadcast.
        // No anvil is running, so a 4001 (rather than a broadcast error) proves the
        // send never left the approval gate.
        let (_dir, path) = test_wallet();
        let mut d = dispatcher(path, RejectingApprover);
        d.handle(&json!({ "id": 1, "method": "wallet_unlock", "params": [] }));
        let resp = d.handle(&json!({
            "id": 2,
            "method": "eth_sendTransaction",
            "params": [{
                "from": ANVIL_ADDR0,
                "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
                "value": "0xde0b6b3a7640000"
            }]
        }));
        assert_eq!(
            resp.get("error")
                .and_then(|e| e.get("code"))
                .and_then(Value::as_i64),
            Some(4001),
            "expected rejection, got: {resp}"
        );
    }

    #[test]
    fn wallet_status_reflects_lock_then_unlock() {
        let (_dir, path) = test_wallet();
        let mut d = dispatcher(path, AutoApprover);

        let locked = d.handle(&json!({ "id": 1, "method": "wallet_status", "params": [] }));
        let result = &locked["result"];
        assert_eq!(result["locked"], json!(true));
        assert_eq!(result["accounts"], json!([]));
        assert_eq!(result["activeSessions"], json!(0));
        assert_eq!(result["hasKeystore"], json!(true));

        let unlock = d.handle(&json!({ "id": 2, "method": "wallet_unlock", "params": [] }));
        assert_eq!(unlock["result"]["success"], json!(true));
        let accounts = unlock["result"]["accounts"].as_array().expect("accounts");
        assert_eq!(accounts.len(), 1);
        assert!(
            accounts[0]
                .as_str()
                .unwrap()
                .eq_ignore_ascii_case(ANVIL_ADDR0)
        );

        let status = d.handle(&json!({ "id": 3, "method": "wallet_status", "params": [] }));
        assert_eq!(status["result"]["locked"], json!(false));
        assert_eq!(status["result"]["activeSessions"], json!(1));
    }

    #[test]
    fn eth_accounts_requires_unlock_then_lists_addresses() {
        let (_dir, path) = test_wallet();
        let mut d = dispatcher(path, AutoApprover);

        let locked = d.handle(&json!({ "id": 1, "method": "eth_accounts", "params": [] }));
        assert_eq!(locked["error"]["code"], json!(-1));
        assert!(locked.get("result").is_none());

        d.handle(&json!({ "id": 2, "method": "wallet_unlock", "params": [] }));
        let accounts = d.handle(&json!({ "id": 3, "method": "eth_accounts", "params": [] }));
        let list = accounts["result"].as_array().expect("accounts array");
        assert_eq!(list.len(), 1);
        assert!(list[0].as_str().unwrap().eq_ignore_ascii_case(ANVIL_ADDR0));
    }

    #[test]
    fn eth_request_accounts_approved_returns_accounts() {
        let (_dir, path) = test_wallet();
        let mut d = dispatcher(path, AutoApprover);
        d.handle(&json!({ "id": 1, "method": "wallet_unlock", "params": [] }));

        let resp = d.handle(&json!({
            "id": 2,
            "method": "eth_requestAccounts",
            "params": [{ "origin": "https://example.com" }],
        }));
        let list = resp["result"].as_array().expect("accounts array");
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn personal_sign_returns_65_byte_signature() {
        let (_dir, path) = test_wallet();
        let mut d = dispatcher(path, AutoApprover);
        d.handle(&json!({ "id": 1, "method": "wallet_unlock", "params": [] }));

        let resp = d.handle(&json!({
            "id": 2,
            "method": "personal_sign",
            "params": ["Hello World", ANVIL_ADDR0],
        }));
        let sig = resp["result"].as_str().expect("signature string");
        // "0x" + 65 bytes * 2 hex chars.
        assert!(sig.starts_with("0x"));
        assert_eq!(sig.len(), 2 + 130);
    }

    #[test]
    fn rejecting_approver_yields_4001() {
        let (_dir, path) = test_wallet();
        let mut d = dispatcher(path, RejectingApprover);
        d.handle(&json!({ "id": 1, "method": "wallet_unlock", "params": [] }));

        let resp = d.handle(&json!({
            "id": 2,
            "method": "personal_sign",
            "params": ["Hello World", ANVIL_ADDR0],
        }));
        assert_eq!(resp["error"]["code"], json!(4001));
        assert!(resp.get("result").is_none());
    }

    #[test]
    fn send_transaction_unknown_chain_id_is_a_clear_error() {
        // An unconfigured chainId must fail before any RPC call, naming the chain
        // and where to configure it. 0x5 (Goerli) is absent from the defaults.
        let (_dir, path) = test_wallet();
        let mut d = dispatcher(path, AutoApprover);
        d.handle(&json!({ "id": 1, "method": "wallet_unlock", "params": [] }));
        let resp = d.handle(&json!({
            "id": 2,
            "method": "eth_sendTransaction",
            "params": [{
                "from": ANVIL_ADDR0,
                "to": ANVIL_ADDR0,
                "value": "0x0",
                "chainId": "0x5",
            }],
        }));
        assert_eq!(resp["error"]["code"], json!(-1));
        let message = resp["error"]["message"].as_str().expect("message");
        assert!(message.contains("unknown chain id 5"), "{message}");
    }

    #[test]
    fn unknown_method_is_general_error() {
        let (_dir, path) = test_wallet();
        let mut d = dispatcher(path, AutoApprover);
        let resp = d.handle(&json!({ "id": 9, "method": "eth_frobnicate", "params": [] }));
        assert_eq!(resp["error"]["code"], json!(-1));
        assert_eq!(resp["id"], json!(9));
    }
}

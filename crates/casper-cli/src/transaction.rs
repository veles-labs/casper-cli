use anyhow::{Context, Result, anyhow, bail};
use casper_execution_engine::engine_state::{EngineConfig, ExecutionEngineV1};
use casper_types::account::AccountHash;
use casper_types::bytesrepr::deserialize_from_slice;
use casper_types::contracts::ContractHash;
use casper_types::{
    AddressableEntityHash, CLType, CLValue, DeployHash, Digest, PackageHash, PublicKey,
    RuntimeArgs, SecretKey, Transaction, TransactionHash, TransactionV1Hash, TransferTarget, U512,
    URef,
};
use clap::{Args, Subcommand};
use sha3::{Digest as _, Keccak256};
use std::fs;
use std::sync::Arc;
use tokio::runtime::Runtime;
use veles_casper_rust_sdk::jsonrpc::CasperClient;

use crate::arguments::parse_argument;
use crate::contract_runtime::ContractRuntime;
use crate::contract_runtime::store::SledStore;
use crate::storage::StorageConfig;
use crate::wallet;
use crate::{cl_type, cl_value};
use crate::{network, utils};

mod call;
mod get;
mod put;
mod transfer;

const DEFAULT_GAS_PRICE_TOLERANCE: u8 = 1;
const EVM_ADDRESS_LEN: usize = 20;
const EVM_ADDRESS_HEX_LEN: usize = EVM_ADDRESS_LEN * 2;

#[derive(Clone, Debug, Eq, PartialEq)]
enum ResolvedTransferTarget {
    Native(TransferTarget),
    EvmAddress([u8; EVM_ADDRESS_LEN]),
}

impl ResolvedTransferTarget {
    fn is_evm_address(&self) -> bool {
        matches!(self, ResolvedTransferTarget::EvmAddress(_))
    }
}

#[derive(Args)]
/// Transaction submission commands.
pub struct TxArgs {
    #[command(subcommand)]
    command: TxCommand,
}

#[derive(Subcommand)]
/// Transaction subcommands.
pub enum TxCommand {
    /// Build a session transaction from Wasm.
    Put(put::PutArgs),
    /// Call a stored contract by hash.
    Call(call::CallArgs),
    /// Fetch transaction execution details by hash.
    Get(get::GetArgs),
    /// Transfer tokens to another account.
    Transfer(transfer::TransferArgs),
}

pub fn handle(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    args: TxArgs,
) -> Result<()> {
    match args.command {
        TxCommand::Put(command) => put::handle(storage, context, command),
        TxCommand::Call(command) => call::handle(storage, context, command),
        TxCommand::Get(command) => get::handle(context, command),
        TxCommand::Transfer(command) => transfer::handle(storage, context, command),
    }
}

fn resolve_from_secret_key(storage: &StorageConfig, value: &str) -> Result<SecretKey> {
    if let Some((wallet_name, account_name)) = value.split_once(':') {
        if wallet_name.is_empty() || account_name.is_empty() {
            bail!("--from must be in the form wallet:account or a legacy wallet name");
        }
        return wallet::resolve_account_secret_key(storage, wallet_name, account_name);
    }
    if let Some(secret_key) = wallet::try_resolve_legacy_secret_key(storage, value)? {
        return Ok(secret_key);
    }
    bail!("--from must be in the form wallet:account or a legacy wallet name");
}

fn parse_runtime_args(values: &[String]) -> Result<RuntimeArgs> {
    let mut runtime_args = RuntimeArgs::new();
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        let (name, cl_value) = parse_argument(value).map_err(anyhow::Error::new)?;
        if !seen.insert(name.clone()) {
            bail!("duplicate argument name '{name}'");
        }
        runtime_args.insert_cl_value(name, cl_value);
    }
    Ok(runtime_args)
}

fn parse_transaction_hash(input: &str) -> Result<TransactionHash> {
    let trimmed = input.trim();
    let (kind, hex) = if let Some(inner) = trimmed.strip_prefix("deploy-hash-") {
        ("deploy", inner)
    } else if let Some(inner) = trimmed.strip_prefix("transaction-v1-hash-") {
        ("v1", inner)
    } else {
        ("v1", trimmed)
    };

    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let digest = Digest::from_hex(hex).context("invalid transaction hash hex")?;
    match kind {
        "deploy" => Ok(TransactionHash::from(DeployHash::new(digest))),
        "v1" => Ok(TransactionHash::from(TransactionV1Hash::from(digest))),
        _ => bail!("unsupported transaction hash format"),
    }
}

fn simulate_transaction(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    transaction: Transaction,
) -> Result<()> {
    let (network_name, binary_port) = network::active_network_binary_port(context)?;
    let (_network_name, rpc) = network::active_network_rpc(context)?;

    let base_dir = storage.base_dir()?;
    let runtime_dir = base_dir.join("global-state-cache").join(&network_name);
    fs::create_dir_all(&runtime_dir)
        .with_context(|| format!("failed to create {}", runtime_dir.display()))?;
    let db = sled::open(&runtime_dir)
        .with_context(|| format!("failed to open {}", runtime_dir.display()))?;
    let store = SledStore::new(
        binary_port.clone(),
        Arc::new(db),
        &format!("trie-cache-{network_name}"),
    );
    let engine = ExecutionEngineV1::new(EngineConfig::default());
    let contract_runtime = ContractRuntime::new(store.clone(), engine);
    let runtime = Runtime::new().context("failed to start async runtime")?;

    let client = CasperClient::new(rpc);
    let block = runtime
        .block_on(async { client.get_block(None).await })?
        .block_with_signatures
        .ok_or(anyhow!("Nope"))?
        .block;
    let block_header = block.clone_header();
    let state_root_hash = *block.state_root_hash();
    let block_info = casper_execution_engine::engine_state::BlockInfo::new(
        state_root_hash,
        block.timestamp().into(),
        *block_header.parent_hash(),
        block_header.height(),
        block_header.protocol_version(),
    );
    let Transaction::V1(txn) = transaction else {
        return Err(anyhow!("Only Transaction V1 is supported for simulation"));
    };

    let (hits_before, misses_before) = store.cache_stats();

    let result = contract_runtime
        .execute(block_info, txn)
        .context("execution")?;

    println!(
        "Simulation result on {network_name} at block height {}:",
        block_header.height()
    );
    println!(
        "Gas used: {}",
        utils::format_cspr(&result.consumed().value())
    );
    match result.error() {
        Some(exec_error) => {
            eprintln!("Execution failed: {}", exec_error);
            bail!("simulation failed");
        }
        None => {
            println!("Execution succeeded.");
        }
    }

    if let Some(bytes) = result.ret()
        && bytes.cl_type() != &CLType::Unit
    {
        let value = match cl_value::cl_value_to_string(bytes) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("Warning: failed to format return value: {error}");
                format!("0x{}", hex::encode(bytes.inner_bytes()))
            }
        };
        println!(
            "Return {}: {value}",
            cl_type::cl_type_to_string(bytes.cl_type())
        );
    } else {
        println!("Return: <empty>");
    }

    let (hits_after, misses_after) = store.cache_stats();
    println!("New tries downloaded: {}", misses_after - misses_before);
    println!("Cache hits during execution: {}", hits_after - hits_before);
    println!("Cleaning up unreferenced tries...");
    let cleaned_up = store.gc_unreferenced(&[state_root_hash.value()])?;
    println!("Cleaned up {} unreferenced tries", cleaned_up);
    Ok(())
}

fn resolve_transfer_target(storage: &StorageConfig, value: &str) -> Result<ResolvedTransferTarget> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("--to cannot be empty");
    }
    if let Some((wallet_name, account_name)) = trimmed.split_once(':') {
        if wallet_name.is_empty() || account_name.is_empty() {
            bail!("--to wallet reference must be <wallet>:<account>");
        }
        let public_key_hex =
            wallet::resolve_account_public_key(storage, wallet_name, account_name)?;
        return parse_transfer_target(&public_key_hex);
    }
    if let Some(public_key_hex) = wallet::try_resolve_legacy_public_key(storage, trimmed)? {
        return parse_transfer_target(&public_key_hex);
    }
    parse_transfer_target(trimmed)
}

fn parse_transfer_target(value: &str) -> Result<ResolvedTransferTarget> {
    const ACCOUNT_HASH_LEN: usize = 32;
    if let Ok(account_hash) = AccountHash::from_formatted_str(value) {
        return Ok(ResolvedTransferTarget::Native(TransferTarget::AccountHash(
            account_hash,
        )));
    }
    if let Ok(uref) = URef::from_formatted_str(value) {
        return Ok(ResolvedTransferTarget::Native(TransferTarget::URef(uref)));
    }
    if let Some(address) = parse_evm_address(value)? {
        return Ok(ResolvedTransferTarget::EvmAddress(address));
    }
    let hex = strip_hex_prefix(value);
    let bytes = hex::decode(hex).context("invalid transfer target hex")?;
    if bytes.len() == ACCOUNT_HASH_LEN {
        let mut hash = [0u8; ACCOUNT_HASH_LEN];
        hash.copy_from_slice(&bytes);
        return Ok(ResolvedTransferTarget::Native(TransferTarget::AccountHash(
            AccountHash::new(hash),
        )));
    }
    let public_key: PublicKey = deserialize_from_slice(&bytes).map_err(|_| {
        anyhow!(
            "transfer target must be a wallet reference, legacy wallet name, 0x-prefixed 20-byte EVM address, 32-byte account hash, formatted URef, or public key bytes"
        )
    })?;
    Ok(ResolvedTransferTarget::Native(TransferTarget::PublicKey(
        public_key,
    )))
}

fn evm_transfer_runtime_args(amount: U512, address: [u8; EVM_ADDRESS_LEN]) -> Result<RuntimeArgs> {
    let mut runtime_args = RuntimeArgs::new();
    runtime_args.insert_cl_value(
        "target",
        CLValue::from_components(CLType::ByteArray(EVM_ADDRESS_LEN as u32), address.to_vec()),
    );
    runtime_args
        .insert("amount", amount)
        .map_err(|err| anyhow!("failed to encode transfer amount: {err:?}"))?;
    Ok(runtime_args)
}

fn strip_hex_prefix(value: &str) -> &str {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
}

fn strip_evm_hex_prefix(value: &str) -> Option<&str> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
}

fn parse_evm_address(value: &str) -> Result<Option<[u8; EVM_ADDRESS_LEN]>> {
    let trimmed = value.trim();
    let Some(hex) = strip_evm_hex_prefix(trimmed) else {
        if trimmed.len() == EVM_ADDRESS_HEX_LEN
            && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("EVM address recipients must include a 0x prefix");
        }
        return Ok(None);
    };
    if hex.len() != EVM_ADDRESS_HEX_LEN {
        return Ok(None);
    }
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid EVM address hex");
    }
    if has_mixed_hex_case(hex) && !has_valid_eip55_checksum(hex) {
        bail!("invalid EIP-55 checksum for EVM address");
    }
    let bytes = hex::decode(hex).context("invalid EVM address hex")?;
    let mut address = [0u8; EVM_ADDRESS_LEN];
    address.copy_from_slice(&bytes);
    Ok(Some(address))
}

fn has_mixed_hex_case(value: &str) -> bool {
    let has_lower = value.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_upper = value.bytes().any(|byte| byte.is_ascii_uppercase());
    has_lower && has_upper
}

fn has_valid_eip55_checksum(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let hash = Keccak256::digest(lower.as_bytes());
    value.bytes().enumerate().all(|(index, byte)| {
        if !byte.is_ascii_alphabetic() {
            return true;
        }
        let hash_byte = hash[index / 2];
        let hash_nibble = if index % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };
        byte.is_ascii_uppercase() == (hash_nibble >= 8)
    })
}

fn parse_contract_hash(value: &str) -> Result<AddressableEntityHash> {
    const CONTRACT_HASH_LEN: usize = 32;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("contract hash cannot be empty");
    }
    if let Ok(hash) = AddressableEntityHash::from_formatted_str(trimmed) {
        return Ok(hash);
    }
    if let Ok(hash) = ContractHash::from_formatted_str(trimmed) {
        return Ok(AddressableEntityHash::from(hash));
    }
    let bytes = hex::decode(trimmed).context("invalid contract hash hex")?;
    if bytes.len() != CONTRACT_HASH_LEN {
        bail!("contract hash must be 32 bytes");
    }
    let mut hash = [0u8; CONTRACT_HASH_LEN];
    hash.copy_from_slice(&bytes);
    Ok(AddressableEntityHash::new(hash))
}

fn parse_package_hash(value: &str) -> Result<PackageHash> {
    const PACKAGE_HASH_LEN: usize = 32;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("package hash cannot be empty");
    }
    if let Ok(hash) = PackageHash::from_formatted_str(trimmed) {
        return Ok(hash);
    }
    let bytes = hex::decode(trimmed).context("invalid package hash hex")?;
    if bytes.len() != PACKAGE_HASH_LEN {
        bail!("package hash must be 32 bytes");
    }
    let mut hash = [0u8; PACKAGE_HASH_LEN];
    hash.copy_from_slice(&bytes);
    Ok(PackageHash::new(hash))
}

fn looks_like_hex_hash(value: &str) -> bool {
    let trimmed = value.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex.len() != 64 {
        return false;
    }
    hex.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn looks_like_contract_hash(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("contract-")
        || trimmed.starts_with("addressable-entity-")
        || looks_like_hex_hash(trimmed)
}

fn looks_like_package_hash(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("package-") || looks_like_hex_hash(trimmed)
}

#[cfg(test)]
mod tests {
    use super::{
        ResolvedTransferTarget, evm_transfer_runtime_args, parse_contract_hash, parse_package_hash,
        parse_transaction_hash, parse_transfer_target,
    };
    use casper_types::bytesrepr::ToBytes;
    use casper_types::contracts::ContractHash;
    use casper_types::crypto::AsymmetricType;
    use casper_types::{
        AccessRights, AddressableEntityHash, CLType, DeployHash, Digest, PackageHash, PublicKey,
        TransactionHash, TransactionV1Hash, TransferTarget, U512, URef, account::AccountHash,
    };

    fn sample_digest_hex() -> String {
        "00".repeat(Digest::LENGTH)
    }

    #[test]
    fn parse_transaction_hash_defaults_to_v1() {
        let hex = sample_digest_hex();
        let digest = Digest::from_hex(&hex).expect("digest from hex");
        let parsed = parse_transaction_hash(&hex).expect("parse transaction hash");
        assert_eq!(
            parsed,
            TransactionHash::from(TransactionV1Hash::from(digest))
        );
    }

    #[test]
    fn parse_transaction_hash_accepts_v1_prefix() {
        let hex = sample_digest_hex();
        let digest = Digest::from_hex(&hex).expect("digest from hex");
        let input = format!("transaction-v1-hash-{hex}");
        let parsed = parse_transaction_hash(&input).expect("parse transaction hash");
        assert_eq!(
            parsed,
            TransactionHash::from(TransactionV1Hash::from(digest))
        );
    }

    #[test]
    fn parse_transaction_hash_accepts_deploy_prefix() {
        let hex = sample_digest_hex();
        let digest = Digest::from_hex(&hex).expect("digest from hex");
        let input = format!("deploy-hash-{hex}");
        let parsed = parse_transaction_hash(&input).expect("parse transaction hash");
        assert_eq!(parsed, TransactionHash::from(DeployHash::new(digest)));
    }

    #[test]
    fn parse_transaction_hash_rejects_invalid_hex() {
        let err = parse_transaction_hash("transaction-v1-hash-not-hex")
            .expect_err("invalid hex should error");
        let message = format!("{err}");
        assert!(message.contains("invalid transaction hash hex"));
    }

    #[test]
    fn parses_contract_hash_formatted() {
        let contract_hash = ContractHash::new([1u8; 32]);
        let formatted = contract_hash.to_formatted_string();
        let parsed = parse_contract_hash(&formatted).expect("hash");
        assert_eq!(parsed, AddressableEntityHash::from(contract_hash));
    }

    #[test]
    fn parses_addressable_entity_hash_formatted() {
        let entity_hash = AddressableEntityHash::new([2u8; 32]);
        let formatted = entity_hash.to_formatted_string();
        let parsed = parse_contract_hash(&formatted).expect("hash");
        assert_eq!(parsed, entity_hash);
    }

    #[test]
    fn parses_raw_contract_hash_hex() {
        let bytes = [3u8; 32];
        let hex = hex::encode(bytes);
        let parsed = parse_contract_hash(&hex).expect("hash");
        assert_eq!(parsed, AddressableEntityHash::new(bytes));
    }

    #[test]
    fn parses_package_hash_formatted() {
        let package_hash = PackageHash::new([4u8; 32]);
        let formatted = package_hash.to_formatted_string();
        let parsed = parse_package_hash(&formatted).expect("hash");
        assert_eq!(parsed, package_hash);
    }

    #[test]
    fn parses_raw_package_hash_hex() {
        let bytes = [5u8; 32];
        let hex = hex::encode(bytes);
        let parsed = parse_package_hash(&hex).expect("hash");
        assert_eq!(parsed, PackageHash::new(bytes));
    }

    #[test]
    fn parses_transfer_target_public_key_bytes() {
        let public_key = PublicKey::ed25519_from_bytes([1u8; 32]).expect("public key");
        let bytes = public_key.to_bytes().expect("bytes");
        let hex = hex::encode(bytes);
        let parsed = parse_transfer_target(&hex).expect("target");
        assert_eq!(
            parsed,
            ResolvedTransferTarget::Native(TransferTarget::PublicKey(public_key))
        );
    }

    #[test]
    fn parses_transfer_target_account_hash_bytes() {
        let account_hash = AccountHash::new([2u8; 32]);
        let hex = hex::encode(account_hash.as_ref());
        let parsed = parse_transfer_target(&hex).expect("target");
        assert_eq!(
            parsed,
            ResolvedTransferTarget::Native(TransferTarget::AccountHash(account_hash))
        );
    }

    #[test]
    fn parses_transfer_target_account_hash_bytes_with_0x_prefix() {
        let account_hash = AccountHash::new([2u8; 32]);
        let hex = format!("0x{}", hex::encode(account_hash.as_ref()));
        let parsed = parse_transfer_target(&hex).expect("target");
        assert_eq!(
            parsed,
            ResolvedTransferTarget::Native(TransferTarget::AccountHash(account_hash))
        );
    }

    #[test]
    fn parses_transfer_target_uref_formatted() {
        let uref = URef::new([3u8; 32], AccessRights::READ_ADD_WRITE);
        let formatted = uref.to_formatted_string();
        let parsed = parse_transfer_target(&formatted).expect("target");
        assert_eq!(
            parsed,
            ResolvedTransferTarget::Native(TransferTarget::URef(uref))
        );
    }

    #[test]
    fn rejects_transfer_target_evm_address_without_prefix() {
        let err = parse_transfer_target("de709f2102306220921060314715629080e2fb77")
            .expect_err("unprefixed EVM address should fail");
        let message = format!("{err}");
        assert!(message.contains("must include a 0x prefix"));
    }

    #[test]
    fn parses_transfer_target_evm_address_with_prefix() {
        let parsed =
            parse_transfer_target("0xde709f2102306220921060314715629080e2fb77").expect("target");
        assert!(matches!(parsed, ResolvedTransferTarget::EvmAddress(_)));
    }

    #[test]
    fn parses_transfer_target_evm_address_with_eip55_checksum() {
        let parsed =
            parse_transfer_target("0x52908400098527886E0F7030069857D2E4169EE7").expect("target");
        assert_eq!(
            parsed,
            ResolvedTransferTarget::EvmAddress([
                0x52, 0x90, 0x84, 0x00, 0x09, 0x85, 0x27, 0x88, 0x6e, 0x0f, 0x70, 0x30, 0x06, 0x98,
                0x57, 0xd2, 0xe4, 0x16, 0x9e, 0xe7,
            ])
        );
    }

    #[test]
    fn rejects_transfer_target_evm_address_with_invalid_eip55_checksum() {
        let err = parse_transfer_target("0x52908400098527886E0F7030069857D2E4169Ee7")
            .expect_err("invalid checksum should fail");
        let message = format!("{err}");
        assert!(message.contains("invalid EIP-55 checksum"));
    }

    #[test]
    fn rejects_malformed_evm_sized_transfer_target_hex() {
        let err = parse_transfer_target("0xde709f2102306220921060314715629080e2fb7z")
            .expect_err("invalid hex should fail");
        let message = format!("{err}");
        assert!(message.contains("invalid EVM address hex"));
    }

    #[test]
    fn rejects_short_or_long_transfer_target_hex() {
        let short = parse_transfer_target("0x1234").expect_err("short target should fail");
        let short_message = format!("{short}");
        assert!(short_message.contains("transfer target must be"));

        let long = parse_transfer_target(&format!("0x{}", "11".repeat(21)))
            .expect_err("long target should fail");
        let long_message = format!("{long}");
        assert!(long_message.contains("transfer target must be"));
    }

    #[test]
    fn evm_transfer_runtime_args_use_byte_array_20_target() {
        let address = [0x11; 20];
        let args = evm_transfer_runtime_args(U512::from(1u64), address).expect("runtime args");
        let target = args.get("target").expect("target arg");
        assert_eq!(target.cl_type(), &CLType::ByteArray(20));
        assert_eq!(target.inner_bytes(), &address.to_vec());

        let amount = args.get("amount").expect("amount arg");
        assert_eq!(amount.cl_type(), &CLType::U512);
    }
}

use anyhow::{Context, Result, anyhow, bail};
use casper_execution_engine::engine_state::{EngineConfig, ExecutionEngineV1};
use casper_types::account::AccountHash;
use casper_types::bytesrepr::{Bytes, deserialize_from_slice};
use casper_types::contracts::ContractHash;
use casper_types::{
    AddressableEntityHash, CLType, DeployHash, Digest, EntityVersion, PackageHash, PricingMode,
    PublicKey, RuntimeArgs, SecretKey, Transaction, TransactionHash, TransactionRuntimeParams,
    TransactionV1Hash, TransferTarget, URef,
};
use clap::{Args, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::Runtime;
use veles_casper_rust_sdk::TransactionV1Builder;
use veles_casper_rust_sdk::jsonrpc::CasperClient;

use crate::arguments::parse_argument;
use crate::contract_runtime::ContractRuntime;
use crate::contract_runtime::store::SledStore;
use crate::storage::StorageConfig;
use crate::wallet;
use crate::{cl_type, cl_value};
use crate::{network, utils};

const DEFAULT_GAS_PRICE_TOLERANCE: u8 = 1;

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
    Put(PutArgs),
    /// Call a stored contract by hash.
    Call(CallArgs),
    /// Fetch transaction execution details by hash.
    Get(GetArgs),
    /// Transfer tokens to another account.
    Transfer(TransferArgs),
}

#[derive(Args)]
/// Arguments for creating a session transaction.
pub struct PutArgs {
    /// Path to the session Wasm.
    wasm: PathBuf,
    /// Payment amount in CSPR.
    #[arg(long, default_value = "2.5")]
    payment_amount: String,
    /// Gas price tolerance (minimum 1).
    #[arg(long, default_value_t = DEFAULT_GAS_PRICE_TOLERANCE)]
    gas_price_tolerance: u8,
    /// Wallet/account reference (<wallet>:<account>) or legacy wallet name.
    #[arg(long)]
    from: String,
    /// Runtime argument in the form name:cltype=value or name=value (hex for Any).
    #[arg(long = "arg", value_name = "NAME[:CLTYPE]=VALUE")]
    args: Vec<String>,
    /// Mark the session as an install/upgrade transaction.
    #[arg(long)]
    install_upgrade: bool,
    /// Simulate execution using the network binary port.
    #[arg(long)]
    simulate: bool,
    /// Print only the transaction hash on success.
    #[arg(long)]
    raw: bool,
}

#[derive(Args)]
/// Arguments for calling a stored contract.
pub struct CallArgs {
    /// Contract hash (contract-/addressable-entity- prefix or raw hex), package hash with --package,
    /// or named key alias.
    contract_hash: String,
    /// Contract entry point name.
    entry_point: String,
    /// Payment amount in CSPR.
    #[arg(long, default_value = "2.5")]
    payment_amount: String,
    /// Gas price tolerance (minimum 1).
    #[arg(long, default_value_t = DEFAULT_GAS_PRICE_TOLERANCE)]
    gas_price_tolerance: u8,
    /// Wallet/account reference (<wallet>:<account>) or legacy wallet name.
    #[arg(long)]
    from: String,
    /// Runtime argument in the form name:cltype=value or name=value (hex for Any).
    #[arg(long = "arg", value_name = "NAME[:CLTYPE]=VALUE")]
    args: Vec<String>,
    /// Interpret the contract hash as a package hash.
    #[arg(long)]
    package: bool,
    /// Package version (requires --package).
    #[arg(long, value_name = "VERSION")]
    version: Option<EntityVersion>,
    /// Simulate execution using the network binary port.
    #[arg(long)]
    simulate: bool,
    /// Print only the transaction hash on success.
    #[arg(long)]
    raw: bool,
}

#[derive(Args)]
/// Arguments for transferring CSPR.
pub struct TransferArgs {
    /// Wallet/account reference (<wallet>:<account>) or legacy wallet name.
    #[arg(long)]
    from: String,
    /// Recipient wallet/account, legacy wallet name, public key bytes hex, or account hash bytes hex.
    #[arg(long)]
    to: String,
    /// Amount in CSPR.
    #[arg(long)]
    amount: String,
    /// Gas price tolerance (minimum 1).
    #[arg(long, default_value_t = DEFAULT_GAS_PRICE_TOLERANCE)]
    gas_price_tolerance: u8,
    /// Simulate execution using the network binary port.
    #[arg(long)]
    simulate: bool,
    /// Print only the transaction hash on success.
    #[arg(long)]
    raw: bool,
}

#[derive(Args)]
/// Arguments for fetching transaction details.
pub struct GetArgs {
    /// Transaction hash hex (or deploy-hash-<hex>/transaction-v1-hash-<hex>).
    transaction_hash: String,
    /// Request finalized approvals from the node.
    #[arg(long)]
    finalized_approvals: bool,
    /// Print only the execution_info JSON (or null if missing).
    #[arg(long)]
    raw: bool,
}

pub fn handle(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    args: TxArgs,
) -> Result<()> {
    match args.command {
        TxCommand::Put(command) => put_session(storage, context, command),
        TxCommand::Call(command) => call_contract(storage, context, command),
        TxCommand::Get(command) => get_transaction(context, command),
        TxCommand::Transfer(command) => transfer(storage, context, command),
    }
}

fn put_session(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    args: PutArgs,
) -> Result<()> {
    let module_bytes =
        fs::read(&args.wasm).with_context(|| format!("failed to read {}", args.wasm.display()))?;
    let runtime = TransactionRuntimeParams::VmCasperV1;
    let payment_amount = utils::u512_to_u64(utils::parse_cspr_to_motes(
        "payment amount",
        &args.payment_amount,
    )?)?;
    let pricing_mode = PricingMode::PaymentLimited {
        payment_amount,
        gas_price_tolerance: args.gas_price_tolerance,
        standard_payment: true,
    };
    let secret_key = resolve_from_secret_key(storage, &args.from)?;
    let chain_name = network::active_network_chain_name(context)?;
    let (network_name, rpc_endpoint) = network::active_network_rpc(context)?;

    let runtime_args = parse_runtime_args(&args.args)?;
    let builder =
        TransactionV1Builder::new_session(args.install_upgrade, Bytes::from(module_bytes), runtime)
            .with_pricing_mode(pricing_mode)
            .with_chain_name(chain_name)
            .with_runtime_args(runtime_args)
            .with_secret_key(&secret_key);

    let tx = builder.build()?;
    let transaction = Transaction::V1(tx);
    if args.simulate {
        return simulate_transaction(storage, context, transaction);
    }
    let runtime = Runtime::new().context("failed to start async runtime")?;
    let tx_hash = runtime.block_on(async {
        let client = CasperClient::new(rpc_endpoint);
        client.put_transaction(transaction).await
    })?;
    let tx_hash_bytes = tx_hash.digest();
    if args.raw {
        println!("{tx_hash_bytes:x}");
    } else {
        println!("Transaction submitted to {network_name}: {tx_hash_bytes:x}");
    }
    Ok(())
}

fn call_contract(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    args: CallArgs,
) -> Result<()> {
    if args.version.is_some() && !args.package {
        bail!("--version requires --package");
    }
    let runtime = TransactionRuntimeParams::VmCasperV1;
    let payment_amount = utils::u512_to_u64(utils::parse_cspr_to_motes(
        "payment amount",
        &args.payment_amount,
    )?)?;
    let pricing_mode = PricingMode::PaymentLimited {
        payment_amount,
        gas_price_tolerance: args.gas_price_tolerance,
        standard_payment: true,
    };
    let secret_key = resolve_from_secret_key(storage, &args.from)?;
    let chain_name = network::active_network_chain_name(context)?;
    let (network_name, rpc_endpoint) = network::active_network_rpc(context)?;

    let runtime_args = parse_runtime_args(&args.args)?;
    let entry_point = args.entry_point.as_str();
    let maybe_version = args.version;
    let target = args.contract_hash.trim();
    if target.is_empty() {
        if args.package {
            bail!("package hash cannot be empty");
        }
        bail!("contract hash cannot be empty");
    }
    let builder = if args.package {
        if looks_like_package_hash(target) {
            let package_hash = parse_package_hash(target)?;
            TransactionV1Builder::new_targeting_package(
                package_hash,
                maybe_version,
                entry_point,
                runtime,
            )
        } else if maybe_version.is_some() {
            TransactionV1Builder::new_targeting_package_via_alias_with_version_key(
                target,
                maybe_version,
                None,
                entry_point,
                runtime,
            )
        } else {
            TransactionV1Builder::new_targeting_package_via_alias(
                target,
                maybe_version,
                entry_point,
                runtime,
            )
        }
    } else if looks_like_contract_hash(target) {
        let contract_hash = parse_contract_hash(target)?;
        TransactionV1Builder::new_targeting_invocable_entity(contract_hash, entry_point, runtime)
    } else {
        TransactionV1Builder::new_targeting_invocable_entity_via_alias(target, entry_point, runtime)
    }
    .with_pricing_mode(pricing_mode)
    .with_chain_name(chain_name)
    .with_runtime_args(runtime_args)
    .with_secret_key(&secret_key);

    let tx = builder.build()?;
    let transaction = Transaction::V1(tx);
    if args.simulate {
        return simulate_transaction(storage, context, transaction);
    }
    let runtime = Runtime::new().context("failed to start async runtime")?;
    let tx_hash = runtime.block_on(async {
        let client = CasperClient::new(rpc_endpoint);
        client.put_transaction(transaction).await
    })?;
    let tx_hash_bytes = tx_hash.digest();
    if args.raw {
        println!("{tx_hash_bytes:x}");
    } else {
        println!("Contract call submitted to {network_name}: {tx_hash_bytes:x}");
    }
    Ok(())
}

fn transfer(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    args: TransferArgs,
) -> Result<()> {
    let amount = utils::parse_cspr_to_motes("transfer amount", &args.amount)?;
    let target = resolve_transfer_target(storage, &args.to)?;
    let secret_key = resolve_from_secret_key(storage, &args.from)?;
    let chain_name = network::active_network_chain_name(context)?;
    let (network_name, rpc_endpoint) = network::active_network_rpc(context)?;

    let pricing_mode = PricingMode::PaymentLimited {
        payment_amount: 2_500_000_000u64, // This is a standard payment of 2.5 CSPR which is ignored by the host anyway.
        gas_price_tolerance: args.gas_price_tolerance,
        standard_payment: true,
    };
    let builder = TransactionV1Builder::new_transfer(amount, None, target, None)
        .map_err(|err| anyhow!(err.to_string()))?
        .with_pricing_mode(pricing_mode)
        .with_chain_name(chain_name)
        .with_secret_key(&secret_key);

    let tx = builder.build()?;
    let transaction = Transaction::V1(tx);
    if args.simulate {
        return simulate_transaction(storage, context, transaction);
    }
    let runtime = Runtime::new().context("failed to start async runtime")?;
    let tx_hash = runtime.block_on(async {
        let client = CasperClient::new(rpc_endpoint);
        client.put_transaction(transaction).await
    })?;
    let tx_hash_bytes = tx_hash.digest();
    if args.raw {
        println!("{tx_hash_bytes:x}");
    } else {
        println!("Transfer submitted to {network_name}: {tx_hash_bytes:x}");
    }
    Ok(())
}

fn get_transaction(context: &network::ConfigContext, args: GetArgs) -> Result<()> {
    let transaction_hash = parse_transaction_hash(&args.transaction_hash)?;
    let (network_name, rpc_endpoint) = network::active_network_rpc(context)?;

    let runtime = Runtime::new().context("failed to start async runtime")?;
    let result = runtime.block_on(async {
        let client = CasperClient::new(rpc_endpoint);
        client
            .get_transaction(transaction_hash, args.finalized_approvals)
            .await
    })?;

    if args.raw {
        if let Some(execution_info) = result.execution_info {
            let json = serde_json::to_string_pretty(&execution_info)
                .context("format execution_info as json")?;
            println!("{json}");
        } else {
            println!("null");
        }
        return Ok(());
    }

    println!("Network: {network_name}");
    match result.execution_info {
        Some(execution_info) => {
            println!("Block hash: {:x}", execution_info.block_hash.inner());
            println!("Block height: {}", execution_info.block_height);
            if let Some(execution_result) = execution_info.execution_result {
                let consumed = execution_result.consumed();
                let consumed_cspr = utils::format_cspr(&consumed);
                println!("Gas consumed: {consumed_cspr} CSPR");
                if let Some(error) = execution_result.error_message() {
                    println!("Execution error: {error}");
                    bail!("transaction execution failed");
                } else {
                    println!("Execution status: success");
                }
            } else {
                println!("Execution result: <missing>");
            }
        }
        None => {
            println!("Execution info: <missing>");
        }
    }

    Ok(())
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

fn resolve_transfer_target(storage: &StorageConfig, value: &str) -> Result<TransferTarget> {
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

fn parse_transfer_target(value: &str) -> Result<TransferTarget> {
    const ACCOUNT_HASH_LEN: usize = 32;
    if let Ok(account_hash) = AccountHash::from_formatted_str(value) {
        return Ok(TransferTarget::AccountHash(account_hash));
    }
    if let Ok(uref) = URef::from_formatted_str(value) {
        return Ok(TransferTarget::URef(uref));
    }
    let bytes = hex::decode(value).context("invalid transfer target hex")?;
    if bytes.len() == ACCOUNT_HASH_LEN {
        let mut hash = [0u8; ACCOUNT_HASH_LEN];
        hash.copy_from_slice(&bytes);
        return Ok(TransferTarget::AccountHash(AccountHash::new(hash)));
    }
    let public_key: PublicKey =
        deserialize_from_slice(&bytes).map_err(|_| anyhow!("invalid public key bytes"))?;
    Ok(TransferTarget::PublicKey(public_key))
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
        parse_contract_hash, parse_package_hash, parse_transaction_hash, parse_transfer_target,
    };
    use casper_types::bytesrepr::ToBytes;
    use casper_types::contracts::ContractHash;
    use casper_types::crypto::AsymmetricType;
    use casper_types::{
        AccessRights, AddressableEntityHash, DeployHash, Digest, PackageHash, PublicKey,
        TransactionHash, TransactionV1Hash, TransferTarget, URef, account::AccountHash,
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
        assert_eq!(parsed, TransferTarget::PublicKey(public_key));
    }

    #[test]
    fn parses_transfer_target_account_hash_bytes() {
        let account_hash = AccountHash::new([2u8; 32]);
        let hex = hex::encode(account_hash.as_ref());
        let parsed = parse_transfer_target(&hex).expect("target");
        assert_eq!(parsed, TransferTarget::AccountHash(account_hash));
    }

    #[test]
    fn parses_transfer_target_uref_formatted() {
        let uref = URef::new([3u8; 32], AccessRights::READ_ADD_WRITE);
        let formatted = uref.to_formatted_string();
        let parsed = parse_transfer_target(&formatted).expect("target");
        assert_eq!(parsed, TransferTarget::URef(uref));
    }
}

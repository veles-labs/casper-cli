use anyhow::{Context, Result, anyhow, bail};
use casper_types::account::AccountHash;
use casper_types::bytesrepr::{Bytes, deserialize_from_slice};
use casper_types::contracts::ContractHash;
use casper_types::{
    AddressableEntityHash, DEFAULT_ENTRY_POINT_NAME, PricingMode, PublicKey, RuntimeArgs,
    Transaction, TransactionEntryPoint, TransactionRuntimeParams, TransferTarget, U512, URef,
};
use clap::{Args, Subcommand};
use std::fs;
use std::path::PathBuf;
use tokio::runtime::Runtime;
use veles_casper_rust_sdk::TransactionV1Builder;
use veles_casper_rust_sdk::jsonrpc::CasperClient;

use crate::arguments::parse_argument;
use crate::network;
use crate::storage::StorageConfig;
use crate::wallet;

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
    /// Wallet and account name in the form wallet:account.
    #[arg(long)]
    from: String,
    /// Runtime argument in the form name:cltype=value or name=value (hex for Any).
    #[arg(long = "arg", value_name = "NAME[:CLTYPE]=VALUE")]
    args: Vec<String>,
    /// Mark the session as an install/upgrade transaction.
    #[arg(long)]
    install_upgrade: bool,
}

#[derive(Args)]
/// Arguments for calling a stored contract.
pub struct CallArgs {
    /// Contract hash (contract-/addressable-entity- prefix or raw hex).
    contract_hash: String,
    /// Contract entry point name.
    entry_point: String,
    /// Payment amount in CSPR.
    #[arg(long, default_value = "2.5")]
    payment_amount: String,
    /// Gas price tolerance (minimum 1).
    #[arg(long, default_value_t = DEFAULT_GAS_PRICE_TOLERANCE)]
    gas_price_tolerance: u8,
    /// Wallet and account name in the form wallet:account.
    #[arg(long)]
    from: String,
    /// Runtime argument in the form name:cltype=value or name=value (hex for Any).
    #[arg(long = "arg", value_name = "NAME[:CLTYPE]=VALUE")]
    args: Vec<String>,
}

#[derive(Args)]
/// Arguments for transferring CSPR.
pub struct TransferArgs {
    /// Wallet and account name in the form wallet:account.
    #[arg(long)]
    from: String,
    /// Recipient wallet/account, public key bytes hex, or account hash bytes hex.
    #[arg(long)]
    to: String,
    /// Amount in CSPR.
    #[arg(long)]
    amount: String,
    /// Gas price tolerance (minimum 1).
    #[arg(long, default_value_t = DEFAULT_GAS_PRICE_TOLERANCE)]
    gas_price_tolerance: u8,
}

pub fn handle(storage: &StorageConfig, args: TxArgs) -> Result<()> {
    match args.command {
        TxCommand::Put(command) => put_session(storage, command),
        TxCommand::Call(command) => call_contract(storage, command),
        TxCommand::Transfer(command) => transfer(storage, command),
    }
}

fn put_session(storage: &StorageConfig, args: PutArgs) -> Result<()> {
    let module_bytes =
        fs::read(&args.wasm).with_context(|| format!("failed to read {}", args.wasm.display()))?;
    let runtime = TransactionRuntimeParams::VmCasperV1;
    let payment_amount = u512_to_u64(parse_cspr_to_motes("payment amount", &args.payment_amount)?)?;
    let pricing_mode = PricingMode::PaymentLimited {
        payment_amount,
        gas_price_tolerance: args.gas_price_tolerance,
        standard_payment: true,
    };
    let (wallet_name, account_name) = parse_wallet_account(&args.from)?;
    let secret_key = wallet::resolve_account_secret_key(storage, &wallet_name, &account_name)?;
    let chain_name = network::active_network_chain_name()?;
    let (network_name, rpc_endpoint) = network::active_network_rpc()?;

    let runtime_args = parse_runtime_args(&args.args)?;
    let builder =
        TransactionV1Builder::new_session(args.install_upgrade, Bytes::from(module_bytes), runtime)
            .with_pricing_mode(pricing_mode)
            .with_chain_name(chain_name)
            .with_runtime_args(runtime_args)
            .with_secret_key(&secret_key);

    let tx = builder.build()?;
    let transaction = Transaction::V1(tx);
    let runtime = Runtime::new().context("failed to start async runtime")?;
    let tx_hash = runtime.block_on(async {
        let client = CasperClient::new(rpc_endpoint);
        client.put_transaction(transaction).await
    })?;
    let tx_hash_bytes = tx_hash.digest();
    println!("Transaction submitted to {network_name}: {tx_hash_bytes:x}");
    Ok(())
}

fn call_contract(storage: &StorageConfig, args: CallArgs) -> Result<()> {
    let contract_hash = parse_contract_hash(&args.contract_hash)?;
    let runtime = TransactionRuntimeParams::VmCasperV1;
    let payment_amount = u512_to_u64(parse_cspr_to_motes("payment amount", &args.payment_amount)?)?;
    let pricing_mode = PricingMode::PaymentLimited {
        payment_amount,
        gas_price_tolerance: args.gas_price_tolerance,
        standard_payment: true,
    };
    let (wallet_name, account_name) = parse_wallet_account(&args.from)?;
    let secret_key = wallet::resolve_account_secret_key(storage, &wallet_name, &account_name)?;
    let chain_name = network::active_network_chain_name()?;
    let (network_name, rpc_endpoint) = network::active_network_rpc()?;

    let runtime_args = parse_runtime_args(&args.args)?;
    let builder = TransactionV1Builder::new_targeting_invocable_entity(
        contract_hash,
        DEFAULT_ENTRY_POINT_NAME,
        runtime,
    )
    .with_entry_point(TransactionEntryPoint::Custom(args.entry_point))
    .with_pricing_mode(pricing_mode)
    .with_chain_name(chain_name)
    .with_runtime_args(runtime_args)
    .with_secret_key(&secret_key);

    let tx = builder.build()?;
    let transaction = Transaction::V1(tx);
    let runtime = Runtime::new().context("failed to start async runtime")?;
    let tx_hash = runtime.block_on(async {
        let client = CasperClient::new(rpc_endpoint);
        client.put_transaction(transaction).await
    })?;
    let tx_hash_bytes = tx_hash.digest();
    println!("Contract call submitted to {network_name}: {tx_hash_bytes:x}");
    Ok(())
}

fn transfer(storage: &StorageConfig, args: TransferArgs) -> Result<()> {
    let amount = parse_cspr_to_motes("transfer amount", &args.amount)?;
    let target = resolve_transfer_target(storage, &args.to)?;
    let (wallet_name, account_name) = parse_wallet_account(&args.from)?;
    let secret_key = wallet::resolve_account_secret_key(storage, &wallet_name, &account_name)?;
    let chain_name = network::active_network_chain_name()?;
    let (network_name, rpc_endpoint) = network::active_network_rpc()?;

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
    let runtime = Runtime::new().context("failed to start async runtime")?;
    let tx_hash = runtime.block_on(async {
        let client = CasperClient::new(rpc_endpoint);
        client.put_transaction(transaction).await
    })?;
    let tx_hash_bytes = tx_hash.digest();
    println!("Transfer submitted to {network_name}: {tx_hash_bytes:x}");
    Ok(())
}

fn parse_wallet_account(value: &str) -> Result<(String, String)> {
    let (wallet_name, account_name) = value
        .split_once(':')
        .ok_or_else(|| anyhow!("--from must be in the form wallet:account"))?;
    if wallet_name.is_empty() || account_name.is_empty() {
        bail!("--from must be in the form wallet:account");
    }
    Ok((wallet_name.to_string(), account_name.to_string()))
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

fn parse_cspr_to_motes(label: &str, value: &str) -> Result<U512> {
    const MOTES_PER_CSPR: u64 = 1_000_000_000;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{label} cannot be empty");
    }
    let normalized = trimmed.replace('_', "");
    let (whole, frac) = match normalized.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (normalized.as_str(), ""),
    };
    if whole.is_empty() && frac.is_empty() {
        bail!("{label} is invalid");
    }
    let whole_motes = if whole.is_empty() {
        U512::zero()
    } else {
        U512::from_dec_str(whole)
            .map_err(|_| anyhow!("{label} has invalid digits"))?
            .checked_mul(U512::from(MOTES_PER_CSPR))
            .ok_or_else(|| anyhow!("{label} is too large"))?
    };
    if frac.len() > 9 {
        bail!("{label} supports up to 9 decimal places");
    }
    let mut frac_digits = frac.to_string();
    while frac_digits.len() < 9 {
        frac_digits.push('0');
    }
    let frac_motes = if frac_digits.is_empty() {
        U512::zero()
    } else {
        U512::from_dec_str(&frac_digits).map_err(|_| anyhow!("{label} has invalid digits"))?
    };
    whole_motes
        .checked_add(frac_motes)
        .ok_or_else(|| anyhow!("{label} is too large"))
}

fn u512_to_u64(value: U512) -> Result<u64> {
    u64::try_from(value).map_err(|_| anyhow!("payment amount exceeds u64 range"))
}

#[cfg(test)]
mod tests {
    use super::{parse_contract_hash, parse_cspr_to_motes, parse_transfer_target, u512_to_u64};
    use casper_types::bytesrepr::ToBytes;
    use casper_types::contracts::ContractHash;
    use casper_types::crypto::AsymmetricType;
    use casper_types::{
        AccessRights, AddressableEntityHash, PublicKey, TransferTarget, U512, URef,
        account::AccountHash,
    };

    #[test]
    fn parses_whole_cspr() {
        assert_eq!(
            parse_cspr_to_motes("amount", "5").expect("motes"),
            U512::from(5_000_000_000u64)
        );
    }

    #[test]
    fn parses_fractional_cspr() {
        assert_eq!(
            parse_cspr_to_motes("amount", "2.5").expect("motes"),
            U512::from(2_500_000_000u64)
        );
        assert_eq!(
            parse_cspr_to_motes("amount", ".5").expect("motes"),
            U512::from(500_000_000u64)
        );
        assert_eq!(
            parse_cspr_to_motes("amount", "0.000000001").expect("motes"),
            U512::from(1u64)
        );
    }

    #[test]
    fn parses_with_underscores() {
        assert_eq!(
            parse_cspr_to_motes("amount", "1_000.000_000_001").expect("motes"),
            U512::from(1_000_000_000_001u64)
        );
    }

    #[test]
    fn rejects_too_many_decimals() {
        let result = parse_cspr_to_motes("amount", "1.0000000001");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_digits() {
        let result = parse_cspr_to_motes("amount", "nope");
        assert!(result.is_err());
    }

    #[test]
    fn max_u64_motes_is_ok() {
        let max_cspr = "18446744073.709551615";
        assert_eq!(
            parse_cspr_to_motes("amount", max_cspr).expect("motes"),
            U512::from(u64::MAX)
        );
    }

    #[test]
    fn rejects_overflowing_values() {
        let over_decimal = "18446744073.709551616";
        let over_whole = "18446744074";
        let over_decimal = parse_cspr_to_motes("amount", over_decimal).expect("motes");
        let over_whole = parse_cspr_to_motes("amount", over_whole).expect("motes");
        assert_eq!(
            over_decimal,
            U512::from_dec_str("18446744073709551616").expect("u512"),
        );
        assert_eq!(
            over_whole,
            U512::from_dec_str("18446744074000000000").expect("u512"),
        );
        assert!(u512_to_u64(over_decimal).is_err());
        assert!(u512_to_u64(over_whole).is_err());
    }

    #[test]
    fn large_nctl_initial_values() {
        let cspr = "1000000000000000000000000000";
        let motes = parse_cspr_to_motes("amount", cspr).expect("motes");
        assert_eq!(
            motes,
            U512::from_dec_str("1000000000000000000000000000000000000").expect("u512")
        );
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

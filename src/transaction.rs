use anyhow::{Context, Result, anyhow, bail};
use casper_types::{PricingMode, Transaction, TransactionRuntimeParams, U512, bytesrepr::Bytes};
use clap::{Args, Subcommand};
use std::fs;
use std::path::PathBuf;
use tokio::runtime::Runtime;
use veles_casper_rust_sdk::TransactionV1Builder;
use veles_casper_rust_sdk::jsonrpc::CasperClient;

use crate::network;
use crate::storage::StorageConfig;
use crate::wallet;

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
    #[arg(long, default_value_t = 1)]
    gas_price_tolerance: u8,
    /// Wallet and account name in the form wallet:account.
    #[arg(long)]
    from: String,
    /// Mark the session as an install/upgrade transaction.
    #[arg(long)]
    install_upgrade: bool,
}

pub fn handle(storage: &StorageConfig, args: TxArgs) -> Result<()> {
    match args.command {
        TxCommand::Put(command) => put_session(storage, command),
    }
}

fn put_session(storage: &StorageConfig, args: PutArgs) -> Result<()> {
    let module_bytes =
        fs::read(&args.wasm).with_context(|| format!("failed to read {}", args.wasm.display()))?;
    let runtime = TransactionRuntimeParams::VmCasperV1;
    let payment_amount = u512_to_u64(parse_cspr_to_motes(&args.payment_amount)?)?;
    let pricing_mode = PricingMode::PaymentLimited {
        payment_amount,
        gas_price_tolerance: args.gas_price_tolerance,
        standard_payment: true,
    };
    let (wallet_name, account_name) = parse_wallet_account(&args.from)?;
    let secret_key = wallet::resolve_account_secret_key(storage, &wallet_name, &account_name)?;
    let chain_name = network::active_network_chain_name()?;
    let (network_name, rpc_endpoint) = network::active_network_rpc()?;

    let builder =
        TransactionV1Builder::new_session(args.install_upgrade, Bytes::from(module_bytes), runtime)
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
    println!("Transaction submitted to {network_name}: {tx_hash_bytes:x}");
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

fn parse_cspr_to_motes(value: &str) -> Result<U512> {
    const MOTES_PER_CSPR: u64 = 1_000_000_000;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("payment amount cannot be empty");
    }
    let normalized = trimmed.replace('_', "");
    let (whole, frac) = match normalized.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (normalized.as_str(), ""),
    };
    if whole.is_empty() && frac.is_empty() {
        bail!("payment amount is invalid");
    }
    let whole_motes = if whole.is_empty() {
        U512::zero()
    } else {
        U512::from_dec_str(whole)
            .map_err(|_| anyhow!("payment amount has invalid digits"))?
            .checked_mul(U512::from(MOTES_PER_CSPR))
            .ok_or_else(|| anyhow!("payment amount is too large"))?
    };
    if frac.len() > 9 {
        bail!("payment amount supports up to 9 decimal places");
    }
    let mut frac_digits = frac.to_string();
    while frac_digits.len() < 9 {
        frac_digits.push('0');
    }
    let frac_motes = if frac_digits.is_empty() {
        U512::zero()
    } else {
        U512::from_dec_str(&frac_digits)
            .map_err(|_| anyhow!("payment amount has invalid digits"))?
    };
    whole_motes
        .checked_add(frac_motes)
        .ok_or_else(|| anyhow!("payment amount is too large"))
}

fn u512_to_u64(value: U512) -> Result<u64> {
    u64::try_from(value).map_err(|_| anyhow!("payment amount exceeds u64 range"))
}

#[cfg(test)]
mod tests {
    use super::{parse_cspr_to_motes, u512_to_u64};
    use casper_types::U512;

    #[test]
    fn parses_whole_cspr() {
        assert_eq!(
            parse_cspr_to_motes("5").expect("motes"),
            U512::from(5_000_000_000u64)
        );
    }

    #[test]
    fn parses_fractional_cspr() {
        assert_eq!(
            parse_cspr_to_motes("2.5").expect("motes"),
            U512::from(2_500_000_000u64)
        );
        assert_eq!(
            parse_cspr_to_motes(".5").expect("motes"),
            U512::from(500_000_000u64)
        );
        assert_eq!(
            parse_cspr_to_motes("0.000000001").expect("motes"),
            U512::from(1u64)
        );
    }

    #[test]
    fn parses_with_underscores() {
        assert_eq!(
            parse_cspr_to_motes("1_000.000_000_001").expect("motes"),
            U512::from(1_000_000_000_001u64)
        );
    }

    #[test]
    fn rejects_too_many_decimals() {
        let result = parse_cspr_to_motes("1.0000000001");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_digits() {
        let result = parse_cspr_to_motes("nope");
        assert!(result.is_err());
    }

    #[test]
    fn max_u64_motes_is_ok() {
        let max_cspr = "18446744073.709551615";
        assert_eq!(
            parse_cspr_to_motes(max_cspr).expect("motes"),
            U512::from(u64::MAX)
        );
    }

    #[test]
    fn rejects_overflowing_values() {
        let over_decimal = "18446744073.709551616";
        let over_whole = "18446744074";
        let over_decimal = parse_cspr_to_motes(over_decimal).expect("motes");
        let over_whole = parse_cspr_to_motes(over_whole).expect("motes");
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
        let motes = parse_cspr_to_motes(cspr).expect("motes");
        assert_eq!(
            motes,
            U512::from_dec_str("1000000000000000000000000000000000000").expect("u512")
        );
    }
}

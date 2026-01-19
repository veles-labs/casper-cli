use anyhow::{Context, Result};
use casper_types::bytesrepr::Bytes;
use casper_types::{PricingMode, Transaction, TransactionRuntimeParams};
use clap::Args;
use std::fs;
use std::path::PathBuf;
use tokio::runtime::Runtime;
use veles_casper_rust_sdk::TransactionV1Builder;
use veles_casper_rust_sdk::jsonrpc::CasperClient;

use crate::network;
use crate::storage::StorageConfig;
use crate::utils;

use super::{
    DEFAULT_GAS_PRICE_TOLERANCE, parse_runtime_args, resolve_from_secret_key,
    simulate_transaction,
};

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

pub fn handle(
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

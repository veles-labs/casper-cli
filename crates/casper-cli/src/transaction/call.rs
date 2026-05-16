use anyhow::{Context, Result, bail};
use casper_types::{EntityVersion, PricingMode, Transaction, TransactionRuntimeParams};
use clap::Args;
use tokio::runtime::Runtime;
use veles_casper_rust_sdk::TransactionV1Builder;
use veles_casper_rust_sdk::jsonrpc::CasperClient;

use crate::network;
use crate::storage::StorageConfig;
use crate::utils;

use super::{
    DEFAULT_GAS_PRICE_TOLERANCE, account_hash_initiator_from_secret_key, looks_like_contract_hash,
    looks_like_package_hash, parse_contract_hash, parse_package_hash, parse_runtime_args,
    resolve_from_secret_key, simulate_transaction,
};

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

pub fn handle(
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
    let initiator_addr = account_hash_initiator_from_secret_key(&secret_key);
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
    .with_initiator_addr(initiator_addr)
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

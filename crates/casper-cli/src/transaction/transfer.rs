use anyhow::{Context, Result, anyhow, bail};
use casper_types::{PricingMode, Transaction, account::AccountHash};
use clap::Args;
use tokio::runtime::Runtime;
use veles_casper_rust_sdk::TransactionV1Builder;
use veles_casper_rust_sdk::jsonrpc::CasperClient;

use crate::network;
use crate::storage::StorageConfig;
use crate::utils;

use super::{
    DEFAULT_GAS_PRICE_TOLERANCE, ResolvedTransferTarget, evm_transfer_runtime_args,
    resolve_from_secret_key, resolve_transfer_target, simulate_transaction,
};

#[derive(Args)]
/// Arguments for transferring CSPR.
pub struct TransferArgs {
    /// Wallet/account reference (<wallet>:<account>) or legacy wallet name.
    #[arg(long)]
    from: String,
    /// Recipient wallet/account, legacy wallet name, 0x-prefixed EVM address, public key bytes hex, or account hash bytes hex.
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

pub fn handle(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    args: TransferArgs,
) -> Result<()> {
    let amount = utils::parse_cspr_to_motes("transfer amount", &args.amount)?;
    let target = resolve_transfer_target(storage, &args.to)?;
    if args.simulate && target.is_evm_address() {
        bail!("simulation is not supported for native transfers to EVM addresses");
    }
    let secret_key = resolve_from_secret_key(storage, &args.from)?;
    let chain_name = network::active_network_chain_name(context)?;
    let (network_name, rpc_endpoint) = network::active_network_rpc(context)?;

    let pricing_mode = PricingMode::PaymentLimited {
        payment_amount: 2_500_000_000u64, // This is a standard payment of 2.5 CSPR which is ignored by the host anyway.
        gas_price_tolerance: args.gas_price_tolerance,
        standard_payment: true,
    };
    let builder = match target {
        ResolvedTransferTarget::Native(target) => {
            TransactionV1Builder::new_transfer(amount, None, target, None)
                .map_err(|err| anyhow!(err.to_string()))?
        }
        ResolvedTransferTarget::EvmAddress(address) => {
            let runtime_args = evm_transfer_runtime_args(amount, address)?;
            TransactionV1Builder::new_transfer(amount, None, AccountHash::new([0u8; 32]), None)
                .map_err(|err| anyhow!(err.to_string()))?
                .with_runtime_args(runtime_args)
        }
    }
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

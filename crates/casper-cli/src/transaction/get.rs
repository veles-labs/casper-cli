use anyhow::{Context, Result, bail};
use clap::Args;
use tokio::runtime::Runtime;
use veles_casper_rust_sdk::jsonrpc::CasperClient;

use crate::network;
use crate::utils;

use super::parse_transaction_hash;

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

pub fn handle(context: &network::ConfigContext, args: GetArgs) -> Result<()> {
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

use anyhow::{Context, Result};
use clap::Args;
use tokio::runtime::Runtime;

use veles_casper_rust_sdk::jsonrpc::CasperClient;

use crate::network;
use crate::storage::StorageConfig;

#[derive(Args)]
/// Arguments for fetching an account balance.
pub struct BalanceArgs {
    /// Wallet/account reference (<wallet>:<account>), legacy wallet name, account hash hex, or public key hex.
    name: String,
}

pub fn handle(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    args: BalanceArgs,
) -> Result<()> {
    let name = args.name;
    let resolved = super::identifier::resolve(storage, &name)?;
    let account_identifier = resolved.identifier();
    let display_name = resolved.display_name(&name);
    let (network_name, rpc_endpoint) = network::active_network_rpc(context)?;

    let runtime = Runtime::new().context("failed to start async runtime")?;

    let result = runtime.block_on(async {
        let client = CasperClient::new(rpc_endpoint);
        client.get_balance(account_identifier).await
    })?;

    match result {
        Some(motes) => {
            let cspr = crate::utils::format_cspr(&motes);
            println!("Balance of {display_name} on {network_name}: {cspr} CSPR");
        }
        None => {
            println!("No account found on network {network_name}");
        }
    }

    Ok(())
}

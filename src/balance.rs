use anyhow::{Context, Result, bail};
use clap::Args;
use tokio::runtime::Runtime;

use casper_types::{PublicKey, bytesrepr::deserialize_from_slice};
use veles_casper_rust_sdk::jsonrpc::CasperClient;

use crate::network;
use crate::wallet;

const MOTES_PER_CSPR: u64 = 1_000_000_000;

#[derive(Args)]
/// Arguments for fetching an account balance.
pub struct BalanceArgs {
    /// Wallet/account reference (<wallet>:<account>) or public key hex.
    name: String,
}

pub fn handle(wallet_path_override: &Option<std::path::PathBuf>, args: BalanceArgs) -> Result<()> {
    let public_key_hex = resolve_public_key_hex(wallet_path_override, &args.name)?;
    let (network_name, rpc_endpoint) = network::active_network_rpc()?;

    let client = CasperClient::new(network_name, vec![rpc_endpoint])
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    let runtime = Runtime::new().context("failed to start async runtime")?;
    let balance = runtime
        .block_on(client.get_balance(&public_key_hex))
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    match balance {
        Some(motes) => {
            let cspr = format_cspr(motes);
            println!("Balance: {cspr} CSPR");
            println!("Motes: {motes}");
        }
        None => {
            println!("No account found for public key {public_key_hex}");
        }
    }

    Ok(())
}

fn resolve_public_key_hex(
    wallet_path_override: &Option<std::path::PathBuf>,
    input: &str,
) -> Result<String> {
    if let Some((wallet_name, account_name)) = input.split_once(':') {
        if wallet_name.is_empty() || account_name.is_empty() {
            bail!("wallet/account reference must be <wallet>:<account>");
        }
        return wallet::resolve_account_public_key(wallet_path_override, wallet_name, account_name);
    }
    parse_public_key_hex(input)
}

fn parse_public_key_hex(input: &str) -> Result<String> {
    let bytes = hex::decode(input).context("invalid public key hex")?;
    let public_key: PublicKey =
        deserialize_from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid public key bytes"))?;
    Ok(public_key.to_hex_string())
}

fn format_cspr(motes: u64) -> String {
    let whole = motes / MOTES_PER_CSPR;
    let fractional = motes % MOTES_PER_CSPR;
    format!("{whole}.{fractional:09}")
}

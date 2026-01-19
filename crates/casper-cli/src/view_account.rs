use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use comfy_table::{Cell, Table};
use tokio::runtime::Runtime;

use casper_types::{PublicKey, account::AccountHash, bytesrepr::deserialize_from_slice};
use veles_casper_rust_sdk::jsonrpc::{AccountIdentifier, CasperClient};

use crate::network;
use crate::storage::StorageConfig;
use crate::wallet;

const ACCOUNT_HASH_LEN: usize = 32;

#[derive(Args)]
/// Arguments for viewing account details.
pub struct ViewAccountArgs {
    /// Wallet/account reference (<wallet>:<account>), legacy wallet name, account hash hex, or public key hex.
    name: String,
}

pub fn handle(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    args: ViewAccountArgs,
) -> Result<()> {
    let name = args.name;
    let account_identifier = resolve_account_identifier(storage, &name)?;
    let (network_name, rpc_endpoint) = network::active_network_rpc(context)?;

    let runtime = Runtime::new().context("failed to start async runtime")?;
    let result = runtime.block_on(async {
        let client = CasperClient::new(rpc_endpoint);
        client.get_account(account_identifier).await
    })?;

    match result {
        Some(account_result) => {
            let account = account_result.account;
            println!("Account details on network {network_name}:");
            println!("Account hash: {}", account.account_hash());
            println!("Main purse: {}", account.main_purse().to_formatted_string());
            let mut assoc_table = Table::new();
            assoc_table.set_header(vec!["Associated Key", "Weight"]);
            for (hash, weight) in account.associated_keys().iter() {
                assoc_table.add_row(vec![Cell::new(hash), Cell::new(weight.value())]);
            }
            println!("Associated keys:");
            println!("{assoc_table}");
            let named_keys = account.named_keys().clone().into_inner();
            if named_keys.is_empty() {
                println!("Named keys: (none)");
            } else {
                let mut table = Table::new();
                table.set_header(vec!["Name", "Key"]);
                for (name, key) in named_keys {
                    table.add_row(vec![Cell::new(name), Cell::new(key.to_formatted_string())]);
                }
                println!("Named keys:");
                println!("{table}");
            }
        }
        None => {
            println!("No account found on network {network_name}");
        }
    }

    Ok(())
}

fn resolve_account_identifier(storage: &StorageConfig, input: &str) -> Result<AccountIdentifier> {
    if let Some((wallet_name, account_name)) = input.split_once(':') {
        if wallet_name.is_empty() || account_name.is_empty() {
            bail!("wallet/account reference must be <wallet>:<account>");
        }
        let public_key_hex =
            wallet::resolve_account_public_key(storage, wallet_name, account_name)?;
        return parse_account_identifier(&public_key_hex);
    }
    if let Some(public_key_hex) = wallet::try_resolve_legacy_public_key(storage, input)? {
        return parse_account_identifier(&public_key_hex);
    }
    parse_account_identifier(input)
}

fn parse_account_identifier(input: &str) -> Result<AccountIdentifier> {
    let bytes = hex::decode(input).context("invalid public key hex")?;
    if bytes.len() == ACCOUNT_HASH_LEN {
        let mut hash = [0u8; ACCOUNT_HASH_LEN];
        hash.copy_from_slice(&bytes);
        return Ok(AccountIdentifier::AccountHash(AccountHash::new(hash)));
    }
    let public_key: PublicKey =
        deserialize_from_slice(&bytes).map_err(|_| anyhow!("invalid public key bytes"))?;
    Ok(AccountIdentifier::PublicKey(public_key))
}

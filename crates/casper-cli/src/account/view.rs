use anyhow::{Context, Result, anyhow};
use clap::Args;
use comfy_table::{Cell, Table};
use tokio::runtime::Runtime;

use casper_types::{
    PublicKey,
    bytesrepr::ToBytes,
};
use veles_casper_rust_sdk::jsonrpc::CasperClient;

use crate::network;
use crate::storage::StorageConfig;

#[derive(Args)]
/// Arguments for viewing account details.
pub struct ViewArgs {
    /// Wallet/account reference (<wallet>:<account>), legacy wallet name, account hash hex, or public key hex.
    name: String,
}

pub fn handle(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    args: ViewArgs,
) -> Result<()> {
    let name = args.name;
    let resolved = super::identifier::resolve(storage, &name)?;
    let account_identifier = resolved.identifier();
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
            match resolved.public_key() {
                Some(public_key) => {
                    let key_kind = public_key_kind_label(public_key);
                    let key_hex = public_key_hex(public_key)?;
                    println!("Public key ({key_kind}): {key_hex}");
                }
                None => {
                    println!("Public key: (unavailable; account hash input)");
                }
            }
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

fn public_key_kind_label(public_key: &PublicKey) -> &'static str {
    match public_key {
        PublicKey::Ed25519(_) => "ed25519",
        PublicKey::Secp256k1(_) => "secp256k1",
        PublicKey::System => "system",
        _ => "unknown",
    }
}

fn public_key_hex(public_key: &PublicKey) -> Result<String> {
    let public_key_bytes = public_key
        .to_bytes()
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(hex::encode(public_key_bytes))
}

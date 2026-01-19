use anyhow::{Context, Result};
use casper_types::U512;
use clap::Args;
use comfy_table::{Cell, Table};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::runtime::Runtime;
use veles_casper_rust_sdk::jsonrpc::{AccountIdentifier, CasperClient};

use crate::network;
use crate::storage::StorageConfig;
use crate::utils;

use super::{DerivationScheme, WalletType, legacy_key_kind_from_public_key_hex};

#[derive(Args)]
/// Arguments for showing wallet info.
pub struct InfoArgs {
    /// Name of the wallet.
    name: String,
}

pub fn handle(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    args: InfoArgs,
) -> Result<()> {
    let storage = super::wallet_storage(storage, &args.name)?;
    super::ensure_wallet_exists(&storage, &args.name)?;
    let metadata = super::load_metadata(&storage.metadata_path)?;

    match &metadata.wallet_type {
        WalletType::Bip39 => {
            println!("Wallet type: bip39");
            println!("Compatibility: Ledger, Casper Wallet");
        }
        WalletType::Seeded => {
            println!("Wallet type: seeded");
            println!("Domain: {}", metadata.domain);
            println!("Compatibility: explicit only");
        }
        WalletType::LegacyPem { public_key } => {
            let key_kind = legacy_key_kind_from_public_key_hex(public_key)?;
            let account_hash = account_hash_from_public_key_hex(public_key)?;
            println!("Origin: legacy secret key PEM");
            println!("Key type: {}", key_kind);
            println!("Account hash: {}", account_hash);
            return Ok(());
        }
    }
    match metadata.derivation {
        DerivationScheme::Bip32Secp256k1 => {
            println!("Derivation: bip32 (secp256k1)");
        }
        DerivationScheme::Slip10Ed25519 => {
            println!("Derivation: slip0010 (ed25519)");
        }
    }
    println!("Encrypted: {}", metadata.encrypted);
    println!("Known accounts: {}", metadata.accounts.len());
    if !metadata.accounts.is_empty() {
        let (_network_name, rpc_endpoint) = network::active_network_rpc(context)?;
        let mut account_identifiers = Vec::with_capacity(metadata.accounts.len());
        let mut account_hashes = Vec::with_capacity(metadata.accounts.len());
        for account in &metadata.accounts {
            let (identifier, account_hash) = account_identifier_and_hash(&account.public_key)
                .with_context(|| format!("invalid public key for account '{}'", account.name))?;
            account_identifiers.push(identifier);
            account_hashes.push(account_hash);
        }
        let progress = balance_progress_bar(account_identifiers.len() as u64)?;
        let runtime = Runtime::new().context("failed to start async runtime")?;
        let balances = runtime.block_on(async move {
            let client = CasperClient::new(rpc_endpoint);
            fetch_wallet_balances(&client, account_identifiers, &progress).await
        })?;
        let mut table = Table::new();
        table.set_header(vec!["Name", "Path", "Account Hash", "Balance"]);
        for ((account, balance), account_hash) in metadata
            .accounts
            .iter()
            .zip(balances.iter())
            .zip(account_hashes.iter())
        {
            let balance_label = match balance {
                Some(motes) => format!("{} CSPR", utils::format_cspr(motes)),
                None => "0 CSPR".to_string(),
            };
            table.add_row(vec![
                Cell::new(&account.name),
                Cell::new(&account.path),
                Cell::new(account_hash),
                Cell::new(balance_label),
            ]);
        }
        println!("{table}");
    }

    Ok(())
}

fn balance_progress_bar(total: u64) -> Result<ProgressBar> {
    if total == 0 {
        return Ok(ProgressBar::hidden());
    }
    let bar = ProgressBar::new(total);
    let style = ProgressStyle::with_template("{msg} [{bar:40}] {pos}/{len}")
        .context("failed to set progress bar style")?
        .progress_chars("=>-");
    bar.set_style(style);
    bar.set_message("Querying balances");
    Ok(bar)
}

async fn fetch_wallet_balances(
    client: &CasperClient,
    account_identifiers: Vec<AccountIdentifier>,
    progress: &ProgressBar,
) -> Result<Vec<Option<U512>>> {
    let mut balances = Vec::with_capacity(account_identifiers.len());
    for account_identifier in account_identifiers {
        let balance = client.get_balance(account_identifier).await?;
        progress.inc(1);
        balances.push(balance);
    }
    progress.finish_and_clear();
    Ok(balances)
}

fn account_identifier_and_hash(input: &str) -> Result<(AccountIdentifier, String)> {
    let public_key = super::public_key_from_hex(input)?;
    let account_hash = format!("{}", public_key.to_account_hash());
    Ok((AccountIdentifier::PublicKey(public_key), account_hash))
}

fn account_hash_from_public_key_hex(input: &str) -> Result<String> {
    let public_key = super::public_key_from_hex(input)?;
    Ok(format!("{}", public_key.to_account_hash()))
}

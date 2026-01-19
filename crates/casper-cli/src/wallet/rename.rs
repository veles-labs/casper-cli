use anyhow::{Result, bail};
use clap::Args;

use crate::storage::StorageConfig;

use super::{WalletType, load_metadata, save_metadata, wallet_storage, ensure_wallet_exists};

#[derive(Args)]
/// Arguments for renaming an account.
pub struct RenameArgs {
    /// Name of the wallet.
    pub(super) wallet_name: String,
    /// Existing account name.
    pub(super) old_name: String,
    /// New account name.
    pub(super) new_name: String,
}

pub fn handle(storage: &StorageConfig, args: RenameArgs) -> Result<()> {
    let storage = wallet_storage(storage, &args.wallet_name)?;
    ensure_wallet_exists(&storage, &args.wallet_name)?;
    let mut metadata = load_metadata(&storage.metadata_path)?;
    if matches!(&metadata.wallet_type, WalletType::LegacyPem { .. }) {
        bail!("legacy secret key wallets do not contain accounts");
    }

    if args.new_name.is_empty() {
        bail!("new account name cannot be empty");
    }
    if args.new_name.starts_with('-') {
        bail!("account name cannot start with '-'");
    }
    if args.old_name == args.new_name {
        bail!("new account name matches the existing name");
    }
    if metadata
        .accounts
        .iter()
        .any(|account| account.name == args.new_name)
    {
        bail!("account name '{}' already exists", args.new_name);
    }

    let mut renamed = false;
    for account in &mut metadata.accounts {
        if account.name == args.old_name {
            account.name = args.new_name.clone();
            renamed = true;
            break;
        }
    }

    if !renamed {
        bail!("account '{}' not found", args.old_name);
    }

    save_metadata(&storage.metadata_path, &metadata)?;
    println!("Renamed account '{}' to '{}'", args.old_name, args.new_name);
    Ok(())
}

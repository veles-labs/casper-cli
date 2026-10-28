use anyhow::{Result, anyhow, ensure};
use clap::Args;

use crate::{
    secure_storage::{
        StorageBackendKind, StoreMode, atomic_file::PendingWrite, file::FileSecureStorage,
    },
    storage::StorageConfig,
};

use super::{ensure_wallet_exists, load_metadata, wallet_storage};

#[derive(Args)]
/// Arguments for updating a wallet's password protection.
pub struct PasswordArgs {
    /// Name of the wallet to update.
    name: String,
    /// Remove password protection and store the secret in plaintext (unsafe).
    #[arg(long)]
    unencrypted: bool,
}

pub fn handle(storage: &StorageConfig, args: PasswordArgs) -> Result<()> {
    let file_storage = storage.file_secret_storage()?;
    update(storage, args, &file_storage)
}

fn update(
    storage: &StorageConfig,
    args: PasswordArgs,
    file_storage: &FileSecureStorage,
) -> Result<()> {
    let wallet = wallet_storage(storage, &args.name)?;
    ensure_wallet_exists(&wallet, &args.name)?;
    let mut metadata = load_metadata(&wallet.metadata_path)?;
    ensure!(
        metadata.storage == StorageBackendKind::File,
        "wallet metadata does not describe a file-backed wallet"
    );
    metadata.encrypted = !args.unencrypted;
    let pending_metadata = PendingWrite::new(
        &wallet.metadata_path,
        &serde_json::to_vec_pretty(&metadata)?,
    )
    .map_err(|error| anyhow!("prepare wallet metadata update: {error}"))?;
    let mode = if args.unencrypted {
        StoreMode::Unencrypted
    } else {
        StoreMode::Encrypted
    };
    file_storage
        .change_password(&args.name, mode, || pending_metadata.persist())
        .map_err(|error| anyhow!(error.to_string()))?;
    if args.unencrypted {
        println!("Password protection removed from wallet '{}'.", args.name);
    } else {
        println!("Password protection updated for wallet '{}'.", args.name);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

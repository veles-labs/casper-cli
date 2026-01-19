use anyhow::{Result, anyhow, bail};
use clap::Args;
use std::fs;

use crate::storage::StorageConfig;

use super::wallet_storage;

#[derive(Args)]
/// Arguments for deleting a wallet.
pub struct DeleteArgs {
    /// Name of the wallet.
    name: String,
}

pub fn handle(storage: &StorageConfig, args: DeleteArgs) -> Result<()> {
    let storage = wallet_storage(storage, &args.name)?;
    let metadata_exists = storage.metadata_path.exists();
    let secret_exists = storage
        .storage
        .exists(&args.name)
        .map_err(|err| anyhow!(err.to_string()))?;
    if !metadata_exists && !secret_exists {
        bail!("wallet '{}' does not exist; create it first", args.name);
    }

    storage
        .storage
        .delete(&args.name)
        .map_err(|err| anyhow!(err.to_string()))?;
    match fs::remove_file(&storage.metadata_path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    println!("Deleted wallet '{}'", args.name);
    Ok(())
}

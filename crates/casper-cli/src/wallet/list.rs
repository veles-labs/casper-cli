use anyhow::{Result, anyhow};
use comfy_table::{Cell, Table};

use crate::storage::StorageConfig;

use super::{load_metadata, wallets_dir};

pub fn handle(storage: &StorageConfig) -> Result<()> {
    let metadata_dir = wallets_dir(storage)?;
    let secret_storage = storage.secret_storage()?;
    let mut names = secret_storage
        .list()
        .map_err(|err| anyhow!(err.to_string()))?;

    if names.is_empty() {
        println!("No wallets found.");
        return Ok(());
    }

    names.sort();

    let mut table = Table::new();
    table.set_header(vec!["Name", "Encrypted", "Accounts"]);
    for name in names {
        let metadata_path = metadata_dir.join(format!("{name}.json"));
        if metadata_path.exists() {
            let metadata = load_metadata(&metadata_path)?;
            table.add_row(vec![
                Cell::new(metadata.name),
                Cell::new(metadata.encrypted),
                Cell::new(metadata.accounts.len()),
            ]);
        } else {
            table.add_row(vec![
                Cell::new(name),
                Cell::new("unknown"),
                Cell::new("unknown"),
            ]);
        }
    }
    println!("{table}");

    Ok(())
}

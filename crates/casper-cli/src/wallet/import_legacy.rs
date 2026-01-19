use anyhow::{Result, anyhow};
use clap::Args;
use std::path::PathBuf;

use crate::secure_storage::{RootSecret, StoreMode};
use crate::storage::StorageConfig;

use super::{
    DerivationScheme, WalletMetadata, ensure_unencrypted_allowed, ensure_wallet_absent,
    read_legacy_pem, wallet_storage, wallet_type_from_secret,
};

#[derive(Args)]
/// Arguments for importing a legacy secret key PEM.
pub struct ImportLegacyArgs {
    /// Name for the wallet.
    name: String,
    /// Path to the legacy secret key PEM (defaults to stdin).
    #[arg(long, value_name = "PATH")]
    pem_file: Option<PathBuf>,
    /// Store wallet secrets unencrypted (unsafe).
    #[arg(long)]
    unencrypted: bool,
}

pub fn handle(storage: &StorageConfig, args: ImportLegacyArgs) -> Result<()> {
    let wallet_storage = wallet_storage(storage, &args.name)?;
    ensure_unencrypted_allowed(wallet_storage.storage.as_ref(), args.unencrypted)?;
    ensure_wallet_absent(&wallet_storage, &args.name)?;

    let pem = read_legacy_pem(args.pem_file.as_ref())?;

    let uses_master_password = wallet_storage.storage.uses_master_password();
    let store_mode = if args.unencrypted {
        StoreMode::Unencrypted
    } else {
        StoreMode::Encrypted
    };
    let root_secret = RootSecret::LegacyPem { pem };
    let (wallet_type, domain) = wallet_type_from_secret(&root_secret)?;
    let encrypted = if uses_master_password {
        !args.unencrypted
    } else {
        true
    };
    let derivation = DerivationScheme::Bip32Secp256k1;
    let metadata = WalletMetadata {
        version: 1,
        name: args.name.clone(),
        storage: wallet_storage.storage.backend_kind(),
        encrypted,
        wallet_type,
        derivation,
        domain,
        accounts: Vec::new(),
    };

    wallet_storage
        .storage
        .store(&args.name, &root_secret, store_mode)
        .map_err(|err| anyhow!(err.to_string()))?;
    super::save_metadata(&wallet_storage.metadata_path, &metadata)?;
    println!("Wallet saved to {}", wallet_storage.metadata_path.display());
    Ok(())
}

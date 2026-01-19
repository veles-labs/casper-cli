use anyhow::{Result, anyhow};
use bip39::{Language, Mnemonic};
use clap::Args;

use crate::secure_storage::{RootSecret, StoreMode};
use crate::storage::StorageConfig;

use super::{
    WalletMetadata, derivation_from_flags, ensure_unencrypted_allowed, ensure_wallet_absent,
    prompt_mnemonic, prompt_passphrase, wallet_storage, wallet_type_from_secret,
};

#[derive(Args)]
/// Arguments for recovering a wallet from a mnemonic.
pub struct RecoverArgs {
    /// Name for the wallet.
    name: String,
    /// Use BIP-32 secp256k1 derivation (default).
    #[arg(long, conflicts_with = "slip10")]
    bip32: bool,
    /// Use SLIP-0010 ed25519 derivation.
    #[arg(long, conflicts_with = "bip32")]
    slip10: bool,
    /// Store wallet secrets unencrypted (unsafe).
    #[arg(long)]
    unencrypted: bool,
}

pub fn handle(storage: &StorageConfig, args: RecoverArgs) -> Result<()> {
    let wallet_storage = wallet_storage(storage, &args.name)?;
    ensure_unencrypted_allowed(wallet_storage.storage.as_ref(), args.unencrypted)?;
    ensure_wallet_absent(&wallet_storage, &args.name)?;

    let mnemonic_input = prompt_mnemonic()?;
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_input)
        .map_err(|err| anyhow!("invalid mnemonic: {err}"))?;
    let passphrase = prompt_passphrase("Enter optional BIP-39 passphrase: ")?;

    let uses_master_password = wallet_storage.storage.uses_master_password();
    let store_mode = if args.unencrypted {
        StoreMode::Unencrypted
    } else {
        StoreMode::Encrypted
    };
    let derivation = derivation_from_flags(args.bip32, args.slip10)?;

    let root_secret = RootSecret::Bip39 {
        mnemonic: mnemonic.to_string(),
        passphrase,
    };

    let (wallet_type, domain) = wallet_type_from_secret(&root_secret)?;
    let encrypted = if uses_master_password {
        !args.unencrypted
    } else {
        true
    };
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

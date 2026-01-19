use anyhow::{Context, Result, anyhow, bail};
use bip39::{Language, Mnemonic};
use clap::Args;
use rand_core::OsRng;

use crate::secure_storage::{RootSecret, StoreMode};
use crate::storage::StorageConfig;

use super::{
    WalletMetadata, derivation_from_flags, ensure_unencrypted_allowed, ensure_wallet_absent,
    parse_word_count, prompt_passphrase, wallet_storage, wallet_type_from_secret,
    warn_seeded_wallet,
};

#[derive(Args)]
/// Arguments for creating a wallet.
pub struct CreateArgs {
    /// Name for the wallet.
    name: String,
    /// Use BIP-39 (default).
    #[arg(long)]
    bip39: bool,
    /// Use BIP-32 secp256k1 derivation (default).
    #[arg(long, conflicts_with = "slip10")]
    bip32: bool,
    /// Use SLIP-0010 ed25519 derivation.
    #[arg(long, conflicts_with = "bip32")]
    slip10: bool,
    /// BIP-39 word count (12, 15, 18, 21, or 24). Defaults to 24.
    #[arg(long, value_parser = parse_word_count)]
    words: Option<u16>,
    /// Deterministic seed input (requires --domain).
    #[arg(long)]
    seed: Option<String>,
    /// Deterministic derivation domain (requires --seed).
    #[arg(long)]
    domain: Option<String>,
    /// Store wallet secrets unencrypted (unsafe).
    #[arg(long)]
    unencrypted: bool,
}

pub fn handle(storage: &StorageConfig, args: CreateArgs) -> Result<()> {
    let wallet_storage = wallet_storage(storage, &args.name)?;
    ensure_unencrypted_allowed(wallet_storage.storage.as_ref(), args.unencrypted)?;
    ensure_wallet_absent(&wallet_storage, &args.name)?;
    let uses_master_password = wallet_storage.storage.uses_master_password();
    let store_mode = if args.unencrypted {
        StoreMode::Unencrypted
    } else {
        StoreMode::Encrypted
    };

    let using_seed = args.seed.is_some() || args.domain.is_some();
    if args.bip39 && using_seed {
        bail!("--bip39 is mutually exclusive with --seed/--domain");
    }
    if using_seed && args.words.is_some() {
        bail!("--words is only valid with BIP-39 mnemonics");
    }
    let derivation = derivation_from_flags(args.bip32, args.slip10)?;

    let root_secret = if using_seed {
        let seed = args.seed.context("--seed is required with --domain")?;
        let domain = args.domain.context("--domain is required with --seed")?;
        warn_seeded_wallet(&domain);
        RootSecret::Seeded { seed, domain }
    } else {
        let word_count = args.words.unwrap_or(24) as usize;
        let mnemonic = Mnemonic::generate_in_with(&mut OsRng, Language::English, word_count)
            .map_err(|err| anyhow!("failed to generate mnemonic: {err}"))?;
        let passphrase = prompt_passphrase("Enter optional BIP-39 passphrase: ")?;

        if passphrase.is_empty() {
            println!("Passphrase: (none)");
        } else {
            println!("Passphrase: (set; stored in secure storage)");
        }

        println!("Mnemonic: {}", mnemonic);
        RootSecret::Bip39 {
            mnemonic: mnemonic.to_string(),
            passphrase,
        }
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

use crate::secure_storage::keyring;
use crate::secure_storage::{RootSecret, SecureStorage, StorageBackendKind, StoreMode};
use crate::storage::StorageConfig;
use anyhow::{Context, Result, anyhow, bail};
use bip32::{DerivationPath, Language, Mnemonic, XPrv};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use clap::{Args, Subcommand};
use comfy_table::{Cell, Table};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const WALLET_DIR_NAME: &str = "wallets";
const DEFAULT_PATH_PREFIX: &str = "m/44'/506'/0'/0";

#[derive(Args)]
/// Wallet-related CLI entry point.
pub struct WalletArgs {
    #[command(subcommand)]
    command: WalletCommand,
}

#[derive(Subcommand)]
/// Wallet subcommands.
pub enum WalletCommand {
    /// Create a new wallet.
    Create(CreateArgs),
    /// Recover a wallet from a mnemonic.
    Recover(RecoverArgs),
    /// List wallets in the configured storage directory.
    List,
    /// Show wallet metadata and known accounts.
    Info(InfoArgs),
    /// Derive one or more accounts from the wallet root.
    Derive(DeriveArgs),
    /// Add the next derived account to a wallet.
    Add(AddArgs),
    /// Rename an account inside a wallet.
    #[command(name = "rename-account")]
    RenameAccount(RenameArgs),
    /// Delete a wallet's metadata and secret.
    Delete(DeleteArgs),
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Args)]
/// Arguments for creating a wallet.
pub struct CreateArgs {
    /// Name for the wallet.
    name: String,
    /// Use BIP-39 (default).
    #[arg(long)]
    bip39: bool,
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

#[derive(Args)]
/// Arguments for recovering a wallet from a mnemonic.
pub struct RecoverArgs {
    /// Name for the wallet.
    name: String,
    /// Store wallet secrets unencrypted (unsafe).
    #[arg(long)]
    unencrypted: bool,
}

#[derive(Args)]
/// Arguments for showing wallet info.
pub struct InfoArgs {
    /// Name of the wallet.
    name: String,
}

#[derive(Args)]
/// Arguments for deleting a wallet.
pub struct DeleteArgs {
    /// Name of the wallet.
    name: String,
}

#[derive(Args)]
/// Arguments for deriving accounts.
pub struct DeriveArgs {
    /// Name of the wallet.
    name: String,
    /// Number of accounts to derive.
    #[arg(long, default_value_t = 1)]
    count: u32,
    /// Starting index for derivation.
    #[arg(long, default_value_t = 0)]
    start: u32,
    /// Print private keys (dangerous).
    #[arg(long, alias = "private")]
    show_private: bool,
}

#[derive(Args)]
/// Arguments for adding the next derived account.
pub struct AddArgs {
    /// Name of the wallet.
    wallet_name: String,
    /// Name for the account.
    account_name: Option<String>,
}

#[derive(Args)]
/// Arguments for renaming an account.
pub struct RenameArgs {
    /// Name of the wallet.
    wallet_name: String,
    /// Existing account name.
    old_name: String,
    /// New account name.
    new_name: String,
}

#[derive(Serialize, Deserialize)]
struct WalletMetadata {
    version: u8,
    name: String,
    storage: StorageBackendKind,
    encrypted: bool,
    wallet_type: WalletType,
    domain: String,
    accounts: Vec<DerivedAccount>,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum WalletType {
    Bip39,
    Seeded,
}

#[derive(Serialize, Deserialize, Clone)]
struct DerivedAccount {
    name: String,
    index: u32,
    path: String,
    public_key: String,
}

pub fn handle(storage: &StorageConfig, args: WalletArgs) -> Result<()> {
    match args.command {
        WalletCommand::Create(command) => create_wallet(storage, command),
        WalletCommand::Recover(command) => recover_wallet(storage, command),
        WalletCommand::List => wallet_list(storage),
        WalletCommand::Info(command) => wallet_info(storage, command),
        WalletCommand::Derive(command) => wallet_derive(storage, command),
        WalletCommand::Add(command) => wallet_add(storage, command),
        WalletCommand::RenameAccount(command) => wallet_rename(storage, command),
        WalletCommand::Delete(command) => wallet_delete(storage, command),
        WalletCommand::External(command) => wallet_external(storage, command),
    }
}

pub fn resolve_account_public_key(
    storage: &StorageConfig,
    wallet_name: &str,
    account_name: &str,
) -> Result<String> {
    let storage = wallet_storage(storage, wallet_name)?;
    if !storage.metadata_path.exists() {
        bail!("wallet '{}' does not exist; create it first", wallet_name);
    }
    let metadata = load_metadata(&storage.metadata_path)?;
    for account in &metadata.accounts {
        if account.name == account_name {
            return Ok(account.public_key.clone());
        }
    }
    bail!(
        "account '{}' not found in wallet '{}'",
        account_name,
        wallet_name
    );
}

fn create_wallet(storage: &StorageConfig, args: CreateArgs) -> Result<()> {
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

    let root_secret = if using_seed {
        let seed = args.seed.context("--seed is required with --domain")?;
        let domain = args.domain.context("--domain is required with --seed")?;
        warn_seeded_wallet(&domain);
        RootSecret::Seeded { seed, domain }
    } else {
        let mnemonic = Mnemonic::random(OsRng, Language::English);
        let passphrase = prompt_passphrase("Enter optional BIP-39 passphrase: ")?;

        if passphrase.is_empty() {
            println!("Passphrase: (none)");
        } else {
            println!("Passphrase: (set; stored in secure storage)");
        }

        println!("Mnemonic: {}", mnemonic.phrase());
        RootSecret::Bip39 {
            mnemonic: mnemonic.phrase().to_string(),
            passphrase,
        }
    };

    let (wallet_type, domain) = wallet_type_from_secret(&root_secret);
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
        domain,
        accounts: Vec::new(),
    };
    wallet_storage
        .storage
        .store(&args.name, &root_secret, store_mode)
        .map_err(|err| anyhow!(err.to_string()))?;
    save_metadata(&wallet_storage.metadata_path, &metadata)?;
    println!("Wallet saved to {}", wallet_storage.metadata_path.display());
    Ok(())
}

fn recover_wallet(storage: &StorageConfig, args: RecoverArgs) -> Result<()> {
    let wallet_storage = wallet_storage(storage, &args.name)?;
    ensure_unencrypted_allowed(wallet_storage.storage.as_ref(), args.unencrypted)?;
    ensure_wallet_absent(&wallet_storage, &args.name)?;

    let mnemonic_input = prompt_mnemonic()?;
    let mnemonic = Mnemonic::new(mnemonic_input, Language::English)
        .map_err(|_| anyhow!("invalid mnemonic"))?;
    let passphrase = prompt_passphrase("Enter optional BIP-39 passphrase: ")?;

    let uses_master_password = wallet_storage.storage.uses_master_password();
    let store_mode = if args.unencrypted {
        StoreMode::Unencrypted
    } else {
        StoreMode::Encrypted
    };

    let root_secret = RootSecret::Bip39 {
        mnemonic: mnemonic.phrase().to_string(),
        passphrase,
    };

    let (wallet_type, domain) = wallet_type_from_secret(&root_secret);
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
        domain,
        accounts: Vec::new(),
    };

    wallet_storage
        .storage
        .store(&args.name, &root_secret, store_mode)
        .map_err(|err| anyhow!(err.to_string()))?;
    save_metadata(&wallet_storage.metadata_path, &metadata)?;
    println!("Wallet saved to {}", wallet_storage.metadata_path.display());
    Ok(())
}

fn wallet_list(storage: &StorageConfig) -> Result<()> {
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

fn wallet_info(storage: &StorageConfig, args: InfoArgs) -> Result<()> {
    let storage = wallet_storage(storage, &args.name)?;
    ensure_wallet_exists(&storage, &args.name)?;
    let mut metadata = load_metadata(&storage.metadata_path)?;

    match metadata.wallet_type {
        WalletType::Bip39 => {
            println!("Wallet type: bip39");
            println!("Compatibility: Ledger, Casper Wallet");
        }
        WalletType::Seeded => {
            println!("Wallet type: seeded");
            println!("Domain: {}", metadata.domain);
            println!("Compatibility: explicit only");
        }
    }
    println!("Encrypted: {}", metadata.encrypted);
    println!("Known accounts: {}", metadata.accounts.len());
    if !metadata.accounts.is_empty() {
        let mut table = Table::new();
        table.set_header(vec!["Name", "Path", "Public Key"]);
        for account in &mut metadata.accounts {
            table.add_row(vec![
                Cell::new(&account.name),
                Cell::new(&account.path),
                Cell::new(&account.public_key),
            ]);
        }
        println!("{table}");
    }

    Ok(())
}

fn wallet_derive(storage: &StorageConfig, args: DeriveArgs) -> Result<()> {
    let wallet_storage = wallet_storage(storage, &args.name)?;
    ensure_wallet_exists(&wallet_storage, &args.name)?;
    let mut metadata = load_metadata(&wallet_storage.metadata_path)?;
    let root_secret = wallet_storage
        .storage
        .load(&args.name)
        .map_err(|err| anyhow!(err.to_string()))?;
    let seed = root_seed(&root_secret)?;

    let mut updated = false;
    let end = args.start.saturating_add(args.count);
    let mut table = Table::new();
    table.set_header(vec!["Name", "Path", "Public Key"]);
    for index in args.start..end {
        let path = format!("{}/{}", DEFAULT_PATH_PREFIX, index);
        let derivation_path = path.parse::<DerivationPath>()?;
        let xprv = XPrv::derive_from_path(&seed, &derivation_path)?;
        let public_key_bytes = xprv.public_key().to_bytes();

        let public_key = {
            let mut casper_public_key = public_key_bytes.to_vec();
            casper_public_key.insert(0, 0x02); // 1 indicates secp256k1 key
            casper_public_key
        };

        let public_key_hex = hex::encode(&public_key);
        let name = default_account_name(index);
        table.add_row(vec![
            Cell::new(&name),
            Cell::new(&path),
            Cell::new(&public_key_hex),
        ]);

        if args.show_private {
            println!("Private key: {}", hex::encode(xprv.to_bytes()));
        }

        if add_account(&mut metadata, &name, index, &path, &public_key_hex) {
            updated = true;
        }
    }

    if updated {
        save_metadata(&wallet_storage.metadata_path, &metadata)?;
    }

    if args.count > 0 {
        println!("{table}");
    }

    Ok(())
}

fn wallet_add(storage: &StorageConfig, args: AddArgs) -> Result<()> {
    let wallet_storage = wallet_storage(storage, &args.wallet_name)?;
    ensure_wallet_exists(&wallet_storage, &args.wallet_name)?;
    let mut metadata = load_metadata(&wallet_storage.metadata_path)?;
    let root_secret = wallet_storage
        .storage
        .load(&args.wallet_name)
        .map_err(|err| anyhow!(err.to_string()))?;

    let next_index = metadata
        .accounts
        .iter()
        .map(|account| account.index)
        .max()
        .map(|index| index.saturating_add(1))
        .unwrap_or(0);

    let account_name = args
        .account_name
        .unwrap_or_else(|| default_account_name(next_index));
    if account_name.is_empty() {
        bail!("account name cannot be empty");
    }
    if account_name.starts_with('-') {
        bail!("account name cannot start with '-'");
    }
    if metadata
        .accounts
        .iter()
        .any(|account| account.name == account_name)
    {
        bail!("account name '{}' already exists", account_name);
    }

    let seed = root_seed(&root_secret)?;
    let (path, public_key_hex) = derive_account(&seed, next_index)?;

    add_account(
        &mut metadata,
        &account_name,
        next_index,
        &path,
        &public_key_hex,
    );
    save_metadata(&wallet_storage.metadata_path, &metadata)?;

    let mut table = Table::new();
    table.set_header(vec!["Name", "Path", "Public Key"]);
    table.add_row(vec![
        Cell::new(&account_name),
        Cell::new(path),
        Cell::new(public_key_hex),
    ]);
    println!("{table}");

    Ok(())
}

fn wallet_rename(storage: &StorageConfig, args: RenameArgs) -> Result<()> {
    let storage = wallet_storage(storage, &args.wallet_name)?;
    ensure_wallet_exists(&storage, &args.wallet_name)?;
    let mut metadata = load_metadata(&storage.metadata_path)?;

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

fn wallet_delete(storage: &StorageConfig, args: DeleteArgs) -> Result<()> {
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

fn wallet_external(storage: &StorageConfig, args: Vec<String>) -> Result<()> {
    if args.len() >= 2 && args[1] == "add" {
        if args.len() == 3 && (args[2] == "--help" || args[2] == "-h") {
            print_wallet_add_help();
            return Ok(());
        }
        if args.len() > 3 {
            bail!("usage: casper wallet <wallet-name> add [account-name]");
        }
        return wallet_add(
            storage,
            AddArgs {
                wallet_name: args[0].clone(),
                account_name: args.get(2).cloned(),
            },
        );
    }
    if args.len() >= 2 && args[1] == "rename" {
        if args.len() == 4 && (args[3] == "--help" || args[3] == "-h") {
            print_wallet_rename_help();
            return Ok(());
        }
        if args.len() != 4 {
            bail!("usage: casper wallet <wallet-name> rename-account <old-name> <new-name>");
        }
        return wallet_rename(
            storage,
            RenameArgs {
                wallet_name: args[0].clone(),
                old_name: args[2].clone(),
                new_name: args[3].clone(),
            },
        );
    }
    if args.len() >= 2 && args[1] == "rename-account" {
        if args.len() == 4 && (args[3] == "--help" || args[3] == "-h") {
            print_wallet_rename_help();
            return Ok(());
        }
        if args.len() != 4 {
            bail!("usage: casper wallet <wallet-name> rename-account <old-name> <new-name>");
        }
        return wallet_rename(
            storage,
            RenameArgs {
                wallet_name: args[0].clone(),
                old_name: args[2].clone(),
                new_name: args[3].clone(),
            },
        );
    }

    bail!("unsupported wallet command: {}", args.join(" "))
}

fn print_wallet_add_help() {
    println!("Usage: casper wallet <wallet-name> add [account-name]");
    println!();
    println!("Adds the next derived account to the wallet.");
    println!("If account-name is omitted, defaults to account-{{index}}.");
}

fn print_wallet_rename_help() {
    println!("Usage: casper wallet <wallet-name> rename-account <old-name> <new-name>");
    println!();
    println!("Renames an existing account in the wallet.");
}

struct WalletStorage {
    metadata_path: PathBuf,
    secret_location: String,
    storage: Box<dyn SecureStorage>,
}

fn wallet_storage(storage: &StorageConfig, name: &str) -> Result<WalletStorage> {
    validate_wallet_name(name)?;
    let base_dir = storage.base_dir()?;
    let metadata_path = base_dir
        .join(WALLET_DIR_NAME)
        .join(format!("{}.json", name));
    let secret_location = storage.secret_location(name)?;
    let secret_storage = storage.secret_storage()?;
    Ok(WalletStorage {
        metadata_path,
        secret_location,
        storage: secret_storage,
    })
}

fn wallets_dir(storage: &StorageConfig) -> Result<PathBuf> {
    Ok(storage.base_dir()?.join(WALLET_DIR_NAME))
}

fn ensure_wallet_exists(storage: &WalletStorage, name: &str) -> Result<()> {
    let metadata_exists = storage.metadata_path.exists();
    let secret_exists = storage
        .storage
        .exists(name)
        .map_err(|err| anyhow!(err.to_string()))?;
    if !metadata_exists && !secret_exists {
        bail!("wallet '{}' does not exist; create it first", name);
    }
    if !metadata_exists {
        bail!(
            "wallet '{}' metadata missing at {}",
            name,
            storage.metadata_path.display()
        );
    }
    if !secret_exists {
        bail!(
            "wallet '{}' secret missing at {}",
            name,
            storage.secret_location
        );
    }
    Ok(())
}

fn ensure_wallet_absent(storage: &WalletStorage, name: &str) -> Result<()> {
    let metadata_exists = storage.metadata_path.exists();
    let metadata = if metadata_exists {
        Some(load_metadata(&storage.metadata_path)?)
    } else {
        None
    };
    let secret_exists = storage
        .storage
        .exists(name)
        .map_err(|err| anyhow!(err.to_string()))?;
    if metadata_exists && secret_exists {
        let backend = metadata
            .as_ref()
            .map(|metadata| metadata.storage.as_str())
            .unwrap_or("unknown");
        bail!(
            "wallet '{}' already exists (metadata storage: {})",
            name,
            backend
        );
    }
    if metadata_exists && !secret_exists {
        let backend = metadata
            .as_ref()
            .map(|metadata| metadata.storage.as_str())
            .unwrap_or("unknown");
        bail!(
            "wallet '{}' metadata exists for {} storage at {}, but secret is missing at {}",
            name,
            backend,
            storage.metadata_path.display(),
            storage.secret_location
        );
    }
    if !metadata_exists && secret_exists {
        bail!(
            "wallet '{}' secret exists at {}, but metadata is missing at {}",
            name,
            storage.secret_location,
            storage.metadata_path.display()
        );
    }
    Ok(())
}

fn ensure_unencrypted_allowed(storage: &dyn SecureStorage, requested: bool) -> Result<()> {
    if requested && !storage.uses_master_password() {
        bail!("--unencrypted is not supported with this storage backend");
    }
    Ok(())
}

fn load_metadata(path: &Path) -> Result<WalletMetadata> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("failed to read wallet metadata {}", path.display()))?;
    let metadata = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse wallet metadata {}", path.display()))?;
    Ok(metadata)
}

fn save_metadata(path: &Path, metadata: &WalletMetadata) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let data = serde_json::to_string_pretty(metadata)?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn validate_wallet_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("wallet name cannot be empty");
    }
    if name == "." || name == ".." {
        bail!("wallet name cannot be '.' or '..'");
    }
    if name.contains('/') || name.contains('\\') {
        bail!("wallet name cannot contain path separators");
    }
    if keyring::is_reserved_wallet_name(name) {
        bail!("wallet name is reserved");
    }
    Ok(())
}

fn add_account(
    metadata: &mut WalletMetadata,
    name: &str,
    index: u32,
    path: &str,
    public_key: &str,
) -> bool {
    if name.is_empty() {
        return false;
    }
    if let Some(existing) = metadata
        .accounts
        .iter_mut()
        .find(|account| account.path == path)
    {
        if existing.name.is_empty() && !name.is_empty() {
            existing.name = name.to_string();
            return true;
        }
        return false;
    }
    metadata.accounts.push(DerivedAccount {
        name: name.to_string(),
        index,
        path: path.to_string(),
        public_key: public_key.to_string(),
    });
    true
}

fn default_account_name(index: u32) -> String {
    format!("account-{}", index)
}

fn wallet_type_from_secret(secret: &RootSecret) -> (WalletType, String) {
    match secret {
        RootSecret::Bip39 { .. } => (WalletType::Bip39, "bip39".to_string()),
        RootSecret::Seeded { domain, .. } => (WalletType::Seeded, domain.clone()),
    }
}

fn derive_account(seed: &[u8], index: u32) -> Result<(String, String)> {
    let path = format!("{}/{}", DEFAULT_PATH_PREFIX, index);
    let derivation_path = path.parse::<DerivationPath>()?;
    let xprv = XPrv::derive_from_path(seed, &derivation_path)?;
    let public_key_bytes = xprv.public_key().to_bytes();

    let public_key = {
        let mut casper_public_key = public_key_bytes.to_vec();
        casper_public_key.insert(0, 0x02); // 1 indicates secp256k1 key
        casper_public_key
    };

    let public_key_hex = hex::encode(&public_key);
    Ok((path, public_key_hex))
}

fn root_seed(root_secret: &RootSecret) -> Result<Vec<u8>> {
    match root_secret {
        RootSecret::Bip39 {
            mnemonic,
            passphrase,
        } => {
            let mnemonic = Mnemonic::new(mnemonic, Language::English)
                .map_err(|_| anyhow!("invalid stored mnemonic"))?;
            Ok(mnemonic.to_seed(passphrase).as_bytes().to_vec())
        }
        RootSecret::Seeded { seed, domain } => Ok(seeded_entropy(domain, seed)?.to_vec()),
    }
}

fn seeded_entropy(domain: &str, seed: &str) -> Result<[u8; 32]> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| anyhow!("invalid blake2 output length"))?;
    hasher.update(domain.as_bytes());
    hasher.update(seed.as_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .map_err(|_| anyhow!("blake2 finalize failed"))?;
    Ok(out)
}

fn prompt_passphrase(prompt: &str) -> Result<String> {
    let passphrase = rpassword::prompt_password(prompt)?;
    Ok(passphrase)
}

fn prompt_mnemonic() -> Result<String> {
    let input = rpassword::prompt_password("Enter BIP-39 mnemonic: ")?;
    let normalized = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        bail!("mnemonic cannot be empty");
    }
    Ok(normalized)
}

fn warn_seeded_wallet(domain: &str) {
    eprintln!("WARNING: seeded wallets are NOT BIP-39 compatible.");
    eprintln!("WARNING: deterministic mode is intended for devnets only.");
    eprintln!("WARNING: domain separation is mandatory: {}", domain);
}

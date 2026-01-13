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
use zeroize::Zeroizing;

use crate::secure_storage::file::FileSecureStorage;
use crate::secure_storage::{RootSecret, SecureStorage, StorageAuth};

const WALLET_DIR_NAME: &str = "wallets";
const SECRETS_DIR_NAME: &str = "secrets";
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
    #[serde(default = "default_encrypted")]
    encrypted: bool,
    wallet_type: WalletType,
    #[serde(default = "default_domain")]
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

pub fn handle(wallet_path_override: &Option<PathBuf>, args: WalletArgs) -> Result<()> {
    match args.command {
        WalletCommand::Create(command) => create_wallet(wallet_path_override, command),
        WalletCommand::Recover(command) => recover_wallet(wallet_path_override, command),
        WalletCommand::List => wallet_list(wallet_path_override),
        WalletCommand::Info(command) => wallet_info(wallet_path_override, command),
        WalletCommand::Derive(command) => wallet_derive(wallet_path_override, command),
        WalletCommand::Add(command) => wallet_add(wallet_path_override, command),
        WalletCommand::RenameAccount(command) => wallet_rename(wallet_path_override, command),
        WalletCommand::Delete(command) => wallet_delete(wallet_path_override, command),
        WalletCommand::External(command) => wallet_external(wallet_path_override, command),
    }
}

pub fn resolve_account_public_key(
    wallet_path_override: &Option<PathBuf>,
    wallet_name: &str,
    account_name: &str,
) -> Result<String> {
    let paths = storage_paths(wallet_path_override, wallet_name)?;
    if !paths.metadata_path.exists() {
        bail!("wallet '{}' does not exist; create it first", wallet_name);
    }
    let metadata = load_metadata(&paths.metadata_path)?;
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

fn create_wallet(wallet_path_override: &Option<PathBuf>, args: CreateArgs) -> Result<()> {
    let paths = storage_paths(wallet_path_override, &args.name)?;
    let storage = FileSecureStorage::new(paths.secrets_dir.clone());
    ensure_wallet_absent(&storage, &paths, &args.name)?;
    let auth = if args.unencrypted {
        warn_unencrypted_wallet();
        StorageAuth::None
    } else {
        prompt_master_password(true)?
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
    let metadata = WalletMetadata {
        version: 1,
        name: args.name.clone(),
        encrypted: !args.unencrypted,
        wallet_type,
        domain,
        accounts: Vec::new(),
    };
    storage
        .store(&args.name, &root_secret, &auth)
        .map_err(|err| anyhow!(err.to_string()))?;
    save_metadata(&paths.metadata_path, &metadata)?;
    println!("Wallet saved to {}", paths.metadata_path.display());
    Ok(())
}

fn recover_wallet(wallet_path_override: &Option<PathBuf>, args: RecoverArgs) -> Result<()> {
    let paths = storage_paths(wallet_path_override, &args.name)?;
    let storage = FileSecureStorage::new(paths.secrets_dir.clone());
    ensure_wallet_absent(&storage, &paths, &args.name)?;

    let mnemonic_input = prompt_mnemonic()?;
    let mnemonic = Mnemonic::new(mnemonic_input, Language::English)
        .map_err(|_| anyhow!("invalid mnemonic"))?;
    let passphrase = prompt_passphrase("Enter optional BIP-39 passphrase: ")?;

    let auth = if args.unencrypted {
        warn_unencrypted_wallet();
        StorageAuth::None
    } else {
        prompt_master_password(true)?
    };

    let root_secret = RootSecret::Bip39 {
        mnemonic: mnemonic.phrase().to_string(),
        passphrase,
    };

    let (wallet_type, domain) = wallet_type_from_secret(&root_secret);
    let metadata = WalletMetadata {
        version: 1,
        name: args.name.clone(),
        encrypted: !args.unencrypted,
        wallet_type,
        domain,
        accounts: Vec::new(),
    };

    storage
        .store(&args.name, &root_secret, &auth)
        .map_err(|err| anyhow!(err.to_string()))?;
    save_metadata(&paths.metadata_path, &metadata)?;
    println!("Wallet saved to {}", paths.metadata_path.display());
    Ok(())
}

fn wallet_list(wallet_path_override: &Option<PathBuf>) -> Result<()> {
    let wallets_dir = wallets_dir(wallet_path_override)?;
    if !wallets_dir.exists() {
        println!("No wallets found.");
        return Ok(());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&wallets_dir)
        .with_context(|| format!("failed to read {}", wallets_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let metadata = load_metadata(&path)?;
        entries.push(metadata);
    }

    if entries.is_empty() {
        println!("No wallets found.");
        return Ok(());
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let mut table = Table::new();
    table.set_header(vec!["Name", "Encrypted", "Accounts"]);
    for metadata in entries {
        table.add_row(vec![
            Cell::new(metadata.name),
            Cell::new(metadata.encrypted),
            Cell::new(metadata.accounts.len()),
        ]);
    }
    println!("{table}");

    Ok(())
}

fn wallet_info(wallet_path_override: &Option<PathBuf>, args: InfoArgs) -> Result<()> {
    let paths = storage_paths(wallet_path_override, &args.name)?;
    let storage = FileSecureStorage::new(paths.secrets_dir.clone());
    ensure_wallet_exists(&storage, &paths, &args.name)?;
    let mut metadata = load_metadata(&paths.metadata_path)?;
    let mut updated = false;
    if metadata.domain == default_domain() && metadata.wallet_type == WalletType::Bip39 {
        metadata.domain = "bip39".to_string();
        updated = true;
    }

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

    if updated {
        save_metadata(&paths.metadata_path, &metadata)?;
    }

    Ok(())
}

fn wallet_derive(wallet_path_override: &Option<PathBuf>, args: DeriveArgs) -> Result<()> {
    let paths = storage_paths(wallet_path_override, &args.name)?;
    let storage = FileSecureStorage::new(paths.secrets_dir.clone());
    ensure_wallet_exists(&storage, &paths, &args.name)?;
    let mut metadata = load_metadata(&paths.metadata_path)?;
    let auth = auth_for_metadata(&metadata, false)?;
    let root_secret = storage
        .load(&args.name, &auth)
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
        save_metadata(&paths.metadata_path, &metadata)?;
    }

    if args.count > 0 {
        println!("{table}");
    }

    Ok(())
}

fn wallet_add(wallet_path_override: &Option<PathBuf>, args: AddArgs) -> Result<()> {
    let paths = storage_paths(wallet_path_override, &args.wallet_name)?;
    let storage = FileSecureStorage::new(paths.secrets_dir.clone());
    ensure_wallet_exists(&storage, &paths, &args.wallet_name)?;
    let mut metadata = load_metadata(&paths.metadata_path)?;
    let auth = auth_for_metadata(&metadata, false)?;
    let root_secret = storage
        .load(&args.wallet_name, &auth)
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
    save_metadata(&paths.metadata_path, &metadata)?;

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

fn wallet_rename(wallet_path_override: &Option<PathBuf>, args: RenameArgs) -> Result<()> {
    let paths = storage_paths(wallet_path_override, &args.wallet_name)?;
    let storage = FileSecureStorage::new(paths.secrets_dir.clone());
    ensure_wallet_exists(&storage, &paths, &args.wallet_name)?;
    let mut metadata = load_metadata(&paths.metadata_path)?;

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

    save_metadata(&paths.metadata_path, &metadata)?;
    println!("Renamed account '{}' to '{}'", args.old_name, args.new_name);
    Ok(())
}

fn wallet_delete(wallet_path_override: &Option<PathBuf>, args: DeleteArgs) -> Result<()> {
    let paths = storage_paths(wallet_path_override, &args.name)?;
    let storage = FileSecureStorage::new(paths.secrets_dir.clone());
    let metadata_exists = paths.metadata_path.exists();
    let secret_exists = storage
        .exists(&args.name)
        .map_err(|err| anyhow!(err.to_string()))?;
    if !metadata_exists && !secret_exists {
        bail!("wallet '{}' does not exist; create it first", args.name);
    }

    storage
        .delete(&args.name)
        .map_err(|err| anyhow!(err.to_string()))?;
    match fs::remove_file(&paths.metadata_path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    println!("Deleted wallet '{}'", args.name);
    Ok(())
}

fn wallet_external(wallet_path_override: &Option<PathBuf>, args: Vec<String>) -> Result<()> {
    if args.len() >= 2 && args[1] == "add" {
        if args.len() == 3 && (args[2] == "--help" || args[2] == "-h") {
            print_wallet_add_help();
            return Ok(());
        }
        if args.len() > 3 {
            bail!("usage: casper wallet <wallet-name> add [account-name]");
        }
        return wallet_add(
            wallet_path_override,
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
            wallet_path_override,
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
            wallet_path_override,
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

struct StoragePaths {
    metadata_path: PathBuf,
    secrets_dir: PathBuf,
}

fn secret_path(secrets_dir: &Path, name: &str) -> PathBuf {
    secrets_dir.join(format!("{}.enc", name))
}

fn storage_paths(override_path: &Option<PathBuf>, name: &str) -> Result<StoragePaths> {
    validate_wallet_name(name)?;
    let base_dir = base_dir_from_override(override_path)?;
    let metadata_path = base_dir
        .join(WALLET_DIR_NAME)
        .join(format!("{}.json", name));

    Ok(StoragePaths {
        metadata_path,
        secrets_dir: base_dir.join(SECRETS_DIR_NAME),
    })
}

fn base_dir_from_override(override_path: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        let is_json = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("json"))
            .unwrap_or(false);
        if is_json || path.is_file() {
            return path
                .parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| anyhow!("wallet path has no parent directory"));
        }
        return Ok(path.clone());
    }
    Ok(dirs::config_dir()
        .or_else(|| std::env::current_dir().ok())
        .context("unable to determine config directory")?
        .join("casper-cli"))
}

fn wallets_dir(override_path: &Option<PathBuf>) -> Result<PathBuf> {
    Ok(base_dir_from_override(override_path)?.join(WALLET_DIR_NAME))
}

fn ensure_wallet_exists(
    storage: &FileSecureStorage,
    paths: &StoragePaths,
    name: &str,
) -> Result<()> {
    let metadata_exists = paths.metadata_path.exists();
    let secret_exists = storage
        .exists(name)
        .map_err(|err| anyhow!(err.to_string()))?;
    if !metadata_exists && !secret_exists {
        bail!("wallet '{}' does not exist; create it first", name);
    }
    if !metadata_exists {
        bail!(
            "wallet '{}' metadata missing at {}",
            name,
            paths.metadata_path.display()
        );
    }
    if !secret_exists {
        bail!(
            "wallet '{}' secret missing at {}",
            name,
            secret_path(&paths.secrets_dir, name).display()
        );
    }
    Ok(())
}

fn ensure_wallet_absent(
    storage: &FileSecureStorage,
    paths: &StoragePaths,
    name: &str,
) -> Result<()> {
    let metadata_exists = paths.metadata_path.exists();
    let secret_exists = storage
        .exists(name)
        .map_err(|err| anyhow!(err.to_string()))?;
    if secret_exists || metadata_exists {
        bail!("wallet '{}' already exists", name);
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

fn default_encrypted() -> bool {
    true
}

fn default_domain() -> String {
    "unknown".to_string()
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

fn prompt_master_password(confirm: bool) -> Result<StorageAuth> {
    let password = rpassword::prompt_password("Enter master password: ")?;
    if confirm {
        let confirmation = rpassword::prompt_password("Confirm master password: ")?;
        if password != confirmation {
            bail!("master passwords do not match");
        }
    }
    if password.is_empty() {
        eprintln!("\x1b[1;31mWARNING: EMPTY MASTER PASSWORD\x1b[0m");
        eprintln!("\x1b[1;33mSecrets will be stored with no protection.\x1b[0m");
    } else if password.len() < 12 {
        eprintln!("WARNING: master password is short; consider using 12+ characters.");
    }
    Ok(StorageAuth::Password(Zeroizing::new(password)))
}

fn prompt_mnemonic() -> Result<String> {
    let input = rpassword::prompt_password("Enter BIP-39 mnemonic: ")?;
    let normalized = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        bail!("mnemonic cannot be empty");
    }
    Ok(normalized)
}

fn auth_for_metadata(metadata: &WalletMetadata, confirm: bool) -> Result<StorageAuth> {
    if metadata.encrypted {
        prompt_master_password(confirm)
    } else {
        warn_unencrypted_wallet();
        Ok(StorageAuth::None)
    }
}

fn warn_unencrypted_wallet() {
    eprintln!("\x1b[1;31mWARNING: UNENCRYPTED WALLET\x1b[0m");
    eprintln!("\x1b[1;33mSecrets will be stored in plaintext.\x1b[0m");
}

fn warn_seeded_wallet(domain: &str) {
    eprintln!("WARNING: seeded wallets are NOT BIP-39 compatible.");
    eprintln!("WARNING: deterministic mode is intended for devnets only.");
    eprintln!("WARNING: domain separation is mandatory: {}", domain);
}

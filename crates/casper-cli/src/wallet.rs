use crate::network::ConfigContext;
use crate::secure_storage::keyring;
use crate::secure_storage::{RootSecret, SecureStorage, StorageBackendKind};
use crate::slip0010;
use crate::storage::StorageConfig;
use anyhow::{Context, Result, anyhow, bail};
use bip32::{ChildNumber, DerivationPath, XPrv};
use bip39::{Language, Mnemonic};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use casper_types::{
    ED25519_TAG, PublicKey, SECP256K1_TAG, SecretKey,
    bytesrepr::{ToBytes, deserialize_from_slice},
};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const WALLET_DIR_NAME: &str = "wallets";
const DEFAULT_BIP32_SECP256K1_PATH_PREFIX: &str = "m/44'/506'/0'/0";

mod create;
mod delete;
mod derive;
mod derive_vanity;
mod external;
mod import_legacy;
mod info;
mod list;
mod recover;
mod rename;

fn parse_word_count(value: &str) -> std::result::Result<u16, String> {
    match value {
        "12" => Ok(12),
        "15" => Ok(15),
        "18" => Ok(18),
        "21" => Ok(21),
        "24" => Ok(24),
        _ => Err("word count must be 12, 15, 18, 21, or 24".to_string()),
    }
}

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
    Create(create::CreateArgs),
    /// Recover a wallet from a mnemonic.
    Recover(recover::RecoverArgs),
    /// Import a legacy secret key PEM as a wallet.
    #[command(name = "import-legacy")]
    ImportLegacy(import_legacy::ImportLegacyArgs),
    /// List wallets in the configured storage directory.
    List,
    /// Show wallet metadata and known accounts.
    Info(info::InfoArgs),
    /// Derive one or more accounts from the wallet root.
    Derive(derive::DeriveArgs),
    /// Search derivation paths for vanity accounts.
    #[command(name = "derive-vanity")]
    DeriveVanity(derive_vanity::DeriveVanityArgs),
    /// Rename an account inside a wallet.
    #[command(name = "rename-account")]
    RenameAccount(rename::RenameArgs),
    /// Delete a wallet's metadata and secret.
    Delete(delete::DeleteArgs),
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Serialize, Deserialize)]
struct WalletMetadata {
    version: u8,
    name: String,
    storage: StorageBackendKind,
    encrypted: bool,
    wallet_type: WalletType,
    #[serde(default)]
    derivation: DerivationScheme,
    domain: String,
    accounts: Vec<DerivedAccount>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum WalletType {
    Bip39,
    Seeded,
    LegacyPem { public_key: String },
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum DerivationScheme {
    #[default]
    Bip32Secp256k1,
    Slip10Ed25519,
}

#[derive(Serialize, Deserialize, Clone)]
struct DerivedAccount {
    name: String,
    index: u32,
    path: String,
    public_key: String,
}

struct DerivedAccountCandidate {
    index: u32,
    path: String,
    public_key_hex: String,
    account_hash_hex: String,
}

enum AccountDeriver<'a> {
    Bip32Secp256k1 { parent: XPrv },
    Slip10Ed25519 { seed: &'a [u8], prefix: Vec<u32> },
}

impl<'a> AccountDeriver<'a> {
    fn new(seed: &'a [u8], derivation: DerivationScheme) -> Result<Self> {
        match derivation {
            DerivationScheme::Bip32Secp256k1 => {
                let parent_path = DEFAULT_BIP32_SECP256K1_PATH_PREFIX.parse::<DerivationPath>()?;
                let parent = XPrv::derive_from_path(seed, &parent_path)?;
                Ok(Self::Bip32Secp256k1 { parent })
            }
            DerivationScheme::Slip10Ed25519 => {
                let prefix =
                    slip0010::parse_hardened_path(slip0010::DEFAULT_SLIP0010_ED25519_PATH_PREFIX)?;
                Ok(Self::Slip10Ed25519 { seed, prefix })
            }
        }
    }

    fn path_for_index(&self, index: u32) -> Result<String> {
        match self {
            Self::Bip32Secp256k1 { .. } => {
                ChildNumber::new(index, false)?;
                Ok(format!("{}/{}", DEFAULT_BIP32_SECP256K1_PATH_PREFIX, index))
            }
            Self::Slip10Ed25519 { .. } => Ok(slip0010::default_path(index)),
        }
    }

    fn derive_candidate(&self, index: u32, path: String) -> Result<DerivedAccountCandidate> {
        let secret_key = self.derive_secret_key(index)?;
        candidate_from_secret_key(index, path, &secret_key)
    }

    fn derive_secret_key(&self, index: u32) -> Result<SecretKey> {
        match self {
            Self::Bip32Secp256k1 { parent } => {
                let child_number = ChildNumber::new(index, false)?;
                let child = parent.derive_child(child_number)?;
                secret_key_from_bip32_xprv(&child)
            }
            Self::Slip10Ed25519 { seed, prefix } => {
                let mut indexes = Vec::with_capacity(prefix.len() + 1);
                indexes.extend_from_slice(prefix);
                indexes.push(index);
                let mut secret_key_bytes = slip0010::derive_private_key(seed, &indexes)?;
                let secret_key = SecretKey::ed25519_from_bytes(secret_key_bytes)
                    .map_err(|err| anyhow!(err.to_string()))?;
                secret_key_bytes.zeroize();
                Ok(secret_key)
            }
        }
    }
}

pub fn handle(storage: &StorageConfig, context: &ConfigContext, args: WalletArgs) -> Result<()> {
    match args.command {
        WalletCommand::Create(command) => create::handle(storage, command),
        WalletCommand::Recover(command) => recover::handle(storage, command),
        WalletCommand::ImportLegacy(command) => import_legacy::handle(storage, command),
        WalletCommand::List => list::handle(storage),
        WalletCommand::Info(command) => info::handle(storage, context, command),
        WalletCommand::Derive(command) => derive::handle(storage, context, command),
        WalletCommand::DeriveVanity(command) => derive_vanity::handle(storage, context, command),
        WalletCommand::RenameAccount(command) => rename::handle(storage, command),
        WalletCommand::Delete(command) => delete::handle(storage, command),
        WalletCommand::External(command) => external::handle(storage, command),
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
    if matches!(&metadata.wallet_type, WalletType::LegacyPem { .. }) {
        bail!("legacy secret key wallets do not contain accounts");
    }
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

pub fn resolve_account_secret_key(
    storage: &StorageConfig,
    wallet_name: &str,
    account_name: &str,
) -> Result<SecretKey> {
    let storage = wallet_storage(storage, wallet_name)?;
    ensure_wallet_exists(&storage, wallet_name)?;
    let metadata = load_metadata(&storage.metadata_path)?;
    if matches!(&metadata.wallet_type, WalletType::LegacyPem { .. }) {
        bail!("legacy secret key wallets do not contain accounts");
    }
    let account = metadata
        .accounts
        .iter()
        .find(|account| account.name == account_name)
        .ok_or_else(|| {
            anyhow!(
                "account '{}' not found in wallet '{}'",
                account_name,
                wallet_name
            )
        })?;
    let root_secret = storage
        .storage
        .load(wallet_name)
        .map_err(|err| anyhow!(err.to_string()))?;
    let mut seed = root_seed(&root_secret)?;
    let result = derive_secret_key_for_path(&seed, metadata.derivation, &account.path);
    seed.zeroize();
    result
}

pub(crate) fn try_resolve_legacy_secret_key(
    storage: &StorageConfig,
    wallet_name: &str,
) -> Result<Option<SecretKey>> {
    let Some((wallet_storage, metadata)) = load_wallet_metadata_if_exists(storage, wallet_name)?
    else {
        return Ok(None);
    };
    if !matches!(&metadata.wallet_type, WalletType::LegacyPem { .. }) {
        bail!(
            "wallet '{}' is not a legacy secret key wallet; use <wallet>:<account>",
            wallet_name
        );
    }
    let root_secret = wallet_storage
        .storage
        .load(wallet_name)
        .map_err(|err| anyhow!(err.to_string()))?;
    let secret_key = legacy_secret_key_from_root(&root_secret)?;
    Ok(Some(secret_key))
}

pub(crate) fn try_resolve_legacy_public_key(
    storage: &StorageConfig,
    wallet_name: &str,
) -> Result<Option<String>> {
    let Some((_wallet_storage, metadata)) = load_wallet_metadata_if_exists(storage, wallet_name)?
    else {
        return Ok(None);
    };
    let public_key_hex = match &metadata.wallet_type {
        WalletType::LegacyPem { public_key } => public_key.clone(),
        _ => return Ok(None),
    };
    let _ = legacy_key_kind_from_public_key_hex(&public_key_hex)?;
    Ok(Some(public_key_hex))
}

fn legacy_secret_key_from_root(root_secret: &RootSecret) -> Result<SecretKey> {
    match root_secret {
        RootSecret::LegacyPem { pem } => secret_key_from_pem(pem),
        _ => bail!("wallet secret is not a legacy secret key PEM"),
    }
}

fn legacy_public_key_hex_from_root(root_secret: &RootSecret) -> Result<String> {
    let secret_key = legacy_secret_key_from_root(root_secret)?;
    let public_key = PublicKey::from(&secret_key);
    if matches!(public_key, PublicKey::System) {
        bail!("legacy secret key cannot be system key");
    }
    let public_key_bytes = public_key
        .to_bytes()
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(hex::encode(public_key_bytes))
}

fn legacy_key_kind_from_public_key_hex(public_key_hex: &str) -> Result<&'static str> {
    let public_key = public_key_from_hex(public_key_hex)?;
    match public_key {
        PublicKey::Ed25519(_) => Ok("ed25519"),
        PublicKey::Secp256k1(_) => Ok("secp256k1"),
        PublicKey::System => bail!("legacy public key cannot be system key"),
        _ => bail!("unsupported legacy public key type"),
    }
}

fn secret_key_from_pem(pem: &str) -> Result<SecretKey> {
    let secret_key = SecretKey::from_pem(pem.as_bytes())
        .map_err(|err| anyhow!("invalid legacy secret key PEM: {err}"))?;
    if matches!(secret_key, SecretKey::System) {
        bail!("legacy secret key cannot be system key");
    }
    Ok(secret_key)
}

fn public_key_from_hex(input: &str) -> Result<PublicKey> {
    let bytes = hex::decode(input).context("invalid public key hex")?;
    let public_key: PublicKey =
        deserialize_from_slice(&bytes).map_err(|_| anyhow!("invalid public key bytes"))?;
    Ok(public_key)
}

fn derivation_index_limit(derivation: DerivationScheme) -> u64 {
    match derivation {
        DerivationScheme::Bip32Secp256k1 => ChildNumber::HARDENED_FLAG as u64,
        DerivationScheme::Slip10Ed25519 => u64::from(u32::MAX) + 1,
    }
}

fn derivation_path_for_index(derivation: DerivationScheme, index: u32) -> Result<String> {
    match derivation {
        DerivationScheme::Bip32Secp256k1 => {
            ChildNumber::new(index, false)?;
            Ok(format!("{}/{}", DEFAULT_BIP32_SECP256K1_PATH_PREFIX, index))
        }
        DerivationScheme::Slip10Ed25519 => Ok(slip0010::default_path(index)),
    }
}

fn derive_account_candidate(
    seed: &[u8],
    derivation: DerivationScheme,
    index: u32,
) -> Result<DerivedAccountCandidate> {
    let path = derivation_path_for_index(derivation, index)?;
    let secret_key = derive_secret_key_for_path(seed, derivation, &path)?;
    candidate_from_secret_key(index, path, &secret_key)
}

fn candidate_from_secret_key(
    index: u32,
    path: String,
    secret_key: &SecretKey,
) -> Result<DerivedAccountCandidate> {
    let public_key = PublicKey::from(secret_key);
    let public_key_hex = public_key_hex(&public_key)?;
    let account_hash_hex = format!("{}", public_key.to_account_hash());
    Ok(DerivedAccountCandidate {
        index,
        path,
        public_key_hex,
        account_hash_hex,
    })
}

fn secret_key_from_bip32_xprv(xprv: &XPrv) -> Result<SecretKey> {
    let mut secret_key_bytes = xprv.to_bytes();
    let secret_key = SecretKey::secp256k1_from_bytes(secret_key_bytes)
        .map_err(|err| anyhow!(err.to_string()))?;
    secret_key_bytes.zeroize();
    Ok(secret_key)
}

fn derive_secret_key_for_path(
    seed: &[u8],
    derivation: DerivationScheme,
    path: &str,
) -> Result<SecretKey> {
    match derivation {
        DerivationScheme::Bip32Secp256k1 => {
            let derivation_path = path.parse::<DerivationPath>()?;
            let xprv = XPrv::derive_from_path(seed, &derivation_path)?;
            secret_key_from_bip32_xprv(&xprv)
        }
        DerivationScheme::Slip10Ed25519 => {
            let indexes = slip0010::parse_hardened_path(path)?;
            let mut secret_key_bytes = slip0010::derive_private_key(seed, &indexes)?;
            let secret_key = SecretKey::ed25519_from_bytes(secret_key_bytes)
                .map_err(|err| anyhow!(err.to_string()))?;
            secret_key_bytes.zeroize();
            Ok(secret_key)
        }
    }
}

fn secret_key_bytes(secret_key: &SecretKey) -> Result<Vec<u8>> {
    match secret_key {
        SecretKey::System => bail!("secret key cannot be system key"),
        SecretKey::Ed25519(key) => {
            let mut bytes = Vec::with_capacity(1 + SecretKey::ED25519_LENGTH);
            bytes.push(ED25519_TAG);
            bytes.extend_from_slice(&key.to_bytes());
            Ok(bytes)
        }
        SecretKey::Secp256k1(key) => {
            let raw_bytes = key.to_bytes();
            let raw_bytes: &[u8] = raw_bytes.as_ref();
            let mut bytes = Vec::with_capacity(1 + raw_bytes.len());
            bytes.push(SECP256K1_TAG);
            bytes.extend_from_slice(raw_bytes);
            Ok(bytes)
        }
        _ => bail!("unsupported secret key variant"),
    }
}

fn public_key_hex(public_key: &PublicKey) -> Result<String> {
    if matches!(public_key, PublicKey::System) {
        bail!("public key cannot be system key");
    }
    let public_key_bytes = public_key
        .to_bytes()
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(hex::encode(public_key_bytes))
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

fn load_wallet_metadata_if_exists(
    storage: &StorageConfig,
    name: &str,
) -> Result<Option<(WalletStorage, WalletMetadata)>> {
    let wallet_storage = wallet_storage(storage, name)?;
    let metadata_exists = wallet_storage.metadata_path.exists();
    let secret_exists = wallet_storage
        .storage
        .exists(name)
        .map_err(|err| anyhow!(err.to_string()))?;
    if !metadata_exists && !secret_exists {
        return Ok(None);
    }
    if !metadata_exists {
        bail!(
            "wallet '{}' metadata missing at {}",
            name,
            wallet_storage.metadata_path.display()
        );
    }
    if !secret_exists {
        bail!(
            "wallet '{}' secret missing at {}",
            name,
            wallet_storage.secret_location
        );
    }
    let metadata = load_metadata(&wallet_storage.metadata_path)?;
    Ok(Some((wallet_storage, metadata)))
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

fn wallet_type_from_secret(secret: &RootSecret) -> Result<(WalletType, String)> {
    match secret {
        RootSecret::Bip39 { .. } => Ok((WalletType::Bip39, "bip39".to_string())),
        RootSecret::Seeded { domain, .. } => Ok((WalletType::Seeded, domain.clone())),
        RootSecret::LegacyPem { .. } => {
            let public_key = legacy_public_key_hex_from_root(secret)?;
            Ok((
                WalletType::LegacyPem { public_key },
                "legacy_pem".to_string(),
            ))
        }
    }
}

fn derivation_from_flags(bip32: bool, slip10: bool) -> Result<DerivationScheme> {
    if bip32 && slip10 {
        bail!("--bip32 is mutually exclusive with --slip10");
    }
    Ok(if slip10 {
        DerivationScheme::Slip10Ed25519
    } else {
        DerivationScheme::Bip32Secp256k1
    })
}

fn root_seed(root_secret: &RootSecret) -> Result<Vec<u8>> {
    match root_secret {
        RootSecret::Bip39 {
            mnemonic,
            passphrase,
        } => {
            let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
                .map_err(|_| anyhow!("invalid stored mnemonic"))?;
            Ok(mnemonic.to_seed(passphrase).to_vec())
        }
        RootSecret::Seeded { seed, domain } => Ok(seeded_entropy(domain, seed)?.to_vec()),
        RootSecret::LegacyPem { .. } => {
            bail!("legacy secret key wallets do not support account derivation");
        }
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

fn read_legacy_pem(path: Option<&PathBuf>) -> Result<String> {
    let pem = match path {
        Some(path) => fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?,
        None => {
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .context("failed to read legacy PEM from stdin")?;
            buffer
        }
    };
    let trimmed = pem.trim();
    if trimmed.is_empty() {
        bail!("legacy secret key PEM is empty");
    }
    Ok(trimmed.to_string())
}

fn warn_seeded_wallet(domain: &str) {
    eprintln!("WARNING: seeded wallets are NOT BIP-39 compatible.");
    eprintln!("WARNING: deterministic mode is intended for devnets only.");
    eprintln!("WARNING: domain separation is mandatory: {}", domain);
}

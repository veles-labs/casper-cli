use std::error::Error;

use keyring::{Entry, Error as KeyringError};
use serde::{Deserialize, Serialize};

use super::secret_file::{decode_secret, encode_plain_secret, parse_secret_file};
use super::{RootSecret, SecureStorage, StorageBackendKind, StoreMode};

/// Keyring-backed secure storage using the OS credential store.
pub struct KeyringSecureStorage(());

const SERVICE_NAME: &str = "casper-cli";
const INDEX_ENTRY: &str = "__casper_cli_wallet_index";

impl KeyringSecureStorage {
    /// Create a new keyring-backed storage using the provided service name.
    pub fn new() -> Self {
        Self(())
    }

    fn entry(&self, wallet_name: &str) -> Result<Entry, Box<dyn Error>> {
        Ok(Entry::new(SERVICE_NAME, wallet_name)?)
    }

    fn is_missing_entry_error(err: &KeyringError) -> bool {
        matches!(err, KeyringError::NoEntry)
    }

    fn load_index(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let entry = self.entry(INDEX_ENTRY)?;
        match entry.get_password() {
            Ok(payload) => {
                let index: WalletIndex = serde_json::from_str(&payload)?;
                Ok(index.wallets)
            }
            Err(err) if Self::is_missing_entry_error(&err) => Ok(Vec::new()),
            Err(err) => Err(err.into()),
        }
    }

    fn save_index(&self, mut wallets: Vec<String>) -> Result<(), Box<dyn Error>> {
        wallets.sort();
        wallets.dedup();
        let entry = self.entry(INDEX_ENTRY)?;
        let payload = serde_json::to_string(&WalletIndex { wallets })?;
        entry.set_password(&payload)?;
        Ok(())
    }

    fn add_to_index(&self, wallet_name: &str) -> Result<(), Box<dyn Error>> {
        let mut wallets = self.load_index()?;
        if !wallets.iter().any(|name| name == wallet_name) {
            wallets.push(wallet_name.to_string());
            self.save_index(wallets)?;
        }
        Ok(())
    }

    fn remove_from_index(&self, wallet_name: &str) -> Result<(), Box<dyn Error>> {
        let mut wallets = self.load_index()?;
        wallets.retain(|name| name != wallet_name);
        self.save_index(wallets)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct WalletIndex {
    wallets: Vec<String>,
}

pub(crate) fn is_reserved_wallet_name(name: &str) -> bool {
    name == INDEX_ENTRY
}

impl SecureStorage for KeyringSecureStorage {
    fn store(
        &self,
        wallet_name: &str,
        secret: &RootSecret,
        mode: StoreMode,
    ) -> Result<(), Box<dyn Error>> {
        if matches!(mode, StoreMode::Unencrypted) {
            return Err("unencrypted storage is not supported for keyring".into());
        }
        let entry = self.entry(wallet_name)?;
        let data = encode_plain_secret(secret)?;
        let payload = String::from_utf8(data)?;
        entry.set_password(&payload)?;
        self.add_to_index(wallet_name)?;
        Ok(())
    }

    fn load(&self, wallet_name: &str) -> Result<RootSecret, Box<dyn Error>> {
        let entry = self.entry(wallet_name)?;
        let payload = entry.get_password()?;
        let secret_file = parse_secret_file(&payload)?;
        decode_secret(secret_file, wallet_name, None)
    }

    fn delete(&self, wallet_name: &str) -> Result<(), Box<dyn Error>> {
        let entry = self.entry(wallet_name)?;
        let deleted = match entry.delete_credential() {
            Ok(()) => true,
            Err(err) if Self::is_missing_entry_error(&err) => false,
            Err(err) => return Err(err.into()),
        };
        if deleted {
            self.remove_from_index(wallet_name)?;
        }
        Ok(())
    }

    fn exists(&self, wallet_name: &str) -> Result<bool, Box<dyn Error>> {
        let entry = self.entry(wallet_name)?;
        match entry.get_password() {
            Ok(_) => Ok(true),
            Err(err) if Self::is_missing_entry_error(&err) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    fn list(&self) -> Result<Vec<String>, Box<dyn Error>> {
        self.load_index()
    }

    fn uses_master_password(&self) -> bool {
        false
    }

    fn backend_kind(&self) -> StorageBackendKind {
        StorageBackendKind::Keyring
    }
}

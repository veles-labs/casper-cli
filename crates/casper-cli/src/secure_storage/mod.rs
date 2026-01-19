use serde::{Deserialize, Serialize};
use std::error::Error;
use zeroize::Zeroize;

pub mod file;
pub mod keyring;
mod secret_file;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RootSecret {
    Bip39 {
        mnemonic: String,
        passphrase: String,
    },
    Seeded {
        seed: String,
        domain: String,
    },
    LegacyPem {
        pem: String,
    },
}

impl Drop for RootSecret {
    fn drop(&mut self) {
        match self {
            RootSecret::Bip39 {
                mnemonic,
                passphrase,
            } => {
                mnemonic.zeroize();
                passphrase.zeroize();
            }
            RootSecret::Seeded { seed, domain } => {
                seed.zeroize();
                domain.zeroize();
            }
            RootSecret::LegacyPem { pem } => {
                pem.zeroize();
            }
        }
    }
}

pub trait SecureStorage {
    /// Store (or overwrite) a wallet root secret
    fn store(
        &self,
        wallet_name: &str,
        secret: &RootSecret,
        mode: StoreMode,
    ) -> Result<(), Box<dyn Error>>;

    /// Load a wallet root secret
    fn load(&self, wallet_name: &str) -> Result<RootSecret, Box<dyn Error>>;

    /// Delete a wallet root secret
    fn delete(&self, wallet_name: &str) -> Result<(), Box<dyn Error>>;

    /// Check whether a wallet exists
    fn exists(&self, wallet_name: &str) -> Result<bool, Box<dyn Error>>;

    /// List all wallet names known to this backend.
    fn list(&self) -> Result<Vec<String>, Box<dyn Error>>;

    /// Whether this backend relies on a user-supplied master password.
    fn uses_master_password(&self) -> bool;

    /// Identify the backend for metadata tagging.
    fn backend_kind(&self) -> StorageBackendKind;
}

#[derive(Clone, Copy, Debug)]
pub enum StoreMode {
    Encrypted,
    Unencrypted,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackendKind {
    File,
    Keyring,
}

impl StorageBackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            StorageBackendKind::File => "file",
            StorageBackendKind::Keyring => "keyring",
        }
    }
}

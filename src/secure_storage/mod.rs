use serde::{Deserialize, Serialize};
use std::error::Error;
use zeroize::Zeroize;
use zeroize::Zeroizing;

pub mod file;

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
        }
    }
}

pub trait SecureStorage {
    /// Store (or overwrite) a wallet root secret
    fn store(
        &self,
        wallet_name: &str,
        secret: &RootSecret,
        auth: &StorageAuth,
    ) -> Result<(), Box<dyn Error>>;

    /// Load a wallet root secret
    fn load(&self, wallet_name: &str, auth: &StorageAuth) -> Result<RootSecret, Box<dyn Error>>;

    /// Delete a wallet root secret
    fn delete(&self, wallet_name: &str) -> Result<(), Box<dyn Error>>;

    /// Check whether a wallet exists
    fn exists(&self, wallet_name: &str) -> Result<bool, Box<dyn Error>>;
}

pub enum StorageAuth {
    None,
    Password(Zeroizing<String>),
}

impl StorageAuth {
    pub fn password_bytes(&self) -> Option<&[u8]> {
        match self {
            StorageAuth::None => None,
            StorageAuth::Password(password) => Some(password.as_bytes()),
        }
    }
}

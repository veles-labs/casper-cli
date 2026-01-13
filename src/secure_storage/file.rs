use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{RootSecret, SecureStorage, StorageAuth};

const STORAGE_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Argon2id parameters chosen for interactive CLI usage:
/// ~64 MiB memory, 3 iterations, single lane.
const KDF_MEMORY_KIB: u32 = 64 * 1024;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;

/// Encrypted secret file layout.
#[derive(Serialize, Deserialize)]
struct EncryptedSecretFile {
    version: u8,
    kdf: KdfParams,
    nonce: String,
    ciphertext: String,
}

/// Plaintext secret file layout (used for unencrypted wallets).
#[derive(Serialize, Deserialize)]
struct PlainSecretFile {
    version: u8,
    secret: RootSecret,
}

#[derive(Serialize)]
struct PlainSecretFileRef<'a> {
    version: u8,
    secret: &'a RootSecret,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum SecretFile {
    Encrypted(EncryptedSecretFile),
    Plain(PlainSecretFile),
}

/// Parameters stored alongside the ciphertext for future migrations.
#[derive(Serialize, Deserialize)]
struct KdfParams {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Debug)]
struct StorageError(String);

impl StorageError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for StorageError {}

/// File-backed secure storage using Argon2id + XChaCha20-Poly1305.
///
/// - Argon2id provides memory-hard key derivation.
/// - XChaCha20-Poly1305 provides AEAD with a 24-byte nonce.
/// - Wallet name is bound as AAD to prevent file renaming attacks.
pub struct FileSecureStorage {
    base_dir: PathBuf,
}

impl FileSecureStorage {
    /// Create a new file-backed storage rooted at `base_dir`.
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    fn secret_path(&self, wallet_name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.enc", wallet_name))
    }

    fn ensure_dir(path: &Path) -> Result<(), Box<dyn Error>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            Self::restrict_dir_permissions(parent)?;
        }
        Ok(())
    }

    fn restrict_file_permissions(path: &Path) -> Result<(), Box<dyn Error>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn restrict_dir_permissions(path: &Path) -> Result<(), Box<dyn Error>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn write_atomic(path: &Path, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, data)?;
        fs::rename(&tmp_path, path)?;
        Self::restrict_file_permissions(path)?;
        Ok(())
    }

    fn derive_key(
        &self,
        params: &KdfParams,
        salt: &[u8],
        password: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, Box<dyn Error>> {
        // Store algorithm identifier in the file for future migrations.
        if params.algorithm != "argon2id" {
            return Err(StorageError::new("unsupported kdf algorithm").into());
        }
        let argon_params = Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|err| StorageError::new(err.to_string()))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        argon2
            .hash_password_into(password, salt, &mut key[..])
            .map_err(|err| StorageError::new(err.to_string()))?;
        Ok(key)
    }

    fn encrypt_secret(
        &self,
        wallet_name: &str,
        secret: &RootSecret,
        password: &[u8],
    ) -> Result<EncryptedSecretFile, Box<dyn Error>> {
        // Random per-file salt and nonce avoid key/nonce reuse.
        let mut salt = [0u8; SALT_LEN];
        rand_core::OsRng.fill_bytes(&mut salt);

        let kdf = KdfParams {
            algorithm: "argon2id".to_string(),
            memory_kib: KDF_MEMORY_KIB,
            iterations: KDF_ITERATIONS,
            parallelism: KDF_PARALLELISM,
            salt: hex::encode(salt),
        };

        let key = self.derive_key(&kdf, &salt, password)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|err| StorageError::new(err.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand_core::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce: XNonce = nonce_bytes.into();
        let plaintext = Zeroizing::new(serde_json::to_vec(secret)?);

        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: wallet_name.as_bytes(),
                },
            )
            .map_err(|err| StorageError::new(err.to_string()))?;

        Ok(EncryptedSecretFile {
            version: STORAGE_VERSION,
            kdf,
            nonce: hex::encode(nonce_bytes),
            ciphertext: hex::encode(ciphertext),
        })
    }

    fn decrypt_secret(
        &self,
        wallet_name: &str,
        encrypted: &EncryptedSecretFile,
        password: &[u8],
    ) -> Result<RootSecret, Box<dyn Error>> {
        if encrypted.version != STORAGE_VERSION {
            return Err(StorageError::new("unsupported secret version").into());
        }

        let salt = hex::decode(&encrypted.kdf.salt)?;
        if salt.len() != SALT_LEN {
            return Err(StorageError::new("invalid salt length").into());
        }
        let nonce = hex::decode(&encrypted.nonce)?;
        let nonce_bytes: [u8; NONCE_LEN] = nonce
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::new("invalid nonce length"))?;
        let nonce: XNonce = nonce_bytes.into();
        let ciphertext = hex::decode(&encrypted.ciphertext)?;

        let key = self.derive_key(&encrypted.kdf, &salt, password)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|err| StorageError::new(err.to_string()))?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: wallet_name.as_bytes(),
                },
            )
            .map_err(|_| StorageError::new("invalid master password or corrupted data"))?;

        let secret = serde_json::from_slice(&plaintext)?;
        Ok(secret)
    }
}

impl SecureStorage for FileSecureStorage {
    fn store(
        &self,
        wallet_name: &str,
        secret: &RootSecret,
        auth: &StorageAuth,
    ) -> Result<(), Box<dyn Error>> {
        let path = self.secret_path(wallet_name);
        Self::ensure_dir(&path)?;
        let data = match auth.password_bytes() {
            Some(password) => {
                let encrypted = self.encrypt_secret(wallet_name, secret, password)?;
                serde_json::to_vec_pretty(&encrypted)?
            }
            None => {
                let plain = PlainSecretFileRef {
                    version: STORAGE_VERSION,
                    secret,
                };
                serde_json::to_vec_pretty(&plain)?
            }
        };
        Self::write_atomic(&path, &data)?;
        Ok(())
    }

    fn load(&self, wallet_name: &str, auth: &StorageAuth) -> Result<RootSecret, Box<dyn Error>> {
        let path = self.secret_path(wallet_name);
        let data = fs::read_to_string(path)?;
        let secret_file: SecretFile = serde_json::from_str(&data)?;
        match secret_file {
            SecretFile::Plain(plain) => {
                if plain.version != STORAGE_VERSION {
                    return Err(StorageError::new("unsupported secret version").into());
                }
                Ok(plain.secret)
            }
            SecretFile::Encrypted(encrypted) => {
                let password = auth
                    .password_bytes()
                    .ok_or_else(|| StorageError::new("authentication required"))?;
                self.decrypt_secret(wallet_name, &encrypted, password)
            }
        }
    }

    fn delete(&self, wallet_name: &str) -> Result<(), Box<dyn Error>> {
        let path = self.secret_path(wallet_name);
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        Ok(())
    }

    fn exists(&self, wallet_name: &str) -> Result<bool, Box<dyn Error>> {
        Ok(self.secret_path(wallet_name).exists())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const MASTER_PASSWORD: &str = "bawitdaba";

    fn storage_at(dir: &Path) -> FileSecureStorage {
        FileSecureStorage::new(dir.to_path_buf())
    }

    fn make_auth(password: &str) -> StorageAuth {
        StorageAuth::Password(Zeroizing::new(password.to_string()))
    }

    #[test]
    fn roundtrip_bip39_secret() {
        let temp = tempfile::tempdir().expect("tempdir");
        let storage = storage_at(temp.path());
        let secret = RootSecret::Bip39 {
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            passphrase: "passphrase".to_string(),
        };

        let auth = make_auth(MASTER_PASSWORD);
        storage.store("wallet-a", &secret, &auth).expect("store");
        let loaded = storage.load("wallet-a", &auth).expect("load");

        assert_eq!(secret, loaded);
        assert!(temp.path().join("wallet-a.enc").exists());
    }

    #[test]
    fn roundtrip_seeded_secret() {
        let temp = tempfile::tempdir().expect("tempdir");
        let storage = storage_at(temp.path());
        let secret = RootSecret::Seeded {
            seed: "local-devnet".to_string(),
            domain: "casper-unsafe-devnet-v1".to_string(),
        };

        let auth = make_auth(MASTER_PASSWORD);
        storage.store("wallet-b", &secret, &auth).expect("store");
        let loaded = storage.load("wallet-b", &auth).expect("load");

        assert_eq!(secret, loaded);
    }

    #[test]
    fn wrong_password_fails() {
        let temp = tempfile::tempdir().expect("tempdir");
        let storage = storage_at(temp.path());
        let secret = RootSecret::Seeded {
            seed: "seed".to_string(),
            domain: "domain".to_string(),
        };
        let auth = make_auth(MASTER_PASSWORD);
        storage.store("wallet-c", &secret, &auth).expect("store");

        let wrong_auth = make_auth("bad-password");
        let result = storage.load("wallet-c", &wrong_auth);

        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let temp = tempfile::tempdir().expect("tempdir");
        let storage = storage_at(temp.path());
        let secret = RootSecret::Seeded {
            seed: "seed".to_string(),
            domain: "domain".to_string(),
        };
        let auth = make_auth(MASTER_PASSWORD);
        storage.store("wallet-d", &secret, &auth).expect("store");

        let path = temp.path().join("wallet-d.enc");
        let mut encrypted: EncryptedSecretFile =
            serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("parse");
        let mut bytes = hex::decode(&encrypted.ciphertext).expect("decode");
        bytes[0] ^= 0xFF;
        encrypted.ciphertext = hex::encode(bytes);
        fs::write(&path, serde_json::to_string(&encrypted).expect("serialize")).expect("write");

        let result = storage.load("wallet-d", &auth);
        assert!(result.is_err());
    }

    #[test]
    fn renamed_wallet_fails_aad_check() {
        let temp = tempfile::tempdir().expect("tempdir");
        let storage = storage_at(temp.path());
        let secret = RootSecret::Seeded {
            seed: "seed".to_string(),
            domain: "domain".to_string(),
        };
        let auth = make_auth(MASTER_PASSWORD);
        storage.store("wallet-e", &secret, &auth).expect("store");

        let old_path = temp.path().join("wallet-e.enc");
        let new_path = temp.path().join("wallet-f.enc");
        fs::rename(&old_path, &new_path).expect("rename");

        let result = storage.load("wallet-f", &auth);
        assert!(result.is_err());
    }

    #[test]
    fn exists_and_delete_roundtrip() {
        let temp = tempfile::tempdir().expect("tempdir");
        let storage = storage_at(temp.path());
        let secret = RootSecret::Seeded {
            seed: "seed".to_string(),
            domain: "domain".to_string(),
        };

        assert!(!storage.exists("wallet-g").expect("exists"));
        let auth = make_auth(MASTER_PASSWORD);
        storage.store("wallet-g", &secret, &auth).expect("store");
        assert!(storage.exists("wallet-g").expect("exists"));

        storage.delete("wallet-g").expect("delete");
        assert!(!storage.exists("wallet-g").expect("exists"));
    }

    #[test]
    fn delete_missing_is_ok() {
        let temp = tempfile::tempdir().expect("tempdir");
        let storage = storage_at(temp.path());
        storage.delete("wallet-missing").expect("delete");
    }

    #[test]
    fn unencrypted_roundtrip() {
        let temp = tempfile::tempdir().expect("tempdir");
        let storage = storage_at(temp.path());
        let secret = RootSecret::Seeded {
            seed: "seed".to_string(),
            domain: "domain".to_string(),
        };

        storage
            .store("wallet-none", &secret, &StorageAuth::None)
            .expect("store");
        let loaded = storage
            .load("wallet-none", &StorageAuth::None)
            .expect("load");

        assert_eq!(secret, loaded);
    }

    #[test]
    fn encrypted_requires_auth() {
        let temp = tempfile::tempdir().expect("tempdir");
        let storage = storage_at(temp.path());
        let secret = RootSecret::Seeded {
            seed: "seed".to_string(),
            domain: "domain".to_string(),
        };

        let auth = make_auth(MASTER_PASSWORD);
        storage.store("wallet-auth", &secret, &auth).expect("store");
        let result = storage.load("wallet-auth", &StorageAuth::None);
        assert!(result.is_err());
    }
}

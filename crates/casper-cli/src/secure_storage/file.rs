use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use anstyle::{AnsiColor, Style};
use serde::Deserialize;

use super::atomic_file::PendingWrite;
use super::secret_file::{
    SecretFile, decode_secret, encode_encrypted_secret, encode_plain_secret, parse_secret_file,
};
use super::{RootSecret, SecureStorage, StorageBackendKind, StoreMode};
use zeroize::Zeroizing;

/// File-backed secure storage using Argon2id + XChaCha20-Poly1305.
///
/// - Argon2id provides memory-hard key derivation.
/// - XChaCha20-Poly1305 provides AEAD with a 24-byte nonce.
/// - Wallet name is bound as AAD to prevent file renaming attacks.
pub struct FileSecureStorage {
    base_dir: PathBuf,
    password_source: PasswordSource,
}

const METADATA_DIR_NAME: &str = "wallets";
const SECRETS_DIR_NAME: &str = "secrets";

enum PasswordSource {
    Prompt,
    #[cfg(test)]
    Fixed {
        current: Zeroizing<String>,
        new: Zeroizing<String>,
        confirmation: Zeroizing<String>,
    },
}

#[derive(Clone, Copy)]
enum PasswordPurpose {
    Master,
    Current,
    New,
}

impl FileSecureStorage {
    /// Create a new file-backed storage rooted at `base_dir`.
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            password_source: PasswordSource::Prompt,
        }
    }

    #[cfg(test)]
    fn with_password(base_dir: PathBuf, password: impl Into<String>) -> Self {
        let password = Zeroizing::new(password.into());
        Self::with_passwords(base_dir, &password, &password, &password)
    }

    #[cfg(test)]
    pub(crate) fn with_passwords(
        base_dir: PathBuf,
        current: &str,
        new: &str,
        confirmation: &str,
    ) -> Self {
        Self {
            base_dir,
            password_source: PasswordSource::Fixed {
                current: Zeroizing::new(current.to_string()),
                new: Zeroizing::new(new.to_string()),
                confirmation: Zeroizing::new(confirmation.to_string()),
            },
        }
    }

    fn secret_path(&self, wallet_name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.enc", wallet_name))
    }

    fn metadata_root(&self) -> PathBuf {
        if self.base_dir.file_name().and_then(|name| name.to_str()) == Some(SECRETS_DIR_NAME) {
            self.base_dir
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| self.base_dir.clone())
        } else {
            self.base_dir.clone()
        }
    }

    fn ensure_dir(path: &Path) -> Result<(), Box<dyn Error>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            Self::restrict_dir_permissions(parent)?;
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
        PendingWrite::new(path, data)?.persist()
    }

    fn master_password(&self, confirm: bool) -> Result<Zeroizing<String>, Box<dyn Error>> {
        self.password(PasswordPurpose::Master, confirm)
    }

    fn read_password(
        &self,
        purpose: PasswordPurpose,
        confirmation: bool,
    ) -> Result<Zeroizing<String>, Box<dyn Error>> {
        match &self.password_source {
            PasswordSource::Prompt => {
                let prompt = match (purpose, confirmation) {
                    (PasswordPurpose::Master, false) => "Enter master password: ",
                    (PasswordPurpose::Master, true) => "Confirm master password: ",
                    (PasswordPurpose::Current, _) => "Enter current wallet password: ",
                    (PasswordPurpose::New, false) => "Enter new wallet password: ",
                    (PasswordPurpose::New, true) => "Confirm new wallet password: ",
                };
                Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
            }
            #[cfg(test)]
            PasswordSource::Fixed {
                current,
                new,
                confirmation: repeated,
            } => Ok(match (purpose, confirmation) {
                (PasswordPurpose::New, false) => new.clone(),
                (PasswordPurpose::New, true) => repeated.clone(),
                _ => current.clone(),
            }),
        }
    }

    fn password(
        &self,
        purpose: PasswordPurpose,
        confirm: bool,
    ) -> Result<Zeroizing<String>, Box<dyn Error>> {
        let password = self.read_password(purpose, false)?;
        if matches!(purpose, PasswordPurpose::New) && password.is_empty() {
            return Err("new wallet password cannot be empty; use --unencrypted to remove password protection".into());
        }
        if confirm && password != self.read_password(purpose, true)? {
            return Err("passwords do not match".into());
        }
        if !matches!(purpose, PasswordPurpose::Current) {
            if password.is_empty() {
                Self::print_warning("WARNING: EMPTY MASTER PASSWORD");
                Self::print_warning_detail("Secrets will be stored with no protection.");
            } else if password.len() < 12 {
                eprintln!("WARNING: master password is short; consider using 12+ characters.");
            }
        }
        Ok(password)
    }

    /// Authenticate before rewriting a secret. The metadata update is prepared by
    /// the caller; if it fails, atomically restore the original secret file.
    pub(crate) fn change_password(
        &self,
        wallet_name: &str,
        mode: StoreMode,
        update_metadata: impl FnOnce() -> Result<(), Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>> {
        let path = self.secret_path(wallet_name);
        Self::ensure_dir(&path)?;
        // Keep a stable lock file: removing it would permit locking a different
        // inode while another process still holds the original lock.
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path.with_extension("lock"))?;
        lock.try_lock()
            .map_err(|error| format!("cannot lock wallet for password change: {error}"))?;

        let original = Zeroizing::new(fs::read_to_string(&path)?);
        let secret_file = parse_secret_file(&original)?;
        let current_password = if matches!(secret_file, SecretFile::Encrypted(_)) {
            Some(self.password(PasswordPurpose::Current, false)?)
        } else {
            None
        };
        let secret = decode_secret(
            secret_file,
            wallet_name,
            current_password
                .as_ref()
                .map(|password| password.as_bytes()),
        )?;
        drop(current_password);
        let replacement = Zeroizing::new(match mode {
            StoreMode::Encrypted => {
                let password = self.password(PasswordPurpose::New, true)?;
                encode_encrypted_secret(&secret, wallet_name, password.as_bytes())?
            }
            StoreMode::Unencrypted => {
                Self::warn_unencrypted_wallet();
                encode_plain_secret(&secret)?
            }
        });
        drop(secret);
        Self::write_atomic(&path, &replacement)?;
        if let Err(error) = update_metadata() {
            if let Err(rollback) = Self::write_atomic(&path, original.as_bytes()) {
                return Err(format!("wallet protection changed, but metadata update failed ({error}) and restoring the original secret failed ({rollback})").into());
            }
            return Err(format!(
                "wallet metadata update failed; original password protection restored: {error}"
            )
            .into());
        }
        Ok(())
    }

    fn warn_unencrypted_wallet() {
        Self::print_warning("WARNING: UNENCRYPTED WALLET");
        Self::print_warning_detail("Secrets will be stored in plaintext.");
    }

    fn print_warning(message: &str) {
        let style = Style::new().bold().fg_color(Some(AnsiColor::Red.into()));
        eprintln!("{}{}{}", style.render(), message, style.render_reset());
    }

    fn print_warning_detail(message: &str) {
        let style = Style::new().fg_color(Some(AnsiColor::Yellow.into()));
        eprintln!("{}{}{}", style.render(), message, style.render_reset());
    }
}

impl SecureStorage for FileSecureStorage {
    fn store(
        &self,
        wallet_name: &str,
        secret: &RootSecret,
        mode: StoreMode,
    ) -> Result<(), Box<dyn Error>> {
        let path = self.secret_path(wallet_name);
        Self::ensure_dir(&path)?;
        let data = Zeroizing::new(match mode {
            StoreMode::Unencrypted => {
                Self::warn_unencrypted_wallet();
                encode_plain_secret(secret)?
            }
            StoreMode::Encrypted => {
                let password = self.master_password(true)?;
                encode_encrypted_secret(secret, wallet_name, password.as_bytes())?
            }
        });
        Self::write_atomic(&path, &data)?;
        Ok(())
    }

    fn load(&self, wallet_name: &str) -> Result<RootSecret, Box<dyn Error>> {
        let path = self.secret_path(wallet_name);
        let data = Zeroizing::new(fs::read_to_string(path)?);
        let secret_file = parse_secret_file(&data)?;
        match secret_file {
            SecretFile::Plain(_) => decode_secret(secret_file, wallet_name, None),
            SecretFile::Encrypted(_) => {
                let password = self.master_password(false)?;
                decode_secret(secret_file, wallet_name, Some(password.as_bytes()))
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

    fn list(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let mut names = Vec::new();
        let metadata_dir = self.metadata_root().join(METADATA_DIR_NAME);
        if !metadata_dir.exists() {
            return Ok(names);
        }
        for entry in fs::read_dir(&metadata_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let data = fs::read_to_string(&path)?;
            let metadata: WalletMetadataRecord = serde_json::from_str(&data)?;
            if metadata.storage == StorageBackendKind::File {
                names.push(metadata.name);
            }
        }
        names.sort();
        names.dedup();
        Ok(names)
    }

    fn uses_master_password(&self) -> bool {
        true
    }

    fn backend_kind(&self) -> StorageBackendKind {
        StorageBackendKind::File
    }
}

#[derive(Deserialize)]
struct WalletMetadataRecord {
    name: String,
    storage: StorageBackendKind,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const MASTER_PASSWORD: &str = "bawitdaba";

    fn storage_at(dir: &Path) -> FileSecureStorage {
        FileSecureStorage::with_password(dir.to_path_buf(), MASTER_PASSWORD)
    }

    fn storage_with_password(dir: &Path, password: &str) -> FileSecureStorage {
        FileSecureStorage::with_password(dir.to_path_buf(), password)
    }

    #[test]
    fn roundtrip_bip39_secret() {
        let temp = tempfile::tempdir().expect("tempdir");
        let storage = storage_at(temp.path());
        let secret = RootSecret::Bip39 {
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            passphrase: "passphrase".to_string(),
        };

        storage
            .store("wallet-a", &secret, StoreMode::Encrypted)
            .expect("store");
        let loaded = storage.load("wallet-a").expect("load");

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

        storage
            .store("wallet-b", &secret, StoreMode::Encrypted)
            .expect("store");
        let loaded = storage.load("wallet-b").expect("load");

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
        storage
            .store("wallet-c", &secret, StoreMode::Encrypted)
            .expect("store");

        let wrong_storage = storage_with_password(temp.path(), "bad-password");
        let result = wrong_storage.load("wallet-c");

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
        storage
            .store("wallet-d", &secret, StoreMode::Encrypted)
            .expect("store");

        let path = temp.path().join("wallet-d.enc");
        let mut value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("parse");
        let ciphertext = value
            .get("ciphertext")
            .and_then(|value| value.as_str())
            .expect("ciphertext");
        let mut bytes = hex::decode(ciphertext).expect("decode");
        bytes[0] ^= 0xFF;
        value["ciphertext"] = serde_json::Value::String(hex::encode(bytes));
        fs::write(&path, serde_json::to_string(&value).expect("serialize")).expect("write");

        let result = storage.load("wallet-d");
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
        storage
            .store("wallet-e", &secret, StoreMode::Encrypted)
            .expect("store");

        let old_path = temp.path().join("wallet-e.enc");
        let new_path = temp.path().join("wallet-f.enc");
        fs::rename(&old_path, &new_path).expect("rename");

        let result = storage.load("wallet-f");
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
        storage
            .store("wallet-g", &secret, StoreMode::Encrypted)
            .expect("store");
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
            .store("wallet-none", &secret, StoreMode::Unencrypted)
            .expect("store");
        let loaded = storage.load("wallet-none").expect("load");

        assert_eq!(secret, loaded);
    }

    #[test]
    fn metadata_failure_restores_the_original_secret_for_both_changes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let secret = RootSecret::Seeded {
            seed: "unchanged-seed".to_string(),
            domain: "domain".to_string(),
        };
        let original = storage_at(temp.path());
        original
            .store("wallet", &secret, StoreMode::Encrypted)
            .unwrap();
        let before = fs::read(temp.path().join("wallet.enc")).unwrap();
        let storage = FileSecureStorage::with_passwords(
            temp.path().to_path_buf(),
            MASTER_PASSWORD,
            "replacement-password",
            "replacement-password",
        );
        for mode in [StoreMode::Encrypted, StoreMode::Unencrypted] {
            let error = storage
                .change_password("wallet", mode, || {
                    Err("injected metadata write failure".into())
                })
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("original password protection restored")
            );
            assert_eq!(fs::read(temp.path().join("wallet.enc")).unwrap(), before);
            assert_eq!(original.load("wallet").unwrap(), secret);
        }
    }

    #[test]
    fn concurrent_password_changes_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage_at(temp.path());
        let secret = RootSecret::Seeded {
            seed: "seed".to_string(),
            domain: "domain".to_string(),
        };
        storage
            .store("wallet", &secret, StoreMode::Unencrypted)
            .unwrap();
        let before = fs::read(temp.path().join("wallet.enc")).unwrap();
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(temp.path().join("wallet.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        let error = storage
            .change_password("wallet", StoreMode::Encrypted, || {
                panic!("metadata must not be updated")
            })
            .unwrap_err();
        assert!(error.to_string().contains("cannot lock wallet"));
        assert_eq!(fs::read(temp.path().join("wallet.enc")).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_does_not_follow_a_predictable_temporary_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let victim = temp.path().join("unrelated-file");
        fs::write(&victim, "unchanged").unwrap();
        std::os::unix::fs::symlink(&victim, temp.path().join("wallet.tmp")).unwrap();
        let storage = storage_at(temp.path());
        let secret = RootSecret::Seeded {
            seed: "seed".to_string(),
            domain: "domain".to_string(),
        };
        storage
            .store("wallet", &secret, StoreMode::Unencrypted)
            .unwrap();
        assert_eq!(fs::read_to_string(victim).unwrap(), "unchanged");
        assert_eq!(storage.load("wallet").unwrap(), secret);
    }
}

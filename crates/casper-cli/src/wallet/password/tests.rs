use std::{fs, path::PathBuf};

use serde_json::{Value, json};
use tempfile::TempDir;

use super::*;
use crate::{
    network::{ConfigContext, ConfigInitOptions},
    secure_storage::{RootSecret, SecureStorage},
    wallet::{DerivationScheme, DerivedAccount, WalletMetadata, WalletType, save_metadata},
};

const OLD: &str = "old-test-password";
const NEW: &str = "new-test-password";
const NAME: &str = "password-test";

struct Fixture {
    dir: TempDir,
    config: StorageConfig,
}

impl Fixture {
    fn new(secret: &RootSecret, mode: StoreMode) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        fs::write(
            &config_path,
            format!(
                "[storage]\ntype = \"file\"\nroot_path = {:?}\n",
                dir.path().to_str().unwrap()
            ),
        )
        .unwrap();
        let context = ConfigContext::new(config_path, ConfigInitOptions::default());
        let config = StorageConfig::from_config(&context).unwrap();
        let fixture = Self { dir, config };
        FileSecureStorage::with_passwords(fixture.secrets_dir(), OLD, OLD, OLD)
            .store(NAME, secret, mode)
            .unwrap();
        let metadata = WalletMetadata {
            version: 1,
            name: NAME.to_string(),
            storage: StorageBackendKind::File,
            encrypted: matches!(mode, StoreMode::Encrypted),
            wallet_type: match secret {
                RootSecret::Bip39 { .. } => WalletType::Bip39,
                RootSecret::Seeded { .. } => WalletType::Seeded,
                RootSecret::LegacyPem { .. } => WalletType::LegacyPem {
                    public_key: "fixture public key".to_string(),
                },
            },
            derivation: DerivationScheme::Slip10Ed25519,
            domain: "original-domain".to_string(),
            accounts: vec![DerivedAccount {
                name: "existing-account".to_string(),
                index: 123,
                path: "m/44'/506'/0'/0'/123'".to_string(),
                public_key: "original-public-key".to_string(),
            }],
        };
        save_metadata(&fixture.metadata_path(), &metadata).unwrap();
        fixture
    }

    fn secrets_dir(&self) -> PathBuf {
        self.dir.path().join("secrets")
    }
    fn secret_path(&self) -> PathBuf {
        self.secrets_dir().join(format!("{NAME}.enc"))
    }
    fn metadata_path(&self) -> PathBuf {
        self.dir.path().join("wallets").join(format!("{NAME}.json"))
    }
    fn metadata(&self) -> Value {
        serde_json::from_slice(&fs::read(self.metadata_path()).unwrap()).unwrap()
    }
    fn change(
        &self,
        current: &str,
        new: &str,
        confirmation: &str,
        unencrypted: bool,
    ) -> Result<()> {
        let storage =
            FileSecureStorage::with_passwords(self.secrets_dir(), current, new, confirmation);
        update(
            &self.config,
            PasswordArgs {
                name: NAME.to_string(),
                unencrypted,
            },
            &storage,
        )
    }
    fn load(&self, password: &str) -> std::result::Result<RootSecret, Box<dyn std::error::Error>> {
        FileSecureStorage::with_passwords(self.secrets_dir(), password, password, password)
            .load(NAME)
    }
}

fn seeded_secret() -> RootSecret {
    RootSecret::Seeded {
        seed: "fixture-seed".to_string(),
        domain: "fixture-domain".to_string(),
    }
}

#[test]
fn changing_password_preserves_every_wallet_secret_type_and_metadata() {
    let pem = casper_types::SecretKey::ed25519_from_bytes([7; 32])
        .unwrap()
        .to_pem()
        .unwrap();
    for secret in [
        RootSecret::Bip39 { mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(), passphrase: "unchanged BIP-39 passphrase".to_string() },
        seeded_secret(),
        RootSecret::LegacyPem { pem },
    ] {
        let fixture = Fixture::new(&secret, StoreMode::Encrypted);
        let original_metadata = fixture.metadata();
        let original_secret: Value = serde_json::from_slice(&fs::read(fixture.secret_path()).unwrap()).unwrap();
        fixture.change(OLD, NEW, NEW, false).unwrap();

        assert!(fixture.load(OLD).is_err());
        assert_eq!(fixture.load(NEW).unwrap(), secret);
        assert_eq!(fixture.metadata(), original_metadata);
        let updated: Value = serde_json::from_slice(&fs::read(fixture.secret_path()).unwrap()).unwrap();
        assert_ne!(updated["kdf"]["salt"], original_secret["kdf"]["salt"]);
        assert_ne!(updated["nonce"], original_secret["nonce"]);
        assert!(updated.get("secret").is_none());
    }
}

#[test]
fn removing_then_adding_protection_preserves_keys_and_updates_metadata() {
    let secret = seeded_secret();
    let fixture = Fixture::new(&secret, StoreMode::Encrypted);
    let original_metadata = fixture.metadata();
    fixture.change(OLD, "unused", "different", true).unwrap();
    // A prompt-based backend can load this file without requesting any password.
    assert_eq!(
        FileSecureStorage::new(fixture.secrets_dir())
            .load(NAME)
            .unwrap(),
        secret
    );
    assert_eq!(fixture.metadata()["encrypted"], false);
    let plain: Value = serde_json::from_slice(&fs::read(fixture.secret_path()).unwrap()).unwrap();
    assert_eq!(plain["secret"]["seed"], "fixture-seed");
    assert!(plain.get("ciphertext").is_none());

    fixture
        .change("not-needed-for-plaintext", NEW, NEW, false)
        .unwrap();
    assert!(fixture.load(OLD).is_err());
    assert_eq!(fixture.load(NEW).unwrap(), secret);
    assert_eq!(fixture.metadata(), original_metadata);
}

#[test]
fn wrong_password_and_invalid_new_passwords_leave_both_files_unchanged() {
    let fixture = Fixture::new(&seeded_secret(), StoreMode::Encrypted);
    let original_secret = fs::read(fixture.secret_path()).unwrap();
    let original_metadata = fs::read(fixture.metadata_path()).unwrap();
    for (current, new, confirmation, unencrypted) in [
        ("incorrect", NEW, NEW, false),
        ("incorrect", NEW, NEW, true),
        (OLD, "", "", false),
        (OLD, NEW, "does-not-match", false),
    ] {
        assert!(
            fixture
                .change(current, new, confirmation, unencrypted)
                .is_err()
        );
        assert_eq!(fs::read(fixture.secret_path()).unwrap(), original_secret);
        assert_eq!(
            fs::read(fixture.metadata_path()).unwrap(),
            original_metadata
        );
    }
    assert_eq!(fixture.load(OLD).unwrap(), seeded_secret());
}

#[test]
fn tampered_ciphertext_cannot_be_reencrypted_or_exported() {
    let fixture = Fixture::new(&seeded_secret(), StoreMode::Encrypted);
    let mut encrypted: Value =
        serde_json::from_slice(&fs::read(fixture.secret_path()).unwrap()).unwrap();
    let mut bytes = hex::decode(encrypted["ciphertext"].as_str().unwrap()).unwrap();
    bytes[0] ^= 1;
    encrypted["ciphertext"] = json!(hex::encode(bytes));
    fs::write(
        fixture.secret_path(),
        serde_json::to_vec(&encrypted).unwrap(),
    )
    .unwrap();
    let before = fs::read(fixture.secret_path()).unwrap();
    let metadata = fs::read(fixture.metadata_path()).unwrap();
    for unencrypted in [false, true] {
        assert!(fixture.change(OLD, NEW, NEW, unencrypted).is_err());
        assert_eq!(fs::read(fixture.secret_path()).unwrap(), before);
        assert_eq!(fs::read(fixture.metadata_path()).unwrap(), metadata);
    }
}

#[test]
fn keyring_wallets_are_rejected_without_accessing_os_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, "[storage]\ntype = \"keyring\"\n").unwrap();
    let config =
        StorageConfig::from_config(&ConfigContext::new(path, ConfigInitOptions::default()))
            .unwrap();
    for unencrypted in [false, true] {
        let error = handle(
            &config,
            PasswordArgs {
                name: NAME.to_string(),
                unencrypted,
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("keyring protection is managed by the operating system")
        );
    }
}

#[test]
fn missing_wallet_and_invalid_names_fail_before_prompting_or_writing() {
    let fixture = Fixture::new(&seeded_secret(), StoreMode::Unencrypted);
    let storage = FileSecureStorage::new(fixture.secrets_dir());
    for name in ["missing-wallet", "../password-test"] {
        assert!(
            update(
                &fixture.config,
                PasswordArgs {
                    name: name.to_string(),
                    unencrypted: false
                },
                &storage
            )
            .is_err()
        );
    }
    assert_eq!(fixture.metadata()["encrypted"], false);
}

#[cfg(unix)]
#[test]
fn secret_and_metadata_permissions_remain_restrictive_in_both_modes() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new(&seeded_secret(), StoreMode::Encrypted);
    fixture.change(OLD, NEW, NEW, false).unwrap();
    fixture.change(NEW, "unused", "unused", true).unwrap();
    for path in [
        fixture.secret_path(),
        fixture.metadata_path(),
        fixture.secrets_dir().join(format!("{NAME}.lock")),
    ] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    for path in [
        fixture.secrets_dir(),
        fixture.metadata_path().parent().unwrap().to_path_buf(),
    ] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

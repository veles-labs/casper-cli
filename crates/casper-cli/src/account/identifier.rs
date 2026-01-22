use anyhow::{Context, Result, anyhow, bail};

use casper_types::{PublicKey, account::AccountHash, bytesrepr::deserialize_from_slice};
use veles_casper_rust_sdk::jsonrpc::AccountIdentifier;

use crate::storage::StorageConfig;
use crate::wallet;

const ACCOUNT_HASH_LEN: usize = 32;

#[derive(Debug)]
pub(crate) enum ResolvedAccount {
    WalletRef {
        wallet_name: String,
        account_name: String,
        public_key: PublicKey,
    },
    LegacyWallet {
        wallet_name: String,
        public_key: PublicKey,
    },
    AccountHash(AccountHash),
    PublicKey(PublicKey),
}

impl ResolvedAccount {
    pub(crate) fn identifier(&self) -> AccountIdentifier {
        match self {
            ResolvedAccount::WalletRef { public_key, .. }
            | ResolvedAccount::LegacyWallet { public_key, .. }
            | ResolvedAccount::PublicKey(public_key) => {
                AccountIdentifier::PublicKey(public_key.clone())
            }
            ResolvedAccount::AccountHash(account_hash) => {
                AccountIdentifier::AccountHash(*account_hash)
            }
        }
    }

    pub(crate) fn public_key(&self) -> Option<&PublicKey> {
        match self {
            ResolvedAccount::WalletRef { public_key, .. }
            | ResolvedAccount::LegacyWallet { public_key, .. }
            | ResolvedAccount::PublicKey(public_key) => Some(public_key),
            ResolvedAccount::AccountHash(_) => None,
        }
    }

    pub(crate) fn display_name(&self, fallback: &str) -> String {
        match self {
            ResolvedAccount::WalletRef {
                wallet_name,
                account_name,
                ..
            } => format!("{wallet_name}:{account_name}"),
            ResolvedAccount::LegacyWallet { wallet_name, .. } => wallet_name.clone(),
            ResolvedAccount::AccountHash(_) | ResolvedAccount::PublicKey(_) => fallback.to_string(),
        }
    }
}

pub(crate) fn resolve(storage: &StorageConfig, input: &str) -> Result<ResolvedAccount> {
    if let Some((wallet_name, account_name)) = input.split_once(':') {
        if wallet_name.is_empty() || account_name.is_empty() {
            bail!("wallet/account reference must be <wallet>:<account>");
        }
        let public_key_hex =
            wallet::resolve_account_public_key(storage, wallet_name, account_name)?;
        let public_key = parse_public_key_hex(&public_key_hex)?;
        return Ok(ResolvedAccount::WalletRef {
            wallet_name: wallet_name.to_string(),
            account_name: account_name.to_string(),
            public_key,
        });
    }
    if let Some(public_key_hex) = wallet::try_resolve_legacy_public_key(storage, input)? {
        let public_key = parse_public_key_hex(&public_key_hex)?;
        return Ok(ResolvedAccount::LegacyWallet {
            wallet_name: input.to_string(),
            public_key,
        });
    }
    parse_identifier(input)
}

pub(crate) fn parse_identifier(input: &str) -> Result<ResolvedAccount> {
    let bytes = hex::decode(input).context("invalid public key hex")?;
    if bytes.len() == ACCOUNT_HASH_LEN {
        let mut hash = [0u8; ACCOUNT_HASH_LEN];
        hash.copy_from_slice(&bytes);
        return Ok(ResolvedAccount::AccountHash(AccountHash::new(hash)));
    }
    let public_key: PublicKey =
        deserialize_from_slice(&bytes).map_err(|_| anyhow!("invalid public key bytes"))?;
    Ok(ResolvedAccount::PublicKey(public_key))
}

fn parse_public_key_hex(input: &str) -> Result<PublicKey> {
    let bytes = hex::decode(input).context("invalid public key hex")?;
    let public_key: PublicKey =
        deserialize_from_slice(&bytes).map_err(|_| anyhow!("invalid public key bytes"))?;
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::{ResolvedAccount, parse_identifier, resolve};
    use anyhow::Result;
    use casper_types::bytesrepr::ToBytes;
    use casper_types::{PublicKey, SecretKey};
    use serde_json::json;
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    use crate::network::{ConfigContext, ConfigInitOptions};
    use crate::storage::StorageConfig;

    fn write_config(config_path: &Path, storage_root: &Path) -> Result<()> {
        let contents = format!(
            "[storage]\n\
type = \"file\"\n\
root_path = \"{}\"\n",
            storage_root.display()
        );
        fs::write(config_path, contents)?;
        Ok(())
    }

    fn test_storage_config(temp_dir: &TempDir) -> Result<(StorageConfig, PathBuf)> {
        let storage_root = temp_dir.path().join("storage");
        fs::create_dir_all(&storage_root)?;
        let config_path = temp_dir.path().join("config.toml");
        write_config(&config_path, &storage_root)?;
        let context = ConfigContext::new(config_path, ConfigInitOptions::default());
        let storage = StorageConfig::from_config(&context)?;
        Ok((storage, storage_root))
    }

    fn write_wallet_metadata(
        storage_root: &Path,
        wallet_name: &str,
        metadata: serde_json::Value,
    ) -> Result<()> {
        let wallets_dir = storage_root.join("wallets");
        fs::create_dir_all(&wallets_dir)?;
        let path = wallets_dir.join(format!("{wallet_name}.json"));
        let contents = serde_json::to_string_pretty(&metadata)?;
        fs::write(path, contents)?;
        Ok(())
    }

    fn write_wallet_secret(storage_root: &Path, wallet_name: &str) -> Result<()> {
        let secrets_dir = storage_root.join("secrets");
        fs::create_dir_all(&secrets_dir)?;
        let path = secrets_dir.join(format!("{wallet_name}.enc"));
        fs::write(path, "{}")?;
        Ok(())
    }

    fn sample_public_key(tag: u8) -> PublicKey {
        let secret_key = SecretKey::ed25519_from_bytes([tag; 32]).expect("secret key");
        PublicKey::from(&secret_key)
    }

    #[test]
    fn parses_account_hash_hex() -> Result<()> {
        let account_hash = casper_types::account::AccountHash::new([1u8; 32]);
        let hex = hex::encode(account_hash.as_bytes());
        let resolved = parse_identifier(&hex)?;
        match resolved {
            ResolvedAccount::AccountHash(value) => assert_eq!(value, account_hash),
            _ => panic!("expected account hash"),
        }
        Ok(())
    }

    #[test]
    fn parses_public_key_hex() -> Result<()> {
        let public_key = sample_public_key(2);
        let hex = hex::encode(public_key.to_bytes().expect("public key bytes"));
        let resolved = parse_identifier(&hex)?;
        match resolved {
            ResolvedAccount::PublicKey(value) => assert_eq!(value, public_key),
            _ => panic!("expected public key"),
        }
        Ok(())
    }

    #[test]
    fn parse_rejects_invalid_hex() {
        let err = parse_identifier("not-hex").expect_err("invalid hex");
        let message = format!("{err}");
        assert!(message.contains("invalid public key hex"));
    }

    #[test]
    fn parse_rejects_invalid_public_key_bytes() {
        let hex = hex::encode(vec![9u8; 33]);
        let err = parse_identifier(&hex).expect_err("invalid public key bytes");
        let message = format!("{err}");
        assert!(message.contains("invalid public key bytes"));
    }

    #[test]
    fn resolves_wallet_reference() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (storage, storage_root) = test_storage_config(&temp_dir)?;
        let public_key = sample_public_key(3);
        let public_key_hex = hex::encode(public_key.to_bytes().expect("public key bytes"));
        write_wallet_metadata(
            &storage_root,
            "wallet1",
            json!({
                "version": 1,
                "name": "wallet1",
                "storage": "file",
                "encrypted": true,
                "wallet_type": "bip39",
                "derivation": "bip32_secp256k1",
                "domain": "bip39",
                "accounts": [{
                    "name": "account-0",
                    "index": 0,
                    "path": "m/44'/506'/0'/0/0",
                    "public_key": public_key_hex,
                }],
            }),
        )?;
        let resolved = resolve(&storage, "wallet1:account-0")?;
        match &resolved {
            ResolvedAccount::WalletRef {
                wallet_name,
                account_name,
                public_key: resolved_key,
            } => {
                assert_eq!(wallet_name, "wallet1");
                assert_eq!(account_name, "account-0");
                assert_eq!(resolved_key, &public_key);
            }
            _ => panic!("expected wallet reference"),
        }
        assert_eq!(resolved.display_name("fallback"), "wallet1:account-0");
        Ok(())
    }

    #[test]
    fn resolves_legacy_wallet() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (storage, storage_root) = test_storage_config(&temp_dir)?;
        let public_key = sample_public_key(4);
        let public_key_hex = hex::encode(public_key.to_bytes().expect("public key bytes"));
        write_wallet_metadata(
            &storage_root,
            "legacywallet",
            json!({
                "version": 1,
                "name": "legacywallet",
                "storage": "file",
                "encrypted": true,
                "wallet_type": { "legacy_pem": { "public_key": public_key_hex } },
                "derivation": "bip32_secp256k1",
                "domain": "legacy_pem",
                "accounts": [],
            }),
        )?;
        write_wallet_secret(&storage_root, "legacywallet")?;
        let resolved = resolve(&storage, "legacywallet")?;
        match &resolved {
            ResolvedAccount::LegacyWallet {
                wallet_name,
                public_key: resolved_key,
            } => {
                assert_eq!(wallet_name, "legacywallet");
                assert_eq!(resolved_key, &public_key);
            }
            _ => panic!("expected legacy wallet"),
        }
        assert_eq!(resolved.display_name("fallback"), "legacywallet");
        Ok(())
    }

    #[test]
    fn resolves_account_hash_input() -> Result<()> {
        let account_hash = casper_types::account::AccountHash::new([5u8; 32]);
        let hex = hex::encode(account_hash.as_bytes());
        let resolved = parse_identifier(&hex)?;
        assert_eq!(resolved.display_name("fallback"), "fallback");
        match resolved {
            ResolvedAccount::AccountHash(value) => assert_eq!(value, account_hash),
            _ => panic!("expected account hash"),
        }
        Ok(())
    }

    #[test]
    fn resolve_rejects_empty_wallet_reference() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (storage, _storage_root) = test_storage_config(&temp_dir)?;
        let err = resolve(&storage, "wallet:").expect_err("empty account name");
        let message = format!("{err}");
        assert!(message.contains("wallet/account reference must be <wallet>:<account>"));
        Ok(())
    }
}

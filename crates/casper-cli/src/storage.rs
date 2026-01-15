use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::network;
use crate::secure_storage::SecureStorage;
use crate::secure_storage::file::FileSecureStorage;
use crate::secure_storage::keyring::KeyringSecureStorage;

const CONFIG_DIR_NAME: &str = "casper-cli";
const SECRETS_DIR_NAME: &str = "secrets";

#[derive(Clone, Debug)]
pub enum StorageBackend {
    File { base_dir: PathBuf },
    Keyring,
}

#[derive(Clone, Debug)]
pub struct StorageConfig {
    backend: StorageBackend,
}

impl StorageConfig {
    pub(crate) fn from_config(context: &network::ConfigContext) -> Result<Self> {
        network::ensure_default_config_with_options(context.path(), context.options())?;
        Self::from_config_path(context.path(), context.options().storage_override.as_ref())
    }

    pub fn base_dir(&self) -> Result<PathBuf> {
        match &self.backend {
            StorageBackend::File { base_dir } => Ok(base_dir.clone()),
            StorageBackend::Keyring => default_base_dir(),
        }
    }

    pub fn is_keyring(&self) -> bool {
        matches!(self.backend, StorageBackend::Keyring)
    }

    pub fn secret_storage(&self) -> Result<Box<dyn SecureStorage>> {
        match &self.backend {
            StorageBackend::File { base_dir } => Ok(Box::new(FileSecureStorage::new(
                base_dir.join(SECRETS_DIR_NAME),
            ))),
            StorageBackend::Keyring => Ok(Box::new(KeyringSecureStorage::new())),
        }
    }

    pub fn secret_location(&self, wallet_name: &str) -> Result<String> {
        match &self.backend {
            StorageBackend::File { base_dir } => Ok(base_dir
                .join(SECRETS_DIR_NAME)
                .join(format!("{}.enc", wallet_name))
                .display()
                .to_string()),
            StorageBackend::Keyring => Ok("keyring".to_string()),
        }
    }

    fn from_config_path(
        path: &Path,
        storage_override: Option<&network::StorageOverride>,
    ) -> Result<Self> {
        if let Some(override_choice) = storage_override {
            return Ok(Self {
                backend: match override_choice {
                    network::StorageOverride::Keyring => StorageBackend::Keyring,
                    network::StorageOverride::File { root_path } => {
                        if root_path.trim().is_empty() {
                            bail!("--file-storage root_path is empty");
                        }
                        StorageBackend::File {
                            base_dir: file_base_dir_from_path(root_path)?,
                        }
                    }
                },
            });
        }
        let data = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let config: StorageConfigToml =
            toml::from_str(&data).with_context(|| format!("failed to parse {}", path.display()))?;
        let storage = config
            .storage
            .ok_or_else(|| anyhow::anyhow!("config.toml missing [storage] section"))?;
        match storage {
            StorageSection::File { root_path } => {
                if root_path.trim().is_empty() {
                    bail!("config.toml storage.file.root_path is empty");
                }
                let base_dir = file_base_dir_from_path(&root_path)?;
                Ok(Self {
                    backend: StorageBackend::File { base_dir },
                })
            }
            StorageSection::Keyring => Ok(Self {
                backend: StorageBackend::Keyring,
            }),
        }
    }
}

#[derive(Deserialize)]
struct StorageConfigToml {
    storage: Option<StorageSection>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StorageSection {
    File { root_path: String },
    Keyring,
}

fn file_base_dir_from_path(path: &str) -> Result<PathBuf> {
    let path = PathBuf::from(path);
    let is_json = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    if is_json || path.is_file() {
        return path
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| anyhow::anyhow!("storage path has no parent directory"));
    }
    Ok(path)
}

fn default_base_dir() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .or_else(|| std::env::current_dir().ok())
        .context("unable to determine config directory")?
        .join(CONFIG_DIR_NAME))
}

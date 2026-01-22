use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use dialoguer::{Input, Select, theme::ColorfulTheme};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

const CONFIG_FILE_NAME: &str = "config.toml";

mod list;
mod use_cmd;

#[derive(Args)]
/// Network-related CLI entry point.
pub struct NetworkArgs {
    #[command(subcommand)]
    command: NetworkCommand,
}

#[derive(Subcommand)]
/// Network subcommands.
pub enum NetworkCommand {
    /// Select the active network.
    Use(use_cmd::UseArgs),
    /// List configured networks and the active one.
    List,
}

#[derive(Serialize, Deserialize)]
struct AppConfig {
    #[serde(default)]
    active: Option<String>,
    #[serde(default)]
    networks: BTreeMap<String, NetworkEntry>,
    #[serde(default)]
    storage: Option<StorageSection>,
}

#[derive(Serialize, Deserialize, Clone)]
struct NetworkEntry {
    chain_name: String,
    rest: String,
    sse: String,
    rpc: String,
    binary_port: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StorageSection {
    File { root_path: String },
    Keyring,
}

#[derive(Clone, Debug)]
pub(crate) enum StorageOverride {
    Keyring,
    File { root_path: String },
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ConfigInitOptions {
    pub(crate) no_interactive: bool,
    pub(crate) storage_override: Option<StorageOverride>,
}

pub(crate) struct ConfigContext {
    path: PathBuf,
    options: ConfigInitOptions,
}

impl ConfigContext {
    pub(crate) fn new(path: PathBuf, options: ConfigInitOptions) -> Self {
        Self { path, options }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn options(&self) -> &ConfigInitOptions {
        &self.options
    }
}

pub fn handle(context: &ConfigContext, args: NetworkArgs) -> Result<()> {
    match args.command {
        NetworkCommand::Use(command) => use_cmd::handle(context, command),
        NetworkCommand::List => list::handle(context),
    }
}

fn resolve_network_key(config: &AppConfig, name: &str) -> Result<String> {
    if config.networks.contains_key(name) {
        return Ok(name.to_string());
    }

    let mut matches = config
        .networks
        .iter()
        .filter(|(_key, entry)| entry.chain_name == name)
        .collect::<Vec<_>>();

    if matches.is_empty() {
        let available = config
            .networks
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        bail!("unknown network '{name}'. Available: {available}");
    }

    if matches.len() > 1 {
        bail!("ambiguous chain name '{name}'. Use a network key instead.");
    }

    let (key, _entry) = matches.remove(0);
    Ok(key.clone())
}

fn load_or_init_config_with_options(path: &Path, options: &ConfigInitOptions) -> Result<AppConfig> {
    if !path.exists() {
        println!("Missing config file. Initializing new one");
        let override_storage = options
            .storage_override
            .as_ref()
            .map(storage_section_from_override)
            .transpose()?;
        let config = if let Some(storage) = override_storage {
            config_with_storage(storage)
        } else if options.no_interactive {
            bail!(
                "--no-interactive requires --keyring or --file-storage <ROOT_PATH> when config.toml is missing"
            );
        } else if io::stdin().is_terminal() && io::stdout().is_terminal() {
            prompt_default_config()?
        } else {
            println!("No interactive terminal detected; using default storage settings.");
            default_config()?
        };
        let preview = toml::to_string_pretty(&config)?;
        println!("\nGenerated config.toml:\n{preview}");
        println!("Run `casper-cli config edit` to open an editor and you can modify it.");
        save_config(path, &config)?;
        if let Some(active) = config.active.as_deref() {
            println!("Active network: {active}");
            println!("Switch networks with `casper-cli network use <name>`.");
        }
        return Ok(config);
    }
    let data =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut config: AppConfig =
        toml::from_str(&data).with_context(|| format!("failed to parse {}", path.display()))?;
    if config.active.is_none() {
        if config.networks.contains_key("testnet") {
            config.active = Some("testnet".to_string());
            save_config(path, &config)?;
        } else if config.networks.contains_key("devnet") {
            config.active = Some("devnet".to_string());
            save_config(path, &config)?;
        }
    }
    Ok(config)
}

fn save_config(path: &Path, config: &AppConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let data = toml::to_string_pretty(config)?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

pub(crate) fn ensure_default_config_with_options(
    path: &Path,
    options: &ConfigInitOptions,
) -> Result<()> {
    if !path.exists() {
        let _config = load_or_init_config_with_options(path, options)?;
    }
    Ok(())
}

pub(crate) fn default_config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(CONFIG_FILE_NAME))
}

pub(crate) fn active_network_rpc(context: &ConfigContext) -> Result<(String, String)> {
    let config_path = context.path();
    let config = load_or_init_config_with_options(config_path, context.options())?;
    let active = config
        .active
        .clone()
        .ok_or_else(|| anyhow!("active network not set"))?;
    let entry = config
        .networks
        .get(&active)
        .ok_or_else(|| anyhow!("active network '{active}' not found"))?;
    if entry.rpc.trim().is_empty() {
        bail!("active network '{active}' has no rpc endpoint configured");
    }
    Ok((active, entry.rpc.clone()))
}

pub(crate) fn active_network_binary_port(context: &ConfigContext) -> Result<(String, String)> {
    let config_path = context.path();
    let config = load_or_init_config_with_options(config_path, context.options())?;
    let active = config
        .active
        .clone()
        .ok_or_else(|| anyhow!("active network not set"))?;
    let entry = config
        .networks
        .get(&active)
        .ok_or_else(|| anyhow!("active network '{active}' not found"))?;
    let binary_port = entry.binary_port.trim();
    if binary_port.is_empty() {
        bail!("active network '{active}' has no binary port configured");
    }
    Ok((active, binary_port.to_string()))
}

pub(crate) fn active_network_name_and_chain_name(
    context: &ConfigContext,
) -> Result<(String, String)> {
    let config_path = context.path();
    let config = load_or_init_config_with_options(config_path, context.options())?;
    let active = config
        .active
        .clone()
        .ok_or_else(|| anyhow!("active network not set"))?;
    let entry = config
        .networks
        .get(&active)
        .ok_or_else(|| anyhow!("active network '{active}' not found"))?;
    if entry.chain_name.trim().is_empty() {
        bail!("active network '{active}' has no chain name configured");
    }
    Ok((active, entry.chain_name.clone()))
}

pub(crate) fn active_network_chain_name(context: &ConfigContext) -> Result<String> {
    let config_path = context.path();
    let config = load_or_init_config_with_options(config_path, context.options())?;
    let active = config
        .active
        .clone()
        .ok_or_else(|| anyhow!("active network not set"))?;
    let entry = config
        .networks
        .get(&active)
        .ok_or_else(|| anyhow!("active network '{active}' not found"))?;
    if entry.chain_name.trim().is_empty() {
        bail!("active network '{active}' has no chain name configured");
    }
    Ok(entry.chain_name.clone())
}

fn config_dir() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .or_else(|| std::env::current_dir().ok())
        .context("unable to determine config directory")?
        .join("casper-cli"))
}

fn default_config() -> Result<AppConfig> {
    Ok(config_with_storage(StorageSection::Keyring))
}

fn config_with_storage(storage: StorageSection) -> AppConfig {
    let mut networks = BTreeMap::new();
    networks.insert(
        "devnet".to_string(),
        NetworkEntry {
            chain_name: "casper-dev".to_string(),
            rest: "http://127.0.0.1:14101".to_string(),
            sse: "http://127.0.0.1:18101/events".to_string(),
            rpc: "http://127.0.0.1:11101/rpc".to_string(),
            binary_port: "127.0.0.1:28101".to_string(),
        },
    );
    networks.insert(
        "mainnet".to_string(),
        NetworkEntry {
            chain_name: "casper".to_string(),
            rest: "https://api.veleslabs.xyz/mainnet/".to_string(),
            sse: "https://api.veleslabs.xyz/mainnet/events".to_string(),
            rpc: "https://api.veleslabs.xyz/mainnet/rpc".to_string(),
            binary_port: "wss://api.veleslabs.xyz/mainnet/binary".to_string(),
        },
    );
    networks.insert(
        "testnet".to_string(),
        NetworkEntry {
            chain_name: "casper-test".to_string(),
            rest: "https://api.veleslabs.xyz/testnet/".to_string(),
            sse: "https://api.veleslabs.xyz/testnet/events".to_string(),
            rpc: "https://api.veleslabs.xyz/testnet/rpc".to_string(),
            binary_port: "wss://api.veleslabs.xyz/testnet/binary".to_string(),
        },
    );

    AppConfig {
        active: Some("testnet".to_string()),
        networks,
        storage: Some(storage),
    }
}

fn prompt_default_config() -> Result<AppConfig> {
    let theme = ColorfulTheme::default();
    let storage = prompt_storage_section(&theme)?;
    Ok(config_with_storage(storage))
}

fn storage_section_from_override(override_choice: &StorageOverride) -> Result<StorageSection> {
    match override_choice {
        StorageOverride::Keyring => Ok(StorageSection::Keyring),
        StorageOverride::File { root_path } => {
            if root_path.trim().is_empty() {
                bail!("--file-storage root_path is empty");
            }
            Ok(StorageSection::File {
                root_path: root_path.clone(),
            })
        }
    }
}

fn prompt_storage_section(theme: &ColorfulTheme) -> Result<StorageSection> {
    let items = [
        "OS-based keyring where master secrets will be securely stored (default)",
        "File based secure storage (good for development, tests, CI, etc.)",
    ];
    let selection = Select::with_theme(theme)
        .with_prompt("Which secret storage backend do you want to use?")
        .items(&items)
        .default(0)
        .interact()
        .context("read storage backend selection")?;
    match selection {
        0 => Ok(StorageSection::Keyring),
        1 => Ok(StorageSection::File {
            root_path: prompt_file_storage_root(theme)?,
        }),
        _ => bail!("invalid storage selection"),
    }
}

fn prompt_file_storage_root(theme: &ColorfulTheme) -> Result<String> {
    let default_root = default_storage_root()?;
    let items = [
        format!("Default location for file storage (~projectdirs based default: {default_root})"),
        "Custom".to_string(),
    ];
    let selection = Select::with_theme(theme)
        .with_prompt("Where should file-based storage live?")
        .items(&items)
        .default(0)
        .interact()
        .context("read storage location selection")?;
    match selection {
        0 => Ok(default_root),
        1 => {
            let prompt = format!(
                "Enter custom storage location (~projectdirs based default: {default_root})"
            );
            let input: String = Input::with_theme(theme)
                .with_prompt(prompt)
                .default(default_root.clone())
                .interact_text()
                .context("read custom storage location")?;
            let trimmed = input.trim();
            if trimmed.is_empty() {
                return Ok(default_root);
            }
            Ok(expand_tilde(trimmed))
        }
        _ => bail!("invalid storage location selection"),
    }
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).display().to_string();
        }
    } else if path == "~"
        && let Some(home) = dirs::home_dir()
    {
        return home.display().to_string();
    }
    path.to_string()
}

fn default_storage_root() -> Result<String> {
    Ok(config_dir()?.display().to_string())
}

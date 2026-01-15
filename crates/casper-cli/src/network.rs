use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use comfy_table::{Cell, Table};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const CONFIG_FILE_NAME: &str = "config.toml";

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
    Use(NetworkUseArgs),
    /// List configured networks and the active one.
    List,
}

#[derive(Args)]
/// Arguments for selecting a network.
pub struct NetworkUseArgs {
    /// Name of the network (key or chain name).
    name: String,
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
    #[serde(default, alias = "binary")]
    binary_port: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StorageSection {
    File { root_path: String },
    Keyring,
}

pub fn handle(args: NetworkArgs) -> Result<()> {
    match args.command {
        NetworkCommand::Use(command) => network_use(command),
        NetworkCommand::List => network_list(),
    }
}

fn network_use(args: NetworkUseArgs) -> Result<()> {
    let config_path = config_path()?;
    let mut config = load_or_init_config(&config_path)?;
    let key = resolve_network_key(&config, &args.name)?;
    let entry = config
        .networks
        .get(&key)
        .cloned()
        .ok_or_else(|| anyhow!("network '{key}' not found"))?;
    config.active = Some(key.clone());
    save_config(&config_path, &config)?;
    println!("Active network: {key}");
    println!("Chain name: {}", entry.chain_name);
    println!("REST: {}", entry.rest);
    println!("SSE: {}", entry.sse);
    println!("RPC: {}", entry.rpc);
    if let Some(binary_port) = entry.binary_port.as_deref() {
        println!("Binary port: {}", binary_port);
    }
    Ok(())
}

fn network_list() -> Result<()> {
    let config_path = config_path()?;
    let config = load_or_init_config(&config_path)?;

    if config.networks.is_empty() {
        println!("No networks configured.");
        return Ok(());
    }

    let active = config.active.as_deref();
    let mut table = Table::new();
    table.set_header(vec![
        "Name",
        "Chain",
        "Active",
        "REST",
        "SSE",
        "RPC",
        "Binary port",
    ]);
    for (name, entry) in config.networks {
        let is_active = active == Some(name.as_str());
        table.add_row(vec![
            Cell::new(&name),
            Cell::new(&entry.chain_name),
            Cell::new(if is_active { "yes" } else { "" }),
            Cell::new(&entry.rest),
            Cell::new(&entry.sse),
            Cell::new(&entry.rpc),
            Cell::new(entry.binary_port.as_deref().unwrap_or_default()),
        ]);
    }

    println!("{table}");
    Ok(())
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

fn load_or_init_config(path: &Path) -> Result<AppConfig> {
    if !path.exists() {
        let config = default_config()?;
        save_config(path, &config)?;
        return Ok(config);
    }
    let data =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut config: AppConfig =
        toml::from_str(&data).with_context(|| format!("failed to parse {}", path.display()))?;
    if config.active.is_none() && config.networks.contains_key("devnet") {
        config.active = Some("devnet".to_string());
        save_config(path, &config)?;
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

pub(crate) fn ensure_default_config(path: &Path) -> Result<()> {
    if !path.exists() {
        let _config = load_or_init_config(path)?;
    }
    Ok(())
}

pub(crate) fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(CONFIG_FILE_NAME))
}

pub(crate) fn active_network_rpc() -> Result<(String, String)> {
    let config_path = config_path()?;
    let config = load_or_init_config(&config_path)?;
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

pub(crate) fn active_network_binary_port() -> Result<(String, String)> {
    let config_path = config_path()?;
    let config = load_or_init_config(&config_path)?;
    let active = config
        .active
        .clone()
        .ok_or_else(|| anyhow!("active network not set"))?;
    let entry = config
        .networks
        .get(&active)
        .ok_or_else(|| anyhow!("active network '{active}' not found"))?;
    let binary_port = entry.binary_port.as_deref().unwrap_or_default().trim();
    if binary_port.is_empty() {
        bail!("active network '{active}' has no binary port configured");
    }
    Ok((active, binary_port.to_string()))
}

pub(crate) fn active_network_chain_name() -> Result<String> {
    let config_path = config_path()?;
    let config = load_or_init_config(&config_path)?;
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
    let mut networks = BTreeMap::new();
    networks.insert(
        "devnet".to_string(),
        NetworkEntry {
            chain_name: "casper-dev".to_string(),
            rest: "http://127.0.0.1:14101".to_string(),
            sse: "http://127.0.0.1:18101/events".to_string(),
            rpc: "http://127.0.0.1:11101/rpc".to_string(),
            binary_port: Some("127.0.0.1:11102".to_string()),
        },
    );

    Ok(AppConfig {
        active: Some("devnet".to_string()),
        networks,
        storage: Some(StorageSection::File {
            root_path: default_storage_root()?,
        }),
    })
}

fn default_storage_root() -> Result<String> {
    Ok(config_dir()?.display().to_string())
}

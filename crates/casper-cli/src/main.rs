mod arguments;
mod account;
mod cl_type;
mod cl_value;
mod config;
mod contract_runtime;
mod network;
mod secure_storage;
mod slip0010;
pub mod storage;
mod transaction;
pub mod utils;
mod wallet;
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "casper-cli",
    version,
    about = "Casper Network command-line interface"
)]
/// Top-level CLI entry point.
struct Cli {
    /// Disable interactive prompts when initializing config.
    #[arg(long, global = true)]
    no_interactive: bool,
    /// Force OS keyring storage (overrides config.toml).
    #[arg(long, global = true, conflicts_with = "file_storage")]
    keyring: bool,
    /// Force file-based storage with the provided root path (overrides config.toml).
    #[arg(
        long,
        global = true,
        value_name = "ROOT_PATH",
        conflicts_with = "keyring"
    )]
    file_storage: Option<PathBuf>,
    /// Use a custom config.toml path instead of the projectdirs default.
    #[arg(long, global = true, value_name = "PATH")]
    config_path: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
/// Top-level subcommands.
enum Command {
    /// Wallet management commands.
    Wallet(wallet::WalletArgs),
    /// Network selection commands.
    Network(network::NetworkArgs),
    /// Config management commands.
    Config(config::ConfigArgs),
    /// Build and submit transactions.
    #[command(name = "transaction", alias = "tx")]
    Transaction(transaction::TxArgs),
    /// Account inspection commands.
    Account(account::AccountArgs),
}

fn main() -> Result<()> {
    // Ensure rustls has a process-level provider before any TLS is used.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    let config_path = match cli.config_path.clone() {
        Some(path) => path,
        None => network::default_config_path()?,
    };
    let storage_override = match (cli.keyring, cli.file_storage.as_ref()) {
        (true, None) => Some(network::StorageOverride::Keyring),
        (false, Some(path)) => Some(network::StorageOverride::File {
            root_path: path.display().to_string(),
        }),
        _ => None,
    };
    let config_options = network::ConfigInitOptions {
        no_interactive: cli.no_interactive,
        storage_override,
    };
    let config_context = network::ConfigContext::new(config_path, config_options);
    network::ensure_default_config_with_options(config_context.path(), config_context.options())?;
    let storage = storage::StorageConfig::from_config(&config_context)?;
    match cli.command {
        Command::Wallet(command) => wallet::handle(&storage, &config_context, command),
        Command::Network(command) => network::handle(&config_context, command),
        Command::Config(command) => config::handle(&config_context, command),
        Command::Transaction(command) => transaction::handle(&storage, &config_context, command),
        Command::Account(command) => account::handle(&storage, &config_context, command),
    }
}

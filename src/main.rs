mod balance;
mod config;
mod network;
mod secure_storage;
pub mod storage;
mod transaction;
mod wallet;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "casper",
    version,
    about = "Casper Network command-line interface"
)]
/// Top-level CLI entry point.
struct Cli {
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
    /// Fetch the balance for a wallet account or public key.
    Balance(balance::BalanceArgs),
    /// Build and submit transactions.
    #[command(name = "transaction", alias = "tx")]
    Transaction(transaction::TxArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = storage::StorageConfig::from_config()?;
    match cli.command {
        Command::Wallet(command) => wallet::handle(&storage, command),
        Command::Network(command) => network::handle(command),
        Command::Config(command) => config::handle(command),
        Command::Balance(command) => balance::handle(&storage, command),
        Command::Transaction(command) => transaction::handle(&storage, command),
    }
}

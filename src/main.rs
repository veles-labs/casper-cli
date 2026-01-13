mod balance;
mod config;
mod network;
mod secure_storage;
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
    /// Override the default storage location (file or directory).
    #[arg(long)]
    wallet_path: Option<std::path::PathBuf>,
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Wallet(command) => wallet::handle(&cli.wallet_path, command),
        Command::Network(command) => network::handle(command),
        Command::Config(command) => config::handle(command),
        Command::Balance(command) => balance::handle(&cli.wallet_path, command),
    }
}

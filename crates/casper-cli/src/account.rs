use anyhow::Result;
use clap::{Args, Subcommand};

mod balance;
mod identifier;
mod view;

use crate::network;
use crate::storage::StorageConfig;

#[derive(Args)]
/// Account-related CLI entry point.
pub struct AccountArgs {
    #[command(subcommand)]
    command: AccountCommand,
}

#[derive(Subcommand)]
/// Account subcommands.
pub enum AccountCommand {
    /// Fetch the balance for a wallet account or public key.
    #[command(name = "balance")]
    Balance(balance::BalanceArgs),
    /// View account details from the network.
    #[command(name = "view")]
    View(view::ViewArgs),
}

pub fn handle(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    args: AccountArgs,
) -> Result<()> {
    match args.command {
        AccountCommand::Balance(command) => balance::handle(storage, context, command),
        AccountCommand::View(command) => view::handle(storage, context, command),
    }
}

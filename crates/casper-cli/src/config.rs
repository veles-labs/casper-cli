use anyhow::Result;
use clap::{Args, Subcommand};

mod edit;

#[derive(Args)]
/// Config-related CLI entry point.
pub struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Subcommand)]
/// Config subcommands.
pub enum ConfigCommand {
    /// Open config.toml in $EDITOR (fallback to vim, then nano).
    Edit,
}

pub fn handle(context: &crate::network::ConfigContext, args: ConfigArgs) -> Result<()> {
    match args.command {
        ConfigCommand::Edit => edit::handle(context),
    }
}

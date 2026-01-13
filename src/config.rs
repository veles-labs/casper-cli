use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use std::env;
use std::process::Command;

#[derive(Args)]
/// Config-related CLI entry point.
pub struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Subcommand)]
/// Config subcommands.
pub enum ConfigCommand {
    /// Open config.toml in $EDITOR.
    Edit,
}

pub fn handle(args: ConfigArgs) -> Result<()> {
    match args.command {
        ConfigCommand::Edit => config_edit(),
    }
}

fn config_edit() -> Result<()> {
    let editor = env::var("EDITOR")
        .map_err(|_| anyhow!("$EDITOR is not set; export EDITOR to use config edit"))?;
    let config_path = crate::network::config_path()?;
    crate::network::ensure_default_config(&config_path)?;

    let mut parts = editor.split_whitespace();
    let command = parts.next().ok_or_else(|| anyhow!("$EDITOR is empty"))?;
    let mut editor_command = Command::new(command);
    editor_command.args(parts);
    editor_command.arg(&config_path);
    let status = editor_command.status().context("failed to launch editor")?;

    if !status.success() {
        bail!("editor exited with non-zero status");
    }

    Ok(())
}

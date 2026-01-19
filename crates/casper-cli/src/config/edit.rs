use anyhow::{Context, Result, anyhow, bail};
use std::env;
use std::process::Command;

use crate::network::ConfigContext;

pub fn handle(context: &ConfigContext) -> Result<()> {
    let editor = env::var("EDITOR")
        .map_err(|_| anyhow!("$EDITOR is not set; export EDITOR to use config edit"))?;
    let config_path = context.path();
    crate::network::ensure_default_config_with_options(config_path, context.options())?;

    let mut parts = editor.split_whitespace();
    let command = parts.next().ok_or_else(|| anyhow!("$EDITOR is empty"))?;
    let mut editor_command = Command::new(command);
    editor_command.args(parts);
    editor_command.arg(config_path);
    let status = editor_command.status().context("failed to launch editor")?;

    if !status.success() {
        bail!("editor exited with non-zero status");
    }

    Ok(())
}

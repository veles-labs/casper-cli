use anyhow::{Context, Result, anyhow, bail};
use std::env;
use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus};

use crate::network::ConfigContext;

pub fn handle(context: &ConfigContext) -> Result<()> {
    let config_path = context.path();
    crate::network::ensure_default_config_with_options(config_path, context.options())?;

    let status = match env::var("EDITOR") {
        Ok(editor) if !editor.trim().is_empty() => run_editor(&editor, config_path)?,
        Ok(_) | Err(env::VarError::NotPresent) => run_fallback_editor(config_path)?,
        Err(env::VarError::NotUnicode(_)) => {
            bail!("$EDITOR contains invalid Unicode; export EDITOR to use config edit");
        }
    };

    if !status.success() {
        bail!("editor exited with non-zero status");
    }

    Ok(())
}

fn run_editor(editor: &str, config_path: &Path) -> Result<ExitStatus> {
    let mut parts = editor.split_whitespace();
    let command = parts.next().ok_or_else(|| anyhow!("$EDITOR is empty"))?;
    let mut editor_command = Command::new(command);
    editor_command.args(parts);
    editor_command.arg(config_path);
    editor_command.status().context("failed to launch editor")
}

fn run_fallback_editor(config_path: &Path) -> Result<ExitStatus> {
    const FALLBACK_EDITORS: [&str; 2] = ["vim", "nano"];
    for editor in FALLBACK_EDITORS {
        match Command::new(editor).arg(config_path).status() {
            Ok(status) => return Ok(status),
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err).context(format!("failed to launch fallback editor `{editor}`"));
            }
        }
    }
    bail!("$EDITOR is not set and no fallback editor was found (tried: vim, nano)");
}

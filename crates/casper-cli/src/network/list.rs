use anyhow::Result;
use comfy_table::{Cell, Table};

use super::{ConfigContext, load_or_init_config_with_options};

pub fn handle(context: &ConfigContext) -> Result<()> {
    let config_path = context.path();
    let config = load_or_init_config_with_options(config_path, context.options())?;

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
            Cell::new(&entry.binary_port),
        ]);
    }

    println!("{table}");
    Ok(())
}

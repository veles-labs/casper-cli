use anyhow::{Result, anyhow};
use clap::Args;

use super::{ConfigContext, load_or_init_config_with_options, resolve_network_key, save_config};

#[derive(Args)]
/// Arguments for selecting a network.
pub struct UseArgs {
    /// Name of the network (key or chain name).
    name: String,
}

pub fn handle(context: &ConfigContext, args: UseArgs) -> Result<()> {
    let config_path = context.path();
    let mut config = load_or_init_config_with_options(config_path, context.options())?;
    let key = resolve_network_key(&config, &args.name)?;
    let entry = config
        .networks
        .get(&key)
        .cloned()
        .ok_or_else(|| anyhow!("network '{key}' not found"))?;
    config.active = Some(key.clone());
    save_config(config_path, &config)?;
    println!("Active network: {key}");
    println!("Chain name: {}", entry.chain_name);
    println!("REST: {}", entry.rest);
    println!("SSE: {}", entry.sse);
    println!("RPC: {}", entry.rpc);
    println!("Binary port: {}", entry.binary_port);
    Ok(())
}

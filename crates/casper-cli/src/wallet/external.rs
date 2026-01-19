use anyhow::{Result, bail};

use crate::storage::StorageConfig;

use super::rename::{RenameArgs, handle as rename_handle};

pub fn handle(storage: &StorageConfig, args: Vec<String>) -> Result<()> {
    if args.len() >= 2 && args[1] == "rename" {
        if args.len() == 4 && (args[3] == "--help" || args[3] == "-h") {
            print_wallet_rename_help();
            return Ok(());
        }
        if args.len() != 4 {
            bail!("usage: casper wallet <wallet-name> rename-account <old-name> <new-name>");
        }
        return rename_handle(
            storage,
            RenameArgs {
                wallet_name: args[0].clone(),
                old_name: args[2].clone(),
                new_name: args[3].clone(),
            },
        );
    }
    if args.len() >= 2 && args[1] == "rename-account" {
        if args.len() == 4 && (args[3] == "--help" || args[3] == "-h") {
            print_wallet_rename_help();
            return Ok(());
        }
        if args.len() != 4 {
            bail!("usage: casper wallet <wallet-name> rename-account <old-name> <new-name>");
        }
        return rename_handle(
            storage,
            RenameArgs {
                wallet_name: args[0].clone(),
                old_name: args[2].clone(),
                new_name: args[3].clone(),
            },
        );
    }

    bail!("unsupported wallet command: {}", args.join(" "))
}

fn print_wallet_rename_help() {
    println!("Usage: casper wallet <wallet-name> rename-account <old-name> <new-name>");
    println!();
    println!("Renames an existing account in the wallet.");
}

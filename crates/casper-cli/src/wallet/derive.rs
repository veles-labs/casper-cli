use anyhow::{Result, anyhow, bail};
use bip32::{DerivationPath, XPrv};
use casper_types::{ED25519_TAG, PublicKey, SECP256K1_TAG, SecretKey};
use casper_types::bytesrepr::ToBytes;
use clap::Args;
use comfy_table::{Cell, Table};
use std::collections::HashSet;
use tinytemplate::TinyTemplate;
use zeroize::Zeroize;

use crate::network;
use crate::slip0010;
use crate::storage::StorageConfig;

use super::{
    DerivationScheme, WalletType, add_account, ensure_wallet_exists, load_metadata, root_seed,
    save_metadata, wallet_storage,
};

const DEFAULT_BIP32_SECP256K1_PATH_PREFIX: &str = "m/44'/506'/0'/0";

#[derive(Args)]
/// Arguments for deriving accounts.
pub struct DeriveArgs {
    /// Name of the wallet.
    wallet_name: String,
    /// Account name template for derived accounts.
    #[arg(long, default_value = "account-{index}", value_name = "TEMPLATE")]
    name: String,
    /// Number of accounts to derive.
    #[arg(long, default_value_t = 1)]
    count: u32,
    /// Starting index for derivation.
    #[arg(long, default_value_t = 0)]
    start: u32,
    /// Print private keys (dangerous).
    #[arg(long, alias = "private")]
    show_private: bool,
}

#[derive(serde::Serialize)]
struct DeriveNameContext<'a> {
    counter: u32,
    counter1: u32,
    index: u32,
    index1: u32,
    wallet: &'a str,
    network: &'a str,
    chain_name: &'a str,
}

pub fn handle(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    args: DeriveArgs,
) -> Result<()> {
    let wallet_storage = wallet_storage(storage, &args.wallet_name)?;
    ensure_wallet_exists(&wallet_storage, &args.wallet_name)?;
    let mut metadata = load_metadata(&wallet_storage.metadata_path)?;
    if matches!(&metadata.wallet_type, WalletType::LegacyPem { .. }) {
        bail!("legacy secret key wallets do not support account derivation");
    }
    let root_secret = wallet_storage
        .storage
        .load(&args.wallet_name)
        .map_err(|err| anyhow!(err.to_string()))?;
    let mut seed = root_seed(&root_secret)?;
    let result = (|| -> Result<()> {
        let mut updated = false;
        let end = args.start.saturating_add(args.count);
        if args.count > 0
            && metadata
                .accounts
                .iter()
                .any(|account| account.index >= args.start && account.index < end)
        {
            bail!("requested derivation range overlaps existing accounts");
        }

        let name_template = args.name.as_str();
        if name_template.is_empty() {
            bail!("account name template cannot be empty");
        }
        let (network_name, chain_name) = network::active_network_name_and_chain_name(context)?;
        let mut names = TinyTemplate::new();
        names
            .add_template("name", name_template)
            .map_err(|err| anyhow!("invalid account name template: {err}"))?;
        let mut seen_names = metadata
            .accounts
            .iter()
            .map(|account| account.name.clone())
            .collect::<HashSet<_>>();
        let mut derived_names = Vec::new();
        for index in args.start..end {
            let index1 = index
                .checked_add(1)
                .ok_or_else(|| anyhow!("index1 overflows for index {index}"))?;
            let context = DeriveNameContext {
                counter: index - args.start,
                counter1: (index - args.start)
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("i1 overflows for i {}", index - args.start))?,
                index,
                index1,
                wallet: &args.wallet_name,
                network: &network_name,
                chain_name: &chain_name,
            };
            let name = names
                .render("name", &context)
                .map_err(|err| anyhow!("failed to render account name for index {index}: {err}"))?;
            if name.is_empty() {
                bail!("derived account name cannot be empty");
            }
            if name.starts_with('-') {
                bail!("derived account name cannot start with '-'");
            }
            if !seen_names.insert(name.clone()) {
                bail!("account name '{name}' already exists");
            }
            derived_names.push((index, name));
        }

        let mut table = Table::new();
        table.set_header(vec!["Name", "Path", "Account Hash"]);
        for (index, name) in derived_names {
            let (path, secret_key) = match metadata.derivation {
                DerivationScheme::Bip32Secp256k1 => {
                    let path = format!("{}/{}", DEFAULT_BIP32_SECP256K1_PATH_PREFIX, index);
                    let derivation_path = path.parse::<DerivationPath>()?;
                    let xprv = XPrv::derive_from_path(&seed, &derivation_path)?;
                    let mut secret_key_bytes = xprv.to_bytes();
                    let secret_key = SecretKey::secp256k1_from_bytes(secret_key_bytes)
                        .map_err(|err| anyhow!(err.to_string()))?;
                    secret_key_bytes.zeroize();
                    (path, secret_key)
                }
                DerivationScheme::Slip10Ed25519 => {
                    let path = slip0010::default_path(index);
                    let indexes = slip0010::parse_hardened_path(&path)?;
                    let mut secret_key_bytes = slip0010::derive_private_key(&seed, &indexes)?;
                    let secret_key = SecretKey::ed25519_from_bytes(secret_key_bytes)
                        .map_err(|err| anyhow!(err.to_string()))?;
                    secret_key_bytes.zeroize();
                    (path, secret_key)
                }
            };

            let public_key = PublicKey::from(&secret_key);
            let public_key_hex = public_key_hex(&public_key)?;
            let account_hash = format!("{}", public_key.to_account_hash());
            table.add_row(vec![
                Cell::new(&name),
                Cell::new(&path),
                Cell::new(&account_hash),
            ]);

            if args.show_private {
                let mut private_key_bytes = secret_key_bytes(&secret_key)?;
                println!("Private key: {}", hex::encode(&private_key_bytes));
                private_key_bytes.zeroize();
            }

            if add_account(&mut metadata, &name, index, &path, &public_key_hex) {
                updated = true;
            }
        }

        if updated {
            save_metadata(&wallet_storage.metadata_path, &metadata)?;
        }

        if args.count > 0 {
            println!("{table}");
        }

        Ok(())
    })();
    seed.zeroize();
    result
}

fn secret_key_bytes(secret_key: &SecretKey) -> Result<Vec<u8>> {
    match secret_key {
        SecretKey::System => bail!("secret key cannot be system key"),
        SecretKey::Ed25519(key) => {
            let mut bytes = Vec::with_capacity(1 + SecretKey::ED25519_LENGTH);
            bytes.push(ED25519_TAG);
            bytes.extend_from_slice(&key.to_bytes());
            Ok(bytes)
        }
        SecretKey::Secp256k1(key) => {
            let raw_bytes = key.to_bytes();
            let raw_bytes: &[u8] = raw_bytes.as_ref();
            let mut bytes = Vec::with_capacity(1 + raw_bytes.len());
            bytes.push(SECP256K1_TAG);
            bytes.extend_from_slice(raw_bytes);
            Ok(bytes)
        }
        _ => bail!("unsupported secret key variant"),
    }
}

fn public_key_hex(public_key: &PublicKey) -> Result<String> {
    if matches!(public_key, PublicKey::System) {
        bail!("public key cannot be system key");
    }
    let public_key_bytes = public_key
        .to_bytes()
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(hex::encode(public_key_bytes))
}

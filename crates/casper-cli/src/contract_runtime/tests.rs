use casper_execution_engine::engine_state::{EngineConfig, ExecutionEngineV1};
use casper_storage::global_state::state::StateReader;
use casper_types::{
    CLValue, Key, StoredValue, TransactionRuntimeParams, U256, account::AccountHash, runtime_args,
};
use veles_casper_rust_sdk::{TransactionV1Builder, jsonrpc::CasperClient};

use super::*;

/// Run explicitly with:
/// cargo test live_cep18 -- --ignored --nocapture
/// Uses public state queries only; transactions are unsigned and executed locally.
#[test]
#[ignore = "requires the public Casper testnet RPC"]
fn live_cep18_views_match_state_queries() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let endpoint = "https://node.testnet.casper.network/rpc";
    let runtime = tokio::runtime::Runtime::new()?;
    let block = runtime
        .block_on(CasperClient::new(endpoint).get_block(None))?
        .block_with_signatures
        .context("latest block")?
        .block;
    let header = block.clone_header();
    let root = *block.state_root_hash();
    let db = Arc::new(sled::Config::new().temporary(true).open()?);
    let store = SledStore::new(endpoint.to_string(), db, "live-queries")?;
    let reader = state::RemoteStateReader {
        db: store.clone(),
        root,
    };
    // CEP-18 x402 token, published by its deployers for testnet integrations.
    let contract_hash = casper_types::contracts::ContractHash::from_formatted_str(
        "contract-36e657e60199d91d9ace288e573ada1d4c1ab58b1ec6bcd31ae2c0dc62531bd8",
    )
    .expect("valid CEP-18 contract hash");
    let StoredValue::Contract(contract) = reader
        .read(&Key::Hash(contract_hash.value()))?
        .context("CEP-18 contract")?
    else {
        anyhow::bail!("expected legacy CEP-18 contract")
    };
    let engine = ContractRuntime::new(
        store.clone(),
        ExecutionEngineV1::new(EngineConfig::default()),
    );
    for entry_point in ["name", "symbol", "total_supply", "balance_of"] {
        let (args, expected) = if entry_point == "balance_of" {
            let address = Key::Account(AccountHash::new([0; 32]));
            let balances = contract
                .named_keys()
                .get("balances")
                .context("balances dictionary")?
                .into_uref()
                .context("balances URef")?;
            // Base64 encoding of this 33-byte all-zero account key is 44 'A's.
            let dictionary_key = Key::dictionary(balances, "A".repeat(44).as_bytes());
            let expected = match reader.read(&dictionary_key)? {
                Some(StoredValue::CLValue(value)) => value
                    .into_t::<casper_types::CLValueDictionary>()
                    .expect("stored dictionary wrapper")
                    .into_cl_value(),
                None => CLValue::from_t(U256::zero()).expect("U256 CLValue"),
                Some(other) => anyhow::bail!("unexpected balance value: {other:?}"),
            };
            (runtime_args! { "address" => address }, expected)
        } else {
            let key = contract
                .named_keys()
                .get(entry_point)
                .context("view named key")?;
            let StoredValue::CLValue(value) = reader.read(key)?.context("view state")? else {
                anyhow::bail!("expected CLValue")
            };
            (RuntimeArgs::new(), value)
        };
        let transaction = TransactionV1Builder::new_targeting_invocable_entity(
            contract_hash.into(),
            entry_point,
            TransactionRuntimeParams::VmCasperV1,
        )
        .with_chain_name("casper-test")
        .with_initiator_addr(block.proposer().clone())
        .with_timestamp(block.timestamp())
        .with_runtime_args(args)
        .build()?;
        assert!(transaction.approvals().is_empty());
        let result = engine.execute(
            BlockInfo::new(
                root,
                block.timestamp().into(),
                *header.parent_hash(),
                header.height(),
                header.protocol_version(),
            ),
            transaction,
        )?;
        anyhow::ensure!(
            result.error().is_none(),
            "{entry_point} failed: {:?}",
            result.error()
        );
        assert_eq!(result.ret(), Some(&expected), "{entry_point}");
        println!(
            "CEP-18 {entry_point}: {} at block {} ({root})",
            crate::cl_value::cl_value_to_string(&expected)?,
            header.height()
        );
    }
    let (hits, queries) = store.cache_stats();
    println!("Verified live CEP-18 views: {queries} state queries, {hits} cache hits");
    Ok(())
}

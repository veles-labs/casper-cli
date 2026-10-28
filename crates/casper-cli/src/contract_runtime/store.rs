use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use casper_storage::global_state::{
    error::Error as GlobalStateError, trie_store::operations::compute_state_hash,
};
use casper_types::{
    Digest, Key, StoredValue,
    bytesrepr::{self, ToBytes},
    global_state::TrieMerkleProof,
};
use reqwest::Client;
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use sled::{Db, Tree};
use tokio::runtime::Runtime;

type StateProof = TrieMerkleProof<Key, StoredValue>;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct StoreMetrics {
    cache_hits: AtomicU64,
    queries: AtomicU64,
}

#[derive(Deserialize)]
struct QueryResponse {
    jsonrpc: String,
    id: u64,
    result: Option<QueryResult>,
    error: Option<QueryError>,
}

#[derive(Deserialize)]
struct QueryResult {
    // Use the value inside the proof: RPC's stored_value unwraps dictionary values.
    merkle_proof: String,
}

#[derive(Debug, Deserialize)]
struct QueryError {
    code: i64,
    message: String,
    data: Option<serde_json::Value>,
}

#[derive(Clone)]
pub struct SledStore {
    rpc_endpoint: String,
    client: Client,
    tree: Tree,
    metrics: Arc<StoreMetrics>,
    runtime: Arc<Runtime>,
    request_id: Arc<AtomicU64>,
    // StateProvider requires casper-storage's closed error type. Preserve the original
    // failure here so ContractRuntime can return it instead of a generic storage error.
    error: Arc<Mutex<Option<anyhow::Error>>>,
}

impl SledStore {
    pub fn new(rpc_endpoint: String, db: Arc<Db>, tree_name: &str) -> Result<Self> {
        Ok(Self {
            rpc_endpoint,
            client: rpc_client()?,
            tree: db
                .open_tree(tree_name.as_bytes())
                .context("open state query cache")?,
            metrics: Arc::new(StoreMetrics::default()),
            runtime: Arc::new(Runtime::new().context("create simulation runtime")?),
            request_id: Arc::new(AtomicU64::new(0)),
            error: Arc::new(Mutex::new(None)),
        })
    }

    pub(crate) fn read_with_proof(&self, root: Digest, key: &Key) -> Result<Option<StateProof>> {
        let key = key.normalize();
        let mut cache_key = root.to_bytes()?;
        cache_key.extend(key.to_bytes()?);

        if let Some(bytes) = self
            .tree
            .get(&cache_key)
            .context("read state query cache")?
        {
            let proof = bytesrepr::deserialize_from_slice(bytes.as_ref())
                .context("decode cached state proof")?;
            verify_proof(&proof, root, &key)?;
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Some(proof));
        }

        let id = self.request_id.fetch_add(1, Ordering::Relaxed);
        self.metrics.queries.fetch_add(1, Ordering::Relaxed);
        let response = self
            .runtime
            .block_on(async {
                self.client
                    .post(&self.rpc_endpoint)
                    .json(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "query_global_state",
                        "params": {
                            "state_identifier": { "StateRootHash": root },
                            "key": key.to_formatted_string(),
                            "path": [],
                        },
                    }))
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<QueryResponse>()
                    .await
            })
            .with_context(|| format!("query state for {key} at {root}"))?;

        let Some(proof) = decode_query_response(response, id, root, &key)? else {
            // Missing-key responses are trusted node answers, not absence proofs.
            // Do not persist them in the verified proof cache.
            return Ok(None);
        };
        self.tree
            .insert(cache_key, proof.to_bytes()?)
            .context("cache state proof")?;
        Ok(Some(proof))
    }

    pub(crate) fn gc_other_roots(&self, root: Digest) -> Result<usize> {
        let mut batch = sled::Batch::default();
        let mut removed = 0;
        for entry in self.tree.iter() {
            let (key, _) = entry.context("read state query cache for cleanup")?;
            if !key.starts_with(root.as_ref()) {
                batch.remove(key);
                removed += 1;
            }
        }
        self.tree
            .apply_batch(batch)
            .context("clean up state query cache")?;
        Ok(removed)
    }

    pub(crate) fn cache_stats(&self) -> (u64, u64) {
        (
            self.metrics.cache_hits.load(Ordering::Relaxed),
            self.metrics.queries.load(Ordering::Relaxed),
        )
    }

    pub(crate) fn record_error(&self, error: anyhow::Error) -> GlobalStateError {
        let mut failure = self.error.lock().unwrap_or_else(|error| error.into_inner());
        if failure.is_none() {
            *failure = Some(error);
        }
        GlobalStateError::Poison
    }

    pub(crate) fn take_error(&self) -> Option<anyhow::Error> {
        self.error
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    }
}

pub(crate) fn rpc_client() -> Result<Client> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("configure simulation TLS protocols")?
            .with_root_certificates(roots)
            .with_no_client_auth();

    Client::builder()
        .use_preconfigured_tls(tls)
        .no_proxy()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("create simulation RPC client")
}

fn decode_query_response(
    response: QueryResponse,
    id: u64,
    root: Digest,
    key: &Key,
) -> Result<Option<StateProof>> {
    ensure!(
        response.jsonrpc == "2.0" && response.id == id,
        "invalid state query response ID or version"
    );
    match (response.result, response.error) {
        (Some(result), None) => {
            let bytes = hex::decode(result.merkle_proof).context("decode state proof hex")?;
            let mut proofs: Vec<StateProof> =
                bytesrepr::deserialize_from_slice(&bytes).context("decode state proof")?;
            ensure!(
                proofs.len() == 1,
                "expected exactly one proof for a direct state query"
            );
            let proof = proofs.remove(0);
            verify_proof(&proof, root, key)?;
            Ok(Some(proof))
        }
        (None, Some(error)) => {
            if error.code == -32003
                && error.data.as_ref().and_then(serde_json::Value::as_str)
                    == Some("value was not found in the global state")
            {
                return Ok(None);
            }
            bail!(
                "state query failed for {key} at {root}: {} (code {}), data: {:?}",
                error.message,
                error.code,
                error.data
            );
        }
        _ => bail!("state query response must contain either a result or an error"),
    }
}

fn verify_proof(proof: &StateProof, root: Digest, key: &Key) -> Result<()> {
    ensure!(
        proof.key() == key,
        "state proof key does not match requested key {key}"
    );
    ensure!(
        compute_state_hash(proof)? == root,
        "state proof does not match state root {root}"
    );
    Ok(())
}

#[cfg(test)]
mod tests;

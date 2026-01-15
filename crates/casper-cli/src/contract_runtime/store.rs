use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use sled::{Db, Tree};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    runtime::Runtime,
    sync::Mutex,
    time::timeout,
};
use veles_casper_contract_api::binary_port;
use {
    casper_binary_port::{
        BinaryResponseAndRequest, Command, GetRequest, GetTrieFullResult, ResponseType,
    },
    casper_storage::global_state::{error::Error as GlobalStateError, trie::Trie},
    casper_types::{Digest, Key, StoredValue, bytesrepr},
};

#[derive(Debug, Clone)]
pub(crate) enum TrieFetch {
    /// Cached trie pulled directly from sled; no pending bytes to persist.
    Cached { trie: Trie<Key, StoredValue> },
    /// Trie fetched from remote, along with bytes that should be written.
    Fetched {
        trie: Trie<Key, StoredValue>,
        bytes: Vec<u8>,
    },
}

type CachedTrie = Option<TrieFetch>;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct StoreMetrics {
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
}

#[derive(Clone)]
pub struct SledStore {
    binary_port: String,
    tree: Tree,
    metrics: Arc<StoreMetrics>,
    runtime: Arc<Runtime>,
    connection: Arc<Mutex<Option<TcpStream>>>,
    request_id: Arc<AtomicU16>,
}

impl SledStore {
    pub fn new(binary_port_address: String, db: Arc<Db>, tree_name: &str) -> Self {
        let tree = db
            .open_tree(tree_name.as_bytes())
            .expect("failed to open sled tree");
        let runtime = Runtime::new().expect("create tokio runtime");
        Self {
            binary_port: binary_port_address,
            tree,
            metrics: Arc::new(StoreMetrics::default()),
            runtime: Arc::new(runtime),
            connection: Arc::new(Mutex::new(None)),
            request_id: Arc::new(AtomicU16::new(0)),
        }
    }

    fn record_cache_hit(&self) {
        self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    fn record_cache_miss(&self) {
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn gc_unreferenced(&self, roots: &[[u8; 32]]) -> Result<usize> {
        let mut visited = HashSet::new();
        let mut queue: VecDeque<[u8; 32]> = roots.iter().copied().collect();

        while let Some(hash) = queue.pop_front() {
            if !visited.insert(hash) {
                continue;
            }
            if let Some(bytes) = self.tree.get(hash)?
                && let Ok(trie) =
                    bytesrepr::deserialize_from_slice::<_, Trie<Key, StoredValue>>(bytes.as_ref())
            {
                match trie {
                    Trie::Node { pointer_block } => {
                        for (_, pointer) in pointer_block.as_indexed_pointers() {
                            queue.push_back(pointer.hash().value());
                        }
                    }
                    Trie::Extension { pointer, .. } => {
                        queue.push_back(pointer.hash().value());
                    }
                    Trie::Leaf { .. } => {}
                }
            }
        }

        let mut removed = 0;
        for entry in self.tree.iter() {
            let (key, _) = entry?;
            if key.len() != 32 {
                continue;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(key.as_ref());
            if !visited.contains(&arr) {
                self.tree.remove(key)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub(crate) fn download(
        &self,
        state_root_hash: [u8; 32],
    ) -> Result<CachedTrie, GlobalStateError> {
        if let Some(cached) = self.read_cached_trie(state_root_hash)? {
            self.record_cache_hit();
            return Ok(Some(cached));
        }
        self.record_cache_miss();
        let response = self
            .send_request(Command::Get(GetRequest::Trie {
                trie_key: Digest::from_raw(state_root_hash),
            }))
            .map_err(map_binary_port_error)?;
        if response.is_success() {
            let response_type =
                ResponseType::try_from(response.response().returned_data_type_tag().unwrap())
                    .unwrap();
            match response_type {
                ResponseType::GetTrieFullResult => {
                    let trie: GetTrieFullResult =
                        bytesrepr::deserialize_from_slice(response.response().payload()).unwrap();
                    match trie.into_inner() {
                        Some(trie_bytes) => {
                            let trie: Trie<Key, StoredValue> =
                                bytesrepr::deserialize_from_slice(&trie_bytes).unwrap();
                            return Ok(Some(TrieFetch::Fetched {
                                trie,
                                bytes: trie_bytes.to_vec(),
                            }));
                        }
                        None => return Ok(None),
                    }
                }
                _ => panic!("Unexpected response type"),
            }
        }

        eprintln!(
            "Failed to download trie for state root hash {:x?}",
            state_root_hash
        );
        Ok(None)
    }

    pub(crate) fn download_trie_bytes(
        &self,
        state_root_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, GlobalStateError> {
        if let Some(bytes) = self.read_cached_trie_bytes(state_root_hash)? {
            self.record_cache_hit();
            return Ok(Some(bytes));
        }
        self.record_cache_miss();

        let response = self
            .send_request(Command::Get(GetRequest::Trie {
                trie_key: Digest::from_raw(state_root_hash),
            }))
            .map_err(map_binary_port_error)?;
        if response.is_success() {
            let response_type =
                ResponseType::try_from(response.response().returned_data_type_tag().unwrap())
                    .unwrap();
            match response_type {
                ResponseType::GetTrieFullResult => {
                    let trie: GetTrieFullResult =
                        bytesrepr::deserialize_from_slice(response.response().payload()).unwrap();
                    match trie.into_inner() {
                        Some(trie_bytes) => {
                            let bytes = trie_bytes.to_vec();
                            let mut batch = sled::Batch::default();
                            batch.insert(&state_root_hash, bytes.as_slice());
                            self.persist_trie_batch(&batch)?;
                            return Ok(Some(bytes));
                        }
                        None => return Ok(None),
                    }
                }
                _ => panic!("Unexpected response type"),
            }
        }
        Ok(None)
    }

    fn read_cached_trie(&self, state_root_hash: [u8; 32]) -> Result<CachedTrie, GlobalStateError> {
        if let Ok(Some(bytes)) = self.tree.get(state_root_hash)
            && let Ok(trie) =
                bytesrepr::deserialize_from_slice::<_, Trie<Key, StoredValue>>(bytes.as_ref())
        {
            return Ok(Some(TrieFetch::Cached { trie }));
        }
        Ok(None)
    }

    fn read_cached_trie_bytes(
        &self,
        state_root_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, GlobalStateError> {
        if let Ok(Some(bytes)) = self.tree.get(state_root_hash) {
            return Ok(Some(bytes.as_ref().to_vec()));
        }
        Ok(None)
    }

    pub(crate) fn persist_trie_batch(&self, batch: &sled::Batch) -> Result<(), GlobalStateError> {
        self.tree
            .transaction(|tx| {
                tx.apply_batch(batch)?;
                Ok(())
            })
            .map_err(|_: sled::transaction::TransactionError<sled::Error>| GlobalStateError::Poison)
    }

    pub(crate) fn cache_stats(&self) -> (u64, u64) {
        (
            self.metrics.cache_hits.load(Ordering::Relaxed),
            self.metrics.cache_misses.load(Ordering::Relaxed),
        )
    }

    pub(crate) fn send_request(
        &self,
        request: Command,
    ) -> Result<BinaryResponseAndRequest, binary_port::Error> {
        let request_id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let raw_bytes = binary_port::encode_request(&request, request_id)?;
        self.runtime
            .block_on(self.send_request_async(raw_bytes, request_id))
    }

    async fn send_request_async(
        &self,
        raw_bytes: Vec<u8>,
        request_id: u16,
    ) -> Result<BinaryResponseAndRequest, binary_port::Error> {
        let response_buf = self.send_raw(&raw_bytes).await?;
        binary_port::process_response(response_buf, request_id).await
    }

    async fn send_raw(&self, payload: &[u8]) -> Result<Vec<u8>, binary_port::Error> {
        let mut connection = self.connection.lock().await;
        if connection.is_none() {
            *connection = Some(TcpStream::connect(&self.binary_port).await?);
        }

        match send_payload_and_read(connection.as_mut().unwrap(), payload).await {
            Ok(response) => Ok(response),
            Err(error) => {
                *connection = None;
                drop(connection);
                let mut connection = self.connection.lock().await;
                *connection = Some(TcpStream::connect(&self.binary_port).await?);
                match send_payload_and_read(connection.as_mut().unwrap(), payload).await {
                    Ok(response) => Ok(response),
                    Err(_) => Err(error),
                }
            }
        }
    }
}

async fn send_payload_and_read(
    stream: &mut TcpStream,
    payload: &[u8],
) -> Result<Vec<u8>, binary_port::Error> {
    let payload_len = payload.len() as u32;
    let length_bytes = payload_len.to_le_bytes();
    timeout(REQUEST_TIMEOUT, stream.write_all(&length_bytes))
        .await
        .map_err(|_| binary_port::Error::Timeout)??;
    timeout(REQUEST_TIMEOUT, stream.write_all(payload))
        .await
        .map_err(|_| binary_port::Error::Timeout)??;
    timeout(REQUEST_TIMEOUT, stream.flush())
        .await
        .map_err(|_| binary_port::Error::Timeout)??;

    let mut length_buf = [0u8; binary_port::LENGTH_FIELD_SIZE];
    timeout(REQUEST_TIMEOUT, stream.read_exact(&mut length_buf))
        .await
        .map_err(|_| binary_port::Error::Timeout)??;
    let response_length = u32::from_le_bytes(length_buf) as usize;
    let mut response_buf = vec![0u8; response_length];
    timeout(REQUEST_TIMEOUT, stream.read_exact(&mut response_buf))
        .await
        .map_err(|_| binary_port::Error::Timeout)??;
    Ok(response_buf)
}

fn map_binary_port_error(error: binary_port::Error) -> GlobalStateError {
    match error {
        binary_port::Error::Bytesrepr(error) => GlobalStateError::BytesRepr(error),
        _ => GlobalStateError::Poison,
    }
}

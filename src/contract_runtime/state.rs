use std::{cmp, collections::VecDeque};

use casper_storage::global_state::state::StateProvider;
use casper_storage::global_state::trie::PointerBlock;
use casper_storage::global_state::{
    error::Error as GlobalStateError, state::StateReader, trie::Trie,
    trie_store::operations::ReadResult,
};
use casper_types::global_state::TrieMerkleProof;
use casper_types::{
    Key, Pointer, StoredValue,
    bytesrepr::{self, Bytes, FromBytes, ToBytes},
};

use crate::contract_runtime::store::TrieFetch;

use super::store::SledStore;

const TRIE_LEAF_TAG: u8 = 0;
const TRIE_NODE_TAG: u8 = 1;
const TRIE_EXTENSION_TAG: u8 = 2;
const RADIX: usize = 256;
const PROGRESS_INTERVAL: u64 = 1000;

// Holds trie nodes without eagerly deserializing leaf values.
enum LazyTrie {
    Leaf(Vec<u8>),
    Node { pointer_block: Box<PointerBlock> },
    Extension { affix: Bytes, pointer: Pointer },
}

impl LazyTrie {
    fn from_bytes_owned(bytes: Vec<u8>) -> Result<Self, bytesrepr::Error> {
        let (tag, rem) = u8::from_bytes(&bytes)?;
        match tag {
            TRIE_LEAF_TAG => Ok(Self::Leaf(bytes)),
            TRIE_NODE_TAG => {
                let (pointer_block, _rem) = PointerBlock::from_bytes(rem)?;
                Ok(Self::Node {
                    pointer_block: Box::new(pointer_block),
                })
            }
            TRIE_EXTENSION_TAG => {
                let (affix, rem) = Bytes::from_bytes(rem)?;
                let (pointer, _rem) = Pointer::from_bytes(rem)?;
                Ok(Self::Extension { affix, pointer })
            }
            _ => Err(bytesrepr::Error::Formatting),
        }
    }
}

struct VisitedTrieNode {
    trie: LazyTrie,
    maybe_index: Option<usize>,
    path: Vec<u8>,
}

struct TrieMatchIterator<'a, F>
where
    F: FnMut(&[u8]) -> bool,
{
    initial_descend: VecDeque<u8>,
    visited: Vec<VisitedTrieNode>,
    store: &'a SledStore,
    failed: bool,
    matcher: F,
    visited_count: u64,
}

impl<'a, F> TrieMatchIterator<'a, F>
where
    F: FnMut(&[u8]) -> bool,
{
    fn new(
        store: &'a SledStore,
        root: [u8; 32],
        prefix: &[u8],
        matcher: F,
    ) -> Result<Self, GlobalStateError> {
        let mut iter = Self {
            initial_descend: prefix.iter().copied().collect(),
            visited: Vec::new(),
            store,
            failed: false,
            matcher,
            visited_count: 0,
        };

        if let Some(trie) = iter.fetch_trie(root)? {
            iter.visited.push(VisitedTrieNode {
                trie,
                maybe_index: None,
                path: Vec::new(),
            });
        }

        Ok(iter)
    }

    fn fetch_trie(&mut self, hash: [u8; 32]) -> Result<Option<LazyTrie>, GlobalStateError> {
        match self.store.download_trie_bytes(hash)? {
            Some(bytes) => Ok(Some(LazyTrie::from_bytes_owned(bytes)?)),
            None => Ok(None),
        }
    }

    fn maybe_report_progress(&self) {
        if self.visited_count == 1 || self.visited_count % PROGRESS_INTERVAL == 0 {
            let (cached, downloaded) = self.store.cache_stats();
            eprintln!(
                "trie progress: visited={}, cached={}, downloaded={}, remaining≈{}",
                self.visited_count,
                cached,
                downloaded,
                self.visited.len(),
            );
        }
    }
}

impl<F> Iterator for TrieMatchIterator<'_, F>
where
    F: FnMut(&[u8]) -> bool,
{
    type Item = Result<Vec<u8>, GlobalStateError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }

        while let Some(VisitedTrieNode {
            trie,
            maybe_index,
            mut path,
        }) = self.visited.pop()
        {
            self.visited_count += 1;
            self.maybe_report_progress();
            let mut maybe_next_trie: Option<LazyTrie> = None;

            match trie {
                LazyTrie::Leaf(leaf_bytes) => {
                    if leaf_bytes.len() < 2 {
                        self.failed = true;
                        return Some(Err(bytesrepr::Error::Formatting.into()));
                    }

                    let key_bytes = &leaf_bytes[1..];
                    debug_assert!(key_bytes.starts_with(&path));

                    let mut expected_prefix = path.clone();
                    expected_prefix.extend(self.initial_descend.iter().copied());
                    if key_bytes.starts_with(&expected_prefix) && (self.matcher)(&leaf_bytes) {
                        return Some(Ok(leaf_bytes));
                    }
                }
                LazyTrie::Node { pointer_block } => {
                    let mut index: usize = self
                        .initial_descend
                        .front()
                        .map(|i| *i as usize)
                        .or(maybe_index)
                        .unwrap_or_default();
                    while index < RADIX {
                        if let Some(pointer) = pointer_block[index] {
                            match self.fetch_trie(pointer.hash().value()) {
                                Ok(next_trie) => {
                                    maybe_next_trie = next_trie;
                                }
                                Err(error) => {
                                    self.failed = true;
                                    return Some(Err(error));
                                }
                            }
                            if self.initial_descend.pop_front().is_none() {
                                self.visited.push(VisitedTrieNode {
                                    trie: LazyTrie::Node { pointer_block },
                                    maybe_index: Some(index + 1),
                                    path: path.clone(),
                                });
                            }
                            path.push(index as u8);
                            break;
                        }
                        if !self.initial_descend.is_empty() {
                            break;
                        }
                        index += 1;
                    }
                }
                LazyTrie::Extension { affix, pointer } => {
                    let descend_len = cmp::min(self.initial_descend.len(), affix.len());
                    let check_prefix: Vec<u8> = self.initial_descend.drain(..descend_len).collect();
                    if affix.as_slice().starts_with(&check_prefix) {
                        match self.fetch_trie(pointer.hash().value()) {
                            Ok(next_trie) => {
                                maybe_next_trie = next_trie;
                            }
                            Err(error) => {
                                self.failed = true;
                                return Some(Err(error));
                            }
                        }
                        path.extend_from_slice(affix.as_slice());
                    }
                }
            }

            if let Some(next_trie) = maybe_next_trie {
                self.visited.push(VisitedTrieNode {
                    trie: next_trie,
                    maybe_index: None,
                    path,
                });
            }
        }

        None
    }
}

pub struct RemoteStateReader {
    pub(crate) db: SledStore,
    pub(crate) root: [u8; 32],
}

impl RemoteStateReader {
    pub fn iter<'a, F>(
        &'a self,
        prefix: &[u8],
        matcher: F,
    ) -> Result<impl Iterator<Item = Result<Vec<u8>, GlobalStateError>> + 'a, GlobalStateError>
    where
        F: FnMut(&[u8]) -> bool + 'a,
    {
        TrieMatchIterator::new(&self.db, self.root, prefix, matcher)
    }

    fn read_from_store(
        store: &SledStore,
        root: [u8; 32],
        key: &Key,
    ) -> Result<ReadResult<StoredValue>, GlobalStateError> {
        let path: Vec<u8> = key.to_bytes()?;
        let mut depth: usize = 0;
        let mut pending_inserts = sled::Batch::default();
        let mut current: Trie<Key, StoredValue> = match store.download(root)? {
            Some(TrieFetch::Cached { trie }) => trie,
            Some(TrieFetch::Fetched { trie, bytes }) => {
                pending_inserts.insert(&root, bytes);
                trie
            }
            None => return Ok(ReadResult::RootNotFound),
        };

        loop {
            match current {
                Trie::Leaf {
                    key: leaf_key,
                    value: leaf_value,
                } => {
                    let result = if key == &leaf_key {
                        ReadResult::Found(leaf_value)
                    } else {
                        ReadResult::NotFound
                    };
                    store.persist_trie_batch(&pending_inserts)?;
                    return Ok(result);
                }
                Trie::Node { pointer_block } => {
                    let index: usize = {
                        assert!(depth < path.len(), "depth must be < {}", path.len());
                        path[depth].into()
                    };
                    let maybe_pointer: Option<Pointer> = {
                        assert!(index < 256, "key length must be < {}", 256);
                        pointer_block[index]
                    };

                    match maybe_pointer {
                        Some(pointer) => match store.download(pointer.hash().value()) {
                            Ok(Some(TrieFetch::Cached { trie: next })) => {
                                depth += 1;
                                current = next;
                            }
                            Ok(Some(TrieFetch::Fetched { trie: next, bytes })) => {
                                pending_inserts.insert(&pointer.hash().value(), bytes);
                                depth += 1;
                                current = next;
                            }
                            Ok(None) => {
                                store.persist_trie_batch(&pending_inserts)?;
                                return Ok(ReadResult::NotFound);
                            }
                            Err(error) => return Err(error),
                        },
                        None => {
                            store.persist_trie_batch(&pending_inserts)?;
                            return Ok(ReadResult::NotFound);
                        }
                    }
                }
                Trie::Extension { affix, pointer } => {
                    let sub_path = &path[depth..depth + affix.len()];
                    if sub_path == affix.as_slice() {
                        match store.download(pointer.hash().value())? {
                            Some(TrieFetch::Cached { trie: next }) => {
                                depth += affix.len();
                                current = next;
                            }
                            Some(TrieFetch::Fetched { trie: next, bytes }) => {
                                pending_inserts.insert(&pointer.hash().value(), bytes);
                                depth += affix.len();
                                current = next;
                            }
                            None => {
                                store.persist_trie_batch(&pending_inserts)?;
                                return Ok(ReadResult::NotFound);
                            }
                        }
                    } else {
                        store.persist_trie_batch(&pending_inserts)?;
                        return Ok(ReadResult::NotFound);
                    }
                }
            }
        }
    }
}

impl StateReader<Key, StoredValue> for RemoteStateReader {
    type Error = GlobalStateError;

    fn read(&self, key: &Key) -> Result<Option<StoredValue>, Self::Error> {
        match Self::read_from_store(&self.db, self.root, key)? {
            ReadResult::Found(value) => Ok(Some(value)),
            ReadResult::NotFound => Ok(None),
            ReadResult::RootNotFound => panic!("Invalid root"),
        }
    }

    fn read_with_proof(
        &self,
        _key: &Key,
    ) -> Result<Option<TrieMerkleProof<Key, StoredValue>>, Self::Error> {
        unreachable!()
    }

    fn keys_with_prefix(&self, prefix: &[u8]) -> Result<Vec<Key>, Self::Error> {
        let prefix_match = prefix.to_vec();
        let iter = self.iter(prefix, move |leaf_bytes| {
            leaf_bytes
                .get(1..)
                .map(|bytes| bytes.starts_with(&prefix_match))
                .unwrap_or(false)
        })?;
        let mut keys = Vec::new();
        let mut iter_error = None;

        for result in iter {
            match result {
                Ok(leaf_bytes) => {
                    let key_bytes = match leaf_bytes.get(1..) {
                        Some(bytes) => bytes,
                        None => {
                            iter_error = Some(bytesrepr::Error::Formatting.into());
                            break;
                        }
                    };
                    let (key, _remainder) = match Key::from_bytes(key_bytes) {
                        Ok(key) => key,
                        Err(error) => {
                            iter_error = Some(error.into());
                            break;
                        }
                    };
                    keys.push(key);
                }
                Err(error) => {
                    iter_error = Some(error);
                    break;
                }
            }
        }

        if let Some(error) = iter_error {
            return Err(error);
        }
        Ok(keys)
    }
}

pub struct RemoteStateProvider {
    pub(crate) store: SledStore,
}

impl StateProvider for RemoteStateProvider {
    type Reader = RemoteStateReader;

    fn flush(
        &self,
        _request: casper_storage::data_access_layer::FlushRequest,
    ) -> casper_storage::data_access_layer::FlushResult {
        unreachable!()
    }

    fn empty_root(&self) -> casper_types::Digest {
        unreachable!()
    }

    fn tracking_copy(
        &self,
        state_hash: casper_types::Digest,
    ) -> Result<Option<casper_storage::TrackingCopy<Self::Reader>>, GlobalStateError> {
        let reader = RemoteStateReader {
            db: self.store.clone(),
            root: state_hash.value(),
        };
        Ok(Some(casper_storage::TrackingCopy::new(reader, 5, false)))
    }

    fn checkout(
        &self,
        state_hash: casper_types::Digest,
    ) -> Result<Option<Self::Reader>, GlobalStateError> {
        let reader = RemoteStateReader {
            db: self.store.clone(),
            root: state_hash.value(),
        };
        Ok(Some(reader))
    }

    fn trie(
        &self,
        _request: casper_storage::data_access_layer::TrieRequest,
    ) -> casper_storage::data_access_layer::TrieResult {
        unreachable!()
    }

    fn put_trie(
        &self,
        _request: casper_storage::data_access_layer::PutTrieRequest,
    ) -> casper_storage::data_access_layer::PutTrieResult {
        unreachable!()
    }

    fn missing_children(
        &self,
        _trie_raw: &[u8],
    ) -> Result<Vec<casper_types::Digest>, GlobalStateError> {
        unreachable!()
    }

    fn enable_entity(&self) -> bool {
        unreachable!()
    }
}

use casper_storage::global_state::{
    error::Error as GlobalStateError,
    state::{StateProvider, StateReader},
};
use casper_types::{Digest, Key, StoredValue, global_state::TrieMerkleProof};

use super::store::SledStore;

pub struct RemoteStateReader {
    pub(crate) db: SledStore,
    pub(crate) root: Digest,
}

impl StateReader<Key, StoredValue> for RemoteStateReader {
    type Error = GlobalStateError;

    fn read(&self, key: &Key) -> Result<Option<StoredValue>, Self::Error> {
        self.read_with_proof(key)
            .map(|proof| proof.map(TrieMerkleProof::into_value))
    }

    fn read_with_proof(
        &self,
        key: &Key,
    ) -> Result<Option<TrieMerkleProof<Key, StoredValue>>, Self::Error> {
        self.db
            .read_with_proof(self.root, key)
            .map_err(|error| self.db.record_error(error))
    }

    fn keys_with_prefix(&self, _prefix: &[u8]) -> Result<Vec<Key>, Self::Error> {
        Err(self.db.record_error(anyhow::anyhow!(
            "keys_with_prefix is disabled for query-based simulation; this operation requires key enumeration"
        )))
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

    fn empty_root(&self) -> Digest {
        unreachable!()
    }

    fn tracking_copy(
        &self,
        state_hash: Digest,
    ) -> Result<Option<casper_storage::TrackingCopy<Self::Reader>>, GlobalStateError> {
        let reader = RemoteStateReader {
            db: self.store.clone(),
            root: state_hash,
        };
        Ok(Some(casper_storage::TrackingCopy::new(reader, 5, false)))
    }

    fn checkout(&self, state_hash: Digest) -> Result<Option<Self::Reader>, GlobalStateError> {
        Ok(Some(RemoteStateReader {
            db: self.store.clone(),
            root: state_hash,
        }))
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

    fn missing_children(&self, _trie_raw: &[u8]) -> Result<Vec<Digest>, GlobalStateError> {
        unreachable!()
    }

    fn enable_entity(&self) -> bool {
        false
    }
}

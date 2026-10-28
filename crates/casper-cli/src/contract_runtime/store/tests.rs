use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::TcpListener,
    thread::{self, JoinHandle},
    time::Instant,
};

use casper_storage::global_state::state::StateReader;
use casper_types::{AccessRights, CLValue, CLValueDictionary, URef};
use serde_json::{Value, json};

use super::*;
use crate::contract_runtime::state::RemoteStateReader;

fn store(endpoint: String) -> SledStore {
    let _ = rustls::crypto::ring::default_provider().install_default();
    SledStore::new(
        endpoint,
        Arc::new(sled::Config::new().temporary(true).open().unwrap()),
        "queries",
    )
    .unwrap()
}

fn proof(key: Key, value: StoredValue) -> (Digest, StateProof) {
    let proof = StateProof::new(key, value, VecDeque::new());
    (compute_state_hash(&proof).unwrap(), proof)
}

fn proof_response(proof: &StateProof) -> Value {
    json!({
        "result": {
            "merkle_proof": hex::encode(vec![proof.clone()].to_bytes().unwrap()),
            "stored_value": {"CLValue": CLValue::from_t(999u64).unwrap()},
        }
    })
}

// A bounded local HTTP fixture also checks that requests never use trie or prefix APIs.
fn rpc_server(responses: Vec<Value>) -> (String, JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/rpc", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for mut response in responses {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "RPC fixture timed out");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let header_end = loop {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                bytes.push(byte[0]);
                if bytes.ends_with(b"\r\n\r\n") {
                    break bytes.len();
                }
            };
            let headers = String::from_utf8_lossy(&bytes);
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            bytes.resize(header_end + length, 0);
            stream.read_exact(&mut bytes[header_end..]).unwrap();
            let request: Value = serde_json::from_slice(&bytes[header_end..]).unwrap();
            assert_eq!(request["method"], "query_global_state");
            assert_eq!(request["params"]["path"], json!([]));
            response["jsonrpc"] = json!("2.0");
            response["id"] = request["id"].clone();
            requests.push(request);
            let body = serde_json::to_vec(&response).unwrap();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
        }
        requests
    });
    (endpoint, handle)
}

#[test]
fn queries_and_caches_the_raw_dictionary_value_at_a_pinned_root() {
    let key = Key::Dictionary([7; 32]);
    let dictionary = CLValueDictionary::new(
        CLValue::from_t(42u64).unwrap(),
        vec![3; 32],
        b"owner".to_vec(),
    );
    let raw_value = StoredValue::CLValue(CLValue::from_t(dictionary).unwrap());
    let (root, proof) = proof(key, raw_value.clone());
    let (endpoint, server) = rpc_server(vec![proof_response(&proof)]);
    let store = store(endpoint);
    let reader = RemoteStateReader {
        db: store.clone(),
        root,
    };

    assert_eq!(reader.read(&key).unwrap(), Some(raw_value));
    assert_eq!(reader.read_with_proof(&key).unwrap(), Some(proof));
    assert_eq!(store.cache_stats(), (1, 1));
    let requests = server.join().unwrap();
    assert_eq!(
        requests[0]["params"]["state_identifier"],
        json!({"StateRootHash": root})
    );
    assert_eq!(requests[0]["params"]["key"], key.to_formatted_string());
}

#[test]
fn cache_is_scoped_by_root_and_uref_rights_are_normalized() {
    let key = Key::URef(URef::new([4; 32], AccessRights::READ_ADD_WRITE));
    let (first_root, first) = proof(
        key.normalize(),
        StoredValue::CLValue(CLValue::from_t(1u64).unwrap()),
    );
    let (second_root, second) = proof(
        key.normalize(),
        StoredValue::CLValue(CLValue::from_t(2u64).unwrap()),
    );
    let (endpoint, server) = rpc_server(vec![proof_response(&first), proof_response(&second)]);
    let store = store(endpoint);

    assert_eq!(
        store.read_with_proof(first_root, &key).unwrap(),
        Some(first)
    );
    assert_eq!(
        store.read_with_proof(second_root, &key).unwrap(),
        Some(second.clone())
    );
    assert_eq!(store.gc_other_roots(second_root).unwrap(), 1);
    assert_eq!(store.tree.len(), 1);
    assert_eq!(
        store.read_with_proof(second_root, &key).unwrap(),
        Some(second)
    );
    let requests = server.join().unwrap();
    assert_eq!(
        requests[0]["params"]["key"],
        key.normalize().to_formatted_string()
    );
}

#[test]
fn only_an_explicit_missing_value_response_returns_none() {
    let missing = json!({"error": {"code": -32003, "message": "Query failed", "data": "value was not found in the global state"}});
    let (endpoint, server) = rpc_server(vec![missing]);
    let store = store(endpoint);
    assert!(
        store
            .read_with_proof(Digest::from([1; 32]), &Key::Hash([2; 32]))
            .unwrap()
            .is_none()
    );
    assert!(store.tree.is_empty());
    server.join().unwrap();

    for error in [
        json!({"code": -32003, "message": "Query failed", "data": "root not found"}),
        json!({"code": -32601, "message": "Method not found"}),
        json!({"code": -32000, "message": "Internal error"}),
    ] {
        let response =
            serde_json::from_value(json!({"jsonrpc": "2.0", "id": 0, "error": error})).unwrap();
        assert!(
            decode_query_response(response, 0, Digest::from([1; 32]), &Key::Hash([2; 32])).is_err()
        );
    }
}

#[test]
fn rejects_wrong_keys_roots_and_malformed_proofs_without_caching() {
    let key = Key::Hash([2; 32]);
    let (root, proof) = proof(key, StoredValue::CLValue(CLValue::from_t(1u64).unwrap()));
    let (endpoint, server) = rpc_server(vec![
        proof_response(&proof),
        proof_response(&proof),
        json!({"result": {"merkle_proof": "bad-hex"}}),
    ]);
    let store = store(endpoint);
    assert!(store.read_with_proof(Digest::from([9; 32]), &key).is_err());
    assert!(store.read_with_proof(root, &Key::Hash([3; 32])).is_err());
    assert!(store.read_with_proof(root, &key).is_err());
    assert!(store.tree.is_empty());
    server.join().unwrap();
}

#[test]
fn prefix_enumeration_fails_without_network_access_even_for_empty_prefix() {
    let store = store("http://127.0.0.1:0/rpc".to_string());
    let reader = RemoteStateReader {
        db: store.clone(),
        root: Digest::from([1; 32]),
    };
    assert!(reader.keys_with_prefix(&[]).is_err());
    assert!(
        store
            .take_error()
            .unwrap()
            .to_string()
            .contains("keys_with_prefix is disabled")
    );
    assert_eq!(store.cache_stats(), (0, 0));
}

#[test]
fn corrupt_cached_proofs_and_invalid_responses_fail_closed() {
    let key = Key::Hash([2; 32]);
    let (root, proof) = proof(key, StoredValue::CLValue(CLValue::from_t(1u64).unwrap()));
    let store = store("http://127.0.0.1:0/rpc".to_string());
    let mut cache_key = root.to_bytes().unwrap();
    cache_key.extend(key.to_bytes().unwrap());
    let tampered = StateProof::new(
        key,
        StoredValue::CLValue(CLValue::from_t(2u64).unwrap()),
        proof.proof_steps().clone(),
    );
    store
        .tree
        .insert(cache_key, tampered.to_bytes().unwrap())
        .unwrap();
    let reader = RemoteStateReader {
        db: store.clone(),
        root,
    };
    assert!(reader.read(&key).is_err());
    assert!(
        store
            .take_error()
            .unwrap()
            .to_string()
            .contains("state proof does not match")
    );
    assert_eq!(store.cache_stats(), (0, 0));

    let empty_proof =
        json!({"merkle_proof": hex::encode(Vec::<StateProof>::new().to_bytes().unwrap())});
    for response in [
        json!({"jsonrpc": "1.0", "id": 0, "result": empty_proof}),
        json!({"jsonrpc": "2.0", "id": 1, "result": empty_proof}),
        json!({"jsonrpc": "2.0", "id": 0, "result": empty_proof}),
        json!({"jsonrpc": "2.0", "id": 0}),
        json!({"jsonrpc": "2.0", "id": 0, "result": empty_proof, "error": {"code": -32003, "message": "Query failed", "data": "value was not found in the global state"}}),
    ] {
        assert!(
            decode_query_response(serde_json::from_value(response).unwrap(), 0, root, &key)
                .is_err()
        );
    }
}

#[test]
fn connection_failure_is_recorded_instead_of_becoming_an_absent_key() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/rpc", listener.local_addr().unwrap());
    // Closing each accepted connection forces a transport failure, without relying on
    // an unused port or a particular node's availability.
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        drop(stream);
    });
    let store = store(endpoint);
    let reader = RemoteStateReader {
        db: store.clone(),
        root: Digest::from([1; 32]),
    };
    assert!(reader.read(&Key::Hash([2; 32])).is_err());
    let error = store.take_error().unwrap();
    assert!(format!("{error:#}").contains("query state for"));
    assert!(store.tree.is_empty());
    server.join().unwrap();
}

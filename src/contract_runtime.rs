pub mod state;
pub mod store;

use anyhow::{Context, Result};
use std::{collections::BTreeSet, iter, sync::Arc};

use casper_execution_engine::engine_state::{
    BlockInfo, ExecutionEngineV1, SessionDataV1, SessionInputData, WasmV1Request, WasmV1Result,
};
use casper_types::{
    Gas, InitiatorAddr, PricingMode, RuntimeArgs, TransactionArgs, TransactionEntryPoint,
    TransactionTarget, TransactionV1, TransactionV1Hash, account::AccountHash,
};

use crate::contract_runtime::{state::RemoteStateProvider, store::SledStore};

const ARGS_MAP_KEY: u16 = 0;
const TARGET_MAP_KEY: u16 = 1;
const ENTRY_POINT_MAP_KEY: u16 = 2;

#[derive(Clone)]
struct SessionDataV1Owned {
    args: RuntimeArgs,
    target: TransactionTarget,
    entry_point: TransactionEntryPoint,
    is_install_upgrade: bool,
    hash: TransactionV1Hash,
    pricing_mode: PricingMode,
    initiator_addr: InitiatorAddr,
    signers: BTreeSet<AccountHash>,
}

impl SessionDataV1Owned {
    fn as_input_data(&self) -> SessionInputData<'_> {
        let data = SessionDataV1::new(
            &self.args,
            &self.target,
            &self.entry_point,
            self.is_install_upgrade,
            &self.hash,
            &self.pricing_mode,
            &self.initiator_addr,
            self.signers.clone(),
            self.pricing_mode.is_standard_payment(),
        );
        SessionInputData::SessionDataV1 { data }
    }
}

/// A runtime for executing smart contract transactions in local mode.
///
/// This runtime uses a sled store acting as a local trie database and an execution engine
/// to execute smart contract transactions.
///
/// The store is trying to download trie objects from remote binary port server if the object is
/// not found in the local sled database. If a given trie object is present, then it's used directly.
///
/// Usually with a warm cache and a simple smart contract execution, this runtime should be able to
/// execute transactions in a few milliseconds (~1-2 new tries downloaded per execution).
#[derive(Clone)]
pub struct ContractRuntime {
    pub(crate) store: SledStore,
    pub(crate) engine: Arc<ExecutionEngineV1>,
}

impl ContractRuntime {
    pub fn new(store: SledStore, engine: ExecutionEngineV1) -> Self {
        Self {
            store,
            engine: Arc::new(engine),
        }
    }

    /// Execute a smart contract transaction in local mode.
    ///
    /// This mimics the contract runtime behavior in the Casper node, but without networking, transaction acceptor, etc.
    pub fn execute(&self, block_info: BlockInfo, txn: TransactionV1) -> Result<WasmV1Result> {
        let args = txn
            .deserialize_field::<TransactionArgs>(ARGS_MAP_KEY)
            .unwrap();

        let target = txn
            .deserialize_field::<TransactionTarget>(TARGET_MAP_KEY)
            .unwrap();

        let entry_point = txn
            .deserialize_field::<TransactionEntryPoint>(ENTRY_POINT_MAP_KEY)
            .unwrap();

        let approvals = txn.approvals();
        let signers = iter::once(txn.initiator_addr().account_hash())
            .chain(
                approvals
                    .iter()
                    .map(|approval| approval.signer().to_account_hash()),
            )
            .collect();

        let args = args.as_named().cloned().unwrap();

        let session_input_data = SessionDataV1Owned {
            args,
            target,
            entry_point,
            is_install_upgrade: true,
            hash: *txn.hash(),
            pricing_mode: txn.payload().pricing_mode().clone(),
            initiator_addr: txn.payload().initiator_addr().clone(),
            signers,
        };

        let wasm_v1_request =
            WasmV1Request::new_session(block_info, Gas::MAX, &session_input_data.as_input_data())
                .context("new session wasm")?;

        let provider = RemoteStateProvider {
            store: self.store.clone(),
        };

        // Actually execute the smart contract transaction.
        Ok(self.engine.execute(&provider, wasm_v1_request))
    }
}

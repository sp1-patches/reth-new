use alloy_provider::{Provider, ReqwestProvider};
use alloy_rpc_types::{Block, BlockId, EIP1186AccountProofResponse};
use eyre::Ok;
use reth_evm::execute::{BlockExecutionOutput, BlockExecutorProvider, Executor};
use reth_interfaces::executor::BlockValidationError;
use reth_node_ethereum::EthereumNode;
use reth_primitives::{Block as RethBlock, ChainSpecBuilder, Receipts, B256, MAINNET};
use reth_provider::{BundleStateWithReceipts, ProviderError};
use reth_revm::database::StateProviderDatabase;
use revm::{db::InMemoryDB, Database};
use revm_primitives::{AccountInfo, HashMap, U256};
use url::Url;

pub struct WitnessDb {
    pub inner: InMemoryDB,
    pub state_root: B256,
}

impl WitnessDb {
    pub fn new(state_root: B256, merkle_proofs: Vec<EIP1186AccountProofResponse>) -> Self {
        let mut inner = InMemoryDB::default();
        for proof in merkle_proofs {
            // TODO: verify proof against state_root
            // Note that we do not need to hash the code against the code_hash, since
            // `insert_contract` already does this.
            let address = proof.address;
            let account_info = AccountInfo {
                nonce: proof.nonce.as_limbs()[0], // Is there a better way to do U64 -> u64?
                balance: proof.balance,
                code_hash: proof.code_hash,
                code: None, // TODO: fill this with code
            };
            inner.insert_account_info(address, account_info);
            for storage_proof in proof.storage_proof {
                // TODO: verify storage proof.
                let slot = storage_proof.key.0;
                let value = storage_proof.value;
                let _ = inner.insert_account_storage(address, slot.into(), value);
            }
        }
        Self { inner, state_root }
    }
}

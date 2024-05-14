//! A simple script that has takes in a block & RPC, fetches the block.

use alloy_provider::{Provider, ReqwestProvider};
use alloy_rpc_types::{BlockId, EIP1186AccountProofResponse};
use reth_revm::database::StateProviderDatabase;
use revm::db::InMemoryDB;
use url::Url;

struct RpcDb(ReqwestProvider);

// impl StateProvider for RpcDb {
//     fn storage(
//         &self,
//         account: Address,
//         storage_key: StorageKey,
//     ) -> ProviderResult<Option<StorageValue>> {
//     }

//     /// Get account code by its hash
//     fn bytecode_by_hash(&self, code_hash: B256) -> ProviderResult<Option<Bytecode>>;

//     /// Get account and storage proofs.
//     fn proof(&self, address: Address, keys: &[B256]) -> ProviderResult<AccountProof>;
// }

async fn execute() {
    let block = 1000u64;
    let rpc_url = Url::parse("https://example.net").expect("Invalid RPC URL");

    // Initialize a provider.
    let provider = ReqwestProvider::new_http(rpc_url);

    let header =
        provider.get_block_by_number(block.into(), false).await.expect("Couldn't fetch block");

    // Initialize a "provider" DB, where `Database` is implemented with a provider.
    // TODO: figure out how to keep track of what accounts are touched and fetch merkle proofs for
    // them on the fly.
    StateProviderDatabase::new()

    // // Inside the zkVM we will have
    // let state_root = ""; // TODO: read in the state root
    // let merkle_proofs = vec![]; // TODO: read in the merkle proofs
    // let db = WitnessDb::new(state_root, merkle_proofs);
    // let executor =
    //     reth_node_ethereum::EthExecutorProvider::ethereum(ChainSpec::Ethereum).executor(db);
    // executor.execute();

    // verify_against_header(db, finalized_state_root);
}

fn main() {}

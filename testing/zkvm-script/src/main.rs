//! A simple script that has takes in a block & RPC, fetches the block.
mod provider_db;
mod witness;

use crate::{provider_db::RpcDb, witness::WitnessDb};

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

pub struct SP1Input {
    // The block that will be executed inside the zkVM.
    pub block: RethBlock,
    // Used for initializing the InMemoryDB inside the zkVM program.
    pub merkle_proofs: Vec<EIP1186AccountProofResponse>,
    // Code
    pub code: Vec<Vec<u8>>,
}

// TODO: is there some automatic way to implement this?
// TODO: fix all the dummy ProviderError
impl Database for WitnessDb {
    type Error = ProviderError;

    fn basic(
        &mut self,
        address: revm_primitives::Address,
    ) -> Result<Option<AccountInfo>, Self::Error> {
        self.inner.basic(address).map_err(|_| ProviderError::UnsupportedProvider)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<revm_primitives::Bytecode, Self::Error> {
        self.inner.code_by_hash(code_hash).map_err(|_| ProviderError::UnsupportedProvider)
    }

    fn storage(
        &mut self,
        address: revm_primitives::Address,
        index: revm_primitives::U256,
    ) -> Result<revm_primitives::U256, Self::Error> {
        self.inner.storage(address, index).map_err(|_| ProviderError::UnsupportedProvider)
    }

    fn block_hash(&mut self, number: revm_primitives::U256) -> Result<B256, Self::Error> {
        self.inner.block_hash(number).map_err(|_| ProviderError::UnsupportedProvider)
    }
}

async fn execute() -> eyre::Result<()> {
    let block_number = 1000u64;
    let rpc_url = Url::parse("https://example.net").expect("Invalid RPC URL");
    let merkle_block_td = U256::from(0);

    // Initialize a provider.
    let provider = ReqwestProvider::new_http(rpc_url);

    let alloy_block = provider
        .get_block_by_number(block_number.into(), false)
        .await?
        .ok_or(eyre::eyre!("block not found"))?;

    let block = RethBlock::try_from(alloy_block)?;

    let chain_spec = ChainSpecBuilder::default()
        .chain(MAINNET.chain)
        .genesis(
            serde_json::from_str(include_str!(
                "../../../crates/ethereum/node/tests/assets/genesis.json"
            ))
            .unwrap(),
        )
        .cancun_activated()
        .build();
    let provider_db = RpcDb { provider: provider.clone(), block: block_number.into() };
    let db = StateProviderDatabase::new(provider_db);
    let executor =
        reth_node_ethereum::EthExecutorProvider::ethereum(chain_spec.clone().into()).executor(db);
    let BlockExecutionOutput { state, receipts, .. } = executor.execute(
        (
            &block
                .clone()
                .with_recovered_senders()
                .ok_or(BlockValidationError::SenderRecoveryError)?,
            (merkle_block_td + block.header.difficulty).into(),
        )
            .into(),
    )?;
    let block_state = BundleStateWithReceipts::new(
        state,
        Receipts::from_block_receipt(receipts),
        block.header.number,
    );

    // TODO: how do we compute the new state root here? Is there a way to do this incrementally?
    // // Unpacked `BundleState::state_root_slow` function
    // let (in_memory_state_root, in_memory_updates) =
    //     block_state.hash_state_slow().state_root_with_updates(provider.tx_ref())?;

    let next_block = provider
        .get_block_by_number((block_number + 1).into(), false)
        .await?
        .ok_or(eyre::eyre!("next_block not found"))?;

    // Now this is the program inside the zkVM.
    let sp1_input = SP1Input { block: block.clone(), merkle_proofs: vec![], code: vec![] };
    let witness_db = WitnessDb::new(sp1_input.block.header.state_root, sp1_input.merkle_proofs);
    let executor = reth_node_ethereum::EthExecutorProvider::ethereum(chain_spec.clone().into())
        .executor(witness_db);
    let BlockExecutionOutput { state, receipts, .. } = executor.execute(
        (
            &block
                .clone()
                .with_recovered_senders()
                .ok_or(BlockValidationError::SenderRecoveryError)?,
            (merkle_block_td + block.header.difficulty).into(),
        )
            .into(),
    )?;
    let block_state = BundleStateWithReceipts::new(
        state,
        Receipts::from_block_receipt(receipts),
        block.header.number,
    );

    // verify_against_header(db, finalized_state_root);

    Ok(())
}

fn main() {}

//! A simple script that has takes in a block & RPC, fetches the block.
mod provider_db;
mod witness;

use crate::{provider_db::RpcDb, witness::WitnessDb};

use alloy_rpc_types::{Block, BlockId, EIP1186AccountProofResponse};
use eyre::Ok;
use reth_evm::execute::{BlockExecutionOutput, BlockExecutorProvider, Executor};
use reth_interfaces::executor::BlockValidationError;
use reth_primitives::{Block as RethBlock, ChainSpecBuilder, Receipts, B256, MAINNET};
use reth_provider::{BundleStateWithReceipts, ProviderError};
use revm_primitives::U256;
use url::Url;

/// A struct that holds the input for a zkVM program to execute a block.
pub struct SP1Input {
    /// The block that will be executed inside the zkVM program.
    pub block: RethBlock,
    /// Used forinitializing the WitnessDB inside the zkVM program.
    pub merkle_proofs: Vec<EIP1186AccountProofResponse>,
    /// A vector of contract bytecode of the same length as [`merkle_proofs`].
    pub code: Vec<Vec<u8>>,
}

async fn get_input(block_number: u64, rpc_url: Url) -> eyre::Result<SP1Input> {
    // We put imports here that are not used in the zkVM program.
    use alloy_provider::{Provider, ReqwestProvider};
    use reth_revm::database::StateProviderDatabase;

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

    let next_block = provider
        .get_block_by_number((block_number + 1).into(), false)
        .await?
        .ok_or(eyre::eyre!("next_block not found"))?;

    // TODO: how do we compute the new state root here? Is there a way to do this incrementally?
    // // Unpacked `BundleState::state_root_slow` function
    // let (in_memory_state_root, in_memory_updates) =
    //     block_state.hash_state_slow().state_root_with_updates(provider.tx_ref())?;
    // TODO: check that the computed state_root matches the next_block.header.state_root

    let sp1_input = SP1Input { block: block.clone(), merkle_proofs: vec![], code: vec![] };
    Ok(sp1_input)
}

/// Program that verifies the STF, run inside the zkVM.
fn verify_stf(sp1_input: SP1Input) -> eyre::Result<()> {
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
    let block = sp1_input.block.clone();
    let merkle_block_td = U256::from(0); // TODO: this should be an input?

    let witness_db = WitnessDb::new(sp1_input.block.header.state_root, sp1_input.merkle_proofs);

    // TODO: can we import `EthExecutorProvider` from reth-evm instead of reth-node-ethereum?
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

    // TODO: either return or verify the resulting state root.
    Ok(())
}

#[tokio::main]
async fn main() {
    let block_number = 1000u64;
    let rpc_url = Url::parse("https://example.net").expect("Invalid RPC URL");
    // Get the input.
    let sp1_input = get_input(block_number, rpc_url).await.expect("Failed to get input");
    // Verify the STF.
    verify_stf(sp1_input).expect("Failed to verify STF");
}

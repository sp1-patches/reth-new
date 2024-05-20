//! A simple script that has takes in a block & RPC, fetches the block.
pub mod provider_db;
pub mod witness;

use crate::{provider_db::RpcDb, witness::WitnessDb};

use alloy_rpc_types::{Block, BlockId, EIP1186AccountProofResponse};
use ethers_providers::{Http, Middleware, Provider};
use eyre::Ok;
use reth_evm::execute::{BlockExecutionOutput, BlockExecutorProvider, Executor};
use reth_interfaces::executor::BlockValidationError;
use reth_primitives::{
    trie::{AccountProof, StorageProof},
    Account, Address, Block as RethBlock, ChainSpecBuilder, Receipts, B256, MAINNET,
};
use reth_provider::{BundleStateWithReceipts, ProviderError};
use revm::{db::CacheDB, Database};
use revm_primitives::{keccak256, AccountInfo, Bytecode, HashMap, U256};
use url::Url;

#[derive(Debug, Clone)]
/// A struct that holds the input for a zkVM program to execute a block.
pub struct SP1Input {
    /// The block that will be executed inside the zkVM program.
    pub block: RethBlock,
    /// Address to merkle proofs.
    pub address_to_proof: HashMap<Address, FullAccountProof>,
    /// Block number to block hash.
    pub block_hashes: HashMap<U256, B256>,
}

pub struct FullAccountProof {
    account_proof: AccountProof,
    code: Bytecode,
}

impl FullAccountProof {
    fn verify(&self, state_root: B256) -> eyre::Result<()> {
        self.account_proof.verify(state_root)?;
        // Assert that the code hash matches the code.
        // TODO: there is an optimization for EMPTY_CODE_HASH If the self.code is empty.
        let code_hash = keccak256(&self.code.0);
        if self.account_proof.info.unwrap().bytecode_hash.unwrap() != code_hash {
            return Err(eyre::eyre!("Code hash does not match the code"));
        }
        Ok(())
    }
}

async fn get_input(block_number: u64, rpc_url: Url) -> eyre::Result<SP1Input> {
    // We put imports here that are not used in the zkVM program.
    use alloy_provider::{Provider as AlloyProvider, ReqwestProvider};

    // Initialize a provider.
    let provider = ReqwestProvider::new_http(rpc_url);
    let merkle_block_td = U256::ZERO;
    // provider.header_td_by_number(block_number)?.unwrap_or_default();

    let alloy_block = provider
        .get_block_by_number(block_number.into(), true)
        .await?
        .ok_or(eyre::eyre!("block not found"))?;

    let block = RethBlock::try_from(alloy_block)?;
    for transaction in &block.body {
        println!("Transaction: {:?}", transaction);
    }

    let chain_spec = ChainSpecBuilder::default()
        .chain(MAINNET.chain)
        .genesis(
            serde_json::from_str(include_str!(
                "../../../crates/ethereum/node/tests/assets/genesis.json"
            ))
            .unwrap(),
        )
        .shanghai_activated()
        .build();
    let provider_db = RpcDb::new(provider.clone(), (block_number - 1).into());
    // The reason we can clone the provider_db is all the stateful elements are within Arcs.
    let db = CacheDB::new(provider_db.clone());

    println!("Instantiating executor");
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
    println!("Done processing block!");

    let next_block = provider
        .get_block_by_number((block_number + 1).into(), false)
        .await?
        .ok_or(eyre::eyre!("next_block not found"))?;

    // TODO: how do we compute the new state root here? Is there a way to do this incrementally?
    // // Unpacked `BundleState::state_root_slow` function
    // let (in_memory_state_root, in_memory_updates) =
    //     block_state.hash_state_slow().state_root_with_updates(provider.tx_ref())?;
    // TODO: check that the computed state_root matches the next_block.header.state_root

    let sp1_input = provider_db.get_sp1_input(&block).await;

    // This code will be the code that runs inside the zkVM.
    let witness_db_inner = WitnessDb::new(sp1_input.clone());
    let witness_db = CacheDB::new(witness_db_inner);

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

    Ok(sp1_input.clone())
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
        .shanghai_activated()
        .build();
    let block = sp1_input.block.clone();
    let merkle_block_td = U256::from(0); // TODO: this should be an input?

    let witness_db_inner = WitnessDb::new(sp1_input.clone());
    let witness_db = CacheDB::new(witness_db_inner);

    // let provider_db = RpcDb::new(provider.clone(), (block_number - 1).into());
    // let db = CacheDB::new(provider_db.clone());
    // let check_db =
    //     witness_db::CheckDb { witness: witness_db.clone(), rpc: RpcDb::new(provider_db) };

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
    let block_number = 18884864u64;
    let rpc_url =
        Url::parse("https://eth-mainnet.g.alchemy.com/v2/hIxcf_hqT9It2hS8iCFeHKklL8tNyXNF")
            .expect("Invalid RPC URL");
    println!("Fetching block number {} from {}", block_number, rpc_url);
    // Get the input.
    let sp1_input = get_input(block_number, rpc_url).await.expect("Failed to get input");
    // Verify the STF.
    verify_stf(sp1_input).expect("Failed to verify STF");
}

//! A simple script that has takes in a block & RPC, fetches the block.
pub mod provider_db;
pub mod witness;

use crate::{
    provider_db::RpcDb,
    witness::{CheckDb, WitnessDb},
};

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
use revm_primitives::{AccountInfo, HashMap, U256};
use url::Url;

fn convert_proof(proof: EIP1186AccountProofResponse) -> AccountProof {
    let address = proof.address;
    let balance = proof.balance;
    let code_hash = proof.code_hash;
    let nonce = proof.nonce.as_limbs()[0];
    let storage_hash = proof.storage_hash;
    let account_proof = proof.account_proof;
    let account_info = Account { nonce, balance, bytecode_hash: code_hash.into() };
    let storage_proofs = proof.storage_proof.into_iter().map(|storage_proof| {
        let key = storage_proof.key;
        let value = storage_proof.value;
        let proof = storage_proof.proof;
        let mut sp = StorageProof::new(key.0.into());
        sp.set_value(value);
        sp.set_proof(proof);
        sp
    });
    AccountProof {
        address,
        info: Some(account_info),
        proof: account_proof,
        storage_root: storage_hash.into(),
        storage_proofs: storage_proofs.collect(),
    }
}

#[derive(Debug, Clone)]
/// A struct that holds the input for a zkVM program to execute a block.
pub struct SP1Input {
    /// The block that will be executed inside the zkVM program.
    pub block: RethBlock,
    /// Address to merkle proofs.
    pub address_to_proof: HashMap<Address, EIP1186AccountProofResponse>,
    /// Block number to block hash.
    pub block_hashes: HashMap<U256, B256>,
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

    // println!("Got address_to_storage: {:?}", address_to_storage);

    // let sp1_input = SP1Input {
    //     block: block.clone(),
    //     merkle_proofs: merkle_proofs.clone(),
    //     address_to_account_info: provider_db.address_to_account_info.read().unwrap().clone(),
    //     address_to_storage: address_to_storage.clone(),
    //     block_hashes: provider_db.block_hashes.read().unwrap().clone(),
    //     code: code.clone(),
    // };

    // Now we do the check
    let witness_db_inner = WitnessDb::new(sp1_input.clone());
    let witness_db = CacheDB::new(witness_db_inner);

    // let address: Address = "0xCb2286d9471cc185281c4f763d34A962ED212962".parse().unwrap();
    // let index = U256::from(7);
    // let result = witness_db.storage(address, index);

    // let check_db = CheckDb { witness: witness_db, rpc: db };

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

//! A simple script that has takes in a block & RPC, fetches the block.
pub mod cache;
pub mod provider_db;
pub mod witness;

use crate::{cache::CachedProvider, provider_db::RpcDb, witness::WitnessDb};

use alloy_primitives::Bytes;
use alloy_provider::Provider;
use alloy_rlp::{Decodable, Encodable};
use eyre::Ok;
use reth_evm::execute::{BlockExecutionOutput, BlockExecutorProvider, Executor};
use reth_interfaces::executor::BlockValidationError;
use reth_primitives::{
    revm::compat::into_reth_acc,
    trie::{
        nodes::{TrieNode, CHILD_INDEX_RANGE},
        AccountProof, HashBuilder, Nibbles, TrieAccount,
    },
    Address, Block as RethBlock, ChainSpecBuilder, Receipts, B256, MAINNET,
};
use reth_provider::BundleStateWithReceipts;
use reth_trie::{HashedPostState, HashedStorage};
use revm::db::CacheDB;
use revm_primitives::{keccak256, Bytecode, HashMap, U256};
use url::Url;

#[derive(Debug, Clone)]
/// A struct that holds the input for a zkVM program to execute a block.
pub struct SP1Input {
    /// The previous block.
    pub prev_block: RethBlock,
    /// The block that will be executed inside the zkVM program.
    pub block: RethBlock,
    /// Address to merkle proofs.
    pub address_to_proof: HashMap<Address, FullAccountProof>,
    /// Block number to block hash.
    pub block_hashes: HashMap<U256, B256>,
}

#[derive(Debug, Clone)]
pub struct FullAccountProof {
    account_proof: AccountProof,
    code: Bytecode,
}

impl FullAccountProof {
    fn verify(&self, state_root: B256) -> eyre::Result<()> {
        self.account_proof.verify(state_root)?;
        // Assert that the code hash matches the code.
        // TODO: there is an optimization for EMPTY_CODE_HASH If the self.code is empty.
        let code_hash = keccak256(self.code.bytes());
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

    let prev_alloy_block = provider
        .get_block_by_number((block_number - 1).into(), true)
        .await?
        .ok_or(eyre::eyre!("prev_block not found"))?;
    let prev_block = RethBlock::try_from(prev_alloy_block)?;
    let prev_state_root = prev_block.header.state_root;

    let cache_provider = provider.clone();
    let provider_db =
        RpcDb::new(cache_provider.clone(), (block_number - 1).into(), prev_state_root.into());
    // The reason we can clone the provider_db is all the stateful elements are within Arcs.
    let db = CacheDB::new(provider_db.clone());

    println!("Executing block with provider db...");
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

    // let _next_block = provider
    //     .get_block_by_number((block_number + 1).into(), false)
    //     .await?
    //     .ok_or(eyre::eyre!("next_block not found"))?;

    // TODO: how do we compute the new state root here? Is there a way to do this incrementally?
    // // Unpacked `BundleState::state_root_slow` function
    // let (in_memory_state_root, in_memory_updates) =
    //     block_state.hash_state_slow().state_root_with_updates(provider.tx_ref())?;

    let _state_root = update_state_root(&provider_db, &block_state).await?;

    // TODO: check that the computed state_root matches the next_block.header.state_root

    let sp1_input = provider_db.get_sp1_input(&prev_block, &block).await;

    Ok(sp1_input.clone())
}

async fn update_state_root(
    provider_db: &RpcDb,
    block_state: &BundleStateWithReceipts,
) -> eyre::Result<B256> {
    let mut account_reverse_lookup = HashMap::<B256, Address>::default();
    let mut storage_reverse_lookup = HashMap::<B256, B256>::default();
    let mut hashed_state = HashedPostState::default();
    for (address, account) in block_state.bundle_accounts_iter() {
        let hashed_address = keccak256(address);
        account_reverse_lookup.insert(hashed_address, address);
        hashed_state.accounts.insert(hashed_address, account.info.clone().map(into_reth_acc));

        let mut hashed_storage = HashedStorage::new(account.status.was_destroyed());
        for (key, value) in &account.storage {
            let slot = B256::new(key.to_be_bytes());
            let hashed_slot = keccak256(&slot);
            storage_reverse_lookup.insert(hashed_slot, slot);
            hashed_storage.storage.insert(hashed_slot, value.present_value);
        }
        hashed_state.storages.insert(hashed_address, hashed_storage);
    }

    let mut rlp_buf = Vec::with_capacity(128);
    let mut hash_builder = HashBuilder::default();
    let mut prefix_sets = hashed_state.construct_prefix_sets();
    let mut account_prefix_set_iter =
        prefix_sets.account_prefix_set.keys.as_ref().iter().peekable();
    while let Some(account_nibbles) = account_prefix_set_iter.next() {
        let hashed_address = B256::from_slice(&account_nibbles.pack());
        let storage_prefix_sets =
            prefix_sets.storage_prefix_sets.remove(&hashed_address).unwrap_or_default();
        let storage_keys = storage_prefix_sets
            .keys
            .iter()
            .map(|nibbles| *storage_reverse_lookup.get(&B256::from_slice(&nibbles.pack())).unwrap())
            .collect::<Vec<_>>();

        // TODO: calls should be parallelized
        let proof = provider_db
            .provider
            .get_proof(*account_reverse_lookup.get(&hashed_address).unwrap(), storage_keys.clone())
            .await?;

        let storage_root = if proof.storage_proof.is_empty() {
            proof.storage_hash
        } else {
            let mut storage_hash_builder = HashBuilder::default();
            let mut storage_prefix_set_iter = storage_prefix_sets.keys.as_ref().iter().peekable();
            while let Some(storage_nibbles) = storage_prefix_set_iter.next() {
                let hashed_slot = B256::from_slice(&storage_nibbles.pack());
                let slot = storage_reverse_lookup.get(&hashed_slot).unwrap();
                let proof = proof.storage_proof.iter().find(|p| &p.key.0 == slot).unwrap();
                update_hash_builder_from_proof(
                    &mut storage_hash_builder,
                    &proof.proof,
                    Nibbles::default(),
                    storage_nibbles,
                    // TODO: handle zero
                    alloy_rlp::encode_fixed_size(
                        &hashed_state
                            .storages
                            .get(&hashed_address)
                            .and_then(|s| s.storage.get(&hashed_slot).cloned())
                            .unwrap_or_default(),
                    )
                    .as_ref(),
                    storage_prefix_set_iter.peek().copied(),
                )?;
            }
            storage_hash_builder.root()
        };

        // TODO: handle destroyed accounts
        rlp_buf.clear();
        TrieAccount::from((
            hashed_state.accounts.get(&hashed_address).unwrap().unwrap_or_default(),
            storage_root,
        ))
        .encode(&mut rlp_buf);

        update_hash_builder_from_proof(
            &mut hash_builder,
            &proof.account_proof[..],
            Nibbles::default(),
            &account_nibbles,
            &rlp_buf,
            account_prefix_set_iter.peek().copied(),
        )?;
    }

    Ok(hash_builder.root())
}

fn update_hash_builder_from_proof(
    hash_builder: &mut HashBuilder,
    proof: &[Bytes],
    current_key: Nibbles,
    key: &Nibbles,
    value: &[u8],
    next: Option<&Nibbles>,
) -> eyre::Result<()> {
    let Some(node) = proof.first() else {
        // add leaf node
        hash_builder.add_leaf(key.clone(), value);
        return Ok(())
    };

    match TrieNode::decode(&mut &node[..])? {
        TrieNode::Branch(branch) => {
            let mut stack_ptr = branch.as_ref().first_child_index();
            for index in CHILD_INDEX_RANGE {
                let mut updated_key = current_key.clone();
                updated_key.push(index);

                // we should not be adding more
                if Some(&updated_key) <= next {
                    return Ok(())
                }

                if branch.state_mask.is_bit_set(index) {
                    if key.starts_with(&updated_key) {
                        let rem = &proof[std::cmp::min(1, proof.len().saturating_sub(1))..];
                        update_hash_builder_from_proof(
                            hash_builder,
                            rem,
                            updated_key,
                            key,
                            value,
                            next,
                        )?;
                    } else {
                        hash_builder.add_branch(
                            updated_key,
                            // proofs can only contain hashes
                            B256::from_slice(&branch.stack[stack_ptr]),
                            false,
                        );
                    }

                    stack_ptr += 1;
                }
            }
        }
        // overwrite the leaf node
        TrieNode::Leaf(_) => {
            hash_builder.add_leaf(key.clone(), value);
        }
        // noop
        TrieNode::Extension(_) => {}
    };

    Ok(())
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

    println!("Instantiating WitnessDb from SP1Input...");
    let witness_db_inner = WitnessDb::new(sp1_input.clone());
    let witness_db = CacheDB::new(witness_db_inner);
    println!("Executing block with witness db...");

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
    println!("Done processing block!");
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

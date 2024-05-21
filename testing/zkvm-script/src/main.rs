//! A simple script that has takes in a block & RPC, fetches the block.
pub mod cache;
pub mod provider_db;
pub mod witness;

use crate::{provider_db::RpcDb, witness::WitnessDb};

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
        AccountProof, HashBuilder, Nibbles, TrieAccount, EMPTY_ROOT_HASH,
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

    let state_root = update_state_root(&provider_db, &block_state).await?;
    if state_root != block.state_root {
        eyre::bail!("mismatched state root");
    } else {
        println!("Successfully verified state root");
    }

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

    // Reconstruct prefix sets manually to record pre-images for subsequent lookups
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

    let mut prefix_sets = hashed_state.construct_prefix_sets();
    let mut hash_builder = HashBuilder::default();
    let mut account_prefix_set_iter =
        prefix_sets.account_prefix_set.keys.as_ref().iter().peekable();
    while let Some(account_nibbles) = account_prefix_set_iter.next() {
        let hashed_address = B256::from_slice(&account_nibbles.pack());
        let address = *account_reverse_lookup.get(&hashed_address).unwrap();
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
            .get_proof(address, storage_keys.clone())
            .block_id(provider_db.block)
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
                    Some(
                        hashed_state
                            .storages
                            .get(&hashed_address)
                            .and_then(|s| s.storage.get(&hashed_slot).cloned())
                            .unwrap_or_default(),
                    )
                    .filter(|v| !v.is_zero())
                    .map(|v| alloy_rlp::encode_fixed_size(&v).to_vec()),
                    storage_prefix_set_iter.peek().copied(),
                )?;
            }
            storage_hash_builder.root()
        };

        let account = hashed_state.accounts.get(&hashed_address).unwrap().unwrap_or_default();
        let encoded = if account.is_empty() && storage_root == EMPTY_ROOT_HASH {
            None
        } else {
            rlp_buf.clear();
            TrieAccount::from((account, storage_root)).encode(&mut rlp_buf);
            Some(rlp_buf.clone())
        };

        update_hash_builder_from_proof(
            &mut hash_builder,
            &proof.account_proof[..],
            Nibbles::default(),
            &account_nibbles,
            encoded,
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
    value: Option<Vec<u8>>,
    next: Option<&Nibbles>,
) -> eyre::Result<()> {
    let Some(node) = proof.first() else {
        // Add leaf node if any
        if let Some(value) = &value {
            hash_builder.add_leaf(key.clone(), value);
        }
        return Ok(())
    };

    match TrieNode::decode(&mut &node[..])? {
        TrieNode::Branch(branch) => {
            let mut stack_ptr = branch.as_ref().first_child_index();
            for index in CHILD_INDEX_RANGE {
                let mut updated_key = current_key.clone();
                updated_key.push(index);

                let state_mask_bit_set = branch.state_mask.is_bit_set(index);

                if key.starts_with(&updated_key) {
                    update_hash_builder_from_proof(
                        hash_builder,
                        if proof.len() != 0 { &proof[1..] } else { &[] },
                        updated_key,
                        key,
                        value.clone(),
                        next,
                    )?;
                } else if state_mask_bit_set &&
                    updated_key > hash_builder.key &&
                    next.map_or(true, |n| &updated_key < n && !n.starts_with(&updated_key))
                {
                    hash_builder.add_branch(
                        updated_key,
                        // proofs can only contain hashes
                        B256::from_slice(&branch.stack[stack_ptr][1..]),
                        false,
                    );
                }

                if state_mask_bit_set {
                    stack_ptr += 1;
                }
            }
        }

        TrieNode::Extension(extension) => {
            let mut updated_key = current_key.clone();
            updated_key.extend_from_slice(&extension.key);
            update_hash_builder_from_proof(
                hash_builder,
                if proof.len() == 0 { &[] } else { &proof[1..] },
                updated_key,
                key,
                value.clone(),
                next,
            )?;
        }
        TrieNode::Leaf(leaf) => {
            let mut updated_key = current_key.clone();
            updated_key.extend_from_slice(&leaf.key);

            // Add current leaf node and supplied if any
            let mut leaves = Vec::new();
            if &updated_key != key {
                leaves.push((updated_key, &leaf.value));
            }
            if let Some(value) = &value {
                leaves.push((key.clone(), &value));
            }
            leaves.sort_unstable_by_key(|(key, _)| key.clone());
            for (nibbles, value) in leaves {
                hash_builder.add_leaf(nibbles, value);
            }
        }
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

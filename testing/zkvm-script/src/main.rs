//! A simple script that has takes in a block & RPC, fetches the block.
pub mod cache;
pub mod provider_db;
pub mod witness;

use std::collections::{BTreeMap, HashSet};

use crate::{provider_db::RpcDb, witness::WitnessDb};

use alloy_primitives::Bytes;
use alloy_provider::Provider;
use alloy_rlp::{Decodable, Encodable};
use eyre::Ok;
use futures::stream::FuturesUnordered;
use itertools::Either;
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

    let proof_futs = FuturesUnordered::default();
    // Reconstruct prefix sets manually to record pre-images for subsequent lookups
    for (address, account) in block_state.bundle_accounts_iter() {
        let hashed_address = keccak256(address);
        account_reverse_lookup.insert(hashed_address, address);
        hashed_state.accounts.insert(hashed_address, account.info.clone().map(into_reth_acc));

        let mut storage_keys = Vec::new();
        let mut hashed_storage = HashedStorage::new(account.status.was_destroyed());
        for (key, value) in &account.storage {
            let slot = B256::new(key.to_be_bytes());
            let hashed_slot = keccak256(&slot);
            storage_keys.push(slot);
            storage_reverse_lookup.insert(hashed_slot, slot);
            hashed_storage.storage.insert(hashed_slot, value.present_value);
        }
        hashed_state.storages.insert(hashed_address, hashed_storage);

        let provider = provider_db.provider.clone();
        proof_futs.push(Box::pin(async move {
            provider.get_proof(address, storage_keys).block_id(provider_db.block).await
        }));
    }

    let proof_responses: Vec<_> = futures::TryStreamExt::try_collect(proof_futs).await?;

    let prefix_sets = hashed_state.construct_prefix_sets();

    let mut storage_roots = HashMap::<B256, B256>::default();
    for account_nibbles in prefix_sets.account_prefix_set.keys.as_ref() {
        let hashed_address = B256::from_slice(&account_nibbles.pack());
        let address = *account_reverse_lookup.get(&hashed_address).unwrap();
        let storage_prefix_sets =
            prefix_sets.storage_prefix_sets.get(&hashed_address).cloned().unwrap_or_default();

        let proof = proof_responses.iter().find(|x| x.address == address).unwrap();

        let root = if proof.storage_proof.is_empty() {
            proof.storage_hash
        } else {
            compute_root_from_proofs(storage_prefix_sets.keys.as_ref().iter().map(
                |storage_nibbles| {
                    let hashed_slot = B256::from_slice(&storage_nibbles.pack());
                    let slot = storage_reverse_lookup.get(&hashed_slot).unwrap();
                    let storage_proof =
                        proof.storage_proof.iter().find(|x| &x.key.0 == slot).unwrap();
                    let encoded = Some(
                        hashed_state
                            .storages
                            .get(&hashed_address)
                            .and_then(|s| s.storage.get(&hashed_slot).cloned())
                            .unwrap_or_default(),
                    )
                    .filter(|v| !v.is_zero())
                    .map(|v| alloy_rlp::encode_fixed_size(&v).to_vec());
                    (storage_nibbles.clone(), encoded, storage_proof.proof.clone())
                },
            ))?
        };
        storage_roots.insert(hashed_address, root);
    }

    let mut rlp_buf = Vec::with_capacity(128);

    compute_root_from_proofs(prefix_sets.account_prefix_set.keys.as_ref().iter().map(
        |account_nibbles| {
            let hashed_address = B256::from_slice(&account_nibbles.pack());
            let address = *account_reverse_lookup.get(&hashed_address).unwrap();
            let proof = proof_responses.iter().find(|x| x.address == address).unwrap();

            let storage_root = *storage_roots.get(&hashed_address).unwrap();

            let account = hashed_state.accounts.get(&hashed_address).unwrap().unwrap_or_default();
            let encoded = if account.is_empty() && storage_root == EMPTY_ROOT_HASH {
                None
            } else {
                rlp_buf.clear();
                TrieAccount::from((account, storage_root)).encode(&mut rlp_buf);
                Some(rlp_buf.clone())
            };
            (account_nibbles.clone(), encoded, proof.account_proof.clone())
        },
    ))
}

fn compute_root_from_proofs(
    items: impl IntoIterator<Item = (Nibbles, Option<Vec<u8>>, Vec<Bytes>)>,
) -> eyre::Result<B256> {
    let mut trie_nodes = BTreeMap::default();

    for (key, value, proof) in items {
        let mut path = Nibbles::default();
        for encoded in proof {
            let mut next_path = path.clone();
            match TrieNode::decode(&mut &encoded[..])? {
                TrieNode::Branch(branch) => {
                    next_path.push(key[path.len()]);
                    let mut stack_ptr = branch.as_ref().first_child_index();
                    for index in CHILD_INDEX_RANGE {
                        let mut branch_child_path = path.clone();
                        branch_child_path.push(index);

                        if branch.state_mask.is_bit_set(index) {
                            if !key.starts_with(&branch_child_path) {
                                trie_nodes.insert(
                                    branch_child_path,
                                    Either::Left(B256::from_slice(&branch.stack[stack_ptr][1..])),
                                );
                            }
                            stack_ptr += 1;
                        }
                    }
                }
                TrieNode::Extension(extension) => {
                    next_path.extend_from_slice(&extension.key);
                }
                TrieNode::Leaf(leaf) => {
                    next_path.extend_from_slice(&leaf.key);
                    if next_path != key {
                        trie_nodes.insert(next_path.clone(), Either::Right(leaf.value.clone()));
                    }
                }
            };
            path = next_path;
        }

        if let Some(value) = value {
            trie_nodes.insert(key, Either::Right(value));
        }
    }

    // ignore branch child hashes in the path of leaves
    // or lower child hashes
    let mut keys = trie_nodes.keys().peekable();
    let mut ignored_keys = HashSet::<Nibbles>::default();
    while let Some(key) = keys.next() {
        if keys.peek().map_or(false, |next| next.starts_with(&key)) {
            ignored_keys.insert(key.clone());
        }
    }

    let mut hash_builder = HashBuilder::default();
    let mut trie_nodes =
        trie_nodes.into_iter().filter(|(path, _)| !ignored_keys.contains(path)).peekable();
    while let Some((path, value)) = trie_nodes.next() {
        match value {
            Either::Left(branch_hash) => {
                let parent_branch_path = path.slice(..path.len() - 1);
                if hash_builder.key.starts_with(&parent_branch_path) ||
                    trie_nodes
                        .peek()
                        .map_or(false, |next| next.0.starts_with(&parent_branch_path))
                {
                    hash_builder.add_branch(path, branch_hash, false);
                } else {
                    // parent is a branch node that needs to be turned into extension
                    todo!()
                }
            }
            Either::Right(leaf_value) => {
                hash_builder.add_leaf(path, &leaf_value);
            }
        }
    }
    let root = hash_builder.root();
    Ok(root)
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

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
        proof::ProofRetainer,
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

    let state_root = update_state_root(&provider_db, &block_state, block_number).await?;
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
    block_number: u64,
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
            let (root, all_proof_nodes) =
                compute_root_from_proofs(storage_prefix_sets.keys.as_ref().iter().map(|storage_nibbles| {
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
                }))?;

            let storage_keys = storage_prefix_sets
                .keys
                .iter()
                .map(|nibbles| {
                    *storage_reverse_lookup.get(&B256::from_slice(&nibbles.pack())).unwrap()
                })
                .collect::<Vec<_>>();

            let expected_proof = provider_db
                .provider
                .get_proof(address, storage_keys.clone())
                .block_id(block_number.into())
                .await
                .unwrap();

            for nibbles in storage_prefix_sets.keys.iter() {
                // Iterate over all proof nodes and find the matching ones.
                // The filtered results are guaranteed to be in order.
                let matching_proof_nodes = all_proof_nodes
                    .iter()
                    .filter(|(path, _)| nibbles.starts_with(path))
                    .map(|(_, node)| node.clone())
                    .collect::<Vec<_>>();
                let storage_slot =
                    storage_reverse_lookup.get(&B256::from_slice(&nibbles.pack())).unwrap();
                let expected =
                    expected_proof.storage_proof.iter().find(|p| &p.key.0 == storage_slot).unwrap();

                similar_asserts::assert_eq!(
                    matching_proof_nodes,
                    expected.proof,
                    "mismatched proofs for {} (hashed {}) at slot {} (hashed {}). block {}",
                    account_reverse_lookup.get(&hashed_address).unwrap(),
                    hashed_address,
                    storage_slot,
                    B256::from_slice(&nibbles.pack()),
                    block_number
                );
            }

            root
        };
        storage_roots.insert(hashed_address, root);
    }

    let mut rlp_buf = Vec::with_capacity(128);

    let (root, _) =
        compute_root_from_proofs(prefix_sets.account_prefix_set.keys.as_ref().iter().map(|account_nibbles| {
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
        }))?;
    Ok(root)
}

fn compute_root_from_proofs(
    items: impl IntoIterator<Item = (Nibbles, Option<Vec<u8>>, Vec<Bytes>)>, 
) -> eyre::Result<(B256, BTreeMap<Nibbles, Bytes>)> {
    let mut trie_nodes = BTreeMap::default();

    // TODO: remove
    let mut proofs_to_retain = Vec::new();
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
                                    Either::Left(B256::from_slice(
                                        &branch.stack[stack_ptr][1..],
                                    )),
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
                        trie_nodes.insert(
                            next_path.clone(),
                            Either::Right(leaf.value.clone()),
                        );
                    }
                }
            };
            path = next_path;
        }

        proofs_to_retain.push(key.clone());
        if let Some(value) = value {
            trie_nodes.insert(key.clone(), Either::Right(value));
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

    // TODO: remove
    let retainer = ProofRetainer::from_iter(proofs_to_retain);
    let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);
    let mut to_add = trie_nodes.into_iter().filter(|(path, _)| !ignored_keys.contains(path)).peekable();
    while let Some((path, value)) = to_add.next() {
        match value {
            Either::Left(branch_hash) => {
                let peeked = to_add.peek();
                let parent_branch_path = path.slice(..path.len() - 1);
                println!(
                    "considering branch: {:?}. hash builder key: {:?}. next: {:?}. parent: {:?}. adding: {} || {}",
                    path,
                    hash_builder.key,
                    peeked,
                    parent_branch_path,
                    hash_builder.key.starts_with(&parent_branch_path), 
                    peeked.map_or(false, |next| next.0.starts_with(&parent_branch_path))
                );
                if hash_builder.key.starts_with(&parent_branch_path) ||
                    to_add.peek().map_or(false, |next| next.0.starts_with(&parent_branch_path))
                {
                    hash_builder.add_branch(path, branch_hash, false);
                } else {
                    // parent is a branch node that needs to be turned into extension
                    todo!()
                }
            }
            Either::Right(leaf_value) => {
                println!(
                    "adding leaf: {:?}. hash builder key: {:?}. next: {:?}.  value: {:?}",
                    path,
                    hash_builder.key,
                    to_add.peek(),
                    leaf_value
                );
                hash_builder.add_leaf(path, &leaf_value);
            }
        }
    }
    let root = hash_builder.root();
    let proofs = hash_builder.take_proofs();
    Ok((root, proofs))
}

// hashed slot: 0x19e79c65572283f6545c06718dba7ebac5dd4e41dcb17c678dffdce8a8b8b983
// neighbor hashed slot: 0x19e7e0637a3a68ed6a0a2709bf1328a4d803cff945c17cd67e013544d9a9730a

// Original
// root: 0xf90211a093f53296837ff36c948861bdb424c8caf9cfc328c7b39188088a436ecaa35d60a02b038a83b9a2474bd01b09822d602c41212cf06ebd0bf97741875cb0e43b9cf2a0aeccd8da54e917754f2509b3d28b50734488bb1a0b9c1ddf8a71fd89ae7c7c51a0703701ad54f64a132278315001ffe671a7a2b46a50f2e1106e9a11edd2fcc568a0f512b08653b42eaf7da1850a6a2d41ad673b5088f8ed20cfd9cb2f275f0511e3a0f4381926982b6a9fe86e8b5f933ee6057eace01d301d31fa880046ecaa433418a04c0beb17898e1f745685e75a7d9d4dfe96a91f26d5f8a76cea4942b505c43fa5a0d43cb6ca0abcbff483613e1418dd7b66a9d8f07cd6cff0a139cac8fda24b1394a045bbb1e4cd7a3ea71f8160c39df5c7bf5fdcfa6604b7f8a5e9abe16eac15f73aa0ae7948adac8b4f3fe2867b9439f37fbd4ccf07cee9cc89b61202a26f531bdda5a0300f18e2b5bc63ea840b17bbeb3d10e983ec42bc95b568153f58e7256bf24a37a0af5cc4b8f901aff06ef831495bbb2da7b552690108f5d663ae42dc41a47a7df9a025c5636672cc01e33e6540fde11ee108392c0a8b28472b35032ad2d796127f73a0d13b474697d727271320726e692ce929fc59ac617bdc60aef840bb540ef6ce3da0d86aa7388a0efcb7fd0004955b1cb938aa233404e683fa8ebac1f263ba1f2520a063d1bbf4c30c81d482307b3f72ed73a0f268aafa2f99fa5f4b059a099920a6d980,
// 1: 0xf90211a08b9d720c41c294e2c6b619b7b63727917a88921514884521f7f1768cdef29b3aa0637be999926bdb4941978e45d3e6df5c480bdce5bebc588b6f17cd9ba833018ca0a066b524c57aab439f24ccc94952c198d28ecfaf8aa6e134115b904f662670a6a0cc078fc393d4c76f7fcf47b09c06f6df7e6f5af64b1fee38ae2cde29afb9f685a0932bb11bc5dd354a4228f6a47f01890513005d438d8615e5d6b8f56d7d0a9e25a01c82eca0a099cc276fe87d1865771bacc3d4fd21b8c8963c1c1a5ef10074becda00832db7f4571c59427a43c090723223419090978d09df3966cc5005f692fd47aa094f33825469131e3c55d65a3b453a25697829cbdbb5c2bcd690ac8a4397d18b1a05e6eea014b018e73f622b774f769bbccf62a04aeabaada1323f8df27d614481aa06fabb7900ad5c1f4c19b72a33295df6188287f3588b055fdb5703a3d78553852a072ac7f0450df09921bc114a296995cfd0ff3fffc8113649abc1d7349d909911aa0b2c9ef9bb20e0035d489c5f19b26dabd3914e2a85a47c3a2b4dab45aa40f1118a081ab378478178a64469c45d267726e6e09aa3188d60d30e5a573f8754bf299afa01322ae4928e0cbfb860cdc090b190d22c20abbbc84f76d52011f72e30cd9c05aa0c7695e3f91222d3679eb989ce0f678b28e65bd4ca9bc674e893cdf1dfa938131a06a7e78b836043df994158040d52db1b51175f841118ff9fd93420c230f257d6180,
// 9: 0xf8b180a0f8fef385de3777478d3463c0613ebff67f484481f1c06f11879def1423b99ca680a0c0348cee59bd6e702c332aa4f7e91ab93af9adf57195cd17bf5fdb85a4242fab80808080a06d4b4ab1e312f3a9174c532350d3133ba92dd0d763c10276db67276cb134303e80a0475f5df490d6ec0abaf1fac328259cff82effc83f5ff49ba60303aafb574ac1c808080a0b2a4dc5579b32ea95c1e7d6a022d85ec5ae5b43cd9ba5f48e70ff86cd6fb16cf8080,
// e: 0xf85180808080808080a05a0d7d67dc7407dbdca8295776d4a0ba69c2afa7632d1b438076aa8d6eb82e578080808080a0d86a294d8fa338b8302cce695b5c3c9312b02ff38d3fc52162d34824e76b1d2b808080,
// 7: 0xf851808080808080808080a0517196a0b0b13d7f486614b6dded0d7f19167d10f36dba0ba699b4b784653ed180808080a0fb2f566725f96184b433cd4ada3c2bb8d8dad89f8397ed849b64bd4236975b838080,
// 9: 0xf8419e3c65572283f6545c06718dba7ebac5dd4e41dcb17c678dffdce8a8b8b983a1a0ffffffffffffffffffffffffffffffffffffffffef734b9da55b73cc8d21ed45

// Got:
// -    root: 0xf90211a093f53296837ff36c948861bdb424c8caf9cfc328c7b39188088a436ecaa35d60a04f0c440646fd2e16ef733b48a1c6b3c0aa1fce2122606407376abc10084915b0a0aeccd8da54e917754f2509b3d28b50734488bb1a0b9c1ddf8a71fd89ae7c7c51a0703701ad54f64a132278315001ffe671a7a2b46a50f2e1106e9a11edd2fcc568a0f512b08653b42eaf7da1850a6a2d41ad673b5088f8ed20cfd9cb2f275f0511e3a0f4381926982b6a9fe86e8b5f933ee6057eace01d301d31fa880046ecaa433418a04c0beb17898e1f745685e75a7d9d4dfe96a91f26d5f8a76cea4942b505c43fa5a0d43cb6ca0abcbff483613e1418dd7b66a9d8f07cd6cff0a139cac8fda24b1394a045bbb1e4cd7a3ea71f8160c39df5c7bf5fdcfa6604b7f8a5e9abe16eac15f73aa0ae7948adac8b4f3fe2867b9439f37fbd4ccf07cee9cc89b61202a26f531bdda5a0300f18e2b5bc63ea840b17bbeb3d10e983ec42bc95b568153f58e7256bf24a37a0af5cc4b8f901aff06ef831495bbb2da7b552690108f5d663ae42dc41a47a7df9a025c5636672cc01e33e6540fde11ee108392c0a8b28472b35032ad2d796127f73a0d13b474697d727271320726e692ce929fc59ac617bdc60aef840bb540ef6ce3da0d86aa7388a0efcb7fd0004955b1cb938aa233404e683fa8ebac1f263ba1f2520a063d1bbf4c30c81d482307b3f72ed73a0f268aafa2f99fa5f4b059a099920a6d980,
// -    1: 0xf90211a08b9d720c41c294e2c6b619b7b63727917a88921514884521f7f1768cdef29b3aa0637be999926bdb4941978e45d3e6df5c480bdce5bebc588b6f17cd9ba833018ca0a066b524c57aab439f24ccc94952c198d28ecfaf8aa6e134115b904f662670a6a0cc078fc393d4c76f7fcf47b09c06f6df7e6f5af64b1fee38ae2cde29afb9f685a0932bb11bc5dd354a4228f6a47f01890513005d438d8615e5d6b8f56d7d0a9e25a01c82eca0a099cc276fe87d1865771bacc3d4fd21b8c8963c1c1a5ef10074becda00832db7f4571c59427a43c090723223419090978d09df3966cc5005f692fd47aa094f33825469131e3c55d65a3b453a25697829cbdbb5c2bcd690ac8a4397d18b1a05e6eea014b018e73f622b774f769bbccf62a04aeabaada1323f8df27d614481aa094cbfc3f2cb6084d6fec9364000c14f7e2a396ca0b96585cc361ce766f5e45c1a072ac7f0450df09921bc114a296995cfd0ff3fffc8113649abc1d7349d909911aa0b2c9ef9bb20e0035d489c5f19b26dabd3914e2a85a47c3a2b4dab45aa40f1118a081ab378478178a64469c45d267726e6e09aa3188d60d30e5a573f8754bf299afa01322ae4928e0cbfb860cdc090b190d22c20abbbc84f76d52011f72e30cd9c05aa0c7695e3f91222d3679eb989ce0f678b28e65bd4ca9bc674e893cdf1dfa938131a06a7e78b836043df994158040d52db1b51175f841118ff9fd93420c230f257d6180,
// -    9: 0xf8b180a0f8fef385de3777478d3463c0613ebff67f484481f1c06f11879def1423b99ca680a0c0348cee59bd6e702c332aa4f7e91ab93af9adf57195cd17bf5fdb85a4242fab80808080a06d4b4ab1e312f3a9174c532350d3133ba92dd0d763c10276db67276cb134303e80a0475f5df490d6ec0abaf1fac328259cff82effc83f5ff49ba60303aafb574ac1c808080a0d7ba808f47ae53c4505803eb05dce8b04e2f80cb450c5a892a15d3862e071afe8080,
// -    e: 0xf85180808080808080a0e0cab3d373600713ea3effd6b41055a40b07896a5bdfa63cb9d234797123c7498080808080a0d86a294d8fa338b8302cce695b5c3c9312b02ff38d3fc52162d34824e76b1d2b808080,
// - 7: 0xe21ea0fb2f566725f96184b433cd4ada3c2bb8d8dad89f8397ed849b64bd4236975b83,

// Expected:
// +    root: 0xf90211a093f53296837ff36c948861bdb424c8caf9cfc328c7b39188088a436ecaa35d60a0286fbd2070e426862a99fc981af90953d4f22e43d4c4aef372dcd0c80afeb79ca0aeccd8da54e917754f2509b3d28b50734488bb1a0b9c1ddf8a71fd89ae7c7c51a0703701ad54f64a132278315001ffe671a7a2b46a50f2e1106e9a11edd2fcc568a0f512b08653b42eaf7da1850a6a2d41ad673b5088f8ed20cfd9cb2f275f0511e3a0f4381926982b6a9fe86e8b5f933ee6057eace01d301d31fa880046ecaa433418a04c0beb17898e1f745685e75a7d9d4dfe96a91f26d5f8a76cea4942b505c43fa5a0d43cb6ca0abcbff483613e1418dd7b66a9d8f07cd6cff0a139cac8fda24b1394a045bbb1e4cd7a3ea71f8160c39df5c7bf5fdcfa6604b7f8a5e9abe16eac15f73aa0ae7948adac8b4f3fe2867b9439f37fbd4ccf07cee9cc89b61202a26f531bdda5a0300f18e2b5bc63ea840b17bbeb3d10e983ec42bc95b568153f58e7256bf24a37a0af5cc4b8f901aff06ef831495bbb2da7b552690108f5d663ae42dc41a47a7df9a025c5636672cc01e33e6540fde11ee108392c0a8b28472b35032ad2d796127f73a0d13b474697d727271320726e692ce929fc59ac617bdc60aef840bb540ef6ce3da0d86aa7388a0efcb7fd0004955b1cb938aa233404e683fa8ebac1f263ba1f2520a063d1bbf4c30c81d482307b3f72ed73a0f268aafa2f99fa5f4b059a099920a6d980,
// +    1: 0xf90211a08b9d720c41c294e2c6b619b7b63727917a88921514884521f7f1768cdef29b3aa0637be999926bdb4941978e45d3e6df5c480bdce5bebc588b6f17cd9ba833018ca0a066b524c57aab439f24ccc94952c198d28ecfaf8aa6e134115b904f662670a6a0cc078fc393d4c76f7fcf47b09c06f6df7e6f5af64b1fee38ae2cde29afb9f685a0932bb11bc5dd354a4228f6a47f01890513005d438d8615e5d6b8f56d7d0a9e25a01c82eca0a099cc276fe87d1865771bacc3d4fd21b8c8963c1c1a5ef10074becda00832db7f4571c59427a43c090723223419090978d09df3966cc5005f692fd47aa094f33825469131e3c55d65a3b453a25697829cbdbb5c2bcd690ac8a4397d18b1a05e6eea014b018e73f622b774f769bbccf62a04aeabaada1323f8df27d614481aa0dbf87c1d63ee20150034bb02f53f77c97e5d924e22bf938de1c4cd3e51245a2da072ac7f0450df09921bc114a296995cfd0ff3fffc8113649abc1d7349d909911aa0b2c9ef9bb20e0035d489c5f19b26dabd3914e2a85a47c3a2b4dab45aa40f1118a081ab378478178a64469c45d267726e6e09aa3188d60d30e5a573f8754bf299afa01322ae4928e0cbfb860cdc090b190d22c20abbbc84f76d52011f72e30cd9c05aa0c7695e3f91222d3679eb989ce0f678b28e65bd4ca9bc674e893cdf1dfa938131a06a7e78b836043df994158040d52db1b51175f841118ff9fd93420c230f257d6180,
// +    9: 0xf8b180a0f8fef385de3777478d3463c0613ebff67f484481f1c06f11879def1423b99ca680a0c0348cee59bd6e702c332aa4f7e91ab93af9adf57195cd17bf5fdb85a4242fab80808080a06d4b4ab1e312f3a9174c532350d3133ba92dd0d763c10276db67276cb134303e80a0475f5df490d6ec0abaf1fac328259cff82effc83f5ff49ba60303aafb574ac1c808080a0ed2ca8b2e73c242eaeabaa8a96275e9f33be2535de1606461a13d23e7e3929d68080,
// +    e: 0xf85180808080808080a0510a5b195c4102df8a479ec1ad4449e0b16cc4f0635be8b95150670b87ae3b548080808080a0d86a294d8fa338b8302cce695b5c3c9312b02ff38d3fc52162d34824e76b1d2b808080,
// +    7: 0xf8429f20e0637a3a68ed6a0a2709bf1328a4d803cff945c17cd67e013544d9a9730aa1a0fffffffffffffffffffffffffffffffffffffffff94fbfac13bd8b4355b3c281,

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
    let block_number = 18884865u64;
    let rpc_url =
        Url::parse("https://eth-mainnet.g.alchemy.com/v2/hIxcf_hqT9It2hS8iCFeHKklL8tNyXNF")
            .expect("Invalid RPC URL");
    println!("Fetching block number {} from {}", block_number, rpc_url);
    // Get the input.
    let sp1_input = get_input(block_number, rpc_url).await.expect("Failed to get input");
    // Verify the STF.
    verify_stf(sp1_input).expect("Failed to verify STF");
}

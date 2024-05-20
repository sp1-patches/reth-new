#[allow(unused_imports)]
use alloy_provider::{Provider, ReqwestProvider};
use alloy_rpc_types::{BlockId, EIP1186AccountProofResponse};
use async_std::task;
use futures::future::join_all;

// use alloy_transport::TransportResult;
use crate::RethBlock;
use alloy_transport_http::ReqwestTransport;
use reth_primitives::{
    trie::AccountProof, Account, Address, BlockNumber, StorageKey, StorageValue, B256, U256, U64,
};
use reth_provider::{
    AccountReader, BlockHashReader, ProviderError, StateProvider, StateRootProvider,
};
use reth_revm::DatabaseRef;
use reth_trie::updates::TrieUpdates;
use revm_primitives::{result, AccountInfo, Bytecode, HashMap, HashSet};
use std::{
    hash::Hash,
    sync::{Arc, RwLock},
};
use tokio::{runtime::Handle, task::block_in_place};

use crate::SP1Input;

#[derive(Clone, Debug)]
/// An implementation of a [`DatabaseRef`] that uses an [`ReqwestProvider`] to fetch data.
pub struct RpcDb {
    /// The [`ReqwestProvider`] that will be used to fetch data.
    /// TODO: In the future this should be a generic [`Provider`] trait from alloy_provider.
    pub provider: ReqwestProvider,
    /// The [`BlockId`] that will be used when fetching data from the RPC.
    pub block: BlockId,

    /// A mapping from [`Address`] to [`AccountInfo`] for all addresses that have been fetched.
    pub address_to_account_info: Arc<RwLock<HashMap<Address, AccountInfo>>>,
    pub address_to_storage: Arc<RwLock<HashMap<Address, HashMap<U256, U256>>>>,
    pub block_hashes: Arc<RwLock<HashMap<U256, B256>>>,
}

impl RpcDb {
    pub fn new(provider: ReqwestProvider, block: BlockId) -> Self {
        RpcDb {
            provider,
            block,
            address_to_account_info: Arc::new(RwLock::new(HashMap::new())),
            address_to_storage: Arc::new(RwLock::new(HashMap::new())),
            block_hashes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Fetch the account info (and code) for an address.
    async fn fetch_account_info(&self, address: Address) -> AccountInfo {
        // TODO: when alloy adds a `eth_getAccount` method, we can use that here to save RPC load,
        // since getProof is expensive.
        let proof = self
            .provider
            .get_proof(address, vec![], self.block)
            .await
            .expect("Failed to get proof");
        let code =
            self.provider.get_code_at(address, self.block).await.expect("Failed to get code");
        let bytecode = Bytecode::new_raw(code);

        let account_info = AccountInfo {
            nonce: proof.nonce.as_limbs()[0],
            balance: proof.balance,
            code_hash: proof.code_hash,
            code: Some(bytecode.clone()),
        };

        // Keep track of the account_info and code in the mappings for RpcDb.
        self.address_to_account_info.write().unwrap().insert(address, account_info.clone());

        account_info
    }

    /// Fetch the storage for an address and index.
    async fn fetch_storage(&self, address: Address, index: U256) -> U256 {
        let value = self
            .provider
            .get_storage_at(address, index, self.block)
            .await
            .expect("Failed to get storage");
        self.address_to_storage
            .write()
            .unwrap()
            .entry(address)
            .or_insert_with(HashMap::new)
            .insert(index, value);
        value
    }

    /// Fetch the block hash for a block number.
    async fn fetch_block_hash(&self, number: U256) -> B256 {
        let num_u64 = number.as_limbs()[0];
        let block = self
            .provider
            .get_block_by_number(num_u64.into(), false)
            .await
            .expect("Failed to get block");
        let hash = block.expect("Block not found").header.hash.expect("Block hash not found");
        self.block_hashes.write().unwrap().insert(number, hash);
        hash
    }

    /// Given all of the account and storage accesses in a block, fetch merkle proofs for all of
    /// them.
    async fn get_proofs(&self) -> HashMap<Address, EIP1186AccountProofResponse> {
        // Acquire read locks at the top
        let account_info = self.address_to_account_info.read().unwrap();
        let storage_guard = self.address_to_storage.read().unwrap();

        let mut addresses: HashSet<&Address> = account_info.keys().collect();
        addresses.extend(storage_guard.keys());

        // Create a future for each address to fetch a proof of the account and storage keys.
        let futures: Vec<_> = addresses
            .into_iter()
            .map(|address| {
                let storage_keys: Vec<B256> = storage_guard
                    .get(address)
                    .map(|storage_map| {
                        storage_map.keys().into_iter().map(|k| (*k).into()).collect()
                    })
                    .unwrap_or_else(Vec::new);

                let provider = self.provider.clone();
                let block = self.block;

                async move {
                    match provider.get_proof(*address, storage_keys, block).await {
                        Ok(proof) => Some((address, proof)),
                        Err(_) => None,
                    }
                }
            })
            .collect();

        // Execute all futures in parallel.
        let results = join_all(futures).await;

        // Collect results into a HashMap.
        results.into_iter().filter_map(|result| result).collect()
    }

    pub async fn get_sp1_input(&self, block: &RethBlock) -> SP1Input {
        let proofs = self.get_proofs().await;
        let block_hashes = self.block_hashes.read().unwrap().clone();
        SP1Input { block: block.clone(), address_to_proof: proofs, block_hashes }
    }
}

impl DatabaseRef for RpcDb {
    type Error = ProviderError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(Some(task::block_on(self.fetch_account_info(address))))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        unimplemented!()
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(task::block_on(self.fetch_storage(address, index)))
    }

    fn block_hash_ref(&self, number: U256) -> Result<B256, Self::Error> {
        Ok(task::block_on(self.fetch_block_hash(number)))
    }
}

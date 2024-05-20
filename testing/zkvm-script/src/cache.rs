use alloy_provider::{Provider, ReqwestProvider};
use alloy_rpc_types::{Block, BlockId, EIP1186AccountProofResponse};
use futures::Future;
use reth_primitives::{
    trie::{AccountProof, StorageProof},
    Account, Address, BlockNumberOrTag, StorageKey, B256, U256, U64,
};
use reth_provider::ProviderError;
use revm_primitives::Bytes;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    sync::{Arc, RwLock},
};

#[derive(Clone, Debug)]
pub struct CachedProvider {
    provider: ReqwestProvider,
    cache: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    cache_file: String,
}

impl CachedProvider {
    pub fn new(provider: ReqwestProvider, cache_file: String) -> Self {
        let cache = if Path::new(&cache_file).exists() {
            let mut file = File::open(&cache_file).expect("Failed to open cache file");
            let mut contents = String::new();
            file.read_to_string(&mut contents).expect("Failed to read cache file");
            serde_json::from_str(&contents).unwrap_or_else(|_| HashMap::new())
        } else {
            HashMap::new()
        };

        CachedProvider { provider, cache: Arc::new(RwLock::new(cache)), cache_file }
    }

    pub fn save(&self) {
        let cache = self.cache.read().unwrap();
        let serialized_cache = serde_json::to_string(&*cache).expect("Failed to serialize cache");
        let mut file = File::create(&self.cache_file).expect("Failed to create cache file");
        file.write_all(serialized_cache.as_bytes()).expect("Failed to write cache file");
    }

    fn load_from_cache<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let cache = self.cache.read().unwrap();
        cache.get(key).and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    fn save_to_cache<T: Serialize>(&self, key: &str, value: &T) {
        let mut cache = self.cache.write().unwrap();
        cache.insert(
            key.to_string(),
            serde_json::to_value(value).expect("Failed to serialize value"),
        );
    }

    // async fn cached_request<T, F, Fut>(&self, key: &str, request_fn: F) -> T
    // where
    //     T: Serialize + DeserializeOwned + Clone,
    //     F: FnOnce() -> Fut,
    //     Fut: Future<Output = io::Result<T>>,
    // {
    //     if let Some(cached) = self.load_from_cache(key) {
    //         return cached;
    //     }

    //     let result = request_fn().await.expect("Request failed");
    //     self.save_to_cache(key, &result);
    //     result
    // }

    pub async fn get_proof(
        &self,
        address: Address,
        storage_keys: Vec<StorageKey>,
        block_id: BlockId,
    ) -> Result<EIP1186AccountProofResponse, ProviderError> {
        let key = format!("get_proof_{:?}_{:?}_{:?}", address, storage_keys, block_id);
        if let Some(cached) = self.load_from_cache(&key) {
            return Ok(cached);
        }
        let proof = self
            .provider
            .get_proof(address, storage_keys)
            .block_id(block_id)
            .await
            .expect("Failed to get proof");
        self.save_to_cache(&key, &proof);
        Ok(proof)
    }

    pub async fn get_code_at(
        &self,
        address: Address,
        block_id: BlockId,
    ) -> Result<Bytes, ProviderError> {
        let key = format!("get_code_at_{:?}_{:?}", address, block_id);
        if let Some(cached) = self.load_from_cache(&key) {
            return Ok(cached);
        }
        let code = self
            .provider
            .get_code_at(address)
            .block_id(block_id)
            .await
            .expect("Failed to get code");
        self.save_to_cache(&key, &code);
        Ok(code)
    }

    pub async fn get_storage_at(
        &self,
        address: Address,
        index: U256,
        block_id: BlockId,
    ) -> Result<U256, ProviderError> {
        let key = format!("get_storage_at_{:?}_{:?}_{:?}", address, index, block_id);
        if let Some(cached) = self.load_from_cache(&key) {
            println!("Loaded from cache for get_storage_at");
            return Ok(cached);
        }
        let storage = self
            .provider
            .get_storage_at(address, index)
            .block_id(block_id)
            .await
            .expect("Failed to get storage");
        self.save_to_cache(&key, &storage);
        Ok(storage)
    }

    pub async fn get_block_by_number(
        &self,
        number: BlockNumberOrTag,
        full: bool,
    ) -> Result<Option<Block>, ProviderError> {
        let key = format!("get_block_by_number_{:?}_{:?}", number, full);
        if let Some(cached) = self.load_from_cache(&key) {
            return Ok(cached);
        }
        let block = self
            .provider
            .get_block_by_number(number.into(), false)
            .await
            .expect("Failed to get block");
        self.save_to_cache(&key, &block);
        Ok(block)
    }
}

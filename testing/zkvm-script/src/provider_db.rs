use core::hash;

use crate::convert_proof;
#[allow(unused_imports)]
use alloy_provider::{Provider, ReqwestProvider};
use alloy_rpc_types::serde_helpers::num;
use reth_interfaces::provider::ProviderResult;
use reth_primitives::{
    trie::AccountProof, Account, Address, BlockId, BlockNumber, StorageKey, StorageValue, B256,
    U256, U64,
};
use reth_provider::{
    AccountReader, BlockHashReader, ProviderError, StateProvider, StateRootProvider,
};
use reth_trie::updates::TrieUpdates;
use revm::DatabaseRef;
use revm_primitives::{result, AccountInfo, Bytecode, HashMap};
use tokio::{runtime::Handle, task::block_in_place};

pub struct RpcDb {
    // TODO: make this a general "Provider" trait from alloy_provider.
    pub provider: ReqwestProvider,
    pub block: BlockId,
    pub handle: Handle,
}

impl RpcDb {
    pub fn new(provider: ReqwestProvider, block: BlockId) -> Self {
        let handle = Handle::current();
        RpcDb { provider, block, handle }
    }
}

impl DatabaseRef for RpcDb {
    type Error = ProviderError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        println!("getting account {}", address);
        let result = block_in_place(|| {
            Handle::current()
                .block_on(async move { self.provider.get_proof(address, vec![], self.block).await })
        });
        let code = block_in_place(|| {
            Handle::current()
                .block_on(async move { self.provider.get_code_at(address, self.block).await })
        });
        result
            .map(|proof| {
                println!("address {}, nonce: {}", address, proof.nonce.as_limbs()[0]);
                Some(AccountInfo {
                    nonce: proof.nonce.as_limbs()[0],
                    balance: proof.balance,
                    code_hash: proof.code_hash,
                    code: code.ok().map(|code| Bytecode::new_raw(code)),
                })
            })
            .map_err(|err| ProviderError::FsPathError("hi".into()))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // We use basic_ref to get the code from the provider.
        unimplemented!()
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        println!("getting address {} {}", address, index);
        let result = block_in_place(|| {
            Handle::current().block_on(async move {
                // TODO: this index might need to be hashed, not sure.
                self.provider.get_storage_at(address, index.into(), self.block).await
            })
        });
        result.map(|value| value.into()).map_err(|err| ProviderError::FsPathError("hi".into()))
    }

    fn block_hash_ref(&self, number: U256) -> Result<B256, Self::Error> {
        println!("getting block_hash {:?}", number);
        let num_u64 = number.as_limbs()[0];
        let result = block_in_place(|| {
            Handle::current().block_on(async move {
                self.provider.get_block_by_number(num_u64.into(), false).await
            })
        });
        if result.is_err() {
            return Err(ProviderError::FsPathError("hi".into()));
        }
        let block = result.unwrap();
        if block.is_none() {
            return Err(ProviderError::FsPathError("hi".into()));
        }
        let block = block.unwrap();
        let hash = block.header.hash;
        if hash.is_none() {
            return Err(ProviderError::FsPathError("hi".into()));
        }
        Ok(hash.unwrap().into())
    }
}

#[allow(unused_imports)]
use alloy_provider::{Provider, ReqwestProvider};
use reth_interfaces::provider::ProviderResult;
use reth_primitives::{
    trie::AccountProof, Account, Address, BlockId, BlockNumber, Bytecode, StorageKey, StorageValue,
    B256,
};
use reth_provider::{AccountReader, BlockHashReader, StateProvider, StateRootProvider};
use reth_trie::updates::TrieUpdates;

pub struct RpcDb {
    // TODO: make this a general "Provider" trait from alloy_provider.
    pub provider: ReqwestProvider,
    pub block: BlockId,
}

impl StateProvider for RpcDb {
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        todo!();
    }

    /// Get account code by its hash
    fn bytecode_by_hash(&self, code_hash: B256) -> ProviderResult<Option<Bytecode>> {
        unimplemented!();
    }

    /// Get account and storage proofs.
    fn proof(&self, address: Address, keys: &[B256]) -> ProviderResult<AccountProof> {
        todo!();
    }
}

impl BlockHashReader for RpcDb {
    fn block_hash(&self, number: BlockNumber) -> ProviderResult<Option<B256>> {
        todo!();
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> reth_interfaces::provider::ProviderResult<Vec<B256>> {
        todo!();
    }
}

impl AccountReader for RpcDb {
    fn basic_account(&self, address: Address) -> ProviderResult<Option<Account>> {
        todo!();
    }
}

impl StateRootProvider for RpcDb {
    fn state_root(&self, bundle_state: &revm::db::BundleState) -> ProviderResult<B256> {
        todo!();
    }

    fn state_root_with_updates(
        &self,
        bundle_state: &revm::db::BundleState,
    ) -> reth_interfaces::provider::ProviderResult<(B256, TrieUpdates)> {
        todo!();
    }
}

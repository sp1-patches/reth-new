use alloy_rpc_types::EIP1186AccountProofResponse;
use reth_primitives::B256;
// TODO: we need to be able to import `ProviderError` from `reth_provider` in the zkVM.
use reth_provider::ProviderError;
use revm::{db::InMemoryDB, Database};
use revm_primitives::AccountInfo;

pub(crate) struct WitnessDb {
    pub(crate) inner: InMemoryDB,
    pub(crate) state_root: B256,
}

impl WitnessDb {
    pub(crate) fn new(state_root: B256, merkle_proofs: Vec<EIP1186AccountProofResponse>) -> Self {
        let mut inner = InMemoryDB::default();
        for proof in merkle_proofs {
            // TODO: verify proof against state_root
            // Note that we do not need to hash the code against the code_hash, since
            // `insert_contract` already does this.
            let address = proof.address;
            let account_info = AccountInfo {
                nonce: proof.nonce.as_limbs()[0], // Is there a better way to do U64 -> u64?
                balance: proof.balance,
                code_hash: proof.code_hash,
                code: None, // TODO: fill this with code
            };
            inner.insert_account_info(address, account_info);
            for storage_proof in proof.storage_proof {
                // TODO: verify storage proof.
                let slot = storage_proof.key.0;
                let value = storage_proof.value;
                let _ = inner.insert_account_storage(address, slot.into(), value);
            }
        }
        Self { inner, state_root }
    }
}

// TODO: is there some automatic way to implement this?
// TODO: fix all the dummy ProviderError
impl Database for WitnessDb {
    type Error = ProviderError;

    fn basic(
        &mut self,
        address: revm_primitives::Address,
    ) -> Result<Option<AccountInfo>, Self::Error> {
        self.inner.basic(address).map_err(|_| ProviderError::UnsupportedProvider)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<revm_primitives::Bytecode, Self::Error> {
        self.inner.code_by_hash(code_hash).map_err(|_| ProviderError::UnsupportedProvider)
    }

    fn storage(
        &mut self,
        address: revm_primitives::Address,
        index: revm_primitives::U256,
    ) -> Result<revm_primitives::U256, Self::Error> {
        self.inner.storage(address, index).map_err(|_| ProviderError::UnsupportedProvider)
    }

    fn block_hash(&mut self, number: revm_primitives::U256) -> Result<B256, Self::Error> {
        self.inner.block_hash(number).map_err(|_| ProviderError::UnsupportedProvider)
    }
}

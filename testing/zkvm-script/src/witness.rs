use alloy_rpc_types::EIP1186AccountProofResponse;
use reth_primitives::B256;
// TODO: we need to be able to import `ProviderError` from `reth_provider` in the zkVM.
use reth_provider::ProviderError;
use revm::{db::InMemoryDB, Database, DatabaseRef};
use revm_primitives::{keccak256, AccountInfo, Address, Bytecode, HashMap, U256};

use crate::{provider_db::RpcDb, SP1Input};
use revm::db::CacheDB;

pub(crate) struct WitnessDb {
    pub address_to_account_info: HashMap<Address, AccountInfo>,
    pub address_to_storage: HashMap<Address, HashMap<U256, U256>>,
    pub block_hashes: HashMap<U256, B256>,
    pub(crate) state_root: B256,
}

impl WitnessDb {
    pub(crate) fn new(sp1_input: SP1Input) -> Self {
        let state_root: B256 = sp1_input.block.state_root.into();
        let address_to_account_info = HashMap::new();
        let address_to_storage = HashMap::new();

        for (address, proof) in sp1_input.address_to_proof {
            proof.verify(state_root).expect("account proof verification failed");
            let account_proof = proof.account_proof;
            let account_info = AccountInfo {
                nonce: account_proof.nonce.as_limbs()[0],
                balance: account_proof.balance,
                code_hash: account_proof.code_hash,
                code: proof.code,
            };
            address_to_account_info.insert(address, account_info);
            let storage_map = account_proof
                .storage_proofs
                .into_iter()
                .map(|storage_proof| (storage_proof.key, storage_proof.value))
                .collect();
            address_to_storage.insert(address, storage_map);
        }
        let block_hashes = sp1_input.block_hashes;

        Self {
            inner,
            address_to_account_info: HashMap::new(),
            address_to_storage: HashMap::new(),
            block_hashes: HashMap::new(),
            state_root: sp1_input.block.state_root,
        }
    }
}

impl DatabaseRef for WitnessDb {
    type Error = ProviderError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.address_to_account_info.get(&address).cloned())
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        unimplemented!()
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self.address_to_storage.get(&address).unwrap().get(&index).unwrap().clone())
    }

    fn block_hash_ref(&self, number: U256) -> Result<B256, Self::Error> {
        Ok(self.block_hashes.get(&number).unwrap().clone())
    }
}

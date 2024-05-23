use crate::SP1Input;
use reth_interfaces::provider::ProviderError;
use reth_primitives::B256;
use revm::DatabaseRef;
use revm_primitives::{AccountInfo, Address, Bytecode, HashMap, U256};

pub struct WitnessDb {
    pub address_to_account_info: HashMap<Address, AccountInfo>,
    pub address_to_storage: HashMap<Address, HashMap<U256, U256>>,
    pub block_hashes: HashMap<U256, B256>,
    pub(crate) state_root: B256,
}

impl WitnessDb {
    pub fn new(sp1_input: SP1Input) -> Self {
        let state_root: B256 = sp1_input.prev_block.state_root.into();
        let mut address_to_account_info = HashMap::new();
        let mut address_to_storage = HashMap::new();

        for (address, proof) in sp1_input.address_to_proof {
            println!("Verifying account proof for address {address:?}...");
            proof.verify(state_root).expect("account proof verification failed");
            let account_info = proof.account_proof.info.unwrap();
            let account_info = AccountInfo {
                nonce: account_info.nonce,
                balance: account_info.balance.into(),
                code_hash: account_info.bytecode_hash.unwrap(),
                code: Some(proof.code),
            };
            address_to_account_info.insert(address, account_info);
            let storage_map: HashMap<U256, U256> = proof
                .account_proof
                .storage_proofs
                .into_iter()
                .map(|storage_proof| (storage_proof.key.into(), storage_proof.value.into()))
                .collect();
            address_to_storage.insert(address, storage_map);
        }
        let block_hashes = sp1_input.block_hashes;

        Self {
            address_to_account_info,
            address_to_storage,
            block_hashes,
            state_root: sp1_input.block.state_root,
        }
    }
}

impl DatabaseRef for WitnessDb {
    type Error = ProviderError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.address_to_account_info.get(&address).cloned())
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        // We return the code from the basic_ref.
        unimplemented!()
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self.address_to_storage.get(&address).unwrap().get(&index).unwrap().clone())
    }

    fn block_hash_ref(&self, number: U256) -> Result<B256, Self::Error> {
        Ok(self.block_hashes.get(&number).unwrap().clone())
    }
}

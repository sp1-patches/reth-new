use alloy_rpc_types::EIP1186AccountProofResponse;
use reth_primitives::B256;
// TODO: we need to be able to import `ProviderError` from `reth_provider` in the zkVM.
use reth_provider::ProviderError;
use revm::{db::InMemoryDB, Database, DatabaseRef};
use revm_primitives::{keccak256, AccountInfo, Address, Bytecode, HashMap, U256};

use crate::{provider_db::RpcDb, SP1Input};
use revm::db::CacheDB;

pub(crate) struct WitnessDb {
    pub(crate) inner: InMemoryDB,
    pub address_to_account_info: HashMap<Address, AccountInfo>,
    pub address_to_storage: HashMap<Address, HashMap<U256, U256>>,
    pub block_hashes: HashMap<U256, B256>,
    pub(crate) state_root: B256,
}

impl WitnessDb {
    pub(crate) fn new(sp1_input: SP1Input) -> Self {
        println!("WitnessDb::new");
        let mut inner = InMemoryDB::default();
        // let SP1Input { block, address_to_account_info, address_to_storage, block_hashes, .. } =
        //     sp1_input;
        // for (proof, code) in merkle_proofs.into_iter().zip(code.into_iter()) {
        //     // TODO: verify proof against state_root
        //     // Note that we do not need to hash the code against the code_hash, since
        //     // `insert_contract` already does this.
        //     let address = proof.address;
        //     let code = if code.is_empty() { None } else { Some(Bytecode::new_raw(code.into())) };
        //     let account_info = AccountInfo {
        //         nonce: proof.nonce.as_limbs()[0], // Is there a better way to do U64 -> u64?
        //         balance: proof.balance,
        //         code_hash: proof.code_hash,
        //         code,
        //     };
        //     inner.insert_account_info(address, account_info);
        //     let storage_map = address_to_storage.get(&address);
        //     println!("inserting storage for address {}", address);
        //     if let Some(storage_map) = storage_map {
        //         for (index, value) in storage_map {
        //             println!("inserting storage {} {}", index, value);
        //             let _ = inner.insert_account_storage(address, *index, *value);
        //         }
        //     }
        //     // TODO: right now these are empty.
        //     // for storage_proof in proof.storage_proof {
        //     //     // TODO: verify storage proof.
        //     //     let slot = storage_proof.key.0;
        //     //     let value = storage_proof.value;
        //     //     let _ = inner.insert_account_storage(address, slot.into(), value);
        //     // }
        // }
        Self {
            inner,
            address_to_account_info: HashMap::new(),
            address_to_storage: HashMap::new(),
            block_hashes: HashMap::new(),
            state_root: sp1_input.block.state_root,
        }
    }
}

// TODO: is there some automatic way to implement this?
// TODO: fix all the dummy ProviderError
impl DatabaseRef for WitnessDb {
    type Error = ProviderError;

    fn basic_ref(
        &self,
        address: revm_primitives::Address,
    ) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.address_to_account_info.get(&address).cloned())
        // self.inner.basic_ref(address).map_err(|_| ProviderError::UnsupportedProvider)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        unimplemented!()
    }

    fn storage_ref(
        &self,
        address: revm_primitives::Address,
        index: U256,
    ) -> Result<U256, Self::Error> {
        Ok(self.address_to_storage.get(&address).unwrap().get(&index).unwrap().clone())
        // self.inner.storage_ref(address, index).map_err(|_| ProviderError::UnsupportedProvider)
    }

    fn block_hash_ref(&self, number: U256) -> Result<B256, Self::Error> {
        Ok(self.block_hashes.get(&number).unwrap().clone())
        // self.inner.block_hash_ref(number).map_err(|_| ProviderError::UnsupportedProvider)
    }

    // fn bas(
    //     &mut self,
    //     address: revm_primitives::Address,
    // ) -> Result<Option<AccountInfo>, Self::Error> {
    //     self.inner.basic(address).map_err(|_| ProviderError::UnsupportedProvider)
    // }

    // fn code_by_hash(&mut self, code_hash: B256) -> Result<revm_primitives::Bytecode, Self::Error>
    // {     self.inner.code_by_hash(code_hash).map_err(|_| ProviderError::UnsupportedProvider)
    // }

    // fn storage(
    //     &mut self,
    //     address: revm_primitives::Address,
    //     index: revm_primitives::U256,
    // ) -> Result<revm_primitives::U256, Self::Error> {
    //     self.inner.storage(address, index).map_err(|_| ProviderError::UnsupportedProvider)
    // }

    // fn block_hash(&mut self, number: revm_primitives::U256) -> Result<B256, Self::Error> {
    //     self.inner.block_hash(number).map_err(|_| ProviderError::UnsupportedProvider)
    // }
}

pub struct CheckDb {
    pub witness: CacheDB<WitnessDb>,
    pub rpc: CacheDB<RpcDb>,
}

impl Database for CheckDb {
    type Error = ProviderError;

    fn basic(
        &mut self,
        address: revm_primitives::Address,
    ) -> Result<Option<AccountInfo>, Self::Error> {
        let res1 = self.witness.basic(address).unwrap();
        let res2 = self.rpc.basic(address).unwrap();
        if res1 != res2 {
            println!("basic mismatch for address {}", address);
            println!("witness: {:?}", res1);
            println!("rpc: {:?}", res2);
            panic!("account mismatch");
        }
        self.rpc.basic(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<revm_primitives::Bytecode, Self::Error> {
        let res1 = self.witness.code_by_hash(code_hash).unwrap();
        let res2 = self.rpc.code_by_hash(code_hash).unwrap();
        if res1 != res2 {
            println!("code mismatch for hash {}", code_hash);
            println!("witness: {:?}", res1);
            println!("rpc: {:?}", res2);
            panic!("code mismatch");
        }
        self.rpc.code_by_hash(code_hash)
    }

    fn storage(
        &mut self,
        address: revm_primitives::Address,
        index: revm_primitives::U256,
    ) -> Result<revm_primitives::U256, Self::Error> {
        let index_b = B256::from(index);
        let hash = keccak256(index_b);
        let hash_b: U256 = B256::from(hash).into();
        let res1 = self.witness.storage(address, hash_b).unwrap();
        let res2 = self.rpc.storage(address, index).unwrap();
        if res1 != res2 {
            println!("storage mismatch for address {} index {}", address, index);
            println!("witness: {:?}", res1);
            println!("rpc: {:?}", res2);
        } else {
            println!("no storage mismatch for address {} index {}", address, index);
        }
        self.rpc.storage(address, index)
    }

    fn block_hash(&mut self, number: revm_primitives::U256) -> Result<B256, Self::Error> {
        let res1 = self.witness.block_hash(number).unwrap();
        let res2 = self.rpc.block_hash(number).unwrap();
        if res1 != res2 {
            println!("block hash mismatch for number {}", number);
            println!("witness: {:?}", res1);
            println!("rpc: {:?}", res2);
            panic!("block_hash mismatch");
        }
        self.rpc.block_hash(number)
    }
}

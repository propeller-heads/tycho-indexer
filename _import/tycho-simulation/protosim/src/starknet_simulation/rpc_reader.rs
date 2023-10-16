use cairo_vm::felt::Felt252;
use starknet_api::{
    core::{ClassHash as SNClassHash, ContractAddress, PatriciaKey},
    hash::StarkHash,
    state::StorageKey,
};
use starknet_in_rust::{
    core::errors::state_errors::StateError,
    services::api::contract_classes::compiled_class::CompiledClass,
    state::{state_api::StateReader, state_cache::StorageEntry},
    utils::{Address, ClassHash},
};

use super::rpc_state::RpcState;

#[derive(Debug)]
pub struct RpcStateReader(RpcState);

impl StateReader for RpcStateReader {
    fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
        let hash = SNClassHash(StarkHash::new(*class_hash).unwrap());
        Ok(CompiledClass::from(self.0.get_contract_class(&hash)))
    }

    fn get_class_hash_at(&self, contract_address: &Address) -> Result<ClassHash, StateError> {
        let address = ContractAddress(
            PatriciaKey::try_from(
                StarkHash::new(contract_address.clone().0.to_be_bytes()).unwrap(),
            )
            .unwrap(),
        );
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(
            self.0
                .get_class_hash_at(&address)
                .0
                .bytes(),
        );
        Ok(bytes)
    }

    fn get_nonce_at(&self, contract_address: &Address) -> Result<Felt252, StateError> {
        let address = ContractAddress(
            PatriciaKey::try_from(
                StarkHash::new(contract_address.clone().0.to_be_bytes()).unwrap(),
            )
            .unwrap(),
        );
        let nonce = self.0.get_nonce_at(&address);
        Ok(Felt252::from_bytes_be(nonce.bytes()))
    }

    fn get_storage_at(&self, storage_entry: &StorageEntry) -> Result<Felt252, StateError> {
        let (contract_address, key) = storage_entry;
        let address = ContractAddress(
            PatriciaKey::try_from(
                StarkHash::new(contract_address.clone().0.to_be_bytes()).unwrap(),
            )
            .unwrap(),
        );
        let key = StorageKey(PatriciaKey::try_from(StarkHash::new(*key).unwrap()).unwrap());
        let value = self.0.get_storage_at(&address, &key);
        Ok(Felt252::from_bytes_be(value.bytes()))
    }

    fn get_compiled_class_hash(&self, class_hash: &ClassHash) -> Result<[u8; 32], StateError> {
        Ok(*class_hash)
    }
}

#[cfg(test)]
mod tests {
    use crate::starknet_simulation::rpc_state::{BlockTag, RpcChain};

    use super::*;

    fn setup_reader() -> RpcStateReader {
        let rpc_state = RpcState::new_infura(RpcChain::MainNet, BlockTag::Latest.into());
        RpcStateReader(rpc_state)
    }

    #[test]
    #[ignore] // needs infura key
    fn test_get_class_hash_at() {
        let reader = setup_reader();

        let address_bytes =
            hex::decode("04d0390b777b424e43839cd1e744799f3de6c176c7e32c1812a41dbd9c19db6a")
                .expect("Decoding failed");
        let contract_address: Address = Address(Felt252::from_bytes_be(&address_bytes));

        let result = reader
            .get_class_hash_at(&contract_address)
            .unwrap();

        assert_eq!(
            result,
            [
                7, 181, 205, 106, 105, 73, 204, 23, 48, 248, 157, 121, 95, 36, 66, 246, 171, 67,
                30, 166, 201, 165, 190, 0, 104, 93, 80, 249, 116, 51, 197, 235
            ]
        );
    }

    #[test]
    #[ignore] // needs infura key
    fn test_get_contract_class() {
        let reader = setup_reader();

        let class_hash: &ClassHash = &[
            7, 181, 205, 106, 105, 73, 204, 23, 48, 248, 157, 121, 95, 36, 66, 246, 171, 67, 30,
            166, 201, 165, 190, 0, 104, 93, 80, 249, 116, 51, 197, 235,
        ];

        let result = reader.get_contract_class(class_hash);

        // the CompiledClass object is huge, so we just check it is returned and skip the details
        // here
        assert!(result.is_ok());
    }

    #[test]
    #[ignore] // needs infura key
    fn test_get_storage_at() {
        let reader = setup_reader();

        let address_bytes =
            hex::decode("04d0390b777b424e43839cd1e744799f3de6c176c7e32c1812a41dbd9c19db6a")
                .expect("Decoding failed");
        let address: Address = Address(Felt252::from_bytes_be(&address_bytes));
        let entry = [0; 32];
        let storage_entry: StorageEntry = (address, entry);

        let result = reader
            .get_storage_at(&storage_entry)
            .unwrap();

        let zero_as_bytes: [u8; 32] = [0; 32];
        assert_eq!(result, Felt252::from_bytes_be(&zero_as_bytes))
    }
}

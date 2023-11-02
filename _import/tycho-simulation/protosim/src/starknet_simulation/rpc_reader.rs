use cairo_vm::felt::Felt252;
use rpc_state_reader::rpc_state::{BlockValue, RpcState};
use starknet_api::{
    core::{ClassHash as SNClassHash, ContractAddress, PatriciaKey},
    hash::StarkHash,
    state::StorageKey,
};
use starknet_in_rust::{
    core::errors::state_errors::StateError,
    services::api::contract_classes::compiled_class::CompiledClass,
    state::{state_api::StateReader, state_cache::StorageEntry},
    utils::{Address, ClassHash, CompiledClassHash},
};

trait ToContractAddress {
    fn to_contract_address(&self) -> ContractAddress;
}

impl ToContractAddress for Address {
    fn to_contract_address(&self) -> ContractAddress {
        ContractAddress(
            PatriciaKey::try_from(StarkHash::new(self.0.to_be_bytes()).unwrap()).unwrap(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct RpcStateReader(pub RpcState);

impl RpcStateReader {
    pub fn new(state: RpcState) -> Self {
        Self(state)
    }

    pub fn with_updated_block(&self, new_block: BlockValue) -> Self {
        let mut cloned_state = self.0.clone();
        cloned_state.block = new_block;
        RpcStateReader(cloned_state)
    }

    pub fn block(&self) -> &BlockValue {
        &self.0.block
    }
}

impl StateReader for RpcStateReader {
    fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
        let hash = match StarkHash::new(*class_hash) {
            Ok(val) => SNClassHash(val),
            Err(err) => return Err(StateError::CustomError(err.to_string())),
        };
        Ok(CompiledClass::from(self.0.get_contract_class(&hash)))
    }

    fn get_class_hash_at(&self, contract_address: &Address) -> Result<ClassHash, StateError> {
        let address = contract_address.to_contract_address();
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
        let address = contract_address.to_contract_address();
        let nonce = self.0.get_nonce_at(&address);
        Ok(Felt252::from_bytes_be(nonce.bytes()))
    }

    fn get_storage_at(&self, storage_entry: &StorageEntry) -> Result<Felt252, StateError> {
        let (contract_address, key) = storage_entry;
        let address = contract_address.to_contract_address();
        let key_hash =
            StarkHash::new(*key).map_err(|err| StateError::CustomError(err.to_string()))?;
        let key = match PatriciaKey::try_from(key_hash) {
            Ok(val) => StorageKey(val),
            Err(err) => return Err(StateError::CustomError(err.to_string())),
        };
        let value = self.0.get_storage_at(&address, &key);
        Ok(Felt252::from_bytes_be(value.bytes()))
    }

    fn get_compiled_class_hash(
        &self,
        class_hash: &ClassHash,
    ) -> Result<CompiledClassHash, StateError> {
        Ok(*class_hash)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use dotenv::dotenv;
    use std::env;

    use rpc_state_reader::rpc_state::{RpcBlockInfo, RpcChain};
    use starknet_api::{block::BlockNumber, core::ChainId};

    use super::*;

    pub fn setup_reader(block_number: u64, rpc_chain: RpcChain) -> RpcStateReader {
        let infura_api_key = env::var("INFURA_API_KEY").unwrap_or_else(|_| {
            dotenv().expect("Missing .env file");
            env::var("INFURA_API_KEY").expect("Missing INFURA_API_KEY in .env file")
        });
        let rpc_endpoint = format!("https://{}.infura.io/v3/{}", rpc_chain, infura_api_key);
        let rpc_chain_id: ChainId = rpc_chain.into();
        let feeder_url = format!("https://{}.starknet.io/feeder_gateway", rpc_chain_id);
        RpcStateReader::new(RpcState::new(
            rpc_chain,
            BlockNumber(block_number).into(),
            &rpc_endpoint,
            &feeder_url,
        ))
    }

    #[test]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_get_class_hash_at() {
        let reader = setup_reader(333333, RpcChain::MainNet);

        // Jedi Swap ETH/USDC pool address
        let address_bytes =
            hex::decode("04d0390b777b424e43839cd1e744799f3de6c176c7e32c1812a41dbd9c19db6a")
                .unwrap();
        let contract_address: Address = Address(Felt252::from_bytes_be(&address_bytes));

        // expected class hash
        let hash_bytes =
            hex::decode("07b5cd6a6949cc1730f89d795f2442f6ab431ea6c9a5be00685d50f97433c5eb")
                .unwrap();
        let expected_result: ClassHash = hash_bytes
            .as_slice()
            .try_into()
            .unwrap();

        let result = reader
            .get_class_hash_at(&contract_address)
            .unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_get_contract_class() {
        let reader = setup_reader(333333, RpcChain::MainNet);

        // Jedi Swap ETH/USDC pool class hash
        let class_hash: ClassHash =
            hex::decode("07b5cd6a6949cc1730f89d795f2442f6ab431ea6c9a5be00685d50f97433c5eb")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();

        let result = reader.get_contract_class(&class_hash);

        // the CompiledClass object is huge, so we just check it is returned and skip the details
        // here
        assert!(result.is_ok())
    }

    #[test]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_get_nonce_at() {
        let reader = setup_reader(333333, RpcChain::MainNet);

        // a test wallet address
        let address_bytes =
            hex::decode("03e9dB89D1c040968Cd82c07356E8e93B51825ab3CdAbA3d6dBA7a856729ef71")
                .unwrap();
        let contract_address: Address = Address(Felt252::from_bytes_be(&address_bytes));

        let result = reader
            .get_nonce_at(&contract_address)
            .unwrap();

        assert_eq!(result.to_string(), "22")
    }

    #[test]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_get_storage_at() {
        let reader = setup_reader(333333, RpcChain::MainNet);

        let address_bytes =
            hex::decode("04d0390b777b424e43839cd1e744799f3de6c176c7e32c1812a41dbd9c19db6a")
                .unwrap();
        let address: Address = Address(Felt252::from_bytes_be(&address_bytes));
        let entry = [0; 32];
        let storage_entry: StorageEntry = (address, entry);

        let result = reader
            .get_storage_at(&storage_entry)
            .unwrap();

        let zero_as_bytes: ClassHash = [0; 32];
        assert_eq!(result, Felt252::from_bytes_be(&zero_as_bytes))
    }

    #[test]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_get_compiled_class_hash() {
        let reader = setup_reader(333333, RpcChain::MainNet);

        // Jedi Swap ETH/USDC pool class hash
        let class_hash: &ClassHash = &[
            7, 181, 205, 106, 105, 73, 204, 23, 48, 248, 157, 121, 95, 36, 66, 246, 171, 67, 30,
            166, 201, 165, 190, 0, 104, 93, 80, 249, 116, 51, 197, 235,
        ];

        //expected compiled class hash
        let expected_hash: CompiledClassHash = [
            7, 181, 205, 106, 105, 73, 204, 23, 48, 248, 157, 121, 95, 36, 66, 246, 171, 67, 30,
            166, 201, 165, 190, 0, 104, 93, 80, 249, 116, 51, 197, 235,
        ];

        let result = reader
            .get_compiled_class_hash(class_hash)
            .unwrap();

        assert_eq!(result, expected_hash)
    }

    #[test]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_with_updated_block() {
        let reader = setup_reader(333333, RpcChain::MainNet);
        let RpcBlockInfo { block_number: initial_block_number, .. } = reader.0.get_block_info();
        let new_block = BlockNumber(333334).into();

        let updated_reader = reader.with_updated_block(new_block);
        let RpcBlockInfo { block_number: updated_block_number, .. } =
            updated_reader.0.get_block_info();
        assert_eq!(initial_block_number, BlockNumber(333333));
        assert_eq!(updated_block_number, BlockNumber(333334));
        assert_ne!(initial_block_number, updated_block_number);
    }
}

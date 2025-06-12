use std::{collections::HashMap, fmt::Debug};

use alloy::{
    primitives::{keccak256, Address, Keccak256, B256, U256},
    sol_types::SolValue,
};
use chrono::Utc;
use revm::{
    state::{AccountInfo, Bytecode},
    DatabaseRef,
};

use super::{
    constants::{EXTERNAL_ACCOUNT, MAX_BALANCE},
    utils::coerce_error,
};
use crate::{
    evm::{
        engine_db::engine_db_interface::EngineDatabaseInterface,
        simulation::{SimulationEngine, SimulationParameters, SimulationResult},
    },
    protocol::errors::SimulationError,
};

#[derive(Debug, Clone)]
pub struct TychoSimulationResponse {
    pub return_value: Vec<u8>,
    pub simulation_result: SimulationResult,
}

/// Represents a contract interface that interacts with the tycho_simulation environment to perform
/// simulations on Ethereum smart contracts.
///
/// `TychoSimulationContract` is a wrapper around the low-level details of encoding and decoding
/// inputs and outputs, simulating transactions, and handling ABI interactions specific to the Tycho
/// environment. It is designed to be used by applications requiring smart contract simulations
/// and includes methods for encoding function calls, decoding transaction results, and interacting
/// with the `SimulationEngine`.
///
/// # Type Parameters
/// - `D`: A database reference that implements `DatabaseRef` and `Clone`, which the simulation
///   engine uses to access blockchain state.
///
/// # Fields
/// - `abi`: The Application Binary Interface of the contract, which defines its functions and event
///   signatures.
/// - `address`: The address of the contract being simulated.
/// - `engine`: The `SimulationEngine` instance responsible for simulating transactions and managing
///   the contract's state.
///
/// # Errors
/// Returns errors of type `SimulationError` when encoding, decoding, or simulation operations
/// fail. These errors provide detailed feedback on potential issues.
#[derive(Clone, Debug)]
pub struct TychoSimulationContract<D: EngineDatabaseInterface + Clone + Debug>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    pub(crate) address: Address,
    pub(crate) engine: SimulationEngine<D>,
}

impl<D: EngineDatabaseInterface + Clone + Debug> TychoSimulationContract<D>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    pub fn new(address: Address, engine: SimulationEngine<D>) -> Result<Self, SimulationError> {
        Ok(Self { address, engine })
    }

    // Creates a new instance with the ISwapAdapter ABI
    pub fn new_contract(
        address: Address,
        adapter_contract_bytecode: Bytecode,
        engine: SimulationEngine<D>,
    ) -> Result<Self, SimulationError> {
        engine.state.init_account(
            address,
            AccountInfo {
                balance: *MAX_BALANCE,
                nonce: 0,
                code_hash: B256::from(keccak256(
                    adapter_contract_bytecode
                        .clone()
                        .bytes(),
                )),
                code: Some(adapter_contract_bytecode),
            },
            None,
            false,
        );

        Ok(Self { address, engine })
    }

    fn encode_input(&self, selector: &str, args: impl SolValue) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        hasher.update(selector.as_bytes());
        let selector_bytes = &hasher.finalize()[..4];
        let mut call_data = selector_bytes.to_vec();
        let mut encoded_args = args.abi_encode();
        // Remove extra prefix if present (32 bytes for dynamic data)
        // Alloy encoding is including a prefix for dynamic data indicating the offset or length
        // but at this point we don't want that
        if encoded_args.len() > 32 &&
            encoded_args[..32] ==
                [0u8; 31]
                    .into_iter()
                    .chain([32].to_vec())
                    .collect::<Vec<u8>>()
        {
            encoded_args = encoded_args[32..].to_vec();
        }
        call_data.extend(encoded_args);
        call_data
    }

    #[allow(clippy::too_many_arguments)]
    pub fn call(
        &self,
        selector: &str,
        args: impl SolValue,
        block_number: u64,
        timestamp: Option<u64>,
        overrides: Option<HashMap<Address, HashMap<U256, U256>>>,
        caller: Option<Address>,
        value: U256,
        transient_storage: Option<HashMap<Address, HashMap<U256, U256>>>,
    ) -> Result<TychoSimulationResponse, SimulationError> {
        let call_data = self.encode_input(selector, args);
        let params = SimulationParameters {
            data: call_data,
            to: self.address,
            block_number,
            timestamp: timestamp.unwrap_or_else(|| {
                Utc::now()
                    .naive_utc()
                    .and_utc()
                    .timestamp() as u64
            }),
            overrides,
            caller: caller.unwrap_or(*EXTERNAL_ACCOUNT),
            value,
            gas_limit: None,
            transient_storage,
        };

        let sim_result = self.simulate(params)?;

        Ok(TychoSimulationResponse {
            return_value: sim_result.result.to_vec(),
            simulation_result: sim_result,
        })
    }

    fn simulate(&self, params: SimulationParameters) -> Result<SimulationResult, SimulationError> {
        self.engine
            .simulate(&params)
            .map_err(|e| coerce_error(&e, "pool_state", params.gas_limit))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::primitives::{hex, Bytes};

    use super::*;
    use crate::evm::{
        engine_db::{
            create_engine,
            engine_db_interface::EngineDatabaseInterface,
            simulation_db::SimulationDB,
            tycho_db::PreCachedDBError,
            utils::{get_client, get_runtime},
        },
        protocol::vm::{constants::BALANCER_V2, utils::string_to_bytes32},
    };

    #[derive(Debug, Clone)]
    struct MockDatabase;

    impl DatabaseRef for MockDatabase {
        type Error = PreCachedDBError;

        fn basic_ref(&self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(Some(AccountInfo::default()))
        }

        fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
            Ok(Bytecode::new())
        }

        fn storage_ref(&self, _address: Address, _index: U256) -> Result<U256, Self::Error> {
            Ok(U256::from(0))
        }

        fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
            Ok(B256::default())
        }
    }

    impl EngineDatabaseInterface for MockDatabase {
        type Error = String;

        fn init_account(
            &self,
            _address: Address,
            _account: AccountInfo,
            _permanent_storage: Option<HashMap<U256, U256>>,
            _mocked: bool,
        ) {
            // Do nothing
        }

        fn clear_temp_storage(&mut self) {
            // Do nothing
        }
    }

    fn create_mock_engine() -> SimulationEngine<MockDatabase> {
        SimulationEngine::new(MockDatabase, false)
    }

    fn create_contract() -> TychoSimulationContract<MockDatabase> {
        let address = Address::ZERO;
        let engine = create_mock_engine();
        TychoSimulationContract::new_contract(
            address,
            Bytecode::new_raw(BALANCER_V2.into()),
            engine,
        )
        .unwrap()
    }

    #[test]
    fn test_encode_input_get_capabilities() {
        let contract = create_contract();

        // Arguments for the 'getCapabilities' function
        let pool_id =
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string();
        let sell_token = Address::from_str("0000000000000000000000000000000000000002").unwrap();
        let buy_token = Address::from_str("0000000000000000000000000000000000000003").unwrap();

        let encoded = contract.encode_input(
            "getCapabilities(bytes32,address,address)",
            (string_to_bytes32(&pool_id).unwrap(), sell_token, buy_token),
        );

        // The expected selector for "getCapabilities(bytes32,address,address)"
        let expected_selector = hex!("48bd7dfd");
        assert_eq!(&encoded[..4], &expected_selector[..]);

        let expected_pool_id =
            hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let expected_sell_token =
            hex!("0000000000000000000000000000000000000000000000000000000000000002"); // padded to 32 bytes
        let expected_buy_token =
            hex!("0000000000000000000000000000000000000000000000000000000000000003"); // padded to 32 bytes

        assert_eq!(&encoded[4..36], &expected_pool_id); // 32 bytes for poolId
        assert_eq!(&encoded[36..68], &expected_sell_token); // 32 bytes for address (padded)
        assert_eq!(&encoded[68..100], &expected_buy_token); // 32 bytes for address (padded)
    }

    #[test]
    fn test_transient_storage() {
        let db = SimulationDB::new(get_client(None), get_runtime(), None);
        let engine = create_engine(db, true).expect("Failed to create simulation engine");

        let contract_address = Address::from_str("0x0010d0d5db05933fa0d9f7038d365e1541a41888") // Irrelevant address
            .expect("Invalid address");
        let storage_slot: U256 =
            U256::from_str("0xc090fc4683624cfc3884e9d8de5eca132f2d0ec062aff75d43c0465d5ceeab23")
                .expect("Invalid storage slot");
        let storage_value: U256 = U256::from(42); // Example value to store

        // Bytecode retrieved by running `forge inspect TLoadTest deployedBytecode` on the following
        // contract (must be converted to a Solidity file):
        //
        // // SPDX-License-Identifier: UNLICENSED
        // pragma solidity ^0.8.26;
        //
        // contract TLoadTest {
        //    bytes32 constant SLOT =
        // 0xc090fc4683624cfc3884e9d8de5eca132f2d0ec062aff75d43c0465d5ceeab23;
        //
        //    function test() public view returns (bool) {
        //        assembly {
        //            let x := tload(SLOT)
        //            mstore(0x0, x)
        //            return(0x0, 0x20)
        //        }
        //    }
        // }

        let bytecode = Bytecode::new_raw(Bytes::from_str("0x6004361015600b575f80fd5b5f3560e01c63f8a8fd6d14601d575f80fd5b346054575f3660031901126054577fc090fc4683624cfc3884e9d8de5eca132f2d0ec062aff75d43c0465d5ceeab235c5f5260205ff35b5f80fdfea2646970667358221220f176684ab08659ff85817601a5398286c6029cf53bde9b1cce1a0c9bace67dad64736f6c634300081c0033").unwrap());
        let contract = TychoSimulationContract::new_contract(contract_address, bytecode, engine)
            .expect("Failed to create GenericVMHookHandler");

        let transient_storage_params =
            HashMap::from([(contract_address, HashMap::from([(storage_slot, storage_value)]))]);
        let args = ();
        let selector = "test()";

        let res = contract
            .call(
                selector,
                args,
                22578103, // blockHeader
                None,
                None,
                None,
                U256::from(0u64),
                Some(transient_storage_params),
            )
            .unwrap();

        let decoded: U256 = U256::abi_decode(&res.return_value)
            .map_err(|e| {
                SimulationError::FatalError(format!("Failed to decode test return value: {e:?}"))
            })
            .unwrap();

        assert_eq!(decoded, storage_value);
    }
}

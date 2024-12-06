use std::{collections::HashMap, fmt::Debug, path::PathBuf};

use alloy_primitives::{keccak256, Address, Keccak256, B256, U256};
use alloy_sol_types::SolValue;
use chrono::Utc;
use revm::{db::DatabaseRef, primitives::AccountInfo};

use crate::{
    evm::{
        engine_db::engine_db_interface::EngineDatabaseInterface,
        simulation::{SimulationEngine, SimulationParameters, SimulationResult},
    },
    protocol::errors::SimulationError,
};

use super::{
    constants::{ADAPTER_ADDRESS, EXTERNAL_ACCOUNT, MAX_BALANCE},
    utils::{coerce_error, get_contract_bytecode},
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
pub struct TychoSimulationContract<D: EngineDatabaseInterface + Clone>
where
    <D as DatabaseRef>::Error: std::fmt::Debug,
    <D as EngineDatabaseInterface>::Error: std::fmt::Debug,
{
    address: Address,
    pub(crate) engine: SimulationEngine<D>, /* TODO: Should we expose it directly or make some
                                             * getter functions? */
}

impl<D: EngineDatabaseInterface + Clone> TychoSimulationContract<D>
where
    <D as DatabaseRef>::Error: std::fmt::Debug,
    <D as EngineDatabaseInterface>::Error: std::fmt::Debug,
{
    pub fn new(address: Address, engine: SimulationEngine<D>) -> Result<Self, SimulationError> {
        Ok(Self { address, engine })
    }

    // Creates a new instance with the ISwapAdapter ABI
    pub fn new_swap_adapter(
        address: Address,
        adapter_contract_path: &PathBuf,
        engine: SimulationEngine<D>,
    ) -> Result<Self, SimulationError> {
        let adapter_contract_code = get_contract_bytecode(adapter_contract_path)
            .map_err(|err| SimulationError::FatalError(err.to_string()))?;

        engine.state.init_account(
            *ADAPTER_ADDRESS,
            AccountInfo {
                balance: *MAX_BALANCE,
                nonce: 0,
                code_hash: B256::from(keccak256(adapter_contract_code.clone().bytes())),
                code: Some(adapter_contract_code),
            },
            None,
            false,
        );

        Ok(Self { address, engine })
    }

    fn encode_input(&self, selector: &str, args: impl SolValue + std::fmt::Debug) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        hasher.update(selector.as_bytes());
        let selector_bytes = &hasher.finalize()[..4];
        let mut call_data = selector_bytes.to_vec();
        let mut encoded_args = args.abi_encode();
        // Remove extra prefix if present (32 bytes for dynamic data)
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
        args: impl SolValue + std::fmt::Debug,
        block_number: u64,
        timestamp: Option<u64>,
        overrides: Option<HashMap<Address, HashMap<U256, U256>>>,
        caller: Option<Address>,
        value: U256,
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
    use super::*;
    use alloy_primitives::hex;
    use std::str::FromStr;

    use revm::{
        db::DatabaseRef,
        primitives::{AccountInfo, Bytecode, B256},
    };

    use crate::evm::{
        engine_db::engine_db_interface::EngineDatabaseInterface,
        protocol::vm::utils::string_to_bytes32,
    };

    #[derive(Debug, Clone)]
    struct MockDatabase;

    impl DatabaseRef for MockDatabase {
        type Error = String;

        fn basic_ref(
            &self,
            _address: revm::precompile::Address,
        ) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(Some(AccountInfo::default()))
        }

        fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
            Ok(Bytecode::new())
        }

        fn storage_ref(
            &self,
            _address: revm::precompile::Address,
            _index: U256,
        ) -> Result<U256, Self::Error> {
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
        TychoSimulationContract::new_swap_adapter(
            address,
            &PathBuf::from("src/evm/protocol/vm/assets/BalancerSwapAdapter.evm.runtime"),
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
}

use std::ops::Add;
use ethers::{
    providers::Middleware,
    types::{Bytes, U256, Address},  // Address is an alias of H160
};
use revm::{
    primitives::{EVMError, ExecutionResult, TransactTo, B160 as rB160, U256 as rU256},
    EVM,
};
use revm::precompile::HashMap;
use revm::primitives::{bytes, EVMResult};  // `bytes` is an external crate
use crate::evm_simulation::storage::{SharedSimulationDB, StateUpdate};
use super::storage;

#[derive(Debug)]
pub enum SimulationError {
    /// Something went wrong while getting storage; might be caused by network issues
    StorageError(String),
    /// Simulation didn't succeed; likely not related to network, so retrying won't help
    TransactionError(String),
}

pub struct SimulationResult {
    pub result: bytes::Bytes,
    pub state_updates: HashMap<Address, StateUpdate>,
    pub gas_used: u64,
}

pub struct SimulationEngine<M: Middleware> {
    pub state: storage::SimulationDB<M>,
}

impl<M: Middleware> SimulationEngine<M> {
    // TODO: return StateUpdate and Bytes
    // TODO: support overrides
    pub fn simulate(
        &mut self,
        params: &SimulationParameters,
    ) -> Result<SimulationResult, SimulationError> {
        // We allocate a new EVM so we can work with a simple referenced DB instead of a fully
        // concurrently save shared reference and write locked object. Note that concurrently
        // calling this method is therefore not possible.
        // There is no need to keep an EVM on the struct as it only holds the environment and the
        // db, the db is simply a reference wrapper. To avoid lifetimes leaking we don't let the evm
        // struct outlive this scope.
        let mut vm = EVM::new();

        // The below call to vm.database consumes its argument. By wrapping state in a new object,
        // we protect the state from being consumed.
        let db_ref = storage::SharedSimulationDB::new(&mut self.state);
        vm.database(db_ref);
        vm.env.tx.caller = params.revm_caller();
        vm.env.tx.transact_to = params.revm_to();
        vm.env.tx.data = params.revm_data();
        vm.env.tx.value = params.revm_value();
        vm.env.tx.gas_limit = params.revm_gas_limit().unwrap_or(u64::MAX);

        let evm_result = vm.transact();

        println!("{:?}", evm_result.as_ref().unwrap());
        println!();
        for (key, value) in evm_result.as_ref().unwrap().state.iter() {
            println!("changes for address {key:?}:");
            println!("  balance: {:?}, nonce: {}", value.info.balance, value.info.nonce);
            for (index, slot) in value.storage.iter() {
                if slot.is_changed(){
                    println!("  {index:?}:\n    original: {}\n    new: {}", slot.original_value, slot.present_value)
                } else {
                    println!("  slot {index} not changed");
                }
            }
        }

        interpret_evm_result(evm_result)
    }
}

/// This is, beyond all discussion, the prettiest function ever written.
fn interpret_evm_result<DBError: std::fmt::Debug>(evm_result: EVMResult<DBError>) -> Result<SimulationResult, SimulationError> {
    match evm_result {
        Ok(result_and_state) => {
            match result_and_state.result { 
                ExecutionResult::Success {gas_used, output, ..} => {
                    Ok(SimulationResult {
                        result: output.into_data(),
                        state_updates: {
                            let mut account_updates: HashMap<Address, StateUpdate> = HashMap::new();
                            for (address, account) in result_and_state.state {
                                account_updates.insert(
                                    Address::from(address),
                                    StateUpdate{
                                        // revm doesn't say if the balance was actually changed
                                        balance: Some(account.info.balance),
                                        // revm doesn't say if the code was actually changed
                                        code: account.info.code.map(|x| x.bytecode),
                                        storage: {
                                            if account.storage.is_empty() { 
                                                None 
                                            } else {
                                                let mut slot_updates: HashMap<rU256, rU256> = HashMap::new();
                                                for (index, slot) in account.storage {
                                                    if slot.is_changed() {
                                                        slot_updates.insert(index, slot.present_value);
                                                    }
                                                }
                                                if slot_updates.is_empty() {
                                                    None
                                                } else { 
                                                    Some(slot_updates)
                                                }
                                            }
                                        }
                                    }
                                );
                            }
                            account_updates
                        },
                        gas_used
                    })
                },
                ExecutionResult::Revert { output, .. } => {
                    let revert_msg = std::str::from_utf8(output.as_ref())
                        .unwrap_or("[can't decode output]");
                    Err(SimulationError::TransactionError(format!("Execution reverted: {revert_msg}")))
                },
                ExecutionResult::Halt {reason, ..} => {
                    Err(SimulationError::TransactionError(format!("Execution halted: {reason:?}")))
                }
            }
        },
        Err(evm_error) => {
            match evm_error {
                EVMError::Transaction(invalid_tx) => 
                    Err(SimulationError::TransactionError(format!("EVM error: {invalid_tx:?}"))),
                EVMError::PrevrandaoNotSet => 
                    Err(SimulationError::TransactionError("EVM error: PrevrandaoNotSet".to_string())),
                EVMError::Database(db_error) =>
                    Err(SimulationError::StorageError(format!("Storage error: {db_error:?}"))),
            }
        }
    }
}

/// Data needed to invoke a transaction simulation
pub struct SimulationParameters {
    /// Address of the sending account
    pub caller: Address,
    /// Address of the receiving account/contract
    pub to: Address,
    /// Calldata
    pub data: Bytes,
    /// Amount of native token sent
    pub value: U256,
    /// EVM state overrides.
    /// Will be merged with existing state. Will take effect only for current simulation.
    pub overrides: Option<HashMap<U256, U256>>,
    /// Limit of gas to be used by the transaction
    pub gas_limit: Option<u64>,
}


// Converters of fields to revm types
impl SimulationParameters {
    fn revm_caller(&self) -> rB160 {
        rB160::from_slice(&self.caller.0)
    }

    fn revm_to(&self) -> TransactTo {
        TransactTo::Call(rB160::from_slice(&self.to.0))
    }

    fn revm_data(&self) -> revm::primitives::Bytes {
        revm::primitives::Bytes::copy_from_slice(&self.data.0)
    }

    fn revm_value(&self) -> rU256 {
        rU256::from_limbs(self.value.0)
    }

    fn revm_overrides(&self) -> Option<HashMap<rU256, rU256>> {
        self.overrides.clone().map(|original| {
            let mut result = HashMap::new();
            for (key, value) in original {
                result.insert(
                    rU256::from_limbs(key.0),
                    rU256::from_limbs(value.0));
            }
            result
        })
    }

    fn revm_gas_limit(&self) -> Option<u64> {
        // In this case we don't need to convert. The method is here just for consistency.
        self.gas_limit
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use std::{error::Error, str::FromStr, sync::Arc};
    use super::*;
    use ethers::{
        abi::parse_abi,
        prelude::BaseContract,
        providers::{Http, Provider, ProviderError},
        types::{Address, U256},
    };
    use revm::primitives::{Account, AccountInfo, B256, bytes, Eval, ExecutionResult, Output, ResultAndState, StorageSlot, State as rState, Halt, OutOfGasError, InvalidTransaction};
    use crate::evm_simulation::storage::SimulationDB;


    #[test]
    fn test_converting_to_revm() {
        let address_string = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
        let params = SimulationParameters {
            caller: Address::from_str(address_string).unwrap(),
            to: Address::from_str(address_string).unwrap(),
            data: Bytes::from_static(b"Hello"),
            value: U256::from(123),
            overrides: Some(
                [
                    (U256::from(1), U256::from(11)),
                    (U256::from(2), U256::from(22)),
                ].iter().cloned().collect()
            ),
            gas_limit: Some(33),
        };

        assert_eq!(params.revm_caller(), rB160::from_str(address_string).unwrap());
        assert_eq!(
            if let TransactTo::Call(value) = params.revm_to() {value} else {panic!()},
            rB160::from_str(address_string).unwrap()
        );
        assert_eq!(params.revm_data(), revm::primitives::Bytes::from_static(b"Hello"));
        assert_eq!(params.revm_value(), rU256::from_str("123").unwrap());
        // Below I am using `from_str` instead of `from`, because `from` for this type gives
        // an ugly false positive error in Pycharm.
        let expected_overrides = [
            (rU256::from_str("1").unwrap(), rU256::from_str("11").unwrap()),
            (rU256::from_str("2").unwrap(), rU256::from_str("22").unwrap()),
        ].iter().cloned().collect();
        assert_eq!(params.revm_overrides().unwrap(), expected_overrides);
        assert_eq!(params.revm_gas_limit().unwrap(), 33_u64);
    }

    #[test]
    fn test_converting_nones_to_revm() {
        let params = SimulationParameters{
            caller: Address::zero(),
            to: Address::zero(),
            data: Bytes::new(),
            value: U256::zero(),
            overrides: None,
            gas_limit: None,
        };

        assert_eq!(params.revm_overrides(), None);
        assert_eq!(params.revm_gas_limit(), None);
    }

    #[test]
    fn test_interpret_result_ok_success() {
        let evm_result: EVMResult<ProviderError> = EVMResult::Ok(
            ResultAndState {
                result: ExecutionResult::Success {
                    reason: Eval::Return,
                    gas_used: 100_u64,
                    gas_refunded: 10_u64,
                    logs: Vec::new(),
                    output: Output::Call(bytes::Bytes::from_static(b"output")),
                },
                state: [
                    (   // storage has changed
                        rB160::from(Address::zero()), 
                        Account{
                            info: AccountInfo {
                                balance: rU256::from_limbs([1, 0, 0, 0]),
                                nonce: 2,
                                code_hash: B256::zero(),
                                code: None,
                            },
                            storage: [
                                // this slot has changed
                                (rU256::from_limbs([3,1,0,0]), StorageSlot{
                                    original_value: rU256::from_limbs([4, 0, 0, 0]),
                                    present_value: rU256::from_limbs([5,0,0,0]),
                                }),
                                // this slot hasn't changed
                                (rU256::from_limbs([3,2,0,0]), StorageSlot{
                                    original_value: rU256::from_limbs([4, 0, 0, 0]),
                                    present_value: rU256::from_limbs([4,0,0,0]),
                                })
                            ].iter().cloned().collect(),
                            storage_cleared: false,
                            is_destroyed: false,
                            is_touched: true,
                            is_not_existing: false,
                        }
                    )
                ].iter().cloned().collect(),
            }
        );
        
        let result = interpret_evm_result(evm_result);
        let simulation_result = result.unwrap();
        
        assert_eq!(simulation_result.result, bytes::Bytes::from_static(b"output"));
        let expected_state_updates = [
            (
                Address::zero(),
                StateUpdate {
                    storage: Some(
                        [
                            (rU256::from_limbs([3, 1, 0, 0]),
                             rU256::from_limbs([5, 0, 0, 0]))
                        ].iter().cloned().collect()
                    ),
                    balance: Some(rU256::from_limbs([1, 0, 0, 0])),
                    code: None,
                }
            )
        ].iter().cloned().collect();
        assert_eq!(simulation_result.state_updates, expected_state_updates);
        assert_eq!(simulation_result.gas_used, 100);
    }

    #[test]
    fn test_interpret_result_ok_revert() {
        let evm_result: EVMResult<ProviderError> = EVMResult::Ok(
            ResultAndState {
                result: ExecutionResult::Revert {
                    gas_used: 100_u64,
                    output: bytes::Bytes::from_static(b"output"),
                },
                state: rState::new(),
            }
        );

        let result = interpret_evm_result(evm_result);

        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            SimulationError::TransactionError(msg) =>
                assert_eq!(msg, "Execution reverted: output"),
            _ => panic!("Wrong type of SimulationError!"),
        }
    }
    
    #[test]
    fn test_interpret_result_ok_halt() {
        let evm_result: EVMResult<ProviderError> = EVMResult::Ok(
            ResultAndState {
                result: ExecutionResult::Halt {
                    reason: Halt::OutOfGas(OutOfGasError::BasicOutOfGas),
                    gas_used: 100_u64,
                },
                state: rState::new(),
            }
        );

        let result = interpret_evm_result(evm_result);

        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            SimulationError::TransactionError(msg) =>
                assert_eq!(msg, "Execution halted: OutOfGas(BasicOutOfGas)"),
            _ => panic!("Wrong type of SimulationError!"),
        }
    }
    
    #[test]
    fn test_interpret_result_err_invalid_transaction() {
        let evm_result: EVMResult<ProviderError> = EVMResult::Err(
            EVMError::Transaction(InvalidTransaction::GasMaxFeeGreaterThanPriorityFee)
        );

        let result = interpret_evm_result(evm_result);

        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            SimulationError::TransactionError(msg) =>
                assert_eq!(msg, "EVM error: GasMaxFeeGreaterThanPriorityFee"),
            _ => panic!("Wrong type of SimulationError!"),
        }
    }
    
    #[test]
    fn test_interpret_result_err_db_error() {
        let evm_result = EVMResult::Err(
            EVMError::Database(ProviderError::CustomError("boo".to_string()))
        );

        let result = interpret_evm_result(evm_result);

        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            SimulationError::StorageError(msg) =>
                assert_eq!(msg, "Storage error: CustomError(\"boo\")"),
            _ => panic!("Wrong type of SimulationError!"),
        }
    }
    

    #[test]
    fn test_integration_revm_v2_swap() -> Result<(), Box<dyn Error>> {
        let client = Provider::<Http>::try_from(
            "https://nd-476-591-342.p2pify.com/47924752fae22aeef1e970c35e88efa0",
        )
            .unwrap();
        let client = Arc::new(client);
        let runtime = tokio::runtime::Handle::try_current()
            .is_err()
            .then(|| tokio::runtime::Runtime::new().unwrap())
            .unwrap();
        let state = storage::SimulationDB::new(client, Some(Arc::new(runtime)), None);

        // any random address will work
        let caller = Address::from_str("0x0000000000000000000000000000000000000000")?;
        let router_addr = Address::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")?;
        let router_abi = BaseContract::from(
        parse_abi(&[
            "function getAmountsOut(uint amountIn, address[] memory path) public view returns (uint[] memory amounts)",
        ])?
        );
        let weth_addr = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")?;
        let usdc_addr = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")?;
        let encoded = router_abi
            .encode(
                "getAmountsOut",
                (U256::from(100_000_000), vec![usdc_addr, weth_addr]),
            )
            .unwrap();

        let sim_params = SimulationParameters {
            caller,
            to: router_addr,
            data: encoded,
            value: U256::zero(),
            overrides: None,
            gas_limit: None,
        };
        let mut eng = SimulationEngine { state };

        let result = eng.simulate(&sim_params);

        let amounts_out = match result {
            Ok(SimulationResult { result, state_updates, gas_used }) =>
                router_abi.decode_output::<Vec<U256>, _>("getAmountsOut", result)?,
            _ => panic!("Execution reverted!"),
        };

        println!(
            "Swap yielded {} WETH",
            amounts_out.last().expect("Empty decoding result")
        );

        let start = Instant::now();
        let n_iter = 3;  // TODO: increase when caching works
        for _ in 0..n_iter {
            eng.simulate(&sim_params).unwrap();
        }
        let duration = start.elapsed();

        println!("Using revm:");
        println!("Total Duration [n_iter={n_iter}]: {:?}", duration);
        println!("Single get_amount_out call: {:?}", duration / 1000);

        Ok(())
    }
}

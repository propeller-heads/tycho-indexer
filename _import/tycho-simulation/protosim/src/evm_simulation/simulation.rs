use ethers::{
    providers::Middleware,
    types::{Bytes, H160, U256},
};
use revm::{
    primitives::{EVMError, ExecutionResult, TransactTo, B160, U256 as rU256},
    EVM,
};
use revm::precompile::HashMap;

use super::storage;

pub struct SimulationEngine<M: Middleware> {
    pub state: storage::SimulationDB<M>,
}

impl<M: Middleware> SimulationEngine<M> {
    // TODO: return StateUpdate and Bytes
    // TODO: support overrides
    pub fn simulate(
        &mut self,
        params: &SimulationParameters,
    ) -> ExecutionResult {
        // We allocate a new EVM so we can work with a simple referenced DB instead of a fully
        // concurrentl save shared reference and write locked object. Note that conurrently
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
        vm.env.tx.gas_limit = params.gas_limit.unwrap_or(u64::MAX);
        let ref_tx = vm.transact().unwrap();
        ref_tx.result
    }
}

/// Data needed to invoke a transaction simulation
pub struct SimulationParameters {
    /// Address of the sending account
    pub caller: H160,
    /// Address of the receiving account/contract
    pub to: H160,
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
    fn revm_caller(&self) -> B160 {
        B160::from_slice(&self.caller.0)
    }

    fn revm_to(&self) -> TransactTo {
        TransactTo::Call(B160::from_slice(&self.to.0))
    }

    fn revm_data(&self) -> revm::primitives::Bytes {
        revm::primitives::Bytes::copy_from_slice(&self.data.0)
    }

    fn revm_value(&self) -> rU256 {
        rU256::from_limbs(self.value.0)
    }
    
    fn revm_overrides(&self) -> Option<HashMap<rU256, rU256>> {
        match &self.overrides {
            None => { None },
            Some(original) => {
                let mut result = HashMap::new();
                for (key, value) in original {
                    result.insert(
                        rU256::from_limbs(key.0), 
                        rU256::from_limbs(value.0));
                }
                Some(result)
            }
        }
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
    use rstest::{fixture, rstest};
    use super::*;
    use ethers::{
        abi::parse_abi,
        prelude::BaseContract,
        providers::{Http, Provider},
        types::{H160, U256},
    };
    use revm::primitives::ExecutionResult;
    
    #[test]
    fn test_converting_to_revm() {
        let address_string = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
        let params = SimulationParameters{
            caller: H160::from_str(address_string).unwrap(),
            to: H160::from_str(address_string).unwrap(),
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
        
        assert_eq!(params.revm_caller(), B160::from_str(address_string).unwrap());
        assert_eq!(
            if let TransactTo::Call(value) = params.revm_to() {value} else {panic!()},
            B160::from_str(address_string).unwrap()
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
            caller: H160::zero(),
            to: H160::zero(),
            data: Bytes::new(),
            value: U256::zero(),
            overrides: None,
            gas_limit: None,
        };
        
        assert_eq!(params.revm_overrides(), None);
        assert_eq!(params.revm_gas_limit(), None);
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
        let caller = H160::from_str("0x0000000000000000000000000000000000000000")?;
        let router_addr = H160::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")?;
        let router_abi = BaseContract::from(
        parse_abi(&[
            "function getAmountsOut(uint amountIn, address[] memory path) public view returns (uint[] memory amounts)",
        ])?
        );
        let weth_addr = H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")?;
        let usdc_addr = H160::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")?;
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

        let computation_result = eng.simulate(&sim_params);

        let amounts_out = match computation_result {
            ExecutionResult::Success {
                reason: _,
                gas_used: _,
                gas_refunded: _,
                logs: _,
                output,
            } => match output {
                revm::primitives::Output::Call(data) => {
                    router_abi.decode_output::<Vec<U256>, _>("getAmountsOut", data)?
                }
                revm::primitives::Output::Create(_, _) => {
                    panic!("contract creation has not output")
                }
            },
            _ => panic!("Exxecution reverted!"),
        };

        println!(
            "Swap yielded {} WETH",
            amounts_out.last().expect("Empty decoding result")
        );

        let start = Instant::now();
        let n_iter = 3;
        for _ in 0..n_iter {
            eng.simulate(&sim_params);
        }
        let duration = start.elapsed();

        println!("Using revm:");
        println!("Total Duration [n_iter={n_iter}]: {:?}", duration);
        println!("Single get_amount_out call: {:?}", duration / 1000);

        Ok(())
    }
}

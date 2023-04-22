use ethers::{
    providers::Middleware,
    types::{Bytes, H160, U256},
};
use revm::{
    primitives::{Bytecode, EVMError, Env, ExecutionResult, TransactTo, B160, U256 as rU256},
    EVM,
};

use super::storage;

struct SimulationEngine<M: Middleware + Clone> {
    pub state: storage::SimulationDB<M>,
}

impl<M: Middleware + Clone> SimulationEngine<M> {
    pub fn update_contract_storage(
        &mut self,
        updates: storage::ContractStorageUpdate,
    ) -> Result<(), M::Error> {
        for (address, storage_update) in updates {
            self.state
                .replace_account_storage(B160(address.0), storage_update)?;
        }
        Ok(())
    }

    pub fn update_code(&mut self, address: H160, code: Option<Bytecode>) -> Option<Bytecode> {
        // TODO: handle all edge cases
        let raddr = B160(address.0);
        let mut db_ref = storage::SharedSimulationDB::new(&mut self.state);
        db_ref.update_code(raddr, code)
    }

    pub fn simulate(
        &mut self,
        params: &SimulationParameters,
    ) -> Result<ExecutionResult, EVMError<M::Error>> {
        // We allocate a new EVM so we can work with a simple referenced DB instead of a fully
        // concurrentl save shared reference and write locked object. Note that conurrently
        // calling this method is therefore not possible.
        // There is no need to keep an EVM on the struct as it only holds the environment and the
        // db, the db is simply a reference wrapper. To avoid lifetimes leaking we don't let the evm
        // struct outlive this scope.
        let mut vm = EVM::new();

        let db_ref = storage::SharedSimulationDB::new(&mut self.state);
        vm.database(db_ref);
        vm.env.tx.caller = params.revm_caller();
        vm.env.tx.transact_to = params.revm_to();
        vm.env.tx.data = params.revm_data();
        vm.env.tx.value = params.revm_value();
        let ref_tx = vm.transact()?;
        Ok(ref_tx.result)
    }
}

pub struct SimulationParameters {
    caller: H160,
    to: H160,
    data: Bytes,
    value: U256,
}

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
}

// next steps:
//  - convienient way to set up storage
//      - Way to specify the same code for multiple addresses
//      - Should potentially allow to mock e.g. token contracts
//      - Allow direct access to underlying storage providing a
//          data type this will be much faster e.g. for spot price
//          calculations then actually querying the storage with evm bytecode.
//  - add ability to simulate with state overrides
//    - we will need a way to apply state overrides temporarily to the database
//    - Ideally without cloning the entire state as this might be potentially huge
//    - So we should just record what was changed, added or removed
//    - The overrides should be a parameter to the simulation as the DB is global
//          and holds the state for all swaps, we wouldn't want it to micromanage
//          state overrides of other dependencies.

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use std::{error::Error, str::FromStr, sync::Arc};

    use super::*;
    use ethers::{
        abi::parse_abi,
        prelude::BaseContract,
        providers::{Http, Provider},
        types::{H160, U256},
    };
    use revm::{db::CacheDB, primitives::ExecutionResult, EVM};

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
        let state = storage::SimulationDB::new(storage::EthRpcDB {
            client,
            runtime: Some(Arc::new(runtime)),
        });

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
        };
        let mut eng = SimulationEngine { state };

        let computation_result = eng
            .simulate(&sim_params)
            .unwrap_or_else(|e| panic!("Execution failed: {e:?}"));

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
        for _ in 0..1000 {
            eng.simulate(&sim_params).expect("Benchmark sim failed");
        }
        let duration = start.elapsed();

        println!("Using revm:");
        println!("Total Duration [n_iter=1000]: {:?}", duration);
        println!("Single get_amount_out call: {:?}", duration / 1000);

        Ok(())
    }
}

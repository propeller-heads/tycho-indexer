use std::collections::HashMap;

use ethers::{
    providers::Middleware,
    types::{Bytes, H160, H256, U256},
};
use revm::{
    interpreter::analysis::to_analysed,
    primitives::{
        AccountInfo, Bytecode, Bytes as rBytes, EVMError, ExecutionResult, TransactTo, B160, B256,
        U256 as rU256,
    },
    EVM,
};

use super::storage;

struct SimulationResult {
    result: ExecutionResult,
}

struct SimulationEngine<M: Middleware + Clone> {
    pub state: storage::SimulationDB<M>,
}

impl<M: Middleware + Clone> SimulationEngine<M> {
    // TODO: return StateUpdate and Bytes
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
            block: None,
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

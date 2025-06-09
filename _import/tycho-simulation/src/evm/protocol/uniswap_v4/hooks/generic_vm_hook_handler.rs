#![allow(dead_code)]

use std::{any::Any, collections::HashMap, fmt::Debug, str::FromStr};

use alloy::{
    primitives::{keccak256, Address, Signed, Uint, B256, U256},
    sol_types::SolType,
};
use revm::{
    state::{AccountInfo, Bytecode},
    DatabaseRef,
};
use tycho_common::{dto::ProtocolStateDelta, Bytes};

use crate::{
    evm::{
        engine_db::engine_db_interface::EngineDatabaseInterface,
        protocol::{
            uniswap_v4::{
                hooks::{
                    constants::POOL_MANAGER_BYTECODE,
                    hook_handler::{
                        AfterSwapParameters, AmountRanges, BeforeSwapDelta, BeforeSwapParameters,
                        BeforeSwapReturn, HookHandler, SwapParams, WithGasEstimate,
                    },
                },
                state::UniswapV4State,
            },
            vm::{constants::MAX_BALANCE, tycho_simulation_contract::TychoSimulationContract},
        },
        simulation::SimulationEngine,
    },
    models::{Balances, Token},
    protocol::errors::{SimulationError, TransitionError},
};

#[derive(Debug, Clone)]
struct GenericVMHookHandler<D: EngineDatabaseInterface + Clone + Debug>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    contract: TychoSimulationContract<D>,
    address: Address,
    pool_manager: Address,
}

impl<D: EngineDatabaseInterface + Clone + Debug> PartialEq for GenericVMHookHandler<D>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.pool_manager == other.pool_manager
    }
}

impl<D: EngineDatabaseInterface + Clone + Debug> GenericVMHookHandler<D>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    pub fn new(
        address: Address,
        bytecode: Bytecode,
        engine: SimulationEngine<D>,
    ) -> Result<Self, SimulationError> {
        // Init pool manager
        // For now we use saved bytecode, but tycho-indexer should be able to provide this
        let pool_manager = Address::from_str("0x000000000004444c5dc75cb358380d2e3de08a90")
            .expect("Invalid pool manager address");

        let pool_manager_bytecode = Bytecode::new_raw(POOL_MANAGER_BYTECODE.into());

        engine.state.init_account(
            pool_manager,
            AccountInfo {
                balance: *MAX_BALANCE,
                nonce: 0,
                code_hash: B256::from(keccak256(pool_manager_bytecode.clone().bytes())),
                code: Some(pool_manager_bytecode),
            },
            None,
            false,
        );

        Ok(GenericVMHookHandler {
            contract: TychoSimulationContract::new_swap_adapter(address, bytecode, engine)?,
            address,
            pool_manager,
        })
    }

    pub fn unlock_pool_manager(&self) -> HashMap<Address, (U256, U256)> {
        let is_unlocked_slot = U256::from_be_bytes(keccak256("Unlocked").0) - U256::from(1);
        HashMap::from([(self.pool_manager, (is_unlocked_slot, U256::from(1u64)))])
        // the slot is here https://github.com/Uniswap/v4-core/blob/main/src/libraries/Lock.sol#L8C5-L8C117
    }
}

impl<D: EngineDatabaseInterface + Clone + Debug + 'static> HookHandler for GenericVMHookHandler<D>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    fn address(&self) -> Address {
        self.address
    }

    fn before_swap(
        &self,
        params: BeforeSwapParameters,
        block: u64,
    ) -> Result<WithGasEstimate<BeforeSwapReturn>, SimulationError> {
        let transient_storage_params = self.unlock_pool_manager();
        let args = (
            params.sender,
            (
                params.context.currency_0,
                params.context.currency_1,
                Uint::<24, 1>::from(params.context.fees.lp_fee),
                Signed::<24, 1>::try_from(params.context.tick).map_err(|e| {
                    SimulationError::FatalError(format!("Failed to convert tick: {e:?}"))
                })?,
                self.address,
            ),
            (
                params.swap_params.zero_for_one,
                params.swap_params.amount_specified,
                params.swap_params.sqrt_price_limit,
            ),
            params.hook_data.to_vec(),
        );
        let selector = "beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)";

        let res = self.contract.call(
            selector,
            args,
            block,
            None,
            None,
            Some(self.pool_manager),
            U256::from(0u64),
            Some(transient_storage_params),
        )?;

        let decoded = BeforeSwapReturn::abi_decode(&res.return_value).map_err(|e| {
            SimulationError::FatalError(format!("Failed to decode before swap return value: {e:?}"))
        })?;
        Ok(WithGasEstimate { gas_estimate: res.simulation_result.gas_used, result: decoded })
    }

    fn after_swap(
        &self,
        _params: AfterSwapParameters,
    ) -> Result<WithGasEstimate<BeforeSwapDelta>, SimulationError> {
        self.unlock_pool_manager();
        todo!()
        // self.contract.call(..)
    }

    fn fee(&self, _context: &UniswapV4State, _params: SwapParams) -> Result<f64, SimulationError> {
        todo!()
    }

    fn spot_price(&self, _base: &Token, _quote: &Token) -> Result<f64, SimulationError> {
        todo!()
    }

    fn get_amount_ranges(
        &self,
        _token_in: Address,
        _token_out: Address,
    ) -> Result<AmountRanges, SimulationError> {
        todo!()
    }

    fn delta_transition(
        &mut self,
        _delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        todo!()
    }

    fn clone_box(&self) -> Box<dyn HookHandler> {
        Box::new((*self).clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_equal(&self, other: &dyn HookHandler) -> bool {
        other.as_any().downcast_ref::<Self>() == Some(self)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::primitives::{aliases::U24, B256, I256};

    use super::*;
    use crate::evm::{
        engine_db::{
            create_engine,
            simulation_db::{BlockHeader, SimulationDB},
            utils::{get_client, get_runtime},
        },
        protocol::uniswap_v4::{
            hooks::{constants::BUNNI_HOOK_BYTECODE, hook_handler::StateContext},
            state::UniswapV4Fees,
        },
    };

    #[test]
    fn test_before_swap() {
        let block = BlockHeader {
            number: 22578103,
            hash: B256::from_str(
                "0x035c0e674c3bf3384a74b766908ab41c1968e989360aa26bea1dd64b1626f5f0",
            )
            .unwrap(),
            timestamp: 1748397011,
        };
        let db = SimulationDB::new(get_client(None), get_runtime(), Some(block));
        let engine = create_engine(db, true).expect("Failed to create simulation engine");

        let hook_address = Address::from_str("0x0010d0d5db05933fa0d9f7038d365e1541a41888")
            .expect("Invalid hook address");

        // BunniHook bytecode obtained from blockchain explorer.
        let bytecode = Bytecode::new_raw(BUNNI_HOOK_BYTECODE.into());

        let hook_handler = GenericVMHookHandler::new(hook_address, bytecode, engine)
            .expect("Failed to create GenericVMHookHandler");

        // simulating this tx: 0x6eef1c491d72edf73efd007b152b18d5f7814c5f3bd1c7d9be465fb9b4920f17
        let params = BeforeSwapParameters {
            context: StateContext {
                currency_0: Address::from_str("0x0000000000000000000000000000000000000000")
                    .unwrap(),
                currency_1: Address::from_str("0x000000c396558ffbab5ea628f39658bdf61345b3")
                    .unwrap(), // BUNNI
                fees: UniswapV4Fees { zero_for_one: 0, one_for_zero: 0, lp_fee: 1 },
                tick: 60,
            },
            sender: Address::from_str("0x66a9893cc07d91d95644aedd05d03f95e1dba8af").unwrap(),
            swap_params: SwapParams {
                zero_for_one: true,
                amount_specified: I256::try_from(-200000000000000000i128).unwrap(),
                sqrt_price_limit: U256::from(4295128740u64),
            },
            hook_data: Default::default(),
        };

        let result = hook_handler.before_swap(params, block.number);

        let res = result.unwrap().result;
        assert_eq!(res.selector.to_string(), "0x575e24b4");
        assert_eq!(
            res.amountDelta,
            I256::from_raw(
                U256::from_str("68056473384187693032957288407292048885944984507633924869").unwrap()
            )
        );
        assert_eq!(res.fee, U24::from(0));
    }
}

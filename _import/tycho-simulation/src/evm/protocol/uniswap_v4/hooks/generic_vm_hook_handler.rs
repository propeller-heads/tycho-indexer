#![allow(dead_code)]

use std::{any::Any, collections::HashMap, fmt::Debug, str::FromStr};

use alloy::primitives::{keccak256, Address, B256, U256};
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
        _params: BeforeSwapParameters,
        _block: u64,
    ) -> Result<WithGasEstimate<BeforeSwapReturn>, SimulationError> {
        todo!()
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

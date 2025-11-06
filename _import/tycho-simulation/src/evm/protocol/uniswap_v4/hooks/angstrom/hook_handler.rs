use std::{any::Any, collections::HashMap, fmt::Debug};

use alloy::primitives::{aliases::U24, keccak256, Address, I128, I256, U256};
use revm::primitives::FixedBytes;
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        protocol_sim::Balances,
    },
    Bytes,
};

use crate::evm::protocol::uniswap_v4::hooks::{
    hook_handler::HookHandler,
    models::{
        AfterSwapDelta, AfterSwapParameters, AmountRanges, BeforeSwapDelta, BeforeSwapOutput,
        BeforeSwapParameters, BeforeSwapSolOutput, SwapParams, WithGasEstimate,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AngstromHookHandler {
    address: Address,
    pool_manager: Address,
    current_trading_pairs: HashMap<(Address, Address), AngstromFees>,
}

impl AngstromHookHandler {
    pub fn new(
        address: Address,
        pool_manager: Address,
        current_trading_pairs: HashMap<(Address, Address), AngstromFees>,
    ) -> Self {
        Self { address, pool_manager, current_trading_pairs }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct AngstromFees {
    pub unlock: U24,
    pub protocol_unlock: U24,
}
impl HookHandler for AngstromHookHandler {
    fn address(&self) -> Address {
        self.address
    }
    fn fee(
        &self,
        _: &crate::evm::protocol::uniswap_v4::state::UniswapV4State,
        _: SwapParams,
    ) -> Result<f64, SimulationError> {
        todo!("Currently tycho grabs the fee from before_swap")
    }

    fn before_swap(
        &self,
        params: BeforeSwapParameters,
        _: Option<HashMap<Address, HashMap<U256, U256>>>,
        _: Option<HashMap<Address, HashMap<U256, U256>>>,
    ) -> Result<WithGasEstimate<BeforeSwapOutput>, SimulationError> {
        // start 400 for call
        let mut gas_estimate = 400;
        if !params.hook_data.is_empty() {
            // Another call + sstore + ec-recover
            gas_estimate += 10_000;
        }

        // let Some(fee) = self
        //     .current_trading_pairs
        //     .get(&(params.context.currency_0, params.context.currency_1))
        //     .copied()
        // else {
        //     return Err(SimulationError::FatalError(
        //         "pair is not enabled for trading on angstrom".to_string(),
        //     ));
        // };

        // amount of gas to do a asset lookup;
        gas_estimate += 1000;

        let selector = &keccak256("beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)")[..4];

        Ok(WithGasEstimate {
            gas_estimate,
            result: BeforeSwapOutput {
                amount_delta: BeforeSwapDelta(I256::ZERO),
                fee: U24::ZERO,
                overwrites: HashMap::new(),
                transient_storage: HashMap::new(),
            },
        })
    }

    fn after_swap(
        &self,
        params: AfterSwapParameters,
        _: Option<HashMap<Address, HashMap<U256, U256>>>,
        _: Option<HashMap<Address, HashMap<U256, U256>>>,
    ) -> Result<WithGasEstimate<AfterSwapDelta>, SimulationError> {
        // let Some(fee) = self
        //     .current_trading_pairs
        //     .get(&(params.context.currency_0, params.context.currency_1))
        //     .copied()
        // else {
        //     return Err(SimulationError::FatalError(
        //         "pair is not enabled for trading on angstrom".to_string(),
        //     ));
        // };

        // let protocol_fee = fee.protocol_unlock;

        let exact_input = params.swap_params.amount_specified < I256::ZERO;
        let target_amount = if exact_input != params.swap_params.zero_for_one {
            params.delta.amount0()
        } else {
            params.delta.amount1()
        };

        // Take absolute value of target amount
        let p_target_amount =
            if target_amount < I128::ZERO { target_amount.wrapping_neg() } else { target_amount };

        // let fee_rate_e6 = I128::unchecked_from(protocol_fee.to::<u32>());
        let one_e6 = I128::unchecked_from(1_000_000);

        // let protocol_fee_amount = if exact_input {
        //     p_target_amount * fee_rate_e6 / one_e6
        // } else {
        //     p_target_amount * one_e6 / (one_e6 - fee_rate_e6) - p_target_amount
        // };

        Ok(WithGasEstimate {
            // lookup + mint + tick updates post swap.
            gas_estimate: 15_000,
            result: p_target_amount,
        })
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        Err(TransitionError::SimulationError(SimulationError::RecoverableError(
            "delta_transition is not implemented for AngstromHook".to_string(),
        )))
        // if let Some(fees) = delta
        //     .updated_attributes
        //     .get("angstrom_pools_update")
        // {
        //     if fees.is_empty() || fees.len() - 1 % 46 != 0 {
        //         return Err(TransitionError::DecodeError(
        //             "angstrom_pools_update attributes are not properly formatted".to_string(),
        //         ));
        //     }
        //
        //     let count = fees[0] as u8;
        //     let mut offset = 1;
        //
        //     for _ in 0..count {
        //         let token_0 = Address::from_slice(&fees[offset + 0..offset + 20]);
        //         let token_1 = Address::from_slice(&fees[offset + 20..offset + 40]);
        //         let unlock = U24::from_be_slice(&fees[offset + 40..offset + 43]);
        //         let protocol_unlock = U24::from_be_slice(&fees[offset + 43..offset + 46]);
        //         self.current_trading_pairs
        //             .insert((token_0, token_1), AngstromFees { unlock, protocol_unlock });
        //
        //         offset += 46;
        //     }
        // }
        //
        // if let Some(fees) = delta
        //     .updated_attributes
        //     .get("angstrom_pools_removed")
        // {
        //     if fees.is_empty() || fees.len() - 1 % 40 != 0 {
        //         return Err(TransitionError::DecodeError(
        //             "angstrom_pools_removed attributes are not properly formatted".to_string(),
        //         ));
        //     }
        //
        //     let count = fees[0] as u8;
        //     let mut offset = 1;
        //
        //     for _ in 0..count {
        //         let token_0 = Address::from_slice(&fees[offset + 0..offset + 20]);
        //         let token_1 = Address::from_slice(&fees[offset + 20..offset + 40]);
        //         self.current_trading_pairs
        //             .remove(&(token_0, token_1));
        //
        //         offset += 40;
        //     }
        // }
        //
        // Ok(())
    }

    fn spot_price(&self, _base: &Token, _quote: &Token) -> Result<f64, SimulationError> {
        Err(SimulationError::RecoverableError(
            "spot_price is not implemented for AngstromHook".to_string(),
        ))
    }

    fn get_amount_ranges(
        &self,
        _token_in: Bytes,
        _token_out: Bytes,
    ) -> Result<AmountRanges, SimulationError> {
        Err(SimulationError::RecoverableError(
            "get_amount_ranges is not implemented for AngstromHook".to_string(),
        ))
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

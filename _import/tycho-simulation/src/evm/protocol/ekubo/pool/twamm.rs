use std::time::SystemTime;

use alloy::eips::merge::SLOT_DURATION_SECS;
use evm_ekubo_sdk::{
    math::
        uint::U256
    ,
    quoting::{
        self, twamm_pool::{TwammPoolError, TwammPoolState, TwammSaleRateDelta}, types::{NodeKey, Pool, QuoteParams, TokenAmount}
    },
};

use super::{full_range::FullRangePool, EkuboPool, EkuboPoolQuote};
use crate::{evm::protocol::ekubo::twamm_sale_rate_delta::TwammSaleRateDeltas, protocol::errors::{InvalidSnapshotError, SimulationError, TransitionError}};

#[derive(Debug, Eq, Clone)]
pub struct TwammPool {
    imp: quoting::twamm_pool::TwammPool,
    virtual_order_deltas: TwammSaleRateDeltas,
    state: TwammPoolState,
    swapped_this_block: bool,
}

impl PartialEq for TwammPool {
    // The other properties are just helpers for keeping the underlying pool implementation
    // up-to-date
    fn eq(&self, other: &Self) -> bool {
        self.imp == other.imp
    }
}

fn impl_from_state(
    key: &NodeKey,
    state: &TwammPoolState,
    virtual_order_deltas: impl Into<Vec<TwammSaleRateDelta>>,
) -> Result<quoting::twamm_pool::TwammPool, TwammPoolError> {
    quoting::twamm_pool::TwammPool::new(
        key.token0,
        key.token1,
        key.config.fee,
        key.config.extension,
        state.full_range_pool_state.sqrt_ratio,
        state.full_range_pool_state.liquidity,
        state.last_execution_time,
        state.token0_sale_rate,
        state.token1_sale_rate,
        virtual_order_deltas.into(),
    )
}

impl TwammPool {
    const GAS_COST_OF_ONE_VIRTUAL_ORDER_DELTA: u64 = 25_000;
    const BASE_GAS_COST_OF_EXECUTING_VIRTUAL_ORDERS: u64 = 15_000;

    const UNDERESTIMATION_SLOT_COUNT: u64 = 4;

    pub fn new(key: &NodeKey, state: TwammPoolState, virtual_order_deltas: Vec<TwammSaleRateDelta>) -> Result<Self, InvalidSnapshotError> {
        Ok(Self {
            imp: impl_from_state(key, &state, virtual_order_deltas.clone()).map_err(|err| {
                InvalidSnapshotError::ValueError(format!("creating oracle pool: {err:?}"))
            })?,
            virtual_order_deltas: virtual_order_deltas.into(),
            state,
            swapped_this_block: false,
        })
    }

    pub fn last_execution_time(&self) -> u64 {
        self.state.last_execution_time
    }

    pub fn set_last_execution_time(&mut self, last_execution_time: u64) {
        self.state.last_execution_time = last_execution_time;
    }

    pub fn set_token0_sale_rate(&mut self, token0_sale_rate: u128) {
        self.state.token0_sale_rate = token0_sale_rate;
    }

    pub fn set_token1_sale_rate(&mut self, token1_sale_rate: u128) {
        self.state.token1_sale_rate = token1_sale_rate;
    }

    pub fn set_sale_rate_delta(&mut self, delta: TwammSaleRateDelta) {
        self.virtual_order_deltas.set(delta);
    }

    fn estimate_block_timestamp(&self) -> u64 {
        if self.swapped_this_block {
            self.state.last_execution_time
        } else {
            // TODO How accurate is it to take the current timestamp?
            Ord::max(self.state.last_execution_time + SLOT_DURATION_SECS, current_timestamp())
        }
    }
}

impl EkuboPool for TwammPool {
    fn key(&self) -> &NodeKey {
        self.imp.get_key()
    }

    fn sqrt_ratio(&self) -> U256 {
        self.state
            .full_range_pool_state
            .sqrt_ratio
    }

    fn set_sqrt_ratio(&mut self, sqrt_ratio: U256) {
        self.state
            .full_range_pool_state
            .sqrt_ratio = sqrt_ratio;
    }

    fn set_liquidity(&mut self, liquidity: u128) {
        self.state
            .full_range_pool_state
            .liquidity = liquidity;
    }

    fn quote(
        &self,
        token_amount: TokenAmount,
    ) -> Result<EkuboPoolQuote, SimulationError> {
        let quote = self
            .imp
            .quote(QuoteParams {
                token_amount,
                sqrt_ratio_limit: None,
                override_state: None,
                meta: self.estimate_block_timestamp(),
            })
            .map_err(|err| SimulationError::RecoverableError(format!("{err:?}")))?;

        let state_after = quote.state_after;

        let new_state = Self {
            imp: impl_from_state(self.key(), &state_after, &self.virtual_order_deltas).map_err(|err| {
                SimulationError::RecoverableError(format!("recreating TWAMM pool: {err:?}"))
            })?,
            virtual_order_deltas: self.virtual_order_deltas.clone(),
            state: state_after,
            swapped_this_block: true,
        }
        .into();

        Ok(EkuboPoolQuote {
            consumed_amount: quote.consumed_amount,
            calculated_amount: quote.calculated_amount,
            gas: FullRangePool::gas_costs()
                + quote.execution_resources.virtual_orders_executed as u64 * Self::BASE_GAS_COST_OF_EXECUTING_VIRTUAL_ORDERS
                + quote.execution_resources.virtual_order_delta_times_crossed as u64 * Self::GAS_COST_OF_ONE_VIRTUAL_ORDER_DELTA,
            new_state,
        })
    }

    fn get_limit(&self, token_in: U256) -> Result<u128, SimulationError> {
        let key = self.key();
        let estimated_timestamp = self.estimate_block_timestamp();

        // Only execute the virtual orders up to a given timestamp
        let virtual_order_quote = self
            .imp
            .quote(QuoteParams {
                token_amount: TokenAmount {
                    token: token_in,
                    amount: 0,
                },
                sqrt_ratio_limit: None,
                override_state: None,
                meta: estimated_timestamp + Self::UNDERESTIMATION_SLOT_COUNT * SLOT_DURATION_SECS,
            })
            .map_err(|err| SimulationError::RecoverableError(format!("executing virtual orders quote: {err:?}")))?;

        // If letting some virtual orders execute leads to a less favorable price for the given swap direction
        let moved_to_unfavorable_price = (virtual_order_quote.state_after.full_range_pool_state.sqrt_ratio < self.state.full_range_pool_state.sqrt_ratio) == (token_in == key.token0);

        // Quote with the less favorable state (either the current one or the one where future virtual orders are already executed)
        let quote = self
            .imp
            .quote(QuoteParams {
                token_amount: TokenAmount { amount: i128::MAX, token: token_in },
                sqrt_ratio_limit: None,
                override_state: moved_to_unfavorable_price.then_some(virtual_order_quote.state_after),
                meta: if moved_to_unfavorable_price {
                    virtual_order_quote.state_after.last_execution_time
                } else {
                    estimated_timestamp
                },
            })
            .map_err(|err| SimulationError::RecoverableError(format!("quoting error: {err:?}")))?;

        u128::try_from(quote.consumed_amount).map_err(|_| {
            SimulationError::FatalError("consumed amount should be non-negative".to_string())
        })
    }

    fn finish_transition(&mut self) -> Result<(), TransitionError<String>> {
        self.imp = impl_from_state(self.key(), &self.state, &self.virtual_order_deltas)
        .map_err(|err| {
            TransitionError::SimulationError(SimulationError::RecoverableError(format!(
                "reinstantiate TWAMM pool: {err:?}"
            )))
        })?;

        self.swapped_this_block = false;

        Ok(())
    }
}

fn current_timestamp() -> u64 {
    SystemTime
        ::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

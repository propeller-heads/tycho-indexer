use evm_ekubo_sdk::{
    math::{
        tick::{MAX_TICK, MIN_TICK},
        uint::U256,
    },
    quoting::{
        self,
        full_range_pool::{FullRangePoolError, FullRangePoolState},
        types::{NodeKey, Pool, QuoteParams, Tick, TokenAmount},
    },
};

use super::{EkuboPool, EkuboPoolQuote};
use crate::protocol::errors::{InvalidSnapshotError, SimulationError, TransitionError};

#[derive(Debug, Clone, Eq)]
pub struct FullRangePool {
    state: FullRangePoolState,

    imp: quoting::full_range_pool::FullRangePool,
}

fn impl_from_state(
    key: NodeKey,
    state: FullRangePoolState,
) -> Result<quoting::full_range_pool::FullRangePool, FullRangePoolError> {
    quoting::full_range_pool::FullRangePool::new(key, state)
}

impl PartialEq for FullRangePool {
    // The other properties are just helpers for keeping the underlying pool implementation
    // up-to-date
    fn eq(&self, other: &Self) -> bool {
        self.imp == other.imp
    }
}

impl FullRangePool {
    const BASE_GAS_COST: u64 = 20_000;

    pub fn new(key: NodeKey, state: FullRangePoolState) -> Result<Self, InvalidSnapshotError> {
        Ok(Self {
            state,

            imp: impl_from_state(key, state).map_err(|err| {
                InvalidSnapshotError::ValueError(format!("creating full range pool: {err:?}"))
            })?,
        })
    }

    pub fn quote(&self, token_amount: TokenAmount) -> Result<EkuboPoolQuote, SimulationError> {
        let quote = self
            .imp
            .quote(QuoteParams {
                token_amount,
                sqrt_ratio_limit: None,
                override_state: None,
                meta: (),
            })
            .map_err(|err| SimulationError::RecoverableError(format!("{err:?}")))?;

        let state_after = quote.state_after;

        let new_state = Self {
            imp: impl_from_state(*self.key(), state_after).map_err(|err| {
                SimulationError::RecoverableError(format!("recreating full range pool: {err:?}"))
            })?,
            state: state_after,
        }
        .into();

        Ok(EkuboPoolQuote {
            consumed_amount: quote.consumed_amount,
            calculated_amount: quote.calculated_amount,
            gas: FullRangePool::gas_costs(),
            new_state,
        })
    }

    pub const fn gas_costs() -> u64 {
        Self::BASE_GAS_COST
    }
}

impl EkuboPool for FullRangePool {
    fn key(&self) -> &NodeKey {
        self.imp.get_key()
    }

    fn sqrt_ratio(&self) -> U256 {
        self.state.sqrt_ratio
    }

    fn set_sqrt_ratio(&mut self, sqrt_ratio: U256) {
        self.state.sqrt_ratio = sqrt_ratio;
    }

    fn set_liquidity(&mut self, liquidity: u128) {
        self.state.liquidity = liquidity;
    }

    fn set_tick(&mut self, tick: Tick) -> Result<(), String> {
        let idx = tick.index;

        if ![MIN_TICK, MAX_TICK].contains(&idx) {
            return Err(format!("pool is full range but passed tick has index {idx}"));
        }

        self.set_liquidity(tick.liquidity_delta.unsigned_abs());

        Ok(())
    }

    fn get_limit(&self, token_in: U256) -> Result<u128, SimulationError> {
        let max_in_token_amount = TokenAmount { amount: i128::MAX, token: token_in };

        let quote = self
            .imp
            .quote(QuoteParams {
                token_amount: max_in_token_amount,
                sqrt_ratio_limit: None,
                override_state: None,
                meta: (),
            })
            .map_err(|err| SimulationError::RecoverableError(format!("quoting error: {err:?}")))?;

        u128::try_from(quote.consumed_amount).map_err(|_| {
            SimulationError::FatalError("consumed amount should be non-negative".to_string())
        })
    }

    fn reinstantiate(&mut self) -> Result<(), TransitionError<String>> {
        self.imp = impl_from_state(*self.key(), self.state).map_err(|err| {
            TransitionError::SimulationError(SimulationError::RecoverableError(format!(
                "reinstantiate full range pool: {err:?}"
            )))
        })?;

        Ok(())
    }
}

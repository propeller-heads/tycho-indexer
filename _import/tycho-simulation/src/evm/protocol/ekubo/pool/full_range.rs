use evm_ekubo_sdk::{
    math::{tick::MIN_SQRT_RATIO, uint::U256},
    quoting::{
        self,
        full_range_pool::FullRangePoolState,
        types::{NodeKey, Pool, QuoteParams, TokenAmount},
    },
};

use super::{EkuboPool, EkuboPoolQuote};
use crate::protocol::errors::{InvalidSnapshotError, SimulationError, TransitionError};

#[derive(Debug, Clone, Eq)]
pub struct FullRangePool {
    imp: quoting::full_range_pool::FullRangePool,
    state: FullRangePoolState,
}

impl PartialEq for FullRangePool {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key() && self.state == other.state
    }
}

const DUMMY_STATE: FullRangePoolState =
    FullRangePoolState { sqrt_ratio: MIN_SQRT_RATIO, liquidity: 0 };

impl FullRangePool {
    const BASE_GAS_COST: u64 = 20_000;

    pub fn new(key: NodeKey, state: FullRangePoolState) -> Result<Self, InvalidSnapshotError> {
        Ok(Self {
            state,
            imp: quoting::full_range_pool::FullRangePool::new(key, DUMMY_STATE).map_err(|err| {
                InvalidSnapshotError::ValueError(format!("creating full range pool: {err:?}"))
            })?,
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

    fn quote(&self, token_amount: TokenAmount) -> Result<EkuboPoolQuote, SimulationError> {
        let quote = self
            .imp
            .quote(QuoteParams {
                token_amount,
                sqrt_ratio_limit: None,
                override_state: Some(self.state),
                meta: (),
            })
            .map_err(|err| SimulationError::RecoverableError(format!("{err:?}")))?;

        Ok(EkuboPoolQuote {
            consumed_amount: quote.consumed_amount,
            calculated_amount: quote.calculated_amount,
            gas: FullRangePool::gas_costs(),
            new_state: Self { imp: self.imp.clone(), state: quote.state_after }.into(),
        })
    }

    fn get_limit(&self, token_in: U256) -> Result<u128, SimulationError> {
        let max_in_token_amount = TokenAmount { amount: i128::MAX, token: token_in };

        let quote = self
            .imp
            .quote(QuoteParams {
                token_amount: max_in_token_amount,
                sqrt_ratio_limit: None,
                override_state: Some(self.state),
                meta: (),
            })
            .map_err(|err| SimulationError::RecoverableError(format!("quoting error: {err:?}")))?;

        u128::try_from(quote.consumed_amount).map_err(|_| {
            SimulationError::FatalError("consumed amount should be non-negative".to_string())
        })
    }

    fn finish_transition(&mut self) -> Result<(), TransitionError<String>> {
        Ok(())
    }
}

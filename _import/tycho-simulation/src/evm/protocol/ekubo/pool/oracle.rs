use evm_ekubo_sdk::{
    math::{tick::MIN_SQRT_RATIO, uint::U256},
    quoting::{
        self,
        full_range_pool::FullRangePoolState,
        oracle_pool::OraclePoolState,
        types::{NodeKey, Pool, QuoteParams, TokenAmount},
    },
};

use super::{full_range::FullRangePool, EkuboPool, EkuboPoolQuote};
use crate::protocol::errors::{InvalidSnapshotError, SimulationError, TransitionError};

#[derive(Debug, Eq, Clone)]
pub struct OraclePool {
    imp: quoting::oracle_pool::OraclePool,
    state: OraclePoolState,

    swapped_this_block: bool,
}

impl PartialEq for OraclePool {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key() && self.state == other.state
    }
}

const DUMMY_STATE: OraclePoolState = OraclePoolState {
    full_range_pool_state: FullRangePoolState { liquidity: 0, sqrt_ratio: MIN_SQRT_RATIO },
    last_snapshot_time: 0,
};

impl OraclePool {
    const GAS_COST_OF_UPDATING_ORACLE_SNAPSHOT: u64 = 15_000;

    pub fn new(key: &NodeKey, state: OraclePoolState) -> Result<Self, InvalidSnapshotError> {
        Ok(Self {
            imp: quoting::oracle_pool::OraclePool::new(
                key.token1,
                key.config.extension,
                DUMMY_STATE
                    .full_range_pool_state
                    .sqrt_ratio,
                DUMMY_STATE
                    .full_range_pool_state
                    .liquidity,
                DUMMY_STATE.last_snapshot_time,
            )
            .map_err(|err| {
                InvalidSnapshotError::ValueError(format!("creating oracle pool: {err:?}"))
            })?,
            state,
            swapped_this_block: false,
        })
    }
}

impl EkuboPool for OraclePool {
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

    fn quote(&self, token_amount: TokenAmount) -> Result<EkuboPoolQuote, SimulationError> {
        // Not actual timestamps but the Ekubo SDK only cares about the existence of time
        // differences
        let timestamp = if self.swapped_this_block {
            self.state.last_snapshot_time
        } else {
            self.state.last_snapshot_time + 1
        };

        let quote = self
            .imp
            .quote(QuoteParams {
                token_amount,
                sqrt_ratio_limit: None,
                override_state: Some(self.state),
                meta: timestamp,
            })
            .map_err(|err| SimulationError::RecoverableError(format!("{err:?}")))?;

        Ok(EkuboPoolQuote {
            consumed_amount: quote.consumed_amount,
            calculated_amount: quote.calculated_amount,
            gas: FullRangePool::gas_costs() +
                quote
                    .execution_resources
                    .snapshots_written as u64 *
                    Self::GAS_COST_OF_UPDATING_ORACLE_SNAPSHOT,
            new_state: Self {
                imp: self.imp.clone(),
                state: quote.state_after,
                swapped_this_block: true,
            }
            .into(),
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
                meta: 0,
            })
            .map_err(|err| SimulationError::RecoverableError(format!("quoting error: {err:?}")))?;

        u128::try_from(quote.consumed_amount).map_err(|_| {
            SimulationError::FatalError("consumed amount should be non-negative".to_string())
        })
    }

    fn finish_transition(&mut self) -> Result<(), TransitionError<String>> {
        self.swapped_this_block = false;

        Ok(())
    }
}

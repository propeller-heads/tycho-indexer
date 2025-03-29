use evm_ekubo_sdk::{
    math::uint::U256,
    quoting::{
        self,
        oracle_pool::OraclePoolState,
        types::{NodeKey, Pool, QuoteParams, TokenAmount},
    },
};

use super::{base::BasePool, EkuboPool, EkuboPoolQuote};
use crate::protocol::errors::SimulationError;

#[derive(Debug, Eq, Clone)]
pub struct OraclePool {
    imp: quoting::oracle_pool::OraclePool,
    state: OraclePoolState,
}

impl PartialEq for OraclePool {
    fn eq(&self, other: &Self) -> bool {
        self.imp == other.imp
    }
}

fn impl_from_state(key: &NodeKey, state: &OraclePoolState) -> quoting::oracle_pool::OraclePool {
    quoting::oracle_pool::OraclePool::new(
        key.token1,
        key.config.extension,
        state.base_pool_state.sqrt_ratio,
        state.base_pool_state.liquidity,
        state.last_snapshot_time,
    )
}

impl OraclePool {
    const GAS_COST_OF_UPDATING_ORACLE_SNAPSHOT: u64 = 15_000;

    pub fn new(key: &NodeKey, state: OraclePoolState) -> Self {
        Self { imp: impl_from_state(key, &state), state }
    }

    pub fn set_last_snapshot_time(&mut self, last_snapshot_time: u64) {
        self.state.last_snapshot_time = last_snapshot_time;
    }

    // TODO Add parameter when timestamps are supported
    pub fn quote(
        &self,
        token_amount: TokenAmount, /* block_timestamp: u64 */
    ) -> Result<EkuboPoolQuote, SimulationError> {
        let quote = self
            .imp
            .quote(QuoteParams {
                token_amount,
                sqrt_ratio_limit: None,
                override_state: None,
                meta: 0, // TODO Set to timestamp
            })
            .map_err(|err| SimulationError::RecoverableError(format!("{err:?}")))?;

        let state_after = quote.state_after;

        let new_state =
            Self { imp: impl_from_state(self.key(), &state_after), state: state_after }.into();

        let resources = quote.execution_resources;

        Ok(EkuboPoolQuote {
            calculated_amount: quote.calculated_amount,
            gas: BasePool::gas_costs(&resources.base_pool_resources, true) +
                Self::GAS_COST_OF_UPDATING_ORACLE_SNAPSHOT, /* TODO Depend on snapshots_written
                                                             * when timestamps are supported */
            new_state,
        })
    }
}

impl EkuboPool for OraclePool {
    fn key(&self) -> &NodeKey {
        self.imp.key()
    }

    fn sqrt_ratio(&self) -> U256 {
        self.state.base_pool_state.sqrt_ratio
    }

    fn set_sqrt_ratio(&mut self, sqrt_ratio: U256) {
        self.state.base_pool_state.sqrt_ratio = sqrt_ratio;
    }

    fn set_liquidity(&mut self, liquidity: u128) {
        self.state.base_pool_state.liquidity = liquidity;
    }

    fn reinstantiate(&mut self) {
        let key = self.imp.key();

        self.imp = quoting::oracle_pool::OraclePool::new(
            key.token1,
            key.config.extension,
            self.state.base_pool_state.sqrt_ratio,
            self.state.base_pool_state.liquidity,
            self.state.last_snapshot_time,
        );
    }

    fn get_limit(&self, token_in: U256) -> Result<u128, SimulationError> {
        let max_in_token_amount = TokenAmount { amount: i128::MAX, token: token_in };

        let quote = self
            .imp
            .quote(QuoteParams {
                token_amount: max_in_token_amount,
                sqrt_ratio_limit: None,
                override_state: None,
                meta: 0,
            })
            .map_err(|err| SimulationError::RecoverableError(format!("quoting error: {err:?}")))?;

        u128::try_from(quote.consumed_amount).map_err(|_| {
            SimulationError::FatalError("consumed amount should be non-negative".to_string())
        })
    }
}

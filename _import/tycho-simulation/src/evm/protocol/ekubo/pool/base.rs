use evm_ekubo_sdk::{
    math::uint::U256,
    quoting::{
        self,
        base_pool::{BasePoolResources, BasePoolState},
        types::{NodeKey, Pool, QuoteParams, Tick, TokenAmount},
        util::find_nearest_initialized_tick_index,
    },
};

use super::{EkuboPool, EkuboPoolQuote};
use crate::{evm::protocol::ekubo::tick::Ticks, protocol::errors::SimulationError};

#[derive(Debug, Clone, Eq)]
pub struct BasePool {
    state: BasePoolState,
    active_tick: Option<i32>,
    ticks: Ticks,

    imp: quoting::base_pool::BasePool,
}

impl PartialEq for BasePool {
    // The other properties are just helpers for keeping the underlying pool implementation
    // up-to-date
    fn eq(&self, other: &Self) -> bool {
        self.imp == other.imp
    }
}

fn impl_from_state(
    key: NodeKey,
    state: BasePoolState,
    ticks: Vec<Tick>,
) -> quoting::base_pool::BasePool {
    quoting::base_pool::BasePool::new(key, state, ticks)
}

impl BasePool {
    const BASE_GAS_COST_OF_ONE_SWAP: u64 = 25_000;
    const GAS_COST_OF_ONE_TICK_SPACING_CROSSED: u64 = 4_000;
    const GAS_COST_OF_ONE_INITIALIZED_TICK_CROSSED: u64 = 20_000;

    pub fn new(key: NodeKey, state: BasePoolState, ticks: Ticks, active_tick: i32) -> Self {
        Self {
            imp: impl_from_state(key, state, ticks.inner().clone()),
            state,
            active_tick: Some(active_tick),
            ticks,
        }
    }

    pub fn set_active_tick(&mut self, tick: i32) {
        self.active_tick = Some(tick);
    }

    pub fn set_tick(&mut self, tick: Tick) {
        self.ticks.set(tick);
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
            imp: impl_from_state(*self.key(), state_after, self.ticks.inner().clone()),
            state: state_after,
            active_tick: None,
            ticks: self.ticks.clone(),
        }
        .into();

        Ok(EkuboPoolQuote {
            calculated_amount: quote.calculated_amount,
            gas: Self::gas_costs(&quote.execution_resources),
            new_state,
        })
    }

    pub fn gas_costs(resources: &BasePoolResources) -> u64 {
        Self::BASE_GAS_COST_OF_ONE_SWAP +
            resources.tick_spacings_crossed as u64 * Self::GAS_COST_OF_ONE_TICK_SPACING_CROSSED +
            resources.initialized_ticks_crossed as u64 *
                Self::GAS_COST_OF_ONE_INITIALIZED_TICK_CROSSED
    }
}

impl EkuboPool for BasePool {
    fn key(&self) -> &NodeKey {
        self.imp.key()
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

    fn reinstantiate(&mut self) {
        // Only after a swap we set the active_tick to None. In this case, the active_tick_index is
        // already correctly computed though
        if let Some(active_tick) = self.active_tick {
            self.state.active_tick_index =
                find_nearest_initialized_tick_index(self.ticks.inner(), active_tick);
        }

        self.imp = impl_from_state(*self.key(), self.state, self.ticks.inner().clone());
    }
}

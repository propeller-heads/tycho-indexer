use evm_ekubo_sdk::{
    math::{tick::to_sqrt_ratio, uint::U256},
    quoting::{
        self,
        base_pool::{BasePoolError, BasePoolState},
        types::{NodeKey, Pool, QuoteParams, Tick, TokenAmount},
        util::find_nearest_initialized_tick_index,
    },
};
use num_traits::Zero;

use super::{EkuboPool, EkuboPoolQuote};
use crate::protocol::errors::{InvalidSnapshotError, SimulationError, TransitionError};

#[derive(Debug, Clone, Eq)]
pub struct BasePool {
    imp: quoting::base_pool::BasePool,
    state: BasePoolState,

    changed_ticks: Vec<Tick>,
    active_tick: Option<i32>,
}

impl PartialEq for BasePool {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key() &&
            self.imp.get_sorted_ticks() == other.imp.get_sorted_ticks() &&
            self.state == other.state
    }
}

fn impl_from_state(
    key: NodeKey,
    state: BasePoolState,
    ticks: Vec<Tick>,
) -> Result<quoting::base_pool::BasePool, BasePoolError> {
    quoting::base_pool::BasePool::new(key, state, ticks)
}

impl BasePool {
    const BASE_GAS_COST: u64 = 24_000;
    const GAS_COST_OF_ONE_TICK_SPACING_CROSSED: u64 = 4_000;
    const GAS_COST_OF_ONE_INITIALIZED_TICK_CROSSED: u64 = 20_000;

    // Factor to be used in get_limit to account for computation inaccuracies due to not using tick
    // bitmaps
    const WEI_UNDERESTIMATION_FACTOR: u128 = 2;

    pub fn new(
        key: NodeKey,
        state: BasePoolState,
        ticks: Vec<Tick>,
        active_tick: i32,
    ) -> Result<Self, InvalidSnapshotError> {
        Ok(Self {
            imp: impl_from_state(key, state, ticks).map_err(|err| {
                InvalidSnapshotError::ValueError(format!("creating base pool: {err:?}"))
            })?,
            state,
            active_tick: Some(active_tick),
            changed_ticks: vec![],
        })
    }

    pub fn set_active_tick(&mut self, tick: i32) {
        self.active_tick = Some(tick);
    }

    pub fn set_tick(&mut self, tick: Tick) {
        self.changed_ticks.push(tick);
    }
}

impl EkuboPool for BasePool {
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

        let state_after = quote.state_after;

        let new_state = Self {
            imp: self.imp.clone(),
            state: state_after,
            active_tick: None,
            changed_ticks: self.changed_ticks.clone(),
        }
        .into();

        let resources = quote.execution_resources;

        Ok(EkuboPoolQuote {
            consumed_amount: quote.consumed_amount,
            calculated_amount: quote.calculated_amount,
            gas: Self::BASE_GAS_COST +
                resources.tick_spacings_crossed as u64 *
                    Self::GAS_COST_OF_ONE_TICK_SPACING_CROSSED +
                resources.initialized_ticks_crossed as u64 *
                    Self::GAS_COST_OF_ONE_INITIALIZED_TICK_CROSSED,
            new_state,
        })
    }

    fn get_limit(&self, token_in: U256) -> Result<u128, SimulationError> {
        let max_in_token_amount = TokenAmount { amount: i128::MAX, token: token_in };

        let sqrt_ratio = self.sqrt_ratio();
        let ticks = self.imp.get_sorted_ticks();

        let sqrt_ratio_limit = if token_in == self.key().token0 {
            ticks
                .first()
                .map_or(Ok(sqrt_ratio), |tick| {
                    to_sqrt_ratio(tick.index)
                        .ok_or_else(|| {
                            SimulationError::FatalError(
                                "sqrt_ratio should be computable from tick index".to_string(),
                            )
                        })
                        .map(|r| Ord::min(r, sqrt_ratio))
                })
        } else {
            ticks
                .last()
                .map_or(Ok(sqrt_ratio), |tick| {
                    to_sqrt_ratio(tick.index)
                        .ok_or_else(|| {
                            SimulationError::FatalError(
                                "sqrt_ratio should be computable from tick index".to_string(),
                            )
                        })
                        .map(|r| Ord::max(r, sqrt_ratio))
                })
        }?;

        let quote = self
            .imp
            .quote(QuoteParams {
                token_amount: max_in_token_amount,
                sqrt_ratio_limit: Some(sqrt_ratio_limit),
                override_state: Some(self.state),
                meta: (),
            })
            .map_err(|err| SimulationError::RecoverableError(format!("quoting error: {err:?}")))?;

        let resources = quote.execution_resources;

        Ok(u128::try_from(quote.consumed_amount)
            .map_err(|_| {
                SimulationError::FatalError("consumed amount should be non-negative".to_string())
            })?
            .saturating_sub(
                Self::WEI_UNDERESTIMATION_FACTOR *
                    (resources.initialized_ticks_crossed as u128 +
                        resources.tick_spacings_crossed as u128 / 256 +
                        1),
            ))
    }

    fn finish_transition(&mut self) -> Result<(), TransitionError<String>> {
        let updated_ticks = (!self.changed_ticks.is_empty()).then(|| {
            let mut ticks = self.imp.get_sorted_ticks().clone();

            for tick in self.changed_ticks.drain(..) {
                let res = ticks.binary_search_by_key(&tick.index, |t| t.index);

                match res {
                    Ok(idx) => {
                        if tick.liquidity_delta.is_zero() {
                            ticks.remove(idx);
                        } else {
                            ticks[idx] = tick;
                        }
                    }
                    Err(idx) => {
                        ticks.insert(idx, tick);
                    }
                }
            }

            ticks
        });

        // Only after a swap we set the active_tick to None. In this case, the active_tick_index is
        // already correctly computed though
        if let Some(active_tick) = self.active_tick {
            self.state.active_tick_index = find_nearest_initialized_tick_index(
                updated_ticks
                    .as_ref()
                    .unwrap_or_else(|| self.imp.get_sorted_ticks()),
                active_tick,
            );
        }

        if let Some(ticks) = updated_ticks {
            self.imp = impl_from_state(*self.key(), self.state, ticks).map_err(|err| {
                TransitionError::SimulationError(SimulationError::RecoverableError(format!(
                    "reinstantiate base pool: {err:?}"
                )))
            })?;
        }

        Ok(())
    }
}

use std::collections::{HashMap, HashSet};

use ekubo_sdk::{
    chain::evm::{EvmMevCapturePool, EvmPoolKey, EvmTokenAmount},
    quoting::{
        pools::{
            base::BasePoolState,
            mev_capture::{MevCapturePoolKey, MevCapturePoolState},
        },
        types::{Pool, QuoteParams, Tick},
        util::find_nearest_initialized_tick_index,
    },
    U256,
};
use num_traits::Zero;
use revm::primitives::Address;
use serde::{Deserialize, Serialize};
use tycho_common::{
    simulation::errors::{SimulationError, TransitionError},
    Bytes,
};

use super::{EkuboPool, EkuboPoolQuote};
use crate::{
    evm::protocol::ekubo_v3::{
        attributes::ticks_from_attributes,
        pool::base::{self, BasePool},
    },
    protocol::errors::InvalidSnapshotError,
};

#[derive(Debug, Eq, Clone, Serialize, Deserialize)]
pub struct MevCapturePool {
    imp: EvmMevCapturePool,

    ticks: Vec<Tick>,
    base_pool_state: BasePoolState,
    last_tick: i32,

    active_tick: Option<i32>,
}

impl PartialEq for MevCapturePool {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
            && self.base_pool_state == other.base_pool_state
            && self.ticks == other.ticks
            && self.last_tick == other.last_tick
    }
}

fn impl_from_state(
    key: MevCapturePoolKey,
    base_pool_state: BasePoolState,
    ticks: Vec<Tick>,
    tick: i32,
) -> Result<EvmMevCapturePool, String> {
    EvmMevCapturePool::new(
        base::impl_from_state(key, base_pool_state, ticks)
            .map_err(|err| format!("creating base pool: {err:?}"))?,
        0,
        tick,
    )
    .map_err(|err| format!("creating MEV-capture pool: {err:?}"))
}

impl MevCapturePool {
    const BASE_GAS_COST: u64 = 41_600;
    const GAS_COST_OF_ONE_STATE_UPDATE: u64 = 16_400;

    pub fn new(
        key: MevCapturePoolKey,
        ticks: Vec<Tick>,
        sqrt_ratio: U256,
        liquidity: u128,
        tick: i32,
    ) -> Result<Self, InvalidSnapshotError> {
        let base_pool_state = BasePoolState {
            sqrt_ratio,
            liquidity,
            active_tick_index: find_nearest_initialized_tick_index(&ticks, tick),
        };

        Ok(Self {
            imp: impl_from_state(key, base_pool_state, ticks.clone(), tick).map_err(|err| {
                InvalidSnapshotError::ValueError(format!("creating MEV-capture pool: {err:?}"))
            })?,
            ticks,
            base_pool_state,
            last_tick: tick,
            active_tick: Some(tick),
        })
    }
}

impl EkuboPool for MevCapturePool {
    fn key(&self) -> EvmPoolKey {
        self.imp.key().map_into_config()
    }

    fn sqrt_ratio(&self) -> U256 {
        self.base_pool_state.sqrt_ratio
    }

    fn set_sqrt_ratio(&mut self, sqrt_ratio: U256) {
        self.base_pool_state.sqrt_ratio = sqrt_ratio;
    }

    fn set_liquidity(&mut self, liquidity: u128) {
        self.base_pool_state.liquidity = liquidity;
    }

    fn quote(&self, token_amount: EvmTokenAmount) -> Result<EkuboPoolQuote, SimulationError> {
        let first_swap_this_block = self.active_tick.is_some();

        let quote = self
            .imp
            .quote(QuoteParams {
                token_amount,
                sqrt_ratio_limit: None,
                override_state: Some(MevCapturePoolState {
                    last_update_time: 0,
                    base_pool_state: self.base_pool_state,
                }),
                meta: u64::from(first_swap_this_block),
            })
            .map_err(|err| SimulationError::RecoverableError(format!("quoting error: {err:?}")))?;

        Ok(EkuboPoolQuote {
            consumed_amount: quote.consumed_amount,
            calculated_amount: quote.calculated_amount,
            gas: Self::BASE_GAS_COST
                + u64::from(
                    quote
                        .execution_resources
                        .state_update_count,
                ) * Self::GAS_COST_OF_ONE_STATE_UPDATE
                + BasePool::gas_costs(
                    quote
                        .execution_resources
                        .base_pool_resources,
                ),
            new_state: Self {
                imp: self.imp.clone(),
                ticks: self.ticks.clone(),
                base_pool_state: quote.state_after.base_pool_state,
                last_tick: self.last_tick,
                active_tick: None,
            }
            .into(),
        })
    }

    fn get_limit(&self, token_in: Address) -> Result<i128, SimulationError> {
        base::get_limit(
            token_in,
            self.sqrt_ratio(),
            &self.imp,
            MevCapturePoolState { last_update_time: 0, base_pool_state: self.base_pool_state },
            0,
            |r| r.base_pool_resources,
        )
    }

    fn finish_transition(
        &mut self,
        updated_attributes: HashMap<String, Bytes>,
        deleted_attributes: HashSet<String>,
    ) -> Result<(), TransitionError<String>> {
        let active_tick_update = updated_attributes
            .get("tick")
            .and_then(|updated_tick| {
                let updated_tick = updated_tick.clone().into();

                (self.active_tick != Some(updated_tick)).then_some(updated_tick)
            });

        let changed_ticks = ticks_from_attributes(
            updated_attributes.into_iter().chain(
                deleted_attributes
                    .into_iter()
                    .map(|key| (key, Bytes::new())),
            ),
        )
        .map_err(TransitionError::DecodeError)?;

        let new_initialized_ticks = !changed_ticks.is_empty();

        for tick in changed_ticks {
            let res = self
                .ticks
                .binary_search_by_key(&tick.index, |t| t.index);

            match res {
                Ok(idx) => {
                    if tick.liquidity_delta.is_zero() {
                        self.ticks.remove(idx);
                    } else {
                        self.ticks[idx] = tick;
                    }
                }
                Err(idx) => {
                    self.ticks.insert(idx, tick);
                }
            }
        }

        if let Some(new_active_tick) = active_tick_update {
            self.last_tick = new_active_tick;
            self.active_tick = Some(new_active_tick);
        }

        if active_tick_update.is_some() || new_initialized_ticks {
            self.base_pool_state.active_tick_index = find_nearest_initialized_tick_index(
                &self.ticks,
                self.active_tick.ok_or_else(|| {
                    TransitionError::MissingAttribute(
                        "base state should always have an active tick during transitions"
                            .to_string(),
                    )
                })?,
            );
        }

        if new_initialized_ticks {
            self.imp = impl_from_state(
                self.imp.key(),
                self.base_pool_state,
                self.ticks.clone(),
                self.last_tick,
            )
            .map_err(|err| {
                TransitionError::SimulationError(SimulationError::RecoverableError(format!(
                    "reinstantiate base pool: {err:?}"
                )))
            })?;
        }

        Ok(())
    }
}

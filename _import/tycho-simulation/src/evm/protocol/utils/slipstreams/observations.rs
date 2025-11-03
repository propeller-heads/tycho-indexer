use alloy::primitives::U256;
use serde::Deserialize;
use tycho_common::simulation::errors::SimulationError;

use crate::evm::protocol::safe_math::{safe_add_u256, safe_div_u256, safe_mul_u256, safe_sub_u256};

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Observation {
    pub(crate) block_timestamp: u32,
    pub(crate) tick_cumulative: i64,
    pub(crate) seconds_per_liquidity_cumulative_x128: U256,
    pub(crate) initialized: bool,
    pub(crate) index: i32,
}

impl Observation {
    pub fn from_attribute(index: i32, bytes: &[u8]) -> Result<Self, SimulationError> {
        let mut obs: Observation = serde_json::from_slice(bytes).map_err(|e| {
            SimulationError::FatalError(format!("Failed to deserialize Observation: {}", e))
        })?;
        obs.index = index;
        Ok(obs)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Observations {
    observations: Vec<Observation>,
}

impl Observations {
    pub fn new(observations: Vec<Observation>) -> Self {
        Self { observations }
    }

    pub fn upsert_observation(&mut self, index: i32, bytes: &[u8]) -> Result<(), SimulationError> {
        let idx = index as usize;
        if bytes.is_empty() {
            return if idx < self.observations.len() {
                self.observations.remove(idx);
                Ok(())
            } else {
                Err(SimulationError::FatalError(format!(
                    "Cannot delete: index {} out of bounds (len={})",
                    index,
                    self.observations.len()
                )))
            }
        }
        let mut obs: Observation = serde_json::from_slice(bytes).map_err(|e| {
            SimulationError::FatalError(format!("Failed to deserialize Observation: {}", e))
        })?;
        obs.index = index;
        if idx < self.observations.len() {
            self.observations[idx] = obs;
            return Ok(());
        }
        if idx >= self.observations.capacity() {
            self.observations
                .reserve(idx - self.observations.len() + 1);
        }

        while self.observations.len() < idx {
            self.observations
                .push(Observation::default());
        }

        self.observations.push(obs);
        Ok(())
    }

    pub fn observe(
        &self,
        time: u32,
        seconds_agos: &[u32],
        tick: i32,
        index: u16,
        liquidity: u128,
        cardinality: u16,
    ) -> Result<(Vec<i64>, Vec<U256>), SimulationError> {
        if cardinality == 0 {
            return Err(SimulationError::FatalError("Cardinality must be > 0".to_string()));
        }
        let mut tick_cumulatives = Vec::with_capacity(seconds_agos.len());
        let mut seconds_per_liquidity_cumulative_x128s = Vec::with_capacity(seconds_agos.len());

        for &seconds_ago in seconds_agos {
            let (tick_cum, sec_liq) =
                self.observe_single(time, seconds_ago, tick, index, liquidity, cardinality)?;
            tick_cumulatives.push(tick_cum);
            seconds_per_liquidity_cumulative_x128s.push(sec_liq);
        }

        Ok((tick_cumulatives, seconds_per_liquidity_cumulative_x128s))
    }

    pub fn binary_search(
        &self,
        time: u32,
        target: u32,
        index: u16,
        cardinality: u16,
    ) -> Result<(Observation, Observation), SimulationError> {
        let mut l = (index as usize + 1) % cardinality as usize;
        let mut r = l + cardinality as usize - 1;

        loop {
            let i = (l + r) / 2;
            let before_or_at = self.observations[i % cardinality as usize];

            if !before_or_at.initialized {
                l = i + 1;
                continue;
            }

            let at_or_after = self.observations[(i + 1) % cardinality as usize];
            let target_at_or_after = lte(time, before_or_at.block_timestamp, target);
            if target_at_or_after && lte(time, target, at_or_after.block_timestamp) {
                return Ok((before_or_at, at_or_after));
            }

            if !target_at_or_after {
                if i == 0 {
                    break;
                }
                r = i - 1;
            } else {
                l = i + 1;
            }
        }

        Err(SimulationError::FatalError(
            "Binary search failed — inconsistent oracle data".to_string(),
        ))
    }

    pub fn get_surrounding_observations(
        &self,
        time: u32,
        target: u32,
        tick: i32,
        index: u16,
        liquidity: u128,
        cardinality: u16,
    ) -> Result<(Observation, Observation), SimulationError> {
        let mut before_or_at = self.observations[index as usize];

        if lte(time, before_or_at.block_timestamp, target) {
            if before_or_at.block_timestamp == target {
                return Ok((before_or_at, before_or_at));
            }
            return Ok((before_or_at, transform(&before_or_at, target, tick, liquidity)));
        }

        before_or_at = self.observations[(index as usize + 1) % cardinality as usize];
        if !before_or_at.initialized {
            before_or_at = self.observations[0];
        }

        if !lte(time, before_or_at.block_timestamp, target) {
            return Err(SimulationError::FatalError(
                "Target too old (after oldest observation)".to_string(),
            ))
        }

        self.binary_search(time, target, index, cardinality)
    }

    pub fn observe_single(
        &self,
        time: u32,
        seconds_ago: u32,
        tick: i32,
        index: u16,
        liquidity: u128,
        cardinality: u16,
    ) -> Result<(i64, U256), SimulationError> {
        if seconds_ago == 0 {
            let mut last = self.observations[index as usize];
            if last.block_timestamp != time {
                last = transform(&last, time, tick, liquidity);
            }
            return Ok((last.tick_cumulative, last.seconds_per_liquidity_cumulative_x128));
        }

        let target = time - seconds_ago;
        let (before_or_at, at_or_after) =
            self.get_surrounding_observations(time, target, tick, index, liquidity, cardinality)?;

        if target == before_or_at.block_timestamp {
            // we're at the left boundary
            Ok((before_or_at.tick_cumulative, before_or_at.seconds_per_liquidity_cumulative_x128))
        } else if target == at_or_after.block_timestamp {
            // we're at the right boundary
            Ok((at_or_after.tick_cumulative, at_or_after.seconds_per_liquidity_cumulative_x128))
        } else {
            // we're in the middle
            let observation_time_delta = at_or_after
                .block_timestamp
                .wrapping_sub(before_or_at.block_timestamp)
                as i64;
            let target_delta = target.wrapping_sub(before_or_at.block_timestamp) as i64;

            let tick_cumulative = before_or_at.tick_cumulative +
                ((at_or_after.tick_cumulative - before_or_at.tick_cumulative) * target_delta /
                    observation_time_delta);

            let seconds_per_liquidity_cumulative_x128 = {
                let delta = safe_sub_u256(
                    at_or_after.seconds_per_liquidity_cumulative_x128,
                    before_or_at.seconds_per_liquidity_cumulative_x128,
                )?;
                let scaled = safe_div_u256(
                    safe_mul_u256(delta, U256::from(target_delta as u128))?,
                    U256::from(observation_time_delta as u128),
                )?;
                safe_add_u256(before_or_at.seconds_per_liquidity_cumulative_x128, scaled)?
            };

            Ok((tick_cumulative, seconds_per_liquidity_cumulative_x128))
        }
    }
}

fn lte(time: u32, a: u32, b: u32) -> bool {
    if a <= time && b <= time {
        return a <= b;
    }

    let a_adjusted = if a > time { a as u64 } else { a as u64 + (1u64 << 32) };
    let b_adjusted = if b > time { b as u64 } else { b as u64 + (1u64 << 32) };

    a_adjusted <= b_adjusted
}

fn transform(before: &Observation, target: u32, tick: i32, liquidity: u128) -> Observation {
    let delta = target - before.block_timestamp;
    let tick_cumulative = before.tick_cumulative + tick as i64 * delta as i64;

    // seconds_per_liquidity_cumulative_x128 += delta / liquidity
    let seconds_per_liquidity_cumulative_x128 = if liquidity > 0 {
        before.seconds_per_liquidity_cumulative_x128 +
            (U256::from(delta as u128) << 128) / U256::from(liquidity)
    } else {
        before.seconds_per_liquidity_cumulative_x128
    };

    Observation {
        block_timestamp: target,
        tick_cumulative,
        seconds_per_liquidity_cumulative_x128,
        initialized: true,
        index: before.index,
    }
}

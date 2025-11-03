use crate::evm::protocol::utils::slipstreams::observations::Observations;

pub(crate) const ZERO_FEE_INDICATOR: u32 = 420;
pub(crate) const DEFAULT_SECONDS_AGO: u32 = 600;
pub(crate) const MIN_SECONDS_AGO: u32 = 2;
pub(crate) const DEFAULT_SCALING_FACTOR: u64 = 0;
pub(crate) const DEFAULT_FEE_CAP: u32 = 10000;
const SCALING_PRECISION: u128 = 1_000_000;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DynamicFeeConfig {
    base_fee: u32,
    fee_cap: u32,
    scaling_factor: u64,
}

impl DynamicFeeConfig {
    pub fn new(base_fee: u32, fee_cap: u32, scaling_factor: u64) -> Self {
        Self { base_fee, fee_cap, scaling_factor }
    }
    pub fn update_fee_cap(&mut self, fee_cap: u32) {
        self.fee_cap = fee_cap;
    }
    pub fn update_scaling_factor(&mut self, scaling_factor: u64) {
        self.scaling_factor = scaling_factor;
    }
    pub fn update_base_fee(&mut self, base_fee: u32) {
        self.base_fee = base_fee;
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn get_dynamic_fee(
    dfc: &DynamicFeeConfig,
    default_base_fee: u32,
    current_tick: i32,
    liquidity: u128,
    observation_index: u16,
    observation_cardinality: u16,
    observations: &Observations,
    blocktime: u32,
) -> u32 {
    if dfc.base_fee == ZERO_FEE_INDICATOR {
        return 0;
    }
    let base_fee = if dfc.base_fee != 0 { dfc.base_fee } else { default_base_fee };

    let (scaling_factor, fee_cap) = if dfc.scaling_factor != 0 {
        (dfc.scaling_factor, dfc.fee_cap)
    } else {
        (DEFAULT_SCALING_FACTOR, DEFAULT_FEE_CAP)
    };
    let total_fee = base_fee +
        calculate_dynamic_fee(
            current_tick,
            liquidity,
            observation_index,
            observation_cardinality,
            observations,
            blocktime,
            scaling_factor,
        );
    total_fee.min(fee_cap)
}

fn calculate_dynamic_fee(
    current_tick: i32,
    liquidity: u128,
    observation_index: u16,
    observation_cardinality: u16,
    observations: &Observations,
    blocktime: u32,
    scaling_factor: u64,
) -> u32 {
    if observation_cardinality < (DEFAULT_SECONDS_AGO / MIN_SECONDS_AGO) as u16 {
        return 0;
    };
    let tw_avg_tick = match observations.observe(
        blocktime,
        &[DEFAULT_SECONDS_AGO, 0],
        current_tick,
        observation_index,
        liquidity,
        observation_cardinality,
    ) {
        Ok((tick_cumulatives, _)) if tick_cumulatives.len() >= 2 => {
            ((tick_cumulatives[1] - tick_cumulatives[0]) / DEFAULT_SECONDS_AGO as i64) as i32
        }
        _ => return 0,
    };

    let abs_tick_delta = (current_tick - tw_avg_tick).unsigned_abs();

    let dynamic_fee = (abs_tick_delta as u128 * scaling_factor as u128) / SCALING_PRECISION;
    dynamic_fee as u32
}

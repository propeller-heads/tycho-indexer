use std::collections::HashMap;

use evm_ekubo_sdk::quoting::twamm_pool::TwammSaleRateDelta;
use itertools::Itertools;
use num_traits::Zero;
use tycho_common::Bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwammSaleRateDeltas(Vec<TwammSaleRateDelta>);

impl TwammSaleRateDeltas {
    pub fn set(&mut self, delta: TwammSaleRateDelta) {
        let res = self
            .0
            .binary_search_by_key(&delta.time, |d| d.time);

        let remove = delta.sale_rate_delta0.is_zero() && delta.sale_rate_delta1.is_zero();

        match res {
            Ok(idx) => {
                if remove {
                    self.0.remove(idx);
                } else {
                    self.0[idx] = delta;
                }
            }
            Err(idx) => {
                if !remove {
                    self.0.insert(idx, delta);
                }
            }
        }
    }
}

impl From<&TwammSaleRateDeltas> for Vec<TwammSaleRateDelta> {
    fn from(value: &TwammSaleRateDeltas) -> Self {
        value.0.clone()
    }
}

impl From<Vec<TwammSaleRateDelta>> for TwammSaleRateDeltas {
    fn from(value: Vec<TwammSaleRateDelta>) -> Self {
        Self(value)
    }
}

pub fn sale_rate_deltas_from_attributes<T: IntoIterator<Item = (String, Bytes)>>(
    attributes: T,
    last_execution_time: u64,
) -> Result<impl Iterator<Item = TwammSaleRateDelta>, String> {
    let iter = attributes.into_iter();
    let size_hint = iter.size_hint().0;

    let update_delta = |delta: &mut TwammSaleRateDelta, is_token1, value| {
        *(if is_token1 {
            &mut delta.sale_rate_delta1
        } else {
            &mut delta.sale_rate_delta0
        }) = value;
    };

    Ok(iter
        .filter_map(|(key, value)| {
            if !key.starts_with("orders/") {
                return None;
            }

            let splits = key.split("/").collect_vec();
            let splits_len = splits.len();

            if splits_len != 3 {
                return Some(Err(format!("orders attribute should have 3 segments but received {splits_len}")));
            }

            let time: u64 = match splits[2].parse() {
                Ok(time) => time,
                Err(err) => return Some(Err(format!("order time can't be parsed as u64: {err}"))),
            };

            if time <= last_execution_time {
                return None;
            }

            let is_token1 = match splits[1] {
                "token0" => false,
                "token1" => true,
                token => return Some(Err(format!("expected token0 or token1 but received {token}"))),
            };

            let delta: i128 = value
                .clone()
                .into();

            Some(Ok((time, is_token1, delta)))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .fold(HashMap::with_capacity(size_hint), |mut map, (time, is_token1, value)| {
            map
                .entry(time)
                .and_modify(|delta| update_delta(delta, is_token1, value))
                .or_insert_with(|| {
                    let mut delta = TwammSaleRateDelta {
                        time,
                        sale_rate_delta0: 0,
                        sale_rate_delta1: 0,
                    };

                    update_delta(&mut delta, is_token1, value);

                    delta
                });

            map
        })
        .into_values()
    )
}

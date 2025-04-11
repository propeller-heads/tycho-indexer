use std::collections::HashMap;

use evm_ekubo_sdk::quoting::{twamm_pool::TwammSaleRateDelta, types::Tick};
use itertools::Itertools;
use tycho_common::Bytes;

pub fn ticks_from_attributes<T: IntoIterator<Item = (String, Bytes)>>(
    attributes: T,
) -> Result<Vec<Tick>, String> {
    attributes
        .into_iter()
        .filter_map(|(key, value)| {
            key.starts_with("ticks/").then(|| {
                key.split('/')
                    .nth(1)
                    .ok_or_else(|| "expected key name to contain tick index".to_string())?
                    .parse::<i32>()
                    .map_or_else(
                        |err| Err(format!("tick index can't be parsed as i32: {err}")),
                        |index| Ok(Tick { index, liquidity_delta: i128::from(value.clone()) }),
                    )
            })
        })
        .try_collect()
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
        .try_collect::<_, Vec<_>, _>()?
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

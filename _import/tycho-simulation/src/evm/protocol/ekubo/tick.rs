use evm_ekubo_sdk::quoting::types::Tick;
use itertools::Itertools;
use num_traits::Zero;
use tycho_common::Bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticks(Vec<Tick>);

impl Ticks {
    pub fn new(ticks: Vec<Tick>) -> Self {
        Self(ticks)
    }

    pub fn inner(&self) -> &Vec<Tick> {
        &self.0
    }

    pub fn set(&mut self, tick: Tick) {
        let res = self
            .0
            .binary_search_by_key(&tick.index, |t| t.index);

        let remove = tick.liquidity_delta.is_zero();

        match res {
            Ok(idx) => {
                if remove {
                    self.0.remove(idx);
                } else {
                    self.0[idx] = tick;
                }
            }
            Err(idx) => {
                if !remove {
                    self.0.insert(idx, tick);
                }
            }
        }
    }
}

impl From<Vec<Tick>> for Ticks {
    fn from(value: Vec<Tick>) -> Self {
        Self(value)
    }
}

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

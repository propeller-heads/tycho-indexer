use thiserror::Error;

use crate::action::{
    simulate::SimulateForward,
    swap::{action::Swap, AmountLimits, LimitsParameters, MarginalPriceParameters},
};

#[derive(Error, Debug)]
pub enum ApproximationError {
    #[error("Approximation error: {0}")]
    Fatal(String),
}

type Result<T> = std::result::Result<T, ApproximationError>;

pub trait MarginalPriceApproximator<T: SimulateForward<Swap>> {
    fn approximate(&self, swappable: &T, params: &MarginalPriceParameters) -> Result<f64>;
}

pub trait LimitsApproximator<T: SimulateForward<Swap>> {
    fn approximate(&self, swappable: &T, params: &LimitsParameters) -> Result<AmountLimits>;
}

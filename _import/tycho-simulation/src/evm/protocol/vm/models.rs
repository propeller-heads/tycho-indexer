use alloy_primitives::U256;
use strum_macros::Display;

use crate::protocol::errors::SimulationError;

/// Represents a distinct functionality or feature that an `EVMPoolState` can support.
///
/// Each `Capability` variant corresponds to a specific functionality that influences how the
/// simulation interacts with the `EVMPoolState`.
///
/// # Variants
///
/// - `SellSide`: Supports swapping with a fixed sell amount.
/// - `BuySide`: Supports swapping with a fixed buy amount.
/// - `PriceFunction`: Supports evaluating dynamic pricing based on a function.
/// - `FeeOnTransfer`: Support tokens that charge a fee on transfer.
/// - `ConstantPrice`: The pool does not suffer from price impact and maintains a constant price for
///   increasingly larger specified amounts.
/// - `TokenBalanceIndependent`:Indicates that the pool does not read its own token balances from
///   token contracts while swapping.
/// - `ScaledPrice`: Indicates that prices are returned scaled, else it is assumed prices still
///   require scaling by token decimals.
/// - `HardLimits`: Indicates that if we try to go over the sell limits, the pool will revert.
/// - `MarginalPrice`: Indicates whether the pool's price function can be called with amountIn=0 to
///   return the current price
#[derive(Eq, PartialEq, Hash, Debug, Display, Clone)]
pub enum Capability {
    SellSide = 1,
    BuySide = 2,
    PriceFunction = 3,
    FeeOnTransfer = 4,
    ConstantPrice = 5,
    TokenBalanceIndependent = 6,
    ScaledPrice = 7,
    HardLimits = 8,
    MarginalPrice = 9,
}

impl Capability {
    pub fn from_u256(value: U256) -> Result<Self, SimulationError> {
        let value_as_u8 = value.to_le_bytes::<32>()[0];
        match value_as_u8 {
            1 => Ok(Capability::SellSide),
            2 => Ok(Capability::BuySide),
            3 => Ok(Capability::PriceFunction),
            4 => Ok(Capability::FeeOnTransfer),
            5 => Ok(Capability::ConstantPrice),
            6 => Ok(Capability::TokenBalanceIndependent),
            7 => Ok(Capability::ScaledPrice),
            8 => Ok(Capability::HardLimits),
            9 => Ok(Capability::MarginalPrice),
            _ => {
                Err(SimulationError::FatalError(format!("Unexpected Capability value: {}", value)))
            }
        }
    }
}

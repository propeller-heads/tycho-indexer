// TODO: remove skip for clippy dead_code check
use crate::protocol::vm::errors::ProtosimError;
use ethers::abi::Uint;

#[allow(dead_code)]
#[derive(Eq, PartialEq, Hash, Debug)]
pub enum Capability {
    SellSide = 0,
    BuySide = 1,
    PriceFunction = 2,
    FeeOnTransfer = 3,
    ConstantPrice = 4,
    TokenBalanceIndependent = 5,
    ScaledPrice = 6,
    HardLimits = 7,
    MarginalPrice = 8,
}

impl Capability {
    pub fn from_uint(value: Uint) -> Result<Self, ProtosimError> {
        match value.as_u32() {
            0 => Ok(Capability::SellSide),
            1 => Ok(Capability::BuySide),
            2 => Ok(Capability::PriceFunction),
            3 => Ok(Capability::FeeOnTransfer),
            4 => Ok(Capability::ConstantPrice),
            5 => Ok(Capability::TokenBalanceIndependent),
            6 => Ok(Capability::ScaledPrice),
            7 => Ok(Capability::HardLimits),
            8 => Ok(Capability::MarginalPrice),
            _ => {
                Err(ProtosimError::DecodingError(format!("Unexpected Capability value: {}", value)))
            }
        }
    }
}

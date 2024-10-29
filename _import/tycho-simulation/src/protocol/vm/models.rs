// TODO: remove skip for clippy dead_code check
use crate::protocol::vm::errors::ProtosimError;
use ethers::abi::Uint;

#[allow(dead_code)]
#[derive(Eq, PartialEq, Hash, Debug)]
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
    pub fn from_uint(value: Uint) -> Result<Self, ProtosimError> {
        match value.as_u32() {
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
                Err(ProtosimError::DecodingError(format!("Unexpected Capability value: {}", value)))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeAmount {
    Lowest = 100,      // 0.01%
    Low = 500,         // 0.05%
    MediumLow = 2500,  // 0.25% [Pancakeswap V3]
    Medium = 3000,     // 0.3%
    MediumHigh = 5000, // 0.5% [Pancakeswap V3]
    High = 10_000,     // 1%
}

impl std::convert::TryFrom<i32> for FeeAmount {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            100 => Ok(FeeAmount::Lowest),
            500 => Ok(FeeAmount::Low),
            2500 => Ok(FeeAmount::MediumLow),
            3000 => Ok(FeeAmount::Medium),
            5000 => Ok(FeeAmount::MediumHigh),
            10_000 => Ok(FeeAmount::High),
            _ => Err(()),
        }
    }
}

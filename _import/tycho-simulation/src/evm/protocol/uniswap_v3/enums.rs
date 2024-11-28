#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeAmount {
    Lowest = 100,
    Low = 500,
    Medium = 3000,
    High = 10_000,
}

impl std::convert::TryFrom<i32> for FeeAmount {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            100 => Ok(FeeAmount::Lowest),
            500 => Ok(FeeAmount::Low),
            3000 => Ok(FeeAmount::Medium),
            10_000 => Ok(FeeAmount::High),
            _ => Err(()),
        }
    }
}

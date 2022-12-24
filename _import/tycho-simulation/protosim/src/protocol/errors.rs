use super::models::GetAmountOutResult;

#[derive(Debug, PartialEq)]
pub enum TradeSimulationErrorKind {
    InsufficientData,
    NoLiquidity,
    Unkown,
    InsufficientAmount,
}

#[derive(Debug)]
pub struct TradeSimulationError {
    pub kind: TradeSimulationErrorKind,
    pub partial_result: Option<GetAmountOutResult>,
}

impl TradeSimulationError {
    pub fn new(kind: TradeSimulationErrorKind, partial_result: Option<GetAmountOutResult>) -> Self {
        return TradeSimulationError {
            kind,
            partial_result,
        };
    }
}

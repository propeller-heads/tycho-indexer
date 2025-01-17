use crate::encoding::{
    errors::EncodingError,
    models::{Solution, Transaction},
    strategy_encoder::StrategySelector,
    user_approvals_manager::UserApprovalsManager,
};

#[allow(dead_code)]
pub trait RouterEncoder<S: StrategySelector, A: UserApprovalsManager> {
    fn encode_router_calldata(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError>;
    fn handle_approvals(&self, solutions: &[Solution]) -> Result<Vec<Vec<u8>>, EncodingError>;
}

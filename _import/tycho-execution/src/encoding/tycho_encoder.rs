use crate::encoding::{
    errors::EncodingError,
    models::{Solution, Transaction},
};

/// An encoder must implement this trait in order to encode a solution into a Transaction for
/// execution using a Tycho router or related contracts.
pub trait TychoEncoder {
    fn encode_router_calldata(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError>;
}

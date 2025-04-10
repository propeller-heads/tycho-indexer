use crate::encoding::{
    errors::EncodingError,
    models::{Solution, Transaction},
};

/// A high-level encoder that converts solutions into executable transactions. Allows for modularity
/// in the encoding process.
pub trait TychoEncoder {
    /// Encodes solutions into transactions that can be executed by the Tycho router.
    ///
    /// # Arguments
    /// * `solutions` - Vector of solutions to encode, each potentially using different setups (swap
    ///   paths, protocols, etc.)
    ///
    /// # Returns
    /// * `Result<Vec<Transaction>, EncodingError>` - Vector of executable transactions
    fn encode_calldata(&self, solutions: Vec<Solution>) -> Result<Vec<Transaction>, EncodingError>;

    fn validate_solution(&self, solution: &Solution) -> Result<(), EncodingError>;
}

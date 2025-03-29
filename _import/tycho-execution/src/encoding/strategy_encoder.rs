use tycho_common::Bytes;

use crate::encoding::{errors::EncodingError, models::Solution, swap_encoder::SwapEncoder};

/// A trait that defines how to encode a `Solution` for execution.
pub trait StrategyEncoder {
    /// `encode_strategy` takes a `Solution`, which contains all the necessary information about
    /// the swaps to be performed, and encodes it into a format that can be executed by the router
    /// or executor contracts.
    ///
    /// # Arguments
    /// * `solution` - The `Solution` to encode, containing swap details, amounts, and execution
    ///   path
    ///
    /// # Returns
    /// * `Result<(Vec<u8>, Bytes, Option<String>), EncodingError>` - A tuple containing:
    ///   - The encoded data as bytes
    ///   - The address of the contract to call (router or executor)
    ///   - Optionally, the function selector to use when calling the contract
    fn encode_strategy(&self, solution: Solution) -> Result<(Vec<u8>, Bytes), EncodingError>;

    /// Retrieves the swap encoder for a specific protocol system.
    ///
    /// # Arguments
    /// * `protocol_system` - The identifier of the protocol system (e.g., "uniswap_v2")
    ///
    /// # Returns
    /// * `Option<&Box<dyn SwapEncoder>>` - The swap encoder for the protocol if available
    #[allow(clippy::borrowed_box)]
    fn get_swap_encoder(&self, protocol_system: &str) -> Option<&Box<dyn SwapEncoder>>;

    /// Creates a cloned instance of the strategy encoder.
    fn clone_box(&self) -> Box<dyn StrategyEncoder>;
}

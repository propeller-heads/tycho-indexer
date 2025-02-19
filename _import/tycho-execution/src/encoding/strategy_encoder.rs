use tycho_core::Bytes;

use crate::encoding::{errors::EncodingError, models::Solution, swap_encoder::SwapEncoder};

/// Encodes a solution using a specific strategy.
pub trait StrategyEncoder {
    fn encode_strategy(
        &self,
        to_encode: Solution,
    ) -> Result<(Vec<u8>, Bytes, Option<String>), EncodingError>;

    #[allow(clippy::borrowed_box)]
    fn get_swap_encoder(&self, protocol_system: &str) -> Option<&Box<dyn SwapEncoder>>;
    fn clone_box(&self) -> Box<dyn StrategyEncoder>;
}

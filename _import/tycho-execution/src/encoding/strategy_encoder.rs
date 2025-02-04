use tycho_core::{models::Chain, Bytes};

use crate::encoding::{errors::EncodingError, models::Solution, swap_encoder::SwapEncoder};

pub trait StrategyEncoder {
    fn encode_strategy(
        &self,
        to_encode: Solution,
        router_address: Bytes,
    ) -> Result<(Vec<u8>, Bytes), EncodingError>;

    #[allow(clippy::borrowed_box)]
    fn get_swap_encoder(&self, protocol_system: &str) -> Option<&Box<dyn SwapEncoder>>;
}

pub trait StrategyEncoderRegistry {
    fn new(
        chain: Chain,
        executors_file_path: &str,
        signer_pk: Option<String>,
    ) -> Result<Self, EncodingError>
    where
        Self: Sized;
    #[allow(clippy::borrowed_box)]
    fn get_encoder(&self, solution: &Solution) -> Result<&Box<dyn StrategyEncoder>, EncodingError>;
}

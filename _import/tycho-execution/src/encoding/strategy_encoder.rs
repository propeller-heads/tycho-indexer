use tycho_core::{models::Chain, Bytes};

use crate::encoding::{errors::EncodingError, models::Solution};

pub trait StrategyEncoder {
    fn encode_strategy(
        &self,
        to_encode: Solution,
        router_address: Bytes,
    ) -> Result<(Vec<u8>, Bytes), EncodingError>;
}

pub trait StrategySelector {
    fn select_strategy(
        &self,
        solution: &Solution,
        signer_pk: Option<String>,
        chain_id: Chain,
    ) -> Result<Box<dyn StrategyEncoder>, EncodingError>;
}

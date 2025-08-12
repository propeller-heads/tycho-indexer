use std::collections::HashMap;

use async_trait::async_trait;
use num_bigint::BigUint;

use crate::{
    models::protocol::GetAmountOutParams,
    simulation::{errors::SimulationError, protocol_sim::ProtocolSim},
    Bytes,
};

#[derive(Debug)]
pub struct SignedQuote {
    pub base_token: Bytes,
    pub quote_token: Bytes,
    pub amount_in: BigUint,
    pub amount_out: BigUint,
    // each RFQ will need different attributes
    pub quote_attributes: HashMap<String, Bytes>,
}

#[async_trait]
pub trait IndicativelyPriced: ProtocolSim {
    async fn request_signed_quote(
        &self,
        _params: GetAmountOutParams,
    ) -> Result<SignedQuote, SimulationError> {
        Err(SimulationError::FatalError("request_signed_quote not implemented".into()))
    }
}

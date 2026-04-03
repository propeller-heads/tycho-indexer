use std::{collections::HashMap, str::FromStr};

use alloy::{primitives::Address, sol_types::SolValue};
use tycho_common::{models::Chain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::utils::bytes_to_address,
    models::{EncodingContext, Swap},
    swap_encoder::SwapEncoder,
};

/// Encodes a swap on an Aerodrome V1 pool through the given executor address.
#[derive(Clone)]
pub struct AerodromeV1SwapEncoder {
    executor_address: Bytes,
}

impl AerodromeV1SwapEncoder {}

impl SwapEncoder for AerodromeV1SwapEncoder {
    fn new(
        executor_address: Bytes,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self { executor_address })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        _encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_in_address = bytes_to_address(swap.token_in())?;
        let token_out_address = bytes_to_address(swap.token_out())?;
        let component_id = Address::from_str(&swap.component().id).map_err(|_| {
            EncodingError::FatalError("Invalid aerodrome_v1 component id".to_string())
        })?;

        Ok((component_id, token_in_address, token_out_address).abi_encode_packed())
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }

    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use alloy::hex::encode;
    use tycho_common::models::protocol::ProtocolComponent;

    use super::*;
    use crate::encoding::{
        evm::{swap_encoder::aerodrome_v1::AerodromeV1SwapEncoder, utils::write_calldata_to_file},
        models::Swap,
    };

    #[test]
    fn test_encode_aerodrome_v1() {
        let pool = ProtocolComponent {
            id: String::from("0x168ddF44Df9e1d7A8b5BdF4f9e8A8dB6f6e95D15"),
            ..Default::default()
        };

        let token_in = Bytes::from("0x4200000000000000000000000000000000000006");
        let token_out = Bytes::from("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
        let swap = Swap::new(pool, token_in.clone(), token_out.clone());
        let encoding_context = EncodingContext {
            router_address: Some(Bytes::zero(20)),
            group_token_in: token_in.clone(),
            group_token_out: token_out.clone(),
        };

        let encoder = AerodromeV1SwapEncoder::new(
            Bytes::from("0x1111111111111111111111111111111111111111"),
            Chain::Base,
            None,
        )
        .unwrap();

        let encoded_swap = encoder
            .encode_swap(&swap, &encoding_context)
            .unwrap();
        let hex_swap = encode(&encoded_swap);

        assert_eq!(
            hex_swap,
            String::from(concat!(
                "168ddf44df9e1d7a8b5bdf4f9e8a8db6f6e95d15",
                "4200000000000000000000000000000000000006",
                "833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            ))
        );

        write_calldata_to_file("test_encode_aerodrome_v1", hex_swap.as_str());
    }
}

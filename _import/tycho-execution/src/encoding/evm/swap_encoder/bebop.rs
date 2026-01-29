use std::{collections::HashMap, sync::Arc};

use alloy::sol_types::SolValue;
use tokio::{
    runtime::{Handle, Runtime},
    task::block_in_place,
};
use tycho_common::{
    models::{protocol::GetAmountOutParams, Chain},
    Bytes,
};

use crate::encoding::{
    errors::EncodingError,
    evm::utils::{biguint_to_u256, bytes_to_address, get_runtime},
    models::{EncodingContext, Swap},
    swap_encoder::SwapEncoder,
};

/// Encodes a swap on Bebop (PMM RFQ) through the given executor address.
///
/// Bebop uses a Request-for-Quote model where quotes are obtained off-chain
/// and settled on-chain. This encoder supports PMM RFQ execution.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
#[derive(Clone)]
pub struct BebopSwapEncoder {
    executor_address: Bytes,
    runtime_handle: Handle,
    #[allow(dead_code)]
    runtime: Option<Arc<Runtime>>,
}

impl SwapEncoder for BebopSwapEncoder {
    fn new(
        executor_address: Bytes,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        let (runtime_handle, runtime) = get_runtime()?;
        Ok(Self { executor_address, runtime_handle, runtime })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_in = bytes_to_address(swap.token_in())?;
        let token_out = bytes_to_address(swap.token_out())?;

        let protocol_state = swap
            .get_protocol_state()
            .as_ref()
            .ok_or_else(|| {
                EncodingError::FatalError("protocol_state is required for Bebop".to_string())
            })?;
        let (partial_fill_offset, original_filled_taker_amount, bebop_calldata) = {
            let indicatively_priced_state = protocol_state
                .as_indicatively_priced()
                .map_err(|e| {
                    EncodingError::FatalError(format!("State is not indicatively priced {e}"))
                })?;
            let estimated_amount_in = swap
                .get_estimated_amount_in()
                .clone()
                .ok_or(EncodingError::FatalError(
                    "Estimated amount in is mandatory for a Bebop swap".to_string(),
                ))?;
            let token_in = swap.token_in().clone();
            let token_out = swap.token_out().clone();

            let params = GetAmountOutParams {
                amount_in: estimated_amount_in,
                token_in,
                token_out,
                sender: encoding_context
                    .router_address
                    .clone()
                    .ok_or(EncodingError::FatalError(
                        "The router address is needed to perform a Bebop swap".to_string(),
                    ))?,
                receiver: encoding_context.receiver.clone(),
            };
            let signed_quote = block_in_place(|| {
                self.runtime_handle.block_on(async {
                    indicatively_priced_state
                        .request_signed_quote(params)
                        .await
                })
            })?;
            let bebop_calldata = signed_quote
                .quote_attributes
                .get("calldata")
                .ok_or(EncodingError::FatalError(
                    "Bebop quote must have a calldata attribute".to_string(),
                ))?;
            let partial_fill_offset = signed_quote
                .quote_attributes
                .get("partial_fill_offset")
                .ok_or(EncodingError::FatalError(
                    "Bebop quote must have a partial_fill_offset attribute".to_string(),
                ))?;
            let original_filled_taker_amount = biguint_to_u256(&signed_quote.amount_out);
            (
                // we are only interested in the last byte to get a u8
                partial_fill_offset[partial_fill_offset.len() - 1],
                original_filled_taker_amount,
                bebop_calldata.to_vec(),
            )
        };

        let receiver = bytes_to_address(&encoding_context.receiver)?;

        // Encode packed data for the executor
        // Format: token_in | token_out | partial_fill_offset |
        //         original_filled_taker_amount | approval_needed | receiver | bebop_calldata
        let args = (
            token_in,
            token_out,
            partial_fill_offset.to_be_bytes(),
            original_filled_taker_amount.to_be_bytes::<32>(),
            receiver,
            &bebop_calldata[..],
        );

        Ok(args.abi_encode_packed())
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
    use std::str::FromStr;

    use alloy::hex::encode;
    use num_bigint::BigUint;
    use tycho_common::models::protocol::ProtocolComponent;

    use super::*;
    use crate::encoding::evm::{
        swap_encoder::bebop::BebopSwapEncoder, testing_utils::MockRFQState,
    };

    #[test]
    fn test_encode_bebop_single_with_protocol_state() {
        // 3000 USDC -> 1 WETH using a mocked RFQ state to get a quote
        let bebop_calldata = Bytes::from_str("0x123456").unwrap();
        let partial_fill_offset = 12u64;
        let quote_amount_out = BigUint::from_str("1000000000000000000").unwrap();

        let bebop_component = ProtocolComponent {
            id: String::from("bebop-rfq"),
            protocol_system: String::from("rfq:bebop"),
            ..Default::default()
        };
        let bebop_state = MockRFQState {
            quote_amount_out,
            quote_data: HashMap::from([
                ("calldata".to_string(), bebop_calldata.clone()),
                (
                    "partial_fill_offset".to_string(),
                    Bytes::from(
                        partial_fill_offset
                            .to_be_bytes()
                            .to_vec(),
                    ),
                ),
            ]),
        };

        let token_in = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // USDC
        let token_out = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"); // WETH

        let swap = Swap::new(bebop_component, token_in.clone(), token_out.clone())
            .estimated_amount_in(BigUint::from_str("3000000000").unwrap())
            .protocol_state(Arc::new(bebop_state));

        let encoding_context = EncodingContext {
            receiver: Bytes::from("0xc5564C13A157E6240659fb81882A28091add8670"),
            exact_out: false,
            router_address: Some(Bytes::zero(20)),
            group_token_in: token_in.clone(),
            group_token_out: token_out.clone(),
            historical_trade: false,
        };

        let encoder = BebopSwapEncoder::new(
            Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
            Chain::Ethereum,
            None,
        )
        .unwrap();

        let encoded_swap = encoder
            .encode_swap(&swap, &encoding_context)
            .unwrap();
        let hex_swap = encode(&encoded_swap);

        let expected_swap = String::from(concat!(
            // token in
            "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            // token out
            "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            // partiall filled offset
            "0c",
            //  original taker amount
            "0000000000000000000000000000000000000000000000000de0b6b3a7640000",
            //receiver,
            "c5564c13a157e6240659fb81882a28091add8670",
        ));
        assert_eq!(hex_swap, expected_swap + &bebop_calldata.to_string()[2..]);
    }
}

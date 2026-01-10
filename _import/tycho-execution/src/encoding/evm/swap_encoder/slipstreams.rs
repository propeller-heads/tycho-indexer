use std::{collections::HashMap, str::FromStr};

use alloy::{primitives::Address, sol_types::SolValue};
use tycho_common::{models::Chain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::utils::{bytes_to_address, get_static_attribute, pad_or_truncate_to_size},
    models::{EncodingContext, Swap},
    swap_encoder::SwapEncoder,
};

/// Encodes a swap on a Aerodrome Slipstreams pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
#[derive(Clone)]
pub struct SlipstreamsSwapEncoder {
    executor_address: Bytes,
}

impl SlipstreamsSwapEncoder {
    fn get_zero_to_one(sell_token_address: Address, buy_token_address: Address) -> bool {
        sell_token_address < buy_token_address
    }
}

impl SwapEncoder for SlipstreamsSwapEncoder {
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
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_in_address = bytes_to_address(swap.token_in())?;
        let token_out_address = bytes_to_address(swap.token_out())?;

        let zero_to_one = Self::get_zero_to_one(token_in_address, token_out_address);
        let component_id = Address::from_str(&swap.component().id).map_err(|_| {
            EncodingError::FatalError("Invalid Slipstreams component id".to_string())
        })?;
        let tick_spacing_bytes = get_static_attribute(swap, "tick_spacing")?;

        let tick_spacing_bytes_u24 =
            pad_or_truncate_to_size::<3>(&tick_spacing_bytes).map_err(|_| {
                EncodingError::FatalError("Failed to extract tick_spacing bytes".to_string())
            })?;

        let args = (
            token_in_address,
            token_out_address,
            tick_spacing_bytes_u24,
            (encoding_context.transfer_type as u8).to_be_bytes(),
            bytes_to_address(&encoding_context.receiver)?,
            component_id,
            zero_to_one,
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

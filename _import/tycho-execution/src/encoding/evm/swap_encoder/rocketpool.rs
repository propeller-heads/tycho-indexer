use std::collections::HashMap;

use alloy::sol_types::SolValue;
use tycho_common::{models::Chain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::utils::bytes_to_address,
    models::{EncodingContext, Swap},
    swap_encoder::SwapEncoder,
};

/// Encodes a swap on a Rocketpool pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
/// * `native_token_address` - The address of the native token (only ETH).
#[derive(Clone)]
pub struct RocketpoolSwapEncoder {
    executor_address: Bytes,
    native_token_address: Bytes,
}

impl SwapEncoder for RocketpoolSwapEncoder {
    fn new(
        executor_address: Bytes,
        chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        if chain != Chain::Ethereum {
            return Err(EncodingError::FatalError(
                "Rocketpool swaps are only supported on Ethereum".to_string(),
            ));
        }
        let native_token_address = chain.native_token().address;

        Ok(Self { executor_address, native_token_address })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let is_deposit = *swap.token_in() == self.native_token_address;

        let args = (
            is_deposit,
            (encoding_context.transfer_type as u8).to_be_bytes(),
            bytes_to_address(&encoding_context.receiver)?,
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
    use alloy::hex::encode;
    use tycho_common::models::protocol::ProtocolComponent;

    use super::*;
    use crate::encoding::{
        evm::{swap_encoder::rocketpool::RocketpoolSwapEncoder, utils::write_calldata_to_file},
        models::TransferType,
    };
    #[test]
    fn test_encode_rocketpool_deposit() {
        // ETH -> (rocketpool) -> rETH
        let rocketpool_pool = ProtocolComponent {
            id: String::from("0xdd3f50f8a6cafbe9b31a427582963f465e745af8"),
            protocol_system: String::from("rocketpool"),
            ..Default::default()
        };
        let token_in = Bytes::from("0x0000000000000000000000000000000000000000");
        let token_out = Bytes::from("0xae78736Cd615f374D3085123A210448E74Fc6393");
        let swap = Swap::new(rocketpool_pool, token_in.clone(), token_out.clone());
        let encoding_context = EncodingContext {
            // The receiver was generated with `makeAddr("bob*") using forge`
            receiver: Bytes::from("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de"),
            exact_out: false,
            router_address: Some(Bytes::default()),
            group_token_in: token_in.clone(),
            group_token_out: token_out.clone(),
            transfer_type: TransferType::Transfer,
            historical_trade: false,
        };
        let encoder = RocketpoolSwapEncoder::new(
            Bytes::from("0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"),
            Chain::Ethereum,
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
                // is deposit
                "01",
                // transfer type
                "01",
                // receiver
                "9964bff29baa37b47604f3f3f51f3b3c5149d6de",
            ))
            .to_lowercase()
        );

        write_calldata_to_file("test_encode_rocketpool_deposit", hex_swap.as_str());
    }

    #[test]
    fn test_encode_rocketpool_burn() {
        // ETH -> (rocketpool) -> rETH
        let rocketpool_pool = ProtocolComponent {
            id: String::from("0xdd3f50f8a6cafbe9b31a427582963f465e745af8"),
            protocol_system: String::from("rocketpool"),
            ..Default::default()
        };
        let token_in = Bytes::from("0xae78736Cd615f374D3085123A210448E74Fc6393");
        let token_out = Bytes::from("0x0000000000000000000000000000000000000000");
        let swap = Swap::new(rocketpool_pool, token_in.clone(), token_out.clone());
        let encoding_context = EncodingContext {
            // The receiver was generated with `makeAddr("bob*") using forge`
            receiver: Bytes::from("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de"),
            exact_out: false,
            router_address: Some(Bytes::default()),
            group_token_in: token_in.clone(),
            group_token_out: token_out.clone(),
            transfer_type: TransferType::Transfer,
            historical_trade: false,
        };
        let encoder = RocketpoolSwapEncoder::new(
            Bytes::from("0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"),
            Chain::Ethereum,
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
                // is deposit
                "00",
                // transfer type
                "01",
                // receiver
                "9964bff29baa37b47604f3f3f51f3b3c5149d6de",
            ))
            .to_lowercase()
        );

        write_calldata_to_file("test_encode_rocketpool_burn", hex_swap.as_str());
    }
}

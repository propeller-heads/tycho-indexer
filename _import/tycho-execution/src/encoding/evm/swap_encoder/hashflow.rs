use std::{collections::HashMap, str::FromStr, sync::Arc};

use alloy::{primitives::Address, sol_types::SolValue};
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
    evm::{
        approvals::protocol_approvals_manager::ProtocolApprovalsManager,
        utils::{bytes_to_address, get_runtime},
    },
    models::{EncodingContext, Swap},
    swap_encoder::SwapEncoder,
};

#[derive(Clone)]
pub struct HashflowSwapEncoder {
    executor_address: Bytes,
    hashflow_router_address: Bytes,
    native_token_address: Bytes,
    runtime_handle: Handle,
    #[allow(dead_code)]
    runtime: Option<Arc<Runtime>>,
}

impl SwapEncoder for HashflowSwapEncoder {
    fn new(
        executor_address: Bytes,
        chain: Chain,
        config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        let config = config.ok_or(EncodingError::FatalError(
            "Missing hashflow specific addresses in config".to_string(),
        ))?;
        let hashflow_router_address = config
            .get("hashflow_router_address")
            .map(|s| {
                Bytes::from_str(s).map_err(|_| {
                    EncodingError::FatalError("Invalid hashflow router address".to_string())
                })
            })
            .ok_or(EncodingError::FatalError(
                "Missing hashflow router address in config".to_string(),
            ))
            .flatten()?;
        let native_token_address = chain.native_token().address;
        let (runtime_handle, runtime) = get_runtime()?;
        Ok(Self {
            executor_address,
            hashflow_router_address,
            native_token_address,
            runtime_handle,
            runtime,
        })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        // Native tokens doesn't need approval, only ERC20 tokens do
        let sender = encoding_context
            .router_address
            .clone()
            .ok_or(EncodingError::FatalError(
                "The router address is needed to perform a Hashflow swap".to_string(),
            ))?;

        // Native ETH doesn't need approval, only ERC20 tokens do
        let approval_needed = if *swap.token_in() == self.native_token_address {
            false
        } else {
            let tycho_router_address = bytes_to_address(&sender)?;
            let hashflow_router_address = Address::from_slice(&self.hashflow_router_address);
            ProtocolApprovalsManager::new()?.approval_needed(
                bytes_to_address(swap.token_in())?,
                tycho_router_address,
                hashflow_router_address,
            )?
        };

        // Get quote
        let protocol_state = swap
            .get_protocol_state()
            .as_ref()
            .ok_or_else(|| {
                EncodingError::FatalError("protocol_state is required for Hashflow".to_string())
            })?;
        let amount_in = swap
            .get_estimated_amount_in()
            .as_ref()
            .ok_or(EncodingError::FatalError(
                "Estimated amount in is mandatory for a Hashflow swap".to_string(),
            ))?
            .clone();
        let sender = encoding_context
            .router_address
            .clone()
            .ok_or(EncodingError::FatalError(
                "The router address is needed to perform a Hashflow swap".to_string(),
            ))?;
        let signed_quote = block_in_place(|| {
            self.runtime_handle.block_on(async {
                protocol_state
                    .as_indicatively_priced()?
                    .request_signed_quote(GetAmountOutParams {
                        amount_in,
                        token_in: swap.token_in().clone(),
                        token_out: swap.token_out().clone(),
                        sender,
                        receiver: encoding_context.receiver.clone(),
                    })
                    .await
            })
        })?;

        // Encode packed data for the executor
        // Format: approval_needed | transfer_type | hashflow_calldata[..]
        let hashflow_fields = [
            "pool",
            "external_account",
            "trader",
            "base_token",
            "quote_token",
            "base_token_amount",
            "quote_token_amount",
            "quote_expiry",
            "nonce",
            "tx_id",
            "signature",
        ];
        let mut hashflow_calldata = vec![];
        for field in &hashflow_fields {
            let value = signed_quote
                .quote_attributes
                .get(*field)
                .ok_or(EncodingError::FatalError(format!(
                    "Hashflow quote must have a {field} attribute"
                )))?;
            hashflow_calldata.extend_from_slice(value);
        }
        let args = (
            (encoding_context.transfer_type as u8).to_be_bytes(),
            (approval_needed as u8).to_be_bytes(),
            &hashflow_calldata[..],
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
mod test {
    use alloy::hex::encode;
    use num_bigint::BigUint;
    use tycho_common::models::protocol::ProtocolComponent;

    use super::*;
    use crate::encoding::{
        evm::{
            swap_encoder::hashflow::HashflowSwapEncoder, testing_utils::MockRFQState,
            utils::biguint_to_u256,
        },
        models::{Swap, TransferType},
    };

    fn hashflow_config() -> Option<HashMap<String, String>> {
        Some(HashMap::from([(
            "hashflow_router_address".to_string(),
            "0x55084eE0fEf03f14a305cd24286359A35D735151".to_string(),
        )]))
    }

    #[test]
    fn test_encode_hashflow_single_fails_without_protocol_data() {
        // Hashflow requires a swap with protocol data, otherwise will return an error
        let hashflow_component = ProtocolComponent {
            id: String::from("hashflow-rfq"),
            protocol_system: String::from("rfq:hashflow"),
            ..Default::default()
        };

        let token_in = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // USDC
        let token_out = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"); // WETH

        let swap = Swap::new(hashflow_component, token_in.clone(), token_out.clone())
            .estimated_amount_in(BigUint::from_str("3000000000").unwrap());

        let encoding_context = EncodingContext {
            receiver: Bytes::from("0xc5564C13A157E6240659fb81882A28091add8670"),
            exact_out: false,
            router_address: Some(Bytes::zero(20)),
            group_token_in: token_in.clone(),
            group_token_out: token_out.clone(),
            transfer_type: TransferType::Transfer,
            historical_trade: false,
        };

        let encoder = HashflowSwapEncoder::new(
            Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
            Chain::Ethereum,
            hashflow_config(),
        )
        .unwrap();
        encoder
            .encode_swap(&swap, &encoding_context)
            .expect_err("Should returned an error if the swap has no protocol state");
    }

    #[test]
    fn test_encode_hashflow_single_with_protocol_state() {
        // 3000 USDC -> 1 WETH using a mocked RFQ state to get a quote
        let quote_amount_out = BigUint::from_str("1000000000000000000").unwrap();

        let hashflow_component = ProtocolComponent {
            id: String::from("hashflow-rfq"),
            protocol_system: String::from("rfq:hashflow"),
            ..Default::default()
        };
        let hashflow_quote_data = vec![
            (
                "pool".to_string(),
                Bytes::from_str("0x478eca1b93865dca0b9f325935eb123c8a4af011").unwrap(),
            ),
            (
                "external_account".to_string(),
                Bytes::from_str("0xbee3211ab312a8d065c4fef0247448e17a8da000").unwrap(),
            ),
            (
                "trader".to_string(),
                Bytes::from_str("0xcd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2").unwrap(),
            ),
            (
                "base_token".to_string(),
                Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
            ),
            (
                "quote_token".to_string(),
                Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap(),
            ),
            (
                "base_token_amount".to_string(),
                Bytes::from(biguint_to_u256(&BigUint::from(3000_u64)).to_be_bytes::<32>().to_vec()),
            ),
            (
                "quote_token_amount".to_string(),
                Bytes::from(biguint_to_u256(&BigUint::from(1_u64)).to_be_bytes::<32>().to_vec()),
            ),
            ("quote_expiry".to_string(), Bytes::from(biguint_to_u256(&BigUint::from(1755610328_u64)).to_be_bytes::<32>().to_vec())),
            ("nonce".to_string(), Bytes::from(biguint_to_u256(&BigUint::from(1755610283723_u64)).to_be_bytes::<32>().to_vec())),
            (
                "tx_id".to_string(),
                Bytes::from_str(
                    "0x125000064000640000001747eb8c38ffffffffffffff0029642016edb36d0000",
                )
                    .unwrap(),
            ),
            ("signature".to_string(), Bytes::from_str("0x6ddb3b21fe8509e274ddf46c55209cdbf30360944abbca6569ed6b26740d052f419964dcb5a3bdb98b4ed1fb3642a2760b8312118599a962251f7a8f73fe4fbe1c").unwrap()),
        ];
        let hashflow_quote_data_values =
            hashflow_quote_data
                .iter()
                .fold(vec![], |mut acc, (_key, value)| {
                    acc.extend_from_slice(value);
                    acc
                });
        let hashflow_calldata = Bytes::from(hashflow_quote_data_values);
        let hashflow_state = MockRFQState {
            quote_amount_out,
            quote_data: hashflow_quote_data
                .into_iter()
                .collect(),
        };

        let token_in = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // USDC
        let token_out = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"); // WETH

        let swap = Swap::new(hashflow_component, token_in.clone(), token_out.clone())
            .estimated_amount_in(BigUint::from_str("3000000000").unwrap())
            .protocol_state(Arc::new(hashflow_state));

        let encoding_context = EncodingContext {
            receiver: Bytes::from("0xc5564C13A157E6240659fb81882A28091add8670"),
            exact_out: false,
            router_address: Some(Bytes::zero(20)),
            group_token_in: token_in.clone(),
            group_token_out: token_out.clone(),
            transfer_type: TransferType::Transfer,
            historical_trade: false,
        };

        let encoder = HashflowSwapEncoder::new(
            Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
            Chain::Ethereum,
            hashflow_config(),
        )
        .unwrap();

        let encoded_swap = encoder
            .encode_swap(&swap, &encoding_context)
            .unwrap();
        let hex_swap = encode(&encoded_swap);

        let expected_swap = String::from(concat!(
            "01", // transfer type
            "01", // approval needed
        ));
        assert_eq!(hex_swap, expected_swap + &hashflow_calldata.to_string()[2..]);
    }
}

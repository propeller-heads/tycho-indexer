use std::str::FromStr;

use alloy::hex::decode;
use alloy_primitives::Address;
use alloy_sol_types::SolValue;
use tycho_core::Bytes;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        approvals::protocol_approvals_manager::ProtocolApprovalsManager, utils::bytes_to_address,
    },
    models::{EncodingContext, Swap},
    swap_encoder::SwapEncoder,
};

pub struct UniswapV2SwapEncoder {
    executor_address: String,
}

impl UniswapV2SwapEncoder {
    fn get_zero_to_one(sell_token_address: Address, buy_token_address: Address) -> bool {
        sell_token_address < buy_token_address
    }
}

impl SwapEncoder for UniswapV2SwapEncoder {
    fn new(executor_address: String) -> Self {
        Self { executor_address }
    }

    fn encode_swap(
        &self,
        swap: Swap,
        encoding_context: EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_in_address = bytes_to_address(&swap.token_in)?;
        let token_out_address = bytes_to_address(&swap.token_out)?;

        let zero_for_one = Self::get_zero_to_one(token_in_address, token_out_address);
        let protocol_id = Bytes::from(
            decode(
                swap.component
                    .id
                    .trim_start_matches("0x"),
            )
            .map_err(|_| {
                EncodingError::FatalError(format!(
                    "Failed to parse component id: {}",
                    swap.component.id
                ))
            })?,
        );

        // Sell token address is always needed to perform manual transfer from router into the pool,
        // since no optimizations are performed that send from one pool to the next
        let args = (
            token_in_address,
            bytes_to_address(&protocol_id)?,
            bytes_to_address(&encoding_context.receiver)?,
            zero_for_one,
            encoding_context.exact_out,
        );

        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &str {
        &self.executor_address
    }
}

pub struct BalancerV2SwapEncoder {
    executor_address: String,
    vault_address: Address,
}

impl SwapEncoder for BalancerV2SwapEncoder {
    fn new(executor_address: String) -> Self {
        Self {
            executor_address,
            vault_address: Address::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8")
                .expect("Invalid string for balancer vault address"),
        }
    }
    fn encode_swap(
        &self,
        swap: Swap,
        encoding_context: EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_approvals_manager = ProtocolApprovalsManager::new();
        let token = bytes_to_address(&swap.token_in)?;
        let router_address = bytes_to_address(&encoding_context.router_address)?;
        let approval_needed =
            token_approvals_manager.approval_needed(token, router_address, self.vault_address)?;
        // should we return gas estimation here too?? if there is an approval needed, gas will be
        // higher.
        let args = (
            bytes_to_address(&swap.token_in)?,
            bytes_to_address(&swap.token_out)?,
            swap.component.id,
            bytes_to_address(&encoding_context.receiver)?,
            encoding_context.exact_out,
            approval_needed,
        );
        Ok(args.abi_encode())
    }

    fn executor_address(&self) -> &str {
        &self.executor_address
    }
}

#[cfg(test)]
mod tests {
    use alloy::hex::encode;
    use tycho_core::{dto::ProtocolComponent, Bytes};

    use super::*;

    #[tokio::test]
    async fn test_encode_uniswap_v2() {
        let usv2_pool = ProtocolComponent {
            id: String::from("0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640"),
            ..Default::default()
        };
        let swap = Swap {
            component: usv2_pool,
            token_in: Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
            token_out: Bytes::from("0x6b175474e89094c44da98b954eedeac495271d0f"),
            split: 0f64,
        };
        let encoding_context = EncodingContext {
            receiver: Bytes::from("0x0000000000000000000000000000000000000001"),
            exact_out: false,
            router_address: Bytes::zero(20),
        };
        let encoder = super::UniswapV2SwapEncoder::new(String::from("0x"));
        let encoded_swap = encoder
            .encode_swap(swap, encoding_context)
            .unwrap();
        let hex_swap = encode(&encoded_swap);
        assert_eq!(
            hex_swap,
            String::from(concat!(
                // in token
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                // component id
                "88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
                // receiver
                "0000000000000000000000000000000000000001",
                // zero for one
                "00",
                // exact out
                "00",
            ))
        );
    }
}

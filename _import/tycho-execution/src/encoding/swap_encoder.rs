use alloy_primitives::Address;
use alloy_sol_types::SolValue;
use anyhow::Error;
use std::str::FromStr;
use tycho_core::Bytes;

use crate::encoding::utils::bytes_to_address;
use crate::encoding::{
    approvals_manager::{get_client, TokenApprovalsManager},
    models::{EncodingContext, Swap},
};

pub trait SwapEncoder: Sync + Send {
    fn encode_swap(&self, swap: Swap, encoding_context: EncodingContext) -> Result<Vec<u8>, Error>;
}

struct UniswapV2SwapEncoder {}

impl SwapEncoder for UniswapV2SwapEncoder {
    fn encode_swap(&self, swap: Swap, encoding_context: EncodingContext) -> Result<Vec<u8>, Error> {
        todo!()
    }
}

struct BalancerV2SwapEncoder {
    vault_address: Bytes,
}

impl BalancerV2SwapEncoder {
    pub fn new() -> Self {
        Self {
            vault_address: Bytes::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8")
                .expect("Invalid string for balancer vault address"),
        }
    }
}

impl SwapEncoder for BalancerV2SwapEncoder {
    fn encode_swap(&self, swap: Swap, encoding_context: EncodingContext) -> Result<Vec<u8>, Error> {
        let client = get_client();
        let token_approvals_manager = TokenApprovalsManager::new(client);
        let runtime = tokio::runtime::Handle::try_current()
            .is_err()
            .then(|| tokio::runtime::Runtime::new().unwrap())
            .unwrap();
        let approval_needed = runtime.block_on(async {
            token_approvals_manager
                .approval_needed(
                    swap.token_in.clone(),
                    encoding_context.router_address,
                    self.vault_address.clone(),
                )
                .await
        });
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
}

pub fn get_swap_encoder(protocol_system: &str) -> Box<dyn SwapEncoder> {
    match protocol_system {
        "uniswap_v2" => Box::new(UniswapV2SwapEncoder {}),
        "vm:balancer_v2" => Box::new(BalancerV2SwapEncoder::new()),
        _ => panic!("Unknown protocol system: {}", protocol_system),
    }
}

pub fn get_swap_executor_address(protocol_system: &str) -> Address {
    match protocol_system {
        "uniswap_v2" => Address::from_str("0x5C2F5a71f67c01775180ADc06909288B4C329308")
            .expect("Invalid address"),
        "vm:balancer_v2" => Address::from_str("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4")
            .expect("Invalid address"),
        _ => panic!("Unknown protocol system: {}", protocol_system),
    }
}

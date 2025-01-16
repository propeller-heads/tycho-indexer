use std::str::FromStr;

use alloy_primitives::Address;
use alloy_sol_types::SolValue;
use anyhow::Error;

use crate::encoding::{
    approvals::approvals_manager::ProtocolApprovalsManager,
    models::{EncodingContext, Swap},
    utils::bytes_to_address,
};

pub trait SwapEncoder: Sync + Send {
    fn new(executor_address: Address) -> Self
    where
        Self: Sized;
    fn encode_swap(&self, swap: Swap, encoding_context: EncodingContext) -> Result<Vec<u8>, Error>;
    fn executor_address(&self) -> Address;
}

pub struct UniswapV2SwapEncoder {
    executor_address: Address,
}

impl UniswapV2SwapEncoder {}
impl SwapEncoder for UniswapV2SwapEncoder {
    fn new(executor_address: Address) -> Self {
        Self { executor_address }
    }
    fn encode_swap(
        &self,
        _swap: Swap,
        _encoding_context: EncodingContext,
    ) -> Result<Vec<u8>, Error> {
        todo!()
    }

    fn executor_address(&self) -> Address {
        self.executor_address
    }
}

pub struct BalancerV2SwapEncoder {
    executor_address: Address,
    vault_address: Address,
}

impl SwapEncoder for BalancerV2SwapEncoder {
    fn new(executor_address: Address) -> Self {
        Self {
            executor_address,
            vault_address: Address::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8")
                .expect("Invalid string for balancer vault address"),
        }
    }
    fn encode_swap(&self, swap: Swap, encoding_context: EncodingContext) -> Result<Vec<u8>, Error> {
        let token_approvals_manager = ProtocolApprovalsManager::new();
        let runtime = tokio::runtime::Handle::try_current()
            .is_err()
            .then(|| tokio::runtime::Runtime::new().unwrap())
            .unwrap();
        let token = bytes_to_address(&swap.token_in)?;
        let router_address = bytes_to_address(&encoding_context.address_for_approvals)?;
        let approval_needed = runtime.block_on(async {
            token_approvals_manager
                .approval_needed(token, self.vault_address, router_address)
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

    fn executor_address(&self) -> Address {
        self.executor_address
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_encode_swap() {
        // Dummy test to make CI pass. Please implement me.
    }
}

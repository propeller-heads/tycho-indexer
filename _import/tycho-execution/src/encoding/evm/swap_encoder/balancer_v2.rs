use std::{collections::HashMap, str::FromStr};

use alloy::{
    primitives::{Address, Bytes as AlloyBytes},
    sol_types::SolValue,
};
use tycho_common::{models::Chain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::{
        approvals::protocol_approvals_manager::ProtocolApprovalsManager, utils::bytes_to_address,
    },
    models::{EncodingContext, Swap},
    swap_encoder::SwapEncoder,
};

/// Encodes a swap on a Balancer V2 pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
/// * `vault_address` - The address of the vault contract that will perform the swap.
#[derive(Clone)]
pub struct BalancerV2SwapEncoder {
    executor_address: Bytes,
    vault_address: Bytes,
}

impl SwapEncoder for BalancerV2SwapEncoder {
    fn new(
        executor_address: Bytes,
        _chain: Chain,
        config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        let config = config.ok_or(EncodingError::FatalError(
            "Missing balancer v2 specific addresses in config".to_string(),
        ))?;
        let vault_address = config
            .get("vault_address")
            .map(|s| {
                Bytes::from_str(s).map_err(|_| {
                    EncodingError::FatalError("Invalid balancer v2 vault address".to_string())
                })
            })
            .ok_or(EncodingError::FatalError(
                "Missing balancer v2 vault address in config".to_string(),
            ))
            .flatten()?;
        Ok(Self { executor_address, vault_address })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_approvals_manager = ProtocolApprovalsManager::new()?;
        let token = bytes_to_address(swap.token_in())?;
        let mut approval_needed: bool = true;

        if let Some(router_address) = &encoding_context.router_address {
            if !encoding_context.historical_trade {
                let tycho_router_address = bytes_to_address(router_address)?;
                approval_needed = token_approvals_manager.approval_needed(
                    token,
                    tycho_router_address,
                    Address::from_slice(&self.vault_address),
                )?;
            }
        };

        let component_id = AlloyBytes::from_str(&swap.component().id)
            .map_err(|_| EncodingError::FatalError("Invalid component ID".to_string()))?;

        let args = (
            bytes_to_address(swap.token_in())?,
            bytes_to_address(swap.token_out())?,
            component_id,
            bytes_to_address(&encoding_context.receiver)?,
            approval_needed,
            (encoding_context.transfer_type as u8).to_be_bytes(),
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
        evm::{swap_encoder::balancer_v2::BalancerV2SwapEncoder, utils::write_calldata_to_file},
        models::{Swap, TransferType},
    };
    #[test]
    fn test_encode_balancer_v2() {
        let balancer_pool = ProtocolComponent {
            id: String::from("0x5c6ee304399dbdb9c8ef030ab642b10820db8f56000200000000000000000014"),
            protocol_system: String::from("vm:balancer_v2"),
            ..Default::default()
        };
        let token_in = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
        let token_out = Bytes::from("0xba100000625a3754423978a60c9317c58a424e3D");
        let swap = Swap::new(balancer_pool, token_in.clone(), token_out.clone());
        let encoding_context = EncodingContext {
            // The receiver was generated with `makeAddr("bob*") using forge`
            receiver: Bytes::from("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de"),
            exact_out: false,
            router_address: Some(Bytes::zero(20)),
            group_token_in: token_in.clone(),
            group_token_out: token_out.clone(),
            transfer_type: TransferType::None,
            historical_trade: true,
        };
        let encoder = BalancerV2SwapEncoder::new(
            Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
            Chain::Ethereum,
            Some(HashMap::from([(
                "vault_address".to_string(),
                "0xba12222222228d8ba445958a75a0704d566bf2c8".to_string(),
            )])),
        )
        .unwrap();
        let encoded_swap = encoder
            .encode_swap(&swap, &encoding_context)
            .unwrap();
        let hex_swap = encode(&encoded_swap);

        assert_eq!(
            hex_swap,
            String::from(concat!(
                // token in
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                // token out
                "ba100000625a3754423978a60c9317c58a424e3d",
                // pool id
                "5c6ee304399dbdb9c8ef030ab642b10820db8f56000200000000000000000014",
                // receiver
                "9964bff29baa37b47604f3f3f51f3b3c5149d6de",
                // approval needed
                "01",
                // transfer type None
                "02"
            ))
        );
        write_calldata_to_file("test_encode_balancer_v2", hex_swap.as_str());
    }
}

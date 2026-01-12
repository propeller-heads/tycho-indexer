use std::collections::HashMap;

use alloy::sol_types::SolValue;
use tycho_common::{models::Chain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::{
        approvals::protocol_approvals_manager::ProtocolApprovalsManager, utils::bytes_to_address,
    },
    models::{EncodingContext, Swap},
    swap_encoder::SwapEncoder,
};

/// Encodes a swap on a Lido pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
#[derive(Clone)]
pub struct LidoSwapEncoder {
    executor_address: Bytes,
    st_eth_address: Bytes,
    wst_eth_address: Bytes,
    eth_address: Bytes,
}

#[repr(u8)]
enum LidoPool {
    StETH = 0,
    WStETH = 1,
}

#[repr(u8)]
enum LidoPoolDirection {
    Stake = 0,
    Wrap = 1,
    Unwrap = 2,
}

impl SwapEncoder for LidoSwapEncoder {
    fn new(
        executor_address: Bytes,
        chain: Chain,
        config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        let config =
            config.ok_or_else(|| EncodingError::FatalError("Lido config is empty".to_string()))?;

        let st_eth_address = config
            .get("st_eth_address")
            .map(|a| Bytes::from(a.as_str()))
            .ok_or_else(|| {
                EncodingError::FatalError("Missing st_eth_address in lido config".to_string())
            })?;

        let wst_eth_address = config
            .get("wst_eth_address")
            .map(|a| Bytes::from(a.as_str()))
            .ok_or_else(|| {
                EncodingError::FatalError("Missing wst_eth_address in lido config".to_string())
            })?;

        Ok(Self {
            executor_address,
            st_eth_address,
            wst_eth_address,
            eth_address: chain.native_token().address,
        })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let (pool, direction, approval_needed) =
            if *swap.token_in() == self.eth_address && *swap.token_out() == self.st_eth_address {
                (LidoPool::StETH, LidoPoolDirection::Stake, false)
            } else if *swap.token_in() == self.st_eth_address &&
                *swap.token_out() == self.wst_eth_address
            {
                let token_approvals_manager = ProtocolApprovalsManager::new()?;
                let token = bytes_to_address(&self.st_eth_address)?;
                let mut approval_needed: bool = true;

                if let Some(router_address) = &encoding_context.router_address {
                    if !encoding_context.historical_trade {
                        let tycho_router_address = bytes_to_address(router_address)?;
                        approval_needed = token_approvals_manager.approval_needed(
                            token,
                            tycho_router_address,
                            bytes_to_address(&self.wst_eth_address)?,
                        )?;
                    }
                }

                (LidoPool::WStETH, LidoPoolDirection::Wrap, approval_needed)
            } else if *swap.token_in() == self.wst_eth_address &&
                *swap.token_out() == self.st_eth_address
            {
                (LidoPool::WStETH, LidoPoolDirection::Unwrap, false)
            } else {
                return Err(EncodingError::InvalidInput("Combination not allowed".to_owned()))
            };

        let args = (
            bytes_to_address(&encoding_context.receiver)?,
            (encoding_context.transfer_type as u8).to_be_bytes(),
            (pool as u8).to_be_bytes(),
            (direction as u8).to_be_bytes(),
            approval_needed,
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
        evm::swap_encoder::lido::LidoSwapEncoder,
        models::{Swap, TransferType},
    };

    fn lido_config() -> HashMap<String, String> {
        HashMap::from([
            (
                "st_eth_address".to_string(),
                "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84".to_string(),
            ),
            (
                "wst_eth_address".to_string(),
                "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0".to_string(),
            ),
        ])
    }

    #[test]
    fn test_encode_lido_steth() {
        let lido_steth_pool = ProtocolComponent {
            id: String::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
            ..Default::default()
        };

        let token_in = Bytes::from("0x0000000000000000000000000000000000000000");
        let token_out = Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84");
        let swap = Swap::new(lido_steth_pool, token_in.clone(), token_out.clone());
        let encoding_context = EncodingContext {
            receiver: Bytes::from("0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e"), // BOB
            exact_out: false,
            router_address: Some(Bytes::zero(20)),
            group_token_in: token_in.clone(),
            group_token_out: token_out.clone(),
            transfer_type: TransferType::None,
            historical_trade: false,
        };
        let encoder = LidoSwapEncoder::new(
            Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
            Chain::Ethereum,
            Some(lido_config()),
        )
        .unwrap();
        let encoded_swap = encoder
            .encode_swap(&swap, &encoding_context)
            .unwrap();
        let hex_swap = encode(&encoded_swap);
        assert_eq!(
            hex_swap,
            String::from(concat!(
                // receiver
                "1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e",
                // transfer type Transfer
                "02",
                // pool
                "00",
                // direction
                "00",
                // approval_needed
                "00",
            ))
        );
    }

    #[test]
    fn test_encode_lido_wsteth_wrap() {
        let lido_wsteth_pool = ProtocolComponent {
            id: String::from("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"),
            ..Default::default()
        };

        let token_in = Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84");
        let token_out = Bytes::from("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0");
        let swap = Swap::new(lido_wsteth_pool, token_in.clone(), token_out.clone());
        let encoding_context = EncodingContext {
            receiver: Bytes::from("0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e"), // BOB
            exact_out: false,
            router_address: Some(Bytes::zero(20)),
            group_token_in: token_in.clone(),
            group_token_out: token_out.clone(),
            transfer_type: TransferType::None,
            historical_trade: false,
        };
        let encoder = LidoSwapEncoder::new(
            Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
            Chain::Ethereum,
            Some(lido_config()),
        )
        .unwrap();
        let encoded_swap = encoder
            .encode_swap(&swap, &encoding_context)
            .unwrap();
        let hex_swap = encode(&encoded_swap);
        assert_eq!(
            hex_swap,
            String::from(concat!(
                // receiver
                "1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e",
                // transfer type Transfer
                "02",
                // pool
                "01",
                // direction
                "01",
                // approval_needed
                "01",
            ))
        );
    }

    #[test]
    fn test_encode_lido_wsteth_unwrap() {
        let lido_wsteth_pool = ProtocolComponent {
            id: String::from("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"),
            ..Default::default()
        };

        let token_in = Bytes::from("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0");
        let token_out = Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84");
        let swap = Swap::new(lido_wsteth_pool, token_in.clone(), token_out.clone());
        let encoding_context = EncodingContext {
            receiver: Bytes::from("0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e"), // BOB
            exact_out: false,
            router_address: Some(Bytes::zero(20)),
            group_token_in: token_in.clone(),
            group_token_out: token_out.clone(),
            transfer_type: TransferType::None,
            historical_trade: false,
        };
        let encoder = LidoSwapEncoder::new(
            Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
            Chain::Ethereum,
            Some(lido_config()),
        )
        .unwrap();
        let encoded_swap = encoder
            .encode_swap(&swap, &encoding_context)
            .unwrap();
        let hex_swap = encode(&encoded_swap);
        assert_eq!(
            hex_swap,
            String::from(concat!(
                // receiver
                "1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e",
                // transfer type Transfer
                "02",
                // pool
                "01",
                // direction
                "02",
                // approval_needed
                "00",
            ))
        );
    }

    #[test]
    fn test_encode_lido_wrong_pool() {
        let lido_wsteth_pool = ProtocolComponent {
            id: String::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
            ..Default::default()
        };

        let token_in = Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84");
        let token_out = Bytes::from("0x0000000000000000000000000000000000000000");
        let swap = Swap::new(lido_wsteth_pool, token_in.clone(), token_out.clone());
        let encoding_context = EncodingContext {
            receiver: Bytes::from("0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e"), // BOB
            exact_out: false,
            router_address: Some(Bytes::zero(20)),
            group_token_in: token_in.clone(),
            group_token_out: token_out.clone(),
            transfer_type: TransferType::None,
            historical_trade: false,
        };
        let encoder = LidoSwapEncoder::new(
            Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
            Chain::Ethereum,
            Some(lido_config()),
        )
        .unwrap();

        let encoded_swap = encoder.encode_swap(&swap, &encoding_context);
        assert!(encoded_swap.is_err());
    }
}

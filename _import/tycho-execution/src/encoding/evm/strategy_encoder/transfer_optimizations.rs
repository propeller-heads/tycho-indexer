use std::str::FromStr;

use tycho_common::Bytes;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        constants::{CALLBACK_CONSTRAINED_PROTOCOLS, FUNDS_IN_ROUTER_PROTOCOLS},
        group_swaps::SwapGroup,
    },
    models::{TransferType, UserTransferType},
};

/// A struct that defines how the tokens will be transferred into the given pool given the solution.
#[derive(Clone)]
pub struct TransferOptimization {
    native_token: Bytes,
    wrapped_token: Bytes,
    user_transfer_type: UserTransferType,
    router_address: Bytes,
}

impl TransferOptimization {
    pub fn new(
        native_token: Bytes,
        wrapped_token: Bytes,
        user_transfer_type: UserTransferType,
        router_address: Bytes,
    ) -> Self {
        TransferOptimization { native_token, wrapped_token, user_transfer_type, router_address }
    }

    /// Returns the transfer type that should be used for the current transfer.
    pub fn get_transfers(
        &self,
        swap: &SwapGroup,
        given_token: &Bytes,
        wrap: bool,
        in_between_swap_optimization: bool,
    ) -> TransferType {
        let is_first_swap = swap.token_in == *given_token;
        let in_transfer_required: bool =
            !FUNDS_IN_ROUTER_PROTOCOLS.contains(&swap.protocol_system.as_str());

        if swap.token_in == self.native_token {
            // Funds are already in router. All protocols currently take care of native transfers.
            TransferType::None
        } else if (swap.token_in == self.wrapped_token) && wrap {
            // Wrapping already happened in the router so, we just do a normal transfer.
            TransferType::Transfer
        } else if is_first_swap {
            if in_transfer_required {
                if self.user_transfer_type == UserTransferType::None {
                    // Transfer from router to pool.
                    TransferType::Transfer
                } else {
                    // Transfer from swapper to pool
                    TransferType::TransferFrom
                }
            // in transfer is not necessary for these protocols. Only make a transfer from the
            // swapper to the router if the tokens are not already in the router
            } else if self.user_transfer_type != UserTransferType::None {
                // Transfer from swapper to router using.
                TransferType::TransferFrom
            } else {
                TransferType::None
            }
        // all other swaps that not the first one
        } else if !in_transfer_required || in_between_swap_optimization {
            // funds should already be in the router or in the next pool
            TransferType::None
        } else {
            TransferType::Transfer
        }
    }

    // Returns the optimized receiver of the swap. This is used to chain swaps together and avoid
    // unnecessary token transfers.
    // Returns the receiver address and a boolean indicating whether the receiver is optimized (this
    // is necessary for the next swap transfer type decision).
    pub fn get_receiver(
        &self,
        solution_receiver: &Bytes,
        next_swap: Option<&SwapGroup>,
        unwrap: bool,
    ) -> Result<(Bytes, bool), EncodingError> {
        if let Some(next) = next_swap {
            // if the protocol of the next swap supports transfer in optimization
            if !FUNDS_IN_ROUTER_PROTOCOLS.contains(&next.protocol_system.as_str()) {
                // if the protocol does not allow for chained swaps, we can't optimize the
                // receiver of this swap nor the transfer in of the next swap
                if CALLBACK_CONSTRAINED_PROTOCOLS.contains(&next.protocol_system.as_str()) {
                    Ok((self.router_address.clone(), false))
                } else {
                    Ok((
                        Bytes::from_str(&next.swaps[0].component().id.clone()).map_err(|_| {
                            EncodingError::FatalError("Invalid component id".to_string())
                        })?,
                        true,
                    ))
                }
            } else {
                // the protocol of the next swap does not support transfer in optimization
                Ok((self.router_address.clone(), false))
            }
        } else {
            // last swap - there is no next swap
            if unwrap {
                Ok((self.router_address.clone(), false))
            } else {
                Ok((solution_receiver.clone(), false))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::hex;
    use rstest::rstest;
    use tycho_common::models::protocol::ProtocolComponent;

    use super::*;
    use crate::encoding::models::Swap;

    fn weth() -> Bytes {
        Bytes::from(hex!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").to_vec())
    }

    fn eth() -> Bytes {
        Bytes::from(hex!("0000000000000000000000000000000000000000").to_vec())
    }

    fn dai() -> Bytes {
        Bytes::from(hex!("6b175474e89094c44da98b954eedeac495271d0f").to_vec())
    }

    fn usdc() -> Bytes {
        Bytes::from(hex!("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").to_vec())
    }

    fn router_address() -> Bytes {
        Bytes::from("0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f")
    }

    #[rstest]
    // First swap tests
    // WETH -(univ2)-> DAI we expect a transfer from the user to the protocol
    #[case(weth(), weth(), "uniswap_v2".to_string(), false, UserTransferType::TransferFrom,false, TransferType::TransferFrom)]
    // Native token swap. No transfer is needed
    #[case(eth(), eth(),  "uniswap_v2".to_string(),false, UserTransferType::TransferFrom,false, TransferType::None)]
    // ETH -(wrap)-> WETH -(univ2)-> DAI. Only a transfer from the router into the protocol is
    // needed
    #[case(eth(), weth(),  "uniswap_v2".to_string(),true, UserTransferType::TransferFrom,false,TransferType::Transfer)]
    // USDC -(univ2)-> DAI and the tokens are already in the router. Only a transfer from the router
    // to the protocol is needed
    #[case(usdc(), usdc(), "uniswap_v2".to_string(),false, UserTransferType::None,false, TransferType::Transfer)]
    // USDC -(curve)-> DAI and the tokens are already in the router. No transfer is needed
    #[case(usdc(), usdc(), "vm:curve".to_string(),false, UserTransferType::None, false,TransferType::None)]
    // other swaps tests
    // tokens need to be transferred into the pool
    #[case(weth(), usdc(), "uniswap_v2".to_string(), false, UserTransferType::TransferFrom,false, TransferType::Transfer)]
    // tokens are already in the pool (optimization)
    #[case(weth(), usdc(), "uniswap_v2".to_string(), false, UserTransferType::TransferFrom, true, TransferType::None)]
    // tokens are already in the router and don't need a transfer
    #[case(weth(), usdc(), "vm:curve".to_string(), false, UserTransferType::TransferFrom, false, TransferType::None)]
    fn test_get_transfers(
        #[case] given_token: Bytes,
        #[case] swap_token_in: Bytes,
        #[case] protocol: String,
        #[case] wrap: bool,
        #[case] user_transfer_type: UserTransferType,
        #[case] in_between_swap_optimization: bool,
        #[case] expected_transfer: TransferType,
    ) {
        // The swap token is the same as the given token, which is not the native token
        let swaps = vec![Swap::new(
            ProtocolComponent {
                protocol_system: "uniswap_v2".to_string(),
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                ..Default::default()
            },
            swap_token_in.clone(),
            dai(),
        )];
        let swap = SwapGroup {
            protocol_system: protocol,
            token_in: swap_token_in,
            token_out: dai(),
            split: 0f64,
            swaps,
        };
        let optimization =
            TransferOptimization::new(eth(), weth(), user_transfer_type, router_address());
        let transfer =
            optimization.get_transfers(&swap, &given_token, wrap, in_between_swap_optimization);
        assert_eq!(transfer, expected_transfer);
    }

    fn receiver() -> Bytes {
        Bytes::from("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2")
    }

    fn component_id() -> Bytes {
        Bytes::from("0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11")
    }

    #[rstest]
    // there is no next swap but there is an unwrap -> receiver is the router
    #[case(None, true, router_address(), false)]
    // there is no next swap and no unwrap -> receiver is the solution receiver
    #[case(None, false, receiver(), false)]
    // protocol of next swap supports transfer in optimization
    #[case(Some("uniswap_v2"), false, component_id(), true)]
    // protocol of next swap supports transfer in optimization but is callback constrained
    #[case(Some("uniswap_v3"), false, router_address(), false)]
    // protocol of next swap does not support transfer in optimization
    #[case(Some("vm:curve"), false, router_address(), false)]
    fn test_get_receiver(
        #[case] protocol: Option<&str>,
        #[case] unwrap: bool,
        #[case] expected_receiver: Bytes,
        #[case] expected_optimization: bool,
    ) {
        let optimization = TransferOptimization::new(
            eth(),
            weth(),
            UserTransferType::TransferFrom,
            router_address(),
        );

        let next_swap = if protocol.is_none() {
            None
        } else {
            Some(SwapGroup {
                protocol_system: protocol.unwrap().to_string(),
                token_in: usdc(),
                token_out: dai(),
                split: 0f64,
                swaps: vec![Swap::new(
                    ProtocolComponent {
                        protocol_system: protocol.unwrap().to_string(),
                        id: component_id().to_string(),
                        ..Default::default()
                    },
                    usdc(),
                    dai(),
                )],
            })
        };

        let result = optimization.get_receiver(&receiver(), next_swap.as_ref(), unwrap);

        assert!(result.is_ok());
        let (actual_receiver, optimization_flag) = result.unwrap();
        assert_eq!(actual_receiver, expected_receiver);
        assert_eq!(optimization_flag, expected_optimization);
    }
}

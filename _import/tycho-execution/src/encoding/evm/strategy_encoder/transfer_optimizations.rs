use std::str::FromStr;

use tycho_common::Bytes;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        constants::{CALLBACK_CONSTRAINED_PROTOCOLS, IN_TRANSFER_REQUIRED_PROTOCOLS},
        group_swaps::SwapGroup,
    },
    models::TransferType,
};

/// A struct that defines how the tokens will be transferred into the given pool given the solution.
#[derive(Clone)]
pub struct TransferOptimization {
    native_token: Bytes,
    wrapped_token: Bytes,
    permit2: bool,
    token_in_already_in_router: bool,
    router_address: Bytes,
}

impl TransferOptimization {
    pub fn new(
        native_token: Bytes,
        wrapped_token: Bytes,
        permit2: bool,
        token_in_already_in_router: bool,
        router_address: Bytes,
    ) -> Self {
        TransferOptimization {
            native_token,
            wrapped_token,
            permit2,
            token_in_already_in_router,
            router_address,
        }
    }

    /// Returns the transfer method that should be used for the given swap and solution.
    pub fn get_transfer_type(
        &self,
        swap: SwapGroup,
        given_token: Bytes,
        wrap: bool,
        in_between_swap_optimization: bool,
    ) -> TransferType {
        let in_transfer_required: bool =
            IN_TRANSFER_REQUIRED_PROTOCOLS.contains(&swap.protocol_system.as_str());

        let is_first_swap = swap.token_in == given_token;

        if swap.token_in == self.native_token {
            // Funds are already in router. All protocols currently take care of native transfers.
            TransferType::None
        } else if (swap.token_in == self.wrapped_token) && wrap {
            // Wrapping already happened in the router so we can just use a normal transfer.
            TransferType::TransferToProtocol
        } else if is_first_swap {
            if in_transfer_required {
                if self.token_in_already_in_router {
                    // Transfer from router to pool.
                    TransferType::TransferToProtocol
                } else if self.permit2 {
                    // Transfer from swapper to pool using permit2.
                    TransferType::TransferPermit2ToProtocol
                } else {
                    // Transfer from swapper to pool.
                    TransferType::TransferFromToProtocol
                }
                // in transfer is not necessary for these protocols. Only make a transfer if the
                // tokens are not already in the router
            } else if !self.token_in_already_in_router {
                if self.permit2 {
                    // Transfer from swapper to router using permit2.
                    TransferType::TransferPermit2ToRouter
                } else {
                    // Transfer from swapper to router.
                    TransferType::TransferFromToRouter
                }
            } else {
                TransferType::None
            }
        // all other swaps
        } else if !in_transfer_required || in_between_swap_optimization {
            // funds should already be in the router or in the next pool
            TransferType::None
        } else {
            TransferType::TransferToProtocol
        }
    }

    // Returns the optimized receiver of the swap. This is used to chain swaps together and avoid
    // unnecessary token transfers.
    // Returns the receiver address and a boolean indicating whether the receiver is optimized (this
    // is necessary for the next swap transfer type decision).
    pub fn get_receiver(
        &self,
        solution_receiver: Bytes,
        next_swap: Option<&SwapGroup>,
    ) -> Result<(Bytes, bool), EncodingError> {
        if let Some(next) = next_swap {
            // if the protocol of the next swap supports transfer in optimization
            if IN_TRANSFER_REQUIRED_PROTOCOLS.contains(&next.protocol_system.as_str()) {
                // if the protocol does not allow for chained swaps, we can't optimize the
                // receiver of this swap nor the transfer in of the next swap
                if CALLBACK_CONSTRAINED_PROTOCOLS.contains(&next.protocol_system.as_str()) {
                    Ok((self.router_address.clone(), false))
                } else {
                    Ok((
                        Bytes::from_str(&next.swaps[0].component.id.clone()).map_err(|_| {
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
            Ok((solution_receiver, false))
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::hex;
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

    #[test]
    fn test_first_swap_transfer_from_permit2() {
        // The swap token is the same as the given token, which is not the native token
        let swap = SwapGroup {
            protocol_system: "uniswap_v2".to_string(),
            token_in: weth(),
            token_out: dai(),
            split: 0f64,
            swaps: vec![],
        };
        let optimization = TransferOptimization::new(eth(), weth(), true, false, router_address());
        let transfer_method = optimization.get_transfer_type(swap.clone(), weth(), false, false);
        assert_eq!(transfer_method, TransferType::TransferPermit2ToProtocol);
    }

    #[test]
    fn test_first_swap_transfer_from() {
        // The swap token is the same as the given token, which is not the native token
        let swap = SwapGroup {
            protocol_system: "uniswap_v2".to_string(),
            token_in: weth(),
            token_out: dai(),
            split: 0f64,
            swaps: vec![],
        };
        let optimization = TransferOptimization::new(eth(), weth(), false, false, router_address());
        let transfer_method = optimization.get_transfer_type(swap.clone(), weth(), false, false);
        assert_eq!(transfer_method, TransferType::TransferFromToProtocol);
    }

    #[test]
    fn test_first_swap_native() {
        // The swap token is the same as the given token, and it's the native token.
        // No transfer action is needed.
        let swap = SwapGroup {
            protocol_system: "uniswap_v2".to_string(),
            token_in: eth(),
            token_out: dai(),
            split: 0f64,
            swaps: vec![],
        };
        let optimization = TransferOptimization::new(eth(), weth(), false, false, router_address());
        let transfer_method = optimization.get_transfer_type(swap.clone(), eth(), false, false);
        assert_eq!(transfer_method, TransferType::None);
    }

    #[test]
    fn test_first_swap_wrapped() {
        // The swap token is NOT the same as the given token, but we are wrapping.
        // Since the swap's token in is the wrapped token - this is the first swap.
        let swap = SwapGroup {
            protocol_system: "uniswap_v2".to_string(),
            token_in: weth(),
            token_out: dai(),
            split: 0f64,
            swaps: vec![],
        };
        let optimization = TransferOptimization::new(eth(), weth(), false, false, router_address());
        let transfer_method = optimization.get_transfer_type(swap.clone(), eth(), true, false);
        assert_eq!(transfer_method, TransferType::TransferToProtocol);
    }

    #[test]
    fn test_not_first_swap() {
        // The swap token is NOT the same as the given token, and we are NOT wrapping.
        // Thus, this is not the first swap.
        let swap = SwapGroup {
            protocol_system: "uniswap_v2".to_string(),
            token_in: usdc(),
            token_out: dai(),
            split: 0f64,
            swaps: vec![],
        };
        let optimization = TransferOptimization::new(eth(), weth(), false, false, router_address());
        let transfer_method = optimization.get_transfer_type(swap.clone(), weth(), false, false);
        assert_eq!(transfer_method, TransferType::TransferToProtocol);
    }

    #[test]
    fn test_not_first_swap_funds_in_router() {
        // Not the first swap and the protocol requires the funds to be in the router (which they
        // already are, so the transfer type is None)
        let swap = SwapGroup {
            protocol_system: "vm:curve".to_string(),
            token_in: usdc(),
            token_out: dai(),
            split: 0f64,
            swaps: vec![],
        };
        let optimization = TransferOptimization::new(eth(), weth(), false, false, router_address());
        let transfer_method = optimization.get_transfer_type(swap.clone(), weth(), false, false);
        assert_eq!(transfer_method, TransferType::None);
    }

    #[test]
    fn test_not_first_swap_in_between_swap_optimization() {
        // Not the first swap and the in between swaps are optimized. The funds should already be in
        // the next pool or in the router
        let swap = SwapGroup {
            protocol_system: "uniswap_v2".to_string(),
            token_in: usdc(),
            token_out: dai(),
            split: 0f64,
            swaps: vec![],
        };
        let optimization = TransferOptimization::new(eth(), weth(), false, false, router_address());
        let transfer_method = optimization.get_transfer_type(swap.clone(), weth(), false, true);
        assert_eq!(transfer_method, TransferType::None);
    }

    #[test]
    fn test_first_swap_tokens_already_in_router_optimization() {
        // It is the first swap, tokens are already in the router and the protocol requires the
        // transfer in
        let swap = SwapGroup {
            protocol_system: "uniswap_v2".to_string(),
            token_in: usdc(),
            token_out: dai(),
            split: 0f64,
            swaps: vec![],
        };
        let optimization = TransferOptimization::new(eth(), weth(), false, true, router_address());
        let transfer_method = optimization.get_transfer_type(swap.clone(), usdc(), false, false);
        assert_eq!(transfer_method, TransferType::TransferToProtocol);
    }

    #[test]
    fn test_first_swap_tokens_already_in_router_no_transfer_needed_optimization() {
        // It is the first swap, tokens are already in the router and the protocol does not require
        // the transfer in
        let swap = SwapGroup {
            protocol_system: "vm:curve".to_string(),
            token_in: usdc(),
            token_out: dai(),
            split: 0f64,
            swaps: vec![],
        };
        let optimization = TransferOptimization::new(eth(), weth(), false, true, router_address());
        let transfer_method = optimization.get_transfer_type(swap.clone(), usdc(), false, false);
        assert_eq!(transfer_method, TransferType::None);
    }

    fn receiver() -> Bytes {
        Bytes::from("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2")
    }

    fn component_id() -> Bytes {
        Bytes::from("0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11")
    }

    #[rstest]
    // there is no next swap -> receiver is the solution receiver
    #[case(None, receiver(), false)]
    // protocol of next swap supports transfer in optimization
    #[case(Some("uniswap_v2"), component_id(), true)]
    // protocol of next swap supports transfer in optimization but is callback constrained
    #[case(Some("uniswap_v3"), router_address(), false)]
    // protocol of next swap does not support transfer in optimization
    #[case(Some("vm:curve"), router_address(), false)]
    fn test_get_receiver(
        #[case] protocol: Option<&str>,
        #[case] expected_receiver: Bytes,
        #[case] expected_optimization: bool,
    ) {
        let optimization = TransferOptimization::new(eth(), weth(), false, false, router_address());

        let next_swap = if protocol.is_none() {
            None
        } else {
            Some(SwapGroup {
                protocol_system: protocol.unwrap().to_string(),
                token_in: usdc(),
                token_out: dai(),
                split: 0f64,
                swaps: vec![Swap {
                    component: ProtocolComponent {
                        protocol_system: protocol.unwrap().to_string(),
                        id: component_id().to_string(),
                        ..Default::default()
                    },
                    token_in: usdc(),
                    token_out: dai(),
                    split: 0f64,
                }],
            })
        };

        let result = optimization.get_receiver(receiver(), next_swap.as_ref());

        assert!(result.is_ok());
        let (actual_receiver, optimization_flag) = result.unwrap();
        assert_eq!(actual_receiver, expected_receiver);
        assert_eq!(optimization_flag, expected_optimization);
    }
}

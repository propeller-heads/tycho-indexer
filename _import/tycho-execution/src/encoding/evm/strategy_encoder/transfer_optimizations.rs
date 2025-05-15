use std::str::FromStr;

use tycho_common::Bytes;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        constants::{CALLBACK_CONSTRAINED_PROTOCOLS, IN_TRANSFER_REQUIRED_PROTOCOLS},
        group_swaps::SwapGroup,
    },
};

/// A struct that defines how the tokens will be transferred into the given pool given the solution.
#[derive(Clone)]
pub struct TransferOptimization {
    native_token: Bytes,
    wrapped_token: Bytes,
    token_in_already_in_router: bool,
    router_address: Bytes,
}

impl TransferOptimization {
    pub fn new(
        native_token: Bytes,
        wrapped_token: Bytes,
        token_in_already_in_router: bool,
        router_address: Bytes,
    ) -> Self {
        TransferOptimization {
            native_token,
            wrapped_token,
            token_in_already_in_router,
            router_address,
        }
    }

    /// Returns the information about the necessary transfers.
    /// Returns (bool, String, bool) where:
    /// * bool: true if a transfer from the user is needed, false otherwise (it might use regular
    ///   approvals or permit2)
    /// * String: the address to transfer from (if not needed it's the zero address)
    /// * bool: true if the tokens are already in the router and there only needs to be a transfer
    ///   from the router into the pool
    pub fn get_transfers(&self, swap: SwapGroup, wrap: bool) -> (bool, String, bool) {
        let zero_address = Bytes::from([0u8; 20]).to_string();
        let in_transfer_required: bool =
            IN_TRANSFER_REQUIRED_PROTOCOLS.contains(&swap.protocol_system.as_str());

        if swap.token_in == self.native_token {
            // Funds are already in router. All protocols currently take care of native transfers.
            (false, zero_address, false)
        } else if (swap.token_in == self.wrapped_token) && wrap {
            // Wrapping already happened in the router so, we just do a normal transfer.
            (false, zero_address, true)
        } else if in_transfer_required {
            if self.token_in_already_in_router {
                // Transfer from router to pool.
                (false, zero_address, true)
            } else {
                // Transfer from swapper to pool
                (true, swap.swaps[0].component.id.clone(), false)
            }
        // in transfer is not necessary for these protocols. Only make a transfer from the swapper
        // to the router if the tokens are not already in the router
        } else if !self.token_in_already_in_router {
            // Transfer from swapper to router using.
            (true, self.router_address.to_string(), false)
        } else {
            (false, zero_address, false)
        }
    }

    pub fn get_in_between_transfer(
        &self,
        protocol_system: &str,
        in_between_swap_optimization: bool,
    ) -> bool {
        let in_transfer_required: bool = IN_TRANSFER_REQUIRED_PROTOCOLS.contains(protocol_system);

        if !in_transfer_required || in_between_swap_optimization {
            // funds should already be in the router or in the next pool
            false
        } else {
            true
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

    fn zero_address() -> String {
        Bytes::from([0u8; 20]).to_string()
    }

    #[rstest]
    // WETH -(univ2)-> DAI we expect a transfer from the user to the protocol
    #[case(weth(), "uniswap_v2".to_string(), false, false, true, "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11", false)]
    // Native token swap. No transfer is needed
    #[case(eth(),  "uniswap_v2".to_string(),false, false, false, zero_address(), false)]
    // ETH -(wrap)-> WETH -(univ2)-> DAI. Only a transfer from the router into the protocol is
    // needed
    #[case(weth(),  "uniswap_v2".to_string(),true, false, false, zero_address(), true)]
    // USDC -(univ2)-> DAI and the tokens are already in the router. Only a transfer from the router
    // to the protocol is needed
    #[case(usdc(), "uniswap_v2".to_string(),false, true, false, zero_address(), true)]
    // USDC -(curve)-> DAI and the tokens are already in the router. No transfer is needed
    #[case(usdc(), "vm:curve".to_string(),false, true, false, zero_address(), false)]
    fn test_get_transfers(
        #[case] token_in: Bytes,
        #[case] protocol: String,
        #[case] wrap: bool,
        #[case] token_in_already_in_router: bool,
        #[case] expected_transfer_from: bool,
        #[case] expected_receiver: String,
        #[case] expected_transfer: bool,
    ) {
        // The swap token is the same as the given token, which is not the native token
        let swaps = vec![Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v2".to_string(),
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                ..Default::default()
            },
            token_in: token_in.clone(),
            token_out: dai(),
            split: 0f64,
        }];
        let swap =
            SwapGroup { protocol_system: protocol, token_in, token_out: dai(), split: 0f64, swaps };
        let optimization =
            TransferOptimization::new(eth(), weth(), token_in_already_in_router, router_address());
        let (transfer_from, receiver, transfer) = optimization.get_transfers(swap.clone(), wrap);
        assert_eq!(transfer_from, expected_transfer_from);
        assert_eq!(receiver, expected_receiver);
        assert_eq!(transfer, expected_transfer);
    }

    #[rstest]
    // tokens need to be transferred into the pool
    #[case("uniswap_v2", false, true)]
    // tokens are already in the pool (optimization)
    #[case("uniswap_v2", true, false)]
    // tokens are already in the router and don't need a transfer
    #[case("vm:curve", false, false)]
    fn test_get_in_between_transfers(
        #[case] protocol: &str,
        #[case] in_between_swap_optimization: bool,
        #[case] expected_transfer: bool,
    ) {
        let optimization = TransferOptimization::new(eth(), weth(), false, router_address());
        let transfer = optimization.get_in_between_transfer(protocol, in_between_swap_optimization);
        assert_eq!(transfer, expected_transfer);
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
        let optimization = TransferOptimization::new(eth(), weth(), false, router_address());

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

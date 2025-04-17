use tycho_common::Bytes;

use crate::encoding::{
    evm::constants::IN_TRANSFER_OPTIMIZABLE_PROTOCOLS,
    models::{Swap, TransferType},
};

/// A trait that defines how the tokens will be transferred into the given pool given the solution.
pub trait TransferOptimization {
    /// Returns the transfer method that should be used for the given swap and solution.
    #[allow(clippy::too_many_arguments)]
    fn get_transfer_type(
        &self,
        swap: Swap,
        given_token: Bytes,
        native_token: Bytes,
        wrapped_token: Bytes,
        permit2: bool,
        wrap: bool,
        in_between_swap_optimization: bool,
    ) -> TransferType {
        let in_transfer_optimizable: bool =
            IN_TRANSFER_OPTIMIZABLE_PROTOCOLS.contains(&swap.component.protocol_system.as_str());

        let is_first_swap = swap.token_in == given_token;

        if swap.token_in == native_token {
            // Funds are already in router. All protocols currently take care of native transfers.
            TransferType::None
        } else if (swap.token_in == wrapped_token) && wrap {
            // Wrapping already happened in the router so we can just use a normal transfer.
            TransferType::TransferToProtocol
        } else if is_first_swap {
            if in_transfer_optimizable {
                if permit2 {
                    // Transfer from swapper to pool using permit2.
                    TransferType::TransferPermit2ToProtocol
                } else {
                    // Transfer from swapper to pool.
                    TransferType::TransferFromToProtocol
                }
            } else if permit2 {
                // Transfer from swapper to router using permit2.
                TransferType::TransferPermit2ToRouter
            } else {
                // Transfer from swapper to router.
                TransferType::TransferFromToRouter
            }
        // all other swaps
        } else if !in_transfer_optimizable || in_between_swap_optimization {
            // funds should already be in the router or in the next pool
            TransferType::None
        } else {
            TransferType::TransferToProtocol
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::hex;
    use tycho_common::{models::protocol::ProtocolComponent, Bytes};

    use super::*;

    struct MockStrategy {}
    impl TransferOptimization for MockStrategy {}

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

    #[test]
    fn test_first_swap_transfer_from_permit2() {
        // The swap token is the same as the given token, which is not the native token
        let swap = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth(),
            token_out: dai(),
            split: 0f64,
        };
        let strategy = MockStrategy {};
        let transfer_method =
            strategy.get_transfer_type(swap.clone(), weth(), eth(), weth(), true, false, false);
        assert_eq!(transfer_method, TransferType::TransferPermit2ToProtocol);
    }

    #[test]
    fn test_first_swap_transfer_from() {
        // The swap token is the same as the given token, which is not the native token
        let swap = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth(),
            token_out: dai(),
            split: 0f64,
        };
        let strategy = MockStrategy {};
        let transfer_method =
            strategy.get_transfer_type(swap.clone(), weth(), eth(), weth(), false, false, false);
        assert_eq!(transfer_method, TransferType::TransferFromToProtocol);
    }

    #[test]
    fn test_first_swap_native() {
        // The swap token is the same as the given token, and it's the native token.
        // No transfer action is needed.
        let swap = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: eth(),
            token_out: dai(),
            split: 0f64,
        };
        let strategy = MockStrategy {};
        let transfer_method =
            strategy.get_transfer_type(swap.clone(), eth(), eth(), weth(), false, false, false);
        assert_eq!(transfer_method, TransferType::None);
    }

    #[test]
    fn test_first_swap_wrapped() {
        // The swap token is NOT the same as the given token, but we are wrapping.
        // Since the swap's token in is the wrapped token - this is the first swap.
        let swap = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth(),
            token_out: dai(),
            split: 0f64,
        };
        let strategy = MockStrategy {};
        let transfer_method =
            strategy.get_transfer_type(swap.clone(), eth(), eth(), weth(), false, true, false);
        assert_eq!(transfer_method, TransferType::TransferToProtocol);
    }

    #[test]
    fn test_not_first_swap() {
        // The swap token is NOT the same as the given token, and we are NOT wrapping.
        // Thus, this is not the first swap.
        let swap = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: usdc(),
            token_out: dai(),
            split: 0f64,
        };
        let strategy = MockStrategy {};
        let transfer_method =
            strategy.get_transfer_type(swap.clone(), weth(), eth(), weth(), false, false, false);
        assert_eq!(transfer_method, TransferType::TransferToProtocol);
    }

    #[test]
    fn test_not_first_swap_funds_in_router() {
        // Not the first swap and the protocol requires the funds to be in the router (which they
        // already are, so the transfer type is None)
        let swap = Swap {
            component: ProtocolComponent {
                protocol_system: "vm:curve".to_string(),
                ..Default::default()
            },
            token_in: usdc(),
            token_out: dai(),
            split: 0f64,
        };
        let strategy = MockStrategy {};
        let transfer_method =
            strategy.get_transfer_type(swap.clone(), weth(), eth(), weth(), false, false, false);
        assert_eq!(transfer_method, TransferType::None);
    }

    #[test]
    fn test_not_first_swap_in_between_swap_optimization() {
        // Not the first swap and the in between swaps are optimized. The funds should already be in
        // the next pool or in the router
        let swap = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: usdc(),
            token_out: dai(),
            split: 0f64,
        };
        let strategy = MockStrategy {};
        let transfer_method =
            strategy.get_transfer_type(swap.clone(), weth(), eth(), weth(), false, false, true);
        assert_eq!(transfer_method, TransferType::None);
    }
}

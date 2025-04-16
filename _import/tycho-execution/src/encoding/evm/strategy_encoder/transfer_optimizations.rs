use tycho_common::Bytes;

use crate::encoding::{
    evm::constants::{IN_TRANSFER_OPTIMIZABLE_PROTOCOLS, PROTOCOLS_EXPECTING_FUNDS_IN_ROUTER},
    models::{Swap, TransferType},
};

/// A trait that defines how the tokens will be transferred into the given pool given the solution.
pub trait TransferOptimization {
    /// Returns the transfer method that should be used for the given swap and solution.
    fn get_transfer_type(
        &self,
        swap: Swap,
        given_token: Bytes,
        native_token: Bytes,
        wrapped_token: Bytes,
        permit2: bool,
        wrap: bool,
    ) -> TransferType {
        let send_funds_to_pool: bool =
            IN_TRANSFER_OPTIMIZABLE_PROTOCOLS.contains(&swap.component.protocol_system.as_str());
        let funds_expected_in_router: bool =
            PROTOCOLS_EXPECTING_FUNDS_IN_ROUTER.contains(&swap.component.protocol_system.as_str());

        // In the case of wrapping, check if the swap's token in is the wrapped token to
        // determine if it's the first swap. Otherwise, compare to the given token.
        let is_first_swap = swap.token_in == given_token;

        if swap.token_in == native_token {
            // Funds are already in router. All protocols currently take care of native transfers.
            TransferType::None
        } else if (swap.token_in == wrapped_token) && wrap {
            TransferType::TransferToProtocol
        } else if is_first_swap && send_funds_to_pool {
            if permit2 {
                // Transfer from swapper to pool using permit2.
                TransferType::TransferPermit2ToProtocol
            } else {
                // Transfer from swapper to pool.
                TransferType::TransferFromToProtocol
            }
        } else if is_first_swap && funds_expected_in_router {
            if permit2 {
                // Transfer from swapper to router using permit2.
                TransferType::TransferPermit2ToRouter
            } else {
                // Transfer from swapper to router.
                TransferType::TransferFromToRouter
            }
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
            strategy.get_transfer_type(swap.clone(), weth(), eth(), weth(), true, false);
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
            strategy.get_transfer_type(swap.clone(), weth(), eth(), weth(), false, false);
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
            strategy.get_transfer_type(swap.clone(), eth(), eth(), weth(), false, false);
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
            strategy.get_transfer_type(swap.clone(), eth(), eth(), weth(), false, true);
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
            strategy.get_transfer_type(swap.clone(), weth(), eth(), weth(), false, false);
        assert_eq!(transfer_method, TransferType::TransferToProtocol);
    }
}

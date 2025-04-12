use tycho_common::Bytes;

use crate::encoding::{
    evm::constants::{IN_TRANSFER_OPTIMIZABLE_PROTOCOLS, PROTOCOLS_EXPECTING_FUNDS_IN_ROUTER},
    models::{Swap, TransferType},
};

/// A trait that defines how the tokens will be transferred into the given pool given the solution.
pub trait TransferOptimization {
    /// Returns the transfer method that should be used for the given swap and solution.
    fn get_transfer_method(
        &self,
        swap: Swap,
        given_token: Bytes,
        native_token: Bytes,
        permit2: bool,
    ) -> TransferType {
        let send_funds_to_pool: bool =
            IN_TRANSFER_OPTIMIZABLE_PROTOCOLS.contains(&swap.component.protocol_system.as_str());
        let funds_expected_in_router: bool =
            PROTOCOLS_EXPECTING_FUNDS_IN_ROUTER.contains(&swap.component.protocol_system.as_str());

        if (swap.token_in == given_token) && send_funds_to_pool {
            if swap.token_in == native_token {
                // Funds are already in router. Transfer from router to pool.
                TransferType::Transfer
            } else if permit2 {
                // Transfer from swapper to pool using permit2.
                TransferType::Permit2Transfer
            } else {
                // Transfer from swapper to pool.
                TransferType::TransferFrom
            }
        } else if (swap.token_in == given_token) && funds_expected_in_router {
            if swap.token_in == native_token {
                // Funds already in router. Do nothing.
                TransferType::None
            } else if permit2 {
                // Transfer from swapper to router using permit2.
                TransferType::Permit2TransferToRouter
            } else {
                // Transfer from swapper to router.
                TransferType::TransferToRouter
            }
        } else {
            TransferType::Transfer
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

    #[test]
    fn test_first_swap_transfer_from_permit2() {
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
        let transfer_method = strategy.get_transfer_method(swap.clone(), weth(), eth(), true);
        assert_eq!(transfer_method, TransferType::Permit2Transfer);
    }

    #[test]
    fn test_first_swap_transfer_from() {
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
        let transfer_method = strategy.get_transfer_method(swap.clone(), weth(), eth(), false);
        assert_eq!(transfer_method, TransferType::TransferFrom);
    }

    #[test]
    fn test_first_swap_transfer() {
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
        let transfer_method = strategy.get_transfer_method(swap.clone(), dai(), eth(), false);
        assert_eq!(transfer_method, TransferType::Transfer);
    }
}

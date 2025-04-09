use tycho_common::Bytes;

use crate::encoding::{
    evm::constants::IN_TRANSFER_OPTIMIZABLE_PROTOCOLS,
    models::{Swap, TransferType},
};

/// A trait that defines how the tokens will be transferred into the given pool given the solution.
pub trait TransferOptimization {
    /// Returns the transfer method that should be used for the given swap and solution.
    ///
    /// If the swap is for the in token of the solution and the protocol supports transferring
    /// straight from the user, it will return `TransferType::Permit2Transfer` or
    /// `TransferType::TransferFrom`.
    fn get_transfer_method(&self, swap: Swap, given_token: Bytes, permit2: bool) -> TransferType {
        let optimize_in_transfer =
            IN_TRANSFER_OPTIMIZABLE_PROTOCOLS.contains(&swap.component.protocol_system.as_str());
        if (swap.token_in == given_token) && optimize_in_transfer {
            if permit2 {
                TransferType::Permit2Transfer
            } else {
                TransferType::TransferFrom
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
        let transfer_method = strategy.get_transfer_method(swap.clone(), weth(), true);
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
        let transfer_method = strategy.get_transfer_method(swap.clone(), weth(), false);
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
        let transfer_method = strategy.get_transfer_method(swap.clone(), dai(), false);
        assert_eq!(transfer_method, TransferType::Transfer);
    }
}

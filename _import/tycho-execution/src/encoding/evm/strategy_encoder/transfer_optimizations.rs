use std::{env, str::FromStr};

use tycho_common::Bytes;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        constants::{CALLBACK_CONSTRAINED_PROTOCOLS, FUNDS_IN_ROUTER_PROTOCOLS},
        group_swaps::SwapGroup,
    },
    models::UserTransferType,
};

/// A struct that defines how the tokens will be transferred into the given pool given the solution.
#[derive(Clone)]
pub struct TransferOptimization {
    native_token: Bytes,
    user_transfer_type: UserTransferType,
    router_address: Bytes,
    tycho_fees_enabled: bool,
}

impl TransferOptimization {
    pub fn new(
        native_token: Bytes,
        user_transfer_type: UserTransferType,
        router_address: Bytes,
    ) -> Self {
        let tycho_fees_enabled: bool =
            env::var("TYCHO_FEES_ENABLED").unwrap_or("false".to_string()) == "true";

        TransferOptimization {
            native_token,
            user_transfer_type,
            router_address,
            tycho_fees_enabled,
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
        solution_fees: bool,
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
            if solution_fees || self.tycho_fees_enabled {
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

    fn receiver() -> Bytes {
        Bytes::from("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2")
    }

    fn component_id() -> Bytes {
        Bytes::from("0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11")
    }

    #[rstest]
    // there is no next swap -> receiver is the solution receiver
    #[case(None, receiver(), false, false)]
    // there is no next swap and there are fees -> receiver is the router
    #[case(None, router_address(), true, false)]
    // protocol of next swap supports transfer in optimization
    #[case(Some("uniswap_v2"), component_id(), false, true)]
    // protocol of next swap supports transfer in optimization but is callback constrained
    #[case(Some("uniswap_v3"), router_address(), false, false)]
    // protocol of next swap does not support transfer in optimization
    #[case(Some("vm:curve"), router_address(), false, false)]
    fn test_get_receiver(
        #[case] protocol: Option<&str>,
        #[case] expected_receiver: Bytes,
        #[case] solution_fees: bool,
        #[case] expected_optimization: bool,
    ) {
        let optimization =
            TransferOptimization::new(eth(), UserTransferType::TransferFrom, router_address());

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

        let result = optimization.get_receiver(&receiver(), next_swap.as_ref(), solution_fees);

        assert!(result.is_ok());
        let (actual_receiver, optimization_flag) = result.unwrap();
        assert_eq!(actual_receiver, expected_receiver);
        assert_eq!(optimization_flag, expected_optimization);
    }
}

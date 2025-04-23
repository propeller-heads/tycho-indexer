use tycho_common::Bytes;

use crate::encoding::{evm::constants::GROUPABLE_PROTOCOLS, models::Swap};

/// Represents a group of swaps that can be encoded into a single swap execution for gas
/// optimization.
///
/// # Fields
/// * `token_in`: Bytes, the input token of the first swap
/// * `token_out`: Bytes, the output token of the final swap
/// * `protocol_system`: String, the protocol system of the swaps
/// * `swaps`: Vec<Swap>, the sequence of swaps to be executed as a group
/// * `split`: f64, the split percentage of the first swap in the group
#[derive(Clone, PartialEq, Debug)]
pub struct SwapGroup {
    pub token_in: Bytes,
    pub token_out: Bytes,
    pub protocol_system: String,
    pub swaps: Vec<Swap>,
    pub split: f64,
}

/// Group consecutive swaps which can be encoded into one swap execution for gas optimization.
///
/// An example where this applies is the case of USV4, which uses a PoolManager contract
/// to save token transfers on consecutive swaps.
pub fn group_swaps(swaps: Vec<Swap>) -> Vec<SwapGroup> {
    let mut grouped_swaps: Vec<SwapGroup> = Vec::new();
    let mut current_group: Option<SwapGroup> = None;
    let mut last_swap_protocol = "".to_string();
    let mut groupable_protocol;
    let mut last_swap_out_token = Bytes::default();
    for swap in swaps {
        let current_swap_protocol = swap.component.protocol_system.clone();
        groupable_protocol = GROUPABLE_PROTOCOLS.contains(&current_swap_protocol.as_str());

        // Split 0 can also mean that the swap is the remaining part of a branch of splits,
        // so we need to check the last swap's out token as well
        let no_split = swap.split == 0.0 && swap.token_in == last_swap_out_token;

        if current_swap_protocol == last_swap_protocol && groupable_protocol && no_split {
            // Second or later groupable pool in a sequence of groupable pools. Merge to the
            // current group.
            if let Some(group) = current_group.as_mut() {
                group.swaps.push(swap.clone());
                // Update the output token of the current group.
                group.token_out = swap.token_out.clone();
            }
        } else {
            // Not second or later USV4 pool. Push the current group (if it exists) and then
            // create a new group.
            if let Some(group) = current_group.as_mut() {
                grouped_swaps.push(group.clone());
            }
            current_group = Some(SwapGroup {
                token_in: swap.token_in.clone(),
                token_out: swap.token_out.clone(),
                protocol_system: current_swap_protocol.clone(),
                swaps: vec![swap.clone()],
                split: swap.split,
            });
        }
        last_swap_protocol = current_swap_protocol;
        last_swap_out_token = swap.token_out.clone();
    }
    if let Some(group) = current_group.as_mut() {
        grouped_swaps.push(group.clone());
    }
    grouped_swaps
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy_primitives::hex;
    use tycho_common::{models::protocol::ProtocolComponent, Bytes};

    use super::*;
    use crate::encoding::models::Swap;

    fn weth() -> Bytes {
        Bytes::from(hex!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").to_vec())
    }

    #[test]
    fn test_group_swaps_simple() {
        // The first and second swaps can be grouped since there is no split, and they are
        // both USV4.
        //
        //   WETH ──(USV4)──> WBTC ───(USV4)──> USDC ───(USV2)──> DAI

        let weth = weth();
        let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let swap_weth_wbtc = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: wbtc.clone(),
            // This represents the remaining 50%, but to avoid any rounding errors we set this to
            // 0 to signify "the remainder of the WETH value". It should still be very close to 50%
            split: 0f64,
        };
        let swap_wbtc_usdc = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: wbtc.clone(),
            token_out: usdc.clone(),
            split: 0f64,
        };
        let swap_usdc_dai = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: usdc.clone(),
            token_out: dai.clone(),
            split: 0f64,
        };
        let grouped_swaps = group_swaps(vec![
            swap_weth_wbtc.clone(),
            swap_wbtc_usdc.clone(),
            swap_usdc_dai.clone(),
        ]);

        assert_eq!(
            grouped_swaps,
            vec![
                SwapGroup {
                    swaps: vec![swap_weth_wbtc, swap_wbtc_usdc],
                    token_in: weth,
                    token_out: usdc.clone(),
                    protocol_system: "uniswap_v4".to_string(),
                    split: 0f64,
                },
                SwapGroup {
                    swaps: vec![swap_usdc_dai],
                    token_in: usdc,
                    token_out: dai,
                    protocol_system: "uniswap_v2".to_string(),
                    split: 0f64,
                }
            ]
        );
    }

    #[test]
    fn test_group_swaps_complex_split() {
        // There is a split in the solution, but it's possible to combine two of the USV4 splits.
        // The WETH -> USDC swap cannot get grouped with anything, but the WETH -> DAI and
        // DAI -> USDC swaps can be grouped.
        //
        //                            ┌──(USV4)──> USDC
        //   WBTC ──> (USV4)──> WETH ─┤
        //                            └──(USV4)──> DAI ───(USV4)──> USDC

        let weth = weth();
        let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let swap_wbtc_weth = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: wbtc.clone(),
            token_out: weth.clone(),
            split: 0f64,
        };
        let swap_weth_usdc = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: usdc.clone(),
            split: 0.5f64,
        };
        let swap_weth_dai = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: dai.clone(),
            // This represents the remaining 50%, but to avoid any rounding errors we set this to
            // 0 to signify "the remainder of the WETH value". It should still be very close to 50%
            split: 0f64,
        };
        let swap_dai_usdc = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: dai.clone(),
            token_out: usdc.clone(),
            split: 0f64,
        };
        let grouped_swaps = group_swaps(vec![
            swap_wbtc_weth.clone(),
            swap_weth_usdc.clone(),
            swap_weth_dai.clone(),
            swap_dai_usdc.clone(),
        ]);

        assert_eq!(
            grouped_swaps,
            vec![
                SwapGroup {
                    swaps: vec![swap_wbtc_weth],
                    token_in: wbtc.clone(),
                    token_out: weth.clone(),
                    protocol_system: "uniswap_v4".to_string(),
                    split: 0f64,
                },
                SwapGroup {
                    swaps: vec![swap_weth_usdc],
                    token_in: weth.clone(),
                    token_out: usdc.clone(),
                    protocol_system: "uniswap_v4".to_string(),
                    split: 0.5f64,
                },
                SwapGroup {
                    swaps: vec![swap_weth_dai, swap_dai_usdc],
                    token_in: weth,
                    token_out: usdc,
                    protocol_system: "uniswap_v4".to_string(),
                    split: 0f64,
                }
            ]
        );
    }

    #[test]
    fn test_group_swaps_complex_split_multi_protocol() {
        // There is a split in the solution, but it's possible to group the USV4 splits with each
        // other and the Balancer V3 swaps with each other.
        //
        //         ┌──(BalancerV3)──> WBTC ──(BalancerV3)──> USDC
        //   WETH ─┤
        //         └──(USV4)──> DAI ───(USV4)──> USDC

        let weth = weth();
        let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let swap_weth_wbtc = Swap {
            component: ProtocolComponent {
                protocol_system: "vm:balancer_v3".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: wbtc.clone(),
            split: 0.5f64,
        };
        let swap_wbtc_usdc = Swap {
            component: ProtocolComponent {
                protocol_system: "vm:balancer_v3".to_string(),
                ..Default::default()
            },
            token_in: wbtc.clone(),
            token_out: usdc.clone(),
            split: 0f64,
        };
        let swap_weth_dai = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: dai.clone(),
            // This represents the remaining 50%, but to avoid any rounding errors we set this to
            // 0 to signify "the remainder of the WETH value". It should still be very close to 50%
            split: 0f64,
        };
        let swap_dai_usdc = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: dai.clone(),
            token_out: usdc.clone(),
            split: 0f64,
        };

        let grouped_swaps = group_swaps(vec![
            swap_weth_wbtc.clone(),
            swap_wbtc_usdc.clone(),
            swap_weth_dai.clone(),
            swap_dai_usdc.clone(),
        ]);

        assert_eq!(
            grouped_swaps,
            vec![
                SwapGroup {
                    swaps: vec![swap_weth_wbtc, swap_wbtc_usdc],
                    token_in: weth.clone(),
                    token_out: usdc.clone(),
                    protocol_system: "vm:balancer_v3".to_string(),
                    split: 0.5f64,
                },
                SwapGroup {
                    swaps: vec![swap_weth_dai, swap_dai_usdc],
                    token_in: weth,
                    token_out: usdc,
                    protocol_system: "uniswap_v4".to_string(),
                    split: 0f64,
                }
            ]
        );
    }
}

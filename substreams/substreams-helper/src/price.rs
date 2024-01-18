use std::ops::Div;

use hex_literal::hex;
use substreams::scalar::BigDecimal;

use crate::{abi, math, types};

const CONFIG: Config = Config {
    ethereum: NetworkConfig {
        yearn_lens_oracle: hex!("83d95e0d5f402511db06817aff3f9ea88224b030"),
        yearn_lens_oracle_start_block: 12242339,
        chainlink_feed_registry: hex!("47fb2585d2c56fe188d0e6ec628a38b74fceeedf"),
        chainlink_feed_registry_start_block: 12864088,
        curve_calculations: hex!("25BF7b72815476Dd515044F9650Bf79bAd0Df655"),
        curve_calculations_start_block: 12370088,
        sushiswap_calculations: hex!("8263e161a855b644f582d9c164c66aabee53f927"),
        sushiswap_calculations_start_block: 12692284,
        usdc_decimals: 6,
        usd_denominations: hex!("0000000000000000000000000000000000000348"),
    },
};

/// Price lib config for all supported networks
struct Config {
    ethereum: NetworkConfig,
}

/// Price lib config for each supported network
struct NetworkConfig {
    yearn_lens_oracle: [u8; 20],
    yearn_lens_oracle_start_block: u64,
    chainlink_feed_registry: [u8; 20],
    chainlink_feed_registry_start_block: u64,
    curve_calculations: [u8; 20],
    curve_calculations_start_block: u64,
    sushiswap_calculations: [u8; 20],
    sushiswap_calculations_start_block: u64,
    usdc_decimals: u8,
    usd_denominations: [u8; 20],
}

pub fn get_price(
    network: types::Network,
    block_number: u64,
    token_address: Vec<u8>,
) -> Result<BigDecimal, String> {
    let network_config = match network {
        types::Network::Ethereum => CONFIG.ethereum,
    };

    via_yearn_lens_oracle(&network_config, block_number, token_address.clone())
        .or_else(|| {
            via_chainlink_feed_registry(&network_config, block_number, token_address.clone())
        })
        .or_else(|| via_curve_calculations(&network_config, block_number, token_address.clone()))
        .or_else(|| {
            via_sushiswap_calculations(&network_config, block_number, token_address.clone())
        })
        .ok_or("price error".to_string())
}

fn via_yearn_lens_oracle(
    network_config: &NetworkConfig,
    block_number: u64,
    token_address: Vec<u8>,
) -> Option<BigDecimal> {
    if block_number < network_config.yearn_lens_oracle_start_block {
        None
    } else {
        abi::yearn_lens_oracle::functions::GetPriceUsdcRecommended { token_address }
            .call(network_config.yearn_lens_oracle.to_vec())
            .map(|price_mantissa| {
                math::decimal_from_str(price_mantissa.to_string().as_str())
                    .unwrap()
                    .div(math::exponent_to_big_decimal(network_config.usdc_decimals))
            })
    }
}

/// Reference: https://docs.chain.link/docs/feed-registry
fn via_chainlink_feed_registry(
    network_config: &NetworkConfig,
    block_number: u64,
    token_address: Vec<u8>,
) -> Option<BigDecimal> {
    if block_number < network_config.chainlink_feed_registry_start_block {
        None
    } else {
        let price_mantissa_res = abi::chainlink_feed_registry::functions::LatestRoundData {
            base: token_address.clone(),
            quote: network_config.usd_denominations.to_vec(),
        }
        .call(network_config.chainlink_feed_registry.to_vec());
        let decimals_res = abi::chainlink_feed_registry::functions::Decimals {
            base: token_address,
            quote: network_config.usd_denominations.to_vec(),
        }
        .call(network_config.chainlink_feed_registry.to_vec());

        if let (Some(price_mantissa), Some(decimals)) = (price_mantissa_res, decimals_res) {
            Some(price_mantissa.1.to_decimal(decimals.to_u64()))
        } else {
            None
        }
    }
}

fn via_curve_calculations(
    network_config: &NetworkConfig,
    block_number: u64,
    token_address: Vec<u8>,
) -> Option<BigDecimal> {
    if block_number < network_config.curve_calculations_start_block {
        None
    } else {
        abi::curve_calculations::functions::GetCurvePriceUsdc {
            curve_lp_token_address: token_address,
        }
        .call(network_config.curve_calculations.to_vec())
        .map(|price_mantissa| {
            math::decimal_from_str(price_mantissa.to_string().as_str())
                .unwrap_or(BigDecimal::zero())
                .div(math::exponent_to_big_decimal(network_config.usdc_decimals))
        })
    }
}

fn via_sushiswap_calculations(
    network_config: &NetworkConfig,
    block_number: u64,
    token_address: Vec<u8>,
) -> Option<BigDecimal> {
    if block_number < network_config.sushiswap_calculations_start_block {
        None
    } else {
        abi::sushiswap_calculations::functions::GetPriceUsdc { token_address }
            .call(network_config.sushiswap_calculations.to_vec())
            .map(|price_mantissa| {
                math::decimal_from_str(price_mantissa.to_string().as_str())
                    .unwrap_or(BigDecimal::zero())
                    .div(math::exponent_to_big_decimal(network_config.usdc_decimals))
            })
    }
}

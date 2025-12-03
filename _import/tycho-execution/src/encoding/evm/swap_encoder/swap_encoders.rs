use std::{collections::HashMap, str::FromStr, sync::Arc};

use alloy::{
    primitives::{Address, Bytes as AlloyBytes, U8},
    sol_types::SolValue,
};
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use tokio::{
    runtime::{Handle, Runtime},
    task::block_in_place,
};
use tycho_common::{
    models::{protocol::GetAmountOutParams, Chain},
    Bytes,
};

use crate::encoding::{
    errors::EncodingError,
    evm::{
        approvals::protocol_approvals_manager::ProtocolApprovalsManager,
        constants::ANGSTROM_DEFAULT_BLOCKS_IN_FUTURE,
        utils::{
            biguint_to_u256, bytes_to_address, get_runtime, get_static_attribute,
            pad_or_truncate_to_size,
        },
    },
    models::{EncodingContext, Swap},
    swap_encoder::SwapEncoder,
};

/// Encodes a swap on a Uniswap V2 pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
#[derive(Clone)]
pub struct UniswapV2SwapEncoder {
    executor_address: Bytes,
}

impl UniswapV2SwapEncoder {
    fn get_zero_to_one(sell_token_address: Address, buy_token_address: Address) -> bool {
        sell_token_address < buy_token_address
    }
}

impl SwapEncoder for UniswapV2SwapEncoder {
    fn new(
        executor_address: Bytes,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self { executor_address })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_in_address = bytes_to_address(&swap.token_in)?;
        let token_out_address = bytes_to_address(&swap.token_out)?;

        let zero_to_one = Self::get_zero_to_one(token_in_address, token_out_address);
        let component_id = Address::from_str(&swap.component.id)
            .map_err(|_| EncodingError::FatalError("Invalid USV2 component id".to_string()))?;

        // Token in address is always needed to perform a manual transfer from the router,
        // since no optimizations are performed that send from one pool to the next
        let args = (
            token_in_address,
            component_id,
            bytes_to_address(&encoding_context.receiver)?,
            zero_to_one,
            (encoding_context.transfer_type as u8).to_be_bytes(),
        );

        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }

    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

/// Encodes a swap on a Uniswap V3 pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
#[derive(Clone)]
pub struct UniswapV3SwapEncoder {
    executor_address: Bytes,
}

impl UniswapV3SwapEncoder {
    fn get_zero_to_one(sell_token_address: Address, buy_token_address: Address) -> bool {
        sell_token_address < buy_token_address
    }
}

impl SwapEncoder for UniswapV3SwapEncoder {
    fn new(
        executor_address: Bytes,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self { executor_address })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_in_address = bytes_to_address(&swap.token_in)?;
        let token_out_address = bytes_to_address(&swap.token_out)?;

        let zero_to_one = Self::get_zero_to_one(token_in_address, token_out_address);
        let component_id = Address::from_str(&swap.component.id)
            .map_err(|_| EncodingError::FatalError("Invalid USV3 component id".to_string()))?;
        let pool_fee_bytes = get_static_attribute(swap, "fee")?;

        let pool_fee_u24 = pad_or_truncate_to_size::<3>(&pool_fee_bytes)
            .map_err(|_| EncodingError::FatalError("Failed to extract fee bytes".to_string()))?;

        let args = (
            token_in_address,
            token_out_address,
            pool_fee_u24,
            bytes_to_address(&encoding_context.receiver)?,
            component_id,
            zero_to_one,
            (encoding_context.transfer_type as u8).to_be_bytes(),
        );

        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }
    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

/// Encodes a swap on a Uniswap V4 pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
#[derive(Clone)]
pub struct UniswapV4SwapEncoder {
    executor_address: Bytes,
    angstrom_hook_address: Bytes,
}

impl UniswapV4SwapEncoder {
    fn get_zero_to_one(sell_token_address: Address, buy_token_address: Address) -> bool {
        sell_token_address < buy_token_address
    }

    /// Fetches attestations from the Angstrom API (blocking)
    fn fetch_angstrom_attestations() -> Result<AttestationResponse, EncodingError> {
        let client = reqwest::blocking::Client::new();

        let api_url = std::env::var("ANGSTROM_API_URL")
            .unwrap_or("https://attestations.angstrom.xyz/getAttestations".to_string());

        let api_key = std::env::var("ANGSTROM_API_KEY").map_err(|_| {
            EncodingError::FatalError(
                "ANGSTROM_API_KEY environment variable is required for Angstrom swaps".to_string(),
            )
        })?;
        let blocks_in_future = std::env::var("ANGSTROM_BLOCKS_IN_FUTURE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(ANGSTROM_DEFAULT_BLOCKS_IN_FUTURE);

        let request_body = serde_json::json!({
            "blocks_in_future": blocks_in_future
        });

        let response = client
            .post(&api_url)
            .header("accept", "application/json")
            .header("X-Api-Key", api_key)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .map_err(|e| {
                EncodingError::FatalError(format!("Failed to fetch attestations: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(EncodingError::FatalError(format!(
                "Angstrom API request failed with status {}: {}",
                status, error_text
            )));
        }

        let attestation_response: AttestationResponse = response.json().map_err(|e| {
            EncodingError::FatalError(format!("Failed to parse attestation response: {}", e))
        })?;

        if !attestation_response.success {
            return Err(EncodingError::FatalError(
                "Angstrom API returned success=false".to_string(),
            ));
        }

        Ok(attestation_response)
    }

    /// Encodes attestations into bytes
    ///
    /// Uses fixed-length format: each attestation is exactly 93 bytes
    /// (8 bytes block number + 85 bytes attestation)
    fn encode_angstrom_attestations(
        attestations: &AttestationResponse,
    ) -> Result<Vec<u8>, EncodingError> {
        let mut encoded = Vec::new();
        for att_data in &attestations.attestations {
            // Encode block number (first 8 bytes)
            encoded.extend_from_slice(&att_data.block_number.to_be_bytes());

            let attestation_hex = att_data
                .attestation
                .strip_prefix("0x")
                .unwrap_or(&att_data.attestation);

            let attestation_bytes = hex::decode(attestation_hex).map_err(|e| {
                EncodingError::FatalError(format!("Failed to decode attestation hex: {}", e))
            })?;

            // Encode attestation data for block (next 85 bytes)
            encoded.extend_from_slice(&attestation_bytes);
        }

        Ok(encoded)
    }
}

impl SwapEncoder for UniswapV4SwapEncoder {
    fn new(
        executor_address: Bytes,
        _chain: Chain,
        config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        let angstrom_hook_address = match config {
            // Allow for no config, since Angstrom is not on every chain
            None => Bytes::new(),
            Some(cfg) => cfg
                .get("angstrom_hook_address")
                .map_or(Ok(Bytes::new()), |s| {
                    Bytes::from_str(s).map_err(|_| {
                        EncodingError::FatalError("Invalid Angstrom hook address".to_string())
                    })
                })?,
        };
        Ok(Self { executor_address, angstrom_hook_address })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let fee = get_static_attribute(swap, "key_lp_fee")?;

        let pool_fee_u24 = pad_or_truncate_to_size::<3>(&fee)
            .map_err(|_| EncodingError::FatalError("Failed to pad fee bytes".to_string()))?;

        let tick_spacing = get_static_attribute(swap, "tick_spacing")?;

        let pool_tick_spacing_u24 = pad_or_truncate_to_size::<3>(&tick_spacing).map_err(|_| {
            EncodingError::FatalError("Failed to pad tick spacing bytes".to_string())
        })?;

        let hook_address = match get_static_attribute(swap, "hooks") {
            Ok(hook) => Address::from_slice(&hook),
            Err(_) => Address::ZERO,
        };

        let is_angstrom_hook = **hook_address == *self.angstrom_hook_address;
        let hook_data = if is_angstrom_hook {
            // Angstrom hook - obtain hook data from API
            // Use block_in_place to avoid runtime dropping issues when called from async context
            let attestations = tokio::task::block_in_place(|| Self::fetch_angstrom_attestations())?;
            Self::encode_angstrom_attestations(&attestations)?
        } else {
            // Regular hook - use user_data as normal
            swap.user_data
                .clone()
                .unwrap_or_default()
                .to_vec()
        };

        let hook_data_length = (hook_data.len() as u16).to_be_bytes();

        // Early check if this is not the first swap
        if encoding_context.group_token_in != swap.token_in {
            return Ok((
                bytes_to_address(&swap.token_out)?,
                pool_fee_u24,
                pool_tick_spacing_u24,
                hook_address,
                hook_data_length,
                AlloyBytes::from(hook_data),
            )
                .abi_encode_packed());
        }

        // This is the first swap, compute all necessary values
        let token_in_address = bytes_to_address(&swap.token_in)?;
        let token_out_address = bytes_to_address(&swap.token_out)?;
        let group_token_in_address = bytes_to_address(&encoding_context.group_token_in)?;
        let group_token_out_address = bytes_to_address(&encoding_context.group_token_out)?;

        let zero_to_one = Self::get_zero_to_one(token_in_address, token_out_address);

        let pool_params = (
            token_out_address,
            pool_fee_u24,
            pool_tick_spacing_u24,
            hook_address,
            hook_data_length,
            AlloyBytes::from(hook_data),
        )
            .abi_encode_packed();

        let args = (
            group_token_in_address,
            group_token_out_address,
            zero_to_one,
            (encoding_context.transfer_type as u8).to_be_bytes(),
            bytes_to_address(&encoding_context.receiver)?,
            pool_params,
        );

        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }

    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

/// Attestation data for Angstrom swaps
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttestationData {
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
    #[serde(rename = "unlockData")]
    pub attestation: String,
}

/// Response from Angstrom attestation API
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttestationResponse {
    pub success: bool,
    pub attestations: Vec<AttestationData>,
}

/// Encodes a swap on a Balancer V2 pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
/// * `vault_address` - The address of the vault contract that will perform the swap.
#[derive(Clone)]
pub struct BalancerV2SwapEncoder {
    executor_address: Bytes,
    vault_address: Bytes,
}

impl SwapEncoder for BalancerV2SwapEncoder {
    fn new(
        executor_address: Bytes,
        _chain: Chain,
        config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        let config = config.ok_or(EncodingError::FatalError(
            "Missing balancer v2 specific addresses in config".to_string(),
        ))?;
        let vault_address = config
            .get("vault_address")
            .map(|s| {
                Bytes::from_str(s).map_err(|_| {
                    EncodingError::FatalError("Invalid balancer v2 vault address".to_string())
                })
            })
            .ok_or(EncodingError::FatalError(
                "Missing balancer v2 vault address in config".to_string(),
            ))
            .flatten()?;
        Ok(Self { executor_address, vault_address })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_approvals_manager = ProtocolApprovalsManager::new()?;
        let token = bytes_to_address(&swap.token_in)?;
        let mut approval_needed: bool = true;

        if let Some(router_address) = &encoding_context.router_address {
            if !encoding_context.historical_trade {
                let tycho_router_address = bytes_to_address(router_address)?;
                approval_needed = token_approvals_manager.approval_needed(
                    token,
                    tycho_router_address,
                    Address::from_slice(&self.vault_address),
                )?;
            }
        };

        let component_id = AlloyBytes::from_str(&swap.component.id)
            .map_err(|_| EncodingError::FatalError("Invalid component ID".to_string()))?;

        let args = (
            bytes_to_address(&swap.token_in)?,
            bytes_to_address(&swap.token_out)?,
            component_id,
            bytes_to_address(&encoding_context.receiver)?,
            approval_needed,
            (encoding_context.transfer_type as u8).to_be_bytes(),
        );
        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }
    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

/// Encodes a swap on an Ekubo pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EkuboSwapEncoder {
    executor_address: Bytes,
}

impl SwapEncoder for EkuboSwapEncoder {
    fn new(
        executor_address: Bytes,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self { executor_address })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        if encoding_context.exact_out {
            return Err(EncodingError::InvalidInput("exact out swaps not implemented".to_string()));
        }

        let fee = u64::from_be_bytes(
            get_static_attribute(swap, "fee")?
                .try_into()
                .map_err(|_| EncodingError::FatalError("fee should be an u64".to_string()))?,
        );

        let tick_spacing = u32::from_be_bytes(
            get_static_attribute(swap, "tick_spacing")?
                .try_into()
                .map_err(|_| {
                    EncodingError::FatalError("tick_spacing should be an u32".to_string())
                })?,
        );

        let extension: Address = get_static_attribute(swap, "extension")?
            .as_slice()
            .try_into()
            .map_err(|_| EncodingError::FatalError("extension should be an address".to_string()))?;

        let mut encoded = vec![];

        if encoding_context.group_token_in == swap.token_in {
            encoded.extend((encoding_context.transfer_type as u8).to_be_bytes());
            encoded.extend(bytes_to_address(&encoding_context.receiver)?);
            encoded.extend(bytes_to_address(&swap.token_in)?);
        }

        encoded.extend(bytes_to_address(&swap.token_out)?);
        encoded.extend((extension, fee, tick_spacing).abi_encode_packed());

        Ok(encoded)
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }

    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

/// Encodes a swap on a Curve pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
/// * `meta_registry_address` - The address of the Curve meta registry contract. Used to get coin
///   indexes.
/// * `native_token_curve_address` - The address used as native token in curve pools.
/// * `native_token_address` - The address of the native token.
#[derive(Clone)]
pub struct CurveSwapEncoder {
    executor_address: Bytes,
    native_token_curve_address: Bytes,
    native_token_address: Bytes,
    wrapped_native_token_address: Bytes,
}

impl CurveSwapEncoder {
    fn get_pool_type(&self, pool_id: &str, factory_address: &str) -> Result<U8, EncodingError> {
        match pool_id {
            // TriPool
            "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7" => Ok(U8::from(1)),
            // STETHPool
            "0xDC24316b9AE028F1497c275EB9192a3Ea0f67022" => Ok(U8::from(1)),
            // TriCryptoPool
            "0xD51a44d3FaE010294C616388b506AcdA1bfAAE46" => Ok(U8::from(3)),
            // SUSDPool
            "0xA5407eAE9Ba41422680e2e00537571bcC53efBfD" => Ok(U8::from(1)),
            // FRAXUSDCPool
            "0xDcEF968d416a41Cdac0ED8702fAC8128A64241A2" => Ok(U8::from(1)),
            _ => match factory_address {
                // CryptoSwapNG factory
                "0x6A8cbed756804B16E05E741eDaBd5cB544AE21bf" => Ok(U8::from(1)),
                // Metapool factory
                "0xB9fC157394Af804a3578134A6585C0dc9cc990d4" => Ok(U8::from(1)),
                // CryptoPool factory
                "0xF18056Bbd320E96A48e3Fbf8bC061322531aac99" => Ok(U8::from(2)),
                // Tricrypto factory
                "0x0c0e5f2fF0ff18a3be9b835635039256dC4B4963" => Ok(U8::from(3)),
                // Twocrypto factory
                "0x98EE851a00abeE0d95D08cF4CA2BdCE32aeaAF7F" => Ok(U8::from(2)),
                // StableSwap factory
                "0x4F8846Ae9380B90d2E71D5e3D042dff3E7ebb40d" => Ok(U8::from(1)),
                _ => Err(EncodingError::FatalError(format!(
                    "Unsupported curve factory address: {factory_address}"
                ))),
            },
        }
    }

    // Some curve pools support both ETH and WETH as tokens.
    // They do the wrapping/unwrapping inside the pool
    fn normalize_token(&self, token: Address, coins: &[Address]) -> Result<Address, EncodingError> {
        let native_token_address = Address::from_slice(&self.native_token_curve_address);
        let wrapped_native_token_address = bytes_to_address(&self.wrapped_native_token_address)?;
        if token == native_token_address && !coins.contains(&token) {
            Ok(wrapped_native_token_address)
        } else if token == wrapped_native_token_address && !coins.contains(&token) {
            Ok(native_token_address)
        } else {
            Ok(token)
        }
    }

    fn get_coin_indexes(
        &self,
        swap: &Swap,
        token_in: Address,
        token_out: Address,
    ) -> Result<(U8, U8), EncodingError> {
        let coins_bytes = get_static_attribute(swap, "coins")?;
        let coins: Vec<Address> = from_str(std::str::from_utf8(&coins_bytes)?)?;

        let token_in = self.normalize_token(token_in, &coins)?;
        let token_out = self.normalize_token(token_out, &coins)?;

        let i = coins
            .iter()
            .position(|&addr| addr == token_in)
            .ok_or(EncodingError::FatalError(format!(
                "Token in address {token_in} not found in curve pool coins"
            )))?;
        let j = coins
            .iter()
            .position(|&addr| addr == token_out)
            .ok_or(EncodingError::FatalError(format!(
                "Token in address {token_out} not found in curve pool coins"
            )))?;
        Ok((U8::from(i), U8::from(j)))
    }
}

impl SwapEncoder for CurveSwapEncoder {
    fn new(
        executor_address: Bytes,
        chain: Chain,
        config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        let config = config.ok_or(EncodingError::FatalError(
            "Missing curve specific addresses in config".to_string(),
        ))?;
        let native_token_curve_address = config
            .get("native_token_address")
            .map(|s| {
                Bytes::from_str(s).map_err(|_| {
                    EncodingError::FatalError("Invalid native token curve address".to_string())
                })
            })
            .ok_or(EncodingError::FatalError(
                "Missing native token curve address in config".to_string(),
            ))
            .flatten()?;
        Ok(Self {
            executor_address,
            native_token_address: chain.native_token().address,
            native_token_curve_address,
            wrapped_native_token_address: chain.wrapped_native_token().address,
        })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_approvals_manager = ProtocolApprovalsManager::new()?;
        let native_token_curve_address = Address::from_slice(&self.native_token_curve_address);
        let token_in = if swap.token_in == self.native_token_address {
            native_token_curve_address
        } else {
            bytes_to_address(&swap.token_in)?
        };
        let token_out = if swap.token_out == self.native_token_address {
            native_token_curve_address
        } else {
            bytes_to_address(&swap.token_out)?
        };
        let approval_needed: bool;

        let component_address = Address::from_str(&swap.component.id)
            .map_err(|_| EncodingError::FatalError("Invalid curve pool address".to_string()))?;
        if let Some(router_address) = &encoding_context.router_address {
            if token_in != native_token_curve_address {
                let tycho_router_address = bytes_to_address(router_address)?;
                approval_needed = token_approvals_manager.approval_needed(
                    token_in,
                    tycho_router_address,
                    component_address,
                )?;
            } else {
                approval_needed = false;
            }
        } else {
            approval_needed = true;
        }

        let factory_bytes = get_static_attribute(swap, "factory")?.to_vec();
        // the conversion to Address is necessary to checksum the address
        let factory_address =
            Address::from_str(std::str::from_utf8(&factory_bytes).map_err(|_| {
                EncodingError::FatalError(
                    "Failed to convert curve factory address to string".to_string(),
                )
            })?)
            .map_err(|_| EncodingError::FatalError("Invalid curve factory address".to_string()))?;

        let pool_address = Address::from_str(&swap.component.id)
            .map_err(|_| EncodingError::FatalError("Invalid curve pool address".to_string()))?;
        let pool_type =
            self.get_pool_type(&pool_address.to_string(), &factory_address.to_string())?;

        let (i, j) = self.get_coin_indexes(swap, token_in, token_out)?;

        let args = (
            token_in,
            token_out,
            component_address,
            pool_type.to_be_bytes::<1>(),
            i.to_be_bytes::<1>(),
            j.to_be_bytes::<1>(),
            approval_needed,
            (encoding_context.transfer_type as u8).to_be_bytes(),
            bytes_to_address(&encoding_context.receiver)?,
        );

        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }
    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

/// Encodes a swap on a Maverick V2 pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
#[derive(Clone)]
pub struct MaverickV2SwapEncoder {
    executor_address: Bytes,
}

impl SwapEncoder for MaverickV2SwapEncoder {
    fn new(
        executor_address: Bytes,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self { executor_address })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let component_id = AlloyBytes::from_str(&swap.component.id)
            .map_err(|_| EncodingError::FatalError("Invalid component ID".to_string()))?;

        let args = (
            bytes_to_address(&swap.token_in)?,
            component_id,
            bytes_to_address(&encoding_context.receiver)?,
            (encoding_context.transfer_type as u8).to_be_bytes(),
        );
        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }
    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

/// Encodes a swap on a Balancer V3 pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
#[derive(Clone)]
pub struct BalancerV3SwapEncoder {
    executor_address: Bytes,
}

impl SwapEncoder for BalancerV3SwapEncoder {
    fn new(
        executor_address: Bytes,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self { executor_address })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let pool = Address::from_str(&swap.component.id).map_err(|_| {
            EncodingError::FatalError("Invalid pool address for Balancer v3".to_string())
        })?;

        let args = (
            bytes_to_address(&swap.token_in)?,
            bytes_to_address(&swap.token_out)?,
            pool,
            (encoding_context.transfer_type as u8).to_be_bytes(),
            bytes_to_address(&encoding_context.receiver)?,
        );
        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }

    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

/// Encodes a swap on Bebop (PMM RFQ) through the given executor address.
///
/// Bebop uses a Request-for-Quote model where quotes are obtained off-chain
/// and settled on-chain. This encoder supports PMM RFQ execution.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
/// * `settlement_address` - The address of the Bebop settlement contract.
#[derive(Clone)]
pub struct BebopSwapEncoder {
    executor_address: Bytes,
    settlement_address: Bytes,
    native_token_bebop_address: Bytes,
    native_token_address: Bytes,
    runtime_handle: Handle,
    #[allow(dead_code)]
    runtime: Option<Arc<Runtime>>,
}

impl SwapEncoder for BebopSwapEncoder {
    fn new(
        executor_address: Bytes,
        chain: Chain,
        config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        let config = config.ok_or(EncodingError::FatalError(
            "Missing bebop specific addresses in config".to_string(),
        ))?;
        let settlement_address = config
            .get("bebop_settlement_address")
            .map(|s| {
                Bytes::from_str(s).map_err(|_| {
                    EncodingError::FatalError("Invalid bebop settlement address".to_string())
                })
            })
            .ok_or(EncodingError::FatalError(
                "Missing bebop settlement address in config".to_string(),
            ))
            .flatten()?;
        let native_token_bebop_address = config
            .get("native_token_address")
            .map(|s| {
                Bytes::from_str(s).map_err(|_| {
                    EncodingError::FatalError("Invalid native token bebop address".to_string())
                })
            })
            .ok_or(EncodingError::FatalError(
                "Missing native token bebop address in config".to_string(),
            ))
            .flatten()?;
        let (runtime_handle, runtime) = get_runtime()?;
        Ok(Self {
            executor_address,
            settlement_address,
            runtime_handle,
            runtime,
            native_token_bebop_address,
            native_token_address: chain.native_token().address,
        })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_in = bytes_to_address(&swap.token_in)?;
        let token_out = bytes_to_address(&swap.token_out)?;
        let sender = encoding_context
            .router_address
            .clone()
            .ok_or(EncodingError::FatalError(
                "The router address is needed to perform a Hashflow swap".to_string(),
            ))?;
        let approval_needed = if swap.token_in == self.native_token_address {
            false
        } else {
            let tycho_router_address = bytes_to_address(&sender)?;
            let settlement_address = Address::from_str(&self.settlement_address.to_string())
                .map_err(|_| {
                    EncodingError::FatalError("Invalid bebop settlement address".to_string())
                })?;
            ProtocolApprovalsManager::new()?.approval_needed(
                token_in,
                tycho_router_address,
                settlement_address,
            )?
        };

        let protocol_state = swap
            .protocol_state
            .as_ref()
            .ok_or_else(|| {
                EncodingError::FatalError("protocol_state is required for Bebop".to_string())
            })?;
        let (partial_fill_offset, original_filled_taker_amount, bebop_calldata) = {
            let indicatively_priced_state = protocol_state
                .as_indicatively_priced()
                .map_err(|e| {
                    EncodingError::FatalError(format!("State is not indicatively priced {e}"))
                })?;
            let estimated_amount_in =
                swap.estimated_amount_in
                    .clone()
                    .ok_or(EncodingError::FatalError(
                        "Estimated amount in is mandatory for a Bebop swap".to_string(),
                    ))?;
            // Bebop uses another address for the native token than the zero address
            let mut token_in = swap.token_in.clone();
            if swap.token_in == self.native_token_address {
                token_in = self.native_token_bebop_address.clone()
            }
            let mut token_out = swap.token_out.clone();
            if swap.token_out == self.native_token_address {
                token_out = self.native_token_bebop_address.clone()
            }

            let params = GetAmountOutParams {
                amount_in: estimated_amount_in,
                token_in,
                token_out,
                sender: encoding_context
                    .router_address
                    .clone()
                    .ok_or(EncodingError::FatalError(
                        "The router address is needed to perform a Bebop swap".to_string(),
                    ))?,
                receiver: encoding_context.receiver.clone(),
            };
            let signed_quote = block_in_place(|| {
                self.runtime_handle.block_on(async {
                    indicatively_priced_state
                        .request_signed_quote(params)
                        .await
                })
            })?;
            let bebop_calldata = signed_quote
                .quote_attributes
                .get("calldata")
                .ok_or(EncodingError::FatalError(
                    "Bebop quote must have a calldata attribute".to_string(),
                ))?;
            let partial_fill_offset = signed_quote
                .quote_attributes
                .get("partial_fill_offset")
                .ok_or(EncodingError::FatalError(
                    "Bebop quote must have a partial_fill_offset attribute".to_string(),
                ))?;
            let original_filled_taker_amount = biguint_to_u256(&signed_quote.amount_out);
            (
                // we are only interested in the last byte to get a u8
                partial_fill_offset[partial_fill_offset.len() - 1],
                original_filled_taker_amount,
                bebop_calldata.to_vec(),
            )
        };

        let receiver = bytes_to_address(&encoding_context.receiver)?;

        // Encode packed data for the executor
        // Format: token_in | token_out | transfer_type | partial_fill_offset |
        //         original_filled_taker_amount | approval_needed | receiver | bebop_calldata
        let args = (
            token_in,
            token_out,
            (encoding_context.transfer_type as u8).to_be_bytes(),
            partial_fill_offset.to_be_bytes(),
            original_filled_taker_amount.to_be_bytes::<32>(),
            (approval_needed as u8).to_be_bytes(),
            receiver,
            &bebop_calldata[..],
        );

        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }

    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
pub struct HashflowSwapEncoder {
    executor_address: Bytes,
    hashflow_router_address: Bytes,
    native_token_address: Bytes,
    runtime_handle: Handle,
    #[allow(dead_code)]
    runtime: Option<Arc<Runtime>>,
}

impl SwapEncoder for HashflowSwapEncoder {
    fn new(
        executor_address: Bytes,
        chain: Chain,
        config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        let config = config.ok_or(EncodingError::FatalError(
            "Missing hashflow specific addresses in config".to_string(),
        ))?;
        let hashflow_router_address = config
            .get("hashflow_router_address")
            .map(|s| {
                Bytes::from_str(s).map_err(|_| {
                    EncodingError::FatalError("Invalid hashflow router address".to_string())
                })
            })
            .ok_or(EncodingError::FatalError(
                "Missing hashflow router address in config".to_string(),
            ))
            .flatten()?;
        let native_token_address = chain.native_token().address;
        let (runtime_handle, runtime) = get_runtime()?;
        Ok(Self {
            executor_address,
            hashflow_router_address,
            native_token_address,
            runtime_handle,
            runtime,
        })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        // Native tokens doesn't need approval, only ERC20 tokens do
        let sender = encoding_context
            .router_address
            .clone()
            .ok_or(EncodingError::FatalError(
                "The router address is needed to perform a Hashflow swap".to_string(),
            ))?;

        // Native ETH doesn't need approval, only ERC20 tokens do
        let approval_needed = if swap.token_in == self.native_token_address {
            false
        } else {
            let tycho_router_address = bytes_to_address(&sender)?;
            let hashflow_router_address = Address::from_slice(&self.hashflow_router_address);
            ProtocolApprovalsManager::new()?.approval_needed(
                bytes_to_address(&swap.token_in)?,
                tycho_router_address,
                hashflow_router_address,
            )?
        };

        // Get quote
        let protocol_state = swap
            .protocol_state
            .as_ref()
            .ok_or_else(|| {
                EncodingError::FatalError("protocol_state is required for Hashflow".to_string())
            })?;
        let amount_in = swap
            .estimated_amount_in
            .as_ref()
            .ok_or(EncodingError::FatalError(
                "Estimated amount in is mandatory for a Hashflow swap".to_string(),
            ))?
            .clone();
        let sender = encoding_context
            .router_address
            .clone()
            .ok_or(EncodingError::FatalError(
                "The router address is needed to perform a Hashflow swap".to_string(),
            ))?;
        let signed_quote = block_in_place(|| {
            self.runtime_handle.block_on(async {
                protocol_state
                    .as_indicatively_priced()?
                    .request_signed_quote(GetAmountOutParams {
                        amount_in,
                        token_in: swap.token_in.clone(),
                        token_out: swap.token_out.clone(),
                        sender,
                        receiver: encoding_context.receiver.clone(),
                    })
                    .await
            })
        })?;

        // Encode packed data for the executor
        // Format: approval_needed | transfer_type | hashflow_calldata[..]
        let hashflow_fields = [
            "pool",
            "external_account",
            "trader",
            "base_token",
            "quote_token",
            "base_token_amount",
            "quote_token_amount",
            "quote_expiry",
            "nonce",
            "tx_id",
            "signature",
        ];
        let mut hashflow_calldata = vec![];
        for field in &hashflow_fields {
            let value = signed_quote
                .quote_attributes
                .get(*field)
                .ok_or(EncodingError::FatalError(format!(
                    "Hashflow quote must have a {field} attribute"
                )))?;
            hashflow_calldata.extend_from_slice(value);
        }
        let args = (
            (encoding_context.transfer_type as u8).to_be_bytes(),
            (approval_needed as u8).to_be_bytes(),
            &hashflow_calldata[..],
        );
        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }

    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
pub struct FluidV1SwapEncoder {
    executor_address: Bytes,
    native_address: Bytes,
    chain: Chain,
}

impl SwapEncoder for FluidV1SwapEncoder {
    fn new(
        executor_address: Bytes,
        chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self {
            executor_address,
            native_address: Bytes::from("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
            chain,
        })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let dex_address = Address::from_str(&swap.component.id).map_err(|_| {
            EncodingError::FatalError(format!(
                "Failed parsing FluidV1 component id as ethereum address: {}",
                &swap.component.id
            ))
        })?;

        let args = (
            dex_address,
            self.coerce_native_address(&swap.token_in) <
                self.coerce_native_address(&swap.token_out),
            bytes_to_address(&encoding_context.receiver)?,
            (encoding_context.transfer_type as u8).to_be_bytes(),
            swap.token_in == self.chain.native_token().address,
        );
        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }

    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

impl FluidV1SwapEncoder {
    fn coerce_native_address<'a>(&'a self, address: &'a Bytes) -> &'a Bytes {
        if address == &self.chain.native_token().address {
            &self.native_address
        } else {
            address
        }
    }
}

/// Encodes a swap on a Aerodrome Slipstreams pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
#[derive(Clone)]
pub struct SlipstreamsSwapEncoder {
    executor_address: Bytes,
}

impl SlipstreamsSwapEncoder {
    fn get_zero_to_one(sell_token_address: Address, buy_token_address: Address) -> bool {
        sell_token_address < buy_token_address
    }
}

impl SwapEncoder for SlipstreamsSwapEncoder {
    fn new(
        executor_address: Bytes,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self { executor_address })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_in_address = bytes_to_address(&swap.token_in)?;
        let token_out_address = bytes_to_address(&swap.token_out)?;

        let zero_to_one = Self::get_zero_to_one(token_in_address, token_out_address);
        let component_id = Address::from_str(&swap.component.id).map_err(|_| {
            EncodingError::FatalError("Invalid Slipstreams component id".to_string())
        })?;
        let tick_spacing_bytes = get_static_attribute(swap, "tick_spacing")?;

        let tick_spacing_bytes_u24 =
            pad_or_truncate_to_size::<3>(&tick_spacing_bytes).map_err(|_| {
                EncodingError::FatalError("Failed to extract tick_spacing bytes".to_string())
            })?;

        let args = (
            token_in_address,
            token_out_address,
            tick_spacing_bytes_u24,
            (encoding_context.transfer_type as u8).to_be_bytes(),
            bytes_to_address(&encoding_context.receiver)?,
            component_id,
            zero_to_one,
        );

        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }
    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

/// Encodes a swap on a Rocketpool pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
/// * `native_token_address` - The address of the native token (only ETH).
#[derive(Clone)]
pub struct RocketpoolSwapEncoder {
    executor_address: Bytes,
    native_token_address: Bytes,
}

impl SwapEncoder for RocketpoolSwapEncoder {
    fn new(
        executor_address: Bytes,
        chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        if chain != Chain::Ethereum {
            return Err(EncodingError::FatalError(
                "Rocketpool swaps are only supported on Ethereum".to_string(),
            ));
        }
        let native_token_address = chain.native_token().address;

        Ok(Self { executor_address, native_token_address })
    }

    fn encode_swap(
        &self,
        swap: &Swap,
        encoding_context: &EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let is_deposit = swap.token_in == self.native_token_address;

        let args = (
            is_deposit,
            (encoding_context.transfer_type as u8).to_be_bytes(),
            bytes_to_address(&encoding_context.receiver)?,
        );

        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &Bytes {
        &self.executor_address
    }

    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy::hex::encode;
    use num_bigint::BigInt;
    use tycho_common::{
        models::{protocol::ProtocolComponent, Chain},
        Bytes,
    };

    use super::*;
    use crate::encoding::{
        evm::utils::write_calldata_to_file,
        models::{SwapBuilder, TransferType},
    };

    mod uniswap_v2 {
        use super::*;
        use crate::encoding::models::SwapBuilder;
        #[test]
        fn test_encode_uniswap_v2() {
            let usv2_pool = ProtocolComponent {
                id: String::from("0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11"),
                ..Default::default()
            };

            let token_in = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
            let token_out = Bytes::from("0x6b175474e89094c44da98b954eedeac495271d0f");
            let swap = SwapBuilder::new(usv2_pool, token_in.clone(), token_out.clone()).build();
            let encoding_context = EncodingContext {
                receiver: Bytes::from("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de"), // BOB*
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };
            let encoder = UniswapV2SwapEncoder::new(
                Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                Chain::Ethereum,
                None,
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);
            assert_eq!(
                hex_swap,
                String::from(concat!(
                    // in token
                    "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                    // component id
                    "a478c2975ab1ea89e8196811f51a7b7ade33eb11",
                    // receiver
                    "9964bff29baa37b47604f3f3f51f3b3c5149d6de",
                    // zero for one
                    "00",
                    // transfer type Transfer
                    "01",
                ))
            );
            write_calldata_to_file("test_encode_uniswap_v2", hex_swap.as_str());
        }
    }

    mod uniswap_v3 {
        use super::*;
        use crate::encoding::models::SwapBuilder;
        #[test]
        fn test_encode_uniswap_v3() {
            let fee = BigInt::from(500);
            let encoded_pool_fee = Bytes::from(fee.to_signed_bytes_be());
            let mut static_attributes: HashMap<String, Bytes> = HashMap::new();
            static_attributes.insert("fee".into(), Bytes::from(encoded_pool_fee.to_vec()));

            let usv3_pool = ProtocolComponent {
                id: String::from("0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640"),
                static_attributes,
                ..Default::default()
            };
            let token_in = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
            let token_out = Bytes::from("0x6b175474e89094c44da98b954eedeac495271d0f");
            let swap = SwapBuilder::new(usv3_pool, token_in.clone(), token_out.clone()).build();
            let encoding_context = EncodingContext {
                receiver: Bytes::from("0x0000000000000000000000000000000000000001"),
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };
            let encoder = UniswapV3SwapEncoder::new(
                Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                Chain::Ethereum,
                None,
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);
            assert_eq!(
                hex_swap,
                String::from(concat!(
                    // in token
                    "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                    // out token
                    "6b175474e89094c44da98b954eedeac495271d0f",
                    // fee
                    "0001f4",
                    // receiver
                    "0000000000000000000000000000000000000001",
                    // pool id
                    "88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
                    // zero for one
                    "00",
                    // transfer type Transfer
                    "01",
                ))
            );
        }
    }

    mod balancer_v2 {
        use super::*;
        use crate::encoding::models::SwapBuilder;

        #[test]
        fn test_encode_balancer_v2() {
            let balancer_pool = ProtocolComponent {
                id: String::from(
                    "0x5c6ee304399dbdb9c8ef030ab642b10820db8f56000200000000000000000014",
                ),
                protocol_system: String::from("vm:balancer_v2"),
                ..Default::default()
            };
            let token_in = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
            let token_out = Bytes::from("0xba100000625a3754423978a60c9317c58a424e3D");
            let swap = SwapBuilder::new(balancer_pool, token_in.clone(), token_out.clone()).build();
            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob*") using forge`
                receiver: Bytes::from("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de"),
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::None,
                historical_trade: true,
            };
            let encoder = BalancerV2SwapEncoder::new(
                Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                Chain::Ethereum,
                Some(HashMap::from([(
                    "vault_address".to_string(),
                    "0xba12222222228d8ba445958a75a0704d566bf2c8".to_string(),
                )])),
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            assert_eq!(
                hex_swap,
                String::from(concat!(
                    // token in
                    "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                    // token out
                    "ba100000625a3754423978a60c9317c58a424e3d",
                    // pool id
                    "5c6ee304399dbdb9c8ef030ab642b10820db8f56000200000000000000000014",
                    // receiver
                    "9964bff29baa37b47604f3f3f51f3b3c5149d6de",
                    // approval needed
                    "01",
                    // transfer type None
                    "02"
                ))
            );
            write_calldata_to_file("test_encode_balancer_v2", hex_swap.as_str());
        }
    }

    mod uniswap_v4 {
        use super::*;
        use crate::encoding::evm::utils::{ple_encode, write_calldata_to_file};

        #[test]
        fn test_encode_uniswap_v4_simple_swap() {
            let fee = BigInt::from(100);
            let tick_spacing = BigInt::from(1);
            let token_in = Bytes::from("0x4c9EDD5852cd905f086C759E8383e09bff1E68B3"); // USDE
            let token_out = Bytes::from("0xdAC17F958D2ee523a2206206994597C13D831ec7"); // USDT

            let mut static_attributes: HashMap<String, Bytes> = HashMap::new();
            static_attributes.insert("key_lp_fee".into(), Bytes::from(fee.to_signed_bytes_be()));
            static_attributes
                .insert("tick_spacing".into(), Bytes::from(tick_spacing.to_signed_bytes_be()));

            let usv4_pool = ProtocolComponent {
                // Pool manager
                id: String::from("0x000000000004444c5dc75cB358380D2e3dE08A90"),
                static_attributes,
                ..Default::default()
            };
            let swap = SwapBuilder::new(usv4_pool, token_in.clone(), token_out.clone()).build();
            let encoding_context = EncodingContext {
                // The receiver is ALICE to match the solidity tests
                receiver: Bytes::from("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2"),
                exact_out: false,
                // Same as the executor address
                router_address: Some(Bytes::from("0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f")),

                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };
            let encoder = UniswapV4SwapEncoder::new(
                Bytes::from("0xF62849F9A0B5Bf2913b396098F7c7019b51A820a"),
                Chain::Ethereum,
                None,
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            assert_eq!(
                hex_swap,
                String::from(concat!(
                    // group token in
                    "4c9edd5852cd905f086c759e8383e09bff1e68b3",
                    // group token out
                    "dac17f958d2ee523a2206206994597c13d831ec7",
                    // zero for one
                    "01",
                    // transfer type Transfer
                    "01",
                    // receiver
                    "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2",
                    // pool params:
                    // - intermediary token
                    "dac17f958d2ee523a2206206994597c13d831ec7",
                    // - fee
                    "000064",
                    // - tick spacing
                    "000001",
                    // hook address (not set, so zero)
                    "0000000000000000000000000000000000000000",
                    // hook data length (0)
                    "0000"
                ))
            );
            write_calldata_to_file("test_encode_uniswap_v4_simple_swap", hex_swap.as_str());
        }

        #[test]
        fn test_encode_uniswap_v4_second_swap() {
            let fee = BigInt::from(3000);
            let tick_spacing = BigInt::from(60);
            let group_token_in = Bytes::from("0x4c9EDD5852cd905f086C759E8383e09bff1E68B3"); // USDE
            let token_in = Bytes::from("0xdAC17F958D2ee523a2206206994597C13D831ec7"); // USDT
            let token_out = Bytes::from("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"); // WBTC

            let mut static_attributes: HashMap<String, Bytes> = HashMap::new();
            static_attributes.insert("key_lp_fee".into(), Bytes::from(fee.to_signed_bytes_be()));
            static_attributes
                .insert("tick_spacing".into(), Bytes::from(tick_spacing.to_signed_bytes_be()));

            let usv4_pool = ProtocolComponent {
                id: String::from("0x000000000004444c5dc75cB358380D2e3dE08A90"),
                static_attributes,
                ..Default::default()
            };

            let swap = SwapBuilder::new(usv4_pool, token_in.clone(), token_out.clone()).build();

            let encoding_context = EncodingContext {
                receiver: Bytes::from("0x0000000000000000000000000000000000000001"),
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: group_token_in.clone(),
                // Token out is the same as the group token out
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };

            let encoder = UniswapV4SwapEncoder::new(
                Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                Chain::Ethereum,
                None,
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            assert_eq!(
                hex_swap,
                String::from(concat!(
                    // pool params:
                    // - intermediary token (20 bytes)
                    "2260fac5e5542a773aa44fbcfedf7c193bc2c599",
                    // - fee (3 bytes)
                    "000bb8",
                    // - tick spacing (3 bytes)
                    "00003c",
                    // hook address (not set, so zero)
                    "0000000000000000000000000000000000000000",
                    // hook data length (0)
                    "0000"
                ))
            );
        }

        #[test]
        fn test_encode_uniswap_v4_sequential_swap() {
            let usde_address = Bytes::from("0x4c9EDD5852cd905f086C759E8383e09bff1E68B3");
            let usdt_address = Bytes::from("0xdAC17F958D2ee523a2206206994597C13D831ec7");
            let wbtc_address = Bytes::from("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599");
            let router_address = Bytes::from("0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f");

            // The context is the same for both swaps, since the group token in and out are the same
            let context = EncodingContext {
                // The receiver is ALICE to match the solidity tests
                receiver: Bytes::from("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2"),
                exact_out: false,
                router_address: Some(router_address.clone()),
                group_token_in: usde_address.clone(),
                group_token_out: wbtc_address.clone(),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };

            // Setup - First sequence: USDE -> USDT
            let usde_usdt_fee = BigInt::from(100);
            let usde_usdt_tick_spacing = BigInt::from(1);

            let mut usde_usdt_static_attributes: HashMap<String, Bytes> = HashMap::new();
            usde_usdt_static_attributes
                .insert("key_lp_fee".into(), Bytes::from(usde_usdt_fee.to_signed_bytes_be()));
            usde_usdt_static_attributes.insert(
                "tick_spacing".into(),
                Bytes::from(usde_usdt_tick_spacing.to_signed_bytes_be()),
            );

            let usde_usdt_component = ProtocolComponent {
                id: String::from("0x000000000004444c5dc75cB358380D2e3dE08A90"),
                static_attributes: usde_usdt_static_attributes,
                ..Default::default()
            };

            // Setup - Second sequence: USDT -> WBTC
            let usdt_wbtc_fee = BigInt::from(3000);
            let usdt_wbtc_tick_spacing = BigInt::from(60);

            let mut usdt_wbtc_static_attributes: HashMap<String, Bytes> = HashMap::new();
            usdt_wbtc_static_attributes
                .insert("key_lp_fee".into(), Bytes::from(usdt_wbtc_fee.to_signed_bytes_be()));
            usdt_wbtc_static_attributes.insert(
                "tick_spacing".into(),
                Bytes::from(usdt_wbtc_tick_spacing.to_signed_bytes_be()),
            );

            let usdt_wbtc_component = ProtocolComponent {
                id: String::from("0x000000000004444c5dc75cB358380D2e3dE08A90"),
                static_attributes: usdt_wbtc_static_attributes,
                ..Default::default()
            };

            let initial_swap =
                SwapBuilder::new(usde_usdt_component, usde_address.clone(), usdt_address.clone())
                    .build();
            let second_swap =
                SwapBuilder::new(usdt_wbtc_component, usdt_address.clone(), wbtc_address.clone())
                    .build();

            let encoder = UniswapV4SwapEncoder::new(
                Bytes::from("0xF62849F9A0B5Bf2913b396098F7c7019b51A820a"),
                Chain::Ethereum,
                None,
            )
            .unwrap();
            let initial_encoded_swap = encoder
                .encode_swap(&initial_swap, &context)
                .unwrap();
            let second_encoded_swap = encoder
                .encode_swap(&second_swap, &context)
                .unwrap();

            let combined_hex = format!(
                "{}{}",
                encode(&initial_encoded_swap),
                encode(ple_encode(vec![second_encoded_swap]))
            );

            assert_eq!(
                combined_hex,
                String::from(concat!(
                    // group_token in
                    "4c9edd5852cd905f086c759e8383e09bff1e68b3",
                    // group_token out
                    "2260fac5e5542a773aa44fbcfedf7c193bc2c599",
                    // zero for one
                    "01",
                    // transfer type Transfer
                    "01",
                    // receiver
                    "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2",
                    // pool params:
                    // - intermediary token USDT
                    "dac17f958d2ee523a2206206994597c13d831ec7",
                    // - fee
                    "000064",
                    // - tick spacing
                    "000001",
                    // hook address (not set, so zero)
                    "0000000000000000000000000000000000000000",
                    // hook data length (0)
                    "0000",
                    // Second swap
                    // ple encoding
                    "0030",
                    // - intermediary token WBTC
                    "2260fac5e5542a773aa44fbcfedf7c193bc2c599",
                    // - fee
                    "000bb8",
                    // - tick spacing
                    "00003c",
                    // hook address (not set, so zero)
                    "0000000000000000000000000000000000000000",
                    // hook data length (0)
                    "0000"
                ))
            );
            write_calldata_to_file("test_encode_uniswap_v4_sequential_swap", combined_hex.as_str());
        }
    }

    mod uniswap_v4_angstrom {
        use super::*;
        use crate::encoding::evm::utils::ple_encode;

        #[test]
        fn test_encode_attestations_format() {
            // Create mock attestation data with real attestations retrieved in the past
            let attestations = AttestationResponse {
                success: true,
                attestations: vec![
                    AttestationData {
                        block_number: 12345678,
                        attestation: "0xd437f3372f3add2c2bc3245e6bd6f9c202e61bb367c79a6f740c7c12ca9c54a760bead943516fafaf8a4fe65a907b31d45c2ab4b525f9f32ec2771033e0832359ceb2e38d9288a755c7c366ce889b0df24b5821b1c".to_string(),
                    },
                    AttestationData {
                        block_number: 12345679,
                        attestation: "0xd437f3372f3add2c2bc3245e6bd6f9c202e61bb30c337ddae661e68cc6986c7784cd0aaec455b1f7514b6cd91bff26f002ce7cb42b3b1e2092ea4d1c1fb1e0641cbccfb021b31de25462f25b355cc99c7d509cdc1b".to_string(),
                    },
                ],
            };

            let encoded =
                UniswapV4SwapEncoder::encode_angstrom_attestations(&attestations).unwrap();

            // Verify the structure with fixed-length format:
            // - For each attestation:
            //   - 8 bytes: block number
            //   - 85 bytes: attestation data
            // Total: 93 bytes per attestation, 186 bytes for 2 attestations

            assert_eq!(encoded.len(), 186);
            let encoded_hex = hex::encode(&encoded);

            assert_eq!(
                encoded_hex,
                String::from(concat!(
                    // First attestation block number (12345678)
                    "0000000000bc614e",
                    // First attestation data
                    "d437f3372f3add2c2bc3245e6bd6f9c202e61bb367c79a6f740c7c12ca9c54a760bead943516fafaf8a4fe65a907b31d45c2ab4b525f9f32ec2771033e0832359ceb2e38d9288a755c7c366ce889b0df24b5821b1c",
                    // Second attestation block number (12345679)
                    "0000000000bc614f",
                    // Second attestation data
                    "d437f3372f3add2c2bc3245e6bd6f9c202e61bb30c337ddae661e68cc6986c7784cd0aaec455b1f7514b6cd91bff26f002ce7cb42b3b1e2092ea4d1c1fb1e0641cbccfb021b31de25462f25b355cc99c7d509cdc1b"
                ))
            );
        }

        #[test]
        #[ignore] // Performs real Angstrom API call
        fn test_encode_grouped_swap_integration() {
            // This test performs a grouped swap: USDC -> WETH -> USDT on two consecutive Angstrom
            // pools
            let usdc_address = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
            let weth_address = Bytes::from("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
            let usdt_address = Bytes::from("0xdAC17F958D2ee523a2206206994597C13D831ec7");
            let angstrom_hook = Bytes::from("0x0000000aa232009084Bd71A5797d089AA4Edfad4");

            // Context for the grouped swap
            let context = EncodingContext {
                receiver: Bytes::from("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2"), // ALICE
                exact_out: false,
                router_address: Some(Bytes::from("0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f")),
                group_token_in: usdc_address.clone(),
                group_token_out: usdt_address.clone(),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };

            // Setup first pool: USDC -> WETH (use real tick spacing and fee from on-chain)
            let mut usdc_weth_attributes: HashMap<String, Bytes> = HashMap::new();
            usdc_weth_attributes.insert("key_lp_fee".into(), Bytes::from("0x800000")); // 8388608
            usdc_weth_attributes.insert("tick_spacing".into(), Bytes::from("0x0a")); // 10
            usdc_weth_attributes.insert("hooks".into(), angstrom_hook.clone());

            let usdc_weth_pool = ProtocolComponent {
                id: String::from("0x000000000004444c5dc75cB358380D2e3dE08A90"),
                static_attributes: usdc_weth_attributes,
                ..Default::default()
            };

            // Setup second pool: WETH -> USDT (use real tick spacing and fee from on-chain)
            let mut weth_usdt_attributes: HashMap<String, Bytes> = HashMap::new();
            weth_usdt_attributes.insert("key_lp_fee".into(), Bytes::from("0x800000")); // 8388608
            weth_usdt_attributes.insert("tick_spacing".into(), Bytes::from("0x0a")); // 10
            weth_usdt_attributes.insert("hooks".into(), angstrom_hook.clone());

            let weth_usdt_pool = ProtocolComponent {
                id: String::from("0x000000000004444c5dc75cB358380D2e3dE08A90"),
                static_attributes: weth_usdt_attributes,
                ..Default::default()
            };

            let first_swap =
                SwapBuilder::new(usdc_weth_pool, usdc_address.clone(), weth_address.clone())
                    .build();
            let second_swap =
                SwapBuilder::new(weth_usdt_pool, weth_address.clone(), usdt_address.clone())
                    .build();

            // Encoder reads Angstrom config from environment variables:
            // - ANGSTROM_API_KEY (required)
            // - ANGSTROM_API_URL (optional)
            // - ANGSTROM_BLOCKS_IN_FUTURE (optional)
            let encoder = UniswapV4SwapEncoder::new(
                Bytes::from("0xF62849F9A0B5Bf2913b396098F7c7019b51A820a"),
                Chain::Ethereum,
                Some(HashMap::from([(
                    "angstrom_hook_address".to_string(),
                    "0x0000000aa232009084Bd71A5797d089AA4Edfad4".to_string(),
                )])),
            )
            .unwrap();

            // Encode both swaps and combine using prefix-length encoding for the second swap
            let first_encoded = encoder
                .encode_swap(&first_swap, &context)
                .unwrap();
            let second_encoded = encoder
                .encode_swap(&second_swap, &context)
                .unwrap();
            let combined_hex =
                format!("{}{}", encode(&first_encoded), encode(ple_encode(vec![second_encoded])));

            write_calldata_to_file("test_encode_angstrom_grouped_swap", combined_hex.as_str());
            // Any different length could indicate we didn't encode attestation data
            assert!(combined_hex.len() == 2552);
        }
    }

    mod ekubo {
        use super::*;

        const RECEIVER: &str = "ca4f73fe97d0b987a0d12b39bbd562c779bab6f6"; // Random address

        #[test]
        fn test_encode_swap_simple() {
            let token_in = Bytes::from(Address::ZERO.as_slice());
            let token_out = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // USDC

            let static_attributes = HashMap::from([
                ("fee".to_string(), Bytes::from(0_u64)),
                ("tick_spacing".to_string(), Bytes::from(0_u32)),
                (
                    "extension".to_string(),
                    Bytes::from("0x51d02a5948496a67827242eabc5725531342527c"),
                ), // Oracle
            ]);

            let component = ProtocolComponent { static_attributes, ..Default::default() };

            let swap = SwapBuilder::new(component, token_in.clone(), token_out.clone()).build();

            let encoding_context = EncodingContext {
                receiver: RECEIVER.into(),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                exact_out: false,
                router_address: Some(Bytes::default()),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };

            let encoder = EkuboSwapEncoder::new(Bytes::default(), Chain::Ethereum, None).unwrap();

            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();

            let hex_swap = encode(&encoded_swap);

            assert_eq!(
                hex_swap,
                concat!(
                    // transfer type Transfer
                    "01",
                    // receiver
                    "ca4f73fe97d0b987a0d12b39bbd562c779bab6f6",
                    // group token in
                    "0000000000000000000000000000000000000000",
                    // token out 1st swap
                    "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                    // pool config 1st swap
                    "51d02a5948496a67827242eabc5725531342527c000000000000000000000000",
                ),
            );
        }

        #[test]
        fn test_encode_swap_multi() {
            let group_token_in = Bytes::from(Address::ZERO.as_slice());
            let group_token_out = Bytes::from("0xdAC17F958D2ee523a2206206994597C13D831ec7"); // USDT
            let intermediary_token = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // USDC

            let encoder = EkuboSwapEncoder::new(Bytes::default(), Chain::Ethereum, None).unwrap();

            let encoding_context = EncodingContext {
                receiver: RECEIVER.into(),
                group_token_in: group_token_in.clone(),
                group_token_out: group_token_out.clone(),
                exact_out: false,
                router_address: Some(Bytes::default()),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };

            let first_swap = SwapBuilder::new(
                ProtocolComponent {
                    static_attributes: HashMap::from([
                        ("fee".to_string(), Bytes::from(0_u64)),
                        ("tick_spacing".to_string(), Bytes::from(0_u32)),
                        (
                            "extension".to_string(),
                            Bytes::from("0x51d02a5948496a67827242eabc5725531342527c"),
                        ), // Oracle
                    ]),
                    ..Default::default()
                },
                group_token_in.clone(),
                intermediary_token.clone(),
            )
            .build();

            let second_swap = SwapBuilder::new(
                ProtocolComponent {
                    // 0.0025% fee & 0.005% base pool
                    static_attributes: HashMap::from([
                        ("fee".to_string(), Bytes::from(461168601842738_u64)),
                        ("tick_spacing".to_string(), Bytes::from(50_u32)),
                        ("extension".to_string(), Bytes::zero(20)),
                    ]),
                    ..Default::default()
                },
                intermediary_token.clone(),
                group_token_out.clone(),
            )
            .build();

            let first_encoded_swap = encoder
                .encode_swap(&first_swap, &encoding_context)
                .unwrap();

            let second_encoded_swap = encoder
                .encode_swap(&second_swap, &encoding_context)
                .unwrap();

            let combined_hex =
                format!("{}{}", encode(first_encoded_swap), encode(second_encoded_swap));

            assert_eq!(
                combined_hex,
                // transfer type
                concat!(
                    // transfer type Transfer
                    "01",
                    // receiver
                    "ca4f73fe97d0b987a0d12b39bbd562c779bab6f6",
                    // group token in
                    "0000000000000000000000000000000000000000",
                    // token out 1st swap
                    "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                    // pool config 1st swap
                    "51d02a5948496a67827242eabc5725531342527c000000000000000000000000",
                    // token out 2nd swap
                    "dac17f958d2ee523a2206206994597c13d831ec7",
                    // pool config 2nd swap
                    "00000000000000000000000000000000000000000001a36e2eb1c43200000032",
                ),
            );
            write_calldata_to_file("test_ekubo_encode_swap_multi", combined_hex.as_str());
        }
    }

    mod curve {
        use rstest::rstest;

        use super::*;

        fn curve_config() -> Option<HashMap<String, String>> {
            Some(HashMap::from([
                (
                    "native_token_address".to_string(),
                    "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE".to_string(),
                ),
                (
                    "meta_registry_address".to_string(),
                    "0xF98B45FA17DE75FB1aD0e7aFD971b0ca00e379fC".to_string(),
                ),
            ]))
        }

        #[rstest]
        #[case(
            "0x5b22307838363533373733363730353435313665313730313463636465643165376438313465646339636534222c22307861353538386637636466353630383131373130613264383264336339633939373639646231646362225d",
            "0x865377367054516e17014CcdED1e7d814EDC9ce4",
            "0xA5588F7cdf560811710A2D82D3C9c99769DB1Dcb",
            0,
            1
        )]
        #[case(
            "0x5b22307836623137353437346538393039346334346461393862393534656564656163343935323731643066222c22307861306238363939316336323138623336633164313964346132653965623063653336303665623438222c22307864616331376639353864326565353233613232303632303639393435393763313364383331656337222c22307835376162316563323864313239373037303532646634646634313864353861326434366435663531225d",
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "0x57Ab1ec28D129707052df4dF418D58a2D46d5f51",
            1,
            3
        )]
        #[case(
            "0x5b22307864616331376639353864326565353233613232303632303639393435393763313364383331656337222c22307832323630666163356535353432613737336161343466626366656466376331393362633263353939222c22307863303261616133396232323366653864306130653563346632376561643930383363373536636332225d",
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
            2,
            1
        )]
        #[case(
            "0x5b22307861306238363939316336323138623336633164313964346132653965623063653336303665623438222c22307832323630666163356535353432613737336161343466626366656466376331393362633263353939222c22307865656565656565656565656565656565656565656565656565656565656565656565656565656565225d",
            "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            2,
            0
        )]
        // Pool that holds ETH but coin is WETH
        #[case(
            "0x5b22307861306238363939316336323138623336633164313964346132653965623063653336303665623438222c22307832323630666163356535353432613737336161343466626366656466376331393362633263353939222c22307865656565656565656565656565656565656565656565656565656565656565656565656565656565225d",
            "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            2,
            0
        )]
        // Pool that holds ETH but coin is WETH
        #[case(
            "0x5b22307861306238363939316336323138623336633164313964346132653965623063653336303665623438222c22307832323630666163356535353432613737336161343466626366656466376331393362633263353939222c22307865656565656565656565656565656565656565656565656565656565656565656565656565656565225d",
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
            0,
            2
        )]
        fn test_curve_get_coin_indexes(
            #[case] coins: &str,
            #[case] token_in: &str,
            #[case] token_out: &str,
            #[case] expected_i: u64,
            #[case] expected_j: u64,
        ) {
            let mut static_attributes: HashMap<String, Bytes> = HashMap::new();
            static_attributes.insert("coins".into(), Bytes::from_str(coins).unwrap());
            let swap = SwapBuilder::new(
                ProtocolComponent {
                    id: "pool-id".into(),
                    protocol_system: String::from("vm:curve"),
                    static_attributes,
                    ..Default::default()
                },
                Bytes::from(token_in),
                Bytes::from(token_out),
            )
            .build();

            let encoder =
                CurveSwapEncoder::new(Bytes::default(), Chain::Ethereum, curve_config()).unwrap();
            let (i, j) = encoder
                .get_coin_indexes(
                    &swap,
                    Address::from_str(token_in).unwrap(),
                    Address::from_str(token_out).unwrap(),
                )
                .unwrap();
            assert_eq!(i, U8::from(expected_i));
            assert_eq!(j, U8::from(expected_j));
        }

        #[test]
        fn test_curve_encode_tripool() {
            let mut static_attributes: HashMap<String, Bytes> = HashMap::new();
            static_attributes.insert(
                "factory".into(),
                Bytes::from(
                    "0x0000000000000000000000000000000000000000"
                        .as_bytes()
                        .to_vec(),
                ),
            );
            static_attributes.insert("coins".into(), Bytes::from_str("0x5b22307836623137353437346538393039346334346461393862393534656564656163343935323731643066222c22307861306238363939316336323138623336633164313964346132653965623063653336303665623438222c22307864616331376639353864326565353233613232303632303639393435393763313364383331656337225d").unwrap());
            let curve_tri_pool = ProtocolComponent {
                id: String::from("0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7"),
                protocol_system: String::from("vm:curve"),
                static_attributes,
                ..Default::default()
            };
            let token_in = Bytes::from("0x6B175474E89094C44Da98b954EedeAC495271d0F");
            let token_out = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
            let swap =
                SwapBuilder::new(curve_tri_pool, token_in.clone(), token_out.clone()).build();

            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob*") using forge`
                receiver: Bytes::from("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de"),
                exact_out: false,
                router_address: None,
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::None,
                historical_trade: false,
            };
            let encoder = CurveSwapEncoder::new(
                Bytes::from("0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f"),
                Chain::Ethereum,
                curve_config(),
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            assert_eq!(
                hex_swap,
                String::from(concat!(
                    // token in
                    "6b175474e89094c44da98b954eedeac495271d0f",
                    // token out
                    "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                    // pool address
                    "bebc44782c7db0a1a60cb6fe97d0b483032ff1c7",
                    // pool type 1
                    "01",
                    // i index
                    "00",
                    // j index
                    "01",
                    // approval needed
                    "01",
                    // transfer type None
                    "02",
                    // receiver,
                    "9964bff29baa37b47604f3f3f51f3b3c5149d6de",
                ))
            );
        }

        #[test]
        fn test_curve_encode_factory() {
            let mut static_attributes: HashMap<String, Bytes> = HashMap::new();
            static_attributes.insert(
                "factory".into(),
                Bytes::from(
                    "0x6A8cbed756804B16E05E741eDaBd5cB544AE21bf"
                        .as_bytes()
                        .to_vec(),
                ),
            );
            static_attributes.insert("coins".into(), Bytes::from_str("0x5b22307834633965646435383532636439303566303836633735396538333833653039626666316536386233222c22307861306238363939316336323138623336633164313964346132653965623063653336303665623438225d").unwrap());
            let curve_pool = ProtocolComponent {
                id: String::from("0x02950460E2b9529D0E00284A5fA2d7bDF3fA4d72"),
                protocol_system: String::from("vm:curve"),
                static_attributes,
                ..Default::default()
            };
            let token_in = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
            let token_out = Bytes::from("0x4c9EDD5852cd905f086C759E8383e09bff1E68B3");
            let swap = SwapBuilder::new(curve_pool, token_in.clone(), token_out.clone()).build();
            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob*") using forge`
                receiver: Bytes::from("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de"),
                exact_out: false,
                router_address: None,
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::None,
                historical_trade: false,
            };
            let encoder = CurveSwapEncoder::new(
                Bytes::from("0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f"),
                Chain::Ethereum,
                curve_config(),
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            assert_eq!(
                hex_swap,
                String::from(concat!(
                    // token in
                    "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                    // token out
                    "4c9edd5852cd905f086c759e8383e09bff1e68b3",
                    // pool address
                    "02950460e2b9529d0e00284a5fa2d7bdf3fa4d72",
                    // pool type 1
                    "01",
                    // i index
                    "01",
                    // j index
                    "00",
                    // approval needed
                    "01",
                    // transfer type None
                    "02",
                    // receiver
                    "9964bff29baa37b47604f3f3f51f3b3c5149d6de",
                ))
            );
        }
        #[test]
        fn test_curve_encode_st_eth() {
            // This test is for the stETH pool, which is a special case in Curve
            // where the token in is ETH but not as the zero address.
            let mut static_attributes: HashMap<String, Bytes> = HashMap::new();
            static_attributes.insert(
                "factory".into(),
                Bytes::from(
                    "0x0000000000000000000000000000000000000000"
                        .as_bytes()
                        .to_vec(),
                ),
            );
            static_attributes.insert("coins".into(), Bytes::from_str("0x5b22307865656565656565656565656565656565656565656565656565656565656565656565656565656565222c22307861653761623936353230646533613138653565313131623565616162303935333132643766653834225d").unwrap());
            let curve_pool = ProtocolComponent {
                id: String::from("0xDC24316b9AE028F1497c275EB9192a3Ea0f67022"),
                protocol_system: String::from("vm:curve"),
                static_attributes,
                ..Default::default()
            };
            let token_in = Bytes::from("0x0000000000000000000000000000000000000000");
            let token_out = Bytes::from("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84");
            let swap = SwapBuilder::new(curve_pool, token_in.clone(), token_out.clone()).build();
            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob*") using forge`
                receiver: Bytes::from("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de"),
                exact_out: false,
                router_address: None,
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::None,
                historical_trade: false,
            };
            let encoder = CurveSwapEncoder::new(
                Bytes::from("0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f"),
                Chain::Ethereum,
                Some(HashMap::from([
                    (
                        "native_token_address".to_string(),
                        "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE".to_string(),
                    ),
                    (
                        "meta_registry_address".to_string(),
                        "0xF98B45FA17DE75FB1aD0e7aFD971b0ca00e379fC".to_string(),
                    ),
                ])),
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            assert_eq!(
                hex_swap,
                String::from(concat!(
                    // token in
                    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    // token out
                    "ae7ab96520de3a18e5e111b5eaab095312d7fe84",
                    // pool address
                    "dc24316b9ae028f1497c275eb9192a3ea0f67022",
                    // pool type 1
                    "01",
                    // i index
                    "00",
                    // j index
                    "01",
                    // approval needed
                    "01",
                    // transfer type None
                    "02",
                    // receiver
                    "9964bff29baa37b47604f3f3f51f3b3c5149d6de",
                ))
            );
        }
    }

    mod balancer_v3 {
        use super::*;

        #[test]
        fn test_encode_balancer_v3() {
            let balancer_pool = ProtocolComponent {
                id: String::from("0x85b2b559bc2d21104c4defdd6efca8a20343361d"),
                protocol_system: String::from("vm:balancer_v3"),
                ..Default::default()
            };
            let token_in = Bytes::from("0x7bc3485026ac48b6cf9baf0a377477fff5703af8");
            let token_out = Bytes::from("0xc71ea051a5f82c67adcf634c36ffe6334793d24c");
            let swap = SwapBuilder::new(balancer_pool, token_in.clone(), token_out.clone()).build();
            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob*") using forge`
                receiver: Bytes::from("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de"),
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };
            let encoder = BalancerV3SwapEncoder::new(
                Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                Chain::Ethereum,
                None,
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            assert_eq!(
                hex_swap,
                String::from(concat!(
                    // token in
                    "7bc3485026ac48b6cf9baf0a377477fff5703af8",
                    // token out
                    "c71ea051a5f82c67adcf634c36ffe6334793d24c",
                    // pool id
                    "85b2b559bc2d21104c4defdd6efca8a20343361d",
                    // transfer type None
                    "01",
                    // receiver
                    "9964bff29baa37b47604f3f3f51f3b3c5149d6de",
                ))
            );
            write_calldata_to_file("test_encode_balancer_v3", hex_swap.as_str());
        }
    }

    mod maverick_v2 {
        use super::*;
        #[test]
        fn test_encode_maverick_v2() {
            // GHO -> (maverick) -> USDC
            let maverick_pool = ProtocolComponent {
                id: String::from("0x14Cf6D2Fe3E1B326114b07d22A6F6bb59e346c67"),
                protocol_system: String::from("vm:maverick_v2"),
                ..Default::default()
            };
            let token_in = Bytes::from("0x40D16FC0246aD3160Ccc09B8D0D3A2cD28aE6C2f");
            let token_out = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
            let swap = SwapBuilder::new(maverick_pool, token_in.clone(), token_out.clone()).build();
            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob*") using forge`
                receiver: Bytes::from("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de"),
                exact_out: false,
                router_address: Some(Bytes::default()),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };
            let encoder = MaverickV2SwapEncoder::new(
                Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                Chain::Ethereum,
                None,
            )
            .unwrap();

            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            assert_eq!(
                hex_swap,
                String::from(concat!(
                    // token in
                    "40D16FC0246aD3160Ccc09B8D0D3A2cD28aE6C2f",
                    // pool
                    "14Cf6D2Fe3E1B326114b07d22A6F6bb59e346c67",
                    // receiver
                    "9964bff29baa37b47604f3f3f51f3b3c5149d6de",
                    // transfer true
                    "01",
                ))
                .to_lowercase()
            );

            write_calldata_to_file("test_encode_maverick_v2", hex_swap.as_str());
        }
    }

    mod bebop {
        use num_bigint::BigUint;

        use super::*;
        use crate::encoding::evm::testing_utils::MockRFQState;

        fn bebop_config() -> HashMap<String, String> {
            HashMap::from([
                (
                    "bebop_settlement_address".to_string(),
                    "0xbbbbbBB520d69a9775E85b458C58c648259FAD5F".to_string(),
                ),
                (
                    "native_token_address".to_string(),
                    "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE".to_string(),
                ),
            ])
        }

        #[test]
        fn test_encode_bebop_single_with_protocol_state() {
            // 3000 USDC -> 1 WETH using a mocked RFQ state to get a quote
            let bebop_calldata = Bytes::from_str("0x123456").unwrap();
            let partial_fill_offset = 12u64;
            let quote_amount_out = BigUint::from_str("1000000000000000000").unwrap();

            let bebop_component = ProtocolComponent {
                id: String::from("bebop-rfq"),
                protocol_system: String::from("rfq:bebop"),
                ..Default::default()
            };
            let bebop_state = MockRFQState {
                quote_amount_out,
                quote_data: HashMap::from([
                    ("calldata".to_string(), bebop_calldata.clone()),
                    (
                        "partial_fill_offset".to_string(),
                        Bytes::from(
                            partial_fill_offset
                                .to_be_bytes()
                                .to_vec(),
                        ),
                    ),
                ]),
            };

            let token_in = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // USDC
            let token_out = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"); // WETH

            let swap = SwapBuilder::new(bebop_component, token_in.clone(), token_out.clone())
                .estimated_amount_in(BigUint::from_str("3000000000").unwrap())
                .protocol_state(Arc::new(bebop_state))
                .build();

            let encoding_context = EncodingContext {
                receiver: Bytes::from("0xc5564C13A157E6240659fb81882A28091add8670"),
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };

            let encoder = BebopSwapEncoder::new(
                Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                Chain::Ethereum,
                Some(bebop_config()),
            )
            .unwrap();

            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            let expected_swap = String::from(concat!(
                // token in
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                // token out
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                // transfer type
                "01",
                // partiall filled offset
                "0c",
                //  original taker amount
                "0000000000000000000000000000000000000000000000000de0b6b3a7640000",
                // approval needed
                "01",
                //receiver,
                "c5564c13a157e6240659fb81882a28091add8670",
            ));
            assert_eq!(hex_swap, expected_swap + &bebop_calldata.to_string()[2..]);
        }
    }

    mod hashflow {
        use alloy::hex::encode;
        use num_bigint::BigUint;

        use super::*;
        use crate::encoding::{
            evm::testing_utils::MockRFQState,
            models::{SwapBuilder, TransferType},
        };

        fn hashflow_config() -> Option<HashMap<String, String>> {
            Some(HashMap::from([(
                "hashflow_router_address".to_string(),
                "0x55084eE0fEf03f14a305cd24286359A35D735151".to_string(),
            )]))
        }

        #[test]
        fn test_encode_hashflow_single_fails_without_protocol_data() {
            // Hashflow requires a swap with protocol data, otherwise will return an error
            let hashflow_component = ProtocolComponent {
                id: String::from("hashflow-rfq"),
                protocol_system: String::from("rfq:hashflow"),
                ..Default::default()
            };

            let token_in = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // USDC
            let token_out = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"); // WETH

            let swap = SwapBuilder::new(hashflow_component, token_in.clone(), token_out.clone())
                .estimated_amount_in(BigUint::from_str("3000000000").unwrap())
                .build();

            let encoding_context = EncodingContext {
                receiver: Bytes::from("0xc5564C13A157E6240659fb81882A28091add8670"),
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };

            let encoder = HashflowSwapEncoder::new(
                Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                Chain::Ethereum,
                hashflow_config(),
            )
            .unwrap();
            encoder
                .encode_swap(&swap, &encoding_context)
                .expect_err("Should returned an error if the swap has no protocol state");
        }

        #[test]
        fn test_encode_hashflow_single_with_protocol_state() {
            // 3000 USDC -> 1 WETH using a mocked RFQ state to get a quote
            let quote_amount_out = BigUint::from_str("1000000000000000000").unwrap();

            let hashflow_component = ProtocolComponent {
                id: String::from("hashflow-rfq"),
                protocol_system: String::from("rfq:hashflow"),
                ..Default::default()
            };
            let hashflow_quote_data = vec![
                (
                    "pool".to_string(),
                    Bytes::from_str("0x478eca1b93865dca0b9f325935eb123c8a4af011").unwrap(),
                ),
                (
                    "external_account".to_string(),
                    Bytes::from_str("0xbee3211ab312a8d065c4fef0247448e17a8da000").unwrap(),
                ),
                (
                    "trader".to_string(),
                    Bytes::from_str("0xcd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2").unwrap(),
                ),
                (
                    "base_token".to_string(),
                    Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
                ),
                (
                    "quote_token".to_string(),
                    Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap(),
                ),
                (
                    "base_token_amount".to_string(),
                    Bytes::from(biguint_to_u256(&BigUint::from(3000_u64)).to_be_bytes::<32>().to_vec()),
                ),
                (
                    "quote_token_amount".to_string(),
                    Bytes::from(biguint_to_u256(&BigUint::from(1_u64)).to_be_bytes::<32>().to_vec()),
                ),
                ("quote_expiry".to_string(), Bytes::from(biguint_to_u256(&BigUint::from(1755610328_u64)).to_be_bytes::<32>().to_vec())),
                ("nonce".to_string(), Bytes::from(biguint_to_u256(&BigUint::from(1755610283723_u64)).to_be_bytes::<32>().to_vec())),
                (
                    "tx_id".to_string(),
                    Bytes::from_str(
                        "0x125000064000640000001747eb8c38ffffffffffffff0029642016edb36d0000",
                    )
                        .unwrap(),
                ),
                ("signature".to_string(), Bytes::from_str("0x6ddb3b21fe8509e274ddf46c55209cdbf30360944abbca6569ed6b26740d052f419964dcb5a3bdb98b4ed1fb3642a2760b8312118599a962251f7a8f73fe4fbe1c").unwrap()),
            ];
            let hashflow_quote_data_values =
                hashflow_quote_data
                    .iter()
                    .fold(vec![], |mut acc, (_key, value)| {
                        acc.extend_from_slice(value);
                        acc
                    });
            let hashflow_calldata = Bytes::from(hashflow_quote_data_values);
            let hashflow_state = MockRFQState {
                quote_amount_out,
                quote_data: hashflow_quote_data
                    .into_iter()
                    .collect(),
            };

            let token_in = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // USDC
            let token_out = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"); // WETH

            let swap = SwapBuilder::new(hashflow_component, token_in.clone(), token_out.clone())
                .estimated_amount_in(BigUint::from_str("3000000000").unwrap())
                .protocol_state(Arc::new(hashflow_state))
                .build();

            let encoding_context = EncodingContext {
                receiver: Bytes::from("0xc5564C13A157E6240659fb81882A28091add8670"),
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };

            let encoder = HashflowSwapEncoder::new(
                Bytes::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                Chain::Ethereum,
                hashflow_config(),
            )
            .unwrap();

            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            let expected_swap = String::from(concat!(
                "01", // transfer type
                "01", // approval needed
            ));
            assert_eq!(hex_swap, expected_swap + &hashflow_calldata.to_string()[2..]);
        }
    }

    mod fluid_v1 {
        use super::*;
        #[test]
        fn test_encode_fluid_v1() {
            // sUSDe -> (fluid_v1) -> USDT
            let fluid_dex = ProtocolComponent {
                id: String::from("0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b"),
                protocol_system: String::from("fluid_v1"),
                ..Default::default()
            };
            let token_in = Bytes::from("0x9d39a5de30e57443bff2a8307a4256c8797a3497");
            let token_out = Bytes::from("0xdac17f958d2ee523a2206206994597c13d831ec7");
            let swap = SwapBuilder::new(fluid_dex, token_in.clone(), token_out.clone()).build();
            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob*") using forge`
                receiver: Bytes::from("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de"),
                exact_out: false,
                router_address: Some(Bytes::default()),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::TransferFrom,
                historical_trade: false,
            };
            let encoder = FluidV1SwapEncoder::new(
                Bytes::from("0x212224D2F2d262cd093eE13240ca4873fcCBbA3C"),
                Chain::Ethereum,
                None,
            )
            .unwrap();

            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            assert_eq!(
                hex_swap,
                String::from(concat!(
                    // dex
                    "1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b",
                    // zero2one
                    "01",
                    // receiver
                    "9964bff29baa37b47604f3f3f51f3b3c5149d6de",
                    // transferFrom
                    "00",
                    // isNativeSell
                    "00"
                ))
                .to_lowercase()
            );
        }
    }

    mod rocketpool {
        use super::*;
        #[test]
        fn test_encode_rocketpool() {
            // ETH -> (rocketpool) -> rETH
            let rocketpool_pool = ProtocolComponent {
                id: String::from("0xdd3f50f8a6cafbe9b31a427582963f465e745af8"),
                protocol_system: String::from("rocketpool"),
                ..Default::default()
            };
            let token_in = Bytes::from("0x0000000000000000000000000000000000000000");
            let token_out = Bytes::from("0xae78736Cd615f374D3085123A210448E74Fc6393");
            let swap =
                SwapBuilder::new(rocketpool_pool, token_in.clone(), token_out.clone()).build();
            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob") using forge`
                receiver: Bytes::from("0x1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e"),
                exact_out: false,
                router_address: Some(Bytes::default()),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
                historical_trade: false,
            };
            let encoder = RocketpoolSwapEncoder::new(
                Bytes::from("0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"),
                Chain::Ethereum,
                None,
            )
            .unwrap();

            let encoded_swap = encoder
                .encode_swap(&swap, &encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            assert_eq!(
                hex_swap,
                String::from(concat!(
                    // is deposit
                    "01",
                    // transfer type
                    "01",
                    // receiver
                    "1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e",
                ))
                .to_lowercase()
            );

            write_calldata_to_file("test_encode_rocketpool", hex_swap.as_str());
        }
    }
}

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use alloy::{
    core::sol,
    primitives::{Address, Bytes as AlloyBytes, U256, U8},
    sol_types::SolValue,
};
use serde_json::from_str;
use tycho_common::Bytes;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        approvals::protocol_approvals_manager::ProtocolApprovalsManager,
        utils::{bytes_to_address, get_static_attribute, pad_to_fixed_size},
    },
    models::{BebopOrderType, Chain, EncodingContext, Swap},
    swap_encoder::SwapEncoder,
};

/// Encodes a swap on a Uniswap V2 pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
#[derive(Clone)]
pub struct UniswapV2SwapEncoder {
    executor_address: String,
}

impl UniswapV2SwapEncoder {
    fn get_zero_to_one(sell_token_address: Address, buy_token_address: Address) -> bool {
        sell_token_address < buy_token_address
    }
}

impl SwapEncoder for UniswapV2SwapEncoder {
    fn new(
        executor_address: String,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self { executor_address })
    }

    fn encode_swap(
        &self,
        swap: Swap,
        encoding_context: EncodingContext,
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

    fn executor_address(&self) -> &str {
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
    executor_address: String,
}

impl UniswapV3SwapEncoder {
    fn get_zero_to_one(sell_token_address: Address, buy_token_address: Address) -> bool {
        sell_token_address < buy_token_address
    }
}

impl SwapEncoder for UniswapV3SwapEncoder {
    fn new(
        executor_address: String,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self { executor_address })
    }

    fn encode_swap(
        &self,
        swap: Swap,
        encoding_context: EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_in_address = bytes_to_address(&swap.token_in)?;
        let token_out_address = bytes_to_address(&swap.token_out)?;

        let zero_to_one = Self::get_zero_to_one(token_in_address, token_out_address);
        let component_id = Address::from_str(&swap.component.id)
            .map_err(|_| EncodingError::FatalError("Invalid USV3 component id".to_string()))?;
        let pool_fee_bytes = get_static_attribute(&swap, "fee")?;

        let pool_fee_u24 = pad_to_fixed_size::<3>(&pool_fee_bytes)
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

    fn executor_address(&self) -> &str {
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
    executor_address: String,
}

impl UniswapV4SwapEncoder {
    fn get_zero_to_one(sell_token_address: Address, buy_token_address: Address) -> bool {
        sell_token_address < buy_token_address
    }
}

impl SwapEncoder for UniswapV4SwapEncoder {
    fn new(
        executor_address: String,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self { executor_address })
    }

    fn encode_swap(
        &self,
        swap: Swap,
        encoding_context: EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let fee = get_static_attribute(&swap, "key_lp_fee")?;

        let pool_fee_u24 = pad_to_fixed_size::<3>(&fee)
            .map_err(|_| EncodingError::FatalError("Failed to pad fee bytes".to_string()))?;

        let tick_spacing = get_static_attribute(&swap, "tick_spacing")?;

        let pool_tick_spacing_u24 = pad_to_fixed_size::<3>(&tick_spacing).map_err(|_| {
            EncodingError::FatalError("Failed to pad tick spacing bytes".to_string())
        })?;

        // Early check if this is not the first swap
        if encoding_context.group_token_in != swap.token_in {
            return Ok((bytes_to_address(&swap.token_out)?, pool_fee_u24, pool_tick_spacing_u24)
                .abi_encode_packed());
        }

        // This is the first swap, compute all necessary values
        let token_in_address = bytes_to_address(&swap.token_in)?;
        let token_out_address = bytes_to_address(&swap.token_out)?;
        let group_token_in_address = bytes_to_address(&encoding_context.group_token_in)?;
        let group_token_out_address = bytes_to_address(&encoding_context.group_token_out)?;

        let zero_to_one = Self::get_zero_to_one(token_in_address, token_out_address);

        let pool_params =
            (token_out_address, pool_fee_u24, pool_tick_spacing_u24).abi_encode_packed();

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

    fn executor_address(&self) -> &str {
        &self.executor_address
    }

    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

/// Encodes a swap on a Balancer V2 pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
/// * `vault_address` - The address of the vault contract that will perform the swap.
#[derive(Clone)]
pub struct BalancerV2SwapEncoder {
    executor_address: String,
    vault_address: String,
}

impl SwapEncoder for BalancerV2SwapEncoder {
    fn new(
        executor_address: String,
        _chain: Chain,
        config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        let config = config.ok_or(EncodingError::FatalError(
            "Missing balancer v2 specific addresses in config".to_string(),
        ))?;
        let vault_address = config
            .get("vault_address")
            .ok_or(EncodingError::FatalError(
                "Missing balancer v2 vault address in config".to_string(),
            ))?
            .to_string();
        Ok(Self { executor_address, vault_address })
    }

    fn encode_swap(
        &self,
        swap: Swap,
        encoding_context: EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_approvals_manager = ProtocolApprovalsManager::new()?;
        let token = bytes_to_address(&swap.token_in)?;
        let approval_needed: bool;

        if let Some(router_address) = encoding_context.router_address {
            let tycho_router_address = bytes_to_address(&router_address)?;
            approval_needed = token_approvals_manager.approval_needed(
                token,
                tycho_router_address,
                Address::from_str(&self.vault_address)
                    .map_err(|_| EncodingError::FatalError("Invalid vault address".to_string()))?,
            )?;
        } else {
            approval_needed = true;
        }

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

    fn executor_address(&self) -> &str {
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
    executor_address: String,
}

impl SwapEncoder for EkuboSwapEncoder {
    fn new(
        executor_address: String,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self { executor_address })
    }

    fn encode_swap(
        &self,
        swap: Swap,
        encoding_context: EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        if encoding_context.exact_out {
            return Err(EncodingError::InvalidInput("exact out swaps not implemented".to_string()));
        }

        let fee = u64::from_be_bytes(
            get_static_attribute(&swap, "fee")?
                .try_into()
                .map_err(|_| EncodingError::FatalError("fee should be an u64".to_string()))?,
        );

        let tick_spacing = u32::from_be_bytes(
            get_static_attribute(&swap, "tick_spacing")?
                .try_into()
                .map_err(|_| {
                    EncodingError::FatalError("tick_spacing should be an u32".to_string())
                })?,
        );

        let extension: Address = get_static_attribute(&swap, "extension")?
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

    fn executor_address(&self) -> &str {
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
    executor_address: String,
    native_token_curve_address: String,
    native_token_address: Bytes,
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

    fn get_coin_indexes(
        &self,
        swap: Swap,
        token_in: Address,
        token_out: Address,
    ) -> Result<(U8, U8), EncodingError> {
        let coins_bytes = get_static_attribute(&swap, "coins")?;
        let coins: Vec<Address> = from_str(std::str::from_utf8(&coins_bytes)?)?;
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
                "Token in address {token_in} not found in curve pool coins"
            )))?;
        Ok((U8::from(i), U8::from(j)))
    }
}

impl SwapEncoder for CurveSwapEncoder {
    fn new(
        executor_address: String,
        chain: Chain,
        config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        let config = config.ok_or(EncodingError::FatalError(
            "Missing curve specific addresses in config".to_string(),
        ))?;
        let native_token_curve_address = config
            .get("native_token_address")
            .ok_or(EncodingError::FatalError(
                "Missing native token curve address in config".to_string(),
            ))?
            .to_string();
        Ok(Self {
            executor_address,
            native_token_address: chain.native_token()?,
            native_token_curve_address,
        })
    }

    fn encode_swap(
        &self,
        swap: Swap,
        encoding_context: EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_approvals_manager = ProtocolApprovalsManager::new()?;
        let native_token_curve_address = Address::from_str(&self.native_token_curve_address)
            .map_err(|_| {
                EncodingError::FatalError("Invalid Curve native token curve address".to_string())
            })?;
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
        if let Some(router_address) = encoding_context.router_address {
            if token_in != native_token_curve_address {
                let tycho_router_address = bytes_to_address(&router_address)?;
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

        let factory_bytes = get_static_attribute(&swap, "factory")?.to_vec();
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

    fn executor_address(&self) -> &str {
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
    executor_address: String,
}

impl SwapEncoder for MaverickV2SwapEncoder {
    fn new(
        executor_address: String,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self { executor_address })
    }

    fn encode_swap(
        &self,
        swap: Swap,
        encoding_context: EncodingContext,
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

    fn executor_address(&self) -> &str {
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
    executor_address: String,
}

impl SwapEncoder for BalancerV3SwapEncoder {
    fn new(
        executor_address: String,
        _chain: Chain,
        _config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        Ok(Self { executor_address })
    }

    fn encode_swap(
        &self,
        swap: Swap,
        encoding_context: EncodingContext,
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

    fn executor_address(&self) -> &str {
        &self.executor_address
    }

    fn clone_box(&self) -> Box<dyn SwapEncoder> {
        Box::new(self.clone())
    }
}

// Define Bebop order structures for ABI decoding
sol! {
    struct BebopSingle {
        uint256 expiry;
        address taker_address;
        address maker_address;
        uint256 maker_nonce;
        address taker_token;
        address maker_token;
        uint256 taker_amount;
        uint256 maker_amount;
        address receiver;
        uint256 packed_commands;
        uint256 flags;
    }

    struct BebopAggregate {
        uint256 expiry;
        address taker_address;
        address[] maker_addresses;
        uint256[] maker_nonces;
        address[][] taker_tokens;
        address[][] maker_tokens;
        uint256[][] taker_amounts;
        uint256[][] maker_amounts;
        address receiver;
        bytes commands;
        uint256 flags;
    }
}

/// Encodes a swap on Bebop (PMM RFQ) through the given executor address.
///
/// Bebop uses a Request-for-Quote model where quotes are obtained off-chain
/// and settled on-chain. This encoder supports PMM RFQ execution.
///
/// # Signature Encoding
/// Bebop aggregate orders use concatenated 65-byte ECDSA signatures without length prefixes.
/// Each signature is exactly 65 bytes: r (32) + s (32) + v (1).
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
/// * `settlement_address` - The address of the Bebop settlement contract.
#[derive(Clone)]
pub struct BebopSwapEncoder {
    executor_address: String,
    settlement_address: String,
}

impl BebopSwapEncoder {
    /// Validates the component ID format
    /// Component format: "bebop-rfq"
    fn validate_component_id(component_id: &str) -> Result<(), EncodingError> {
        if component_id != "bebop-rfq" {
            return Err(EncodingError::FatalError(
                "Invalid Bebop component ID format. Expected 'bebop-rfq'".to_string(),
            ));
        }
        Ok(())
    }

    /// Analyzes the quote to determine token input/output characteristics
    /// Returns (has_many_inputs, has_many_outputs)
    fn validate_aggregate_order(
        &self,
        quote_data: &[u8],
        expected_token_out: &Address,
    ) -> Result<(), EncodingError> {
        // Decode the Aggregate order to validate
        let order = BebopAggregate::abi_decode(quote_data).map_err(|e| {
            EncodingError::InvalidInput(format!("Failed to decode Bebop Aggregate order: {}", e))
        })?;

        // Validate that we only have one unique input token across all makers
        let unique_taker_tokens: HashSet<_> = order
            .taker_tokens
            .iter()
            .flat_map(|tokens| tokens.iter())
            .collect();

        if unique_taker_tokens.len() != 1 {
            return Err(EncodingError::InvalidInput(
                "Aggregate orders must have exactly one unique input token across all makers"
                    .to_string(),
            ));
        }

        // Validate that all makers provide exactly one output token
        for (i, maker_tokens) in order.maker_tokens.iter().enumerate() {
            if maker_tokens.len() != 1 {
                return Err(EncodingError::InvalidInput(format!(
                    "Maker {} must provide exactly one output token, found {}",
                    i,
                    maker_tokens.len()
                )));
            }
        }

        // Validate that all makers provide the same output token
        let all_same_output = order
            .maker_tokens
            .iter()
            .flat_map(|maker_tokens| maker_tokens.iter())
            .all(|token| token == expected_token_out);

        if !all_same_output {
            return Err(EncodingError::InvalidInput(
                "All makers must provide the same output token".to_string(),
            ));
        }

        Ok(())
    }
}

impl SwapEncoder for BebopSwapEncoder {
    fn new(
        executor_address: String,
        _chain: Chain,
        config: Option<HashMap<String, String>>,
    ) -> Result<Self, EncodingError> {
        let config = config.ok_or(EncodingError::FatalError(
            "Missing bebop specific addresses in config".to_string(),
        ))?;
        let settlement_address = config
            .get("bebop_settlement_address")
            .ok_or(EncodingError::FatalError(
                "Missing bebop settlement address in config".to_string(),
            ))?
            .to_string();
        Ok(Self { executor_address, settlement_address })
    }

    fn encode_swap(
        &self,
        swap: Swap,
        encoding_context: EncodingContext,
    ) -> Result<Vec<u8>, EncodingError> {
        let token_in = bytes_to_address(&swap.token_in)?;
        let token_out = bytes_to_address(&swap.token_out)?;

        let token_approvals_manager = ProtocolApprovalsManager::new()?;
        let approval_needed: bool;

        if let Some(router_address) = encoding_context.router_address {
            let tycho_router_address = bytes_to_address(&router_address)?;
            let token_to_approve = token_in.clone();
            let settlement_address = Address::from_str(&self.settlement_address)
                .map_err(|_| EncodingError::FatalError("Invalid settlement address".to_string()))?;

            // Native ETH doesn't need approval, only ERC20 tokens do
            if token_to_approve == Address::ZERO {
                approval_needed = false;
            } else {
                approval_needed = token_approvals_manager.approval_needed(
                    token_to_approve,
                    tycho_router_address,
                    settlement_address,
                )?;
            }
        } else {
            approval_needed = true;
        }

        // Validate component ID
        Self::validate_component_id(&swap.component.id)?;

        // Extract data from user_data (required for Bebop)
        let user_data = swap.user_data.ok_or_else(|| {
            EncodingError::InvalidInput(
                "Bebop swaps require user_data with quote and signature".to_string(),
            )
        })?;

        // Parse user_data format:
        // order_type (1 byte) | filledTakerAmount (32 bytes) | quote_data_length (4 bytes) |
        // quote_data | abi_encoded_maker_signatures where abi_encoded_maker_signatures is
        // abi.encode(MakerSignature[])
        if user_data.len() < 37 {
            return Err(EncodingError::InvalidInput(
                "User data too short to contain Bebop RFQ data".to_string(),
            ));
        }

        let order_type = BebopOrderType::try_from(user_data[0])?;

        // Extract filledTakerAmount (32 bytes)
        let filled_taker_amount = U256::from_be_slice(&user_data[1..33]);

        let quote_data_len =
            u32::from_be_bytes([user_data[33], user_data[34], user_data[35], user_data[36]])
                as usize;
        if user_data.len() < 37 + quote_data_len {
            return Err(EncodingError::InvalidInput(
                "User data too short to contain quote data".to_string(),
            ));
        }

        let quote_data = user_data[37..37 + quote_data_len].to_vec();

        // Validate Aggregate orders have single token in/out
        if order_type == BebopOrderType::Aggregate {
            self.validate_aggregate_order(&quote_data, &token_out)?;
        }

        // Decode the ABI-encoded MakerSignature[] array
        let maker_sigs_start = 37 + quote_data_len;
        let remaining_data = &user_data[maker_sigs_start..];

        // Need at least 64 bytes for offset (32) and array length (32)
        if remaining_data.len() < 64 {
            return Err(EncodingError::InvalidInput(
                "User data too short to contain MakerSignature array".to_string(),
            ));
        }

        // Read offset to array (should be 0x20 for single parameter)
        let array_offset: usize = U256::from_be_slice(&remaining_data[0..32])
            .try_into()
            .map_err(|_| EncodingError::InvalidInput("Array offset too large".to_string()))?;

        if array_offset != 32 {
            return Err(EncodingError::InvalidInput(
                "Invalid array offset in ABI encoding".to_string(),
            ));
        }

        // Read array length
        let array_length: usize = U256::from_be_slice(&remaining_data[32..64])
            .try_into()
            .map_err(|_| EncodingError::InvalidInput("Array length too large".to_string()))?;

        // Validate signature count based on order type
        match order_type {
            BebopOrderType::Single => {
                if array_length != 1 {
                    return Err(EncodingError::InvalidInput(format!(
                        "Expected 1 signature for Single order, got {}",
                        array_length
                    )));
                }
            }
            BebopOrderType::Aggregate => {
                if array_length == 0 {
                    return Err(EncodingError::InvalidInput(
                        "Aggregate order requires at least one signature".to_string(),
                    ));
                }
            }
        }

        // For aggregate orders, we just pass through the entire ABI-encoded array
        // For single orders, we validate and re-encode
        let maker_sigs_encoded = if order_type == BebopOrderType::Aggregate {
            // For aggregate orders, pass through the entire encoded array
            remaining_data.to_vec()
        } else {
            // For single orders, validate and re-encode the single signature
            // Read offset to first (and only) struct
            if remaining_data.len() < 96 {
                return Err(EncodingError::InvalidInput(
                    "User data too short to contain struct offset".to_string(),
                ));
            }

            let struct_offset: usize = U256::from_be_slice(&remaining_data[64..96])
                .try_into()
                .map_err(|_| EncodingError::InvalidInput("Struct offset too large".to_string()))?;

            // The struct data starts at the struct_offset
            // struct_offset is relative to the start of array data (after the array length)
            // Array data starts at position 64 (after offset[32] and length[32])
            // Absolute position = 64 + struct_offset
            let struct_start = 64 + struct_offset;

            if remaining_data.len() < struct_start + 64 {
                return Err(EncodingError::InvalidInput(
                    "User data too short to contain MakerSignature struct".to_string(),
                ));
            }

            // Read the struct fields
            // - offset to signatureBytes (32 bytes) - should be 64
            // - flags (32 bytes)
            let sig_offset: usize =
                U256::from_be_slice(&remaining_data[struct_start..struct_start + 32])
                    .try_into()
                    .map_err(|_| {
                        EncodingError::InvalidInput("Signature offset too large".to_string())
                    })?;

            if sig_offset != 64 {
                return Err(EncodingError::InvalidInput(format!(
                    "Invalid signature offset in struct: expected 64, got {}",
                    sig_offset
                )));
            }

            let flags = U256::from_be_slice(&remaining_data[struct_start + 32..struct_start + 64]);

            // Read signature data
            let sig_data_start = struct_start + sig_offset;
            if remaining_data.len() < sig_data_start + 32 {
                return Err(EncodingError::InvalidInput(
                    "User data too short to contain signature length".to_string(),
                ));
            }

            let signature_len: usize =
                U256::from_be_slice(&remaining_data[sig_data_start..sig_data_start + 32])
                    .try_into()
                    .map_err(|_| {
                        EncodingError::InvalidInput("Signature length too large".to_string())
                    })?;

            if remaining_data.len() < sig_data_start + 32 + signature_len {
                return Err(EncodingError::InvalidInput(
                    "User data too short to contain signature data".to_string(),
                ));
            }

            let signature =
                remaining_data[sig_data_start + 32..sig_data_start + 32 + signature_len].to_vec();

            // Re-encode the MakerSignature[] array for the executor
            let mut encoded = Vec::new();

            // Offset to array (always 0x20 for single parameter)
            encoded.extend_from_slice(&U256::from(32).to_be_bytes::<32>());

            // Array length (1 for non-aggregate orders)
            encoded.extend_from_slice(&U256::from(1).to_be_bytes::<32>());

            // Offset to first struct (relative to array data start)
            let struct_offset = 32; // After the array length
            encoded.extend_from_slice(&U256::from(struct_offset).to_be_bytes::<32>());

            // Struct data
            // - offset to signatureBytes (always 64)
            encoded.extend_from_slice(&U256::from(64).to_be_bytes::<32>());

            // - flags
            encoded.extend_from_slice(&flags.to_be_bytes::<32>());

            // - signatureBytes length
            encoded.extend_from_slice(&U256::from(signature.len()).to_be_bytes::<32>());

            // - signatureBytes data (padded)
            encoded.extend_from_slice(&signature);
            let padding = (32 - (signature.len() % 32)) % 32;
            encoded.extend_from_slice(&vec![0u8; padding]);

            encoded
        };

        // Encode packed data for the executor
        // Format: token_in | token_out | transfer_type | order_type | filledTakerAmount |
        //         quote_data_length | quote_data | maker_signatures_length |
        //         abi_encoded_maker_signatures | approval_needed
        let args = (
            token_in,
            token_out,
            (encoding_context.transfer_type as u8).to_be_bytes(),
            (order_type as u8).to_be_bytes(),
            filled_taker_amount.to_be_bytes::<32>(),
            (quote_data.len() as u32).to_be_bytes(),
            &quote_data[..],
            (maker_sigs_encoded.len() as u32).to_be_bytes(),
            &maker_sigs_encoded[..],
            (approval_needed as u8).to_be_bytes(),
        );

        Ok(args.abi_encode_packed())
    }

    fn executor_address(&self) -> &str {
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
        models::{protocol::ProtocolComponent, Chain as TychoCoreChain},
        Bytes,
    };

    use super::*;
    use crate::encoding::{evm::utils::write_calldata_to_file, models::TransferType};

    mod uniswap_v2 {
        use super::*;
        #[test]
        fn test_encode_uniswap_v2() {
            let usv2_pool = ProtocolComponent {
                id: String::from("0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11"),
                ..Default::default()
            };

            let token_in = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
            let token_out = Bytes::from("0x6b175474e89094c44da98b954eedeac495271d0f");
            let swap = Swap {
                component: usv2_pool,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
                user_data: None,
            };
            let encoding_context = EncodingContext {
                receiver: Bytes::from("0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e"), // BOB
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
            };
            let encoder = UniswapV2SwapEncoder::new(
                String::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                TychoCoreChain::Ethereum.into(),
                None,
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(swap, encoding_context)
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
                    "1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e",
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
            let swap = Swap {
                component: usv3_pool,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
                user_data: None,
            };
            let encoding_context = EncodingContext {
                receiver: Bytes::from("0x0000000000000000000000000000000000000001"),
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
            };
            let encoder = UniswapV3SwapEncoder::new(
                String::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                TychoCoreChain::Ethereum.into(),
                None,
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(swap, encoding_context)
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
            let swap = Swap {
                component: balancer_pool,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
                user_data: None,
            };
            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob") using forge`
                receiver: Bytes::from("0x1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e"),
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::None,
            };
            let encoder = BalancerV2SwapEncoder::new(
                String::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                TychoCoreChain::Ethereum.into(),
                Some(HashMap::from([(
                    "vault_address".to_string(),
                    "0xba12222222228d8ba445958a75a0704d566bf2c8".to_string(),
                )])),
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(swap, encoding_context)
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
                    "1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e",
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
        use crate::encoding::evm::utils::write_calldata_to_file;

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
            let swap = Swap {
                component: usv4_pool,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
                user_data: None,
            };
            let encoding_context = EncodingContext {
                // The receiver is ALICE to match the solidity tests
                receiver: Bytes::from("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2"),
                exact_out: false,
                // Same as the executor address
                router_address: Some(Bytes::from("0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f")),

                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
            };
            let encoder = UniswapV4SwapEncoder::new(
                String::from("0xF62849F9A0B5Bf2913b396098F7c7019b51A820a"),
                TychoCoreChain::Ethereum.into(),
                None,
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(swap, encoding_context)
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
                    "000001"
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

            let swap = Swap {
                component: usv4_pool,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
                user_data: None,
            };

            let encoding_context = EncodingContext {
                receiver: Bytes::from("0x0000000000000000000000000000000000000001"),
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: group_token_in.clone(),
                // Token out is the same as the group token out
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
            };

            let encoder = UniswapV4SwapEncoder::new(
                String::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                TychoCoreChain::Ethereum.into(),
                None,
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(swap, encoding_context)
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
                    "00003c"
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

            let initial_swap = Swap {
                component: usde_usdt_component,
                token_in: usde_address.clone(),
                token_out: usdt_address.clone(),
                split: 0f64,
                user_data: None,
            };

            let second_swap = Swap {
                component: usdt_wbtc_component,
                token_in: usdt_address,
                token_out: wbtc_address.clone(),
                split: 0f64,
                user_data: None,
            };

            let encoder = UniswapV4SwapEncoder::new(
                String::from("0xF62849F9A0B5Bf2913b396098F7c7019b51A820a"),
                TychoCoreChain::Ethereum.into(),
                None,
            )
            .unwrap();
            let initial_encoded_swap = encoder
                .encode_swap(initial_swap, context.clone())
                .unwrap();
            let second_encoded_swap = encoder
                .encode_swap(second_swap, context)
                .unwrap();

            let combined_hex =
                format!("{}{}", encode(&initial_encoded_swap), encode(&second_encoded_swap));

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
                    // - intermediary token WBTC
                    "2260fac5e5542a773aa44fbcfedf7c193bc2c599",
                    // - fee
                    "000bb8",
                    // - tick spacing
                    "00003c"
                ))
            );
            write_calldata_to_file("test_encode_uniswap_v4_sequential_swap", combined_hex.as_str());
        }
    }
    mod ekubo {
        use super::*;
        use crate::encoding::evm::utils::write_calldata_to_file;

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

            let swap = Swap {
                component,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
                user_data: None,
            };

            let encoding_context = EncodingContext {
                receiver: RECEIVER.into(),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                exact_out: false,
                router_address: Some(Bytes::default()),
                transfer_type: TransferType::Transfer,
            };

            let encoder =
                EkuboSwapEncoder::new(String::default(), TychoCoreChain::Ethereum.into(), None)
                    .unwrap();

            let encoded_swap = encoder
                .encode_swap(swap, encoding_context)
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

            let encoder =
                EkuboSwapEncoder::new(String::default(), TychoCoreChain::Ethereum.into(), None)
                    .unwrap();

            let encoding_context = EncodingContext {
                receiver: RECEIVER.into(),
                group_token_in: group_token_in.clone(),
                group_token_out: group_token_out.clone(),
                exact_out: false,
                router_address: Some(Bytes::default()),
                transfer_type: TransferType::Transfer,
            };

            let first_swap = Swap {
                component: ProtocolComponent {
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
                token_in: group_token_in.clone(),
                token_out: intermediary_token.clone(),
                split: 0f64,
                user_data: None,
            };

            let second_swap = Swap {
                component: ProtocolComponent {
                    // 0.0025% fee & 0.005% base pool
                    static_attributes: HashMap::from([
                        ("fee".to_string(), Bytes::from(461168601842738_u64)),
                        ("tick_spacing".to_string(), Bytes::from(50_u32)),
                        ("extension".to_string(), Bytes::zero(20)),
                    ]),
                    ..Default::default()
                },
                token_in: intermediary_token.clone(),
                token_out: group_token_out.clone(),
                split: 0f64,
                user_data: None,
            };

            let first_encoded_swap = encoder
                .encode_swap(first_swap, encoding_context.clone())
                .unwrap();

            let second_encoded_swap = encoder
                .encode_swap(second_swap, encoding_context)
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
            let swap = Swap {
                component: ProtocolComponent {
                    id: "pool-id".into(),
                    protocol_system: String::from("vm:curve"),
                    static_attributes,
                    ..Default::default()
                },
                token_in: Bytes::from(token_in),
                token_out: Bytes::from(token_out),
                split: 0f64,
                user_data: None,
            };
            let encoder = CurveSwapEncoder::new(
                String::default(),
                TychoCoreChain::Ethereum.into(),
                curve_config(),
            )
            .unwrap();
            let (i, j) = encoder
                .get_coin_indexes(
                    swap,
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
            let swap = Swap {
                component: curve_tri_pool,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
                user_data: None,
            };
            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob") using forge`
                receiver: Bytes::from("0x1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e"),
                exact_out: false,
                router_address: None,
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::None,
            };
            let encoder = CurveSwapEncoder::new(
                String::from("0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f"),
                TychoCoreChain::Ethereum.into(),
                curve_config(),
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(swap, encoding_context)
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
                    "1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e",
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
            let swap = Swap {
                component: curve_pool,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
                user_data: None,
            };
            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob") using forge`
                receiver: Bytes::from("0x1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e"),
                exact_out: false,
                router_address: None,
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::None,
            };
            let encoder = CurveSwapEncoder::new(
                String::from("0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f"),
                TychoCoreChain::Ethereum.into(),
                curve_config(),
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(swap, encoding_context)
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
                    "1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e",
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
            let swap = Swap {
                component: curve_pool,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
                user_data: None,
            };
            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob") using forge`
                receiver: Bytes::from("0x1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e"),
                exact_out: false,
                router_address: None,
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::None,
            };
            let encoder = CurveSwapEncoder::new(
                String::from("0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f"),
                TychoCoreChain::Ethereum.into(),
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
                .encode_swap(swap, encoding_context)
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
                    "1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e",
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
            let swap = Swap {
                component: balancer_pool,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
                user_data: None,
            };
            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob") using forge`
                receiver: Bytes::from("0x1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e"),
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
            };
            let encoder = BalancerV3SwapEncoder::new(
                String::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                TychoCoreChain::Ethereum.into(),
                None,
            )
            .unwrap();
            let encoded_swap = encoder
                .encode_swap(swap, encoding_context)
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
                    "1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e",
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
            let swap = Swap {
                component: maverick_pool,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
                user_data: None,
            };
            let encoding_context = EncodingContext {
                // The receiver was generated with `makeAddr("bob") using forge`
                receiver: Bytes::from("0x1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e"),
                exact_out: false,
                router_address: Some(Bytes::default()),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
            };
            let encoder = MaverickV2SwapEncoder::new(
                String::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                TychoCoreChain::Ethereum.into(),
                None,
            )
            .unwrap();

            let encoded_swap = encoder
                .encode_swap(swap, encoding_context)
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
                    "1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e",
                    // transfer true
                    "01",
                ))
                .to_lowercase()
            );

            write_calldata_to_file("test_encode_maverick_v2", hex_swap.as_str());
        }
    }

    mod bebop {
        use super::*;
        use crate::encoding::{evm::utils::write_calldata_to_file, models::TransferType};

        #[test]
        fn test_encode_bebop_single() {
            use alloy::{hex, primitives::Address};

            // Use mainnet data
            // Transaction: https://etherscan.io/tx/0x6279bc970273b6e526e86d9b69133c2ca1277e697ba25375f5e6fc4df50c0c94
            let order_type = BebopOrderType::Single as u8;

            // Create the IBebopSettlement.Single struct data using the exact input data from the tx
            let expiry = U256::from(1749483840u64);
            let taker_address =
                Address::from_str("0xc5564C13A157E6240659fb81882A28091add8670").unwrap();
            let maker_address =
                Address::from_str("0xCe79b081c0c924cb67848723ed3057234d10FC6b").unwrap();
            let maker_nonce = U256::from(1749483765992417u64);
            let taker_token =
                Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(); // USDC
            let maker_token =
                Address::from_str("0xfAbA6f8e4a5E8Ab82F62fe7C39859FA577269BE3").unwrap(); // ONDO
            let taker_amount = U256::from(200000000u64); // 200 USDC
            let maker_amount = U256::from_str("237212396774431060000").unwrap(); // 237.21 ONDO
            let receiver = taker_address;
            let packed_commands = U256::ZERO;
            let flags = U256::from_str(
                "51915842898789398998206002334703507894664330885127600393944965515693155942400",
            )
            .unwrap();

            // ABI encode the order struct
            let quote_data = (
                expiry,
                taker_address,
                maker_address,
                maker_nonce,
                taker_token,
                maker_token,
                taker_amount,
                maker_amount,
                receiver,
                packed_commands,
                flags,
            )
                .abi_encode();

            // Real signature from mainnet
            let signature = hex::decode("eb5419631614978da217532a40f02a8f2ece37d8cfb94aaa602baabbdefb56b474f4c2048a0f56502caff4ea7411d99eed6027cd67dc1088aaf4181dcb0df7051c").unwrap();
            let signature_type = 0u8; // ETH_SIGN

            // Build ABI-encoded MakerSignature[] array
            let flags = U256::from(signature_type);
            let mut encoded_maker_sigs = Vec::new();

            // Offset to array (always 0x20 for single parameter)
            encoded_maker_sigs.extend_from_slice(&U256::from(32).to_be_bytes::<32>());

            // Array length (1 for Single order)
            encoded_maker_sigs.extend_from_slice(&U256::from(1).to_be_bytes::<32>());

            // Offset to first struct (relative to array data start)
            encoded_maker_sigs.extend_from_slice(&U256::from(32).to_be_bytes::<32>());

            // Struct data (MakerSignature has signatureBytes first, then flags)
            // - offset to signatureBytes (always 64 since it comes after offset and flags)
            encoded_maker_sigs.extend_from_slice(&U256::from(64).to_be_bytes::<32>());

            // - flags (AFTER the offset, as per struct order)
            encoded_maker_sigs.extend_from_slice(&flags.to_be_bytes::<32>());

            // - signatureBytes length
            encoded_maker_sigs.extend_from_slice(&U256::from(signature.len()).to_be_bytes::<32>());

            // - signatureBytes data (padded)
            encoded_maker_sigs.extend_from_slice(&signature);
            let padding = (32 - (signature.len() % 32)) % 32;
            encoded_maker_sigs.extend_from_slice(&vec![0u8; padding]);

            let filled_taker_amount = U256::ZERO; // 0 means fill entire order

            let mut user_data = Vec::new();
            user_data.push(order_type);
            user_data.extend_from_slice(&filled_taker_amount.to_be_bytes::<32>());
            user_data.extend_from_slice(&(quote_data.len() as u32).to_be_bytes());
            user_data.extend_from_slice(&quote_data);
            user_data.extend_from_slice(&encoded_maker_sigs);

            let bebop_component = ProtocolComponent {
                id: String::from("bebop-rfq"),
                protocol_system: String::from("rfq:bebop"),
                static_attributes: HashMap::new(),
                ..Default::default()
            };

            let token_in = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // USDC
            let token_out = Bytes::from("0xfAbA6f8e4a5E8Ab82F62fe7C39859FA577269BE3"); // ONDO
            let swap = Swap {
                component: bebop_component,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
                user_data: Some(Bytes::from(user_data)),
            };

            let encoding_context = EncodingContext {
                receiver: Bytes::from("0xc5564C13A157E6240659fb81882A28091add8670"), // Taker address from tx
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
            };

            let encoder = BebopSwapEncoder::new(
                String::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                TychoCoreChain::Ethereum.into(),
                Some(HashMap::from([(
                    "bebop_settlement_address".to_string(),
                    "0xbbbbbBB520d69a9775E85b458C58c648259FAD5F".to_string(),
                )])),
            )
            .unwrap();

            let encoded_swap = encoder
                .encode_swap(swap, encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            // Verify the encoding contains the expected tokens
            assert!(hex_swap.contains("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")); // USDC
            assert!(hex_swap.contains("faba6f8e4a5e8ab82f62fe7c39859fa577269be3")); // ONDO

            // Verify it includes the signature
            let sig_hex = hex::encode(&signature);
            assert!(hex_swap.contains(&sig_hex));

            write_calldata_to_file("test_encode_bebop_single", hex_swap.as_str());
        }

        #[test]
        fn test_encode_bebop_aggregate() {
            use alloy::hex;

            // Create user_data for a Bebop Aggregate RFQ quote
            let order_type = BebopOrderType::Aggregate as u8;
            let signature_type = 0u8; // ETH_SIGN

            // Use real mainnet data from https://etherscan.io/tx/0xec88410136c287280da87d0a37c1cb745f320406ca3ae55c678dec11996c1b1c
            // Swap: 0.00985 ETH → 17.969561 USDC
            let aggregate_order = BebopAggregate {
                expiry: U256::from(1746367285u64),
                taker_address: Address::from_str("0x7078B12Ca5B294d95e9aC16D90B7D38238d8F4E6").unwrap(),
                maker_addresses: vec![
                    Address::from_str("0x67336Cec42645F55059EfF241Cb02eA5cC52fF86").unwrap(),
                    Address::from_str("0xBF19CbF0256f19f39A016a86Ff3551ecC6f2aAFE").unwrap(),
                ],
                maker_nonces: vec![U256::from(1746367197308u64), U256::from(15460096u64)],
                taker_tokens: vec![
                    vec![Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap()], // WETH for maker 1
                    vec![Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap()], // WETH for maker 2
                ],
                maker_tokens: vec![
                    vec![Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap()], // USDC from maker 1
                    vec![Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap()], // USDC from maker 2
                ],
                taker_amounts: vec![
                    vec![U256::from(5812106401997138u64)], // First maker takes ~0.0058 ETH
                    vec![U256::from(4037893598002862u64)], // Second maker takes ~0.0040 ETH
                ],
                maker_amounts: vec![
                    vec![U256::from(10607211u64)], // First maker gives ~10.6 USDC
                    vec![U256::from(7362350u64)], // Second maker gives ~7.36 USDC
                ],
                receiver: Address::from_str("0x7078B12Ca5B294d95e9aC16D90B7D38238d8F4E6").unwrap(),
                commands: hex::decode("00040004").unwrap().into(),
                flags: U256::from_str("95769172144825922628485191511070792431742484643425438763224908097896054784000").unwrap(),
            };

            let quote_data = aggregate_order.abi_encode();
            // Real signatures from mainnet transaction
            let sig1 = hex::decode("d5abb425f9bac1f44d48705f41a8ab9cae207517be8553d2c03b06a88995f2f351ab8ce7627a87048178d539dd64fd2380245531a0c8e43fdc614652b1f32fc71c").unwrap();
            let sig2 = hex::decode("f38c698e48a3eac48f184bc324fef0b135ee13705ab38cc0bbf5a792f21002f051e445b9e7d57cf24c35e17629ea35b3263591c4abf8ca87ffa44b41301b89c41b").unwrap();

            // Build ABI-encoded MakerSignature[] array with 2 signatures
            let flags = U256::from(signature_type);
            let mut encoded_maker_sigs = Vec::new();

            // Offset to array (always 0x20 for single parameter)
            encoded_maker_sigs.extend_from_slice(&U256::from(32).to_be_bytes::<32>());

            // Array length (2 for Aggregate order with 2 makers)
            encoded_maker_sigs.extend_from_slice(&U256::from(2).to_be_bytes::<32>());

            // Offsets to structs (relative to array data start)
            // First struct at offset 64 (after the 2 offset values)
            encoded_maker_sigs.extend_from_slice(&U256::from(64).to_be_bytes::<32>());
            // Second struct will be after first struct's data
            // First struct size: 64 (fixed) + 32 (length) + 96 (65 bytes padded) = 192
            encoded_maker_sigs.extend_from_slice(&U256::from(64 + 192).to_be_bytes::<32>());

            // First struct data (MakerSignature has signatureBytes first, then flags)
            // - offset to signatureBytes (always 64)
            encoded_maker_sigs.extend_from_slice(&U256::from(64).to_be_bytes::<32>());
            // - flags (AFTER the offset)
            encoded_maker_sigs.extend_from_slice(&flags.to_be_bytes::<32>());
            // - signatureBytes length
            encoded_maker_sigs.extend_from_slice(&U256::from(sig1.len()).to_be_bytes::<32>());
            // - signatureBytes data (padded)
            encoded_maker_sigs.extend_from_slice(&sig1);
            let padding1 = (32 - (sig1.len() % 32)) % 32;
            encoded_maker_sigs.extend_from_slice(&vec![0u8; padding1]);

            // Second struct data (MakerSignature has signatureBytes first, then flags)
            // - offset to signatureBytes (always 64)
            encoded_maker_sigs.extend_from_slice(&U256::from(64).to_be_bytes::<32>());
            // - flags (AFTER the offset)
            encoded_maker_sigs.extend_from_slice(&flags.to_be_bytes::<32>());
            // - signatureBytes length
            encoded_maker_sigs.extend_from_slice(&U256::from(sig2.len()).to_be_bytes::<32>());
            // - signatureBytes data (padded)
            encoded_maker_sigs.extend_from_slice(&sig2);
            let padding2 = (32 - (sig2.len() % 32)) % 32;
            encoded_maker_sigs.extend_from_slice(&vec![0u8; padding2]);

            let filled_taker_amount = U256::from(0u64); // 0 means fill entire order

            let mut user_data = Vec::new();
            user_data.push(order_type);
            user_data.extend_from_slice(&filled_taker_amount.to_be_bytes::<32>());
            user_data.extend_from_slice(&(quote_data.len() as u32).to_be_bytes());
            user_data.extend_from_slice(&quote_data);
            user_data.extend_from_slice(&encoded_maker_sigs);

            let bebop_component = ProtocolComponent {
                id: String::from("bebop-rfq"),
                protocol_system: String::from("rfq:bebop"),
                static_attributes: HashMap::new(),
                ..Default::default()
            };

            let token_in = Bytes::from("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"); // WETH
            let token_out = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // USDC
            let swap = Swap {
                component: bebop_component,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
                user_data: Some(Bytes::from(user_data)),
            };

            let encoding_context = EncodingContext {
                receiver: Bytes::from("0x7078B12Ca5B294d95e9aC16D90B7D38238d8F4E6"), // Taker address from tx
                exact_out: false,
                router_address: Some(Bytes::zero(20)),
                group_token_in: token_in.clone(),
                group_token_out: token_out.clone(),
                transfer_type: TransferType::Transfer,
            };

            let encoder = BebopSwapEncoder::new(
                String::from("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4"),
                TychoCoreChain::Ethereum.into(),
                Some(HashMap::from([(
                    "bebop_settlement_address".to_string(),
                    "0xbbbbbBB520d69a9775E85b458C58c648259FAD5F".to_string(),
                )])),
            )
            .unwrap();

            let encoded_swap = encoder
                .encode_swap(swap, encoding_context)
                .unwrap();
            let hex_swap = encode(&encoded_swap);

            // Calculate expected hex for ABI-encoded maker signatures array with 2 signatures
            let _expected_abi_maker_sigs = concat!(
                // offset to array
                "0000000000000000000000000000000000000000000000000000000000000020",
                // array length (2)
                "0000000000000000000000000000000000000000000000000000000000000002",
                // offset to first struct (relative to array data start)
                "0000000000000000000000000000000000000000000000000000000000000040",
                // offset to second struct (64 + 192 = 256 = 0x100)
                "0000000000000000000000000000000000000000000000000000000000000100",
                // First struct data:
                // - offset to signatureBytes
                "0000000000000000000000000000000000000000000000000000000000000040",
                // - flags
                "0000000000000000000000000000000000000000000000000000000000000000",
                // - signatureBytes length (66 = 0x42, actual length of signatures)
                "0000000000000000000000000000000000000000000000000000000000000042",
                // - signatureBytes (66 bytes padded to 96)
                "d5abb425f9bac1f44d48705f41a8ab9cae207517be8553d2c03b06a88995f2f3",
                "51ab8ce7627a87048178d539dd64fd2380245531a0c8e43fdc614652b1f32fc7",
                "1c00000000000000000000000000000000000000000000000000000000000000",
                // Second struct data:
                // - offset to signatureBytes
                "0000000000000000000000000000000000000000000000000000000000000040",
                // - flags
                "0000000000000000000000000000000000000000000000000000000000000000",
                // - signatureBytes length (66 = 0x42)
                "0000000000000000000000000000000000000000000000000000000000000042",
                // - signatureBytes (66 bytes padded to 96)
                "f38c698e48a3eac48f184bc324fef0b135ee13705ab38cc0bbf5a792f21002f0",
                "51e445b9e7d57cf24c35e17629ea35b3263591c4abf8ca87ffa44b41301b89c4",
                "1b00000000000000000000000000000000000000000000000000000000000000"
            );

            // The quote data is now an ABI-encoded BebopAggregate struct
            // Calculate its actual length
            let quote_data_hex = hex::encode(&quote_data);
            let quote_data_length = format!("{:08x}", quote_data.len());

            let expected_hex = format!(
                "{}{}{}{}{}{}{}{}{}{}",
                // token in
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                // token out
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                // transfer type Transfer
                "01",
                // order type Aggregate (1)
                "01",
                // filledTakerAmount (0 for full fill)
                "0000000000000000000000000000000000000000000000000000000000000000",
                // quote data length
                &quote_data_length,
                // quote data
                &quote_data_hex,
                // maker signatures length (0x200 = 512 bytes)
                "00000200",
                // abi-encoded maker signatures
                &encode(&encoded_maker_sigs),
                // approval needed
                "01"
            );

            assert_eq!(hex_swap, expected_hex);

            write_calldata_to_file("test_encode_bebop_aggregate", hex_swap.as_str());
        }
    }
}

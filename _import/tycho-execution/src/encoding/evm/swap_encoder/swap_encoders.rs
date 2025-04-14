use std::{collections::HashMap, str::FromStr};

use alloy::{
    providers::Provider,
    rpc::types::{TransactionInput, TransactionRequest},
};
use alloy_primitives::{Address, Bytes as AlloyBytes, TxKind, U256, U8};
use alloy_sol_types::SolValue;
use tokio::task::block_in_place;
use tycho_common::Bytes;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        approvals::protocol_approvals_manager::ProtocolApprovalsManager,
        utils,
        utils::{
            bytes_to_address, encode_input, get_runtime, get_static_attribute, pad_to_fixed_size,
        },
    },
    models::{Chain, EncodingContext, Swap},
    swap_encoder::SwapEncoder,
};

/// Encodes a swap on a Uniswap V2 pool through the given executor address.
///
/// # Fields
/// * `executor_address` - The address of the executor contract that will perform the swap.
/// * `swap_selector` - The selector of the swap function in the executor contract.
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
/// * `swap_selector` - The selector of the swap function in the executor contract.
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
/// * `swap_selector` - The selector of the swap function in the executor contract.
/// * `callback_selector` - The selector of the callback function in the executor contract.
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
            "Missing balancer specific addresses in config".to_string(),
        ))?;
        let vault_address = config
            .get("vault_address")
            .ok_or(EncodingError::FatalError(
                "Missing balancer vault address in config".to_string(),
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
    meta_registry_address: String,
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
                    "Unsupported curve factory address: {}",
                    factory_address
                ))),
            },
        }
    }

    fn get_coin_indexes(
        &self,
        pool_id: Address,
        token_in: Address,
        token_out: Address,
    ) -> Result<(U8, U8), EncodingError> {
        let (handle, _runtime) = get_runtime()?;
        let client = block_in_place(|| handle.block_on(utils::get_client()))?;
        let args = (pool_id, token_in, token_out);
        let data = encode_input("get_coin_indices(address,address,address)", args.abi_encode());
        let tx = TransactionRequest {
            to: Some(TxKind::from(Address::from_str(&self.meta_registry_address).map_err(
                |_| EncodingError::FatalError("Invalid Curve meta registry address".to_string()),
            )?)),
            input: TransactionInput {
                input: Some(alloy_primitives::Bytes::from(data)),
                data: None,
            },
            ..Default::default()
        };
        let output = block_in_place(|| handle.block_on(async { client.call(&tx).await }));
        type ResponseType = (U256, U256, bool);

        match output {
            Ok(response) => {
                let (i_256, j_256, _): ResponseType = ResponseType::abi_decode(&response, true)
                    .map_err(|_| {
                        EncodingError::FatalError(
                            "Failed to decode response when getting coin indexes on a curve pool"
                                .to_string(),
                        )
                    })?;
                let i = U8::from(i_256);
                let j = U8::from(j_256);
                Ok((i, j))
            }
            Err(err) => Err(EncodingError::RecoverableError(format!(
                "Curve meta registry call failed with error: {:?}",
                err
            ))),
        }
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
        let meta_registry_address = config
            .get("meta_registry_address")
            .ok_or(EncodingError::FatalError(
                "Missing meta registry address in config".to_string(),
            ))?
            .to_string();
        Ok(Self {
            executor_address,
            meta_registry_address,
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

        let pool_type = self.get_pool_type(&swap.component.id, &factory_address.to_string())?;

        let (i, j) = self.get_coin_indexes(component_address, token_in, token_out)?;

        let args = (
            token_in,
            token_out,
            component_address,
            pool_type.to_be_bytes::<1>(),
            i.to_be_bytes::<1>(),
            j.to_be_bytes::<1>(),
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
    use crate::encoding::models::TransferType;

    #[test]
    fn test_encode_uniswap_v2() {
        let usv2_pool = ProtocolComponent {
            id: String::from("0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640"),
            ..Default::default()
        };

        let token_in = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
        let token_out = Bytes::from("0x6b175474e89094c44da98b954eedeac495271d0f");
        let swap = Swap {
            component: usv2_pool,
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            split: 0f64,
        };
        let encoding_context = EncodingContext {
            receiver: Bytes::from("0x0000000000000000000000000000000000000001"),
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
                "88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
                // receiver
                "0000000000000000000000000000000000000001",
                // zero for one
                "00",
                // transfer type (transfer)
                "00",
            ))
        );
    }
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
                // transfer type (transfer)
                "00",
            ))
        );
    }

    #[test]
    fn test_encode_balancer_v2() {
        let balancer_pool = ProtocolComponent {
            id: String::from("0x5c6ee304399dbdb9c8ef030ab642b10820db8f56000200000000000000000014"),
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
                // transfer type
                "05"
            ))
        );
    }

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
        };
        let encoding_context = EncodingContext {
            // The receiver address was taken from `address(uniswapV4Exposed)` in the
            // UniswapV4Executor.t.sol
            receiver: Bytes::from("0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f"),
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
        println!("{}", hex_swap);

        assert_eq!(
            hex_swap,
            String::from(concat!(
                // group token in
                "4c9edd5852cd905f086c759e8383e09bff1e68b3",
                // group token out
                "dac17f958d2ee523a2206206994597c13d831ec7",
                // zero for one
                "01",
                // transfer type
                "00",
                // pool params:
                // - intermediary token
                "dac17f958d2ee523a2206206994597c13d831ec7",
                // - fee
                "000064",
                // - tick spacing
                "000001"
            ))
        );
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
        let receiver_address = router_address.clone();

        // The context is the same for both swaps, since the group token in and out are the same
        let context = EncodingContext {
            receiver: receiver_address.clone(),
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
        };

        let second_swap = Swap {
            component: usdt_wbtc_component,
            token_in: usdt_address,
            token_out: wbtc_address.clone(),
            split: 0f64,
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

        println!("{}", combined_hex);
        assert_eq!(
            combined_hex,
            String::from(concat!(
                // group_token in
                "4c9edd5852cd905f086c759e8383e09bff1e68b3",
                // group_token out
                "2260fac5e5542a773aa44fbcfedf7c193bc2c599",
                // zero for one
                "01",
                // transfer type
                "00",
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

            let swap = Swap {
                component,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
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
                RECEIVER.to_string() +
                    concat!(
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
            };

            let first_encoded_swap = encoder
                .encode_swap(first_swap, encoding_context.clone())
                .unwrap();

            let second_encoded_swap = encoder
                .encode_swap(second_swap, encoding_context)
                .unwrap();

            let combined_hex =
                format!("{}{}", encode(first_encoded_swap), encode(second_encoded_swap));

            println!("{}", combined_hex);

            assert_eq!(
                combined_hex,
                RECEIVER.to_string() +
                    concat!(
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
            "0x5500307Bcf134E5851FB4D7D8D1Dc556dCdB84B4",
            "0xdA16Cf041E2780618c49Dbae5d734B89a6Bac9b3",
            "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            1,
            0
        )]
        #[case(
            "0xef484de8C07B6e2d732A92B5F78e81B38f99f95E",
            "0x865377367054516e17014CcdED1e7d814EDC9ce4",
            "0xA5588F7cdf560811710A2D82D3C9c99769DB1Dcb",
            0,
            1
        )]
        #[case(
            "0xA5407eAE9Ba41422680e2e00537571bcC53efBfD",
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "0x57Ab1ec28D129707052df4dF418D58a2D46d5f51",
            1,
            3
        )]
        #[case(
            "0xD51a44d3FaE010294C616388b506AcdA1bfAAE46",
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
            2,
            1
        )]
        #[case(
            "0x7F86Bf177Dd4F3494b841a37e810A34dD56c829B",
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            2,
            0
        )]
        fn test_curve_get_coin_indexes(
            #[case] pool: &str,
            #[case] token_in: &str,
            #[case] token_out: &str,
            #[case] expected_i: u64,
            #[case] expected_j: u64,
        ) {
            let encoder = CurveSwapEncoder::new(
                String::default(),
                TychoCoreChain::Ethereum.into(),
                curve_config(),
            )
            .unwrap();
            let (i, j) = encoder
                .get_coin_indexes(
                    Address::from_str(pool).unwrap(),
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
                    // transfer type
                    "05",
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
                    // transfer type
                    "05",
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
                    // transfer type
                    "05",
                ))
            );
        }
    }
}

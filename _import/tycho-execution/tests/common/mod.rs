#![allow(dead_code)]
pub mod encoding;

use std::str::FromStr;

use alloy::{
    primitives::{B256, U256},
    signers::local::PrivateKeySigner,
};
use tycho_common::{models::Chain as TychoCommonChain, Bytes};
use tycho_execution::encoding::{
    evm::encoder_builders::TychoRouterEncoderBuilder,
    models::{BebopOrderType, Chain, UserTransferType},
    tycho_encoder::TychoEncoder,
};

pub fn router_address() -> Bytes {
    Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap()
}

pub fn eth_chain() -> Chain {
    TychoCommonChain::Ethereum.into()
}

pub fn eth() -> Bytes {
    Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap()
}

pub fn weth() -> Bytes {
    Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap()
}

pub fn usdc() -> Bytes {
    Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap()
}

pub fn dai() -> Bytes {
    Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap()
}

pub fn wbtc() -> Bytes {
    Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap()
}

pub fn pepe() -> Bytes {
    Bytes::from_str("0x6982508145454Ce325dDbE47a25d4ec3d2311933").unwrap()
}

pub fn ondo() -> Bytes {
    Bytes::from_str("0xfAbA6f8e4a5E8Ab82F62fe7C39859FA577269BE3").unwrap()
}

pub fn get_signer() -> PrivateKeySigner {
    // Set up a mock private key for signing (Alice's pk in our contract tests)
    let private_key =
        "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234".to_string();

    let pk = B256::from_str(&private_key).unwrap();
    PrivateKeySigner::from_bytes(&pk).unwrap()
}

pub fn get_tycho_router_encoder(user_transfer_type: UserTransferType) -> Box<dyn TychoEncoder> {
    TychoRouterEncoderBuilder::new()
        .chain(tycho_common::models::Chain::Ethereum)
        .user_transfer_type(user_transfer_type)
        .executors_file_path("config/test_executor_addresses.json".to_string())
        .router_address(router_address())
        .build()
        .expect("Failed to build encoder")
}

/// Builds Bebop user_data with support for single or multiple signatures
///
/// # Arguments
/// * `order_type` - The type of Bebop order (Single or Aggregate)
/// * `filled_taker_amount` - Amount to fill (0 means fill entire order)
/// * `quote_data` - The ABI-encoded order data
/// * `signatures` - Vector of (signature_bytes, signature_type) tuples
///   - For Single orders: expects exactly 1 signature
///   - For Aggregate orders: expects 1 or more signatures (one per maker)
pub fn build_bebop_user_data(
    order_type: BebopOrderType,
    filled_taker_amount: U256,
    quote_data: &[u8],
    signatures: Vec<(Vec<u8>, u8)>, // (signature, signature_type)
) -> Bytes {
    // ABI encode MakerSignature[] array
    // Format: offset_to_array | array_length | [offset_to_struct_i]... | [struct_i_data]...
    let mut encoded_maker_sigs = Vec::new();

    // Calculate total size needed
    let array_offset = 32; // offset to array start
    let array_length_size = 32;
    let struct_offsets_size = 32 * signatures.len();
    let _header_size = array_length_size + struct_offsets_size;

    // Build each struct's data and calculate offsets
    let mut struct_data = Vec::new();
    let mut struct_offsets = Vec::new();
    // Offsets are relative to the start of array data, not the absolute position
    // Array data starts after array length, so first offset is after all offset values
    let mut current_offset = struct_offsets_size; // Just the space for offsets, not including array length

    for (signature, signature_type) in &signatures {
        struct_offsets.push(current_offset);

        // Each struct contains:
        // - offset to signatureBytes (32 bytes) - always 0x40 (64)
        // - flags (32 bytes)
        // - signatureBytes length (32 bytes)
        // - signatureBytes data (padded to 32 bytes)
        let mut struct_bytes = Vec::new();

        // Offset to signatureBytes within this struct
        struct_bytes.extend_from_slice(&U256::from(64).to_be_bytes::<32>());

        // Flags (contains signature type) - AFTER the offset, not before!
        let flags = U256::from(*signature_type);
        struct_bytes.extend_from_slice(&flags.to_be_bytes::<32>());

        // SignatureBytes length
        struct_bytes.extend_from_slice(&U256::from(signature.len()).to_be_bytes::<32>());

        // SignatureBytes data (padded to 32 byte boundary)
        struct_bytes.extend_from_slice(signature);
        let padding = (32 - (signature.len() % 32)) % 32;
        struct_bytes.extend_from_slice(&vec![0u8; padding]);

        current_offset += struct_bytes.len();
        struct_data.push(struct_bytes);
    }

    // Build the complete ABI encoded array
    // Offset to array (always 0x20 for a single parameter)
    encoded_maker_sigs.extend_from_slice(&U256::from(array_offset).to_be_bytes::<32>());

    // Array length
    encoded_maker_sigs.extend_from_slice(&U256::from(signatures.len()).to_be_bytes::<32>());

    // Struct offsets (relative to start of array data)
    for offset in struct_offsets {
        encoded_maker_sigs.extend_from_slice(&U256::from(offset).to_be_bytes::<32>());
    }

    // Struct data
    for data in struct_data {
        encoded_maker_sigs.extend_from_slice(&data);
    }

    // Build complete user_data
    let mut user_data = Vec::new();
    user_data.push(order_type as u8);
    user_data.extend_from_slice(&filled_taker_amount.to_be_bytes::<32>());
    user_data.extend_from_slice(&(quote_data.len() as u32).to_be_bytes());
    user_data.extend_from_slice(quote_data);
    user_data.extend_from_slice(&encoded_maker_sigs);
    Bytes::from(user_data)
}

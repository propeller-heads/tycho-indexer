#![allow(dead_code)]
pub mod encoding;

use std::str::FromStr;

use alloy::{
    primitives::{B256, U256},
    signers::local::PrivateKeySigner,
};
use tycho_common::{models::Chain, Bytes};
use tycho_execution::encoding::{
    evm::encoder_builders::TychoRouterEncoderBuilder,
    models::{BebopOrderType, UserTransferType},
    tycho_encoder::TychoEncoder,
};

pub fn router_address() -> Bytes {
    Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap()
}

pub fn eth_chain() -> Chain {
    Chain::Ethereum
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

pub fn usdt() -> Bytes {
    Bytes::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap()
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

/// Builds the complete Bebop calldata in the format expected by the encoder
/// Returns: partialFillOffset (1 byte) | bebop_calldata (selector + ABI encoded params)
///
/// # Arguments
/// * `order_type` - The type of Bebop order (Single or Aggregate)
/// * `filled_taker_amount` - Amount to fill (0 means fill entire order)
/// * `quote_data` - The ABI-encoded order data (just the struct, not full calldata)
/// * `signatures` - Vector of (signature_bytes, signature_type) tuples
pub fn build_bebop_calldata(
    order_type: BebopOrderType,
    filled_taker_amount: U256,
    quote_data: &[u8],
    signatures: Vec<(Vec<u8>, u8)>,
) -> Bytes {
    // Step 1: Determine selector and partialFillOffset based on order type
    let (selector, partial_fill_offset) = match order_type {
        BebopOrderType::Single => (
            [0x4d, 0xce, 0xbc, 0xba], // swapSingle selector
            12u8,                     /* partialFillOffset (388 = 4 + 12*32) - after order and
                                       * signature offset */
        ),
        BebopOrderType::Aggregate => (
            [0xa2, 0xf7, 0x48, 0x93], // swapAggregate selector
            2u8,                      /* partialFillOffset (68 = 4 + 2*32) - aggregate still
                                       * uses offsets */
        ),
    };

    // Step 2: Build the ABI-encoded parameters based on order type
    let encoded_params = match order_type {
        BebopOrderType::Single => {
            // swapSingle(Single order, MakerSignature signature, uint256 filledTakerAmount)
            encode_single_params(quote_data, &signatures[0], filled_taker_amount)
        }
        BebopOrderType::Aggregate => {
            // swapAggregate(Aggregate order, MakerSignature[] signatures, uint256
            // filledTakerAmount)
            encode_aggregate_params(quote_data, &signatures, filled_taker_amount)
        }
    };

    // Step 3: Combine selector and encoded parameters into complete calldata
    let mut bebop_calldata = Vec::new();
    bebop_calldata.extend_from_slice(&selector);
    bebop_calldata.extend_from_slice(&encoded_params);

    // Step 4: Prepend partialFillOffset to create final user_data
    let mut user_data = vec![partial_fill_offset];
    user_data.extend_from_slice(&bebop_calldata);

    Bytes::from(user_data)
}

fn encode_single_params(
    order_data: &[u8], // Already ABI-encoded Single struct
    signature: &(Vec<u8>, u8),
    filled_taker_amount: U256,
) -> Vec<u8> {
    // abi.encode() with (struct, struct, uint256) where:
    // - Single struct: all fixed-size fields, encoded inline
    // - MakerSignature struct: has dynamic bytes field, needs offset
    // - uint256: fixed-size, encoded inline

    let mut encoded = Vec::new();

    // 1. Order struct fields are encoded inline (11 fields * 32 bytes = 352 bytes)
    encoded.extend_from_slice(order_data);

    // 2. Offset to MakerSignature data (points after all inline data)
    // Offset = 352 (order) + 32 (this offset) + 32 (filledTakerAmount) = 416
    encoded.extend_from_slice(&U256::from(416).to_be_bytes::<32>());

    // 3. filledTakerAmount inline
    encoded.extend_from_slice(&filled_taker_amount.to_be_bytes::<32>());

    // 4. MakerSignature struct data at the offset
    let signature_struct = encode_maker_signature(signature);
    encoded.extend_from_slice(&signature_struct);

    encoded
}

fn encode_aggregate_params(
    order_data: &[u8], // Already ABI-encoded Aggregate struct
    signatures: &[(Vec<u8>, u8)],
    filled_taker_amount: U256,
) -> Vec<u8> {
    // abi.encode() with (struct, struct[], uint256) where:
    // - Aggregate struct: has dynamic arrays, gets offset
    // - MakerSignature[] array: dynamic, gets offset
    // - uint256: fixed-size, encoded inline
    //
    // CRITICAL FIX: The issue is that Rust's ABI encoder produces aggregate orders
    // that are 32 bytes larger than Solidity's (1536 vs 1504 bytes). We cannot just
    // adjust the offset while keeping the wrong-sized data. Instead, we need to
    // truncate the extra 32 bytes from the Rust-encoded order data to match Solidity.

    let mut encoded = Vec::new();

    // Fixed: Using alloy::primitives::Bytes for the commands field produces the correct
    // 1504-byte encoding that matches Solidity. No truncation needed anymore.
    let corrected_order_data = order_data;

    // Calculate offsets
    let order_offset = 96; // After 3 words (3 * 32 = 96)
    let signatures_offset = order_offset + corrected_order_data.len();

    // Write the three parameter slots
    encoded.extend_from_slice(&U256::from(order_offset).to_be_bytes::<32>());
    encoded.extend_from_slice(&U256::from(signatures_offset).to_be_bytes::<32>());
    encoded.extend_from_slice(&filled_taker_amount.to_be_bytes::<32>());

    // Append the corrected order data
    encoded.extend_from_slice(corrected_order_data);

    // Manually encode the signatures array to exactly match the working test
    // Array length
    encoded.extend_from_slice(&U256::from(signatures.len()).to_be_bytes::<32>());

    // For 2 signatures, we need offsets for each struct
    if signatures.len() == 2 {
        // First signature starts after the two offset words (64 bytes)
        let sig1_offset = 64;

        // Calculate size of first signature struct:
        // - offset to bytes field: 32
        // - flags field: 32
        // - length of bytes: 32
        // - actual signature bytes + padding
        let sig1 = &signatures[0];
        let sig1_padding = (32 - (sig1.0.len() % 32)) % 32;
        let sig1_size = 64 + 32 + sig1.0.len() + sig1_padding;

        // Second signature starts after first
        let sig2_offset = sig1_offset + sig1_size;

        // Write offsets
        encoded.extend_from_slice(&U256::from(sig1_offset).to_be_bytes::<32>());
        encoded.extend_from_slice(&U256::from(sig2_offset).to_be_bytes::<32>());

        // Encode each MakerSignature struct
        for signature in signatures {
            // Offset to signatureBytes within this struct (always 64)
            encoded.extend_from_slice(&U256::from(64).to_be_bytes::<32>());
            // Flags (signature type)
            encoded.extend_from_slice(&U256::from(signature.1).to_be_bytes::<32>());
            // SignatureBytes length
            encoded.extend_from_slice(&U256::from(signature.0.len()).to_be_bytes::<32>());
            // SignatureBytes data
            encoded.extend_from_slice(&signature.0);
            // Padding to 32-byte boundary
            let padding = (32 - (signature.0.len() % 32)) % 32;
            encoded.extend(vec![0u8; padding]);
        }
    } else {
        // General case for any number of signatures
        let signatures_array = encode_maker_signatures_array(signatures);
        encoded.extend_from_slice(&signatures_array);
    }

    encoded
}

fn encode_maker_signature(signature: &(Vec<u8>, u8)) -> Vec<u8> {
    let mut encoded = Vec::new();

    // MakerSignature struct has two fields:
    // - bytes signatureBytes (dynamic) - offset at position 0
    // - uint256 flags - at position 32

    // Offset to signatureBytes (always 64 for this struct layout)
    encoded.extend_from_slice(&U256::from(64).to_be_bytes::<32>());

    // Flags (signature type)
    encoded.extend_from_slice(&U256::from(signature.1).to_be_bytes::<32>());

    // SignatureBytes (length + data)
    encoded.extend_from_slice(&U256::from(signature.0.len()).to_be_bytes::<32>());
    encoded.extend_from_slice(&signature.0);

    // Pad to 32-byte boundary
    let padding = (32 - (signature.0.len() % 32)) % 32;
    encoded.extend(vec![0u8; padding]);

    encoded
}

fn encode_maker_signatures_array(signatures: &[(Vec<u8>, u8)]) -> Vec<u8> {
    let mut encoded = Vec::new();

    // Array length
    encoded.extend_from_slice(&U256::from(signatures.len()).to_be_bytes::<32>());

    // Calculate offsets for each struct (relative to start of array data)
    let mut struct_data = Vec::new();
    let mut struct_offsets = Vec::new();
    let struct_offsets_size = 32 * signatures.len();
    let mut current_offset = struct_offsets_size;

    for signature in signatures {
        struct_offsets.push(current_offset);

        // Build struct data
        let mut struct_bytes = Vec::new();

        // Offset to signatureBytes within this struct
        struct_bytes.extend_from_slice(&U256::from(64).to_be_bytes::<32>());

        // Flags (signature type)
        struct_bytes.extend_from_slice(&U256::from(signature.1).to_be_bytes::<32>());

        // SignatureBytes length
        struct_bytes.extend_from_slice(&U256::from(signature.0.len()).to_be_bytes::<32>());

        // SignatureBytes data (padded to 32 byte boundary)
        struct_bytes.extend_from_slice(&signature.0);
        let padding = (32 - (signature.0.len() % 32)) % 32;
        struct_bytes.extend(vec![0u8; padding]);

        current_offset += struct_bytes.len();
        struct_data.push(struct_bytes);
    }

    // Write struct offsets
    for offset in struct_offsets {
        encoded.extend_from_slice(&U256::from(offset).to_be_bytes::<32>());
    }

    // Write struct data
    for data in struct_data {
        encoded.extend_from_slice(&data);
    }

    encoded
}

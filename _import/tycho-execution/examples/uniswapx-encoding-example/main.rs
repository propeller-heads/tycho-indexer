use std::{collections::HashMap, str::FromStr};

use alloy::{
    hex::encode,
    primitives::{Address, Keccak256},
    sol_types::SolValue,
};
use num_bigint::{BigInt, BigUint};
use tycho_common::{models::protocol::ProtocolComponent, Bytes};
use tycho_execution::encoding::{
    evm::{
        approvals::protocol_approvals_manager::ProtocolApprovalsManager,
        encoder_builders::TychoRouterEncoderBuilder,
        utils::{biguint_to_u256, bytes_to_address},
    },
    models::{Solution, Swap, UserTransferType},
};

/// Encodes the input data for a function call to the given function selector.
pub fn encode_input(selector: &str, mut encoded_args: Vec<u8>) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(selector.as_bytes());
    let selector_bytes = &hasher.finalize()[..4];
    let mut call_data = selector_bytes.to_vec();
    // Remove extra prefix if present (32 bytes for dynamic data)
    // Alloy encoding is including a prefix for dynamic data indicating the offset or length
    // but at this point we don't want that
    if encoded_args.len() > 32 &&
        encoded_args[..32] ==
            [0u8; 31]
                .into_iter()
                .chain([32].to_vec())
                .collect::<Vec<u8>>()
    {
        encoded_args = encoded_args[32..].to_vec();
    }
    call_data.extend(encoded_args);
    call_data
}

fn main() {
    let router_address = Bytes::from_str("0xfD0b31d2E955fA55e3fa641Fe90e08b677188d35")
        .expect("Failed to create router address");

    // Initialize the encoder
    let encoder = TychoRouterEncoderBuilder::new()
        .chain(tycho_common::models::Chain::Ethereum)
        .user_transfer_type(UserTransferType::TransferFrom)
        .router_address(router_address.clone())
        .build()
        .expect("Failed to build encoder");

    // Set up UniswapX-related variables
    let filler = Bytes::from_str("0x6D9da78B6A5BEdcA287AA5d49613bA36b90c15C4").unwrap();
    let usx_reactor = Address::from_str("0x00000011F84B9aa48e5f8aA8B9897600006289Be").unwrap();

    // ------------------- Encode a sequential swap -------------------
    // Prepare data to encode. We will encode a sequential swap from DAI to USDT though USDC using
    // USV3 pools
    //
    //   DAI ───(USV3)──> USDC ───(USV2)──> USDT
    //
    // First we need to create  swap objects

    let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();
    let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
    let usdt = Bytes::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap();

    let swap_dai_usdc = Swap {
        component: ProtocolComponent {
            id: "0x5777d92f208679DB4b9778590Fa3CAB3aC9e2168".to_string(),
            protocol_system: "uniswap_v3".to_string(),
            static_attributes: {
                let mut attrs = HashMap::new();
                attrs
                    .insert("fee".to_string(), Bytes::from(BigInt::from(100).to_signed_bytes_be()));
                attrs
            },
            ..Default::default()
        },
        token_in: dai.clone(),
        token_out: usdc.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };
    let swap_usdc_usdt = Swap {
        component: ProtocolComponent {
            id: "0x3416cF6C708Da44DB2624D63ea0AAef7113527C6".to_string(),
            protocol_system: "uniswap_v3".to_string(),
            static_attributes: {
                let mut attrs = HashMap::new();
                attrs
                    .insert("fee".to_string(), Bytes::from(BigInt::from(100).to_signed_bytes_be()));
                attrs
            },
            ..Default::default()
        },
        token_in: usdc.clone(),
        token_out: usdt.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    // Then we create a solution object with the previous swap
    let solution = Solution {
        exact_out: false,
        given_token: dai.clone(),
        given_amount: BigUint::from_str("2_000_000000000000000000").unwrap(),
        checked_token: usdt.clone(),
        checked_amount: BigUint::from_str("1_990_000000").unwrap(),
        sender: filler.clone(),
        receiver: filler.clone(),
        swaps: vec![swap_dai_usdc, swap_usdc_usdt],
        ..Default::default()
    };

    // Encode the solution using appropriate safety checks
    let encoded_solution = encoder
        .encode_solutions(vec![solution.clone()])
        .unwrap()[0]
        .clone();

    let given_amount = biguint_to_u256(&solution.given_amount);
    let min_amount_out = biguint_to_u256(&solution.checked_amount);
    let given_token = bytes_to_address(&solution.given_token).unwrap();
    let checked_token = bytes_to_address(&solution.checked_token).unwrap();
    let receiver = bytes_to_address(&solution.receiver).unwrap();

    let method_calldata = (
        given_amount,
        given_token,
        checked_token,
        min_amount_out,
        false, // wrap
        false, // unwrap
        receiver,
        true, // transferFrom permitted
        encoded_solution.swaps,
    )
        .abi_encode();

    let tycho_calldata = encode_input(&encoded_solution.function_signature, method_calldata);

    // Uniswap X specific part (check necessary approvals)
    let filler_address = bytes_to_address(&filler).unwrap();
    let token_approvals_manager = ProtocolApprovalsManager::new().unwrap();

    let token_in_approval_needed = token_approvals_manager
        .approval_needed(
            bytes_to_address(&dai).unwrap(),
            filler_address,
            bytes_to_address(&router_address).unwrap(),
        )
        .unwrap();

    let token_out_approval_needed = token_approvals_manager
        .approval_needed(bytes_to_address(&usdc).unwrap(), filler_address, usx_reactor)
        .unwrap();

    let full_calldata =
        (token_in_approval_needed, token_out_approval_needed, tycho_calldata).abi_encode_packed();

    let hex_calldata = encode(&full_calldata);

    println!(" ====== Simple swap DAI -> USDT ======");
    println!(
        "The following callback data should be sent to the filler contract, along with the \
        encoded order and signature: {hex_calldata:?}"
    );
}

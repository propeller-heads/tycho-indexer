use std::{collections::HashMap, str::FromStr};

use alloy::{hex::encode, primitives::Address, sol_types::SolValue};
use num_bigint::{BigInt, BigUint};
use tycho_common::{models::protocol::ProtocolComponent, Bytes};
use tycho_execution::encoding::{
    evm::{
        approvals::protocol_approvals_manager::ProtocolApprovalsManager,
        utils::{bytes_to_address, write_calldata_to_file},
    },
    models::{Solution, Swap, UserTransferType},
};

use crate::common::{
    dai, encoding::encode_tycho_router_call, eth, eth_chain, get_tycho_router_encoder,
    router_address, usdc, usdt,
};

mod common;

#[test]
fn test_sequential_swap_usx() {
    // Replicates real uniswap X order settled in tx:
    // 0x005d7b150017ba1b59d2f99395ccae7bda9b739938ade4e509817e32760aaf9d
    // Performs a sequential
    // swap from DAI to USDT though USDC using USV3 pools
    //
    //   DAI ───(USV3)──> USDC ───(USV2)──> USDT
    // Creates all the calldata needed for the uniswap X callbackData

    let filler = Bytes::from_str("0x6D9da78B6A5BEdcA287AA5d49613bA36b90c15C4").unwrap();
    let usx_reactor = Address::from_str("0x00000011F84B9aa48e5f8aA8B9897600006289Be").unwrap();

    let dai = dai();
    let usdc = usdc();
    let usdt = usdt();

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
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

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

    let encoded_solution = encoder
        .encode_solutions(vec![solution.clone()])
        .unwrap()[0]
        .clone();

    let tycho_calldata = encode_tycho_router_call(
        eth_chain().id(),
        encoded_solution,
        &solution,
        &UserTransferType::TransferFrom,
        &eth(),
        None,
    )
    .unwrap()
    .data;

    // Uniswap X specific part
    let filler_address = bytes_to_address(&filler).unwrap();
    let token_approvals_manager = ProtocolApprovalsManager::new().unwrap();

    let token_in_approval_needed = token_approvals_manager
        .approval_needed(
            bytes_to_address(&dai).unwrap(),
            filler_address,
            bytes_to_address(&router_address()).unwrap(),
        )
        .unwrap();

    let token_out_approval_needed = token_approvals_manager
        .approval_needed(bytes_to_address(&usdc).unwrap(), filler_address, usx_reactor)
        .unwrap();

    let full_calldata =
        (token_in_approval_needed, token_out_approval_needed, tycho_calldata).abi_encode_packed();

    let hex_calldata = encode(&full_calldata);
    write_calldata_to_file("test_sequential_swap_usx", hex_calldata.as_str());
}

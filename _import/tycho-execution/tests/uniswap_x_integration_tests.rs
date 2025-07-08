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
    encoding::encode_tycho_router_call, eth, eth_chain, get_tycho_router_encoder, router_address,
    usdc, wbtc, weth,
};

mod common;

#[test]
fn test_sequential_swap_unix() {
    // Performs a sequential swap from WETH to USDC though WBTC using USV3 and USV2
    // pools
    //
    //   WETH ───(USV3)──> WBTC ───(USV2)──> USDC
    // Creates all the calldata needed for the uniswap X callbackData

    let filler = Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap();
    let unix_reactor = Address::from_str("0x00000011F84B9aa48e5f8aA8B9897600006289Be").unwrap();

    let weth = weth();
    let wbtc = wbtc();
    let usdc = usdc();

    let swap_weth_wbtc = Swap {
        component: ProtocolComponent {
            id: "0xCBCdF9626bC03E24f779434178A73a0B4bad62eD".to_string(),
            protocol_system: "uniswap_v3".to_string(),
            static_attributes: {
                let mut attrs = HashMap::new();
                attrs.insert(
                    "fee".to_string(),
                    Bytes::from(BigInt::from(3000).to_signed_bytes_be()),
                );
                attrs
            },
            ..Default::default()
        },
        token_in: weth.clone(),
        token_out: wbtc.clone(),
        split: 0f64,
        user_data: None,
    };
    let swap_wbtc_usdc = Swap {
        component: ProtocolComponent {
            id: "0x004375Dff511095CC5A197A54140a24eFEF3A416".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        token_in: wbtc.clone(),
        token_out: usdc.clone(),
        split: 0f64,
        user_data: None,
    };
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: weth.clone(),
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: usdc.clone(),
        checked_amount: BigUint::from_str("26173932").unwrap(),
        sender: filler.clone(),
        receiver: filler.clone(),
        swaps: vec![swap_weth_wbtc, swap_wbtc_usdc],
        ..Default::default()
    };

    let encoded_solution = encoder
        .encode_solutions(vec![solution.clone()])
        .unwrap()[0]
        .clone();

    let tycho_calldata = encode_tycho_router_call(
        eth_chain().id,
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
            bytes_to_address(&weth).unwrap(),
            filler_address,
            bytes_to_address(&router_address()).unwrap(),
        )
        .unwrap();

    let token_out_approval_needed = token_approvals_manager
        .approval_needed(bytes_to_address(&usdc).unwrap(), filler_address, unix_reactor)
        .unwrap();

    let full_calldata =
        (token_in_approval_needed, token_out_approval_needed, tycho_calldata).abi_encode_packed();

    let hex_calldata = encode(&full_calldata);
    write_calldata_to_file("test_sequential_swap_unix", hex_calldata.as_str());
}

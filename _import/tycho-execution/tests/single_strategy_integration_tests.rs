mod common;

use std::str::FromStr;

use alloy::{hex::encode, primitives::U256, sol_types::SolValue};
use num_bigint::BigUint;
use tycho_common::{models::protocol::ProtocolComponent, Bytes};
use tycho_execution::encoding::{
    evm::utils::{biguint_to_u256, write_calldata_to_file},
    models::{NativeAction, Solution, Swap, UserTransferType},
};

use crate::common::{
    dai, encoding::encode_tycho_router_call, eth, eth_chain, get_signer, get_tycho_router_encoder,
    weth,
};

#[test]
fn test_single_swap_strategy_encoder() {
    // Performs a single swap from WETH to DAI on a USV2 pool, with no grouping
    // optimizations.
    let checked_amount = BigUint::from_str("2018817438608734439720").unwrap();
    let weth = weth();
    let dai = dai();

    let swap = Swap {
        component: ProtocolComponent {
            id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        token_in: weth.clone(),
        token_out: dai.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFromPermit2);

    let solution = Solution {
        exact_out: false,
        given_token: weth,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: dai,
        checked_amount: checked_amount.clone(),
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap],
        ..Default::default()
    };

    let encoded_solutions = encoder
        .encode_solutions(vec![solution.clone()])
        .unwrap();

    let calldata = encode_tycho_router_call(
        eth_chain().id(),
        encoded_solutions[0].clone(),
        &solution,
        &UserTransferType::TransferFromPermit2,
        &eth(),
        Some(get_signer()),
    )
    .unwrap()
    .data;
    let expected_min_amount_encoded = encode(U256::abi_encode(&biguint_to_u256(&checked_amount)));
    let expected_input = [
        "30ace1b1",                                                         // Function selector
        "0000000000000000000000000000000000000000000000000de0b6b3a7640000", // amount in
        "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
        "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f", // token out
        &expected_min_amount_encoded,                                       // min amount out
        "0000000000000000000000000000000000000000000000000000000000000000", // wrap
        "0000000000000000000000000000000000000000000000000000000000000000", // unwrap
        "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
    ]
    .join("");

    // after this there is the permit and because of the deadlines (that depend on block
    // time) it's hard to assert

    let expected_swap = String::from(concat!(
        // length of encoded swap without padding
        "0000000000000000000000000000000000000000000000000000000000000052",
        // Swap data
        "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
        "a478c2975ab1ea89e8196811f51a7b7ade33eb11", // component id
        "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
        "00",                                       // zero2one
        "00",                                       // transfer type TransferFrom
        "0000000000000000000000000000",             // padding
    ));
    let hex_calldata = encode(&calldata);

    assert_eq!(hex_calldata[..456], expected_input);
    assert_eq!(hex_calldata[1224..], expected_swap);
    write_calldata_to_file("test_single_swap_strategy_encoder", &hex_calldata.to_string());
}

#[test]
fn test_single_swap_strategy_encoder_no_permit2() {
    // Performs a single swap from WETH to DAI on a USV2 pool, without permit2 and no
    // grouping optimizations.

    let weth = weth();
    let dai = dai();

    let checked_amount = BigUint::from_str("1_640_000000000000000000").unwrap();
    let expected_min_amount = U256::from_str("1_640_000000000000000000").unwrap();

    let swap = Swap {
        component: ProtocolComponent {
            id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        token_in: weth.clone(),
        token_out: dai.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: weth,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: dai,
        checked_amount,
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap],
        ..Default::default()
    };

    let encoded_solution = encoder
        .encode_solutions(vec![solution.clone()])
        .unwrap()[0]
        .clone();
    let calldata = encode_tycho_router_call(
        eth_chain().id(),
        encoded_solution,
        &solution,
        &UserTransferType::TransferFrom,
        &eth(),
        None,
    )
    .unwrap()
    .data;
    let expected_min_amount_encoded = encode(U256::abi_encode(&expected_min_amount));
    let expected_input = [
        "5c4b639c",                                                         // Function selector
        "0000000000000000000000000000000000000000000000000de0b6b3a7640000", // amount in
        "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
        "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f", // token out
        &expected_min_amount_encoded,                                       // min amount out
        "0000000000000000000000000000000000000000000000000000000000000000", // wrap
        "0000000000000000000000000000000000000000000000000000000000000000", // unwrap
        "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
        "0000000000000000000000000000000000000000000000000000000000000001", // transfer from needed
        "0000000000000000000000000000000000000000000000000000000000000120", // offset of swap bytes
        "0000000000000000000000000000000000000000000000000000000000000052", /* length of swap
                                                                             * bytes without
                                                                             * padding */
        // Swap data
        "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
        "a478c2975ab1ea89e8196811f51a7b7ade33eb11", // component id
        "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
        "00",                                       // zero2one
        "00",                                       // transfer type TransferFrom
        "0000000000000000000000000000",             // padding
    ]
    .join("");

    let hex_calldata = encode(&calldata);

    assert_eq!(hex_calldata, expected_input);
    write_calldata_to_file("test_single_swap_strategy_encoder_no_permit2", hex_calldata.as_str());
}

#[test]
fn test_single_swap_strategy_encoder_no_transfer_in() {
    // Performs a single swap from WETH to DAI on a USV2 pool assuming that the tokens
    // are already in the router

    let weth = weth();
    let dai = dai();

    let checked_amount = BigUint::from_str("1_640_000000000000000000").unwrap();
    let expected_min_amount = U256::from_str("1_640_000000000000000000").unwrap();

    let swap = Swap {
        component: ProtocolComponent {
            id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        token_in: weth.clone(),
        token_out: dai.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };
    let encoder = get_tycho_router_encoder(UserTransferType::None);

    let solution = Solution {
        exact_out: false,
        given_token: weth,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: dai,
        checked_amount,
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap],
        ..Default::default()
    };

    let encoded_solution = encoder
        .encode_solutions(vec![solution.clone()])
        .unwrap()[0]
        .clone();
    let calldata = encode_tycho_router_call(
        eth_chain().id(),
        encoded_solution,
        &solution,
        &UserTransferType::None,
        &eth(),
        None,
    )
    .unwrap()
    .data;
    let expected_min_amount_encoded = encode(U256::abi_encode(&expected_min_amount));
    let expected_input = [
        "5c4b639c",                                                         // Function selector
        "0000000000000000000000000000000000000000000000000de0b6b3a7640000", // amount in
        "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
        "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f", // token out
        &expected_min_amount_encoded,                                       // min amount out
        "0000000000000000000000000000000000000000000000000000000000000000", // wrap
        "0000000000000000000000000000000000000000000000000000000000000000", // unwrap
        "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
        "0000000000000000000000000000000000000000000000000000000000000000", /* transfer from not
                                                                             * needed */
        "0000000000000000000000000000000000000000000000000000000000000120", // offset of swap bytes
        "0000000000000000000000000000000000000000000000000000000000000052", /* length of swap
                                                                             * bytes without
                                                                             * padding */
        // Swap data
        "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
        "a478c2975ab1ea89e8196811f51a7b7ade33eb11", // component id
        "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
        "00",                                       // zero2one
        "01",                                       // transfer type Transfer
        "0000000000000000000000000000",             // padding
    ]
    .join("");

    let hex_calldata = encode(&calldata);

    assert_eq!(hex_calldata, expected_input);
    write_calldata_to_file(
        "test_single_swap_strategy_encoder_no_transfer_in",
        hex_calldata.as_str(),
    );
}

#[test]
fn test_single_swap_strategy_encoder_wrap() {
    // Performs a single swap from WETH to DAI on a USV2 pool, wrapping ETH
    // Note: This test does not assert anything. It is only used to obtain integration
    // test data for our router solidity test.

    let dai = dai();

    let swap = Swap {
        component: ProtocolComponent {
            id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        token_in: weth(),
        token_out: dai.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFromPermit2);

    let solution = Solution {
        exact_out: false,
        given_token: eth(),
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: dai,
        checked_amount: BigUint::from_str("1659881924818443699787").unwrap(),
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap],
        native_action: Some(NativeAction::Wrap),
    };

    let encoded_solution = encoder
        .encode_solutions(vec![solution.clone()])
        .unwrap()[0]
        .clone();

    let calldata = encode_tycho_router_call(
        eth_chain().id(),
        encoded_solution,
        &solution,
        &UserTransferType::TransferFromPermit2,
        &eth(),
        Some(get_signer()),
    )
    .unwrap()
    .data;
    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_swap_strategy_encoder_wrap", hex_calldata.as_str());
}

#[test]
fn test_single_swap_strategy_encoder_unwrap() {
    // Performs a single swap from DAI to WETH on a USV2 pool, unwrapping ETH at the end
    // Note: This test does not assert anything. It is only used to obtain integration
    // test data for our router solidity test.

    let dai = dai();

    let swap = Swap {
        component: ProtocolComponent {
            id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        token_in: dai.clone(),
        token_out: weth(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFromPermit2);

    let solution = Solution {
        exact_out: false,
        given_token: dai,
        given_amount: BigUint::from_str("3_000_000000000000000000").unwrap(),
        checked_token: eth(),
        checked_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap],
        native_action: Some(NativeAction::Unwrap),
    };

    let encoded_solution = encoder
        .encode_solutions(vec![solution.clone()])
        .unwrap()[0]
        .clone();

    let calldata = encode_tycho_router_call(
        eth_chain().id(),
        encoded_solution,
        &solution,
        &UserTransferType::TransferFromPermit2,
        &eth(),
        Some(get_signer()),
    )
    .unwrap()
    .data;

    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_swap_strategy_encoder_unwrap", hex_calldata.as_str());
}

mod common;

use std::str::FromStr;

use alloy::{hex::encode, primitives::U256, sol_types::SolValue};
use num_bigint::BigUint;
use tycho_common::{models::protocol::ProtocolComponent, Bytes};
use tycho_contracts::encoding::{
    evm::utils::{biguint_to_u256, write_calldata_to_file},
    models::{Solution, Swap, UserTransferType},
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

    let swap = Swap::new(
        ProtocolComponent {
            id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        weth.clone(),
        dai.clone(),
    );

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFromPermit2);

    let solution = Solution {
        exact_out: false,
        token_in: weth,
        amount_in: BigUint::from_str("1_000000000000000000").unwrap(),
        token_out: dai,
        min_amount_out: checked_amount.clone(),
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
        &eth(),
        Some(get_signer()),
    )
    .unwrap()
    .data;
    let expected_min_amount_encoded = encode(U256::abi_encode(&biguint_to_u256(&checked_amount)));
    let expected_input = [
        "b322d802", // Function selector (singleSwapPermit2)
        "0000000000000000000000000000000000000000000000000de0b6b3a7640000", // amount in
        "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
        "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f", // token out
        &expected_min_amount_encoded, // min amount out
        "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
        "0000000000000000000000000000000000000000000000000000000000000000", // solverFeeBps = 0
        "0000000000000000000000000000000000000000000000000000000000000000", /* solverFeeReceiver
                     * = address(0) */
        "0000000000000000000000000000000000000000000000000000000000000000", // solverMaxContribution
    ]
    .join("");

    // After this there is the permit and because of the deadlines (that depend on block
    // time) it's hard to assert back

    let expected_swap = String::from(concat!(
        // length of encoded swap (62 bytes)
        "000000000000000000000000000000000000000000000000000000000000003e",
        // Swap data
        "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
        "a478c2975ab1ea89e8196811f51a7b7ade33eb11", // component id (pool address)
        "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
        "00",                                       // zero2one
        "00",                                       // transfer type TransferFrom
        "0000",                                     // padding to 32-byte boundary
    ));
    let hex_calldata = encode(&calldata);

    assert_eq!(hex_calldata[..520], expected_input);
    assert_eq!(hex_calldata[1288..], expected_swap);
    write_calldata_to_file("test_single_swap_strategy_encoder", &hex_calldata.to_string());
}

#[test]
fn test_single_swap_strategy_encoder_no_permit2() {
    // Performs a single swap from WETH to DAI on a USV2 pool, without permit2 and no
    // grouping optimizations.
    std::env::set_var("TYCHO_FEES_ENABLED", "true");

    let weth = weth();
    let dai = dai();

    let checked_amount = BigUint::from_str("1_640_000000000000000000").unwrap();
    let expected_min_amount = U256::from_str("1_640_000000000000000000").unwrap();

    let swap = Swap::new(
        ProtocolComponent {
            id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        weth.clone(),
        dai.clone(),
    );
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        token_in: weth,
        amount_in: BigUint::from_str("1_000000000000000000").unwrap(),
        token_out: dai,
        min_amount_out: checked_amount,
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap],
        ..Default::default()
    };

    let encoded_solution = encoder
        .encode_solutions(vec![solution.clone()])
        .unwrap()[0]
        .clone();
    let calldata =
        encode_tycho_router_call(eth_chain().id(), encoded_solution, &solution, &eth(), None)
            .unwrap()
            .data;
    let expected_min_amount_encoded = encode(U256::abi_encode(&expected_min_amount));
    let expected_input = [
        "d51d2a96", // Function selector
        "0000000000000000000000000000000000000000000000000de0b6b3a7640000", // amount in
        "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
        "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f", // token out
        &expected_min_amount_encoded, // min amount out
        "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
        "0000000000000000000000000000000000000000000000000000000000000000", // solverFeeBps
        "0000000000000000000000000000000000000000000000000000000000000000", // solverFeeReceiver
        "0000000000000000000000000000000000000000000000000000000000000000", // solverMaxContribution
        "0000000000000000000000000000000000000000000000000000000000000120", // offset of swap bytes
        "000000000000000000000000000000000000000000000000000000000000003e", // len swap (62 bytes)
        // Swap data
        "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
        "a478c2975ab1ea89e8196811f51a7b7ade33eb11", // component id (pool address)
        "6bc529dc7b81a031828ddce2bc419d01ff268c66", // receiver
        "00",                                       // zero2one
        "00",                                       // transfer type TransferFrom
        "0000",                                     // padding to 32-byte boundary
    ]
    .join("");

    let hex_calldata = encode(&calldata);

    assert_eq!(hex_calldata, expected_input);
    write_calldata_to_file("test_single_swap_strategy_encoder_no_permit2", hex_calldata.as_str());
}

#[test]
fn test_single_swap_with_fees_and_solver_contribution() {
    // Performs a single swap from WETH to DAI on a USV2 pool, with fees
    // Swap is 1 WETH for 2018.8 DAI
    // Tycho Router takes 1% -> 20.18 DAI (20188174386087344397)
    // Solver takes 1% -> 20.18 DAI (20188174386087344397)
    // But (for some reason) the solver contributes with at most 22 DAI
    let checked_amount = BigUint::from_str("2000_000000000000000000").unwrap();
    let weth = weth();
    let dai = dai();

    let swap = Swap::new(
        ProtocolComponent {
            id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        weth.clone(),
        dai.clone(),
    );
    std::env::set_var("TYCHO_FEES_ENABLED", "true");
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        token_in: weth,
        amount_in: BigUint::from_str("1_000000000000000000").unwrap(),
        token_out: dai,
        min_amount_out: checked_amount.clone(),
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap],
        solver_fee_bps: 100, // 1% fee
        solver_fee_receiver: Bytes::from_str("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de").unwrap(),
        max_solver_contribution: BigUint::from_str("22_000000000000000000").unwrap(),
    };

    let encoded_solutions = encoder
        .encode_solutions(vec![solution.clone()])
        .unwrap();

    let calldata = encode_tycho_router_call(
        eth_chain().id(),
        encoded_solutions[0].clone(),
        &solution,
        &eth(),
        None,
    )
    .unwrap()
    .data;

    let hex_calldata = encode(&calldata);

    write_calldata_to_file(
        "test_single_swap_with_fees_and_solver_contribution",
        &hex_calldata.to_string(),
    );
    std::env::remove_var("TYCHO_FEES_ENABLED");
}

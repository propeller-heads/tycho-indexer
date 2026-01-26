mod common;
use std::{collections::HashMap, str::FromStr};

use alloy::hex::encode;
use num_bigint::{BigInt, BigUint};
use tycho_common::{models::protocol::ProtocolComponent, Bytes};
use tycho_contracts::encoding::{
    evm::utils::write_calldata_to_file,
    models::{Solution, Swap, UserTransferType},
};

use crate::common::{
    encoding::encode_tycho_router_call, eth, eth_chain, get_signer, get_tycho_router_encoder, usdc,
    wbtc, weth,
};

#[test]
fn test_sequential_swap_strategy_encoder() {
    // Note: This test does not assert anything. It is only used to obtain integration
    // test data for our router solidity test.
    //
    // Performs a sequential swap from WETH to USDC through WBTC using USV2 pools
    //
    //   WETH ───(USV2)──> WBTC ───(USV2)──> USDC

    let weth = weth();
    let wbtc = wbtc();
    let usdc = usdc();

    let swap_weth_wbtc = Swap::new(
        ProtocolComponent {
            id: "0xBb2b8038a1640196FbE3e38816F3e67Cba72D940".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        weth.clone(),
        wbtc.clone(),
    );
    let swap_wbtc_usdc = Swap::new(
        ProtocolComponent {
            id: "0x004375Dff511095CC5A197A54140a24eFEF3A416".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        wbtc.clone(),
        usdc.clone(),
    );
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFromPermit2);

    let solution = Solution {
        exact_out: false,
        token_in: weth,
        amount_in: BigUint::from_str("1_000000000000000000").unwrap(),
        token_out: usdc,
        min_amount_out: BigUint::from_str("26173932").unwrap(),
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap_weth_wbtc, swap_wbtc_usdc],
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
        &UserTransferType::TransferFromPermit2,
        &eth(),
        Some(get_signer()),
    )
    .unwrap()
    .data;

    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_sequential_swap_strategy_encoder", hex_calldata.as_str());
}

#[test]
fn test_sequential_swap_strategy_encoder_no_permit2_integration() {
    // Performs a sequential swap from WETH to USDC though WBTC using USV2 pools
    //
    //   WETH ───(USV2)──> WBTC ───(USV2)──> USDC

    let weth = weth();
    let wbtc = wbtc();
    let usdc = usdc();

    let swap_weth_wbtc = Swap::new(
        ProtocolComponent {
            id: "0xBb2b8038a1640196FbE3e38816F3e67Cba72D940".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        weth.clone(),
        wbtc.clone(),
    );
    let swap_wbtc_usdc = Swap::new(
        ProtocolComponent {
            id: "0x004375Dff511095CC5A197A54140a24eFEF3A416".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        wbtc.clone(),
        usdc.clone(),
    );
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        token_in: weth,
        amount_in: BigUint::from_str("1_000000000000000000").unwrap(),
        token_out: usdc,
        min_amount_out: BigUint::from_str("26173932").unwrap(),
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap_weth_wbtc, swap_wbtc_usdc],
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

    let hex_calldata = encode(&calldata);

    let expected = String::from(concat!(
        "16b8bcb1", // function selector (sequentialSwap)
        "0000000000000000000000000000000000000000000000000de0b6b3a7640000", // amount in
        "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
        "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token out
        "00000000000000000000000000000000000000000000000000000000018f61ec", // min amount out
        "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
        "0000000000000000000000000000000000000000000000000000000000000000", // transferFrom
        "0000000000000000000000000000000000000000000000000000000000000000", // solverFeeBps
        "0000000000000000000000000000000000000000000000000000000000000000", // solverFeeReceiver
        "0000000000000000000000000000000000000000000000000000000000000000", // maxSolverContribution
        "0000000000000000000000000000000000000000000000000000000000000140", // offset of swap bytes
        "0000000000000000000000000000000000000000000000000000000000000080", // len swaps
        // swap 1
        "003e",                                     // swap length (62 bytes)
        "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
        "bb2b8038a1640196fbe3e38816f3e67cba72d940", // component id (pool address)
        "004375dff511095cc5a197a54140a24efef3a416", // receiver (next pool)
        "00",                                       // zero to one
        "00",                                       // transfer type TransferFrom
        // swap 2
        "003e",                                     // swap length
        "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
        "004375dff511095cc5a197a54140a24efef3a416", // component id (pool address)
        "6bc529dc7b81a031828ddce2bc419d01ff268c66", // receiver (tycho router)
        "01",                                       // zero to one
        "05",                                       // transfer type None
    ));

    assert_eq!(hex_calldata, expected);
    write_calldata_to_file(
        "test_sequential_swap_strategy_encoder_no_permit2",
        hex_calldata.as_str(),
    );
}

#[test]
fn test_sequential_strategy_cyclic_swap() {
    // This test has start and end tokens that are the same
    // The flow is:
    // USDC -> WETH -> USDC  using two pools

    let weth = weth();
    let usdc = usdc();

    // Create two Uniswap V3 pools for the cyclic swap
    // USDC -> WETH (Pool 1)
    let swap_usdc_weth = Swap::new(
        ProtocolComponent {
            id: "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640".to_string(), /* USDC-WETH USV3
                                                                           * Pool 1 */
            protocol_system: "uniswap_v3".to_string(),
            static_attributes: {
                let mut attrs = HashMap::new();
                attrs
                    .insert("fee".to_string(), Bytes::from(BigInt::from(500).to_signed_bytes_be()));
                attrs
            },
            ..Default::default()
        },
        usdc.clone(),
        weth.clone(),
    );

    // WETH -> USDC (Pool 2)
    let swap_weth_usdc = Swap::new(
        ProtocolComponent {
            id: "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8".to_string(), /* USDC-WETH USV3
                                                                           * Pool 2 */
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
        weth.clone(),
        usdc.clone(),
    );

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFromPermit2);

    let solution = Solution {
        exact_out: false,
        token_in: usdc.clone(),
        amount_in: BigUint::from_str("100000000").unwrap(), // 100 USDC (6 decimals)
        token_out: usdc.clone(),
        min_amount_out: BigUint::from_str("99389294").unwrap(), /* Expected output
                                                                 * from test */
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap_usdc_weth, swap_weth_usdc],
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
        &UserTransferType::TransferFromPermit2,
        &eth(),
        Some(get_signer()),
    )
    .unwrap()
    .data;
    let hex_calldata = alloy::hex::encode(&calldata);
    let expected_input = [
        "3f3723ff", // selector (sequentialSwapPermit2)
        "0000000000000000000000000000000000000000000000000000000005f5e100", // given amount
        "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // given token
        "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // checked token
        "0000000000000000000000000000000000000000000000000000000005ec8f6e", // min amount out
        "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
        "0000000000000000000000000000000000000000000000000000000000000000", // solverFeeBps = 0
        "0000000000000000000000000000000000000000000000000000000000000000", // solverFeeReceiver
        "0000000000000000000000000000000000000000000000000000000000000000", // maxSolverContribution
    ]
    .join("");

    // After this there is the permit and because of the deadlines (that depend on block
    // time) it's hard to assert back

    let expected_swaps = [
        "00000000000000000000000000000000000000000000000000000000000000d6",  // length of ple encoded swaps without padding
        "0069",  // ple encoded swaps
        "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
        "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token in
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token out
        "0001f4",                                   // pool fee
        "00",                                       // transfer type TransferFrom
        "6bc529dc7b81a031828ddce2bc419d01ff268c66", // receiver
        "88e6a0c2ddd26feeb64f039a2c41296fcb3f5640", // component id
        "01",                                       // zero2one
        "0069",                                     // ple encoded swaps
        "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
        "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token out
        "000bb8",                                   // pool fee
        "02",                                       // transfer type Transfer
        "6bc529dc7b81a031828ddce2bc419d01ff268c66", // receiver
        "8ad599c3a0ff1de082011efddc58f1908eb6e6d8", // component id
        "00",                                       // zero2one
        "00000000000000000000",                     // padding
    ]
        .join("");

    assert_eq!(hex_calldata[..520], expected_input);
    assert_eq!(hex_calldata[1288..], expected_swaps);
    write_calldata_to_file("test_sequential_strategy_cyclic_swap", hex_calldata.as_str());
}

#[test]
fn test_sequential_strategy_cyclic_swap_and_vault() {
    // This test has start and end tokens that are the same
    // The flow is:
    // USDC -> WETH -> USDC  using two pools
    // It uses vault's funds

    let weth = weth();
    let usdc = usdc();

    // Create two Uniswap V3 pools for the cyclic swap
    // USDC -> WETH (Pool 1)
    let swap_usdc_weth = Swap::new(
        ProtocolComponent {
            id: "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640".to_string(), /* USDC-WETH USV3
                                                                           * Pool 1 */
            protocol_system: "uniswap_v3".to_string(),
            static_attributes: {
                let mut attrs = HashMap::new();
                attrs
                    .insert("fee".to_string(), Bytes::from(BigInt::from(500).to_signed_bytes_be()));
                attrs
            },
            ..Default::default()
        },
        usdc.clone(),
        weth.clone(),
    );

    // WETH -> USDC (Pool 2)
    let swap_weth_usdc = Swap::new(
        ProtocolComponent {
            id: "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8".to_string(), /* USDC-WETH USV3
                                                                           * Pool 2 */
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
        weth.clone(),
        usdc.clone(),
    );

    let encoder = get_tycho_router_encoder(UserTransferType::UseVaultsFunds);

    let solution = Solution {
        exact_out: false,
        token_in: usdc.clone(),
        amount_in: BigUint::from_str("100000000").unwrap(), // 100 USDC (6 decimals)
        token_out: usdc.clone(),
        min_amount_out: BigUint::from_str("99389294").unwrap(), /* Expected output
                                                                 * from test */
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap_usdc_weth, swap_weth_usdc],
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
        &UserTransferType::UseVaultsFunds,
        &eth(),
        Some(get_signer()),
    )
    .unwrap()
    .data;
    let hex_calldata = alloy::hex::encode(&calldata);
    let expected_input = [
        "16b8bcb1", // selector (sequentialSwap)
        "0000000000000000000000000000000000000000000000000000000005f5e100", // amount in
        "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token in
        "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token out
        "0000000000000000000000000000000000000000000000000000000005ec8f6e", // min amount out
        "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
        "0000000000000000000000000000000000000000000000000000000000000001", // transferFrom
        "0000000000000000000000000000000000000000000000000000000000000000", // solverFeeBps = 0
        "0000000000000000000000000000000000000000000000000000000000000000", // solverFeeReceiver
        "0000000000000000000000000000000000000000000000000000000000000000", // maxSolverContribution
        "0000000000000000000000000000000000000000000000000000000000000140", // offset of swap bytes
        "00000000000000000000000000000000000000000000000000000000000000d6", // length of ple encoded swaps without padding
        "0069",  // ple encoded swaps
        "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
        "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token in
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token out
        "0001f4",                                   // pool fee
        "02",                                       // transfer type Transfer
        "6bc529dc7b81a031828ddce2bc419d01ff268c66", // receiver
        "88e6a0c2ddd26feeb64f039a2c41296fcb3f5640", // component id
        "01",                                       // zero2one
        "0069",                                     // ple encoded swaps
        "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
        "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token out
        "000bb8",                                   // pool fee
        "02",                                       // transfer type Transfer
        "6bc529dc7b81a031828ddce2bc419d01ff268c66", // receiver
        "8ad599c3a0ff1de082011efddc58f1908eb6e6d8", // component id
        "00",                                       // zero2one
        "00000000000000000000",                     // padding
    ]
        .join("");

    assert_eq!(hex_calldata, expected_input);
    write_calldata_to_file("test_sequential_strategy_cyclic_swap_and_vault", hex_calldata.as_str());
}

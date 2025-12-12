mod common;
use std::{collections::HashMap, str::FromStr, sync::Arc};

use alloy::{hex, hex::encode};
use num_bigint::{BigInt, BigUint};
use tycho_common::{models::protocol::ProtocolComponent, Bytes};
use tycho_execution::encoding::{
    evm::{
        testing_utils::MockRFQState,
        utils::{biguint_to_u256, write_calldata_to_file},
    },
    models::{Solution, Swap, SwapBuilder, UserTransferType},
};

use crate::common::{
    alice_address, encoding::encode_tycho_router_call, eth, eth_chain,
    get_base_tycho_router_encoder, get_signer, get_tycho_router_encoder, ondo, pepe, usdc, wbtc,
    weth,
};

#[test]
fn test_single_encoding_strategy_ekubo() {
    //   ETH ──(EKUBO)──> USDC

    let token_in = eth();
    let token_out = usdc(); // USDC

    let static_attributes = HashMap::from([
        ("fee".to_string(), Bytes::from(0_u64)),
        ("tick_spacing".to_string(), Bytes::from(0_u32)),
        ("extension".to_string(), Bytes::from("0x51d02a5948496a67827242eabc5725531342527c")), /* Oracle */
    ]);

    let component = ProtocolComponent {
        // All Ekubo swaps go through the core contract - not necessary to specify pool
        // id for test
        protocol_system: "ekubo_v2".to_string(),
        static_attributes,
        ..Default::default()
    };

    let swap = SwapBuilder::new(component, token_in.clone(), token_out.clone()).build();

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("1000").unwrap(),
        // Alice
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
    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_encoding_strategy_ekubo", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_maverick() {
    // GHO -> (maverick) -> USDC
    let maverick_pool = ProtocolComponent {
        id: String::from("0x14Cf6D2Fe3E1B326114b07d22A6F6bb59e346c67"),
        protocol_system: String::from("vm:maverick_v2"),
        ..Default::default()
    };
    let token_in = Bytes::from("0x40D16FC0246aD3160Ccc09B8D0D3A2cD28aE6C2f");
    let token_out = usdc();
    let swap = SwapBuilder::new(maverick_pool, token_in.clone(), token_out.clone()).build();

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("1000").unwrap(),
        // Alice
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
    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_encoding_strategy_maverick", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_usv4_eth_in() {
    // Performs a single swap from ETH to PEPE using a USV4 pool
    // Note: This test does not assert anything. It is only used to obtain integration
    // test data for our router solidity test.
    //
    //   ETH ───(USV4)──> PEPE
    //
    let eth = eth();
    let pepe = pepe();

    let pool_fee_eth_pepe = Bytes::from(BigInt::from(25000).to_signed_bytes_be());
    let tick_spacing_eth_pepe = Bytes::from(BigInt::from(500).to_signed_bytes_be());
    let mut static_attributes_eth_pepe: HashMap<String, Bytes> = HashMap::new();
    static_attributes_eth_pepe.insert("key_lp_fee".into(), pool_fee_eth_pepe);
    static_attributes_eth_pepe.insert("tick_spacing".into(), tick_spacing_eth_pepe);

    let swap_eth_pepe = Swap {
        component: ProtocolComponent {
            id: "0xecd73ecbf77219f21f129c8836d5d686bbc27d264742ddad620500e3e548e2c9".to_string(),
            protocol_system: "uniswap_v4".to_string(),
            static_attributes: static_attributes_eth_pepe,
            ..Default::default()
        },
        token_in: eth.clone(),
        token_out: pepe.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFromPermit2);

    let solution = Solution {
        exact_out: false,
        given_token: eth.clone(),
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: pepe,
        checked_amount: BigUint::from_str("152373460199848577067005852").unwrap(),
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap_eth_pepe],
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
        &eth,
        Some(get_signer()),
    )
    .unwrap()
    .data;
    let hex_calldata = encode(&calldata);

    write_calldata_to_file("test_single_encoding_strategy_usv4_eth_in", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_usv4_eth_out() {
    // Performs a single swap from USDC to ETH using a USV4 pool
    // Note: This test does not assert anything. It is only used to obtain integration
    // test data for our router solidity test.
    //
    //   USDC ───(USV4)──> ETH
    //
    let eth = eth();
    let usdc = usdc();

    // Fee and tick spacing information for this test is obtained by querying the
    // USV4 Position Manager contract: 0xbd216513d74c8cf14cf4747e6aaa6420ff64ee9e
    // Using the poolKeys function with the first 25 bytes of the pool id
    let pool_fee_usdc_eth = Bytes::from(BigInt::from(3000).to_signed_bytes_be());
    let tick_spacing_usdc_eth = Bytes::from(BigInt::from(60).to_signed_bytes_be());
    let mut static_attributes_usdc_eth: HashMap<String, Bytes> = HashMap::new();
    static_attributes_usdc_eth.insert("key_lp_fee".into(), pool_fee_usdc_eth);
    static_attributes_usdc_eth.insert("tick_spacing".into(), tick_spacing_usdc_eth);

    let swap_usdc_eth = Swap {
        component: ProtocolComponent {
            id: "0xdce6394339af00981949f5f3baf27e3610c76326a700af57e4b3e3ae4977f78d".to_string(),
            protocol_system: "uniswap_v4".to_string(),
            static_attributes: static_attributes_usdc_eth,
            ..Default::default()
        },
        token_in: usdc.clone(),
        token_out: eth.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFromPermit2);

    let solution = Solution {
        exact_out: false,
        given_token: usdc,
        given_amount: BigUint::from_str("3000_000000").unwrap(),
        checked_token: eth.clone(),
        checked_amount: BigUint::from_str("1117254495486192350").unwrap(),
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap_usdc_eth],
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
        &eth,
        Some(get_signer()),
    )
    .unwrap()
    .data;

    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_encoding_strategy_usv4_eth_out", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_usv4_grouped_swap() {
    // Performs a sequential swap from USDC to PEPE though ETH using two consecutive
    // USV4 pools
    //
    //   USDC ──(USV4)──> ETH ───(USV4)──> PEPE
    //

    let eth = eth();
    let usdc = usdc();
    let pepe = pepe();

    // Fee and tick spacing information for this test is obtained by querying the
    // USV4 Position Manager contract: 0xbd216513d74c8cf14cf4747e6aaa6420ff64ee9e
    // Using the poolKeys function with the first 25 bytes of the pool id
    let pool_fee_usdc_eth = Bytes::from(BigInt::from(3000).to_signed_bytes_be());
    let tick_spacing_usdc_eth = Bytes::from(BigInt::from(60).to_signed_bytes_be());
    let mut static_attributes_usdc_eth: HashMap<String, Bytes> = HashMap::new();
    static_attributes_usdc_eth.insert("key_lp_fee".into(), pool_fee_usdc_eth);
    static_attributes_usdc_eth.insert("tick_spacing".into(), tick_spacing_usdc_eth);

    let pool_fee_eth_pepe = Bytes::from(BigInt::from(25000).to_signed_bytes_be());
    let tick_spacing_eth_pepe = Bytes::from(BigInt::from(500).to_signed_bytes_be());
    let mut static_attributes_eth_pepe: HashMap<String, Bytes> = HashMap::new();
    static_attributes_eth_pepe.insert("key_lp_fee".into(), pool_fee_eth_pepe);
    static_attributes_eth_pepe.insert("tick_spacing".into(), tick_spacing_eth_pepe);

    let swap_usdc_eth = Swap {
        component: ProtocolComponent {
            id: "0xdce6394339af00981949f5f3baf27e3610c76326a700af57e4b3e3ae4977f78d".to_string(),
            protocol_system: "uniswap_v4".to_string(),
            static_attributes: static_attributes_usdc_eth,
            ..Default::default()
        },
        token_in: usdc.clone(),
        token_out: eth.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let swap_eth_pepe = Swap {
        component: ProtocolComponent {
            id: "0xecd73ecbf77219f21f129c8836d5d686bbc27d264742ddad620500e3e548e2c9".to_string(),
            protocol_system: "uniswap_v4".to_string(),
            static_attributes: static_attributes_eth_pepe,
            ..Default::default()
        },
        token_in: eth.clone(),
        token_out: pepe.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFromPermit2);

    let solution = Solution {
        exact_out: false,
        given_token: usdc,
        given_amount: BigUint::from_str("1000_000000").unwrap(),
        checked_token: pepe,
        checked_amount: BigUint::from_str("97191013220606467325121599").unwrap(),
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap_usdc_eth, swap_eth_pepe],
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
        &eth,
        Some(get_signer()),
    )
    .unwrap()
    .data;

    let expected_input = [
        "30ace1b1", // Function selector (single swap)
        "000000000000000000000000000000000000000000000000000000003b9aca00", // amount in
        "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token in
        "0000000000000000000000006982508145454ce325ddbe47a25d4ec3d2311933", // token out
        "0000000000000000000000000000000000000000005064ff624d54346285543f", // min amount out
        "0000000000000000000000000000000000000000000000000000000000000000", // wrap
        "0000000000000000000000000000000000000000000000000000000000000000", // unwrap
        "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
    ]
    .join("");

    // after this there is the permit and because of the deadlines (that depend on block
    // time) it's hard to assert

    let expected_swaps = String::from(concat!(
        // length of ple encoded swaps without padding
        "00000000000000000000000000000000000000000000000000000000000000b4",
        // Swap data header
        "f62849f9a0b5bf2913b396098f7c7019b51a820a", // executor address
        // Protocol data
        "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // group token in
        "6982508145454ce325ddbe47a25d4ec3d2311933", // group token in
        "00",                                       // zero2one
        "00",                                       // transfer type TransferFrom
        "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
        // First pool params
        "0000000000000000000000000000000000000000", // intermediary token (ETH)
        "000bb8",                                   // fee
        "00003c",                                   // tick spacing
        "0000000000000000000000000000000000000000", // hook address
        "0000",                                     // hook data length
        // ple encoding
        "0030",
        // Second pool params
        "6982508145454ce325ddbe47a25d4ec3d2311933", // intermediary token (PEPE)
        "0061a8",                                   // fee
        "0001f4",                                   // tick spacing
        "0000000000000000000000000000000000000000", // hook address
        "0000",                                     // hook data length
        "000000000000000000000000"                  // padding
    ));

    let hex_calldata = encode(&calldata);

    assert_eq!(hex_calldata[..456], expected_input);
    assert_eq!(hex_calldata[1224..], expected_swaps);
    write_calldata_to_file(
        "test_single_encoding_strategy_usv4_grouped_swap",
        hex_calldata.as_str(),
    );
}

#[test]
fn test_single_encoding_strategy_usv4_and_hooks_grouped_swap() {
    // Performs a sequential swap from WETH to USDC through ETH using
    // a USV4 pool with Euler hooks followed by a USV4 pool with no hooks
    //
    //   WETH  ───(USV4 Euler Hook)──> USDC ──(USV4)──> ETH

    let usdc = usdc();
    let eth = eth();
    let weth = Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

    // First pool: WETH -> USDC (USV4 with Euler)
    let pool_fee_weth_usdt = Bytes::from(BigInt::from(500).to_signed_bytes_be());
    let tick_spacing_weth_usdt = Bytes::from(BigInt::from(1).to_signed_bytes_be());
    let euler_hook = Bytes::from_str("0x69058613588536167BA0AA94F0CC1Fe420eF28a8").unwrap();
    let mut static_attributes_weth_usdt: HashMap<String, Bytes> = HashMap::new();
    static_attributes_weth_usdt.insert("key_lp_fee".into(), pool_fee_weth_usdt);
    static_attributes_weth_usdt.insert("tick_spacing".into(), tick_spacing_weth_usdt);
    static_attributes_weth_usdt.insert("hooks".into(), euler_hook);

    // Second pool: USDC -> ETH (USV4 no hooks)
    let pool_fee_usdc_eth = Bytes::from(BigInt::from(3000).to_signed_bytes_be());
    let tick_spacing_usdc_eth = Bytes::from(BigInt::from(60).to_signed_bytes_be());
    let mut static_attributes_usdc_eth: HashMap<String, Bytes> = HashMap::new();
    static_attributes_usdc_eth.insert("key_lp_fee".into(), pool_fee_usdc_eth);
    static_attributes_usdc_eth.insert("tick_spacing".into(), tick_spacing_usdc_eth);

    let swap_weth_usdc = Swap {
        component: ProtocolComponent {
            protocol_system: "uniswap_v4_hooks".to_string(),
            static_attributes: static_attributes_weth_usdt,
            ..Default::default()
        },
        token_in: weth.clone(),
        token_out: usdc.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let swap_usdc_eth = Swap {
        component: ProtocolComponent {
            id: "0xdce6394339af00981949f5f3baf27e3610c76326a700af57e4b3e3ae4977f78d".to_string(),
            protocol_system: "uniswap_v4".to_string(),
            static_attributes: static_attributes_usdc_eth,
            ..Default::default()
        },
        token_in: usdc.clone(),
        token_out: eth.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFromPermit2);

    let solution = Solution {
        exact_out: false,
        given_token: weth,
        given_amount: BigUint::from_str("1000000000000000000").unwrap(), // 1 WETH
        checked_token: eth.clone(),
        checked_amount: BigUint::from_str("900000000000000000").unwrap(), // 0.9 ETH
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap_weth_usdc, swap_usdc_eth],
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
        &eth,
        Some(get_signer()),
    )
    .unwrap()
    .data;

    let hex_calldata = encode(&calldata);
    write_calldata_to_file(
        "test_single_encoding_strategy_usv4_and_hooks_grouped_swap",
        hex_calldata.as_str(),
    );
}

#[test]
fn test_single_encoding_strategy_ekubo_grouped_swap() {
    // Test multi-hop Ekubo swap (grouped swaps)
    //
    //   USDE ──(EKUBO)──> USDC ──(EKUBO)──> USDT

    let usde = Bytes::from_str("0x4c9edd5852cd905f086c759e8383e09bff1e68b3").unwrap();
    let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
    let usdt = Bytes::from_str("0xdac17f958d2ee523a2206206994597c13d831ec7").unwrap();

    // First swap: USDE -> USDC
    let swap1 = Swap {
        component: ProtocolComponent {
            id: "a419f0ebb019eb85fdccd0200843752dd9cc31d0cb3127f3adb4ba37a092788f".to_string(),
            protocol_system: "ekubo_v2".to_string(),
            static_attributes: HashMap::from([
                ("fee".to_string(), Bytes::from(922337203685478_u64)),
                ("tick_spacing".to_string(), Bytes::from(100_u32)),
                (
                    "extension".to_string(),
                    Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
                ),
            ]),
            ..Default::default()
        },
        token_in: usde.clone(),
        token_out: usdc.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    // Second swap: USDC -> USDT
    let swap2 = Swap {
        component: ProtocolComponent {
            id: "ca5b3ef9770bb95940bd4e0bff5ead70a5973d904a8b370b52147820e61a2ff6".to_string(),
            protocol_system: "ekubo_v2".to_string(),
            static_attributes: HashMap::from([
                ("fee".to_string(), Bytes::from(92233720368547_u64)),
                ("tick_spacing".to_string(), Bytes::from(50_u32)),
                (
                    "extension".to_string(),
                    Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
                ),
            ]),
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
        given_token: usde,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: usdt,
        checked_amount: BigUint::from_str("1000").unwrap(),
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap1, swap2],
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
    write_calldata_to_file("test_single_ekubo_grouped_swap", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_curve() {
    //   UWU ──(curve 2 crypto pool)──> WETH

    let token_in = Bytes::from("0x55C08ca52497e2f1534B59E2917BF524D4765257"); // UWU
    let token_out = weth();

    let static_attributes = HashMap::from([(
        "factory".to_string(),
        Bytes::from(
            "0x98ee851a00abee0d95d08cf4ca2bdce32aeaaf7f"
                .as_bytes()
                .to_vec(),
        )),
        ("coins".to_string(), Bytes::from_str("0x5b22307863303261616133396232323366653864306130653563346632376561643930383363373536636332222c22307835356330386361353234393765326631353334623539653239313762663532346434373635323537225d").unwrap()),
    ]);

    let component = ProtocolComponent {
        id: String::from("0x77146B0a1d08B6844376dF6d9da99bA7F1b19e71"),
        protocol_system: String::from("vm:curve"),
        static_attributes,
        ..Default::default()
    };

    let swap = Swap {
        component,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("1").unwrap(),
        // Alice
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

    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_encoding_strategy_curve", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_curve_st_eth() {
    //   ETH ──(curve stETH pool)──> STETH

    let token_in = eth();
    let token_out = Bytes::from("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84"); // STETH

    let static_attributes = HashMap::from([(
        "factory".to_string(),
        Bytes::from(
            "0x0000000000000000000000000000000000000000"
                .as_bytes()
                .to_vec(),
        ),
    ),
        ("coins".to_string(), Bytes::from_str("0x5b22307865656565656565656565656565656565656565656565656565656565656565656565656565656565222c22307861653761623936353230646533613138653565313131623565616162303935333132643766653834225d").unwrap()),]);

    let component = ProtocolComponent {
        id: String::from("0xDC24316b9AE028F1497c275EB9192a3Ea0f67022"),
        protocol_system: String::from("vm:curve"),
        static_attributes,
        ..Default::default()
    };

    let swap = Swap {
        component,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("1").unwrap(),
        // Alice
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

    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_encoding_strategy_curve_st_eth", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_balancer_v3() {
    // steakUSDTlite -> (balancer v3) -> steakUSDR
    let balancer_pool = ProtocolComponent {
        id: String::from("0xf028ac624074d6793c36dc8a06ecec0f5a39a718"),
        protocol_system: String::from("vm:balancer_v3"),
        ..Default::default()
    };
    let token_in = Bytes::from("0x097ffedb80d4b2ca6105a07a4d90eb739c45a666");
    let token_out = Bytes::from("0x30881baa943777f92dc934d53d3bfdf33382cab3");
    let swap = Swap {
        component: balancer_pool,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("1000").unwrap(),
        // Alice
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
    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_encoding_strategy_balancer_v3", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_bebop() {
    // The quote was done separately where the sender is the router and the receiver is a random
    // user
    let _router = Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap();
    let user = Bytes::from_str("0xd2068e04cf586f76eece7ba5beb779d7bb1474a1").unwrap();

    let token_in = usdc();
    let token_out = ondo();
    let amount_in = BigUint::from_str("200000000").unwrap(); // 200 USDC
    let amount_out = BigUint::from_str("194477331556159832309").unwrap(); // 203.8 ONDO

    let partial_fill_offset = 12u64;
    let bebop_calldata = Bytes::from_str("0x4dcebcba00000000000000000000000000000000000000000000000000000000689b548f0000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d0139500000000000000000000000067336cec42645f55059eff241cb02ea5cc52ff86000000000000000000000000000000000000000000000000279ead5d9685f25b000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000faba6f8e4a5e8ab82f62fe7c39859fa577269be3000000000000000000000000000000000000000000000000000000000bebc20000000000000000000000000000000000000000000000000a8aea46aa4ec5c0f5000000000000000000000000d2068e04cf586f76eece7ba5beb779d7bb1474a100000000000000000000000000000000000000000000000000000000000000005230bcb979c81cebf94a3b5c08bcfa300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000414ce40058ff07f11d9224c2c8d1e58369e4a90173856202d8d2a17da48058ad683dedb742eda0d4c0cf04cf1c09138898dd7fd06f97268ea7f74ef9b42d29bf4c1b00000000000000000000000000000000000000000000000000000000000000").unwrap();
    let bebop_state = MockRFQState {
        quote_amount_out: amount_out.clone(),
        quote_data: HashMap::from([
            ("calldata".to_string(), bebop_calldata),
            (
                "partial_fill_offset".to_string(),
                Bytes::from(
                    partial_fill_offset
                        .to_be_bytes()
                        .to_vec(),
                ),
            ),
        ]),
    };

    let bebop_component = ProtocolComponent {
        id: String::from("bebop-rfq"),
        protocol_system: String::from("rfq:bebop"),
        static_attributes: HashMap::new(), // No static attributes needed
        ..Default::default()
    };

    let swap = SwapBuilder::new(bebop_component, token_in.clone(), token_out.clone())
        .estimated_amount_in(BigUint::from_str("200000000").unwrap())
        .protocol_state(Arc::new(bebop_state))
        .build();

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: amount_in,
        checked_token: token_out,
        checked_amount: amount_out, // Expected output amount
        sender: user.clone(),
        receiver: user,
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
    let hex_calldata = hex::encode(&calldata);
    write_calldata_to_file("test_single_encoding_strategy_bebop", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_bebop_aggregate() {
    // The quote was done separately where the sender is the router and the receiver is a random
    // user
    let _router = Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap();
    let user = Bytes::from_str("0xd2068e04cf586f76eece7ba5beb779d7bb1474a1").unwrap();

    let token_in = usdc();
    let token_out = ondo();
    let amount_in = BigUint::from_str("20000000000").unwrap(); // 20k USDC
    let amount_out = BigUint::from_str("18699321819466078474202").unwrap(); // 203.8 ONDO
    let partial_fill_offset = 2u64;

    let bebop_calldata = Bytes::from_str("0xa2f7489300000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000689b78880000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d01395000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000003e000000000000000000000000000000000000000000000000000000000000004c0000000000000000000000000d2068e04cf586f76eece7ba5beb779d7bb1474a100000000000000000000000000000000000000000000000000000000000005a060a5c2aaaaa2fe2cda34423cac76a84c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000051c72848c68a965f66fa7a88855f9f7784502a7f000000000000000000000000ce79b081c0c924cb67848723ed3057234d10fc6b00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000002901f2d62bb356ca0000000000000000000000000000000000000000000000002901f2d62bb356cb0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000faba6f8e4a5e8ab82f62fe7c39859fa577269be30000000000000000000000000000000000000000000000000000000000000001000000000000000000000000faba6f8e4a5e8ab82f62fe7c39859fa577269be30000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000044f83c726000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000589400da00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000003aa5f96046644f6e37a000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000004b51a26526ddbeec60000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000417ab4332f2b091d87d56d04eee35dd49452782c782de71608c0425c5ae41f1d7e147173851c870d76720ce07d45cd8622352716b1c7965819ee2bf8c573c499ae1b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000410c8da2637aa929e11caff9afdfc4c489320c6dba77cc934d88ba8956e365fd1d48983087c6e474bbb828181cdfdd17317c4c9c3ee4bc98e3769d0c05cc7a285e1c00000000000000000000000000000000000000000000000000000000000000").unwrap();
    let bebop_state = MockRFQState {
        quote_amount_out: amount_out.clone(),
        quote_data: HashMap::from([
            ("calldata".to_string(), bebop_calldata),
            (
                "partial_fill_offset".to_string(),
                Bytes::from(
                    partial_fill_offset
                        .to_be_bytes()
                        .to_vec(),
                ),
            ),
        ]),
    };

    let bebop_component = ProtocolComponent {
        id: String::from("bebop-rfq"),
        protocol_system: String::from("rfq:bebop"),
        static_attributes: HashMap::new(),
        ..Default::default()
    };

    let swap = SwapBuilder::new(bebop_component, token_in.clone(), token_out.clone())
        .estimated_amount_in(BigUint::from_str("20000000000").unwrap())
        .protocol_state(Arc::new(bebop_state))
        .build();

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in.clone(),
        given_amount: amount_in,
        checked_token: token_out,
        checked_amount: amount_out,
        sender: user.clone(),
        receiver: user,
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
    let hex_calldata = hex::encode(&calldata);

    write_calldata_to_file("test_single_encoding_strategy_bebop_aggregate", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_hashflow() {
    // Note: This test does not assert anything. It is only used to obtain
    // integration test data for our router solidity test.
    //
    // Performs a swap from USDC to WBTC using Hashflow RFQ
    //
    //   USDC ───(Hashflow RFQ)──> WBTC

    let usdc = usdc();
    let wbtc = wbtc();

    // USDC -> WBTC via Hashflow RFQ using real order data
    let quote_amount_out = BigUint::from_str("3714751").unwrap();

    let hashflow_state = MockRFQState {
        quote_amount_out,
        quote_data: HashMap::from([
            (
                "pool".to_string(),
                Bytes::from_str("0x478eca1b93865dca0b9f325935eb123c8a4af011").unwrap(),
            ),
            (
                "external_account".to_string(),
                Bytes::from_str("0xbee3211ab312a8d065c4fef0247448e17a8da000").unwrap(),
            ),
            (
                "trader".to_string(),
                Bytes::from_str("0xcd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2").unwrap(),
            ),
            (
                "base_token".to_string(),
                Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
            ),
            (
                "quote_token".to_string(),
                Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap(),
            ),
            (
                "base_token_amount".to_string(),
                Bytes::from(biguint_to_u256(&BigUint::from(4308094737_u64)).to_be_bytes::<32>().to_vec()),
            ),
            (
                "quote_token_amount".to_string(),
                Bytes::from(biguint_to_u256(&BigUint::from(3714751_u64)).to_be_bytes::<32>().to_vec()),
            ),
            ("quote_expiry".to_string(), Bytes::from(biguint_to_u256(&BigUint::from(1755610328_u64)).to_be_bytes::<32>().to_vec())),
            ("nonce".to_string(), Bytes::from(biguint_to_u256(&BigUint::from(1755610283723_u64)).to_be_bytes::<32>().to_vec())),
            (
                "tx_id".to_string(),
                Bytes::from_str(
                    "0x125000064000640000001747eb8c38ffffffffffffff0029642016edb36d0000",
                )
                    .unwrap(),
            ),
            ("signature".to_string(), Bytes::from_str("0x6ddb3b21fe8509e274ddf46c55209cdbf30360944abbca6569ed6b26740d052f419964dcb5a3bdb98b4ed1fb3642a2760b8312118599a962251f7a8f73fe4fbe1c").unwrap()),
        ]),
    };

    let hashflow_component = ProtocolComponent {
        id: String::from("hashflow-rfq"),
        protocol_system: String::from("rfq:hashflow"),
        ..Default::default()
    };

    let swap_usdc_wbtc = SwapBuilder::new(hashflow_component, usdc.clone(), wbtc.clone())
        .estimated_amount_in(BigUint::from_str("4308094737").unwrap())
        .protocol_state(Arc::new(hashflow_state))
        .build();

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: usdc,
        given_amount: BigUint::from_str("4308094737").unwrap(),
        checked_token: wbtc,
        checked_amount: BigUint::from_str("3714751").unwrap(),
        sender: alice_address(),
        receiver: alice_address(),
        swaps: vec![swap_usdc_wbtc],
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
    write_calldata_to_file("test_single_encoding_strategy_hashflow", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_fluid() {
    let fluid_dex = ProtocolComponent {
        id: String::from("0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b"),
        protocol_system: String::from("fluid_v1"),
        ..Default::default()
    };
    let token_in = Bytes::from("0x9d39a5de30e57443bff2a8307a4256c8797a3497");
    let token_out = Bytes::from("0xdac17f958d2ee523a2206206994597c13d831ec7");
    let alice = Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap();
    let swap = SwapBuilder::new(fluid_dex, token_in.clone(), token_out.clone()).build();

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("1000").unwrap(),
        // Alice
        sender: alice.clone(),
        receiver: alice,
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
    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_encoding_strategy_fluid_v1", hex_calldata.as_str());
}

#[test]
fn test_sequential_encoding_strategy_fluid() {
    let fluid_dex_1 = ProtocolComponent {
        id: String::from("0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b"),
        protocol_system: String::from("fluid_v1"),
        ..Default::default()
    };
    let fluid_dex_2 = ProtocolComponent {
        id: String::from("0xea734B615888c669667038D11950f44b177F15C0"),
        protocol_system: String::from("fluid_v1"),
        ..Default::default()
    };
    let token_in = Bytes::from("0x9d39a5de30e57443bff2a8307a4256c8797a3497");
    let usdt = Bytes::from("0xdac17f958d2ee523a2206206994597c13d831ec7");
    let token_out = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    let alice = Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap();
    let swap_1 = SwapBuilder::new(fluid_dex_1, token_in.clone(), usdt.clone()).build();
    let swap_2 = SwapBuilder::new(fluid_dex_2, usdt.clone(), token_out.clone()).build();

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("1000").unwrap(),
        // Alice
        sender: alice.clone(),
        receiver: alice,
        swaps: vec![swap_1, swap_2],
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
    write_calldata_to_file("test_sequential_encoding_strategy_fluid_v1", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_rocketpool_deposit() {
    // ETH -> (rocketpool) -> rETH
    // Based on real tx 0x6213b6c235c52d2132711c18a1c66934832722fd71c098e843bc792ecdbd11b3
    // where 4.5 ETH was deposited for 3.905847020555141679 rETH
    let rocketpool_pool = ProtocolComponent {
        id: String::from("0xdd3f50f8a6cafbe9b31a427582963f465e745af8"),
        protocol_system: String::from("rocketpool"),
        ..Default::default()
    };
    let token_in = eth();
    let token_out = Bytes::from("0xae78736Cd615f374D3085123A210448E74Fc6393");
    let swap = SwapBuilder::new(rocketpool_pool, token_in.clone(), token_out.clone()).build();

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from(4_500_000_000_000_000_000_u128),
        checked_token: token_out,
        checked_amount: BigUint::from(3_905_847_020_555_141_679_u128),
        // Alice
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
    let hex_calldata = encode(&calldata);
    write_calldata_to_file(
        "test_single_encoding_strategy_rocketpool_deposit",
        hex_calldata.as_str(),
    );
}

#[test]
fn test_single_encoding_strategy_rocketpool_burn() {
    // rETH -> (rocketpool) -> ETH
    // Based on real tx 0xf461ace5ae15d1db7a9f83da2e5a62745e91ecd1908274fb6583f70a29d8f68d
    // where 1 rETH was burned for 1.151971256664605227 ETH
    // We use `bob*` address as sender/receiver as Alice's address has a drainer deployed that
    // would interfere with the test when we send ETH back to her.
    let rocketpool_pool = ProtocolComponent {
        id: String::from("0xdd3f50f8a6cafbe9b31a427582963f465e745af8"),
        protocol_system: String::from("rocketpool"),
        ..Default::default()
    };
    let token_in = Bytes::from("0xae78736Cd615f374D3085123A210448E74Fc6393");
    let token_out = eth();
    let swap = SwapBuilder::new(rocketpool_pool, token_in.clone(), token_out.clone()).build();

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from(1_000_000_000_000_000_000u128), // 1 rETH
        checked_token: token_out,
        checked_amount: BigUint::from(1_151_971_256_664_605_227u128), // 1.151971256664605227 ETH
        // Bob*
        sender: Bytes::from_str("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de").unwrap(),
        receiver: Bytes::from_str("0x9964bff29baa37b47604f3f3f51f3b3c5149d6de").unwrap(),
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
    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_encoding_strategy_rocketpool_burn", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_slipstreams() {
    // WETH -> (Slipstreams) -> USDC
    let static_attributes = HashMap::from([(
        "tick_spacing".to_string(),
        Bytes::from(BigInt::from(100).to_signed_bytes_be()),
    )]);

    let slipstreams_pool = ProtocolComponent {
        id: String::from("0xb2cc224c1c9feE385f8ad6a55b4d94E92359DC59"),
        protocol_system: String::from("aerodrome_slipstreams"),
        static_attributes,
        ..Default::default()
    };
    let token_in = Bytes::from("0x4200000000000000000000000000000000000006");
    let token_out = Bytes::from("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
    let swap = Swap {
        component: slipstreams_pool,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_base_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("1000").unwrap(),
        // Alice
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
    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_encoding_strategy_slipstreams", hex_calldata.as_str());
}

#[test]
fn test_sequential_encoding_strategy_slipstreams() {
    // WETH -> (Slipstreams) -> USDC -> (Slipstreams) -> cbBTC
    let slipstreams_weth_usdc_pool = ProtocolComponent {
        id: String::from("0xb2cc224c1c9feE385f8ad6a55b4d94E92359DC59"),
        protocol_system: String::from("aerodrome_slipstreams"),
        static_attributes: HashMap::from([(
            "tick_spacing".to_string(),
            Bytes::from(BigInt::from(100).to_signed_bytes_be()),
        )]),
        ..Default::default()
    };
    let weth = Bytes::from("0x4200000000000000000000000000000000000006");
    let usdc = Bytes::from("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
    let swap1 = Swap {
        component: slipstreams_weth_usdc_pool,
        token_in: weth.clone(),
        token_out: usdc.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };
    let slipstreams_cbbtc_usdc_pool = ProtocolComponent {
        id: String::from("0x4e962BB3889Bf030368F56810A9c96B83CB3E778"),
        protocol_system: String::from("aerodrome_slipstreams"),
        static_attributes: HashMap::from([(
            "tick_spacing".to_string(),
            Bytes::from(BigInt::from(100).to_signed_bytes_be()),
        )]),
        ..Default::default()
    };
    let btc = Bytes::from("0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf");
    let swap2 = Swap {
        component: slipstreams_cbbtc_usdc_pool,
        token_in: usdc.clone(),
        token_out: btc.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_base_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: weth.clone(),
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: btc.clone(),
        checked_amount: BigUint::from_str("1000").unwrap(),
        // Alice
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap1, swap2],
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
    write_calldata_to_file("test_sequential_encoding_strategy_slipstreams", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_erc4626() {
    // WETH -> (ERC4626) -> spETH
    let erc4626_pool = ProtocolComponent {
        id: String::from("0xfE6eb3b609a7C8352A241f7F3A21CEA4e9209B8f"),
        protocol_system: String::from("erc4626"),
        ..Default::default()
    };
    let token_in = Bytes::from("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    let token_out = Bytes::from("0xfE6eb3b609a7C8352A241f7F3A21CEA4e9209B8f");
    let swap = Swap {
        component: erc4626_pool,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("1000").unwrap(),
        // Alice
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
    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_encoding_strategy_erc4626", hex_calldata.as_str());
}

#[test]
fn test_sequential_encoding_strategy_erc4626() {
    // spUSDC -> (ERC4626) -> USDC -> (ERC4626) -> sUSDC
    let spusdc_pool = ProtocolComponent {
        id: String::from("0x28b3a8fb53b741a8fd78c0fb9a6b2393d896a43d"),
        protocol_system: String::from("erc4626"),
        ..Default::default()
    };
    let sp_usdc = Bytes::from("0x28b3a8fb53b741a8fd78c0fb9a6b2393d896a43d");
    let usdc = Bytes::from("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
    let swap1 = Swap {
        component: spusdc_pool,
        token_in: sp_usdc.clone(),
        token_out: usdc.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };
    let susdc_pool = ProtocolComponent {
        id: String::from("0xbc65ad17c5c0a2a4d159fa5a503f4992c7b545fe"),
        protocol_system: String::from("erc4626"),
        ..Default::default()
    };
    let susdc = Bytes::from("0xbc65ad17c5c0a2a4d159fa5a503f4992c7b545fe");
    let swap2 = Swap {
        component: susdc_pool,
        token_in: usdc.clone(),
        token_out: susdc.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: sp_usdc.clone(),
        given_amount: BigUint::from_str("100_000_000").unwrap(),
        checked_token: susdc.clone(),
        checked_amount: BigUint::from_str("90_000000000000000000").unwrap(),
        // Alice
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap1, swap2],
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
    write_calldata_to_file("test_sequential_encoding_strategy_erc4626", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_steth_lido() {
    let lido_pool = ProtocolComponent {
        id: String::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
        protocol_system: String::from("lido"),
        ..Default::default()
    };
    let token_in = Bytes::from("0x0000000000000000000000000000000000000000");
    let token_out = Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84");
    let swap = Swap {
        component: lido_pool,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("999999999999999997").unwrap(),
        // Alice
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
    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_encoding_strategy_steth_lido", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_wrap_wsteth_lido() {
    let lido_pool = ProtocolComponent {
        id: String::from("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0"),
        protocol_system: String::from("lido"),
        ..Default::default()
    };

    let token_in = Bytes::from("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84");
    let token_out = Bytes::from("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0");
    let swap = Swap {
        component: lido_pool,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from_str("1000000000000000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("819085003283072218").unwrap(),
        // Alice
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
    let hex_calldata = encode(&calldata);
    write_calldata_to_file("test_single_encoding_strategy_wrap_wsteth_lido", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_unwrap_wsteth_lido() {
    let lido_pool = ProtocolComponent {
        id: String::from("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0"),
        protocol_system: String::from("lido"),
        ..Default::default()
    };
    let token_in = Bytes::from("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0");
    let token_out = Bytes::from("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84");

    let swap = Swap {
        component: lido_pool,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: token_in,
        given_amount: BigUint::from_str("1000000000000000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("1197232205332596846").unwrap(),
        // Alice
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

    let hex_calldata = encode(&calldata);
    write_calldata_to_file(
        "test_single_encoding_strategy_unwrap_wsteth_lido",
        hex_calldata.as_str(),
    );
}

#[test]
fn test_single_encoding_strategy_lido_grouped_swap() {
    // Performs a sequential swap from USDC to PEPE though ETH using two consecutive
    // USV4 pools
    //
    //   USDC ──(USV4)──> ETH (Lido)──> stETH
    //
    let eth = eth();
    let usdc = usdc();

    // Fee and tick spacing information for this test is obtained by querying the
    // USV4 Position Manager contract: 0xbd216513d74c8cf14cf4747e6aaa6420ff64ee9e
    // Using the poolKeys function with the first 25 bytes of the pool id
    let pool_fee_usdc_eth = Bytes::from(BigInt::from(3000).to_signed_bytes_be());
    let tick_spacing_usdc_eth = Bytes::from(BigInt::from(60).to_signed_bytes_be());
    let mut static_attributes_usdc_eth: HashMap<String, Bytes> = HashMap::new();
    static_attributes_usdc_eth.insert("key_lp_fee".into(), pool_fee_usdc_eth);
    static_attributes_usdc_eth.insert("tick_spacing".into(), tick_spacing_usdc_eth);

    let swap_usdc_eth = Swap {
        component: ProtocolComponent {
            id: "0xdce6394339af00981949f5f3baf27e3610c76326a700af57e4b3e3ae4977f78d".to_string(),
            protocol_system: "uniswap_v4".to_string(),
            static_attributes: static_attributes_usdc_eth,
            ..Default::default()
        },
        token_in: usdc.clone(),
        token_out: eth.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let lido_pool = ProtocolComponent {
        id: String::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
        protocol_system: String::from("lido"),
        ..Default::default()
    };

    let token_out = Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84");
    let swap_2 = Swap {
        component: lido_pool,
        token_in: eth.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: usdc,
        given_amount: BigUint::from_str("1000_000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("492041525283271396").unwrap(),
        // Alice
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap_usdc_eth, swap_2],
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
        &eth,
        None,
    )
    .unwrap()
    .data;

    let hex_calldata = encode(&calldata);

    write_calldata_to_file("test_single_encoding_strategy_usv4_lido_2", hex_calldata.as_str());
}

#[test]
fn test_single_encoding_strategy_curve_lido_grouped_swap() {
    //   ETH ──(Curve)──> stETH (Lido)──> wstETH

    let token_in = eth();
    let token_out = Bytes::from("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84"); // STETH

    let static_attributes = HashMap::from([(
        "factory".to_string(),
        Bytes::from(
            "0x0000000000000000000000000000000000000000"
                .as_bytes()
                .to_vec(),
        ),
    ),
        ("coins".to_string(), Bytes::from_str("0x5b22307865656565656565656565656565656565656565656565656565656565656565656565656565656565222c22307861653761623936353230646533613138653565313131623565616162303935333132643766653834225d").unwrap()),]);

    let component = ProtocolComponent {
        id: String::from("0xDC24316b9AE028F1497c275EB9192a3Ea0f67022"),
        protocol_system: String::from("vm:curve"),
        static_attributes,
        ..Default::default()
    };

    let swap = Swap {
        component,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let lido_pool = ProtocolComponent {
        id: String::from("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0"),
        protocol_system: String::from("lido"),
        ..Default::default()
    };
    let token_in = Bytes::from("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84");
    let token_out = Bytes::from("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0");

    let swap_2 = Swap {
        component: lido_pool,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
        estimated_amount_in: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: eth(),
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: token_out,
        checked_amount: BigUint::from_str("835224812176401374").unwrap(),
        // Alice
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap, swap_2],
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
        Some(get_signer()),
    )
    .unwrap()
    .data;

    let hex_calldata = encode(&calldata);

    write_calldata_to_file(
        "test_single_encoding_strategy_curve_lido_grouped_swap",
        hex_calldata.as_str(),
    );
}

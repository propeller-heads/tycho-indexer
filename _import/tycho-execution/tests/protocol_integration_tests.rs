mod common;
use std::{collections::HashMap, str::FromStr};

use alloy::{hex, hex::encode};
use num_bigint::{BigInt, BigUint};
use tycho_common::{models::protocol::ProtocolComponent, Bytes};
use tycho_execution::encoding::{
    evm::utils::{biguint_to_u256, write_calldata_to_file},
    models::{Solution, Swap, UserTransferType},
};

use crate::common::{
    build_bebop_calldata, encoding::encode_tycho_router_call, eth, eth_chain, get_signer,
    get_tycho_router_encoder, ondo, pepe, usdc, weth,
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

    let swap = Swap {
        component,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
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
    let swap = Swap {
        component: maverick_pool,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
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
        "0000000000000000000000000000000000000000000000000000000000000086",
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
        // Second pool params
        "6982508145454ce325ddbe47a25d4ec3d2311933", // intermediary token (PEPE)
        "0061a8",                                   // fee
        "0001f4",                                   // tick spacing
        "0000000000000000000000000000000000000000000000000000"  // padding
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
    let partial_fill_offset = 12;

    let calldata = Bytes::from_str("0x4dcebcba00000000000000000000000000000000000000000000000000000000689b548f0000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d0139500000000000000000000000067336cec42645f55059eff241cb02ea5cc52ff86000000000000000000000000000000000000000000000000279ead5d9685f25b000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000faba6f8e4a5e8ab82f62fe7c39859fa577269be3000000000000000000000000000000000000000000000000000000000bebc20000000000000000000000000000000000000000000000000a8aea46aa4ec5c0f5000000000000000000000000d2068e04cf586f76eece7ba5beb779d7bb1474a100000000000000000000000000000000000000000000000000000000000000005230bcb979c81cebf94a3b5c08bcfa300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000414ce40058ff07f11d9224c2c8d1e58369e4a90173856202d8d2a17da48058ad683dedb742eda0d4c0cf04cf1c09138898dd7fd06f97268ea7f74ef9b42d29bf4c1b00000000000000000000000000000000000000000000000000000000000000").unwrap();
    let user_data =
        build_bebop_calldata(&calldata, partial_fill_offset, biguint_to_u256(&amount_in));

    let bebop_component = ProtocolComponent {
        id: String::from("bebop-rfq"),
        protocol_system: String::from("rfq:bebop"),
        static_attributes: HashMap::new(), // No static attributes needed
        ..Default::default()
    };

    let swap = Swap {
        component: bebop_component,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: Some(user_data),
        protocol_state: None,
    };

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
    let partial_fill_offset = 2;

    let calldata = Bytes::from_str("0xa2f7489300000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000689b78880000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d01395000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000003e000000000000000000000000000000000000000000000000000000000000004c0000000000000000000000000d2068e04cf586f76eece7ba5beb779d7bb1474a100000000000000000000000000000000000000000000000000000000000005a060a5c2aaaaa2fe2cda34423cac76a84c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000051c72848c68a965f66fa7a88855f9f7784502a7f000000000000000000000000ce79b081c0c924cb67848723ed3057234d10fc6b00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000002901f2d62bb356ca0000000000000000000000000000000000000000000000002901f2d62bb356cb0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000faba6f8e4a5e8ab82f62fe7c39859fa577269be30000000000000000000000000000000000000000000000000000000000000001000000000000000000000000faba6f8e4a5e8ab82f62fe7c39859fa577269be30000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000044f83c726000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000589400da00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000003aa5f96046644f6e37a000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000004b51a26526ddbeec60000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000417ab4332f2b091d87d56d04eee35dd49452782c782de71608c0425c5ae41f1d7e147173851c870d76720ce07d45cd8622352716b1c7965819ee2bf8c573c499ae1b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000410c8da2637aa929e11caff9afdfc4c489320c6dba77cc934d88ba8956e365fd1d48983087c6e474bbb828181cdfdd17317c4c9c3ee4bc98e3769d0c05cc7a285e1c00000000000000000000000000000000000000000000000000000000000000").unwrap();
    let user_data =
        build_bebop_calldata(&calldata, partial_fill_offset, biguint_to_u256(&amount_in));

    let bebop_component = ProtocolComponent {
        id: String::from("bebop-rfq"),
        protocol_system: String::from("rfq:bebop"),
        static_attributes: HashMap::new(),
        ..Default::default()
    };

    let swap = Swap {
        component: bebop_component,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        split: 0f64,
        user_data: Some(user_data),
        protocol_state: None,
    };

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

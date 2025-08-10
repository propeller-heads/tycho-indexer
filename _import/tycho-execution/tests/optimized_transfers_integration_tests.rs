use std::{collections::HashMap, str::FromStr};

use alloy::{
    hex::encode,
    primitives::{Address, U256},
    sol_types::SolValue,
};
use num_bigint::{BigInt, BigUint};
use tycho_common::{models::protocol::ProtocolComponent, Bytes};
use tycho_execution::encoding::{
    evm::utils::write_calldata_to_file,
    models::{BebopOrderType, Solution, Swap, UserTransferType},
};

use crate::common::{
    build_bebop_calldata, encoding::encode_tycho_router_call, eth, eth_chain, get_signer,
    get_tycho_router_encoder, ondo, usdc, weth,
};

mod common;
// In this module we test the ability to chain swaps or not. Different protocols are
// tested. The encoded data is used for solidity tests as well

#[test]
fn test_uniswap_v3_uniswap_v2() {
    // Note: This test does not assert anything. It is only used to obtain
    // integration test data for our router solidity test.
    //
    // Performs a sequential swap from WETH to USDC though WBTC using USV3 and USV2
    // pools
    //
    //   WETH ───(USV3)──> WBTC ───(USV2)──> USDC

    let weth = weth();
    let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
    let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

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
        protocol_state: None,
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
        protocol_state: None,
    };
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: weth,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: usdc,
        checked_amount: BigUint::from_str("26173932").unwrap(),
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
    write_calldata_to_file("test_uniswap_v3_uniswap_v2", hex_calldata.as_str());
}

#[test]
fn test_uniswap_v3_uniswap_v3() {
    // Note: This test does not assert anything. It is only used to obtain
    // integration test data for our router solidity test.
    //
    // Performs a sequential swap from WETH to USDC though WBTC using USV3 pools
    // There is no optimization between the two USV3 pools, this is currently not
    // supported.
    //
    //   WETH ───(USV3)──> WBTC ───(USV3)──> USDC

    let weth = weth();
    let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
    let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

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
        protocol_state: None,
    };
    let swap_wbtc_usdc = Swap {
        component: ProtocolComponent {
            id: "0x99ac8cA7087fA4A2A1FB6357269965A2014ABc35".to_string(),
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
        token_in: wbtc.clone(),
        token_out: usdc.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
    };
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: weth,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: usdc,
        checked_amount: BigUint::from_str("26173932").unwrap(),
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
    write_calldata_to_file("test_uniswap_v3_uniswap_v3", hex_calldata.as_str());
}

#[test]
fn test_uniswap_v3_curve() {
    // Note: This test does not assert anything. It is only used to obtain
    // integration test data for our router solidity test.
    //
    // Performs a sequential swap from WETH to USDT though WBTC using USV3 and curve
    // pools
    //
    //   WETH ───(USV3)──> WBTC ───(curve)──> USDT

    let weth = weth();
    let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
    let usdt = Bytes::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap();

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
        protocol_state: None,
    };

    let swap_wbtc_usdt = Swap {
        component: ProtocolComponent {
            id: String::from("0xD51a44d3FaE010294C616388b506AcdA1bfAAE46"),
            protocol_system: String::from("vm:curve"),
            static_attributes: {
                let mut attrs: HashMap<String, Bytes> = HashMap::new();
                attrs.insert(
                    "factory".into(),
                    Bytes::from(
                        "0x0000000000000000000000000000000000000000"
                            .as_bytes()
                            .to_vec(),
                    ),
                );
                attrs.insert(
                    "coins".into(),
                    Bytes::from_str("0x5b22307864616331376639353864326565353233613232303632303639393435393763313364383331656337222c22307832323630666163356535353432613737336161343466626366656466376331393362633263353939222c22307863303261616133396232323366653864306130653563346632376561643930383363373536636332225d")
                        .unwrap(),
                );
                attrs
            },
            ..Default::default()
        },
        token_in: wbtc.clone(),
        token_out: usdt.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
    };
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: weth,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: usdt,
        checked_amount: BigUint::from_str("26173932").unwrap(),
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap_weth_wbtc, swap_wbtc_usdt],
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
    write_calldata_to_file("test_uniswap_v3_curve", hex_calldata.as_str());
}

#[test]
fn test_balancer_v2_uniswap_v2() {
    // Note: This test does not assert anything. It is only used to obtain
    // integration test data for our router solidity test.
    //
    // Performs a sequential swap from WETH to USDC though WBTC using balancer and
    // USV2 pools
    //
    //   WETH ───(balancer)──> WBTC ───(USV2)──> USDC

    let weth = weth();
    let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
    let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

    let swap_weth_wbtc = Swap {
        component: ProtocolComponent {
            id: "0xa6f548df93de924d73be7d25dc02554c6bd66db500020000000000000000000e".to_string(),
            protocol_system: "vm:balancer_v2".to_string(),
            ..Default::default()
        },
        token_in: weth.clone(),
        token_out: wbtc.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
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
        protocol_state: None,
    };
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: weth,
        given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
        checked_token: usdc,
        checked_amount: BigUint::from_str("26173932").unwrap(),
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
    write_calldata_to_file("test_balancer_v2_uniswap_v2", hex_calldata.as_str());
}

#[test]
fn test_multi_protocol() {
    // Note: This test does not assert anything. It is only used to obtain
    // integration test data for our router solidity test.
    //
    // Performs the following swap:
    //
    //   DAI ─(USV2)-> WETH ─(bal)─> WBTC ─(curve)─> USDT ─(ekubo)─> USDC ─(USV4)─>
    // ETH

    let weth = weth();
    let eth = eth();
    let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
    let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
    let usdt = Bytes::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap();
    let dai = Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap();

    let usv2_swap_dai_weth = Swap {
        component: ProtocolComponent {
            id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        token_in: dai.clone(),
        token_out: weth.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
    };

    let balancer_swap_weth_wbtc = Swap {
        component: ProtocolComponent {
            id: "0xa6f548df93de924d73be7d25dc02554c6bd66db500020000000000000000000e".to_string(),
            protocol_system: "vm:balancer_v2".to_string(),
            ..Default::default()
        },
        token_in: weth.clone(),
        token_out: wbtc.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
    };

    let curve_swap_wbtc_usdt = Swap {
        component: ProtocolComponent {
            id: String::from("0xD51a44d3FaE010294C616388b506AcdA1bfAAE46"),
            protocol_system: String::from("vm:curve"),
            static_attributes: {
                let mut attrs: HashMap<String, Bytes> = HashMap::new();
                attrs.insert(
                    "factory".into(),
                    Bytes::from(
                        "0x0000000000000000000000000000000000000000"
                            .as_bytes()
                            .to_vec(),
                    ),
                );
                attrs.insert(
                    "coins".into(),
                    Bytes::from_str("0x5b22307864616331376639353864326565353233613232303632303639393435393763313364383331656337222c22307832323630666163356535353432613737336161343466626366656466376331393362633263353939222c22307863303261616133396232323366653864306130653563346632376561643930383363373536636332225d")
                        .unwrap(),
                );
                attrs
            },
            ..Default::default()
        },
        token_in: wbtc.clone(),
        token_out: usdt.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
    };

    // Ekubo

    let component = ProtocolComponent {
        // All Ekubo swaps go through the core contract - not necessary to specify
        // pool id for test
        protocol_system: "ekubo_v2".to_string(),
        // 0.0025% fee & 0.005% base pool
        static_attributes: HashMap::from([
            ("fee".to_string(), Bytes::from(461168601842738_u64)),
            ("tick_spacing".to_string(), Bytes::from(50_u32)),
            ("extension".to_string(), Bytes::zero(20)),
        ]),
        ..Default::default()
    };
    let ekubo_swap_usdt_usdc = Swap {
        component,
        token_in: usdt.clone(),
        token_out: usdc.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
    };

    // USV4
    // Fee and tick spacing information for this test is obtained by querying the
    // USV4 Position Manager contract: 0xbd216513d74c8cf14cf4747e6aaa6420ff64ee9e
    // Using the poolKeys function with the first 25 bytes of the pool id
    let pool_fee_usdc_eth = Bytes::from(BigInt::from(3000).to_signed_bytes_be());
    let tick_spacing_usdc_eth = Bytes::from(BigInt::from(60).to_signed_bytes_be());
    let mut static_attributes_usdc_eth: HashMap<String, Bytes> = HashMap::new();
    static_attributes_usdc_eth.insert("key_lp_fee".into(), pool_fee_usdc_eth);
    static_attributes_usdc_eth.insert("tick_spacing".into(), tick_spacing_usdc_eth);

    let usv4_swap_usdc_eth = Swap {
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

    // Put all components together
    let solution = Solution {
        exact_out: false,
        given_token: dai,
        given_amount: BigUint::from_str("1500_000000000000000000").unwrap(),
        checked_token: eth.clone(),
        checked_amount: BigUint::from_str("732214216964381330").unwrap(),
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![
            usv2_swap_dai_weth,
            balancer_swap_weth_wbtc,
            curve_swap_wbtc_usdt,
            ekubo_swap_usdt_usdc,
            usv4_swap_usdc_eth,
        ],
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
    write_calldata_to_file("test_multi_protocol", hex_calldata.as_str());
}

#[test]
fn test_uniswap_v3_balancer_v3() {
    // Note: This test does not assert anything. It is only used to obtain
    // integration test data for our router solidity test.
    //
    //   WETH ───(USV3)──> WBTC ───(balancer v3)──> QNT

    let weth = weth();
    let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
    let qnt = Bytes::from_str("0x4a220e6096b25eadb88358cb44068a3248254675").unwrap();

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
        protocol_state: None,
    };
    let swap_wbtc_qnt = Swap {
        component: ProtocolComponent {
            id: "0x571bea0e99e139cd0b6b7d9352ca872dfe0d72dd".to_string(),
            protocol_system: "vm:balancer_v3".to_string(),
            ..Default::default()
        },
        token_in: wbtc.clone(),
        token_out: qnt.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
    };
    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: weth,
        given_amount: BigUint::from_str("1_0000000000000000").unwrap(),
        checked_token: qnt,
        checked_amount: BigUint::from_str("26173932").unwrap(),
        sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
        swaps: vec![swap_weth_wbtc, swap_wbtc_qnt],
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
    write_calldata_to_file("test_uniswap_v3_balancer_v3", hex_calldata.as_str());
}

#[test]
fn test_uniswap_v3_bebop() {
    // Note: This test does not assert anything. It is only used to obtain
    // integration test data for our router solidity test.
    //
    // Performs a sequential swap from WETH to ONDO through USDC using USV3 and
    // Bebop RFQ
    //
    //   WETH ───(USV3)──> USDC ───(Bebop RFQ)──> ONDO

    let weth = weth();
    let usdc = usdc();
    let ondo = ondo();

    // First swap: WETH -> USDC via UniswapV3
    let swap_weth_usdc = Swap {
        component: ProtocolComponent {
            id: "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640".to_string(), /* WETH-USDC USV3 Pool
                                                                           * 0.05% */
            protocol_system: "uniswap_v3".to_string(),
            static_attributes: {
                let mut attrs = HashMap::new();
                attrs
                    .insert("fee".to_string(), Bytes::from(BigInt::from(500).to_signed_bytes_be()));
                attrs
            },
            ..Default::default()
        },
        token_in: weth.clone(),
        token_out: usdc.clone(),
        split: 0f64,
        user_data: None,
        protocol_state: None,
    };

    // Second swap: USDC -> ONDO via Bebop RFQ using real order data
    // Using the same real order from the mainnet transaction at block 22667985
    let expiry = 1749483840u64; // Real expiry from the order
    let taker_address = Address::from_str("0xc5564C13A157E6240659fb81882A28091add8670").unwrap(); // Real taker
    let maker_address = Address::from_str("0xCe79b081c0c924cb67848723ed3057234d10FC6b").unwrap(); // Real maker
    let maker_nonce = 1749483765992417u64; // Real nonce
    let taker_token = Address::from_str(&usdc.to_string()).unwrap();
    let maker_token = Address::from_str(&ondo.to_string()).unwrap();
    // Using the real order amounts
    let taker_amount = U256::from_str("200000000").unwrap(); // 200 USDC (6 decimals)
    let maker_amount = U256::from_str("237212396774431060000").unwrap(); // 237.21 ONDO (18 decimals)
    let receiver = Address::from_str("0xc5564C13A157E6240659fb81882A28091add8670").unwrap(); // Real receiver
    let packed_commands = U256::ZERO;
    let flags = U256::from_str(
        "51915842898789398998206002334703507894664330885127600393944965515693155942400",
    )
    .unwrap(); // Real flags

    // Encode using standard ABI encoding (not packed)
    let quote_data = (
        expiry,
        taker_address,
        maker_address,
        maker_nonce,
        taker_token,
        maker_token,
        taker_amount,
        maker_amount,
        receiver,
        packed_commands,
        flags,
    )
        .abi_encode();

    // Real signature from the order
    let signature = hex::decode("eb5419631614978da217532a40f02a8f2ece37d8cfb94aaa602baabbdefb56b474f4c2048a0f56502caff4ea7411d99eed6027cd67dc1088aaf4181dcb0df7051c").unwrap();

    // Build user_data with the quote and signature
    let user_data = build_bebop_calldata(
        BebopOrderType::Single,
        U256::from(0), // 0 means fill entire order
        &quote_data,
        vec![(signature, 0)], // ETH_SIGN signature type (0)
    );

    let bebop_component = ProtocolComponent {
        id: String::from("bebop-rfq"),
        protocol_system: String::from("rfq:bebop"),
        static_attributes: HashMap::new(), // No static attributes needed
        ..Default::default()
    };

    let swap_usdc_ondo = Swap {
        component: bebop_component,
        token_in: usdc.clone(),
        token_out: ondo.clone(),
        split: 0f64,
        user_data: Some(user_data),
        protocol_state: None,
    };

    let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

    let solution = Solution {
        exact_out: false,
        given_token: weth,
        // Use ~0.099 WETH to get approximately 200 USDC from UniswapV3
        // This should leave only dust amount in the router after Bebop consumes 200
        // USDC
        given_amount: BigUint::from_str("99000000000000000").unwrap(), // 0.099 WETH
        checked_token: ondo,
        checked_amount: BigUint::from_str("237212396774431060000").unwrap(), /* Expected ONDO from Bebop order */
        sender: Bytes::from_str("0xc5564C13A157E6240659fb81882A28091add8670").unwrap(), /* Must match order taker_address */
        receiver: Bytes::from_str("0xc5564C13A157E6240659fb81882A28091add8670").unwrap(), /* Using the real order receiver */
        swaps: vec![swap_weth_usdc, swap_usdc_ondo],
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
    write_calldata_to_file("test_uniswap_v3_bebop", hex_calldata.as_str());
}

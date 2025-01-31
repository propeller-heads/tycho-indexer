use std::str::FromStr;

use num_bigint::BigUint;
use tycho_core::{dto::ProtocolComponent, models::Chain, Bytes};
use tycho_execution::encoding::{
    evm::{
        strategy_encoder::strategy_selector::EVMStrategySelector, tycho_encoder::EVMTychoEncoder,
    },
    models::{Solution, Swap},
    tycho_encoder::TychoEncoder,
};

fn main() {
    // Setup variables
    let router_address = "0x1234567890abcdef1234567890abcdef12345678".to_string();
    let signer_pk =
        Some("0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234".to_string());
    let user_address = Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2")
        .expect("Failed to create user address");

    // Initialize the encoder
    let encoder =
        EVMTychoEncoder::new(EVMStrategySelector, router_address, signer_pk, Chain::Ethereum)
            .expect("Failed to create encoder");

    // Prepare data to encode. We will encode a simple swap from WETH to DAI
    // First we need to create a swap object
    let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
        .expect("Failed to create WETH address");
    let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f")
        .expect("Failed to create DAI address");

    let swap = Swap {
        // The protocol component data comes from tycho-indexer
        component: ProtocolComponent {
            id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        token_in: weth.clone(),
        token_out: dai.clone(),
        // Split represents the percentage of the amount to be swapped. If it's 0 it represents 100%
        // or what is left of the amount in.
        split: 0f64,
    };

    // Then we create a solution object with the previous swap
    let solution = Solution {
        sender: user_address.clone(),
        receiver: user_address,
        given_token: weth,
        given_amount: BigUint::from_str("1_000000000000000000").expect("Failed to create amount"),
        checked_token: dai,
        exact_out: false,   // it's an exact in solution
        check_amount: None, // the amount out will not be checked in execution
        swaps: vec![swap],
        ..Default::default()
    };

    // Encode the solution
    let transactions = encoder
        .encode_router_calldata(vec![solution])
        .expect("Failed to encode router calldata");
    let tx = transactions[0].clone();

    println!(
        "The encoded transaction should be sent to address {:?} with the value of {:?} and the \
    following encoded data: {:?}",
        tx.to,
        tx.value,
        hex::encode(tx.data)
    );
}

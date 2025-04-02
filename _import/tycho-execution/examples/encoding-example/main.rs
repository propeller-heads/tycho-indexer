use std::str::FromStr;

use num_bigint::BigUint;
use tycho_common::{
    models::{protocol::ProtocolComponent, Chain},
    Bytes,
};
use tycho_execution::encoding::{
    evm::encoder_builder::EVMEncoderBuilder,
    models::{Solution, Swap},
    tycho_encoder::TychoEncoder,
};

fn main() {
    // Setup variables
    let swapper_pk =
        "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234".to_string();
    let user_address = Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2")
        .expect("Failed to create user address");

    // Initialize the encoder
    let encoder = EVMEncoderBuilder::new()
        .chain(Chain::Ethereum)
        .initialize_tycho_router_with_permit2(swapper_pk)
        .expect("Failed to create encoder builder")
        .build()
        .expect("Failed to build encoder");

    // ------------------- Encode a simple swap -------------------

    // Prepare data to encode. We will encode a simple swap from WETH to USDC
    // First we need to create a swap object
    let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
        .expect("Failed to create WETH address");
    let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
        .expect("Failed to create USDC address");

    let simple_swap = Swap {
        // The protocol component data comes from tycho-indexer
        component: ProtocolComponent {
            id: "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        token_in: weth.clone(),
        token_out: usdc.clone(),
        // Split defines the fraction of the amount to be swapped. A value of 0 indicates 100% of
        // the amount or the total remaining balance.
        split: 0f64,
    };

    // Then we create a solution object with the previous swap
    let solution = Solution {
        sender: user_address.clone(),
        receiver: user_address.clone(),
        given_token: weth.clone(),
        given_amount: BigUint::from_str("1_000000000000000000").expect("Failed to create amount"),
        checked_token: usdc.clone(),
        exact_out: false,     // it's an exact in solution
        checked_amount: None, // the amount out will not be checked in execution
        swaps: vec![simple_swap],
        ..Default::default()
    };

    // Encode the solution
    let tx = encoder
        .encode_router_calldata(vec![solution.clone()])
        .expect("Failed to encode router calldata")[0]
        .clone();
    println!(" ====== Simple swap WETH -> USDC ======");
    println!(
        "The simple swap encoded transaction should be sent to address {:?} with the value of {:?} and the \
    following encoded data: {:?}",
        tx.to,
        tx.value,
        hex::encode(tx.data)
    );

    // ------------------- Encode a swap with multiple splits -------------------
    // To illustrate a more complex solution, we will encode a swap from WETH to USDC with multiple
    // splits. Performs a split swap from WETH to USDC though WBTC and DAI using USV2 pools
    //
    //         ┌──(USV2)──> WBTC ───(USV2)──> USDC
    //   WETH ─┤
    //         └──(USV2)──> DAI  ───(USV2)──> USDC
    //

    let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599")
        .expect("Failed to create WBTC address");
    let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f")
        .expect("Failed to create DAI address");

    let swap_weth_dai = Swap {
        component: ProtocolComponent {
            id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        token_in: weth.clone(),
        token_out: dai.clone(),
        split: 0.5f64,
    };
    let swap_weth_wbtc = Swap {
        component: ProtocolComponent {
            id: "0xBb2b8038a1640196FbE3e38816F3e67Cba72D940".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        token_in: weth.clone(),
        token_out: wbtc.clone(),
        // This represents the remaining 50%, but to avoid any rounding errors we set this to
        // 0 to signify "the remainder of the WETH value". It should still be very close to 50%
        split: 0f64,
    };
    let swap_dai_usdc = Swap {
        component: ProtocolComponent {
            id: "0xAE461cA67B15dc8dc81CE7615e0320dA1A9aB8D5".to_string(),
            protocol_system: "uniswap_v2".to_string(),
            ..Default::default()
        },
        token_in: dai.clone(),
        token_out: usdc.clone(),
        split: 0f64,
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
    };
    let mut complex_solution = solution.clone();
    complex_solution.swaps = vec![swap_weth_dai, swap_weth_wbtc, swap_dai_usdc, swap_wbtc_usdc];

    // Encode the solution
    let complex_tx = encoder
        .encode_router_calldata(vec![complex_solution])
        .expect("Failed to encode router calldata")[0]
        .clone();

    println!(" ====== Complex split swap WETH -> USDC ======");
    println!(
        "The complex solution encoded transaction should be sent to address {:?} with the value of {:?} and the \
    following encoded data: {:?}",
        complex_tx.to,
        complex_tx.value,
        hex::encode(complex_tx.data)
    );
}

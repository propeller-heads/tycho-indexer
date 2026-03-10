use std::{fs, time::Instant};

use tycho_common::models::Chain;
use tycho_contracts::encoding::{
    evm::{
        encoder_builders::TychoRouterEncoderBuilder,
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
    },
    models::Solution,
};

fn main() {
    println!("Starting encoding profile...");

    let start_total = Instant::now();

    // Load and parse JSON
    let start_io = Instant::now();
    let json_content =
        fs::read_to_string("client_solution.json").expect("Failed to read client_solution.json");
    println!("File read took: {:?}", start_io.elapsed());

    let start_parse = Instant::now();
    let solution: Solution =
        serde_json::from_str(&json_content).expect("Failed to parse JSON into Solution");
    println!("JSON parsing took: {:?}", start_parse.elapsed());

    // Get encoder - equivalent to get_tycho_router_encoder(UserTransferType::TransferFrom)
    let start_encoder = Instant::now();
    let swap_encoder_registry = SwapEncoderRegistry::new(Chain::Ethereum)
        .add_default_encoders(None)
        .expect("Failed to get default SwapEncoderRegistry");
    let encoder = TychoRouterEncoderBuilder::new()
        .chain(Chain::Ethereum)
        .swap_encoder_registry(swap_encoder_registry)
        .build()
        .expect("Failed to build encoder");
    println!("Encoder initialization took: {:?}", start_encoder.elapsed());

    // Encode solutions - this is what we want to profile most
    let start_encode = Instant::now();
    let encoded_solution = encoder
        .encode_solutions(vec![solution.clone()])
        .unwrap()[0]
        .clone();
    println!("encode_solutions took: {:?}", start_encode.elapsed());
    println!("encode_solutions: {:?}", encoded_solution);

    println!("Total time: {:?}", start_total.elapsed());
}

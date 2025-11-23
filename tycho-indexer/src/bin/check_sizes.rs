use tycho_common::{
    memory::{measure_allocation, report_used_memory_metrics_with_label},
    models::Chain,
    Bytes,
};

fn main() {
    // Initiateal logging using the tracing crate from the RUST_LOG env var
    measure_allocation("Init Tracing Subscriber", || {
        tracing_subscriber::fmt::init();
    });
    report_used_memory_metrics_with_label("Initial Memory Usage");

    let test_bytes = measure_allocation("Allocation Test Tokens", || {
        let id = Bytes::from(vec![1u8; 20]);
        let token = tycho_common::models::token::Token {
            address: Bytes::from(b"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
            symbol: "USDC".to_string(),
            decimals: 6,
            tax: 1000,
            gas: vec![Some(1000u64)],
            chain: Chain::Ethereum,
            quality: 100,
        };
        vec![(id)]
    });
    println!("Allocated Test Bytes: len={}", test_bytes[0].len(),);
    let serialized = serde_json::to_string(&test_bytes).unwrap();
    let test_bytes_deserialized = measure_allocation("Deserialize Test Bytes (JSON)", || {
        serde_json::from_str::<Vec<(Bytes)>>(&serialized[..]).unwrap()
    });

    let serialized =
        bincode::serde::encode_to_vec(&test_bytes, bincode::config::standard()).unwrap();
    drop(test_bytes);
    let test_bytes_deserialized = measure_allocation("Deserialize Test Bytes (BIN)", || {
        bincode::serde::decode_from_slice::<Vec<(Bytes)>, _>(
            &serialized[..],
            bincode::config::standard(),
        )
        .unwrap()
        .0
    });
    //
    // measure_allocation("Initial Bytes Allocation", || {
    //     let _b = bytes::Bytes::from(vec![0u8; 1024 * 1024]);
    // });
    //
    // let protocol_tokens_path = "protocol_tokens.bin";
    //
    // let protocol_tokens_file =
    //     std::fs::read(protocol_tokens_path).expect("Failed to read protocol_tokens.bin");
    //
    // let tokens = measure_allocation("Allocating Tokens", || {
    //     let mut tokens: Vec<_> = {
    //         let (tokens, _) = bincode::serde::decode_from_slice::<HashMap<Bytes, Token>, _>(
    //             &protocol_tokens_file[..],
    //             bincode::config::standard(),
    //         )
    //         .expect("Failed to deserialize protocol_tokens.bin");
    //         tokens.into_iter().collect()
    //     };
    //
    //     tokens.sort();
    //     tokens.truncate(1);
    //     tokens.shrink_to_fit();
    //
    //     // Debug: check the internal structure of the deserialized Bytes
    //     if let Some((key, token)) = tokens.first() {
    //         println!("\n=== Deserialized Token (306 B) ===");
    //         println!("Key: len={}", key.len());
    //         println!("Address: len={}", token.address.len());
    //         println!("Symbol: len={}, capacity={}", token.symbol.len(), token.symbol.capacity());
    //         println!("Gas: len={}, capacity={}", token.gas.len(), token.gas.capacity());
    //     }
    //
    //     tokens
    // });
    //
    // let _res: Vec<(Bytes, Token)> = measure_allocation("SHARED deep clone", || {
    //     tokens
    //         .iter()
    //         .map(|(key, token)| {
    //             // Force deep copy of Bytes
    //             let key_deep = (bytes::Bytes::from(key.as_ref().to_vec())).clone();
    //             let address_bytes =
    // (bytes::Bytes::from(token.address.as_ref().to_vec())).clone();
    //
    //             // Force deep copy of Token's Bytes fields
    //             let token_deep = Token {
    //                 address: Bytes::from(address_bytes),
    //                 symbol: token.symbol.clone(),
    //                 decimals: token.decimals.clone(),
    //                 tax: token.tax.clone(),
    //                 gas: token.gas.to_owned(),
    //                 chain: token.chain.clone(),
    //                 quality: token.quality.clone(),
    //             };
    //
    //             (Bytes::from(key_deep), token_deep)
    //         })
    //         .collect()
    // });
    //
    // let res: Vec<(Bytes, Token)> = measure_allocation("TRUE deep clone", || {
    //     tokens
    //         .iter()
    //         .map(|(key, token)| {
    //             // Force deep copy of Bytes
    //             let key_deep = Bytes::from(key.as_ref().to_vec());
    //             let address_bytes = Bytes::from(token.address.as_ref().to_vec());
    //
    //             // Force deep copy of Token's Bytes fields
    //             let token_deep = Token {
    //                 address: address_bytes,
    //                 symbol: token.symbol.clone(),
    //                 decimals: token.decimals.clone(),
    //                 tax: token.tax.clone(),
    //                 gas: token.gas.to_owned(),
    //                 chain: token.chain.clone(),
    //                 quality: token.quality.clone(),
    //             };
    //
    //             (key_deep, token_deep)
    //         })
    //         .collect()
    // });
    //
    // report_used_memory_metrics_with_label("After Deep Cloning Tokens");
    //
    // // Debug: check the TRUE deep clone structure
    // if let Some((key, token)) = res.first() {
    //     println!("\n=== TRUE Deep Clone Token (234 B) ===");
    //     println!("Key: len={}", key.len());
    //     println!("Address: len={}", token.address.len());
    //     println!("Symbol: len={}, capacity={}", token.symbol.len(), token.symbol.capacity());
    //     println!("Gas: len={}, capacity={}", token.gas.len(), token.gas.capacity());
    // }
    //
    // drop(tokens);
    //
    // std::thread::sleep(std::time::Duration::from_millis(100));
    // report_used_memory_metrics_with_label("After Dropping Original Tokens");
    //
    // black_box(&res);
    //
    // report_deepsize_of_memory_metrics("Protocol Tokens", &res);
    //
    // // Manually estimate the size of a Vec<(Bytes, Token>)
    // let estimated_size = res
    //     .iter()
    //     .fold(0, |acc, (bytes, token)| {
    //         acc +
    //             // Bytes: stack size + heap allocation
    //             // std::mem::size_of_val(bytes) +
    //             bytes.0.len() +
    //             // Token: stack size only (contains inline fields + pointers)
    //             // std::mem::size_of_val(token) +
    //             // Token.address: heap allocation
    //             token.address.0.len() +
    //             // Token.symbol: heap allocation
    //             token.symbol.capacity() +
    //             // Token.gas: heap allocation
    //             token.gas.capacity() * std::mem::size_of::<Option<u64>>()
    //     }) +
    //     // Outer Vec: stack size + heap allocation
    //     std::mem::size_of_val(&res) +
    //     res.capacity() * std::mem::size_of::<(Bytes, Token)>();
    // println!("Estimated size of Vec<(Bytes, Token)>: {}", format_bytes_inline(estimated_size));
    //
    // let mut token = res[0].1.to_owned();
    //
    // println!("Gas type size: {}", std::mem::size_of_val(&token.gas));
    // println!("Symbol size: {}", std::mem::size_of_val(&token.symbol));
    // println!("Token address size: {}", std::mem::size_of_val(&token.address));
    //
    // println!("Token size: {}", std::mem::size_of_val(&token));
    //
    // token.symbol = "A very long token symbol to test size".to_string();
    // println!("Token size after changing symbol: {}", std::mem::size_of_val(&token));
    //
    // let bytes = measure_allocation("Initial Allocation", || bytes::Bytes::from(vec![1u8; 512]));
    // let other_bytes =
    //     measure_allocation("Other Allocation", || bytes::Bytes::from(vec![1u8; 1024]));
    // println!("Size of Bytes: {}", std::mem::size_of_val(&bytes));
    // println!("Size of other Bytes: {}", std::mem::size_of_val(&other_bytes));
    // let cloned_bytes = measure_allocation("Cloning Bytes", || bytes.clone());
    // println!("Size of cloned Bytes: {}", std::mem::size_of_val(&cloned_bytes));

    // struct Dummy {
    //     a: Bytes,
    //     b: Bytes,
    // }
    //
    // println!("Dummy size: {}", std::mem::size_of::<Dummy>());
    println!("Bytes size: {}", std::mem::size_of::<bytes::Bytes>());
    println!("Vec u8 size: {}", std::mem::size_of::<Vec<u8>>());
    //
    // measure_allocation("Bytes Allocation v1", || {
    //     let mut acc = Vec::with_capacity(1024);
    //
    //     for i in 0..1024 {
    //         // Push a random Bytes of 256 bytes into the vec
    //         let mut random_bytes = Vec::with_capacity(256);
    //         for _ in 0..256 {
    //             random_bytes.push(random::<u8>());
    //         }
    //         let bytes = Bytes::from(random_bytes);
    //         acc.push(bytes);
    //     }
    // });
    // let acc = measure_allocation("Bytes Allocation v2", || vec![Bytes::from(vec![1u8; 256]);
    // 1024]); println!("Stack size of Vec<Bytes>: {}", std::mem::size_of_val(&acc));
    // report_deepsize_of_memory_metrics("Bytes Allocation", &acc);
    // // 1024 * 32 + 16 * 1024 =
}

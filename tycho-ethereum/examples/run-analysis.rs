/// To run: cargo run --example run-analysis
use std::{collections::HashMap, str::FromStr, sync::Arc};

use alloy::primitives::U256;
use anyhow::Result;
use tycho_common::{
    models::{blockchain::BlockTag, token::TokenOwnerStore},
    traits::TokenAnalyzer,
    Bytes,
};
use tycho_ethereum::{token_analyzer::trace_call::TraceCallDetector, BytesCodec};

#[tokio::main]
async fn main() -> Result<(), ()> {
    let rpc = std::env::var("RPC_URL").expect("RPC URL must be set for testing");
    let tf = TokenOwnerStore::new(HashMap::from([(
        Bytes::from_str("3A9FfF453d50D4Ac52A6890647b823379ba36B9E").unwrap(),
        (
            Bytes::from_str("260E069deAd76baAC587B5141bB606Ef8b9Bab6c").unwrap(),
            U256::from_str("13042252617814040589")
                .unwrap()
                .to_bytes(),
        ),
    )]));

    let trace_call = TraceCallDetector::new_from_url(&rpc, Arc::new(tf));

    let quality = trace_call
        .analyze(
            Bytes::from_str("3A9FfF453d50D4Ac52A6890647b823379ba36B9E").unwrap(),
            BlockTag::Latest,
        )
        .await
        .unwrap();

    println!("{quality:?}");
    Ok(())
}

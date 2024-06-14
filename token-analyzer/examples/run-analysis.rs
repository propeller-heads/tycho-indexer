/// To run: cargo run --example run-analysis
use std::{collections::HashMap, str::FromStr, sync::Arc};

use anyhow::Result;
use ethers::types::{H160, U256};
use ethrpc::{http::HttpTransport, Web3, Web3Transport};
use reqwest::Client;
use token_analyzer::{trace_call::TraceCallDetector, BadTokenDetecting, TokenFinder};
use url::Url;
use web3::types::BlockNumber;

#[tokio::main]
async fn main() -> Result<(), ()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let transport = Web3Transport::new(HttpTransport::new(
        Client::new(),
        Url::from_str(
            "https://ethereum-mainnet.core.chainstack.com/71bdd37d35f18d55fed5cc5d138a8fac",
        )
        .unwrap(),
        "transport".to_owned(),
    ));
    let token = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    let liquidity_owner = "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640";
    let liquidity = "99018028084239";

    let w3 = Web3::new(transport);
    let tf = TokenFinder::new(HashMap::from([(
        H160::from_str(token).unwrap(),
        (H160::from_str(liquidity_owner).unwrap(), U256::from_dec_str(liquidity).unwrap()),
    )]));

    let trace_call = TraceCallDetector {
        web3: w3,
        finder: Arc::new(tf),
        settlement_contract: H160::from_str("0xc9f2e6ea1637E499406986ac50ddC92401ce1f58").unwrap(),
    };

    let quality = trace_call
        .detect(H160::from_str(token).unwrap(), BlockNumber::Latest)
        .await
        .unwrap();

    println!("{:?}", quality);
    Ok(())
}

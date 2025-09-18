use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use ethers::{abi::Abi, contract::Contract, prelude::Provider, providers::Http, types::H160};
use ethrpc::Web3;
use serde_json::from_str;
use tracing::{instrument, warn};
use tycho_common::{
    models::{
        blockchain::BlockTag,
        token::{Token, TokenQuality},
        Chain,
    },
    traits::{TokenAnalyzer, TokenOwnerFinding, TokenPreProcessor},
    Bytes,
};
use unicode_segmentation::UnicodeSegmentation;

use crate::{token_analyzer::trace_call::TraceCallDetector, BytesCodec};

#[derive(Debug, Clone)]
pub struct EthereumTokenPreProcessor {
    ethers_client: Arc<Provider<Http>>,
    erc20_abi: Abi,
    web3_client: Web3,
    chain: Chain,
}

const ABI_STR: &str = include_str!("./abi/erc20.json");

impl EthereumTokenPreProcessor {
    pub fn new(ethers_client: Provider<Http>, web3_client: Web3, chain: Chain) -> Self {
        let abi = from_str::<Abi>(ABI_STR).expect("Unable to parse ABI");
        EthereumTokenPreProcessor {
            ethers_client: Arc::new(ethers_client),
            erc20_abi: abi,
            web3_client,
            chain,
        }
    }

    pub fn new_from_url(rpc_url: &str, chain: Chain) -> Self {
        let abi = from_str::<Abi>(ABI_STR).expect("Unable to parse ABI");
        let ethers_client: Provider<Http> =
            Provider::<Http>::try_from(rpc_url).expect("Error creating HTTP provider");

        let web3_client = Web3::new_from_url(rpc_url);
        EthereumTokenPreProcessor {
            ethers_client: Arc::new(ethers_client),
            erc20_abi: abi,
            web3_client,
            chain,
        }
    }
}

#[async_trait]
impl TokenPreProcessor for EthereumTokenPreProcessor {
    #[instrument(skip_all, fields(n_addresses=addresses.len(), block = ?block))]
    async fn get_tokens(
        &self,
        addresses: Vec<Bytes>,
        token_finder: Arc<dyn TokenOwnerFinding>,
        block: BlockTag,
    ) -> Vec<Token> {
        let mut tokens_info = Vec::new();

        for address in addresses {
            let contract = Contract::new(
                H160::from_bytes(&address),
                self.erc20_abi.clone(),
                self.ethers_client.clone(),
            );

            let symbol = contract
                .method("symbol", ())
                .expect("Error preparing request")
                .call()
                .await;

            let decimals: Result<u8, _> = contract
                .method("decimals", ())
                .expect("Error preparing request")
                .call()
                .await;

            let trace_call = TraceCallDetector {
                web3: self.web3_client.clone(),
                finder: token_finder.clone(),
                settlement_contract: H160::from_str("0xc9f2e6ea1637E499406986ac50ddC92401ce1f58") // middle contract used to check for fees, set to cowswap settlement
                    .unwrap(),
            };

            let (token_quality, gas, tax) = trace_call
                .analyze(address.clone(), block)
                .await
                .unwrap_or_else(|e| {
                    warn!(error=?e, "TokenDetectionFailure");
                    (TokenQuality::bad("Detection failed"), None, None)
                });

            let (symbol, decimals, mut quality) = match (symbol, decimals) {
                (Ok(symbol), Ok(decimals)) => (symbol, decimals, 100),
                (Ok(symbol), Err(_)) => (symbol, 18, 0),
                (Err(_), Ok(decimals)) => (address.to_string(), decimals, 0),
                (Err(_), Err(_)) => (address.to_string(), 18, 0),
            };

            if let TokenQuality::Bad { reason } = token_quality {
                warn!(address=?address, ?reason, "BadToken");
                // Flag this token as bad using quality, an external script is responsible for
                // analyzing these tokens again.
                quality = 10;
            };

            // If quality is 100 but it's a fee token, set quality to 50
            if quality == 100 && tax.is_some_and(|tax_value| tax_value > 0) {
                quality = 50;
            }

            tokens_info.push(Token {
                address,
                symbol: symbol
                    .replace('\0', "")
                    .graphemes(true)
                    .take(255)
                    .collect::<String>(),
                decimals: decimals.into(),
                tax: tax.unwrap_or(0),
                gas: gas
                    .map(|g| vec![Some(g)])
                    .unwrap_or_else(Vec::new),
                chain: self.chain,
                quality,
            });
        }

        tokens_info
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, env};

    use tycho_common::models::token::TokenOwnerStore;

    use super::*;

    #[tokio::test]
    #[ignore]
    // This test requires a real RPC URL
    async fn test_get_tokens() {
        let archive_rpc = env::var("ARCHIVE_ETH_RPC_URL").expect("ARCHIVE_ETH_RPC_URL is not set");
        let client: Provider<Http> =
            Provider::<Http>::try_from(archive_rpc.clone()).expect("Error creating HTTP provider");

        let w3 = Web3::new_from_url(&archive_rpc);

        let processor = EthereumTokenPreProcessor::new(client, w3, Chain::Ethereum);

        let tf = TokenOwnerStore::new(HashMap::new());

        let weth_address: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
        let usdc_address: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        let fake_address: &str = "0xA0b86991c7456b36c1d19D4a2e9Eb0cE3606eB48";
        let addresses = vec![
            Bytes::from_str(weth_address).unwrap(),
            Bytes::from_str(usdc_address).unwrap(),
            Bytes::from_str(fake_address).unwrap(),
        ];

        let results = processor
            .get_tokens(addresses, Arc::new(tf), BlockTag::Number(1))
            .await;
        assert_eq!(results.len(), 3);
        let relevant_attrs: Vec<(String, u32, u32)> = results
            .iter()
            .map(|t| (t.symbol.clone(), t.decimals, t.quality))
            .collect();
        assert_eq!(
            relevant_attrs,
            vec![
                ("WETH".to_string(), 18, 100),
                ("USDC".to_string(), 6, 100),
                ("0xa0b8…eb48".to_string(), 18, 0)
            ]
        );
    }
}

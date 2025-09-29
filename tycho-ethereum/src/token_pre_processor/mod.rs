use std::sync::Arc;

use alloy::{hex, primitives::Address};
use async_trait::async_trait;
use reqwest::Client;
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

use crate::{erc20_abi, token_analyzer::trace_call::TraceCallDetector, BytesCodec};

#[derive(Debug, Clone)]
pub struct EthereumTokenPreProcessor {
    rpc_url: String,
    chain: Chain,
}

impl EthereumTokenPreProcessor {
    pub fn new_from_url(rpc_url: &str, chain: Chain) -> Self {
        EthereumTokenPreProcessor { rpc_url: rpc_url.to_string(), chain }
    }

    async fn call_symbol(
        &self,
        token: Address,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let calldata = match erc20_abi::encode_symbol() {
            Ok(calldata) => calldata,
            Err(e) => {
                warn!(?e, "Failed to encode symbol function call, using address as fallback");
                return Ok(format!("0x{:x}", token));
            }
        };

        let result = match self
            .make_rpc_call(token, calldata)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                warn!(?e, ?token, "Failed to call symbol function, using address as fallback");
                return Ok(format!("0x{:x}", token));
            }
        };

        match erc20_abi::decode_symbol(&result) {
            Ok(symbol) => Ok(symbol),
            Err(e) => {
                warn!(
                    ?e,
                    ?token,
                    "Failed to decode symbol function result, using address as fallback"
                );
                Ok(format!("0x{:x}", token))
            }
        }
    }

    async fn call_decimals(
        &self,
        token: Address,
    ) -> Result<u8, Box<dyn std::error::Error + Send + Sync>> {
        let calldata = match erc20_abi::encode_decimals() {
            Ok(calldata) => calldata,
            Err(e) => {
                warn!(?e, "Failed to encode decimals function call, using default decimals 18");
                return Ok(18);
            }
        };

        let result = match self
            .make_rpc_call(token, calldata)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                warn!(?e, ?token, "Failed to call decimals function, using default decimals 18");
                return Ok(18);
            }
        };

        match erc20_abi::decode_decimals(&result) {
            Ok(decimals) => Ok(decimals),
            Err(e) => {
                warn!(
                    ?e,
                    ?token,
                    "Failed to decode decimals function result, using default decimals 18"
                );
                Ok(18)
            }
        }
    }

    async fn make_rpc_call(
        &self,
        to: Address,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let client = Client::new();

        let call_request = serde_json::json!({
            "to": format!("0x{:x}", to),
            "data": format!("0x{}", hex::encode(data))
        });

        let rpc_request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [call_request, "latest"],
            "id": 1
        });

        let response = client
            .post(&self.rpc_url)
            .json(&rpc_request)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        if let Some(error) = response.get("error") {
            return Err(format!("RPC error: {}", error).into());
        }

        let result_str = response
            .get("result")
            .and_then(|r| r.as_str())
            .ok_or("No result in response")?;

        let hex_str = result_str
            .strip_prefix("0x")
            .unwrap_or(result_str);
        Ok(hex::decode(hex_str)?)
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
            let token_address = Address::from_bytes(&address);

            // Make RPC calls directly for symbol and decimals
            let symbol = self.call_symbol(token_address).await;
            let decimals = self.call_decimals(token_address).await;

            let trace_call = TraceCallDetector::new(&self.rpc_url, token_finder.clone());

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
    use std::{collections::HashMap, env, str::FromStr};

    use tycho_common::models::token::TokenOwnerStore;

    use super::*;

    #[tokio::test]
    #[ignore]
    // This test requires a real RPC URL
    async fn test_get_tokens() {
        let archive_rpc = env::var("ARCHIVE_ETH_RPC_URL").expect("ARCHIVE_ETH_RPC_URL is not set");

        let processor = EthereumTokenPreProcessor::new_from_url(&archive_rpc, Chain::Ethereum);

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

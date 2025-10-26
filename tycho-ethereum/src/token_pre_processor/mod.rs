use std::sync::Arc;

use alloy::{
    primitives::{Address, Bytes as AlloyBytes},
    rpc::{
        client::{ClientBuilder, ReqwestClient},
        types::{BlockNumberOrTag, TransactionRequest},
    },
};
use async_trait::async_trait;
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

use crate::{
    erc20,
    token_analyzer::trace_call::{call_request, TraceCallDetector},
    BytesCodec, RPCError, RequestError,
};

#[derive(Debug, Clone)]
pub struct EthereumTokenPreProcessor {
    rpc: ReqwestClient,
    chain: Chain,
}

impl EthereumTokenPreProcessor {
    pub fn new_from_url(rpc_url: &str, chain: Chain) -> Result<Self, RPCError> {
        let url = rpc_url
            .parse()
            .map_err(|e: url::ParseError| {
                RPCError::RequestError(RequestError::Other(e.to_string()))
            })?;
        let rpc = ClientBuilder::default().http(url);
        Ok(EthereumTokenPreProcessor { rpc, chain })
    }

    pub fn new(rpc: ReqwestClient, chain: Chain) -> Self {
        EthereumTokenPreProcessor { rpc, chain }
    }

    async fn call_symbol(&self, token: Address) -> String {
        let calldata = erc20::encode_symbol();

        let result = match self
            .make_rpc_call(call_request(None, token, calldata))
            .await
        {
            Ok(result) => result,
            Err(e) => {
                warn!(?e, ?token, "Failed to call symbol function, using address as fallback");
                return format!("0x{:x}", token);
            }
        };

        match erc20::decode_symbol(&result) {
            Ok(symbol) => symbol,
            Err(e) => {
                warn!(
                    ?e,
                    ?token,
                    "Failed to decode symbol function result, using address as fallback"
                );
                format!("0x{:x}", token)
            }
        }
    }

    async fn call_decimals(&self, token: Address) -> u8 {
        let calldata = erc20::encode_decimals();

        let result = match self
            .make_rpc_call(call_request(None, token, calldata))
            .await
        {
            Ok(result) => result,
            Err(e) => {
                warn!(?e, ?token, "Failed to call decimals function, using default decimals 18");
                return 18;
            }
        };

        match erc20::decode_decimals(&result) {
            Ok(decimals) => decimals,
            Err(e) => {
                warn!(
                    ?e,
                    ?token,
                    "Failed to decode decimals function result, using default decimals 18"
                );
                18
            }
        }
    }

    async fn make_rpc_call(&self, requests: TransactionRequest) -> Result<AlloyBytes, RPCError> {
        self.rpc
            .request("eth_call", (requests, BlockNumberOrTag::Latest))
            .await
            .map_err(|e| {
                RPCError::RequestError(RequestError::Other(format!("RPC eth_call failed: {e}")))
            })
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

            let trace_call = TraceCallDetector::new(self.rpc.clone(), token_finder.clone());

            let (token_quality, gas, tax) = trace_call
                .analyze(address.clone(), block)
                .await
                .unwrap_or_else(|e| {
                    warn!(error=?e, "TokenDetectionFailure");
                    (TokenQuality::bad("Detection failed"), None, None)
                });

            let mut quality = 100;

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
    #[ignore = "require RPC connection"]
    async fn test_make_rpc_call() {
        let rpc_url = env::var("RPC_URL").expect("RPC_URL is not set");

        let processor = EthereumTokenPreProcessor::new_from_url(&rpc_url, Chain::Ethereum)
            .expect("Failed to create processor");

        // Test making an RPC call to get WETH symbol
        let weth_address = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
            .expect("Failed to parse WETH address");
        let calldata = erc20::encode_symbol();
        let request = call_request(None, weth_address, calldata);

        let result = processor
            .make_rpc_call(request)
            .await
            .expect("Failed to make RPC call");

        // Verify we got a non-empty response
        assert!(!result.is_empty(), "RPC call should return non-empty data");

        // Verify we can decode the symbol
        let symbol = erc20::decode_symbol(&result).expect("Failed to decode symbol");
        assert_eq!(symbol, "WETH", "Expected WETH symbol");
    }

    #[tokio::test]
    #[ignore = "require archive RPC connection"]
    async fn test_get_tokens() {
        let rpc_url = env::var("RPC_URL").expect("RPC_URL is not set");

        let processor = EthereumTokenPreProcessor::new_from_url(&rpc_url, Chain::Ethereum)
            .expect("Failed to create processor");

        // TODO - this seems to be never populated with data, so all tokens have quality 10
        let tf = TokenOwnerStore::new(HashMap::new());

        let weth_address: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
        let usdc_address: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        let fake_address: &str = "0xA0b86991c7456b36c1d19D4a2e9Eb0cE3606eB48";
        let addresses = vec![
            Bytes::from_str(weth_address).unwrap(),
            Bytes::from_str(usdc_address).unwrap(),
            Bytes::from_str(fake_address).unwrap(),
        ];

        // TODO - block number probably should not be 1, but something more reasonable
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
                // TODO - probably quality 0 is impossible, and it should be 10 instead (bad token)
                ("0xa0b86991c7456b36c1d19d4a2e9eb0ce3606eb48".to_string(), 18, 0)
            ]
        );
    }
}

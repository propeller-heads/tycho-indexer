use crate::{extractor::evm::ERC20Token, models::Chain};
use ethers::{
    abi::Abi,
    contract::Contract,
    providers::{Http, Provider},
    types::H160,
};
use serde_json::from_str;
use std::{fs, sync::Arc};

pub struct TokenPreProcessor {
    client: Arc<Provider<Http>>,
}

impl TokenPreProcessor {
    pub fn new(rpc_url: &str) -> Self {
        let client = Provider::<Http>::try_from(rpc_url)
            .expect("Error creating HTTP provider")
            .into();

        TokenPreProcessor { client }
    }

    pub async fn get_tokens(
        &self,
        addresses: Vec<H160>,
    ) -> Vec<Result<ERC20Token, Box<dyn std::error::Error>>> {
        let mut tokens_info = Vec::new();

        let abi_str = fs::read_to_string("src/extractor/evm/abi/erc20.json")
            .expect("Unable to read ABI file");
        let abi = from_str::<Abi>(&abi_str).expect("Unable to parse ABI");

        for address in addresses {
            let contract = Contract::new(address, abi.clone(), self.client.clone());

            let symbol: Result<String, _> = contract
                .method("symbol", ())
                .expect("Error preparing request")
                .call()
                .await;

            let decimals: Result<u8, _> = contract
                .method("decimals", ())
                .expect("Error preparing request")
                .call()
                .await;

            match (symbol, decimals) {
                (Ok(symbol), Ok(decimals)) => tokens_info.push(Ok(ERC20Token {
                    address,
                    symbol,
                    decimals: decimals.into(),
                    tax: 0,
                    gas: vec![],
                    chain: Chain::Ethereum,
                })),
                (Err(e), _) | (_, Err(e)) => println!("Error fetching token data: {:?}", e),
            }
        }

        tokens_info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::H160;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_get_tokens() {
        let rpc_url = "https://eth-mainnet.g.alchemy.com/v2/OTD5W7gdTPrzpVot41Lx9tJD9LUiAhbs";
        let processor = TokenPreProcessor::new(rpc_url);

        let weth_address: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
        let usdc_address: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        let addresses =
            vec![H160::from_str(weth_address).unwrap(), H160::from_str(usdc_address).unwrap()];

        let results = processor.get_tokens(addresses).await;

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().symbol, "WETH");
        assert_eq!(results[0].as_ref().unwrap().decimals, 18);
        assert_eq!(results[1].as_ref().unwrap().symbol, "USDC");
        assert_eq!(results[1].as_ref().unwrap().decimals, 6);
    }
}

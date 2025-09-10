use alloy::{
    contract::{ContractInstance, Interface},
    dyn_abi::DynSolValue,
    eips::eip1898::BlockId,
    primitives::{address, Address, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Block,
    transports::http::reqwest::Url,
};
use miette::{IntoDiagnostic, WrapErr};

const NATIVE_ALIASES: &[Address] = &[
    address!("0x0000000000000000000000000000000000000000"),
    address!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
];

const ERC_20_ABI: &str = r#"[{"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"stateMutability":"view","type":"function"}]"#;

pub struct RPCProvider {
    url: Url,
}

impl RPCProvider {
    pub fn new(url: String) -> Self {
        let url = url.as_str().parse().unwrap();
        RPCProvider { url }
    }

    pub async fn get_token_balance(
        &self,
        token_address: Address,
        wallet_address: Address,
        block_number: u64,
    ) -> miette::Result<U256> {
        let provider = ProviderBuilder::new().connect_http(self.url.clone());
        let block_id: BlockId = BlockId::from(block_number);

        match NATIVE_ALIASES.contains(&token_address) {
            true => provider
                .get_balance(wallet_address)
                .block_id(block_id)
                .await
                .into_diagnostic()
                .wrap_err("Failed to fetch token balance"),
            false => {
                let abi = serde_json::from_str(ERC_20_ABI)
                    .into_diagnostic()
                    .wrap_err("invalid ABI")?;

                let contract = ContractInstance::new(token_address, provider, Interface::new(abi));

                let wallet_addr = DynSolValue::from(wallet_address);

                let result_value = contract
                    .function("balanceOf", &[wallet_addr])
                    .expect("Failed to build function call")
                    .block(block_id)
                    .call()
                    .await
                    .into_diagnostic()
                    .wrap_err("Failed to fetch ERC-20 Balance")?;
                let result: U256 = result_value
                    .first()
                    .ok_or_else(|| miette::miette!("No value returned from contract call"))?
                    .as_uint()
                    .ok_or_else(|| miette::miette!("Returned value is not a uint"))?
                    .0;
                Ok(result)
            }
        }
    }

    pub async fn get_block_header(&self, block_number: u64) -> miette::Result<Block> {
        let provider = ProviderBuilder::new().connect_http(self.url.clone());
        let block_id: BlockId = BlockId::from(block_number);

        provider
            .get_block(block_id)
            .await
            .into_diagnostic()
            .wrap_err("Failed to fetch block header")
            .and_then(|block_opt| block_opt.ok_or_else(|| miette::miette!("Block not found")))
    }
}

#[cfg(test)]
mod tests {
    use std::{env, str::FromStr};

    use alloy::primitives::address;

    use super::*;

    #[tokio::test]
    async fn get_token_balance_native_token() {
        let eth_rpc_url = env::var("RPC_URL").expect("Missing RPC_URL in environment");

        let rpc_provider = RPCProvider::new(eth_rpc_url);
        let token_address = address!("0x0000000000000000000000000000000000000000");
        let wallet_address = address!("0x787B8840100d9BaAdD7463f4a73b5BA73B00C6cA");
        let block_number = 21998530;

        let balance = rpc_provider
            .get_token_balance(token_address, wallet_address, block_number)
            .await
            .unwrap();

        assert_eq!(
            balance,
            U256::from_str("1070041574684539264153").expect("Failed to convert ETH value")
        );
    }

    #[tokio::test]
    async fn get_token_balance_erc20_token() {
        let eth_rpc_url = env::var("RPC_URL").expect("Missing RPC_URL in environment");

        let rpc_provider = RPCProvider::new(eth_rpc_url);
        let token_address = address!("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let wallet_address = address!("0x787B8840100d9BaAdD7463f4a73b5BA73B00C6cA");
        let block_number = 21998530;

        let balance = rpc_provider
            .get_token_balance(token_address, wallet_address, block_number)
            .await
            .unwrap();

        assert_eq!(balance, U256::from(717250938432_u64));
    }

    #[tokio::test]
    async fn get_block_header() {
        let eth_rpc_url = env::var("RPC_URL").expect("Missing RPC_URL in environment");

        let rpc_provider = RPCProvider::new(eth_rpc_url);
        let block_number = 21998530;

        let block_header = rpc_provider
            .get_block_header(block_number)
            .await
            .unwrap();

        // Verify that we got a block with the correct number
        assert_eq!(block_number, block_header.header.number);
        assert_eq!(block_header.header.timestamp, 1741393115);
    }
}

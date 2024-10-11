use std::collections::HashMap;

use async_trait::async_trait;
use chrono::NaiveDateTime;
use ethers::{
    middleware::Middleware,
    prelude::{BlockId, Http, Provider, H160, H256, U256},
};
use serde::{Deserialize, Serialize};
use tracing::trace;
use tycho_core::{
    models::{blockchain::Block, contract::AccountDelta, Address, Chain, ChangeType},
    traits::AccountExtractor,
    Bytes,
};

use crate::{BytesConvertible, RPCError};

pub struct EVMAccountExtractor {
    provider: Provider<Http>,
    chain: Chain,
}

#[async_trait]
impl AccountExtractor for EVMAccountExtractor {
    type Error = RPCError;

    async fn get_accounts(
        &self,
        block: tycho_core::models::blockchain::Block,
        account_addresses: Vec<Address>,
    ) -> Result<HashMap<Bytes, AccountDelta>, RPCError> {
        let mut updates = HashMap::new();

        for address in account_addresses {
            let address = H160::from_bytes(&address);
            trace!(contract=?address, block_number=?block.number, block_hash=?block.hash, "Extracting contract code and storage" );
            let block_id = Some(BlockId::from(block.number));

            let balance = Some(
                self.provider
                    .get_balance(address, block_id)
                    .await?,
            );

            let code = self
                .provider
                .get_code(address, block_id)
                .await?;

            let code: Option<Bytes> = Some(Bytes::from(code.to_vec()));

            let slots = self
                .get_storage_range(address, H256::from_bytes(&block.hash))
                .await?
                .into_iter()
                .map(|(k, v)| (k.to_bytes(), Some(v.to_bytes())))
                .collect();

            updates.insert(
                Bytes::from(address.to_fixed_bytes()),
                AccountDelta {
                    address: address.to_bytes(),
                    chain: self.chain,
                    slots,
                    balance: balance.map(BytesConvertible::to_bytes),
                    code,
                    change: ChangeType::Creation,
                },
            );
        }
        return Ok(updates);
    }
}

impl EVMAccountExtractor {
    #[allow(dead_code)]
    pub async fn new(node_url: &str, chain: Chain) -> Result<Self, RPCError>
    where
        Self: Sized,
    {
        let provider = Provider::<Http>::try_from(node_url);
        match provider {
            Ok(p) => Ok(Self { provider: p, chain }),
            Err(e) => Err(RPCError::SetupError(e.to_string())),
        }
    }

    async fn get_storage_range(
        &self,
        address: H160,
        block: H256,
    ) -> Result<HashMap<U256, U256>, RPCError> {
        let mut all_slots = HashMap::new();
        let mut start_key = H256::zero();
        let block = format!("0x{:x}", block);
        loop {
            let params = serde_json::json!([
                block, 0, // transaction index, 0 for the state at the end of the block
                address, start_key, 2147483647 // limit
            ]);

            trace!("Requesting storage range for {:?}, block: {:?}", address, block);
            let result: StorageRange = self
                .provider
                .request("debug_storageRangeAt", params)
                .await?;

            for (_, entry) in result.storage {
                all_slots
                    .insert(U256::from(entry.key.as_bytes()), U256::from(entry.value.as_bytes()));
            }

            if let Some(next_key) = result.next_key {
                start_key = next_key;
            } else {
                break;
            }
        }

        Ok(all_slots)
    }

    pub async fn get_block_data(&self, block_id: i64) -> Result<Block, RPCError> {
        let block = self
            .provider
            .get_block(BlockId::from(u64::try_from(block_id).expect("Invalid block number")))
            .await?
            .expect("Block not found");

        Ok(Block {
            number: block.number.unwrap().as_u64(),
            hash: block.hash.unwrap().to_bytes(),
            parent_hash: block.parent_hash.to_bytes(),
            chain: Chain::Ethereum,
            ts: NaiveDateTime::from_timestamp_opt(block.timestamp.as_u64() as i64, 0)
                .expect("Failed to convert timestamp"),
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct StorageEntry {
    key: H256,
    value: H256,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct StorageRange {
    storage: HashMap<H256, StorageEntry>,
    next_key: Option<H256>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_contract_extractor() -> Result<(), Box<dyn std::error::Error>> {
        let block_hash =
            H256::from_str("0x7f70ac678819e24c4947a3a95fdab886083892a18ba1a962ebaac31455584042")
                .expect("valid block hash");
        let block_number: u64 = 20378314;

        let accounts: Vec<Address> =
            vec![Address::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8")
                .expect("valid address")];
        let node = std::env::var("RPC_URL").expect("RPC URL must be set for testing");
        println!("Using node: {}", node);

        let block = Block::new(
            block_number,
            Chain::Ethereum,
            block_hash.to_bytes(),
            Default::default(),
            Default::default(),
        );
        let extractor = EVMAccountExtractor::new(&node, Chain::Ethereum).await?;
        let updates = extractor
            .get_accounts(block, accounts)
            .await?;

        assert_eq!(updates.len(), 1);
        let update = updates
            .get(
                &Bytes::from_str("ba12222222228d8ba445958a75a0704d566bf2c8")
                    .expect("valid address"),
            )
            .expect("update exists");

        assert_eq!(update.slots.len(), 47690);

        Ok(())
    }
}

use async_trait::async_trait;
use chrono::NaiveDateTime;
use ethers::{
    middleware::Middleware,
    prelude::{BlockId, Http, Provider, H160, H256, U256},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, num::Add, sync::mpsc};
use tracing::trace;
use tycho_core::{
    models::{Address, Chain, ChangeType},
    Bytes,
};

use crate::{
    extractor::{
        evm::{hybrid::HybridPgGateway, AccountUpdate, Block},
        ExtractionError, ExtractorMsg, RPCError,
    },
    pb::sf::substreams::rpc::v2::{BlockScopedData, BlockUndoSignal},
};

#[async_trait]
pub trait DynamicContractExtractor {
    // This method is called on initialization. It should:
    // 1. Check if the account is already present in the database, by calling Postgres Gateway
    //    method
    // 2. If the account is not present, it should extract the account data using the
    //    AccountExtractor.
    // Currently, AccountExtractor already inserts the account data into the database.
    async fn initialize(
        &self,
        block: Block,
        account_addresses: Vec<Address>,
    ) -> Result<(), RPCError>;

    // Infinite loop that runs in a different Tokio task. It should:
    // 1. Receive the contract address from the receiver channel
    // 2. Call the AccountExtractor to extract the account data
    // 3. Update internal struct of tracked accounts, so it can start processing changes on
    //    `handle_tick_scoped_data`

    // QUESTION: How can we ensure that this works for low block times? If extracting the account
    // state takes too long, and there is an update in the subsequent block, we might miss it.
    // We might need some kind of synchronization to ensure we don't miss any updates.
    fn consume(&self) {}

    // These methods were extracted from Extractor trait. Maybe the other methods should be moved
    // to a different trait - like ensure_protocol_types

    // This method will receive a FullBlock from Substreams. The full block should contain all the
    // storage slots that were changed in the block. The method should:
    // 1. Extract the storage slots from the FullBlock that match the registered contracts
    // Build the AccountUpdate object and call the Postgres Gateway method to update the account
    // data in the database.
    // Returns AggregatedBlockChanges with the account updates.
    async fn handle_tick_scoped_data(&self, block: BlockScopedData) -> Result<(), RPCError>;

    // In case of a revert in the block, we need to rollback the account updates. Otherwise we risk
    // having inconsistent state in the db.
    // Behaviour should be similar to HybridExtractor's implementation for `handle_revert` - but
    // only care about AccountUpdates.
    async fn handle_revert(
        &self,
        inp: BlockUndoSignal,
    ) -> Result<Option<ExtractorMsg>, ExtractionError>;
}

pub struct DynamicContractExtractorImpl {
    account_extractor: Box<dyn AccountExtractor>,
    tracked_contracts: Vec<Address>,
    // TODO: Make PG Gateway generic and remove "Hybrid" from the name
    hybrid_pg_gateway: HybridPgGateway,
    receiver: mpsc::Receiver<Address>,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait AccountExtractor {
    async fn get_accounts(
        &self,
        block: Block,
        account_addresses: Vec<Address>,
    ) -> Result<HashMap<H160, AccountUpdate>, RPCError>;
}

pub struct EVMAccountExtractor {
    provider: Provider<Http>,
    chain: Chain,
}

impl<TX> From<ethers::core::types::Block<TX>> for Block {
    fn from(value: ethers::core::types::Block<TX>) -> Self {
        Block {
            number: value.number.unwrap().as_u64(),
            hash: value.hash.unwrap(),
            parent_hash: value.parent_hash,
            chain: Chain::Ethereum,
            ts: NaiveDateTime::from_timestamp_opt(value.timestamp.as_u64() as i64, 0)
                .expect("Failed to convert timestamp"),
        }
    }
}

#[async_trait]
impl AccountExtractor for EVMAccountExtractor {
    async fn get_accounts(
        &self,
        block: Block,
        account_addresses: Vec<Address>,
    ) -> Result<HashMap<H160, AccountUpdate>, RPCError> {
        let mut updates = HashMap::new();

        for address in account_addresses {
            let address: H160 = address.into();

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
                .get_storage_range(address, block.hash)
                .await?;

            updates.insert(
                address,
                AccountUpdate {
                    address,
                    chain: self.chain,
                    slots,
                    balance,
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
        Ok(Block::from(block))
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

        let block = Block {
            number: block_number,
            hash: block_hash,
            parent_hash: Default::default(),
            chain: Chain::Ethereum,
            ts: Default::default(),
        };
        let extractor = EVMAccountExtractor::new(&node, Chain::Ethereum).await?;
        let updates = extractor
            .get_accounts(block, accounts)
            .await?;

        assert_eq!(updates.len(), 1);
        let update = updates
            .get(
                &H160::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8")
                    .expect("valid address"),
            )
            .expect("update exists");

        assert_eq!(update.slots.len(), 47690);

        Ok(())
    }
}

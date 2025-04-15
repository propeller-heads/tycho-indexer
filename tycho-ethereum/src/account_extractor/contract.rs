use std::collections::HashMap;

use alloy::{
    eips::BlockNumberOrTag,
    primitives::Uint,
    rpc::client::{ClientBuilder, RpcClient},
};
use async_trait::async_trait;
use chrono::NaiveDateTime;
use ethers::{
    middleware::Middleware,
    prelude::{BlockId, Http, Provider, H160, H256, U256},
    providers::ProviderError,
};
use futures::future::try_join_all;
use serde::{Deserialize, Serialize};
use tracing::trace;
use tycho_common::{
    models::{blockchain::Block, contract::AccountDelta, Address, Chain, ChangeType},
    traits::{AccountExtractor, AccountStorageSource, StorageSnapshotRequest},
    Bytes,
};

use crate::{BytesCodec, RPCError};

pub struct EVMAccountExtractor {
    provider: Provider<Http>,
    chain: Chain,
}

pub struct EVMBatchAccountExtractor {
    provider: RpcClient,
    chain: Chain,
}

#[async_trait]
impl AccountExtractor for EVMAccountExtractor {
    type Error = RPCError;

    async fn get_accounts(
        &self,
        block: tycho_common::models::blockchain::Block,
        account_addresses: Vec<Address>,
    ) -> Result<HashMap<Bytes, AccountDelta>, RPCError> {
        let mut updates = HashMap::new();
        let block_id = Some(BlockId::from(block.number));

        // Convert addresses to H160 for easier handling
        let h160_addresses: Vec<H160> = account_addresses
            .iter()
            .map(H160::from_bytes)
            .collect();

        // Create futures for balance and code retrieval
        let balance_futures: Vec<_> = h160_addresses
            .iter()
            .map(|&address| {
                self.provider
                    .get_balance(address, block_id)
            })
            .collect();

        let code_futures: Vec<_> = h160_addresses
            .iter()
            .map(|&address| {
                self.provider
                    .get_code(address, block_id)
            })
            .collect();

        // Execute all balance and code requests concurrently
        let balances = try_join_all(balance_futures).await?;
        let codes = try_join_all(code_futures).await?;

        // Process each address with its corresponding balance and code
        for (i, &address) in h160_addresses.iter().enumerate() {
            trace!(contract=?address, block_number=?block.number, block_hash=?block.hash, "Extracting contract code and storage" );

            let balance = Some(balances[i]);
            let code = Some(Bytes::from(codes[i].to_vec()));

            // Get storage slots (this still needs to be done individually)
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
                    balance: balance.map(BytesCodec::to_bytes),
                    code,
                    change: ChangeType::Creation,
                },
            );
        }

        return Ok(updates);
    }
}

impl EVMAccountExtractor {
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
        let block = format!("0x{block:x}");
        loop {
            let params = serde_json::json!([
                block, 0, // transaction index, 0 for the state at the end of the block
                address, start_key, 100000 // limit
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

impl EVMBatchAccountExtractor {
    pub async fn new(node_url: &str, chain: Chain) -> Result<Self, RPCError>
    where
        Self: Sized,
    {
        let url = url::Url::parse(node_url)
            .map_err(|_| RPCError::SetupError("Invalid URL".to_string()))?;
        let provider = ClientBuilder::default().http(url);
        Ok(Self { provider, chain })
    }

    async fn batch_fetch_account_code_and_balance(
        &self,
        block: &&Block,
        max_batch_size: usize,
        chunk: &[StorageSnapshotRequest],
    ) -> Result<(HashMap<Bytes, Bytes>, HashMap<Bytes, Bytes>), RPCError> {
        let mut batch = self.provider.new_batch();
        let mut code_requests = Vec::with_capacity(max_batch_size);
        let mut balance_requests = Vec::with_capacity(max_batch_size);

        for request in chunk {
            code_requests.push(Box::pin(
                batch
                    .add_call(
                        "eth_getCode",
                        &(&request.address, BlockNumberOrTag::from(block.number)),
                    )
                    .map_err(|_| {
                        RPCError::RequestError(ProviderError::CustomError(
                            "Failed to get code".to_string(),
                        ))
                    })?
                    .map_resp(|resp: Bytes| resp.to_vec()),
            ));

            balance_requests.push(Box::pin(
                batch
                    .add_call::<_, Uint<256, 4>>(
                        "eth_getBalance",
                        &(&request.address, BlockNumberOrTag::from(block.number)),
                    )
                    .map_err(|_| {
                        RPCError::RequestError(ProviderError::CustomError(
                            "Failed to get balance".to_string(),
                        ))
                    })?,
            ));
        }

        batch.send().await.map_err(|e| {
            RPCError::RequestError(ProviderError::CustomError(format!(
                "Failed to send batch request: {}",
                e
            )))
        })?;

        let mut codes: HashMap<Bytes, Bytes> = HashMap::with_capacity(max_batch_size);
        let mut balances: HashMap<Bytes, Bytes> = HashMap::with_capacity(max_batch_size);

        for (idx, request) in chunk.iter().enumerate() {
            let address = &request.address;

            let code_result = code_requests[idx]
                .as_mut()
                .await
                .map_err(|e| {
                    RPCError::RequestError(ProviderError::CustomError(format!(
                        "Failed to collect code request data: {}",
                        e
                    )))
                })?;

            codes.insert(address.clone(), code_result.into());

            let balance_result = balance_requests[idx]
                .as_mut()
                .await
                .map_err(|e| {
                    RPCError::RequestError(ProviderError::CustomError(format!(
                        "Failed to collect balance request data: {}",
                        e
                    )))
                })?;

            // TODO: Check if this should be big-endian or little-endian
            balances.insert(address.clone(), Bytes::from(balance_result.to_be_bytes::<32>()));
        }
        Ok((codes, balances))
    }

    async fn fetch_account_storage(
        &self,
        block: &Block,
        max_batch_size: usize,
        request: &StorageSnapshotRequest,
    ) -> Result<HashMap<Bytes, Option<Bytes>>, RPCError> {
        let mut storage_batch = self.provider.new_batch();
        let mut storage_requests = Vec::with_capacity(max_batch_size);

        let mut result = HashMap::new();

        match request.slots {
            Some(slots) => {
                for slot_batch in slots.chunks(max_batch_size) {
                    for slot in slot_batch {
                        storage_requests.push(Box::pin(
                            storage_batch
                                .add_call(
                                    "eth_getStorageAt",
                                    &(&request.address, BlockNumberOrTag::from(block.number), slot),
                                )
                                .map_err(|_| {
                                    RPCError::RequestError(ProviderError::CustomError(
                                        "Failed to get storage".to_string(),
                                    ))
                                })?,
                        ));
                    }

                    storage_batch
                        .send()
                        .await
                        .map_err(|e| {
                            RPCError::RequestError(ProviderError::CustomError(format!(
                                "Failed to send batch request: {}",
                                e
                            )))
                        })?;

                    // for (idx, slot) in slot_batch.iter().enumerate() {
                    //     let address = &request.address;
                    //     let storage_result = storage_requests[idx]
                    //         .as_mut()
                    //         .await
                    //         .map_err(|e| {
                    //             RPCError::RequestError(ProviderError::CustomError(format!(
                    //                 "Failed to collect storage request data: {}",
                    //                 e
                    //             )))
                    //         })?;

                    //     result.insert(slot.clone(), Some(Bytes::from(storage_result)));
                    // }
                    for slot_future in storage_requests {
                        let slot_result = slot_future.await.map_err(|e| {
                            RPCError::RequestError(ProviderError::CustomError(format!(
                                "Failed to collect storage request data: {}",
                                e
                            )))
                        })?;
                        result.insert(slot_result.key.clone(), Some(slot_result.value.clone()));
                    }
                }
            }
            None => {
                // TODO: Implement this -> Call get_storage_range
                return Ok(result);
            }
        }

        Ok(result)
    }
}

#[async_trait]
impl AccountStorageSource for EVMBatchAccountExtractor {
    type Error = RPCError;

    async fn get_storage_snapshots(
        &self,
        requests: &[StorageSnapshotRequest],
        block: &Block,
    ) -> Result<HashMap<Address, AccountDelta>, Self::Error> {
        let mut updates = HashMap::new();

        // TODO: Make these configurable and optimize for preventing rate limiting
        let max_batch_size = 100;
        let storage_max_batch_size = 10000;
        for chunk in requests.chunks(max_batch_size) {
            // let (code, balances)
            let metadata_fut =
                self.batch_fetch_account_code_and_balance(&block, max_batch_size, chunk);
            self.batch_fetch_account_code_and_balance(&block, max_batch_size, chunk);

            let mut storage_futures = Vec::new();
            for request in chunk.iter() {
                storage_futures.push(self.fetch_account_storage(
                    &block,
                    storage_max_batch_size,
                    request,
                ));
            }

            let (codes, balances) = metadata_fut.await?;
            let storage_results = try_join_all(storage_futures).await?;

            for (idx, request) in chunk.iter().enumerate() {
                let address = &request.address;
                let code = codes.get(address).cloned();
                let balance = balances.get(address).cloned();
                let storage = storage_results[idx].expect("Failed to get storage");

                let account_delta = AccountDelta {
                    address: address.clone(),
                    chain: self.chain,
                    slots: storage,
                    balance,
                    code,
                    change: ChangeType::Creation,
                };

                updates.insert(address.clone(), account_delta);
            }
        }

        Ok(updates)
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

    use tracing_test::traced_test;

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
        println!("Using node: {node}");

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

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    /// Test the contract extractor with a large number of storage slots (stETH is the 9th largest
    /// token by number of holders).
    /// This test takes around 2 mins to run and retreives around 50mb of data
    async fn test_contract_extractor_steth() -> Result<(), Box<dyn std::error::Error>> {
        let block_hash =
            H256::from_str("0x7f70ac678819e24c4947a3a95fdab886083892a18ba1a962ebaac31455584042")
                .expect("valid block hash");
        let block_number: u64 = 20378314;

        let accounts: Vec<Address> =
            vec![Address::from_str("0xae7ab96520de3a18e5e111b5eaab095312d7fe84")
                .expect("valid address")];
        let node = std::env::var("RPC_URL").expect("RPC URL must be set for testing");

        let extractor = EVMAccountExtractor::new(&node, Chain::Ethereum).await?;

        let block = Block::new(
            block_number,
            Chain::Ethereum,
            block_hash.to_bytes(),
            Default::default(),
            Default::default(),
        );

        println!("Getting accounts for block: {:?}", block_number);
        let start_time = std::time::Instant::now();
        let updates = extractor
            .get_accounts(block, accounts)
            .await?;
        let duration = start_time.elapsed();
        println!("Time taken to get accounts: {:?}", duration);

        assert_eq!(updates.len(), 1);
        let update = updates
            .get(
                &Bytes::from_str("0xae7ab96520de3a18e5e111b5eaab095312d7fe84")
                    .expect("valid address"),
            )
            .expect("update exists");

        assert_eq!(update.slots.len(), 789526);

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_storage_snapshots() -> Result<(), Box<dyn std::error::Error>> {
        let node = std::env::var("RPC_URL").expect("RPC URL must be set for testing");
        println!("Using node: {}", node);

        let extractor = EVMBatchAccountExtractor::new(&node, Chain::Ethereum).await?;

        let block_hash =
            H256::from_str("0x7f70ac678819e24c4947a3a95fdab886083892a18ba1a962ebaac31455584042")
                .expect("valid block hash");

        let block = Block::new(
            20378314,
            Chain::Ethereum,
            block_hash.to_bytes(),
            Default::default(),
            Default::default(),
        );

        let requests = vec![
            StorageSnapshotRequest {
                address: Address::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8")
                    .expect("valid address"),
                slots: None,
            },
            StorageSnapshotRequest {
                address: Address::from_str("0xae7ab96520de3a18e5e111b5eaab095312d7fe84")
                    .expect("valid address"),
                slots: None,
            },
        ];

        let start_time = std::time::Instant::now();
        let result = extractor
            .get_storage_snapshots(&requests, &block)
            .await?;
        let duration = start_time.elapsed();
        println!("Time taken to get storage snapshots: {:?}", duration);

        assert_eq!(result.len(), 2);

        // First account check
        let first_address =
            Address::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8").expect("valid address");
        let first_delta = result
            .get(&first_address)
            .expect("first address should exist");
        assert_eq!(first_delta.address, first_address);
        assert_eq!(first_delta.chain, Chain::Ethereum);
        assert!(first_delta.code.is_some());
        assert!(first_delta.balance.is_some());
        println!("Balance: {:?}", first_delta.balance);

        // Second account check
        let second_address =
            Address::from_str("0xae7ab96520de3a18e5e111b5eaab095312d7fe84").expect("valid address");
        let second_delta: &AccountDelta = result
            .get(&second_address)
            .expect("second address should exist");
        assert_eq!(second_delta.address, second_address);
        assert_eq!(second_delta.chain, Chain::Ethereum);
        assert!(second_delta.code.is_some());
        assert!(second_delta.balance.is_some());
        println!("Balance: {:?}", second_delta.balance);

        Ok(())
    }
}

use async_trait::async_trait;
use chrono::NaiveDateTime;
use ethers::{
    middleware::Middleware,
    prelude::{BlockId, Http, Provider, H160, H256, U256},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::mpsc};
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

// This message is sent from every HybridExtractor to the DynamicContractExtractor. It contains
// the ExternalAccountEntrypoints that should be added to the DCI.

pub struct EntryPointChangeMessage {
    protocol_system_id: String,
    protocol_component_id: String,
    change_msg: crate::extractor::evm::dci_dto::ExternalAccountEntrypoint,
    change_type: ChangeType,
}

pub struct DCIBlockUpdateMessage {
    block: Block,
    // Set of all AccountUpdates per ComponentId
    account_updates: Option<HashMap<String, Vec<AccountUpdate>>>,
}

pub struct ExternalAccountEntrypoint {
    pub address: Address,  // The contract's address
    pub signature: String, // The function name and parameter types
    pub parameters: HashMap<usize, Vec<Bytes>>,
}

pub struct DCIBlockProcessedMessage {
    block: Block,
    component_id_dependencies: HashMap<String, Address>,
    account_updates: HashMap<Address, Vec<AccountUpdate>>,
}

/*
Responsibilities:
    - ComponentEntrypointStateManager:
        - Keeps track of the latest `ExternalAccountEntrypoint`s set, per <ProtocolSystemId, ComponentId>.
        - Reacts to EntryPointChangeMessage messages, to keep the latest ExternalAccountEntrypoint set. Which means:
            - Adding new Entrypoints, if it's an Attribute Creation message.
            - Update current Entrypoints, if it's an Attribute Update message.
        - Returns, for every ExternalAccountEntrypointChange message received, the list of entrypoints that need to be re-tested.
        - Expostes a function that, when given a set of <ProtocolSystemId, ComponentId> , returns every ExternalAccountEntrypoint that needs to be tested.

    - ExternalAccountRegistry:
        - Keeps track of every account that is tracked (set)
        - Keeps track of every <ProtocolSystemId, ComponentId> -> Account relationship.
        - Keeps track of every inverse, Account -> <ProtocolSystemId, ComponentId> relationship.
        - Exposes a function to register new accounts to a <ProtocolSystemId, ComponentId> pair.
        - Exposes a function to remove accounts from a <ProtocolSystemId, ComponentId> pair
        - Handles block updates:
            - On every Substream full Block, identifies any state changes that happen on this block and return a message, mapping all the Accounts that have changed.

    - RetriggerController:
        - Keeps track of every <Address, StorageSlot> -> <ProtocolSystemId, ComponentId> that can trigger a retrigger
        - Handles block updates:
            - On every block, for every <Address, StorageSlot> change that matches the retrigger map:
                - Request ComponentEntrypointStateManager entrypoints for that <ProtocolSystemId, ComponentId>
                - Return all the entrypoints that need to be fuzzy-explored.

    - ContractAnalysisController:
        - Exposes a function that, when called with ProtocolSystemId, ComponentId, ExternalAccountEntrypoint:
            - Calls ContractAnalyzer.run(ProtocolSystemId, ComponentId, ExternalAccountEntrypoint, Block)
            - From the result, flatten the list of every contract that is received to get a set of contracts
                - For each contract, call the AccountExtractor to get the full state of a contract, for this block (cache the function call with block_id).
            - For each contract in the unflattened list try to find on which storage slot of the contract you can find the address of the next contract called in the dependency graph retruned from the ContractAnalyzer.run result
                - If found, save into an Array of <Address, StorageSlot> retriggers
                - If not, skip, assume it's a static value.
            - Return, in a struct:
                - ContractAnalyzer.run result
                - All the full state (storage slots) for all the touched accounts found on the fuzzer
                - All the retriggers.

    - Fuzzer(ContractAnalyzer trait):
        - Exposes a function to execute a fuzzing test on a Entrypoint
            - Returns fuzz_result

    - DynamicAccountExtactor:
        - Receive substreams message for Full Blocks:
            - Propagate block to ExternalAccountRegistry and collect all the accounts that have changed
            - Propagate block to RetriggerController and collect all the entrypoints that need to be fuzzed on this block
        - Receive EntryPointChangeMessage message from HybridExtractors:
            - Propagate to ComponentEntrypointStateManager and collect all the entrypoints that need to be fuzzed on this block

        - Wait for RetriggerController and EntryPointChangeMessage from HybridExtractors:
            - For each ProtocolSystemId
                - If no ComponentId in entrypoints that need to be fuzzed:
                    - Return DCIBlockProcessedMessage with the ExternalAccountRegistry changes that match the componentIds in this ProtocolSystemId. If nothing matches, emit empty component_id_dependencies and account_updates.
                - For each ComponentId, ExternalAccountEntrypoint (Worth caching the FuzzingExecution call to avoid repeated calls)
                    - Call ContractAnalysisController to execute the fuzzing test
                        - Append to Address: AccountState HashMap (erased on every block)
                - Gather all the full state and the state changes extracted from the ExternalAccountRegistry
                    - Return DCIBlockProcessedMessage

 */

// TODO: Update the following Trait according to the plan above.
#[async_trait]
pub trait DynamicContractExtractor {
    // This method is called on initialization. It should:
    // 1. Check if the account is already present in the database, by calling Postgres Gateway
    //    method
    // 2. If the account is not present, it should extract the account data using the
    //    AccountExtractor.
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

    fn register_channel(&self, channel: mpsc::Receiver<Address>);
}

pub struct DynamicContractExtractorImpl {
    // Account Extractor, responsible for the first extraction of the full contract storage.
    account_extractor: Box<dyn AccountExtractor>,
    // Tracks contracts that are being mapped.
    // Maps: ProtocolSystemId -> ProtocolComponentId -> Addresses
    tracked_contracts: HashMap<String, HashMap<String, Vec<Address>>>,
    // Communication channel between the HybridExtractors and the DynamicContractExtractor. Used
    // for the HybridExtractor to register new contract addresses.
    receiver_channel: mpsc::Receiver<Address>,
    // Communication channel between the DynamicContractExtractor and the HybridExtractors. Used
    // for sending the ContractStorage to the HybridExtractors. One channel per ProtocolSystem
    // (Extractor). Maps: ProtocolSystemId -> Sender
    sender_channels: HashMap<String, mpsc::Sender<AccountUpdate>>,
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

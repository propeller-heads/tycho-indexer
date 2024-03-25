use super::{utils::format_duration, Block};
use crate::{
    extractor::{
        evm::{
            self,
            chain_state::ChainState,
            token_pre_processor::{TokenPreProcessor, TokenPreProcessorTrait},
            BlockMessageWithCursor,
        },
        revert_buffer::RevertBuffer,
        ExtractionError, Extractor, ExtractorMsg,
    },
    pb::{
        sf::substreams::rpc::v2::{BlockScopedData, BlockUndoSignal, ModulesProgress},
        tycho::evm::v1::BlockContractChanges,
    },
};
use async_trait::async_trait;
use chrono::NaiveDateTime;

use ethers::types::{H160, H256};
use mockall::automock;
use prost::Message;
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
};
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, trace, warn};
use tycho_core::{
    models,
    models::{Chain, ExtractionState, ExtractorIdentity, ProtocolType},
    storage::{
        BlockIdentifier, ChainGateway, ContractStateGateway, ExtractionStateGateway,
        ProtocolGateway, StorageError,
    },
    Bytes,
};
use tycho_storage::postgres::cache::CachedGateway;

struct Inner {
    cursor: Vec<u8>,
    last_processed_block: Option<Block>,
    /// Used to give more informative logs
    last_report_ts: NaiveDateTime,
    last_report_block_number: u64,
}

pub struct VmContractExtractor<G> {
    gateway: G,
    name: String,
    chain: Chain,
    chain_state: ChainState,
    protocol_system: String,
    // TODO: There is not reason this needs to be shared
    // try removing the Mutex
    inner: Arc<Mutex<Inner>>,
    protocol_types: HashMap<String, ProtocolType>,
    /// Allows to attach some custom logic, e.g. to fix encoding bugs without re-sync.
    post_processor: Option<fn(evm::BlockContractChanges) -> evm::BlockContractChanges>,
    /// The number of blocks behind the current block to be considered as syncing.
    sync_threshold: u64,
    revert_buffer: Mutex<RevertBuffer<evm::BlockMessageWithCursor<evm::BlockContractChanges>>>,
}

impl<DB> VmContractExtractor<DB> {
    async fn update_cursor(&self, cursor: String) {
        let cursor_bytes: Vec<u8> = cursor.into();
        let mut state = self.inner.lock().await;
        state.cursor = cursor_bytes;
    }

    async fn update_last_processed_block(&self, block: Block) {
        let mut state = self.inner.lock().await;
        state.last_processed_block = Some(block);
    }

    async fn report_progress(&self, block: Block) {
        let mut state = self.inner.lock().await;
        let now = chrono::Local::now().naive_utc();
        let time_passed = now
            .signed_duration_since(state.last_report_ts)
            .num_seconds();
        let is_syncing = self.is_syncing(block.number).await;
        if is_syncing && time_passed >= 60 {
            let current_block = self.chain_state.current_block().await;
            let distance_to_current = current_block - block.number;
            let blocks_processed = block.number - state.last_report_block_number;
            let blocks_per_minute = blocks_processed as f64 * 60.0 / time_passed as f64;
            let time_remaining =
                chrono::Duration::minutes((distance_to_current as f64 / blocks_per_minute) as i64);
            info!(
                extractor_id = self.name,
                blocks_per_minute = format!("{blocks_per_minute:.2}"),
                blocks_processed,
                height = block.number,
                current = current_block,
                time_remaining = format_duration(&time_remaining),
                name = "SyncProgress"
            );
            state.last_report_ts = now;
            state.last_report_block_number = block.number;
        }
    }

    async fn is_syncing(&self, block_number: u64) -> bool {
        let current_block = self.chain_state.current_block().await;
        if current_block > block_number {
            (current_block - block_number) > self.sync_threshold
        } else {
            false
        }
    }
}

pub struct VmPgGateway<T>
where
    T: TokenPreProcessorTrait,
{
    name: String,
    chain: Chain,
    sync_batch_size: usize,
    state_gateway: CachedGateway,
    token_pre_processor: T,
}

#[automock]
#[async_trait]
pub trait VmGateway: Send + Sync {
    async fn get_cursor(&self) -> Result<Vec<u8>, StorageError>;

    async fn ensure_protocol_types(&self, new_protocol_types: &[ProtocolType]);

    async fn upsert_contract(
        &self,
        changes: &evm::BlockContractChanges,
        new_cursor: &str,
        syncing: bool,
    ) -> Result<(), StorageError>;

    async fn revert(
        &self,
        current: Option<BlockIdentifier>,
        to: &BlockIdentifier,
        new_cursor: &str,
    ) -> Result<evm::BlockAccountChanges, StorageError>;
}

impl<T> VmPgGateway<T>
where
    T: TokenPreProcessorTrait,
{
    pub fn new(
        name: &str,
        chain: Chain,
        sync_batch_size: usize,
        gw: CachedGateway,
        token_pre_processor: T,
    ) -> Self {
        VmPgGateway {
            name: name.to_owned(),
            chain,
            sync_batch_size,
            state_gateway: gw,
            token_pre_processor,
        }
    }

    #[instrument(skip_all)]
    async fn save_cursor(&self, new_cursor: &str) -> Result<(), StorageError> {
        let state =
            ExtractionState::new(self.name.to_string(), self.chain, None, new_cursor.as_bytes());
        self.state_gateway
            .save_state(&state)
            .await?;
        Ok(())
    }

    async fn get_new_tokens(
        &self,
        protocol_components: Vec<evm::ProtocolComponent>,
    ) -> Result<Vec<H160>, StorageError> {
        let mut tokens_set = HashSet::new();
        let mut addresses = HashSet::new();
        for component in protocol_components {
            for token in &component.tokens {
                tokens_set.insert(*token);
                let byte_slice = token.as_bytes();
                addresses.insert(Bytes::from(byte_slice.to_vec()));
            }
        }

        let address_refs: Vec<&Bytes> = addresses.iter().collect();
        let addresses_option = Some(address_refs.as_slice());

        let db_tokens = self
            .state_gateway
            .get_tokens(self.chain, addresses_option, None)
            .await?;

        for token in db_tokens {
            tokens_set.remove(&H160::from_slice(token.address.as_ref()));
        }
        Ok(tokens_set.into_iter().collect())
    }

    #[instrument(skip_all, fields(chain = % self.chain, name = % self.name, block_number = % changes.block.number))]
    async fn forward(
        &self,
        changes: &evm::BlockContractChanges,
        new_cursor: &str,
        syncing: bool,
    ) -> Result<(), StorageError> {
        debug!("Upserting block");
        self.state_gateway
            .start_transaction(&(&changes.block).into())
            .await;
        let protocol_components = changes
            .tx_updates
            .iter()
            .flat_map(|tx_u| {
                tx_u.protocol_components
                    .values()
                    .cloned()
            })
            .collect();
        let new_tokens_addresses = self
            .get_new_tokens(protocol_components)
            .await?;
        if !new_tokens_addresses.is_empty() {
            let new_tokens = self
                .token_pre_processor
                .get_tokens(new_tokens_addresses)
                .await
                .iter()
                .map(Into::into)
                .collect::<Vec<_>>();

            self.state_gateway
                .add_tokens(&new_tokens)
                .await?;
        }

        self.state_gateway
            .upsert_block(&[(&changes.block).into()])
            .await?;
        for update in changes.tx_updates.iter() {
            debug!(tx_hash = ?update.tx.hash, "Processing transaction");
            self.state_gateway
                .upsert_tx(&[(&update.tx).into()])
                .await?;
            for (_, acc_update) in update.account_updates.iter() {
                if acc_update.is_creation() {
                    let new: evm::Account = acc_update.ref_into_account(&update.tx);
                    info!(block_number = ?changes.block.number, contract_address = ?new.address, "New contract found at {:#020x}", &new.address);
                    self.state_gateway
                        .insert_contract(&(&new).into())
                        .await?;
                }
            }
            if !update.protocol_components.is_empty() {
                let protocol_components: Vec<models::protocol::ProtocolComponent> = update
                    .protocol_components
                    .values()
                    .map(Into::into)
                    .collect();
                self.state_gateway
                    .add_protocol_components(&protocol_components)
                    .await?;
            }
            if !update.component_balances.is_empty() {
                let mut component_balances_vec: Vec<models::protocol::ComponentBalance> =
                    Vec::new();
                for inner_map in update.component_balances.values() {
                    for balance in inner_map.values() {
                        component_balances_vec.push(balance.into());
                    }
                }
                self.state_gateway
                    .add_component_balances(&component_balances_vec)
                    .await?;
            }
        }
        let collected_changes: Vec<(Bytes, models::contract::ContractDelta)> = changes
            .tx_updates
            .iter()
            .flat_map(|u| {
                let a: Vec<(Bytes, models::contract::ContractDelta)> = u
                    .account_updates
                    .clone()
                    .into_iter()
                    .filter(|(_, acc_u)| acc_u.is_update())
                    .map(|(_, acc_u)| (tycho_core::Bytes::from(u.tx.hash), (&acc_u).into()))
                    .collect();
                a
            })
            .collect();

        let changes_slice: &[(Bytes, models::contract::ContractDelta)] =
            collected_changes.as_slice();

        self.state_gateway
            .update_contracts(changes_slice)
            .await?;
        self.save_cursor(new_cursor).await?;

        let batch_size: usize = if syncing { self.sync_batch_size } else { 0 };
        self.state_gateway
            .commit_transaction(batch_size)
            .await
    }

    async fn get_last_cursor(&self) -> Result<Vec<u8>, StorageError> {
        let state = self
            .state_gateway
            .get_state(&self.name, &self.chain)
            .await?;
        Ok(state.cursor)
    }
}

#[async_trait]
impl VmGateway for VmPgGateway<TokenPreProcessor> {
    async fn get_cursor(&self) -> Result<Vec<u8>, StorageError> {
        self.get_last_cursor().await
    }

    async fn ensure_protocol_types(&self, new_protocol_types: &[ProtocolType]) {
        self.state_gateway
            .add_protocol_types(new_protocol_types)
            .await
            .expect("Couldn't insert protocol types");
    }

    #[instrument(skip_all, fields(chain = % self.chain, name = % self.name, block_number = % changes.block.number))]
    async fn upsert_contract(
        &self,
        changes: &evm::BlockContractChanges,
        new_cursor: &str,
        syncing: bool,
    ) -> Result<(), StorageError> {
        self.forward(changes, new_cursor, syncing)
            .await?;
        Ok(())
    }

    #[allow(unused_variables)]
    #[instrument(skip_all, fields(chain = % self.chain, name = % self.name, block_number = % to))]
    async fn revert(
        &self,
        current: Option<BlockIdentifier>,
        to: &BlockIdentifier,
        new_cursor: &str,
    ) -> Result<evm::BlockAccountChanges, StorageError> {
        panic!("Not implemented!");
    }
}

impl<G> VmContractExtractor<G>
where
    G: VmGateway,
{
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        name: &str,
        chain: Chain,
        chain_state: ChainState,
        gateway: G,
        protocol_types: HashMap<String, ProtocolType>,
        protocol_system: String,
        post_processor: Option<fn(evm::BlockContractChanges) -> evm::BlockContractChanges>,
        sync_threshold: u64,
    ) -> Result<Self, ExtractionError> {
        // check if this extractor has state
        let res = match gateway.get_cursor().await {
            Err(StorageError::NotFound(_, _)) => {
                warn!(?name, ?chain, "No cursor found, starting from the beginning");
                VmContractExtractor {
                    gateway,
                    name: name.to_owned(),
                    chain,
                    chain_state,
                    inner: Arc::new(Mutex::new(Inner {
                        cursor: Vec::new(),
                        last_processed_block: None,
                        last_report_ts: chrono::Local::now().naive_utc(),
                        last_report_block_number: 0,
                    })),
                    protocol_system,
                    protocol_types,
                    post_processor,
                    sync_threshold,
                    revert_buffer: Mutex::new(RevertBuffer::new()),
                }
            }
            Ok(cursor) => {
                let cursor_hex = hex::encode(&cursor);
                info!(
                    ?name,
                    ?chain,
                    cursor = &cursor_hex,
                    "Found existing cursor! Resuming extractor.."
                );
                VmContractExtractor {
                    gateway,
                    name: name.to_owned(),
                    chain,
                    chain_state,
                    inner: Arc::new(Mutex::new(Inner {
                        cursor,
                        last_processed_block: None,
                        last_report_ts: chrono::Local::now().naive_utc(),
                        last_report_block_number: 0,
                    })),
                    protocol_system,
                    protocol_types,
                    post_processor,
                    sync_threshold,
                    revert_buffer: Mutex::new(RevertBuffer::new()),
                }
            }
            Err(err) => return Err(ExtractionError::Setup(err.to_string())),
        };

        res.ensure_protocol_types().await;
        Ok(res)
    }
}

#[async_trait]
impl<G> Extractor for VmContractExtractor<G>
where
    G: VmGateway,
{
    fn get_id(&self) -> ExtractorIdentity {
        ExtractorIdentity::new(self.chain, &self.name)
    }

    /// Make sure that the protocol types are present in the database.
    async fn ensure_protocol_types(&self) {
        let protocol_types: Vec<ProtocolType> = self
            .protocol_types
            .values()
            .cloned()
            .collect();
        self.gateway
            .ensure_protocol_types(&protocol_types)
            .await;
    }

    async fn get_cursor(&self) -> String {
        String::from_utf8(self.inner.lock().await.cursor.clone()).expect("Cursor is utf8")
    }

    async fn get_last_processed_block(&self) -> Option<Block> {
        self.inner
            .lock()
            .await
            .last_processed_block
    }

    #[instrument(skip_all, fields(chain = % self.chain, name = % self.name))]
    async fn handle_tick_scoped_data(
        &self,
        inp: BlockScopedData,
    ) -> Result<Option<ExtractorMsg>, ExtractionError> {
        let data = inp
            .output
            .as_ref()
            .unwrap()
            .map_output
            .as_ref()
            .unwrap();

        let raw_msg = BlockContractChanges::decode(data.value.as_slice())?;

        trace!(?raw_msg, "Received message");

        let msg = match evm::BlockContractChanges::try_from_message(
            raw_msg,
            &self.name,
            self.chain,
            self.protocol_system.clone(),
            &self.protocol_types,
        ) {
            Ok(changes) => {
                tracing::Span::current().record("block_number", changes.block.number);
                changes
            }
            Err(ExtractionError::Empty) => {
                self.update_cursor(inp.cursor).await;
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        let msg =
            if let Some(post_process_f) = self.post_processor { post_process_f(msg) } else { msg };

        // Depending on how Substreams handle them, this condition could be problematic for single
        // block finality blockchains.
        let is_syncing = inp.final_block_height >= msg.block.number;

        match is_syncing {
            true => {
                self.gateway
                    .upsert_contract(&msg, inp.cursor.as_ref(), is_syncing)
                    .await?;
            }
            false => {
                let mut revert_buffer = self.revert_buffer.lock().await;
                revert_buffer
                    .insert_block(BlockMessageWithCursor::new(msg.clone(), inp.cursor.clone()));
                for msg in revert_buffer
                    .drain_new_finalized_blocks(inp.final_block_height)
                    .expect("Final block height not found in revert buffer")
                {
                    self.gateway
                        .upsert_contract(&msg.0, &msg.1, is_syncing)
                        .await?;
                }
            }
        }

        self.update_last_processed_block(msg.block)
            .await;

        self.report_progress(msg.block).await;

        self.update_cursor(inp.cursor).await;

        return Ok(Some(Arc::new(msg.aggregate_updates()?)))
    }

    #[instrument(skip_all, fields(chain = % self.chain, name = % self.name, block_number = % inp.last_valid_block.as_ref().unwrap().number))]
    async fn handle_revert(
        &self,
        inp: BlockUndoSignal,
    ) -> Result<Option<ExtractorMsg>, ExtractionError> {
        let block_ref = inp
            .last_valid_block
            .ok_or_else(|| ExtractionError::DecodeError("Revert without block ref".into()))?;
        let block_hash = H256::from_str(&block_ref.id).map_err(|err| {
            ExtractionError::DecodeError(format!(
                "Failed to parse {} as block hash: {}",
                block_ref.id, err
            ))
        })?;

        let current = self
            .get_last_processed_block()
            .await
            .map(|block| BlockIdentifier::Hash(block.hash.into()));

        // Make sure we have a current block, otherwise it's not safe to revert.
        // TODO: add last block to extraction state and get it when creating a new extractor.
        // assert!(current.is_some(), "Revert without current block");
        if current.is_none() {
            // ignore for now if we don't have the current block, just ignore the revert.
            // This behaviour is not correct and we will have to rollback the database
            // to a good state once the revert issue has been fixed.
            return Ok(None);
        }

        let changes = self
            .gateway
            .revert(
                current,
                &BlockIdentifier::Hash(block_hash.into()),
                inp.last_valid_cursor.as_ref(),
            )
            .await?;
        self.update_cursor(inp.last_valid_cursor)
            .await;

        Ok((!changes.account_updates.is_empty()).then_some(Arc::new(changes)))
    }

    #[instrument(skip_all)]
    async fn handle_progress(&self, _inp: ModulesProgress) -> Result<(), ExtractionError> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pb::sf::substreams::v1::BlockRef;
    use tycho_core::models::{FinancialType, ImplementationType};

    fn ambient_protocol_types() -> HashMap<String, ProtocolType> {
        let mut ambient_protocol_types = HashMap::new();
        ambient_protocol_types.insert(
            "WeightedPool".to_string(),
            ProtocolType::new(
                "WeightedPool".to_string(),
                FinancialType::Swap,
                None,
                ImplementationType::Vm,
            ),
        );
        ambient_protocol_types
    }

    #[tokio::test]
    async fn test_get_cursor() {
        let mut gw = MockVmGateway::new();
        gw.expect_ensure_protocol_types()
            .times(1)
            .returning(|_| ());
        gw.expect_get_cursor()
            .times(1)
            .returning(|| Ok("cursor".into()));

        let extractor = VmContractExtractor::new(
            "vm:ambient",
            Chain::Ethereum,
            ChainState::default(),
            gw,
            ambient_protocol_types(),
            "ambient".into(),
            None,
            5,
        )
        .await
        .expect("extractor init ok");

        let res = extractor.get_cursor().await;

        assert_eq!(res, "cursor");
    }

    fn block_contract_changes_ok() -> BlockContractChanges {
        evm::fixtures::pb_block_contract_changes()
    }

    #[tokio::test]
    async fn test_handle_tick_scoped_data() {
        let mut gw = MockVmGateway::new();
        gw.expect_ensure_protocol_types()
            .times(1)
            .returning(|_| ());
        gw.expect_get_cursor()
            .times(1)
            .returning(|| Ok("cursor".into()));
        gw.expect_upsert_contract()
            .times(1)
            .returning(|_, _, _| Ok(()));
        let extractor = VmContractExtractor::new(
            "vm:ambient",
            Chain::Ethereum,
            ChainState::default(),
            gw,
            ambient_protocol_types(),
            "ambient".to_owned(),
            None,
            5,
        )
        .await
        .expect("extractor init ok");
        let inp = evm::fixtures::pb_block_scoped_data(block_contract_changes_ok());
        let exp = Ok(Some(()));

        let res = extractor
            .handle_tick_scoped_data(inp)
            .await
            .map(|o| o.map(|_| ()));

        assert_eq!(res, exp);
        assert_eq!(extractor.get_cursor().await, "cursor@420");
    }

    #[tokio::test]
    async fn test_handle_tick_scoped_data_skip() {
        let mut gw = MockVmGateway::new();
        gw.expect_ensure_protocol_types()
            .times(1)
            .returning(|_| ());
        gw.expect_get_cursor()
            .times(1)
            .returning(|| Ok("cursor".into()));
        gw.expect_upsert_contract()
            .times(0)
            .returning(|_, _, _| Ok(()));
        let extractor = VmContractExtractor::new(
            "vm:ambient",
            Chain::Ethereum,
            ChainState::default(),
            gw,
            ambient_protocol_types(),
            "ambient".to_owned(),
            None,
            5,
        )
        .await
        .expect("extractor init ok");
        let inp = evm::fixtures::pb_block_scoped_data(());

        let res = extractor
            .handle_tick_scoped_data(inp)
            .await;

        match res {
            Ok(Some(_)) => panic!("Expected Ok(None) but got Ok(Some(..))"),
            Ok(None) => (), // This is the expected case
            Err(_) => panic!("Expected Ok(None) but got Err(..)"),
        }

        assert_eq!(extractor.get_cursor().await, "cursor@420");
    }

    fn undo_signal() -> BlockUndoSignal {
        BlockUndoSignal {
            last_valid_block: Some(BlockRef { id: evm::fixtures::HASH_256_0.into(), number: 400 }),
            last_valid_cursor: "cursor@400".into(),
        }
    }

    #[tokio::test]
    async fn test_handle_revert() {
        let mut gw = MockVmGateway::new();
        gw.expect_ensure_protocol_types()
            .times(1)
            .returning(|_| ());
        gw.expect_get_cursor()
            .times(1)
            .returning(|| Ok("cursor".into()));

        gw.expect_upsert_contract()
            .times(1)
            .returning(|_, _, _| Ok(()));

        gw.expect_revert()
            .withf(|c, v, cursor| {
                c.clone().unwrap() ==
                    BlockIdentifier::Hash(
                        Bytes::from_str(
                            "0x0000000000000000000000000000000000000000000000000000000031323334",
                        )
                        .unwrap(),
                    ) &&
                    v == &BlockIdentifier::Hash(evm::fixtures::HASH_256_0.into()) &&
                    cursor == "cursor@400"
            })
            .times(1)
            .returning(|_, _, _| Ok(evm::BlockAccountChanges::default()));
        let extractor = VmContractExtractor::new(
            "vm:ambient",
            Chain::Ethereum,
            ChainState::default(),
            gw,
            ambient_protocol_types(),
            "ambient".to_owned(),
            None,
            5,
        )
        .await
        .expect("extractor init ok");

        // Call handle_tick_scoped_data to initialize the last processed block.
        let inp = evm::fixtures::pb_block_scoped_data(block_contract_changes_ok());

        extractor
            .handle_tick_scoped_data(inp)
            .await
            .unwrap();

        let inp = undo_signal();

        let res = extractor.handle_revert(inp).await;

        assert!(matches!(res, Ok(None)));
        assert_eq!(extractor.get_cursor().await, "cursor@400");
    }
}

/// It is notoriously hard to mock postgres here, we would need to have traits and abstractions
/// for the connection pooling as well as for transaction handling so the easiest way
/// forward is to just run these tests against a real postgres instance.
///
/// The challenge here is to leave the database empty. So we need to initiate a test transaction
/// and should avoid calling the trait methods which start a transaction of their own. So we do
/// that by moving the main logic of each trait method into a private method and test this
/// method instead.
///
/// Note that it is ok to use higher level db methods here as there is a layer of abstraction
/// between this component and the actual db interactions
#[cfg(test)]
mod test_serial_db {

    use crate::extractor::evm::{
        token_pre_processor::MockTokenPreProcessorTrait, AccountUpdate, ComponentBalance,
        ProtocolComponent,
    };
    use diesel_async::{pooled_connection::deadpool::Pool, AsyncPgConnection};
    use ethers::types::U256;
    use test_log::test;
    use tycho_core::{
        models::{ChangeType, ContractId},
        storage::BlockOrTimestamp,
    };
    use tycho_storage::{
        postgres,
        postgres::{builder::GatewayBuilder, db_fixtures, testing::run_against_db},
    };

    use super::*;

    const TX_HASH_0: &str = "0x2f6350a292c0fc918afe67cb893744a080dacb507b0cea4cc07437b8aff23cdb";
    const TX_HASH_1: &str = "0x0d9e0da36cf9f305a189965b248fc79c923619801e8ab5ef158d4fd528a291ad";
    const TX_HASH_2: &str = "0xcf574444be25450fe26d16b85102b241e964a6e01d75dd962203d4888269be3d";
    const BLOCK_HASH_0: &str = "0x98b4a4fef932b1862be52de218cc32b714a295fae48b775202361a6fa09b66eb";

    const WETH_ADDRESS: &str = "C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    const USDC_ADDRESS: &str = "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const USDT_ADDRESS: &str = "dAC17F958D2ee523a2206206994597C13D831ec7";

    const AMBIENT_CONTRACT: [u8; 20] =
        hex_literal::hex!("aaaaaaaaa24eeeb8d57d431224f73832bc34f688");

    fn get_mocked_token_pre_processor() -> MockTokenPreProcessorTrait {
        let mut mock_processor = MockTokenPreProcessorTrait::new();
        let new_tokens = vec![
            evm::ERC20Token::new(
                H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                    .expect("Invalid H160 address"),
                "WETH".to_string(),
                18,
                0,
                vec![],
                Default::default(),
                100,
            ),
            evm::ERC20Token::new(
                H160::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                    .expect("Invalid H160 address"),
                "USDC".to_string(),
                6,
                0,
                vec![],
                Default::default(),
                100,
            ),
        ];
        mock_processor
            .expect_get_tokens()
            .returning(move |_| new_tokens.clone());

        mock_processor
    }

    async fn setup_gw(pool: Pool<AsyncPgConnection>) -> VmPgGateway<MockTokenPreProcessorTrait> {
        let mut conn = pool
            .get()
            .await
            .expect("pool should get a connection");

        postgres::db_fixtures::insert_protocol_type(&mut conn, "vm:pool", None, None, None).await;
        let chain_id = postgres::db_fixtures::insert_chain(&mut conn, "ethereum").await;
        db_fixtures::insert_token(&mut conn, chain_id, WETH_ADDRESS, "WETH", 18).await;
        db_fixtures::insert_token(&mut conn, chain_id, USDC_ADDRESS, "USDC", 6).await;

        let db_url = std::env::var("DATABASE_URL").expect("Database URL must be set for testing");
        let (cached_gw, _jh) = GatewayBuilder::new(db_url.as_str())
            .set_chains(&[Chain::Ethereum])
            .set_protocol_systems(&["ambient".to_string()])
            .build()
            .await
            .expect("failed to build postgres gateway");
        VmPgGateway::new(
            "vm:ambient",
            Chain::Ethereum,
            1000,
            cached_gw,
            get_mocked_token_pre_processor(),
        )
    }

    #[tokio::test]
    async fn test_get_cursor() {
        run_against_db(|pool| async move {
            let gw = setup_gw(pool).await;
            let evm_gw = gw.state_gateway.clone();
            let state = ExtractionState::new(
                "vm:ambient".to_string(),
                Chain::Ethereum,
                None,
                "cursor@420".as_bytes(),
            );
            evm_gw
                .start_transaction(&models::blockchain::Block::default())
                .await;
            evm_gw
                .save_state(&state)
                .await
                .expect("extaction state insertion succeeded");
            evm_gw
                .commit_transaction(0)
                .await
                .expect("gw transaction failed");

            let cursor = gw
                .get_last_cursor()
                .await
                .expect("get cursor should succeed");

            assert_eq!(cursor, "cursor@420".as_bytes());
        })
        .await;
    }

    fn ambient_account(at_version: u64) -> models::contract::Contract {
        match at_version {
            0 => (&evm::Account::new(
                Chain::Ethereum,
                "0xaaaaaaaaa24eeeb8d57d431224f73832bc34f688"
                    .parse()
                    .unwrap(),
                "0xaaaaaaaaa24eeeb8d57d431224f73832bc34f688".to_owned(),
                evm::fixtures::evm_slots([(1, 200)]),
                U256::from(1000),
                vec![0, 0, 0, 0].into(),
                "0xe8e77626586f73b955364c7b4bbf0bb7f7685ebd40e852b164633a4acbd3244c"
                    .parse()
                    .unwrap(),
                TX_HASH_1.parse().unwrap(),
                TX_HASH_0.parse().unwrap(),
                Some(TX_HASH_0.parse().unwrap()),
            ))
                .into(),
            _ => panic!("Unkown version"),
        }
    }

    fn ambient_creation_and_update() -> evm::BlockContractChanges {
        let base_token = H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
            .expect("Invalid H160 address");
        let quote_token = H160::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
            .expect("Invalid H160 address");
        let component_id = "ambient_USDC_ETH".to_string();
        evm::BlockContractChanges {
            extractor: "vm:ambient".to_owned(),
            chain: Chain::Ethereum,
            block: evm::Block::default(),
            revert: false,
            tx_updates: vec![
                evm::TransactionVMUpdates::new(
                    [(
                        H160(AMBIENT_CONTRACT),
                        AccountUpdate::new(
                            H160(AMBIENT_CONTRACT),
                            Chain::Ethereum,
                            HashMap::new(),
                            None,
                            Some(vec![0, 0, 0, 0].into()),
                            ChangeType::Creation,
                        ),
                    )]
                    .into_iter()
                    .collect(),
                    HashMap::from([(
                        component_id.clone(),
                        ProtocolComponent {
                            id: component_id.clone(),
                            protocol_system: "ambient".to_string(),
                            protocol_type_name: "vm:pool".to_string(),
                            chain: Chain::Ethereum,
                            tokens: vec![base_token, quote_token],
                            contract_ids: vec![H160(AMBIENT_CONTRACT)],
                            static_attributes: Default::default(),
                            change: Default::default(),
                            creation_tx: TX_HASH_0.parse().unwrap(),
                            created_at: Default::default(),
                        },
                    )]),
                    HashMap::from([(
                        component_id.clone(),
                        HashMap::from([(
                            base_token,
                            ComponentBalance {
                                token: base_token,
                                balance: Bytes::from(&[0u8]),
                                balance_float: 10.0,
                                modify_tx: TX_HASH_0.parse().unwrap(),
                                component_id: component_id.clone(),
                            },
                        )]),
                    )]),
                    evm::fixtures::transaction02(TX_HASH_0, evm::fixtures::HASH_256_0, 1),
                ),
                evm::TransactionVMUpdates::new(
                    [(
                        H160(AMBIENT_CONTRACT),
                        AccountUpdate::new(
                            H160(AMBIENT_CONTRACT),
                            Chain::Ethereum,
                            evm::fixtures::evm_slots([(1, 200)]),
                            Some(U256::from(1000)),
                            None,
                            ChangeType::Update,
                        ),
                    )]
                    .into_iter()
                    .collect(),
                    HashMap::new(),
                    HashMap::from([(
                        component_id.clone(),
                        HashMap::from([(
                            base_token,
                            ComponentBalance {
                                token: base_token,
                                balance: Bytes::from(&[0u8]),
                                balance_float: 10.0,
                                modify_tx: TX_HASH_1.parse().unwrap(),
                                component_id: component_id.clone(),
                            },
                        )]),
                    )]),
                    evm::fixtures::transaction02(TX_HASH_1, evm::fixtures::HASH_256_0, 2),
                ),
            ],
        }
    }

    // Allow dead code until reverts are supported again
    #[allow(dead_code)]
    fn ambient_update02() -> evm::BlockContractChanges {
        let block = evm::Block {
            number: 1,
            chain: Chain::Ethereum,
            hash: BLOCK_HASH_0.parse().unwrap(),
            parent_hash: H256::zero(),
            ts: "2020-01-01T01:00:00".parse().unwrap(),
        };
        evm::BlockContractChanges {
            extractor: "vm:ambient".to_owned(),
            chain: Chain::Ethereum,
            block,
            revert: false,
            tx_updates: vec![evm::TransactionVMUpdates::new(
                [(
                    H160(AMBIENT_CONTRACT),
                    AccountUpdate::new(
                        H160(AMBIENT_CONTRACT),
                        Chain::Ethereum,
                        evm::fixtures::evm_slots([(42, 0xbadbabe)]),
                        Some(U256::from(2000)),
                        None,
                        ChangeType::Update,
                    ),
                )]
                .into_iter()
                .collect(),
                HashMap::new(),
                HashMap::new(),
                evm::fixtures::transaction02(TX_HASH_2, BLOCK_HASH_0, 1),
            )],
        }
    }

    #[test(tokio::test)]
    async fn test_upsert_contract() {
        run_against_db(|pool| async move {
            let gw = setup_gw(pool).await;
            let msg = ambient_creation_and_update();
            let exp = ambient_account(0);

            gw.forward(&msg, "cursor@500", false)
                .await
                .expect("upsert should succeed");

            let cached_gw: CachedGateway = gw.state_gateway;

            let res = cached_gw
                .get_contract(
                    &ContractId::new(Chain::Ethereum, AMBIENT_CONTRACT.into()),
                    None,
                    true,
                )
                .await
                .expect("test successfully inserted ambient contract");
            assert_eq!(res, exp);

            let tokens = cached_gw
                .get_tokens(Chain::Ethereum, None, None)
                .await
                .unwrap();
            assert_eq!(tokens.len(), 2);

            let protocol_components = cached_gw
                .get_protocol_components(&Chain::Ethereum, None, None, None)
                .await
                .unwrap();
            assert_eq!(protocol_components.len(), 1);
            assert_eq!(protocol_components[0].creation_tx, Bytes::from(TX_HASH_0));

            let component_balances = cached_gw
                .get_balance_deltas(
                    &Chain::Ethereum,
                    None,
                    &BlockOrTimestamp::Block(BlockIdentifier::Number((
                        Chain::Ethereum,
                        msg.block.number as i64,
                    ))),
                )
                .await
                .unwrap();

            // TODO: improve asserts
            assert_eq!(component_balances.len(), 1);
            dbg!(&component_balances);
            assert_eq!(component_balances[0].component_id, "ambient_USDC_ETH");
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_new_tokens() {
        run_against_db(|pool| async move {
            let gw = setup_gw(pool.clone()).await;

            let component_1 = evm::ProtocolComponent {
                id: "ambient_USDC_WETH".to_owned(),
                protocol_system: "ambient".to_string(),
                protocol_type_name: "vm:pool".to_string(),
                chain: Default::default(),
                tokens: vec![
                    H160::from_str(WETH_ADDRESS).expect("Invalid H160 address"),
                    H160::from_str(USDC_ADDRESS).expect("Invalid H160 address"),
                ],
                contract_ids: vec![],
                creation_tx: Default::default(),
                static_attributes: Default::default(),
                created_at: Default::default(),
                change: Default::default(),
            };
            let component_2 = evm::ProtocolComponent {
                id: "ambient_USDT_WETH".to_owned(),
                protocol_system: "ambient".to_string(),
                protocol_type_name: "vm:pool".to_string(),
                chain: Default::default(),
                tokens: vec![
                    H160::from_str(WETH_ADDRESS).expect("Invalid H160 address"),
                    H160::from_str(USDT_ADDRESS).expect("Invalid H160 address"),
                ],
                contract_ids: vec![],
                creation_tx: Default::default(),
                static_attributes: Default::default(),
                created_at: Default::default(),
                change: Default::default(),
            };
            // get no new tokens
            let new_tokens = gw
                .get_new_tokens(vec![component_1.clone()])
                .await
                .unwrap();
            assert_eq!(new_tokens.len(), 0);

            // get one new token
            let new_tokens = gw
                .get_new_tokens(vec![component_1, component_2])
                .await
                .unwrap();
            assert_eq!(new_tokens.len(), 1);
            assert_eq!(new_tokens[0], H160::from_str(USDT_ADDRESS).expect("Invalid H160 address"));
        })
        .await;
    }
}

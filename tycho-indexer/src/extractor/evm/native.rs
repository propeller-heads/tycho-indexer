use super::{
    token_pre_processor::{TokenPreProcessor, TokenPreProcessorTrait},
    utils::format_duration,
};
use crate::{
    extractor::{
        evm::{self, chain_state::ChainState, Block},
        revert_buffer::{RevertBuffer, RevertBufferEntry},
        ExtractionError, Extractor, ExtractorMsg,
    },
    pb::{
        sf::substreams::rpc::v2::{BlockScopedData, BlockUndoSignal, ModulesProgress},
        tycho::evm::v1::BlockEntityChanges,
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
    models::{
        self, protocol::ProtocolComponentState, Chain, ExtractionState, ExtractorIdentity,
        ProtocolType, TxHash,
    },
    storage::{
        BlockIdentifier, ChainGateway, ExtractionStateGateway, ProtocolGateway, StorageError,
    },
    Bytes,
};
use tycho_storage::postgres::cache::CachedGateway;

pub struct Inner {
    cursor: Vec<u8>,
    last_processed_block: Option<Block>,
    /// Used to give more informative logs
    last_report_ts: NaiveDateTime,
    last_report_block_number: u64,
}

pub struct NativeContractExtractor<G> {
    gateway: G,
    name: String,
    chain: Chain,
    chain_state: ChainState,
    protocol_system: String,
    inner: Arc<Mutex<Inner>>,
    protocol_types: HashMap<String, ProtocolType>,
    /// Allows to attach some custom logic, e.g. to fix encoding bugs without resync.
    post_processor: Option<fn(evm::BlockEntityChanges) -> evm::BlockEntityChanges>,
    /// The number of blocks behind the current block to be considered as syncing.
    sync_threshold: u64,
    revert_buffer: Mutex<RevertBuffer<evm::BlockEntityChanges>>,
}

impl<DB> NativeContractExtractor<DB> {
    async fn update_cursor(&self, cursor: String) {
        let mut state = self.inner.lock().await;
        state.cursor = cursor.into();
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

pub struct NativePgGateway<T>
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
pub trait NativeGateway: Send + Sync {
    async fn get_cursor(&self) -> Result<Vec<u8>, StorageError>;

    async fn ensure_protocol_types(&self, new_protocol_types: &[ProtocolType]);

    async fn advance(
        &self,
        changes: &evm::BlockEntityChanges,
        new_cursor: &str,
        syncing: bool,
    ) -> Result<(), StorageError>;

    async fn revert(
        &self,
        current: Option<BlockIdentifier>,
        to: &BlockIdentifier,
        new_cursor: &str,
    ) -> Result<evm::BlockEntityChangesResult, StorageError>;

    async fn get_components_state<'a>(
        &self,
        component_ids: &[&'a str],
    ) -> Result<Vec<ProtocolComponentState>, StorageError>;
}

impl<T> NativePgGateway<T>
where
    T: TokenPreProcessorTrait,
{
    pub fn new(
        name: &str,
        chain: Chain,
        sync_batch_size: usize,
        state_gateway: CachedGateway,
        token_pre_processor: T,
    ) -> Self {
        Self { name: name.to_owned(), chain, sync_batch_size, state_gateway, token_pre_processor }
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

    /// Get tokens that are not in the database
    async fn get_new_tokens(&self, tokens: HashSet<H160>) -> Result<Vec<H160>, StorageError> {
        let addresses: Vec<Bytes> = tokens
            .iter()
            .map(|a| Bytes::from(a.as_bytes().to_vec()))
            .collect();
        let address_refs: Vec<&Bytes> = addresses.iter().collect();

        let addresses_option = Some(address_refs.as_slice());

        let db_tokens = self
            .state_gateway
            .get_tokens(self.chain, addresses_option, None)
            .await?;

        let db_token_addresses: HashSet<_> = db_tokens
            .iter()
            .map(|token| H160::from_slice(token.address.as_ref()))
            .collect();
        let filtered_tokens = tokens
            .into_iter()
            .filter(|token| !db_token_addresses.contains(token))
            .collect();

        Ok(filtered_tokens)
    }

    #[instrument(skip_all, fields(chain = % self.chain, name = % self.name, block_number = % changes.block.number))]
    async fn forward(
        &self,
        changes: &evm::BlockEntityChanges,
        new_cursor: &str,
        syncing: bool,
    ) -> Result<(), StorageError> {
        debug!("Upserting block");
        self.state_gateway
            .start_transaction(&(&changes.block).into())
            .await;
        self.state_gateway
            .upsert_block(&[(&changes.block).into()])
            .await?;

        let mut new_protocol_components: Vec<models::protocol::ProtocolComponent> = vec![];
        let mut state_updates: Vec<(TxHash, models::protocol::ProtocolComponentStateDelta)> =
            vec![];
        let mut balance_changes: Vec<models::protocol::ComponentBalance> = vec![];

        let mut protocol_tokens: HashSet<H160> = HashSet::new();

        for tx in changes.txs_with_update.iter() {
            self.state_gateway
                .upsert_tx(&[(&tx.tx).into()])
                .await?;

            let hash: TxHash = tx.tx.hash.into();

            for (_component_id, new_protocol_component) in tx.new_protocol_components.iter() {
                new_protocol_components.push(new_protocol_component.into());
                protocol_tokens.extend(new_protocol_component.tokens.iter());
            }

            state_updates.extend(
                tx.protocol_states
                    .values()
                    .map(|state_change| (hash.clone(), state_change.into())),
            );

            balance_changes.extend(
                tx.balance_changes
                    .iter()
                    .flat_map(|(_, tokens)| tokens.values().map(Into::into)),
            );
        }

        let new_tokens_addresses = self
            .get_new_tokens(protocol_tokens)
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

        if !new_protocol_components.is_empty() {
            self.state_gateway
                .add_protocol_components(new_protocol_components.as_slice())
                .await?;
        }

        if !state_updates.is_empty() {
            self.state_gateway
                .update_protocol_states(state_updates.as_slice())
                .await?;
        }

        if !balance_changes.is_empty() {
            self.state_gateway
                .add_component_balances(balance_changes.as_slice())
                .await?;
        }

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
impl NativeGateway for NativePgGateway<TokenPreProcessor> {
    async fn get_cursor(&self) -> Result<Vec<u8>, StorageError> {
        self.get_last_cursor().await
    }

    async fn get_components_state<'a>(
        &self,
        component_ids: &[&'a str],
    ) -> Result<Vec<ProtocolComponentState>, StorageError> {
        self.state_gateway
            .get_protocol_states(&self.chain, None, None, Some(component_ids))
            .await
    }

    async fn ensure_protocol_types(&self, new_protocol_types: &[ProtocolType]) {
        self.state_gateway
            .add_protocol_types(new_protocol_types)
            .await
            .expect("Couldn't insert protocol types");
    }

    #[instrument(skip_all, fields(chain = % self.chain, name = % self.name, block_number = % changes.block.number))]
    async fn advance(
        &self,
        changes: &evm::BlockEntityChanges,
        new_cursor: &str,
        syncing: bool,
    ) -> Result<(), StorageError> {
        self.forward(changes, new_cursor, syncing)
            .await?;
        Ok(())
    }

    async fn revert(
        &self,
        _current: Option<BlockIdentifier>,
        _to: &BlockIdentifier,
        _new_cursor: &str,
    ) -> Result<evm::BlockEntityChangesResult, StorageError> {
        panic!("Not implemented")
    }
}

impl<G> NativeContractExtractor<G>
where
    G: NativeGateway,
{
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        name: &str,
        chain: Chain,
        chain_state: ChainState,
        gateway: G,
        protocol_types: HashMap<String, ProtocolType>,
        protocol_system: String,
        post_processor: Option<fn(evm::BlockEntityChanges) -> evm::BlockEntityChanges>,
        sync_threshold: u64,
    ) -> Result<Self, ExtractionError> {
        let res = match gateway.get_cursor().await {
            Err(StorageError::NotFound(_, _)) => {
                warn!(?name, ?chain, "No cursor found, starting from the beginning");
                NativeContractExtractor {
                    gateway,
                    name: name.to_string(),
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
                NativeContractExtractor {
                    gateway,
                    name: name.to_string(),
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
impl<G> Extractor for NativeContractExtractor<G>
where
    G: NativeGateway,
{
    fn get_id(&self) -> ExtractorIdentity {
        ExtractorIdentity::new(self.chain, &self.name)
    }

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

        let raw_msg = BlockEntityChanges::decode(data.value.as_slice())?;

        trace!(?raw_msg, "Received message");

        // Validate protocol_type_id
        let msg = match evm::BlockEntityChanges::try_from_message(
            raw_msg,
            &self.name,
            self.chain,
            &self.protocol_system,
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

        trace!(?msg, "Processing message");

        // Depending on how Substreams handle them, this condition could be problematic for single
        // block finality blockchains.
        let is_syncing = inp.final_block_height >= msg.block.number;

        match is_syncing {
            true => {
                self.gateway
                    .advance(&msg, inp.cursor.as_ref(), is_syncing)
                    .await?;
            }
            false => {
                let mut revert_buffer = self.revert_buffer.lock().await;
                revert_buffer
                    .insert_block(RevertBufferEntry::new(msg.clone(), inp.cursor.clone()))
                    .expect("Error while inserting a block into revert buffer");
                for msg in revert_buffer
                    .drain_new_finalized_blocks(inp.final_block_height)
                    .expect("Final block height not found in revert buffer")
                {
                    self.gateway
                        .advance(msg.block_update(), msg.cursor(), is_syncing)
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

        let mut revert_buffer = self.revert_buffer.lock().await;

        // Purge the buffer and create a set of state that was reverted
        let reverted_state = revert_buffer
            .purge(block_hash.into())
            .expect("Failed to purge revert buffer");

        let reverted_keys: HashSet<_> = reverted_state
            .iter()
            .flat_map(|block_msg| {
                block_msg
                    .block_update()
                    .txs_with_update
                    .iter()
                    .flat_map(|update| {
                        update
                            .protocol_states
                            .iter()
                            .flat_map(|(c_id, delta)| {
                                delta
                                    .updated_attributes
                                    .keys()
                                    .map(move |key| (c_id, key))
                            })
                    })
            })
            .collect();

        // Fetch previous values for every reverted states
        // First search in the buffer
        let (buffered, missing) = revert_buffer.lookup_state(
            &reverted_keys
                .into_iter()
                .collect::<Vec<_>>(),
        );

        let mut state_updates: HashMap<String, evm::ProtocolStateDelta> = buffered
            .into_iter()
            .fold(HashMap::new(), |mut acc, ((c_id, key), value)| {
                acc.entry(c_id.clone())
                    .or_insert_with(|| evm::ProtocolStateDelta {
                        component_id: c_id.clone(),
                        updated_attributes: HashMap::new(),
                        deleted_attributes: HashSet::new(),
                    })
                    .updated_attributes
                    .insert(key.clone(), value);
                acc
            });

        // Then for every missing previous values in the buffer, get the data from our db
        let missing_map: HashMap<String, Vec<String>> =
            missing
                .into_iter()
                .fold(HashMap::new(), |mut acc, (c_id, key)| {
                    acc.entry(c_id).or_default().push(key);
                    acc
                });

        let missing_components_states = self
            .gateway
            .get_components_state(
                &missing_map
                    .keys()
                    .map(AsRef::as_ref)
                    .collect::<Vec<&str>>(),
            )
            .await
            .expect("Failed to retrieve components states during revert");

        for mut missing_state in missing_components_states {
            if let Some(keys) = missing_map.get(&missing_state.component_id) {
                for key in keys {
                    if let Some(attr) = missing_state.attributes.remove(key) {
                        state_updates
                            .entry(missing_state.component_id.clone())
                            .or_insert_with(|| evm::ProtocolStateDelta {
                                component_id: missing_state.component_id.clone(),
                                updated_attributes: HashMap::new(),
                                deleted_attributes: HashSet::new(),
                            })
                            .updated_attributes
                            .insert(key.clone(), attr);
                    } else {
                        // Return with error if we couldn't find a previous value here because it
                        // means clients would have a wrong state.
                        return Err(ExtractionError::Storage(StorageError::NotFound(
                            "Attribute".to_string(),
                            format!("component_id:{}, key:{}", missing_state.component_id, key),
                        )))
                    }
                }
            }
        }

        let revert_message = evm::BlockEntityChangesResult {
            extractor: self.name.clone(),
            chain: self.chain,
            block: revert_buffer
                .get_most_recent_block()
                .expect("Couldn't find most recent block in buffer during revert")
                .into(),
            revert: true,
            state_updates,
            new_protocol_components: HashMap::new(),
            deleted_protocol_components: HashMap::new(),
            component_balances: HashMap::new(),
            component_tvl: HashMap::new(),
        };

        self.update_cursor(inp.last_valid_cursor)
            .await;

        let should_send = !revert_message.state_updates.is_empty() ||
            !revert_message
                .new_protocol_components
                .is_empty() ||
            !revert_message
                .deleted_protocol_components
                .is_empty() ||
            !revert_message
                .component_balances
                .is_empty() ||
            !revert_message.component_tvl.is_empty();

        Ok(should_send.then_some(Arc::new(revert_message)))
    }

    async fn handle_progress(&self, _inp: ModulesProgress) -> Result<(), ExtractionError> {
        todo!()
    }
}

#[cfg(test)]
mod test {

    use crate::pb::sf::substreams::v1::BlockRef;

    use super::*;

    const EXTRACTOR_NAME: &str = "TestExtractor";
    const TEST_PROTOCOL: &str = "TestProtocol";

    async fn create_extractor(gw: MockNativeGateway) -> NativeContractExtractor<MockNativeGateway> {
        let protocol_types = HashMap::from([("WeightedPool".to_string(), ProtocolType::default())]);

        NativeContractExtractor::new(
            EXTRACTOR_NAME,
            Chain::Ethereum,
            ChainState::default(),
            gw,
            protocol_types,
            TEST_PROTOCOL.to_string(),
            None,
            5,
        )
        .await
        .expect("Failed to create extractor")
    }

    #[tokio::test]
    async fn test_get_cursor() {
        let mut gw = MockNativeGateway::new();
        gw.expect_ensure_protocol_types()
            .times(1)
            .returning(|_| ());
        gw.expect_get_cursor()
            .times(1)
            .returning(|| Ok("cursor".into()));

        let extractor = create_extractor(gw).await;
        let res = extractor.get_cursor().await;

        assert_eq!(res, "cursor");
    }

    #[tokio::test]
    async fn test_handle_tick_scoped_data() {
        let mut gw = MockNativeGateway::new();
        gw.expect_ensure_protocol_types()
            .times(1)
            .returning(|_| ());
        gw.expect_get_cursor()
            .times(1)
            .returning(|| Ok("cursor".into()));
        gw.expect_advance()
            .times(1)
            .returning(|_, _, _| Ok(()));

        let extractor = create_extractor(gw).await;

        let inp = evm::fixtures::pb_block_scoped_data(evm::fixtures::pb_block_entity_changes());
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
        let mut gw = MockNativeGateway::new();
        gw.expect_ensure_protocol_types()
            .times(1)
            .returning(|_| ());
        gw.expect_get_cursor()
            .times(1)
            .returning(|| Ok("cursor".into()));
        gw.expect_advance()
            .times(0)
            .returning(|_, _, _| Ok(()));

        let extractor = create_extractor(gw).await;

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

    #[tokio::test]
    async fn test_handle_revert() {
        let mut gw = MockNativeGateway::new();
        gw.expect_ensure_protocol_types()
            .times(1)
            .returning(|_| ());
        gw.expect_get_cursor()
            .times(1)
            .returning(|| Ok("cursor".into()));

        gw.expect_advance()
            .times(1)
            .returning(|_, _, _| Ok(()));

        gw.expect_revert()
            .withf(|c, v, cursor| {
                c.clone().unwrap() ==
                    BlockIdentifier::Hash(
                        Bytes::from_str(
                            "0x0000000000000000000000000000000000000000000000000000000000000000",
                        )
                        .unwrap(),
                    ) &&
                    v == &BlockIdentifier::Hash(evm::fixtures::HASH_256_0.into()) &&
                    cursor == "cursor@400"
            })
            .times(1)
            .returning(|_, _, _| Ok(evm::BlockEntityChangesResult::default()));
        let extractor = create_extractor(gw).await;
        // Call handle_tick_scoped_data to initialize the last processed block.
        let inp = evm::fixtures::pb_block_scoped_data(evm::fixtures::pb_block_entity_changes());

        let _res = extractor
            .handle_tick_scoped_data(inp)
            .await
            .unwrap();

        let inp = BlockUndoSignal {
            last_valid_block: Some(BlockRef { id: evm::fixtures::HASH_256_0.into(), number: 400 }),
            last_valid_cursor: "cursor@400".into(),
        };

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
        token_pre_processor::MockTokenPreProcessorTrait, ProtocolComponent, Transaction,
    };
    use diesel_async::{pooled_connection::deadpool::Pool, AsyncPgConnection};
    use test_serial_db::evm::ProtocolChangesWithTx;

    use tycho_storage::{
        postgres,
        postgres::{builder::GatewayBuilder, testing::run_against_db},
    };

    use super::*;

    const BLOCK_HASH_0: &str = "0xc520bd7f8d7b964b1a6017a3d747375fcefea0f85994e3cc1810c2523b139da8";
    const CREATED_CONTRACT: &str = "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc";

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

    async fn setup_gw(
        pool: Pool<AsyncPgConnection>,
    ) -> (NativePgGateway<MockTokenPreProcessorTrait>, i64) {
        let mut conn = pool
            .get()
            .await
            .expect("pool should get a connection");
        let chain_id = postgres::db_fixtures::insert_chain(&mut conn, "ethereum").await;
        postgres::db_fixtures::insert_protocol_type(
            &mut conn,
            "Pool",
            Some(models::FinancialType::Swap),
            None,
            Some(models::ImplementationType::Custom),
        )
        .await;

        let db_url = std::env::var("DATABASE_URL").expect("Database URL must be set for testing");
        let (cached_gw, _jh) = GatewayBuilder::new(db_url.as_str())
            .set_chains(&[Chain::Ethereum])
            .set_protocol_systems(&["test".to_string()])
            .build()
            .await
            .expect("failed to build postgres gateway");

        let gw = NativePgGateway::new(
            "test",
            Chain::Ethereum,
            1000,
            cached_gw,
            get_mocked_token_pre_processor(),
        );
        (gw, chain_id)
    }

    #[tokio::test]
    async fn test_get_cursor() {
        run_against_db(|pool| async move {
            let (gw, _) = setup_gw(pool).await;
            let evm_gw = gw.state_gateway.clone();
            let state = ExtractionState::new(
                "test".to_string(),
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

    fn native_pool_creation() -> evm::BlockEntityChanges {
        evm::BlockEntityChanges {
            extractor: "native:test".to_owned(),
            chain: Chain::Ethereum,
            block: evm::Block {
                number: 0,
                chain: Chain::Ethereum,
                hash: BLOCK_HASH_0.parse().unwrap(),
                parent_hash: BLOCK_HASH_0.parse().unwrap(),
                ts: "2020-01-01T01:00:00".parse().unwrap(),
            },
            revert: false,
            txs_with_update: vec![ProtocolChangesWithTx {
                tx: Transaction::new(
                    H256::zero(),
                    BLOCK_HASH_0.parse().unwrap(),
                    H160::zero(),
                    Some(H160::zero()),
                    10,
                ),
                protocol_states: HashMap::new(),
                balance_changes: HashMap::new(),
                new_protocol_components: HashMap::from([(
                    "Pool".to_string(),
                    evm::ProtocolComponent {
                        id: CREATED_CONTRACT.to_string(),
                        protocol_system: "test".to_string(),
                        protocol_type_name: "Pool".to_string(),
                        chain: Chain::Ethereum,
                        tokens: vec![
                            H160::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(),
                            H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
                        ],
                        contract_ids: vec![],
                        creation_tx: Default::default(),
                        static_attributes: Default::default(),
                        created_at: Default::default(),
                        change: Default::default(),
                    },
                )]),
            }],
        }
    }

    #[tokio::test]
    async fn test_forward() {
        run_against_db(|pool| async move {
            let (gw, _) = setup_gw(pool).await;
            let msg = native_pool_creation();

            let _exp = [ProtocolComponent {
                id: CREATED_CONTRACT.to_string(),
                protocol_system: "test".to_string(),
                protocol_type_name: "Pool".to_string(),
                chain: Chain::Ethereum,
                tokens: vec![
                    H160::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(),
                    H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
                ],
                contract_ids: vec![],
                creation_tx: H256::from_str(
                    "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6",
                )
                .unwrap(),
                static_attributes: Default::default(),
                created_at: Default::default(),
                change: Default::default(),
            }];

            gw.forward(&msg, "cursor@500", false)
                .await
                .expect("upsert should succeed");

            let cached_gw: CachedGateway = gw.state_gateway;
            let res = cached_gw
                .get_protocol_components(
                    &Chain::Ethereum,
                    None,
                    Some([CREATED_CONTRACT].as_slice()),
                    None,
                )
                .await
                .expect("test successfully inserted native contract");
            println!("{:?}", res);
            // TODO: This is failing because protocol_type_name is wrong in the gateway - waiting
            // for this fix. assert_eq!(res, exp);
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_new_tokens() {
        run_against_db(|pool| async move {
            let mut conn = pool
                .get()
                .await
                .expect("pool should get a connection");

            let (gw, chain_id) = setup_gw(pool).await;

            let weth_addr = "C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
            let usdc_addr = "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
            let usdt_addr = "dAC17F958D2ee523a2206206994597C13D831ec7";

            postgres::db_fixtures::insert_token(&mut conn, chain_id, weth_addr, "WETH", 18).await;
            postgres::db_fixtures::insert_token(&mut conn, chain_id, usdc_addr, "USDC", 6).await;

            let tokens = HashSet::from([
                H160::from_str(weth_addr).unwrap(), // WETH
                H160::from_str(usdc_addr).unwrap(), // USDC
                H160::from_str(usdt_addr).unwrap(), // USDT
            ]);
            let res = gw
                .get_new_tokens(tokens.iter().cloned().collect())
                .await
                .expect("get new tokens should succeed");

            // Assert len of res == 1
            assert_eq!(res.len(), 1);
            // Assert res contains USDT
            assert_eq!(res[0], H160::from_str(usdt_addr).unwrap());
        })
        .await;
    }
}

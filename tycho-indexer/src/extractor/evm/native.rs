use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
};

use async_trait::async_trait;
use chrono::NaiveDateTime;
use ethers::types::{H160, H256, U256};
use mockall::automock;
use prost::Message;

use token_analyzer::TokenFinder;
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, trace, warn};

use tycho_core::{
    models::{
        self,
        protocol::{ComponentBalance, ProtocolComponentState},
        token::CurrencyToken,
        Address, Chain, ChangeType, ExtractionState, ExtractorIdentity, ProtocolType, TxHash,
    },
    storage::{ChainGateway, ExtractionStateGateway, ProtocolGateway, StorageError},
    Bytes,
};
use tycho_storage::postgres::cache::CachedGateway;

use crate::{
    extractor::{
        evm::{
            self,
            chain_state::ChainState,
            protocol_cache::{ProtocolDataCache, ProtocolMemoryCache},
            Block,
        },
        revert_buffer::RevertBuffer,
        BlockUpdateWithCursor, ExtractionError, Extractor, ExtractorMsg,
    },
    pb::{
        sf::substreams::rpc::v2::{BlockScopedData, BlockUndoSignal, ModulesProgress},
        tycho::evm::v1::BlockEntityChanges,
    },
};

use super::{token_pre_processor::TokenPreProcessorTrait, utils::format_duration};

pub struct Inner {
    cursor: Vec<u8>,
    last_processed_block: Option<Block>,
    /// Used to give more informative logs
    last_report_ts: NaiveDateTime,
    last_report_block_number: u64,
}

pub struct NativeContractExtractor<G, T> {
    gateway: G,
    name: String,
    chain: Chain,
    chain_state: ChainState,
    protocol_system: String,
    token_pre_processor: T,
    protocol_cache: ProtocolMemoryCache,
    inner: Arc<Mutex<Inner>>,
    protocol_types: HashMap<String, ProtocolType>,
    /// Allows to attach some custom logic, e.g. to fix encoding bugs without resync.
    post_processor: Option<fn(evm::BlockEntityChanges) -> evm::BlockEntityChanges>,
    /// The number of blocks behind the current block to be considered as syncing.
    sync_threshold: u64,
    revert_buffer: Mutex<RevertBuffer<BlockUpdateWithCursor<evm::BlockEntityChanges>>>,
}

pub struct NativePgGateway {
    name: String,
    chain: Chain,
    sync_batch_size: usize,
    state_gateway: CachedGateway,
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

    async fn get_protocol_states<'a>(
        &self,
        component_ids: &[&'a str],
    ) -> Result<Vec<ProtocolComponentState>, StorageError>;

    async fn get_components_balances<'a>(
        &self,
        component_ids: &[&'a str],
    ) -> Result<HashMap<String, HashMap<Bytes, ComponentBalance>>, StorageError>;
}

impl NativePgGateway {
    pub fn new(
        name: &str,
        chain: Chain,
        sync_batch_size: usize,
        state_gateway: CachedGateway,
    ) -> Self {
        Self { name: name.to_owned(), chain, sync_batch_size, state_gateway }
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

    async fn forward(
        &self,
        changes: &evm::BlockEntityChanges,
        new_cursor: &str,
        syncing: bool,
    ) -> Result<(), StorageError> {
        self.state_gateway
            .start_transaction(&(&changes.block).into())
            .await;
        if !changes.new_tokens.is_empty() {
            let new_tokens = changes
                .new_tokens
                .values()
                .cloned()
                .collect::<Vec<_>>();
            debug!(new_tokens=?new_tokens.iter().map(|t| &t.address).collect::<Vec<_>>(), "NewTokens");
            self.state_gateway
                .add_tokens(&new_tokens)
                .await?;
        }

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

        if !new_protocol_components.is_empty() {
            debug!(
                protocol_components = ?new_protocol_components
                    .iter()
                    .map(|pc| &pc.id)
                    .collect::<Vec<_>>(),
                "NewProtocolComponents"
            );
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
impl NativeGateway for NativePgGateway {
    async fn get_cursor(&self) -> Result<Vec<u8>, StorageError> {
        self.get_last_cursor().await
    }

    async fn ensure_protocol_types(&self, new_protocol_types: &[ProtocolType]) {
        self.state_gateway
            .add_protocol_types(new_protocol_types)
            .await
            .expect("Couldn't insert protocol types");
    }

    #[instrument(skip_all)]
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

    async fn get_protocol_states<'a>(
        &self,
        component_ids: &[&'a str],
    ) -> Result<Vec<ProtocolComponentState>, StorageError> {
        self.state_gateway
            .get_protocol_states(&self.chain, None, None, Some(component_ids), false)
            .await
    }

    async fn get_components_balances<'a>(
        &self,
        component_ids: &[&'a str],
    ) -> Result<HashMap<String, HashMap<Bytes, ComponentBalance>>, StorageError> {
        self.state_gateway
            .get_balances(&self.chain, Some(component_ids), None)
            .await
    }
}

impl<G, T> NativeContractExtractor<G, T>
where
    G: NativeGateway,
    T: TokenPreProcessorTrait,
{
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        name: &str,
        chain: Chain,
        chain_state: ChainState,
        gateway: G,
        protocol_types: HashMap<String, ProtocolType>,
        protocol_system: String,
        protocol_cache: ProtocolMemoryCache,
        token_pre_processor: T,
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
                    protocol_cache,
                    token_pre_processor,
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
                    protocol_cache,
                    token_pre_processor,
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

    #[instrument(skip_all, fields(chain = % self.chain, name = % self.name, block_number = % msg.block.number))]
    #[allow(clippy::mutable_key_type)]
    async fn handle_tvl_changes(
        &self,
        msg: &mut evm::BlockEntityChangesResult,
    ) -> Result<(), ExtractionError> {
        trace!("Calculating tvl changes");
        if msg.component_balances.is_empty() {
            return Ok(());
        }
        let component_ids = msg
            .component_balances
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let components = self
            .protocol_cache
            .get_protocol_components(self.protocol_system.as_str(), &component_ids)
            .await?;
        let balance_request = components
            .values()
            .flat_map(|pc| pc.tokens.iter().map(|t| (&pc.id, t)))
            .collect::<Vec<_>>();
        // Merge stored balances with new ones
        let balances = {
            let rb = self.revert_buffer.lock().await;
            let mut balances = self
                .get_balances(&rb, &balance_request)
                .await?;
            // we assume the retrieved balances contain all tokens of the component
            // here, doing this merge the other way around would not be safe.
            balances
                .iter_mut()
                .for_each(|(k, bal)| {
                    bal.extend(
                        msg.component_balances
                            .get(k)
                            .cloned()
                            .unwrap_or_else(HashMap::new)
                            .into_iter(),
                    )
                });
            balances
        };
        // collect token decimals and prices to calculate tvl in the next step
        // most of this data should be in the cache.
        let addresses = balances
            .values()
            .flat_map(|b| b.keys())
            .map(|addr| Bytes::from(addr.as_bytes()))
            .collect::<Vec<_>>();
        let prices = self
            .protocol_cache
            .get_token_prices(&addresses)
            .await?
            .into_iter()
            .zip(addresses.iter())
            .filter_map(|(price, address)| {
                if let Some(p) = price {
                    Some((address.clone(), p))
                } else {
                    trace!(?address, "Missing token price!");
                    None
                }
            })
            .collect::<HashMap<_, _>>();
        // calculate new tvl values
        let tvl_updates = balances
            .iter()
            .map(|(cid, bal)| {
                let component_tvl: f64 = bal
                    .iter()
                    .filter_map(|(addr, bal)| {
                        let addr = Bytes::from(addr.as_bytes());
                        let price = *prices.get(&addr)?;
                        let tvl = bal.balance_float / price;
                        Some(tvl)
                    })
                    .sum();
                (cid.clone(), component_tvl)
            })
            .collect::<HashMap<_, _>>();

        msg.component_tvl = tvl_updates;

        Ok(())
    }

    /// Returns balances at the tip of the revert buffer.
    ///
    /// Will return the requested balances at the tip of the revert buffer. Might need
    /// to go to storage to retrieve balances that are not stored within the buffer.
    async fn get_balances(
        &self,
        revert_buffer: &RevertBuffer<BlockUpdateWithCursor<evm::BlockEntityChanges>>,
        reverted_balances_keys: &[(&String, &Bytes)],
    ) -> Result<HashMap<String, HashMap<H160, evm::ComponentBalance>>, ExtractionError> {
        // First search in the buffer
        let (buffered_balances, missing_balances_keys) =
            revert_buffer.lookup_balances(reverted_balances_keys);

        let missing_balances_map: HashMap<String, Vec<Bytes>> = missing_balances_keys
            .into_iter()
            .fold(HashMap::new(), |mut map, (c_id, token)| {
                map.entry(c_id).or_default().push(token);
                map
            });

        trace!(?missing_balances_map, "Missing balance keys after buffer lookup");

        // Then get the missing balances from db
        let missing_balances: HashMap<String, HashMap<Bytes, ComponentBalance>> = self
            .gateway
            .get_components_balances(
                &missing_balances_map
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<&str>>(),
            )
            .await?;

        let empty = HashMap::<Bytes, ComponentBalance>::new();

        let combined_balances: HashMap<
            String,
            HashMap<H160, crate::extractor::evm::ComponentBalance>,
        > = missing_balances_map
            .iter()
            .map(|(id, tokens)| {
                let balances_for_id = missing_balances
                    .get(id)
                    .unwrap_or(&empty);
                let filtered_balances: HashMap<_, _> = tokens
                    .iter()
                    .map(|token| {
                        let balance = balances_for_id
                            .get(token)
                            .cloned()
                            .unwrap_or_else(|| ComponentBalance {
                                token: token.clone(),
                                new_balance: Bytes::from(H256::zero()),
                                balance_float: 0.0,
                                modify_tx: H256::zero().into(),
                                component_id: id.to_string(),
                            });
                        (token.clone(), balance)
                    })
                    .collect();
                (id.clone(), filtered_balances)
            })
            .chain(buffered_balances)
            .map(|(id, balances)| {
                (
                    id,
                    balances
                        .into_iter()
                        .map(|(token, value)| {
                            (
                                H160::from(token),
                                crate::extractor::evm::ComponentBalance::from(&value),
                            )
                        })
                        .collect::<HashMap<_, _>>(),
                )
            })
            .fold(HashMap::new(), |mut acc, (c_id, b_changes)| {
                acc.entry(c_id)
                    .or_default()
                    .extend(b_changes);
                acc
            });
        Ok(combined_balances)
    }

    /// Constructs any newly witnessed currency tokens in this block.
    ///
    /// Fetches token metadata such as symbol and decimals, then proceeds to analyze
    /// the token to add additional metadata such as gas usage any transfer fees etc.
    async fn construct_currency_tokens(
        &self,
        msg: &evm::BlockEntityChanges,
    ) -> Result<HashMap<Address, CurrencyToken>, StorageError> {
        let new_token_addresses = msg
            .protocol_components()
            .into_iter()
            .flat_map(|pc| pc.tokens.clone().into_iter())
            .map(|addr| Bytes::from(addr.as_bytes()))
            .collect::<Vec<_>>();

        // Separate between known and unkown tokens
        let is_token_known = self
            .protocol_cache
            .has_token(&new_token_addresses)
            .await;
        let (unknown_tokens, known_tokens) = new_token_addresses
            .into_iter()
            .zip(is_token_known.into_iter())
            .partition::<Vec<_>, _>(|(_, known)| !*known);
        let known_tokens = known_tokens
            .into_iter()
            .map(|(addr, _)| addr)
            .collect::<Vec<_>>();
        let unkown_tokens_h160 = unknown_tokens
            .into_iter()
            .map(|(addr, _)| H160::from(addr))
            .collect::<Vec<_>>();

        let balance_map: HashMap<H160, (H160, U256)> = msg
            .txs_with_update
            .iter()
            .flat_map(|tx_changes| {
                tx_changes
                    .balance_changes
                    .values()
                    .flat_map(|balance_changes| {
                        balance_changes
                            .values()
                            .filter_map(|bc| match H160::from_str(bc.component_id.as_str()) {
                                Ok(address) => {
                                    Some((bc.token, (address, U256::from_big_endian(&bc.balance))))
                                }
                                Err(e) => {
                                    warn!("Error parsing component_id to H160: {}", e);
                                    None
                                }
                            })
                    })
            })
            .collect();
        let tf = TokenFinder::new(balance_map);
        let existing_tokens = self
            .protocol_cache
            .get_tokens(&known_tokens)
            .await?
            .into_iter()
            .flatten()
            .map(|t| (t.address.clone(), t));
        let new_tokens: HashMap<Address, CurrencyToken> = self
            .token_pre_processor
            .get_tokens(
                unkown_tokens_h160,
                Arc::new(tf),
                web3::types::BlockNumber::Number(msg.block.number.into()),
            )
            .await
            .iter()
            .map(|t| (Bytes::from(t.address.as_bytes()), t.into()))
            .chain(existing_tokens)
            .collect();
        Ok(new_tokens)
    }
}

#[async_trait]
impl<G, T> Extractor for NativeContractExtractor<G, T>
where
    G: NativeGateway,
    T: TokenPreProcessorTrait,
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

    #[instrument(skip_all, fields(block_number))]
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
            inp.final_block_height,
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

        let mut msg =
            if let Some(post_process_f) = self.post_processor { post_process_f(msg) } else { msg };

        msg.new_tokens = self
            .construct_currency_tokens(&msg)
            .await?;
        self.protocol_cache
            .add_tokens(msg.new_tokens.values().cloned())
            .await?;
        self.protocol_cache
            .add_components(
                msg.protocol_components()
                    .iter()
                    .map(Into::into),
            )
            .await?;

        trace!(?msg, "Processing message");

        // Depending on how Substreams handle them, this condition could be problematic for single
        // block finality blockchains.
        let is_syncing = inp.final_block_height >= msg.block.number;
        {
            // keep revert buffer guard within a limited scope

            let mut revert_buffer = self.revert_buffer.lock().await;
            revert_buffer
                .insert_block(BlockUpdateWithCursor::new(msg.clone(), inp.cursor.clone()))
                .map_err(ExtractionError::Storage)?;

            for msg in revert_buffer
                .drain_new_finalized_blocks(inp.final_block_height)
                .map_err(ExtractionError::Storage)?
            {
                self.gateway
                    .advance(msg.block_update(), msg.cursor(), is_syncing)
                    .await?;
            }
        }

        self.update_last_processed_block(msg.block)
            .await;

        self.report_progress(msg.block).await;

        self.update_cursor(inp.cursor).await;

        let mut changes = msg.aggregate_updates()?;
        self.handle_tvl_changes(&mut changes)
            .await?;
        if !is_syncing {
            debug!(
                new_components = changes.new_protocol_components.len(),
                new_tokens = changes.new_tokens.len(),
                update = changes.state_updates.len(),
                tvl_changes = changes.component_tvl.len(),
                "ProcessedMessage"
            );
        }
        return Ok(Some(Arc::new(changes)));
    }

    // Clippy thinks that tuple with Bytes are a mutable type.
    #[instrument(skip_all, fields(target_hash, target_number))]
    #[allow(clippy::mutable_key_type)]
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

        tracing::Span::current().record("target_hash", format!("{:x}", block_hash));
        tracing::Span::current().record("target_number", block_ref.number);

        let mut revert_buffer = self.revert_buffer.lock().await;

        // Purge the buffer
        let reverted_state = revert_buffer
            .purge(block_hash.into())
            .map_err(|e| ExtractionError::RevertBufferError(e.to_string()))?;

        // Handle created and deleted components
        let (reverted_components_creations, reverted_components_deletions) =
            reverted_state.iter().fold(
                (HashMap::new(), HashMap::new()),
                |(mut reverted_creations, mut reverted_deletions), block_msg| {
                    block_msg
                        .block_update()
                        .txs_with_update
                        .iter()
                        .for_each(|update| {
                            update
                                .new_protocol_components
                                .iter()
                                .for_each(|(id, new_component)| {
                                    /*
                                    For each component, only the oldest creation/deletion needs to be reverted. For example, if a component is created then deleted within the reverted
                                    range of blocks, we only want to remove it (so undo its creation).
                                    As here we go through the reverted state from the oldest to the newest, we just insert the first time we meet a component and ignore it if we meet it again after.
                                    */
                                    if !reverted_deletions.contains_key(id) &&
                                        !reverted_creations.contains_key(id)
                                    {
                                        match new_component.change {
                                            ChangeType::Update => {}
                                            ChangeType::Deletion => {
                                                let mut reverted_deletion = new_component.clone();
                                                reverted_deletion.change = ChangeType::Creation;
                                                reverted_deletions
                                                    .insert(id.clone(), reverted_deletion);
                                            }
                                            ChangeType::Creation => {
                                                let mut reverted_creation = new_component.clone();
                                                reverted_creation.change = ChangeType::Deletion;
                                                reverted_creations
                                                    .insert(id.clone(), reverted_creation);
                                            }
                                        }
                                    }
                                });
                        });
                    (reverted_creations, reverted_deletions)
                },
            );

        trace!("Reverted components creations {:?}", &reverted_components_creations);
        // TODO: For these components we need to fetch the whole state (so get it from the db and
        // apply buffer update)
        trace!("Reverted components deletions {:?}", &reverted_components_deletions);

        // Handle reverted state
        let reverted_state_keys: HashSet<_> = reverted_state
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
                            .filter(|(c_id, _)| !reverted_components_creations.contains_key(*c_id))
                            .flat_map(|(c_id, delta)| {
                                delta
                                    .updated_attributes
                                    .keys()
                                    .chain(delta.deleted_attributes.iter())
                                    .map(move |key| (c_id, key))
                            })
                    })
            })
            .collect();

        let reverted_state_keys_vec = reverted_state_keys
            .into_iter()
            .collect::<Vec<_>>();

        trace!("Reverted state keys {:?}", &reverted_state_keys_vec);

        // Fetch previous values for every reverted states
        // First search in the buffer
        let (buffered_state, missing) =
            revert_buffer.lookup_protocol_state(&reverted_state_keys_vec);

        // Then for every missing previous values in the buffer, get the data from our db
        let missing_map: HashMap<String, Vec<String>> =
            missing
                .into_iter()
                .fold(HashMap::new(), |mut acc, (c_id, key)| {
                    acc.entry(c_id).or_default().push(key);
                    acc
                });

        trace!("Missing state keys after buffer lookup {:?}", &missing_map);

        let missing_components_states = self
            .gateway
            .get_protocol_states(
                &missing_map
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<&str>>(),
            )
            .await
            .map_err(ExtractionError::Storage)?;

        // Then merge the two and cast it to the expected struct
        let missing_components_states_map = missing_map
            .into_iter()
            .map(|(component_id, keys)| {
                missing_components_states
                    .iter()
                    .find(|comp| comp.component_id == component_id)
                    .map(|state| (state.clone(), keys))
                    .ok_or(ExtractionError::Storage(StorageError::NotFound(
                        "Component".to_owned(),
                        component_id.to_string(),
                    )))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut not_found: HashMap<_, HashSet<_>> = HashMap::new();
        let mut db_states: HashMap<(String, String), Bytes> = HashMap::new();

        for (state, keys) in missing_components_states_map {
            for key in keys {
                if let Some(value) = state.attributes.get(&key) {
                    db_states.insert((state.component_id.clone(), key.clone()), value.clone());
                } else {
                    not_found
                        .entry(state.component_id.clone())
                        .or_default()
                        .insert(key);
                }
            }
        }

        let empty = HashSet::<String>::new();

        let state_updates: HashMap<String, evm::ProtocolStateDelta> = db_states
            .into_iter()
            .chain(buffered_state)
            .fold(HashMap::new(), |mut acc, ((c_id, key), value)| {
                acc.entry(c_id.clone())
                    .or_insert_with(|| evm::ProtocolStateDelta {
                        component_id: c_id.clone(),
                        updated_attributes: HashMap::new(),
                        deleted_attributes: not_found
                            .get(&c_id)
                            .unwrap_or(&empty)
                            .clone(),
                    })
                    .updated_attributes
                    .insert(key.clone(), value);
                acc
            });

        // Handle token balance changes
        let reverted_balances_keys: HashSet<(&String, Bytes)> = reverted_state
            .iter()
            .flat_map(|block_msg| {
                block_msg
                    .block_update()
                    .txs_with_update
                    .iter()
                    .flat_map(|update| {
                        update
                            .balance_changes
                            .iter()
                            .filter(|(c_id, _)| !reverted_components_creations.contains_key(*c_id))
                            .flat_map(|(id, balance_change)| {
                                balance_change
                                    .iter()
                                    .map(move |(token, _)| (id, Bytes::from(token.as_bytes())))
                            })
                    })
            })
            .collect();

        let reverted_balances_keys_vec = reverted_balances_keys
            .iter()
            .map(|(id, token)| (*id, token))
            .collect::<Vec<_>>();

        trace!("Reverted balance keys {:?}", &reverted_balances_keys_vec);

        let combined_balances = self
            .get_balances(&revert_buffer, &reverted_balances_keys_vec)
            .await?;

        let revert_message = evm::BlockEntityChangesResult {
            extractor: self.name.clone(),
            chain: self.chain,
            block: revert_buffer
                .get_most_recent_block()
                .expect("Couldn't find most recent block in buffer during revert")
                .into(),
            finalized_block_height: reverted_state[0]
                .block_update
                .finalized_block_height,
            revert: true,
            state_updates,
            new_tokens: HashMap::new(),
            new_protocol_components: reverted_components_deletions,
            deleted_protocol_components: reverted_components_creations,
            component_balances: combined_balances,
            component_tvl: HashMap::new(),
        };

        debug!("Succesfully retrieved all previous states during revert!");

        self.update_cursor(inp.last_valid_cursor)
            .await;

        Ok(Some(Arc::new(revert_message)))
    }

    async fn handle_progress(&self, _inp: ModulesProgress) -> Result<(), ExtractionError> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        extractor::evm::token_pre_processor::MockTokenPreProcessorTrait, testing::MockGateway,
    };

    const EXTRACTOR_NAME: &str = "TestExtractor";
    const TEST_PROTOCOL: &str = "TestProtocol";

    async fn create_extractor(
        gw: MockNativeGateway,
    ) -> NativeContractExtractor<MockNativeGateway, MockTokenPreProcessorTrait> {
        let protocol_types = HashMap::from([("WeightedPool".to_string(), ProtocolType::default())]);
        let protocol_cache = ProtocolMemoryCache::new(
            Chain::Ethereum,
            chrono::Duration::seconds(900),
            Arc::new(MockGateway::new()),
        );
        let mut preprocessor = MockTokenPreProcessorTrait::new();
        preprocessor
            .expect_get_tokens()
            .returning(|_, _, _| Vec::new());
        NativeContractExtractor::new(
            EXTRACTOR_NAME,
            Chain::Ethereum,
            ChainState::default(),
            gw,
            protocol_types,
            TEST_PROTOCOL.to_string(),
            protocol_cache,
            preprocessor,
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

        extractor
            .handle_tick_scoped_data(evm::fixtures::pb_block_scoped_data(
                BlockEntityChanges {
                    block: Some(evm::fixtures::pb_blocks(1)),
                    changes: vec![crate::pb::tycho::evm::v1::TransactionEntityChanges {
                        tx: Some(evm::fixtures::pb_transactions(1, 1)),
                        entity_changes: vec![],
                        component_changes: vec![],
                        balance_changes: vec![],
                    }],
                },
                Some(format!("cursor@{}", 1).as_str()),
                Some(1),
            ))
            .await
            .map(|o| o.map(|_| ()))
            .unwrap()
            .unwrap();

        extractor
            .handle_tick_scoped_data(evm::fixtures::pb_block_scoped_data(
                BlockEntityChanges {
                    block: Some(evm::fixtures::pb_blocks(2)),
                    changes: vec![crate::pb::tycho::evm::v1::TransactionEntityChanges {
                        tx: Some(evm::fixtures::pb_transactions(2, 1)),
                        entity_changes: vec![],
                        component_changes: vec![],
                        balance_changes: vec![],
                    }],
                },
                Some(format!("cursor@{}", 2).as_str()),
                Some(2),
            ))
            .await
            .map(|o| o.map(|_| ()))
            .unwrap()
            .unwrap();

        assert_eq!(extractor.get_cursor().await, "cursor@2");
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

        let inp = evm::fixtures::pb_block_scoped_data((), None, None);
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
    use diesel_async::{pooled_connection::deadpool::Pool, AsyncPgConnection};
    use ethers::abi::AbiEncode;
    use futures03::{stream, StreamExt};

    use test_serial_db::evm::ProtocolChangesWithTx;
    use tycho_core::models::{FinancialType, ImplementationType};
    use tycho_storage::postgres::{
        self, builder::GatewayBuilder, db_fixtures, db_fixtures::yesterday_midnight,
        testing::run_against_db,
    };

    use crate::{
        extractor::evm::{
            token_pre_processor::MockTokenPreProcessorTrait, ProtocolComponent, Transaction,
        },
        pb::sf::substreams::v1::BlockRef,
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
            evm::ERC20Token::new(
                H160::from_str("0x6b175474e89094c44da98b954eedeac495271d0f")
                    .expect("Invalid H160 address"),
                "DAI".to_string(),
                18,
                0,
                vec![],
                Default::default(),
                100,
            ),
            evm::ERC20Token::new(
                H160::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7")
                    .expect("Invalid H160 address"),
                "USDT".to_string(),
                6,
                0,
                vec![],
                Default::default(),
                100,
            ),
        ];
        mock_processor
            .expect_get_tokens()
            .returning(move |_, _, _| new_tokens.clone());

        mock_processor
    }

    async fn setup_gw(pool: Pool<AsyncPgConnection>) -> (NativePgGateway, i64) {
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

        let gw = NativePgGateway::new("test", Chain::Ethereum, 1000, cached_gw);
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
            finalized_block_height: 0,
            revert: false,
            new_tokens: HashMap::from([
                (
                    Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                    CurrencyToken::new(
                        &Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                        "USDC",
                        6,
                        0,
                        &[],
                        Default::default(),
                        100,
                    ),
                ),
                (
                    Bytes::from("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
                    CurrencyToken::new(
                        &Bytes::from("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
                        "WETH",
                        18,
                        0,
                        &[],
                        Default::default(),
                        100,
                    ),
                ),
            ]),
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

    #[test_log::test(tokio::test)]
    async fn test_handle_revert() {
        run_against_db(|pool| async move {
            let mut conn = pool
                .get()
                .await
                .expect("pool should get a connection");

            let database_url =
                std::env::var("DATABASE_URL").expect("Database URL must be set for testing");

            db_fixtures::insert_protocol_type(
                &mut conn,
                "pt_1",
                Some(FinancialType::Swap),
                None,
                Some(ImplementationType::Custom),
            )
                .await;

            db_fixtures::insert_protocol_type(
                &mut conn,
                "pt_2",
                Some(FinancialType::Swap),
                None,
                Some(ImplementationType::Custom),
            )
                .await;

            let (cached_gw, _gw_writer_thread) = GatewayBuilder::new(database_url.as_str())
                .set_chains(&[Chain::Ethereum])
                .set_protocol_systems(&["native_protocol_system".to_string()])
                .build()
                .await
                .unwrap();

            let gw = NativePgGateway::new(
                "native_name",
                Chain::Ethereum,
                0,
                cached_gw.clone(),
            );

            let protocol_types = HashMap::from([
                ("pt_1".to_string(), ProtocolType::default()),
                ("pt_2".to_string(), ProtocolType::default()),
            ]);
            let protocol_cache = ProtocolMemoryCache::new(
                Chain::Ethereum,
                chrono::Duration::seconds(900),
                Arc::new(cached_gw),
            );
            let extractor = NativeContractExtractor::new(
                "native_name",
                Chain::Ethereum,
                ChainState::default(),
                gw,
                protocol_types,
                "native_protocol_system".to_string(),
                protocol_cache,
                get_mocked_token_pre_processor(),
                None,
                5,
            )
                .await
                .expect("Failed to create extractor");

            // Send a sequence of block scoped data.
            stream::iter(get_inp_sequence())
                .for_each(|inp| async {
                    extractor
                        .handle_tick_scoped_data(inp)
                        .await
                        .unwrap();
                    dbg!("+++");
                })
                .await;

            let client_msg = extractor
                .handle_revert(BlockUndoSignal {
                    last_valid_block: Some(BlockRef {
                        id: H256::from_low_u64_be(3).encode_hex(),
                        number: 3,
                    }),
                    last_valid_cursor: "cursor@3".into(),
                })
                .await
                .unwrap()
                .unwrap();


            let res = client_msg
                .as_any()
                .downcast_ref::<evm::BlockEntityChangesResult>()
                .expect("not good type");
            let base_ts = yesterday_midnight().timestamp();
            let block_entity_changes_result = evm::BlockEntityChangesResult {
                extractor: "native_name".to_string(),
                chain: Chain::Ethereum,
                block: Block {
                    number: 3,
                    hash: H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000003").unwrap(),
                    parent_hash: H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000002").unwrap(),
                    chain: Chain::Ethereum,
                    ts: NaiveDateTime::from_timestamp_opt(base_ts + 3000, 0).unwrap(),
                },
                finalized_block_height: 1,
                revert: true,
                state_updates: HashMap::from([
                    ("pc_1".to_string(), evm::ProtocolStateDelta {
                        component_id: "pc_1".to_string(),
                        updated_attributes: HashMap::from([
                            ("attr_2".to_string(), Bytes::from("0x0000000000000002")),
                            ("attr_1".to_string(), Bytes::from("0x00000000000003e8")),
                        ]),
                        deleted_attributes: HashSet::new(),
                    }),
                ]),
                new_tokens: HashMap::new(),
                new_protocol_components: HashMap::from([
                    ("pc_2".to_string(), ProtocolComponent {
                        id: "pc_2".to_string(),
                        protocol_system: "native_protocol_system".to_string(),
                        protocol_type_name: "pt_1".to_string(),
                        chain: Chain::Ethereum,
                        tokens: vec![
                            H160::from_str("0xdac17f958d2ee523a2206206994597c13d831ec7").unwrap(),
                            H160::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
                        ],
                        contract_ids: vec![],
                        static_attributes: HashMap::new(),
                        change: ChangeType::Creation,
                        creation_tx: H256::from_str("0x000000000000000000000000000000000000000000000000000000000000c351").unwrap(),
                        created_at: NaiveDateTime::from_timestamp_opt(base_ts + 5000, 0).unwrap(),
                    }),
                ]),
                deleted_protocol_components: HashMap::from([
                    ("pc_3".to_string(), ProtocolComponent {
                        id: "pc_3".to_string(),
                        protocol_system: "native_protocol_system".to_string(),
                        protocol_type_name: "pt_2".to_string(),
                        chain: Chain::Ethereum,
                        tokens: vec![
                            H160::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap(),
                            H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                        ],
                        contract_ids: vec![],
                        static_attributes: HashMap::new(),
                        change: ChangeType::Deletion,
                        creation_tx: H256::from_str("0x0000000000000000000000000000000000000000000000000000000000009c41").unwrap(),
                        created_at: NaiveDateTime::from_timestamp_opt(base_ts + 4000, 0).unwrap(),
                    }),
                ]),
                component_balances: HashMap::from([
                    ("pc_1".to_string(), HashMap::from([
                        (H160::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(), evm::ComponentBalance {
                            token: H160::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
                            balance: Bytes::from("0x00000001"),
                            balance_float: 1.0,
                            modify_tx: H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                            component_id: "pc_1".to_string(),
                        }),
                        (H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(), evm::ComponentBalance {
                            token: H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                            balance: Bytes::from("0x000003e8"),
                            balance_float: 1000.0,
                            modify_tx: H256::from_str("0x0000000000000000000000000000000000000000000000000000000000007531").unwrap(),
                            component_id: "pc_1".to_string(),
                        }),
                    ])),
                ]),
                component_tvl: HashMap::new(),
            };

            assert_eq!(
                res,
                &block_entity_changes_result
            );
        })
            .await;
    }

    fn get_inp_sequence(
    ) -> impl Iterator<Item = crate::pb::sf::substreams::rpc::v2::BlockScopedData> {
        vec![
            evm::fixtures::pb_block_scoped_data(
                evm::fixtures::pb_block_entity_changes(1),
                Some(format!("cursor@{}", 1).as_str()),
                Some(1), // Syncing (buffered)
            ),
            evm::fixtures::pb_block_scoped_data(
                evm::fixtures::pb_block_entity_changes(2),
                Some(format!("cursor@{}", 2).as_str()),
                Some(1), // Buffered
            ),
            evm::fixtures::pb_block_scoped_data(
                evm::fixtures::pb_block_entity_changes(3),
                Some(format!("cursor@{}", 3).as_str()),
                Some(1), // Buffered
            ),
            evm::fixtures::pb_block_scoped_data(
                evm::fixtures::pb_block_entity_changes(4),
                Some(format!("cursor@{}", 4).as_str()),
                Some(1), // Buffered
            ),
            evm::fixtures::pb_block_scoped_data(
                evm::fixtures::pb_block_entity_changes(5),
                Some(format!("cursor@{}", 5).as_str()),
                Some(3), // Buffered + flush 1 + 2
            ),
        ]
        .into_iter()
    }
}

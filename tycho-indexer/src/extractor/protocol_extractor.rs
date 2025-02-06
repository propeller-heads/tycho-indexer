use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
};

use async_trait::async_trait;
use chrono::NaiveDateTime;
use metrics::gauge;
use mockall::automock;
use prost::Message;
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument, trace, warn};

use tycho_core::{
    models::{
        blockchain::{Block, BlockAggregatedChanges, BlockTag},
        contract::{Account, AccountDelta},
        protocol::{
            ComponentBalance, ProtocolComponent, ProtocolComponentState,
            ProtocolComponentStateDelta,
        },
        token::{CurrencyToken, TokenOwnerStore},
        Address, Balance, BlockHash, Chain, ChangeType, ExtractionState, ExtractorIdentity,
        ProtocolType, TxHash,
    },
    storage::{
        ChainGateway, ContractStateGateway, ExtractionStateGateway, ProtocolGateway, StorageError,
    },
    traits::TokenPreProcessor,
    Bytes,
};
use tycho_storage::postgres::cache::CachedGateway;

#[allow(deprecated)]
use crate::{
    extractor::{
        chain_state::ChainState,
        models::{BlockChanges, BlockContractChanges, BlockEntityChanges},
        protobuf_deserialisation::TryFromMessage,
        protocol_cache::{ProtocolDataCache, ProtocolMemoryCache},
        reorg_buffer::ReorgBuffer,
        BlockUpdateWithCursor, ExtractionError, Extractor, ExtractorMsg,
    },
    pb,
    pb::sf::substreams::rpc::v2::{BlockScopedData, BlockUndoSignal, ModulesProgress},
};

pub struct Inner {
    cursor: Vec<u8>,
    last_processed_block: Option<Block>,
    /// Used to give more informative logs
    last_report_ts: NaiveDateTime,
    last_report_block_number: u64,
    first_message_processed: bool,
}

pub struct ProtocolExtractor<G, T> {
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
    post_processor: Option<fn(BlockChanges) -> BlockChanges>,
    reorg_buffer: Mutex<ReorgBuffer<BlockUpdateWithCursor<BlockChanges>>>,
}

impl<G, T> ProtocolExtractor<G, T>
where
    G: ExtractorGateway,
    T: TokenPreProcessor,
{
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        gateway: G,
        name: &str,
        chain: Chain,
        chain_state: ChainState,
        protocol_system: String,
        protocol_cache: ProtocolMemoryCache,
        protocol_types: HashMap<String, ProtocolType>,
        token_pre_processor: T,
        post_processor: Option<fn(BlockChanges) -> BlockChanges>,
    ) -> Result<Self, ExtractionError> {
        // check if this extractor has state
        let res = match gateway.get_cursor().await {
            Err(StorageError::NotFound(_, _)) => {
                warn!(?name, ?chain, "No cursor found, starting from the beginning");
                ProtocolExtractor {
                    gateway,
                    name: name.to_string(),
                    chain,
                    chain_state,
                    protocol_system,
                    token_pre_processor,
                    protocol_cache,
                    inner: Arc::new(Mutex::new(Inner {
                        cursor: vec![],
                        last_processed_block: None,
                        last_report_ts: chrono::Utc::now().naive_utc(),
                        last_report_block_number: 0,
                        first_message_processed: false,
                    })),
                    protocol_types,
                    post_processor,
                    reorg_buffer: Mutex::new(ReorgBuffer::new()),
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
                ProtocolExtractor {
                    gateway,
                    name: name.to_string(),
                    chain,
                    chain_state,
                    inner: Arc::new(Mutex::new(Inner {
                        cursor,
                        last_processed_block: None,
                        last_report_ts: chrono::Local::now().naive_utc(),
                        last_report_block_number: 0,
                        first_message_processed: false,
                    })),
                    protocol_system,
                    protocol_cache,
                    token_pre_processor,
                    protocol_types,
                    post_processor,
                    reorg_buffer: Mutex::new(ReorgBuffer::new()),
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
        state.first_message_processed = true;
    }

    async fn is_first_message(&self) -> bool {
        !self
            .inner
            .lock()
            .await
            .first_message_processed
    }

    async fn update_last_processed_block(&self, block: Block) {
        let mut state = self.inner.lock().await;
        state.last_processed_block = Some(block);
    }

    /// Reports sync progress if a minute has passed since the last report.
    async fn maybe_report_progress(&self, block: &Block) {
        let mut state = self.inner.lock().await;
        let now = chrono::Local::now().naive_utc();
        let time_passed = now
            .signed_duration_since(state.last_report_ts)
            .num_seconds();
        if time_passed >= 60 {
            let current_block = self.chain_state.current_block().await;
            let distance_to_current = current_block - block.number;
            let blocks_processed = block.number - state.last_report_block_number;
            let blocks_per_minute = blocks_processed as f64 * 60.0 / time_passed as f64;
            let time_remaining =
                chrono::Duration::minutes((distance_to_current as f64 / blocks_per_minute) as i64);
            let hours = time_remaining.num_hours();
            let minutes = (time_remaining.num_minutes()) % 60;
            info!(
                extractor_id = self.name,
                blocks_per_minute = format!("{blocks_per_minute:.2}"),
                blocks_processed,
                height = block.number,
                estimated_current = current_block,
                time_remaining = format!("{:02}h{:02}m", hours, minutes),
                name = "SyncProgress"
            );
            state.last_report_ts = now;
            state.last_report_block_number = block.number;
            let extractor_id = self.get_id();
            gauge!(
                "extractor_sync_remaining_minutes",
                "chain" => extractor_id.chain.to_string(),
                "extractor" => extractor_id.name.to_string(),
            )
            .set(time_remaining.num_minutes() as f64);
        }
    }

    #[instrument(skip_all, fields(chain = % self.chain, name = % self.name, block_number = % msg.block.number))]
    async fn handle_tvl_changes(
        &self,
        msg: &mut BlockAggregatedChanges,
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
            let rb = self.reorg_buffer.lock().await;
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
            .flat_map(|b| b.clone().into_keys())
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
                        let price = *prices.get(addr)?;
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

    /// Returns balances at the tip of the reorg buffer.
    ///
    /// Will return the requested balances at the tip of the reorg buffer. Might need
    /// to go to storage to retrieve balances that are not stored within the buffer.
    async fn get_balances(
        &self,
        reorg_buffer: &ReorgBuffer<BlockUpdateWithCursor<BlockChanges>>,
        reverted_balances_keys: &[(&String, &Bytes)],
    ) -> Result<HashMap<String, HashMap<Bytes, ComponentBalance>>, ExtractionError> {
        // First search in the buffer
        let (buffered_balances, missing_balances_keys) =
            reorg_buffer.lookup_balances(reverted_balances_keys);

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

        let combined_balances: HashMap<String, HashMap<Bytes, ComponentBalance>> =
            missing_balances_map
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
                                    balance: Bytes::new(),
                                    balance_float: 0.0,
                                    modify_tx: Bytes::new(),
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

    async fn construct_currency_tokens(
        &self,
        msg: &BlockChanges,
    ) -> Result<HashMap<Address, CurrencyToken>, StorageError> {
        let new_token_addresses = msg
            .protocol_components()
            .into_iter()
            .flat_map(|pc| pc.tokens.clone().into_iter())
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
        let unknown_tokens = unknown_tokens
            .into_iter()
            .map(|(addr, _)| addr)
            .collect::<Vec<_>>();
        // Construct unkown tokens using rpc
        let balance_map: HashMap<Address, (Address, Balance)> = msg
            .txs_with_update
            .iter()
            .flat_map(|tx| {
                tx.protocol_components
                    .iter()
                    // Filtering to keep only components with ChangeType::Creation
                    .filter(|(_, c_change)| c_change.change == ChangeType::Creation)
                    .filter_map(|(c_id, change)| {
                        tx.state_updates
                            .get(&change.id)
                            .and_then(|state| {
                                state
                                    .updated_attributes
                                    .get("balance_owner")
                                    .cloned()
                            })
                            .or_else(|| {
                                change
                                    .contract_addresses
                                    // TODO: Currently, it's assumed that the pool is always the
                                    // first contract in the
                                    // protocol component. This approach is a temporary
                                    // workaround and needs to be revisited for a more robust
                                    // solution.
                                    .first()
                                    .cloned()
                                    .map(Into::into)
                                    .or_else(|| Bytes::from_str(&change.id).ok())
                            })
                            .map(|owner| (c_id, owner))
                    })
                    .filter_map(|(c_id, addr)| {
                        tx.balance_changes
                            .get(c_id)
                            .map(|balances| {
                                balances
                                    .iter()
                                    // We currently only keep the latest created pool for
                                    // it's token
                                    .map(move |(token, balance)| {
                                        (token.clone(), (addr.clone(), balance.balance.clone()))
                                    })
                            })
                    })
                    .flatten()
            })
            .collect::<HashMap<_, _>>();
        let tf = TokenOwnerStore::new(balance_map);
        let existing_tokens = self
            .protocol_cache
            .get_tokens(&known_tokens)
            .await?
            .into_iter()
            .flatten()
            .map(|t| (t.address.clone(), t));
        let new_tokens: HashMap<Address, CurrencyToken> = self
            .token_pre_processor
            .get_tokens(unknown_tokens, Arc::new(tf), BlockTag::Number(msg.block.number))
            .await
            .into_iter()
            .map(|t| (t.address.clone(), t))
            .chain(existing_tokens)
            .collect();
        Ok(new_tokens)
    }
}

#[async_trait]
impl<G, T> Extractor for ProtocolExtractor<G, T>
where
    G: ExtractorGateway,
    T: TokenPreProcessor,
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
            .clone()
    }

    #[allow(deprecated)]
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

        // Backwards Compatibility:
        // Check if message_type ends with BlockAccountChanges or BlockEntityChanges. If it does,
        // then we need to decode as the corresponding message type, then convert it to BlockChanges
        let msg = match data.type_url.as_str() {
            url if url.ends_with("BlockChanges") => {
                let raw_msg = pb::tycho::evm::v1::BlockChanges::decode(data.value.as_slice())?;
                trace!(?raw_msg, "Received BlockChanges message");
                BlockChanges::try_from_message((
                    raw_msg,
                    &self.name,
                    self.chain,
                    &self.protocol_system,
                    &self.protocol_types,
                    inp.final_block_height,
                ))
            }
            url if url.ends_with("BlockContractChanges") => {
                let raw_msg =
                    pb::tycho::evm::v1::BlockContractChanges::decode(data.value.as_slice())?;
                trace!(?raw_msg, "Received BlockContractChanges message");
                BlockContractChanges::try_from_message((
                    raw_msg,
                    &self.name,
                    self.chain,
                    self.protocol_system.clone(),
                    &self.protocol_types,
                    inp.final_block_height,
                ))
                .map(Into::into)
            }
            url if url.ends_with("BlockEntityChanges") => {
                let raw_msg =
                    pb::tycho::evm::v1::BlockEntityChanges::decode(data.value.as_slice())?;
                trace!(?raw_msg, "Received BlockEntityChanges message");
                BlockEntityChanges::try_from_message((
                    raw_msg,
                    &self.name,
                    self.chain,
                    &self.protocol_system,
                    &self.protocol_types,
                    inp.final_block_height,
                ))
                .map(Into::into)
            }
            _ => return Err(ExtractionError::DecodeError("Unknown message type".into())),
        };

        let msg = match msg {
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
            .add_components(msg.protocol_components())
            .await?;

        trace!(?msg, "Processing message");

        // Depending on how Substreams handle them, this condition could be problematic for single
        // block finality blockchains.
        let is_syncing = inp.final_block_height >= msg.block.number;
        {
            // keep reorg buffer guard within a limited scope
            let mut reorg_buffer = self.reorg_buffer.lock().await;
            reorg_buffer
                .insert_block(BlockUpdateWithCursor::new(msg.clone(), inp.cursor.clone()))
                .map_err(ExtractionError::Storage)?;

            let mut msgs = reorg_buffer
                .drain_new_finalized_blocks(inp.final_block_height)
                .map_err(ExtractionError::Storage)?
                .into_iter()
                .peekable();

            while let Some(msg) = msgs.next() {
                // Force a database commit if we're not syncing and this is the last block to be
                // sent. Otherwise, wait to accumulate a full batch before
                // committing.
                let force_db_commit = if is_syncing { false } else { msgs.peek().is_none() };

                self.gateway
                    .advance(msg.block_update(), msg.cursor(), force_db_commit)
                    .await?;
            }
        }

        self.update_last_processed_block(msg.block.clone())
            .await;

        if is_syncing {
            self.maybe_report_progress(&msg.block)
                .await;
        }

        self.update_cursor(inp.cursor).await;

        let mut changes = msg.aggregate_updates()?;
        self.handle_tvl_changes(&mut changes)
            .await?;

        if !is_syncing {
            debug!(
                new_components = changes.new_protocol_components.len(),
                new_tokens = changes.new_tokens.len(),
                account_update = changes.account_deltas.len(),
                state_update = changes.state_deltas.len(),
                tvl_changes = changes.component_tvl.len(),
                "ProcessedMessage"
            );
        }
        return Ok(Some(Arc::new(changes)));
    }

    #[instrument(skip_all, fields(target_hash, target_number))]
    #[allow(clippy::mutable_key_type)] // Clippy thinks that tuple with Bytes are a mutable type.
    async fn handle_revert(
        &self,
        inp: BlockUndoSignal,
    ) -> Result<Option<ExtractorMsg>, ExtractionError> {
        let block_ref = inp
            .last_valid_block
            .ok_or_else(|| ExtractionError::DecodeError("Revert without block ref".into()))?;

        let block_hash = Bytes::from_str(&block_ref.id).map_err(|err| {
            ExtractionError::DecodeError(format!(
                "Failed to parse {} as block hash: {}",
                block_ref.id, err
            ))
        })?;

        tracing::Span::current().record("target_hash", format!("{:x}", block_hash));
        tracing::Span::current().record("target_number", block_ref.number);

        // It can happen that the first received message is an undo signal. In that case we expect
        // to not have the target block in our buffer, therefore we early return and ignore this
        // revert.
        if self.is_first_message().await {
            info!("First message received was a revert. Nothing to revert in the buffer, ignoring it...");
            self.update_cursor(inp.last_valid_cursor)
                .await;
            return Ok(None);
        }

        let mut reorg_buffer = self.reorg_buffer.lock().await;

        // Purge the buffer
        let reverted_state = reorg_buffer
            .purge(block_hash)
            .map_err(|e| ExtractionError::ReorgBufferError(e.to_string()))?;

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
                                .protocol_components
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
        trace!(?reverted_components_creations, "Reverted components creations");
        // TODO: For these reverted deletions we need to fetch the whole state (so get it from the
        //  db and apply buffer update)
        trace!(?reverted_components_deletions, "Reverted components deletions");

        // Handle reverted account state
        let reverted_account_state_keys: HashSet<_> = reverted_state
            .iter()
            .flat_map(|block_msg| {
                block_msg
                    .block_update()
                    .txs_with_update
                    .iter()
                    .flat_map(|update| {
                        update
                            .account_deltas
                            .iter()
                            .filter(|(c_id, _)| {
                                !reverted_components_creations.contains_key(&c_id.to_string())
                            })
                            .flat_map(|(c_id, delta)| {
                                delta
                                    .slots
                                    .keys()
                                    .map(move |key| (c_id, key))
                            })
                    })
            })
            .collect();

        let reverted_account_state_keys_vec = reverted_account_state_keys
            .into_iter()
            .collect::<Vec<_>>();

        trace!(?reverted_account_state_keys_vec, "Reverted account state keys");

        // Fetch previous values for every reverted states
        // First search in the buffer
        let (buffered_state, missing) =
            reorg_buffer.lookup_account_state(&reverted_account_state_keys_vec);

        // Then for every missing previous values in the buffer, get the data from our db
        let missing_map: HashMap<Bytes, Vec<Bytes>> =
            missing
                .into_iter()
                .fold(HashMap::new(), |mut acc, (addr, key)| {
                    acc.entry(addr).or_default().push(key);
                    acc
                });

        trace!(?missing_map, "Missing state keys after buffer lookup");

        let missing_contracts = self
            .gateway
            .get_contracts(
                &missing_map
                    .keys()
                    .cloned()
                    .collect::<Vec<Address>>(),
            )
            .await
            .map_err(ExtractionError::Storage)?;

        // Then merge the two and cast it to the expected struct
        let combined_states = buffered_state
            .into_iter()
            .chain(
                missing_map
                    .iter()
                    .flat_map(|(address, keys)| {
                        let missing_state = missing_contracts
                            .iter()
                            .find(|state| &state.address == address);
                        keys.iter().map(move |key| {
                            match missing_state {
                                Some(state) => {
                                    // If the state is found, attempt to get the value for the key
                                    state.slots.get(key).map_or_else(
                                        // If the value for this key is not found, return empty
                                        // Bytes
                                        || ((state.address.clone(), key.clone()), Bytes::new()),
                                        // If the key is found, return its value
                                        |value| {
                                            ((state.address.clone(), key.clone()), value.clone())
                                        },
                                    )
                                }
                                None => {
                                    // If the whole account state is not found, return empty Bytes
                                    // for the key
                                    ((address.clone(), key.clone()), Bytes::new())
                                }
                            }
                        })
                    }),
            )
            .collect::<Vec<_>>();

        let account_deltas =
            combined_states
                .into_iter()
                .fold(HashMap::new(), |mut acc, ((addr, key), value)| {
                    acc.entry(addr.clone())
                        .or_insert_with(|| AccountDelta {
                            address: addr,
                            chain: self.chain,
                            slots: HashMap::new(),
                            balance: None, //TODO: handle balance changes
                            code: None,    //TODO: handle code changes
                            change: ChangeType::Update,
                        })
                        .slots
                        .insert(key, Some(value));
                    acc
                });

        // Handle reverted protocol state
        let reverted_protocol_state_keys: HashSet<_> = reverted_state
            .iter()
            .flat_map(|block_msg| {
                block_msg
                    .block_update()
                    .txs_with_update
                    .iter()
                    .flat_map(|update| {
                        update
                            .state_updates
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

        let reverted_protocol_state_keys_vec = reverted_protocol_state_keys
            .into_iter()
            .collect::<Vec<_>>();

        trace!("Reverted state keys {:?}", &reverted_protocol_state_keys_vec);

        // Fetch previous values for every reverted states
        // First search in the buffer
        let (buffered_state, missing) =
            reorg_buffer.lookup_protocol_state(&reverted_protocol_state_keys_vec);

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

        let state_deltas: HashMap<String, ProtocolComponentStateDelta> = db_states
            .into_iter()
            .chain(buffered_state)
            .fold(HashMap::new(), |mut acc, ((c_id, key), value)| {
                acc.entry(c_id.clone())
                    .or_insert_with(|| ProtocolComponentStateDelta {
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
                                    .map(move |(token, _)| (id, token.clone()))
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
            .get_balances(&reorg_buffer, &reverted_balances_keys_vec)
            .await?;

        let revert_message = BlockAggregatedChanges {
            extractor: self.name.clone(),
            chain: self.chain,
            block: reorg_buffer
                .get_most_recent_block()
                .expect("Couldn't find most recent block in buffer during revert"),
            finalized_block_height: reverted_state[0]
                .block_update
                .finalized_block_height,
            revert: true,
            state_deltas,
            account_deltas,
            new_tokens: HashMap::new(),
            new_protocol_components: reverted_components_deletions,
            deleted_protocol_components: reverted_components_creations,
            component_balances: combined_balances,
            component_tvl: HashMap::new(),
        };

        debug!("Successfully retrieved all previous states during revert!");

        self.update_cursor(inp.last_valid_cursor)
            .await;

        Ok(Some(Arc::new(revert_message)))
    }

    #[instrument(skip_all)]
    async fn handle_progress(&self, _inp: ModulesProgress) -> Result<(), ExtractionError> {
        todo!()
    }
}
pub struct ExtractorPgGateway {
    name: String,
    chain: Chain,
    db_tx_batch_size: usize,
    state_gateway: CachedGateway,
}

#[automock]
#[async_trait]
pub trait ExtractorGateway: Send + Sync {
    async fn get_cursor(&self) -> Result<Vec<u8>, StorageError>;

    async fn ensure_protocol_types(&self, new_protocol_types: &[ProtocolType]);

    async fn advance(
        &self,
        changes: &BlockChanges,
        new_cursor: &str,
        force_commit: bool,
    ) -> Result<(), StorageError>;

    async fn get_protocol_states<'a>(
        &self,
        component_ids: &[&'a str],
    ) -> Result<Vec<ProtocolComponentState>, StorageError>;

    async fn get_contracts(&self, component_ids: &[Address]) -> Result<Vec<Account>, StorageError>;

    async fn get_components_balances<'a>(
        &self,
        component_ids: &[&'a str],
    ) -> Result<HashMap<String, HashMap<Bytes, ComponentBalance>>, StorageError>;
}

impl ExtractorPgGateway {
    pub fn new(
        name: &str,
        chain: Chain,
        db_tx_batch_size: usize,
        state_gateway: CachedGateway,
    ) -> Self {
        Self { name: name.to_owned(), chain, db_tx_batch_size, state_gateway }
    }

    #[instrument(skip_all)]
    async fn save_cursor(
        &self,
        new_cursor: &str,
        block_hash: BlockHash,
    ) -> Result<(), StorageError> {
        let state = ExtractionState::new(
            self.name.to_string(),
            self.chain,
            None,
            new_cursor.as_bytes(),
            block_hash,
        );
        self.state_gateway
            .save_state(&state)
            .await?;
        Ok(())
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
impl ExtractorGateway for ExtractorPgGateway {
    async fn get_cursor(&self) -> Result<Vec<u8>, StorageError> {
        self.get_last_cursor().await
    }

    async fn ensure_protocol_types(&self, new_protocol_types: &[ProtocolType]) {
        self.state_gateway
            .add_protocol_types(new_protocol_types)
            .await
            .expect("Couldn't insert protocol types");
    }

    async fn advance(
        &self,
        changes: &BlockChanges,
        new_cursor: &str,
        force_commit: bool,
    ) -> Result<(), StorageError> {
        self.state_gateway
            .start_transaction(&changes.block, Some(self.name.as_str()))
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
            .upsert_block(&[changes.block.clone()])
            .await?;

        let mut new_protocol_components: Vec<ProtocolComponent> = vec![];
        let mut state_updates: Vec<(TxHash, ProtocolComponentStateDelta)> = vec![];
        let mut account_changes: Vec<(Bytes, AccountDelta)> = vec![];

        let mut balance_changes: Vec<ComponentBalance> = vec![];
        let mut protocol_tokens: HashSet<Bytes> = HashSet::new();

        for tx_update in changes.txs_with_update.iter() {
            trace!(tx_hash = ?tx_update.tx.hash, "Processing tx");

            // Insert transaction
            self.state_gateway
                .upsert_tx(&[tx_update.tx.clone()])
                .await?;

            let hash: TxHash = tx_update.tx.hash.clone();

            // Map new protocol components
            for (_component_id, new_protocol_component) in tx_update.protocol_components.iter() {
                new_protocol_components.push(new_protocol_component.clone());
                protocol_tokens.extend(new_protocol_component.tokens.clone());
            }

            // Map new account / contracts
            for (_, account_update) in tx_update.account_deltas.iter() {
                if account_update.is_creation() {
                    let new: Account = account_update.ref_into_account(&tx_update.tx);
                    info!(block_number = ?changes.block.number, contract_address = ?new.address, "NewContract");

                    // Insert new accounts
                    self.state_gateway
                        .upsert_contract(&new)
                        .await?;
                } else if account_update.is_update() {
                    account_changes.push((tx_update.tx.hash.clone(), account_update.clone()));
                } else {
                    // log error
                    error!(?account_update, "Invalid account update type");
                }
            }

            // Map protocol state changes
            state_updates.extend(
                tx_update
                    .state_updates
                    .values()
                    .map(|state_change| (hash.clone(), state_change.clone())),
            );

            // Map balance changes
            balance_changes.extend(
                tx_update
                    .balance_changes
                    .clone()
                    .into_iter()
                    .flat_map(|(_, tokens)| tokens.into_values()),
            );
        }

        // Insert new protocol components
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

        // Insert changed accounts
        if !account_changes.is_empty() {
            self.state_gateway
                .update_contracts(account_changes.as_slice())
                .await?;
        }

        // Insert protocol state changes
        if !state_updates.is_empty() {
            self.state_gateway
                .update_protocol_states(state_updates.as_slice())
                .await?;
        }

        // Insert balance changes
        if !balance_changes.is_empty() {
            self.state_gateway
                .add_component_balances(balance_changes.as_slice())
                .await?;
        }

        self.save_cursor(new_cursor, changes.block.hash.clone())
            .await?;

        let batch_size = if force_commit { 0 } else { self.db_tx_batch_size };
        self.state_gateway
            .commit_transaction(batch_size)
            .await
    }

    async fn get_protocol_states<'a>(
        &self,
        component_ids: &[&'a str],
    ) -> Result<Vec<ProtocolComponentState>, StorageError> {
        self.state_gateway
            .get_protocol_states(&self.chain, None, None, Some(component_ids), false, None)
            .await
            .map(|state_data| state_data.entity)
    }

    async fn get_contracts(&self, component_ids: &[Address]) -> Result<Vec<Account>, StorageError> {
        self.state_gateway
            .get_contracts(&self.chain, Some(component_ids), None, true, None)
            .await
            .map(|contract_data| contract_data.entity)
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

#[cfg(test)]
mod test {
    use float_eq::assert_float_eq;
    use mockall::mock;

    use super::*;

    use crate::{pb::testing::fixtures as pb_fixtures, testing::MockGateway};

    use tycho_core::{
        models::blockchain::{Transaction, TxWithChanges},
        traits::TokenOwnerFinding,
    };

    mock! {
        pub TokenPreProcessor {}

        #[async_trait::async_trait]
        impl TokenPreProcessor for TokenPreProcessor {
            async fn get_tokens(
                &self,
                addresses: Vec<Bytes>,
                token_finder: Arc<dyn TokenOwnerFinding>,
                block: BlockTag,
            ) -> Vec<CurrencyToken>;
        }
    }

    const EXTRACTOR_NAME: &str = "TestExtractor";
    const TEST_PROTOCOL: &str = "TestProtocol";
    async fn create_extractor(
        gw: MockExtractorGateway,
    ) -> ProtocolExtractor<MockExtractorGateway, MockTokenPreProcessor> {
        let protocol_types = HashMap::from([("pt_1".to_string(), ProtocolType::default())]);
        let protocol_cache = ProtocolMemoryCache::new(
            Chain::Ethereum,
            chrono::Duration::seconds(900),
            Arc::new(MockGateway::new()),
        );
        let mut preprocessor = MockTokenPreProcessor::new();
        preprocessor
            .expect_get_tokens()
            .returning(|_, _, _| Vec::new());
        ProtocolExtractor::new(
            gw,
            EXTRACTOR_NAME,
            Chain::Ethereum,
            ChainState::default(),
            TEST_PROTOCOL.to_string(),
            protocol_cache,
            protocol_types,
            preprocessor,
            None,
        )
        .await
        .expect("Failed to create extractor")
    }

    #[tokio::test]
    async fn test_get_cursor() {
        let mut gw = MockExtractorGateway::new();
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
        let mut gw = MockExtractorGateway::new();
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
            .handle_tick_scoped_data(pb_fixtures::pb_block_scoped_data(
                pb::tycho::evm::v1::BlockChanges {
                    block: Some(pb_fixtures::pb_blocks(1)),
                    changes: vec![],
                },
                Some(format!("cursor@{}", 1).as_str()),
                Some(1),
            ))
            .await
            .map(|o| o.map(|_| ()))
            .unwrap()
            .unwrap();

        extractor
            .handle_tick_scoped_data(pb_fixtures::pb_block_scoped_data(
                pb::tycho::evm::v1::BlockChanges {
                    block: Some(pb_fixtures::pb_blocks(2)),
                    changes: vec![],
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
    async fn test_handle_tick_scoped_data_old_native_msg() {
        let mut gw = MockExtractorGateway::new();
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
            .handle_tick_scoped_data(pb_fixtures::pb_block_scoped_data(
                pb::tycho::evm::v1::BlockEntityChanges {
                    block: Some(pb_fixtures::pb_blocks(1)),
                    changes: vec![crate::pb::tycho::evm::v1::TransactionEntityChanges {
                        tx: Some(pb_fixtures::pb_transactions(1, 1)),
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
            .handle_tick_scoped_data(pb_fixtures::pb_block_scoped_data(
                pb::tycho::evm::v1::BlockEntityChanges {
                    block: Some(pb_fixtures::pb_blocks(2)),
                    changes: vec![crate::pb::tycho::evm::v1::TransactionEntityChanges {
                        tx: Some(pb_fixtures::pb_transactions(2, 1)),
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
    async fn test_handle_tick_scoped_data_old_vm_msg() {
        let mut gw = MockExtractorGateway::new();
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
            .handle_tick_scoped_data(pb_fixtures::pb_block_scoped_data(
                pb::tycho::evm::v1::BlockContractChanges {
                    block: Some(pb_fixtures::pb_blocks(1)),
                    changes: vec![crate::pb::tycho::evm::v1::TransactionContractChanges {
                        tx: Some(pb_fixtures::pb_transactions(1, 1)),
                        contract_changes: vec![],
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
            .handle_tick_scoped_data(pb_fixtures::pb_block_scoped_data(
                pb::tycho::evm::v1::BlockContractChanges {
                    block: Some(pb_fixtures::pb_blocks(2)),
                    changes: vec![crate::pb::tycho::evm::v1::TransactionContractChanges {
                        tx: Some(pb_fixtures::pb_transactions(2, 1)),
                        contract_changes: vec![],
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
        let mut gw = MockExtractorGateway::new();
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

        let inp = pb_fixtures::pb_block_scoped_data((), None, None);
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

    fn token_prices() -> HashMap<Bytes, f64> {
        HashMap::from([
            (
                Bytes::from("0x0000000000000000000000000000000000000001"),
                344101538937875300000000000.0,
            ),
            (Bytes::from("0x0000000000000000000000000000000000000002"), 2980881444.0),
        ])
    }

    #[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 2))]
    async fn test_construct_tokens() {
        let msg = BlockChanges::new(
            "ex".to_string(),
            Chain::Ethereum,
            Block::default(),
            0,
            false,
            vec![TxWithChanges {
                protocol_components: HashMap::from([(
                    "TestComponent".to_string(),
                    ProtocolComponent {
                        id: "TestComponent".to_string(),
                        tokens: vec![
                            "0x0000000000000000000000000000000000000001"
                                .parse()
                                .unwrap(),
                            "0x0000000000000000000000000000000000000003"
                                .parse()
                                .unwrap(),
                        ],
                        change: ChangeType::Creation,
                        ..Default::default()
                    },
                )]),
                account_deltas: HashMap::new(),
                state_updates: HashMap::from([(
                    "TestComponent".to_string(),
                    ProtocolComponentStateDelta::new(
                        "TestComponent",
                        HashMap::from([(
                            "balance_owner".to_string(),
                            Bytes::from_str("0000000000000000000000000000000000000b0b").unwrap(),
                        )]),
                        HashSet::new(),
                    ),
                )]),
                balance_changes: HashMap::from([(
                    "TestComponent".to_string(),
                    HashMap::from([
                        (
                            Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap(),
                            ComponentBalance {
                                token: Bytes::from_str("0x0000000000000000000000000000000000000001")
                                    .unwrap(),
                                balance: Bytes::from(1000_i32.to_le_bytes()),
                                balance_float: 36522027799.0,
                                modify_tx: Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000011121314").unwrap(),
                                component_id: "TestComponent".to_string(),
                            },
                        ),
                        (
                            Bytes::from_str("0x0000000000000000000000000000000000000003").unwrap(),
                            ComponentBalance {
                                token: Bytes::from_str("0x0000000000000000000000000000000000000003")
                                    .unwrap(),
                                balance: Bytes::from(10000_i32.to_le_bytes()),
                                balance_float: 36522027799.0,
                                modify_tx: Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000011121314").unwrap(),
                                component_id: "TestComponent".to_string(),
                            },
                        ),
                    ]),
                )]),
                account_balance_changes: HashMap::new(),
                tx: Transaction::default(),
            }],
        );

        let protocol_gw = MockGateway::new();
        let protocol_cache = ProtocolMemoryCache::new(
            Chain::Ethereum,
            chrono::Duration::seconds(1),
            Arc::new(protocol_gw),
        );
        let t1 = CurrencyToken::new(
            &Bytes::from("0x0000000000000000000000000000000000000001"),
            "TOK1",
            18,
            0,
            &[],
            Chain::Ethereum,
            100,
        );
        protocol_cache
            .add_tokens([t1.clone()])
            .await
            .expect("adding tokens failed");

        let mut preprocessor = MockTokenPreProcessor::new();
        let t3 = CurrencyToken::new(
            &Bytes::from_str("0000000000000000000000000000000000000003").unwrap(),
            "TOK3",
            18,
            0,
            &[],
            Chain::Ethereum,
            100,
        );
        let ret = vec![t3.clone()];
        preprocessor
            .expect_get_tokens()
            .return_once(|_, balance_owner_store, _| {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        assert_eq!(
                            balance_owner_store
                                .find_owner(
                                    Bytes::from_str("0000000000000000000000000000000000000003")
                                        .unwrap(),
                                    Bytes::from(1000_i32.to_le_bytes()),
                                )
                                .await
                                .unwrap()
                                .unwrap(),
                            (
                                Bytes::from_str("0000000000000000000000000000000000000b0b")
                                    .unwrap(),
                                Bytes::from(10000_i32.to_le_bytes())
                            )
                        );
                        assert_eq!(
                            balance_owner_store
                                .find_owner(
                                    Bytes::from_str("0000000000000000000000000000000000000001")
                                        .unwrap(),
                                    Bytes::from(1000_i32.to_le_bytes()),
                                )
                                .await
                                .unwrap()
                                .unwrap(),
                            (
                                Bytes::from_str("0000000000000000000000000000000000000b0b")
                                    .unwrap(),
                                Bytes::from(1000_i32.to_le_bytes())
                            )
                        );
                    });
                });
                ret
            });
        let mut extractor_gw = MockExtractorGateway::new();
        extractor_gw
            .expect_ensure_protocol_types()
            .times(1)
            .returning(|_| ());
        extractor_gw
            .expect_get_cursor()
            .times(1)
            .returning(|| Ok("cursor".into()));
        let extractor = ProtocolExtractor::new(
            extractor_gw,
            EXTRACTOR_NAME,
            Chain::Ethereum,
            ChainState::default(),
            TEST_PROTOCOL.to_string(),
            protocol_cache,
            HashMap::from([("pt_1".to_string(), ProtocolType::default())]),
            preprocessor,
            None,
        )
        .await
        .expect("Extractor init failed");
        let exp = HashMap::from([(t1.address.clone(), t1), (t3.address.clone(), t3)]);

        let res = extractor
            .construct_currency_tokens(&msg)
            .await
            .expect("construct_currency_tokens failed");

        assert_eq!(res, exp);
    }

    #[test_log::test(tokio::test)]
    async fn test_handle_tvl_changes() {
        let mut msg = BlockAggregatedChanges {
            component_balances: HashMap::from([(
                "comp1".to_string(),
                HashMap::from([(
                    Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap(),
                    ComponentBalance {
                        token: Bytes::from_str("0x0000000000000000000000000000000000000001")
                            .unwrap(),
                        balance: Bytes::from(
                            "0x00000000000000000000000000000000000000000000003635c9adc5dea00000",
                        ),
                        balance_float: 11_304_207_639.4e18,
                        modify_tx: Bytes::zero(32),
                        component_id: "comp1".to_string(),
                    },
                ),
                    (
                        Bytes::from_str("0x0000000000000000000000000000000000000002").unwrap(),
                        ComponentBalance {
                            token: Bytes::from_str("0x0000000000000000000000000000000000000002")
                                .unwrap(),
                            balance: Bytes::from(
                                "0x00000000000000000000000000000000000000000000003635c9adc5dea00000",
                            ),
                            balance_float: 100_000e6,
                            modify_tx: Bytes::zero(32),
                            component_id: "comp1".to_string(),
                        },
                    )

                ]),
            )]),
            ..Default::default()
        };

        let mut protocol_gw = MockGateway::new();
        protocol_gw
            .expect_get_token_prices()
            .return_once(|_| Box::pin(async { Ok(token_prices()) }));
        let protocol_cache = ProtocolMemoryCache::new(
            Chain::Ethereum,
            chrono::Duration::seconds(1),
            Arc::new(protocol_gw),
        );
        protocol_cache
            .add_components([ProtocolComponent::new(
                "comp1",
                "system1",
                "pt_1",
                Chain::Ethereum,
                vec![
                    Bytes::from("0x0000000000000000000000000000000000000001"),
                    Bytes::from("0x0000000000000000000000000000000000000002"),
                ],
                Vec::new(),
                HashMap::new(),
                ChangeType::Creation,
                Bytes::default(),
                NaiveDateTime::default(),
            )])
            .await
            .expect("adding components failed");
        protocol_cache
            .add_tokens([
                CurrencyToken::new(
                    &Bytes::from("0x0000000000000000000000000000000000000001"),
                    "PEPE",
                    18,
                    0,
                    &[],
                    Chain::Ethereum,
                    100,
                ),
                CurrencyToken::new(
                    &Bytes::from("0x0000000000000000000000000000000000000002"),
                    "USDC",
                    6,
                    0,
                    &[],
                    Chain::Ethereum,
                    100,
                ),
            ])
            .await
            .expect("adding tokens failed");

        let preprocessor = MockTokenPreProcessor::new();
        let mut extractor_gw = MockExtractorGateway::new();
        extractor_gw
            .expect_ensure_protocol_types()
            .times(1)
            .returning(|_| ());
        extractor_gw
            .expect_get_cursor()
            .times(1)
            .returning(|| Ok("cursor".into()));
        extractor_gw
            .expect_get_components_balances()
            .return_once(|_| Ok(HashMap::new()));

        let extractor = ProtocolExtractor::new(
            extractor_gw,
            "vm_name",
            Chain::Ethereum,
            ChainState::default(),
            "system1".to_string(),
            protocol_cache,
            HashMap::from([("pt_1".to_string(), ProtocolType::default())]),
            preprocessor,
            None,
        )
        .await
        .expect("extractor init failed");

        let exp_tvl = 66.39849612683253;

        extractor
            .handle_tvl_changes(&mut msg)
            .await
            .expect("handle_tvl_call failed");
        let res = msg
            .component_tvl
            .get("comp1")
            .expect("comp1 tvl not present");

        assert_eq!(msg.component_tvl.len(), 1);
        assert_float_eq!(*res, exp_tvl, rmax <= 0.000_001);
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
    use mockall::mock;

    use diesel_async::{pooled_connection::deadpool::Pool, AsyncPgConnection};
    use futures03::{stream, StreamExt};

    use super::*;

    use tycho_core::{
        models::{
            blockchain::TxWithChanges, contract::AccountBalance, ContractId, FinancialType,
            ImplementationType,
        },
        storage::{BlockIdentifier, BlockOrTimestamp},
        traits::TokenOwnerFinding,
    };
    use tycho_storage::postgres::{builder::GatewayBuilder, db_fixtures, testing::run_against_db};

    use crate::{
        extractor::models::fixtures,
        pb::{sf::substreams::v1::BlockRef, testing::fixtures as pb_fixtures},
    };

    mock! {
        pub TokenPreProcessor {}

        #[async_trait::async_trait]
        impl TokenPreProcessor for TokenPreProcessor {
            async fn get_tokens(
                &self,
                addresses: Vec<Bytes>,
                token_finder: Arc<dyn TokenOwnerFinding>,
                block: BlockTag,
            ) -> Vec<CurrencyToken>;
        }
    }

    const WETH_ADDRESS: &str = "C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    const USDC_ADDRESS: &str = "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

    // Native contract creation fixtures
    const NATIVE_BLOCK_HASH_0: &str =
        "0xc520bd7f8d7b964b1a6017a3d747375fcefea0f85994e3cc1810c2523b139da8";
    const NATIVE_CREATED_CONTRACT: &str = "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc";

    // VM contract creation fixtures
    const VM_TX_HASH_0: &str = "0x2f6350a292c0fc918afe67cb893744a080dacb507b0cea4cc07437b8aff23cdb";
    const VM_TX_HASH_1: &str = "0x0d9e0da36cf9f305a189965b248fc79c923619801e8ab5ef158d4fd528a291ad";

    // Ambient Contract
    const VM_CONTRACT: [u8; 20] = hex_literal::hex!("aaaaaaaaa24eeeb8d57d431224f73832bc34f688");

    // SETUP
    fn get_mocked_token_pre_processor() -> MockTokenPreProcessor {
        let mut mock_processor = MockTokenPreProcessor::new();
        let new_tokens = vec![
            CurrencyToken::new(
                &Bytes::from_str("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                    .expect("Invalid address"),
                "WETH",
                18,
                0,
                &[],
                Default::default(),
                100,
            ),
            CurrencyToken::new(
                &Bytes::from_str("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                    .expect("Invalid address"),
                "USDC",
                6,
                0,
                &[],
                Default::default(),
                100,
            ),
            CurrencyToken::new(
                &Bytes::from_str("6b175474e89094c44da98b954eedeac495271d0f")
                    .expect("Invalid address"),
                "DAI",
                18,
                0,
                &[],
                Default::default(),
                100,
            ),
            CurrencyToken::new(
                &Bytes::from_str("dAC17F958D2ee523a2206206994597C13D831ec7")
                    .expect("Invalid address"),
                "USDT",
                6,
                0,
                &[],
                Default::default(),
                100,
            ),
        ];
        mock_processor
            .expect_get_tokens()
            .returning(move |_, _, _| new_tokens.clone());

        mock_processor
    }

    async fn setup_gw(
        pool: Pool<AsyncPgConnection>,
        implementation_type: ImplementationType,
    ) -> (ExtractorPgGateway, i64) {
        let mut conn = pool
            .get()
            .await
            .expect("pool should get a connection");
        let chain_id = db_fixtures::insert_chain(&mut conn, "ethereum").await;
        db_fixtures::insert_token(
            &mut conn,
            chain_id,
            "0000000000000000000000000000000000000000",
            "ETH",
            18,
            Some(100),
        )
        .await;

        match implementation_type {
            ImplementationType::Custom => {
                db_fixtures::insert_protocol_type(
                    &mut conn,
                    "pool",
                    Some(FinancialType::Swap),
                    None,
                    Some(ImplementationType::Custom),
                )
                .await;
            }
            ImplementationType::Vm => {
                db_fixtures::insert_protocol_type(&mut conn, "vm:pool", None, None, None).await;
            }
        }

        db_fixtures::insert_token(&mut conn, chain_id, WETH_ADDRESS, "WETH", 18, None).await;
        db_fixtures::insert_token(&mut conn, chain_id, USDC_ADDRESS, "USDC", 6, None).await;

        let db_url = std::env::var("DATABASE_URL").expect("Database URL must be set for testing");
        let (cached_gw, _jh) = GatewayBuilder::new(db_url.as_str())
            .set_chains(&[Chain::Ethereum])
            .set_protocol_systems(&["test".to_string()])
            .build()
            .await
            .expect("failed to build postgres gateway");

        let gw = ExtractorPgGateway::new("test", Chain::Ethereum, 1000, cached_gw);
        (gw, chain_id)
    }

    #[tokio::test]
    async fn test_get_cursor() {
        run_against_db(|pool| async move {
            let (gw, _) = setup_gw(pool, ImplementationType::Vm).await;
            let evm_gw = gw.state_gateway.clone();
            let state = ExtractionState::new(
                "test".to_string(),
                Chain::Ethereum,
                None,
                "cursor@420".as_bytes(),
                Bytes::from_str("88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6")
                    .unwrap(),
            );
            evm_gw
                .start_transaction(&Block::default(), None)
                .await;
            evm_gw
                .upsert_block(&[Block {
                    number: 1,
                    chain: Chain::Ethereum,
                    hash: Bytes::from_str(
                        "88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6",
                    )
                    .unwrap(),
                    parent_hash: Bytes::default(),
                    ts: db_fixtures::yesterday_one_am(),
                }])
                .await
                .expect("block insertion succeeded");
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

    fn native_pool_creation() -> BlockChanges {
        BlockChanges::new_with_tokens(
            "native:test".to_owned(),
            Chain::Ethereum,
            Block::new(
                0,
                Chain::Ethereum,
                NATIVE_BLOCK_HASH_0.parse().unwrap(),
                NATIVE_BLOCK_HASH_0.parse().unwrap(),
                "2020-01-01T01:00:00".parse().unwrap(),
            ),
            0,
            false,
            HashMap::from([
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
            vec![TxWithChanges {
                tx: fixtures::create_transaction(fixtures::HASH_256_0, NATIVE_BLOCK_HASH_0, 10),
                state_updates: HashMap::new(),
                balance_changes: HashMap::new(),
                protocol_components: HashMap::from([(
                    "pool".to_string(),
                    ProtocolComponent {
                        id: NATIVE_CREATED_CONTRACT.to_string(),
                        protocol_system: "test".to_string(),
                        protocol_type_name: "pool".to_string(),
                        chain: Chain::Ethereum,
                        tokens: vec![
                            Bytes::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(),
                            Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
                        ],
                        contract_addresses: vec![],
                        creation_tx: Default::default(),
                        static_attributes: Default::default(),
                        created_at: Default::default(),
                        change: Default::default(),
                    },
                )]),
                account_deltas: HashMap::new(),
                account_balance_changes: HashMap::new(),
            }],
        )
    }

    fn vm_account(at_version: u64) -> Account {
        match at_version {
            0 => Account::new(
                Chain::Ethereum,
                "0xaaaaaaaaa24eeeb8d57d431224f73832bc34f688"
                    .parse()
                    .unwrap(),
                "0xaaaaaaaaa24eeeb8d57d431224f73832bc34f688".to_owned(),
                fixtures::slots([(1, 200)]),
                Bytes::from(1000_u64).lpad(32, 0),
                vec![0, 0, 0, 0].into(),
                "0xe8e77626586f73b955364c7b4bbf0bb7f7685ebd40e852b164633a4acbd3244c"
                    .parse()
                    .unwrap(),
                VM_TX_HASH_1.parse().unwrap(),
                VM_TX_HASH_0.parse().unwrap(),
                Some(VM_TX_HASH_0.parse().unwrap()),
            ),
            _ => panic!("Unkown version"),
        }
    }

    // Creates a BlockChanges object with a VM contract creation and an account update. Based on an
    // Ambient pool creation
    fn vm_creation_and_update() -> BlockChanges {
        let base_token = Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let quote_token = Bytes::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
        let component_id = "ambient_USDC_ETH".to_string();
        BlockChanges::new(
            "vm:ambient".to_owned(),
            Chain::Ethereum,
            Block { hash: Bytes::zero(32), ..Default::default() },
            0,
            false,
            vec![
                TxWithChanges::new(
                    HashMap::from([(
                        component_id.clone(),
                        ProtocolComponent {
                            id: component_id.clone(),
                            protocol_system: "test".to_string(),
                            protocol_type_name: "vm:pool".to_string(),
                            chain: Chain::Ethereum,
                            tokens: vec![base_token.clone(), quote_token],
                            contract_addresses: vec![Bytes::from(VM_CONTRACT)],
                            static_attributes: Default::default(),
                            change: Default::default(),
                            creation_tx: VM_TX_HASH_0.parse().unwrap(),
                            created_at: Default::default(),
                        },
                    )]),
                    [(
                        VM_CONTRACT.into(),
                        AccountDelta::new(
                            Chain::Ethereum,
                            VM_CONTRACT.into(),
                            HashMap::new(),
                            None,
                            Some(vec![0, 0, 0, 0].into()),
                            ChangeType::Creation,
                        ),
                    )]
                    .into_iter()
                    .collect(),
                    HashMap::new(),
                    HashMap::from([(
                        component_id.clone(),
                        HashMap::from([(
                            base_token.clone(),
                            ComponentBalance {
                                token: base_token.clone(),
                                balance: Bytes::from(&[0u8]),
                                balance_float: 10.0,
                                modify_tx: VM_TX_HASH_0.parse().unwrap(),
                                component_id: component_id.clone(),
                            },
                        )]),
                    )]),
                    HashMap::from([(
                        VM_CONTRACT.into(),
                        HashMap::from([(
                            base_token.clone(),
                            AccountBalance {
                                token: base_token.clone(),
                                balance: Bytes::from(&[0u8]),
                                modify_tx: VM_TX_HASH_0.parse().unwrap(),
                                account: VM_CONTRACT.into(),
                            },
                        )]),
                    )]),
                    fixtures::create_transaction(VM_TX_HASH_0, fixtures::HASH_256_0, 1),
                ),
                TxWithChanges::new(
                    HashMap::new(),
                    [(
                        VM_CONTRACT.into(),
                        AccountDelta::new(
                            Chain::Ethereum,
                            VM_CONTRACT.into(),
                            fixtures::optional_slots([(1, 200)]),
                            Some(Bytes::from(1000_u64).lpad(32, 0)),
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
                            base_token.clone(),
                            ComponentBalance {
                                token: base_token.clone(),
                                balance: Bytes::from(&[0u8]),
                                balance_float: 10.0,
                                modify_tx: VM_TX_HASH_1.parse().unwrap(),
                                component_id: component_id.clone(),
                            },
                        )]),
                    )]),
                    HashMap::from([(
                        VM_CONTRACT.into(),
                        HashMap::from([(
                            base_token.clone(),
                            AccountBalance {
                                token: base_token,
                                balance: Bytes::from(&[0u8]),
                                modify_tx: VM_TX_HASH_0.parse().unwrap(),
                                account: VM_CONTRACT.into(),
                            },
                        )]),
                    )]),
                    fixtures::create_transaction(VM_TX_HASH_1, fixtures::HASH_256_0, 2),
                ),
            ],
        )
    }

    // Tests a forward call with a native contract creation and an account update
    // TODO: Fix this test. It was already disabled for native extractors, because of
    // protocol_type_name mismatch
    #[ignore]
    #[tokio::test]
    async fn test_forward_native_protocol() {
        run_against_db(|pool| async move {
            let (gw, _) = setup_gw(pool, ImplementationType::Custom).await;
            let msg = native_pool_creation();

            let _exp = [ProtocolComponent {
                id: NATIVE_CREATED_CONTRACT.to_string(),
                protocol_system: "test".to_string(),
                protocol_type_name: "pool".to_string(),
                chain: Chain::Ethereum,
                tokens: vec![
                    Bytes::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(),
                    Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
                ],
                contract_addresses: vec![],
                creation_tx: Bytes::from_str(
                    "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6",
                )
                .unwrap(),
                static_attributes: Default::default(),
                created_at: Default::default(),
                change: Default::default(),
            }];

            gw.advance(&msg, "cursor@500", false)
                .await
                .expect("upsert should succeed");

            let cached_gw: CachedGateway = gw.state_gateway;
            let res = cached_gw
                .get_protocol_components(
                    &Chain::Ethereum,
                    None,
                    Some([NATIVE_CREATED_CONTRACT].as_slice()),
                    None,
                    None,
                )
                .await
                .expect("test successfully inserted native contract")
                .entity;
            println!("{:?}", res);

            // TODO: This is failing because protocol_type_name is wrong in the gateway - waiting
            // assert_eq!(res, exp);
        })
        .await;
    }

    // Tests processing a new block where a new pool is created and its balances get updated
    #[tokio::test]
    async fn test_forward_vm_protocol() {
        run_against_db(|pool| async move {
            let (gw, _) = setup_gw(pool, ImplementationType::Vm).await;
            let msg = vm_creation_and_update();
            let exp = vm_account(0);

            gw.advance(&msg, "cursor@500", true)
                .await
                .expect("upsert should succeed");

            let cached_gw: CachedGateway = gw.state_gateway;

            let res = cached_gw
                .get_contract(&ContractId::new(Chain::Ethereum, VM_CONTRACT.into()), None, true)
                .await
                .expect("test successfully inserted ambient contract");
            assert_eq!(res, exp);

            let tokens = cached_gw
                .get_tokens(Chain::Ethereum, None, None, None, None)
                .await
                .unwrap()
                .entity;
            assert_eq!(tokens.len(), 3);

            let protocol_components = cached_gw
                .get_protocol_components(&Chain::Ethereum, None, None, None, None)
                .await
                .unwrap()
                .entity;
            assert_eq!(protocol_components.len(), 1);
            assert_eq!(protocol_components[0].creation_tx, Bytes::from(VM_TX_HASH_0));

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
            assert_eq!(component_balances[0].component_id, "ambient_USDC_ETH");
        })
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_handle_native_revert() {
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

            let gw = ExtractorPgGateway::new(
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
            let extractor = ProtocolExtractor::new(
                gw,
                "native_name",
                Chain::Ethereum,
                ChainState::default(),
                "native_protocol_system".to_string(),
                protocol_cache,
                protocol_types,
                get_mocked_token_pre_processor(),
                None,
            )
                .await
                .expect("Failed to create extractor");

            // Send a sequence of block scoped data.
            stream::iter(get_native_inp_sequence())
                .for_each(|inp| async {
                    extractor
                        .handle_tick_scoped_data(inp)
                        .await
                        .unwrap();
                })
                .await;

            let client_msg = extractor
                .handle_revert(BlockUndoSignal {
                    last_valid_block: Some(BlockRef {
                        id: "0x0000000000000000000000000000000000000000000000000000000000000003".to_string(),
                        number: 3,
                    }),
                    last_valid_cursor: "cursor@3".into(),
                })
                .await
                .unwrap()
                .unwrap();


            let res = client_msg
                .as_any()
                .downcast_ref::<BlockAggregatedChanges>()
                .expect("not good type");
            let base_ts = db_fixtures::yesterday_midnight().timestamp();
            let block_entity_changes_result = BlockAggregatedChanges {
                extractor: "native_name".to_string(),
                chain: Chain::Ethereum,
                block: Block::new(
                    3,
                    Chain::Ethereum,
                    Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000003").unwrap(),
                    Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000002").unwrap(),
                    NaiveDateTime::from_timestamp_opt(base_ts + 3000, 0).unwrap(),
                ),
                finalized_block_height: 1,
                revert: true,
                state_deltas: HashMap::from([
                    ("pc_1".to_string(), ProtocolComponentStateDelta {
                        component_id: "pc_1".to_string(),
                        updated_attributes: HashMap::from([
                            ("attr_2".to_string(), Bytes::from(2_u64).lpad(32, 0)),
                            ("attr_1".to_string(), Bytes::from(1000_u64).lpad(32, 0)),
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
                            Bytes::from_str("0xdac17f958d2ee523a2206206994597c13d831ec7").unwrap(),
                            Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
                        ],
                        contract_addresses: vec![],
                        static_attributes: HashMap::new(),
                        change: ChangeType::Creation,
                        creation_tx: Bytes::from_str("0x000000000000000000000000000000000000000000000000000000000000c351").unwrap(),
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
                            Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap(),
                            Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                        ],
                        contract_addresses: vec![],
                        static_attributes: HashMap::new(),
                        change: ChangeType::Deletion,
                        creation_tx: Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000009c41").unwrap(),
                        created_at: NaiveDateTime::from_timestamp_opt(base_ts + 4000, 0).unwrap(),
                    }),
                ]),
                component_balances: HashMap::from([
                    ("pc_1".to_string(), HashMap::from([
                        (Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(), ComponentBalance {
                            token: Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
                            balance: Bytes::from("0x00000001"),
                            balance_float: 1.0,
                            modify_tx: Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                            component_id: "pc_1".to_string(),
                        }),
                        (Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(), ComponentBalance {
                            token: Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                            balance: Bytes::from("0x000003e8"),
                            balance_float: 1000.0,
                            modify_tx: Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000007531").unwrap(),
                            component_id: "pc_1".to_string(),
                        }),
                    ])),
                ]),
                component_tvl: HashMap::new(),
                account_deltas: Default::default(),
            };

            assert_eq!(
                res,
                &block_entity_changes_result
            );
        })
            .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_handle_vm_revert() {
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
                Some(ImplementationType::Vm),
            )
                .await;

            db_fixtures::insert_protocol_type(
                &mut conn,
                "pt_2",
                Some(FinancialType::Swap),
                None,
                Some(ImplementationType::Vm),
            )
                .await;

            let (cached_gw, _gw_writer_thread) = GatewayBuilder::new(database_url.as_str())
                .set_chains(&[Chain::Ethereum])
                .set_protocol_systems(&["vm_protocol_system".to_string()])
                .build()
                .await
                .unwrap();

            let gw = ExtractorPgGateway::new(
                "vm_name",
                Chain::Ethereum,
                0,
                cached_gw.clone()
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
            let preprocessor = get_mocked_token_pre_processor();
            let extractor = ProtocolExtractor::new(
                gw,
                "vm_name",
                Chain::Ethereum,
                ChainState::default(),
                "vm_protocol_system".to_string(),
                protocol_cache,
                protocol_types,
                preprocessor,
                None,
            )
                .await
                .expect("Failed to create extractor");

            // Send a sequence of block scoped data.
            stream::iter(get_vm_inp_sequence())
                .for_each(|inp| async {
                    extractor
                        .handle_tick_scoped_data(inp)
                        .await
                        .unwrap();
                })
                .await;

            let client_msg = extractor
                .handle_revert(BlockUndoSignal {
                    last_valid_block: Some(BlockRef {
                        id: "0x0000000000000000000000000000000000000000000000000000000000000003".to_string(),
                        number: 3,
                    }),
                    last_valid_cursor: "cursor@3".into(),
                })
                .await
                .unwrap()
                .unwrap();

            let res = client_msg
                .as_any()
                .downcast_ref::<BlockAggregatedChanges>()
                .expect("not good type");

            let base_ts = db_fixtures::yesterday_midnight().timestamp();
            let block_account_expected = BlockAggregatedChanges {
                extractor: "vm_name".to_string(),
                chain: Chain::Ethereum,
                block: Block::new(
                    3,
                    Chain::Ethereum,
                    Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000003").unwrap(),
                    Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000002").unwrap(),
                    NaiveDateTime::from_timestamp_opt(base_ts + 3000, 0).unwrap(),
                ),
                finalized_block_height: 1,
                revert: true,
                account_deltas: HashMap::from([
                    (Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap(), AccountDelta {
                        address: Bytes::from_str("0000000000000000000000000000000000000001").unwrap(),
                        chain: Chain::Ethereum,
                        slots: HashMap::from([
                            (Bytes::from("0x03"), Some(Bytes::new())),
                            (Bytes::from("0x01"), Some(Bytes::from("0x01"))),
                        ]),
                        balance: None,
                        code: None,
                        change: ChangeType::Update,
                    }),
                    (Bytes::from_str("0x0000000000000000000000000000000000000002").unwrap(), AccountDelta {
                        address: Bytes::from_str("0000000000000000000000000000000000000002").unwrap(),
                        chain: Chain::Ethereum,
                        slots: HashMap::from([
                            (Bytes::from("0x01"), Some(Bytes::from("0x02"))),
                        ]),
                        balance: None,
                        code: None,
                        change: ChangeType::Update,
                    }),
                ]),
                new_tokens: HashMap::new(),
                new_protocol_components: HashMap::new(),
                deleted_protocol_components: HashMap::from([
                    ("pc_3".to_string(), ProtocolComponent {
                        id: "pc_3".to_string(),
                        protocol_system: "vm_protocol_system".to_string(),
                        protocol_type_name: "pt_1".to_string(),
                        chain: Chain::Ethereum,
                        tokens: vec![
                            Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap(),
                            Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
                        ],
                        contract_addresses: vec![
                            Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap(),
                        ],
                        static_attributes: HashMap::new(),
                        change: ChangeType::Deletion,
                        creation_tx: Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000009c41").unwrap(),
                        created_at: NaiveDateTime::from_timestamp_opt(base_ts + 4000, 0).unwrap(),
                    }),
                ]),
                component_balances: HashMap::from([
                    ("pc_1".to_string(), HashMap::from([
                        (Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(), ComponentBalance {
                            token: Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
                            balance: Bytes::from("0x00000064"),
                            balance_float: 100.0,
                            modify_tx: Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000007532").unwrap(),
                            component_id: "pc_1".to_string(),
                        }),
                        (Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(), ComponentBalance {
                            token: Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                            balance: Bytes::from("0x00000001"),
                            balance_float: 1.0,
                            modify_tx: Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                            component_id: "pc_1".to_string(),
                        }),
                    ])),
                ]),
                component_tvl: HashMap::new(),
                state_deltas: Default::default(),
            };
            assert_eq!(
                res,
                &block_account_expected
            );
        })
            .await;
    }

    fn get_native_inp_sequence(
    ) -> impl Iterator<Item = crate::pb::sf::substreams::rpc::v2::BlockScopedData> {
        vec![
            pb_fixtures::pb_block_scoped_data(
                pb_fixtures::pb_native_block_changes(1),
                Some(format!("cursor@{}", 1).as_str()),
                Some(1), // Syncing (buffered)
            ),
            pb_fixtures::pb_block_scoped_data(
                pb_fixtures::pb_native_block_changes(2),
                Some(format!("cursor@{}", 2).as_str()),
                Some(1), // Buffered
            ),
            pb_fixtures::pb_block_scoped_data(
                pb_fixtures::pb_native_block_changes(3),
                Some(format!("cursor@{}", 3).as_str()),
                Some(1), // Buffered
            ),
            pb_fixtures::pb_block_scoped_data(
                pb_fixtures::pb_native_block_changes(4),
                Some(format!("cursor@{}", 4).as_str()),
                Some(1), // Buffered
            ),
            pb_fixtures::pb_block_scoped_data(
                pb_fixtures::pb_native_block_changes(5),
                Some(format!("cursor@{}", 5).as_str()),
                Some(3), // Buffered + flush 1 + 2
            ),
        ]
        .into_iter()
    }

    fn get_vm_inp_sequence(
    ) -> impl Iterator<Item = crate::pb::sf::substreams::rpc::v2::BlockScopedData> {
        vec![
            pb_fixtures::pb_block_scoped_data(
                pb_fixtures::pb_vm_block_changes(1),
                Some(format!("cursor@{}", 1).as_str()),
                Some(1), // Syncing (buffered)
            ),
            pb_fixtures::pb_block_scoped_data(
                pb_fixtures::pb_vm_block_changes(2),
                Some(format!("cursor@{}", 2).as_str()),
                Some(1), // Buffered
            ),
            pb_fixtures::pb_block_scoped_data(
                pb_fixtures::pb_vm_block_changes(3),
                Some(format!("cursor@{}", 3).as_str()),
                Some(1), // Buffered
            ),
            pb_fixtures::pb_block_scoped_data(
                pb_fixtures::pb_vm_block_changes(4),
                Some(format!("cursor@{}", 4).as_str()),
                Some(1), // Buffered
            ),
            pb_fixtures::pb_block_scoped_data(
                pb_fixtures::pb_vm_block_changes(5),
                Some(format!("cursor@{}", 5).as_str()),
                Some(3), // Buffered + flush 1 + 2
            ),
        ]
        .into_iter()
    }
}

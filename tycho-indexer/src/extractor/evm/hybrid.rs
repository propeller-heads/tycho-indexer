use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
};

use async_trait::async_trait;
use chrono::NaiveDateTime;
use ethers::prelude::{H160, H256, U256};
use mockall::automock;
use prost::Message;
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument, trace, warn};

use token_analyzer::TokenFinder;
use tycho_core::{
    models,
    models::{
        contract::Contract,
        protocol::{ComponentBalance, ProtocolComponentState},
        token::CurrencyToken,
        Address, Chain, ChangeType, ExtractionState, ExtractorIdentity, ProtocolType, TxHash,
    },
    storage::{
        ChainGateway, ContractStateGateway, ExtractionStateGateway, ProtocolGateway, StorageError,
    },
    Bytes,
};
use tycho_storage::postgres::cache::CachedGateway;

use crate::{
    extractor::{
        evm,
        evm::{
            chain_state::ChainState,
            protocol_cache::{ProtocolDataCache, ProtocolMemoryCache},
            token_pre_processor::{map_vault, TokenPreProcessorTrait},
            utils::format_duration,
            Block,
        },
        revert_buffer::RevertBuffer,
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
}

pub struct HybridContractExtractor<G, T> {
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
    post_processor: Option<fn(evm::BlockChanges) -> evm::BlockChanges>,
    /// The number of blocks behind the current block to be considered as syncing.
    sync_threshold: u64,
    revert_buffer: Mutex<RevertBuffer<BlockUpdateWithCursor<evm::BlockChanges>>>,
}

impl<G, T> HybridContractExtractor<G, T>
where
    G: HybridGateway,
    T: TokenPreProcessorTrait,
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
        post_processor: Option<fn(evm::BlockChanges) -> evm::BlockChanges>,
        sync_threshold: u64,
    ) -> Result<Self, ExtractionError> {
        // check if this extractor has state
        let res = match gateway.get_cursor().await {
            Err(StorageError::NotFound(_, _)) => {
                warn!(?name, ?chain, "No cursor found, starting from the beginning");
                HybridContractExtractor {
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
                    })),
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
                HybridContractExtractor {
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
        msg: &mut evm::BlockChangesResult,
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
        revert_buffer: &RevertBuffer<BlockUpdateWithCursor<evm::BlockChanges>>,
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

    async fn construct_currency_tokens(
        &self,
        msg: &evm::BlockChanges,
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
        // Construct unkown tokens using rpc
        let balance_map: HashMap<H160, (H160, U256)> = msg
            .txs_with_update
            .iter()
            .flat_map(|tx| {
                tx.protocol_components
                    .iter()
                    // Filtering to keep only components with ChangeType::Creation
                    .filter(|(_, c_change)| c_change.change == ChangeType::Creation)
                    .filter_map(|(c_id, change)| {
                        map_vault(&change.protocol_system)
                            .or_else(|| {
                                change
                                    .contract_ids
                                    // TODO: Currently, it's assumed that the pool is always the
                                    // first contract in the
                                    // protocol component. This approach is a temporary
                                    // workaround and needs to be revisited for a more robust
                                    // solution.
                                    .first()
                                    .copied()
                                    .or_else(|| H160::from_str(&change.id).ok())
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
                                        (*token, (addr, U256::from_big_endian(&balance.balance)))
                                    })
                            })
                    })
                    .flatten()
            })
            .collect::<HashMap<_, _>>();
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
impl<G, T> Extractor for HybridContractExtractor<G, T>
where
    G: HybridGateway,
    T: TokenPreProcessorTrait,
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

        let raw_msg = pb::tycho::evm::v1::BlockChanges::decode(data.value.as_slice())?;
        trace!(?raw_msg, "Received message");
        // Validate protocol_type_id
        let msg = match evm::BlockChanges::try_from_message(
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
                account_update = changes.account_updates.len(),
                state_update = changes.protocol_states.len(),
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
                            .account_updates
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
            revert_buffer.lookup_state(&reverted_account_state_keys_vec);

        // Then for every missing previous values in the buffer, get the data from our db
        let missing_map: HashMap<Bytes, Vec<Bytes>> =
            missing
                .into_iter()
                .fold(HashMap::new(), |mut acc, (addr, key)| {
                    acc.entry(addr.into())
                        .or_default()
                        .push(key.into());
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
                                        // If the key is not found, return 0
                                        || {
                                            (
                                                (state.address.clone().into(), key.clone().into()),
                                                0.into(),
                                            )
                                        },
                                        // If the key is found, return its value
                                        |value| {
                                            (
                                                (
                                                    state.address.clone().into(),
                                                    U256::from_big_endian(key),
                                                ),
                                                U256::from_big_endian(value),
                                            )
                                        },
                                    )
                                }
                                None => {
                                    // If the state is not found, return 0 for the key
                                    (((*address).clone().into(), key.clone().into()), 0.into())
                                }
                            }
                        })
                    }),
            )
            .collect::<Vec<_>>();

        let account_updates =
            combined_states
                .into_iter()
                .fold(HashMap::new(), |mut acc, ((addr, key), value)| {
                    acc.entry(addr)
                        .or_insert_with(|| evm::AccountUpdate {
                            address: addr,
                            chain: self.chain,
                            slots: HashMap::new(),
                            balance: None, //TODO: handle balance changes
                            code: None,    //TODO: handle code changes
                            change: ChangeType::Update,
                        })
                        .slots
                        .insert(key, value);
                    acc
                });

        // Handle reverted protocol state
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
        let (buffered_state, missing) = revert_buffer.lookup_state(&reverted_state_keys_vec);

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

        let revert_message = evm::BlockChangesResult {
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
            protocol_states: state_updates,
            account_updates,
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
    async fn handle_progress(&self, inp: ModulesProgress) -> Result<(), ExtractionError> {
        todo!()
    }
}
pub struct HybridPgGateway {
    name: String,
    chain: Chain,
    sync_batch_size: usize,
    state_gateway: CachedGateway,
}

#[automock]
#[async_trait]
pub trait HybridGateway: Send + Sync {
    async fn get_cursor(&self) -> Result<Vec<u8>, StorageError>;

    async fn ensure_protocol_types(&self, new_protocol_types: &[ProtocolType]);

    async fn advance(
        &self,
        changes: &evm::BlockChanges,
        new_cursor: &str,
        syncing: bool,
    ) -> Result<(), StorageError>;

    async fn get_protocol_states<'a>(
        &self,
        component_ids: &[&'a str],
    ) -> Result<Vec<ProtocolComponentState>, StorageError>;

    async fn upsert_contract(
        &self,
        changes: &evm::BlockChanges,
        new_cursor: &str,
        syncing: bool,
    ) -> Result<(), StorageError>;

    async fn get_contracts(
        &self,
        component_ids: &[models::Address],
    ) -> Result<Vec<Contract>, StorageError>;

    async fn get_components_balances<'a>(
        &self,
        component_ids: &[&'a str],
    ) -> Result<HashMap<String, HashMap<Bytes, ComponentBalance>>, StorageError>;
}

impl HybridPgGateway {
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
        changes: &evm::BlockChanges,
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
        let mut account_changes: Vec<(Bytes, models::contract::ContractDelta)> = vec![];

        let mut balance_changes: Vec<models::protocol::ComponentBalance> = vec![];
        let mut protocol_tokens: HashSet<H160> = HashSet::new();

        for tx_update in changes.txs_with_update.iter() {
            trace!(tx_hash = ?tx_update.tx.hash, "Processing tx");

            // Insert transaction
            self.state_gateway
                .upsert_tx(&[(tx_update).into()])
                .await?;

            let hash: TxHash = tx_update.tx.hash.into();

            // Map new protocol components
            for (_component_id, new_protocol_component) in tx_update.protocol_components.iter() {
                new_protocol_components.push(new_protocol_component.into());
                protocol_tokens.extend(new_protocol_component.tokens.iter());
            }

            // Map new account / contracts
            for (_, account_update) in tx_update.account_updates.iter() {
                if account_update.is_creation() {
                    let new: evm::Account = account_update.ref_into_account(&tx_update.tx);
                    info!(block_number = ?changes.block.number, contract_address = ?new.address, "NewContract");

                    // Insert new accounts
                    self.state_gateway
                        .upsert_contract(&(&new).into())
                        .await?;
                } else if account_update.is_update() {
                    account_changes
                        .push((tycho_core::Bytes::from(tx_update.tx.hash), account_update.into()));
                } else {
                    // log error
                    error!(?account_update, "Invalid account update type");
                }
            }

            // Map protocol state changes
            state_updates.extend(
                tx_update
                    .protocol_states
                    .values()
                    .map(|state_change| (hash.clone(), state_change.into())),
            );

            // Map balance changes
            balance_changes.extend(
                tx_update
                    .balance_changes
                    .iter()
                    .flat_map(|(_, tokens)| tokens.values().map(Into::into)),
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
impl HybridGateway for HybridPgGateway {
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
        changes: &evm::BlockChanges,
        new_cursor: &str,
        syncing: bool,
    ) -> Result<(), StorageError> {
        self.save_cursor(new_cursor).await?;
        self.forward(changes, new_cursor, syncing)
            .await
    }

    async fn get_protocol_states<'a>(
        &self,
        component_ids: &[&'a str],
    ) -> Result<Vec<ProtocolComponentState>, StorageError> {
        self.state_gateway
            .get_protocol_states(&self.chain, None, None, Some(component_ids), false)
            .await
    }

    async fn upsert_contract(
        &self,
        changes: &evm::BlockChanges,
        new_cursor: &str,
        syncing: bool,
    ) -> Result<(), StorageError> {
        self.forward(changes, new_cursor, syncing)
            .await?;
        Ok(())
    }

    async fn get_contracts(
        &self,
        component_ids: &[models::Address],
    ) -> Result<Vec<Contract>, StorageError> {
        self.state_gateway
            .get_contracts(&self.chain, Some(component_ids), None, true, false)
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

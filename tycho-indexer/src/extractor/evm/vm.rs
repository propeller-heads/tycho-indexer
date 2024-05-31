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
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, trace, warn};

use token_analyzer::TokenFinder;
use tycho_core::{
    models::{
        self, contract::Contract, protocol::ComponentBalance, token::CurrencyToken, Address, Chain,
        ChangeType, ExtractionState, ExtractorIdentity, ProtocolType,
    },
    storage::{
        ChainGateway, ContractStateGateway, ExtractionStateGateway, ProtocolGateway, StorageError,
    },
    Bytes,
};
use tycho_storage::postgres::cache::CachedGateway;

use crate::{
    extractor::{
        evm::{
            self,
            chain_state::ChainState,
            protocol_cache::{ProtocolDataCache, ProtocolMemoryCache},
            token_pre_processor::{map_vault, TokenPreProcessorTrait},
        },
        revert_buffer::RevertBuffer,
        BlockUpdateWithCursor, ExtractionError, Extractor, ExtractorMsg,
    },
    pb::{
        sf::substreams::rpc::v2::{BlockScopedData, BlockUndoSignal, ModulesProgress},
        tycho::evm::v1::BlockContractChanges,
    },
};

use super::{utils::format_duration, Block, BlockAccountChanges};

struct Inner {
    cursor: Vec<u8>,
    last_processed_block: Option<Block>,
    /// Used to give more informative logs
    last_report_ts: NaiveDateTime,
    last_report_block_number: u64,
}

pub struct VmContractExtractor<G, T> {
    gateway: G,
    name: String,
    chain: Chain,
    chain_state: ChainState,
    protocol_system: String,
    token_pre_processor: T,
    protocol_cache: ProtocolMemoryCache,
    // TODO: There is not reason this needs to be shared
    //  try removing the Mutex
    inner: Arc<Mutex<Inner>>,
    protocol_types: HashMap<String, ProtocolType>,
    /// Allows to attach some custom logic, e.g. to fix encoding bugs without re-sync.
    post_processor: Option<fn(evm::BlockContractChanges) -> evm::BlockContractChanges>,
    /// The number of blocks behind the current block to be considered as syncing.
    sync_threshold: u64,
    revert_buffer: Mutex<RevertBuffer<BlockUpdateWithCursor<evm::BlockContractChanges>>>,
}

impl<G, T> VmContractExtractor<G, T>
where
    G: VmGateway,
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
                    protocol_cache,
                    token_pre_processor,
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
                    protocol_cache,
                    token_pre_processor,
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

    #[instrument(skip_all, fields(chain = % self.chain, name = % self.name, block_number = % msg.block.number))]
    #[allow(clippy::mutable_key_type)]
    async fn handle_tvl_changes(
        &self,
        msg: &mut BlockAccountChanges,
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
        revert_buffer: &RevertBuffer<BlockUpdateWithCursor<evm::BlockContractChanges>>,
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
        msg: &evm::BlockContractChanges,
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
            .tx_updates
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
                        tx.component_balances
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
impl<G, T> Extractor for VmContractExtractor<G, T>
where
    G: VmGateway,
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

    #[instrument(skip_all)]
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

        // Depending on how Substreams handle them, this condition could be problematic for single
        // block finality blockchains.
        let is_syncing = inp.final_block_height >= msg.block.number;
        {
            // keep revert buffer guard within a limited scope

            let mut revert_buffer = self.revert_buffer.lock().await;
            revert_buffer
                .insert_block(BlockUpdateWithCursor::new(msg.clone(), inp.cursor.clone()))
                .expect("Error while inserting a block into revert buffer");
            for msg in revert_buffer
                .drain_new_finalized_blocks(inp.final_block_height)
                .expect("Final block height not found in revert buffer")
            {
                self.gateway
                    .upsert_contract(msg.block_update(), msg.cursor(), is_syncing)
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
                update = changes.account_updates.len(),
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
                        .tx_updates
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

        // Handle reverted state
        let reverted_state_keys: HashSet<_> = reverted_state
            .iter()
            .flat_map(|block_msg| {
                block_msg
                    .block_update()
                    .tx_updates
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

        let reverted_state_keys_vec = reverted_state_keys
            .into_iter()
            .collect::<Vec<_>>();

        trace!(?reverted_state_keys_vec, "Reverted state keys");

        // Fetch previous values for every reverted states
        // First search in the buffer
        let (buffered_state, missing) =
            revert_buffer.lookup_account_state(&reverted_state_keys_vec);

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

        // Handle token balance changes
        let reverted_balances_keys: HashSet<(&String, Bytes)> = reverted_state
            .iter()
            .flat_map(|block_msg| {
                block_msg
                    .block_update()
                    .tx_updates
                    .iter()
                    .flat_map(|update| {
                        update
                            .component_balances
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

        trace!(?reverted_balances_keys_vec, "Reverted balance keys");

        let combined_balances = self
            .get_balances(&revert_buffer, &reverted_balances_keys_vec)
            .await?;

        let revert_message = evm::BlockAccountChanges {
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
    async fn handle_progress(&self, _inp: ModulesProgress) -> Result<(), ExtractionError> {
        todo!()
    }
}

pub struct VmPgGateway {
    name: String,
    chain: Chain,
    sync_batch_size: usize,
    state_gateway: CachedGateway,
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

    async fn get_contracts(
        &self,
        component_ids: &[models::Address],
    ) -> Result<Vec<Contract>, StorageError>;

    async fn get_components_balances<'a>(
        &self,
        component_ids: &[&'a str],
    ) -> Result<HashMap<String, HashMap<Bytes, ComponentBalance>>, StorageError>;
}

impl VmPgGateway {
    pub fn new(name: &str, chain: Chain, sync_batch_size: usize, gw: CachedGateway) -> Self {
        VmPgGateway { name: name.to_owned(), chain, sync_batch_size, state_gateway: gw }
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
        changes: &evm::BlockContractChanges,
        new_cursor: &str,
        syncing: bool,
    ) -> Result<(), StorageError> {
        self.state_gateway
            .start_transaction(&(&changes.block).into(), Some(self.name.as_str()))
            .await;
        if !changes.new_tokens.is_empty() {
            let new_tokens = changes
                .new_tokens
                .values()
                .cloned()
                .collect::<Vec<_>>();
            self.state_gateway
                .add_tokens(&new_tokens)
                .await?;
        }

        self.state_gateway
            .upsert_block(&[(&changes.block).into()])
            .await?;
        for update in changes.tx_updates.iter() {
            trace!(tx_hash = ?update.tx.hash, "Processing transaction");
            self.state_gateway
                .upsert_tx(&[(&update.tx).into()])
                .await?;
            for (_, acc_update) in update.account_updates.iter() {
                if acc_update.is_creation() {
                    let new: evm::Account = acc_update.ref_into_account(&update.tx);
                    info!(block_number = ?changes.block.number, contract_address = ?new.address, "NewContract");
                    self.state_gateway
                        .upsert_contract(&(&new).into())
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
impl VmGateway for VmPgGateway {
    async fn get_cursor(&self) -> Result<Vec<u8>, StorageError> {
        self.get_last_cursor().await
    }

    async fn get_contracts(
        &self,
        component_ids: &[Address],
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

    async fn ensure_protocol_types(&self, new_protocol_types: &[ProtocolType]) {
        self.state_gateway
            .add_protocol_types(new_protocol_types)
            .await
            .expect("Couldn't insert protocol types");
    }

    #[instrument(skip_all)]
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
}

#[cfg(test)]
mod test {
    use float_eq::assert_float_eq;
    use tycho_core::models::{protocol::ProtocolComponent, FinancialType, ImplementationType};

    use crate::{
        extractor::evm::token_pre_processor::MockTokenPreProcessorTrait, testing::MockGateway,
    };

    use super::*;

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
        let protocol_cache = ProtocolMemoryCache::new(
            Chain::Ethereum,
            chrono::Duration::seconds(900),
            Arc::new(MockGateway::new()),
        );
        let extractor = VmContractExtractor::new(
            "vm:ambient",
            Chain::Ethereum,
            ChainState::default(),
            gw,
            ambient_protocol_types(),
            "ambient".into(),
            protocol_cache,
            MockTokenPreProcessorTrait::new(),
            None,
            5,
        )
        .await
        .expect("extractor init ok");

        let res = extractor.get_cursor().await;

        assert_eq!(res, "cursor");
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
        let protocol_cache = ProtocolMemoryCache::new(
            Chain::Ethereum,
            chrono::Duration::seconds(900),
            Arc::new(MockGateway::new()),
        );
        let mut preprocessor = MockTokenPreProcessorTrait::new();
        preprocessor
            .expect_get_tokens()
            .returning(|_, _, _| Vec::new());
        let extractor = VmContractExtractor::new(
            "vm:ambient",
            Chain::Ethereum,
            ChainState::default(),
            gw,
            ambient_protocol_types(),
            "ambient".to_owned(),
            protocol_cache,
            preprocessor,
            None,
            5,
        )
        .await
        .expect("extractor init ok");

        extractor
            .handle_tick_scoped_data(evm::fixtures::pb_block_scoped_data(
                BlockContractChanges {
                    block: Some(evm::fixtures::pb_blocks(1)),
                    changes: vec![crate::pb::tycho::evm::v1::TransactionContractChanges {
                        tx: Some(evm::fixtures::pb_transactions(1, 1)),
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
            .handle_tick_scoped_data(evm::fixtures::pb_block_scoped_data(
                BlockContractChanges {
                    block: Some(evm::fixtures::pb_blocks(2)),
                    changes: vec![crate::pb::tycho::evm::v1::TransactionContractChanges {
                        tx: Some(evm::fixtures::pb_transactions(2, 1)),
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
        let protocol_cache = ProtocolMemoryCache::new(
            Chain::Ethereum,
            chrono::Duration::seconds(900),
            Arc::new(MockGateway::new()),
        );
        let extractor = VmContractExtractor::new(
            "vm:ambient",
            Chain::Ethereum,
            ChainState::default(),
            gw,
            ambient_protocol_types(),
            "ambient".to_owned(),
            protocol_cache,
            MockTokenPreProcessorTrait::new(),
            None,
            5,
        )
        .await
        .expect("extractor init ok");
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

    fn token_prices() -> HashMap<Bytes, f64> {
        HashMap::from([
            (
                Bytes::from("0x0000000000000000000000000000000000000001"),
                344101538937875300000000000.0,
            ),
            (Bytes::from("0x0000000000000000000000000000000000000002"), 2980881444.0),
        ])
    }

    #[test_log::test(tokio::test)]
    async fn test_construct_tokens() {
        let msg = evm::BlockContractChanges {
            extractor: "ex".to_string(),
            block: evm::Block::default(),
            chain: Chain::Ethereum,
            finalized_block_height: 0,
            revert: false,
            new_tokens: HashMap::new(),
            tx_updates: vec![evm::TransactionVMUpdates {
                account_updates: HashMap::new(),
                protocol_components: HashMap::from([(
                    "comp1".to_string(),
                    evm::ProtocolComponent {
                        tokens: vec![
                            "0x0000000000000000000000000000000000000001"
                                .parse()
                                .unwrap(),
                            "0x0000000000000000000000000000000000000003"
                                .parse()
                                .unwrap(),
                        ],
                        ..Default::default()
                    },
                )]),
                component_balances: HashMap::new(),
                tx: evm::Transaction::default(),
            }],
        };

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

        let mut preprocessor = MockTokenPreProcessorTrait::new();
        let t3 = evm::ERC20Token::new(
            "0x0000000000000000000000000000000000000003"
                .parse()
                .unwrap(),
            "TOK3".to_string(),
            18,
            0,
            Vec::new(),
            Chain::Ethereum,
            100,
        );
        let ret = vec![t3.clone()];
        preprocessor
            .expect_get_tokens()
            .return_once(|_, _, _| ret);
        let mut extractor_gw = MockVmGateway::new();
        extractor_gw
            .expect_ensure_protocol_types()
            .times(1)
            .returning(|_| ());
        extractor_gw
            .expect_get_cursor()
            .times(1)
            .returning(|| Ok("cursor".into()));
        let extractor = VmContractExtractor::new(
            "vm_name",
            Chain::Ethereum,
            ChainState::default(),
            extractor_gw,
            HashMap::from([("pt_1".to_string(), ProtocolType::default())]),
            "system1".to_string(),
            protocol_cache,
            preprocessor,
            None,
            5,
        )
        .await
        .expect("extractor init failed");
        let exp = HashMap::from([
            (t1.address.clone(), t1),
            (Bytes::from(t3.address.as_bytes()), (&t3).into()),
        ]);

        let res = extractor
            .construct_currency_tokens(&msg)
            .await
            .expect("construct_currency_tokens failed");

        assert_eq!(res, exp);
    }

    #[test_log::test(tokio::test)]
    async fn test_handle_tvl_changes() {
        let mut msg = BlockAccountChanges {
            component_balances: HashMap::from([(
                "comp1".to_string(),
                HashMap::from([(
                    H160::from_str("0x0000000000000000000000000000000000000001").unwrap(),
                    evm::ComponentBalance {
                        token: H160::from_str("0x0000000000000000000000000000000000000001")
                            .unwrap(),
                        balance: Bytes::from(
                            "0x00000000000000000000000000000000000000000000003635c9adc5dea00000",
                        ),
                        balance_float: 11_304_207_639.4e18,
                        modify_tx: H256::default(),
                        component_id: "comp1".to_string(),
                    },
                ),
                    (
                        H160::from_str("0x0000000000000000000000000000000000000002").unwrap(),
                        evm::ComponentBalance {
                            token: H160::from_str("0x0000000000000000000000000000000000000002")
                                .unwrap(),
                            balance: Bytes::from(
                                "0x00000000000000000000000000000000000000000000003635c9adc5dea00000",
                            ),
                            balance_float: 100_000e6,
                            modify_tx: H256::default(),
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

        let preprocessor = MockTokenPreProcessorTrait::new();
        let mut extractor_gw = MockVmGateway::new();
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
        let extractor = VmContractExtractor::new(
            "vm_name",
            Chain::Ethereum,
            ChainState::default(),
            extractor_gw,
            HashMap::from([("pt_1".to_string(), ProtocolType::default())]),
            "system1".to_string(),
            protocol_cache,
            preprocessor,
            None,
            5,
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
    use diesel_async::{pooled_connection::deadpool::Pool, AsyncPgConnection};
    use futures03::{stream, StreamExt};
    use hex::ToHex;
    use test_log::test;

    use tycho_core::{
        models::{ContractId, FinancialType, ImplementationType},
        storage::{BlockIdentifier, BlockOrTimestamp},
    };
    use tycho_storage::{
        postgres,
        postgres::{
            builder::GatewayBuilder, db_fixtures, db_fixtures::yesterday_midnight,
            testing::run_against_db,
        },
    };

    use crate::{
        extractor::evm::{
            token_pre_processor::MockTokenPreProcessorTrait, AccountUpdate, ComponentBalance,
            ProtocolComponent,
        },
        pb::sf::substreams::v1::BlockRef,
    };

    use super::*;

    const TX_HASH_0: &str = "0x2f6350a292c0fc918afe67cb893744a080dacb507b0cea4cc07437b8aff23cdb";
    const TX_HASH_1: &str = "0x0d9e0da36cf9f305a189965b248fc79c923619801e8ab5ef158d4fd528a291ad";
    const TX_HASH_2: &str = "0xcf574444be25450fe26d16b85102b241e964a6e01d75dd962203d4888269be3d";
    const BLOCK_HASH_0: &str = "0x98b4a4fef932b1862be52de218cc32b714a295fae48b775202361a6fa09b66eb";

    const WETH_ADDRESS: &str = "C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    const USDC_ADDRESS: &str = "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

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

    async fn setup_gw(pool: Pool<AsyncPgConnection>) -> VmPgGateway {
        let mut conn = pool
            .get()
            .await
            .expect("pool should get a connection");

        postgres::db_fixtures::insert_protocol_type(&mut conn, "vm:pool", None, None, None).await;
        let chain_id = postgres::db_fixtures::insert_chain(&mut conn, "ethereum").await;
        db_fixtures::insert_token(&mut conn, chain_id, WETH_ADDRESS, "WETH", 18, None).await;
        db_fixtures::insert_token(&mut conn, chain_id, USDC_ADDRESS, "USDC", 6, None).await;

        let db_url = std::env::var("DATABASE_URL").expect("Database URL must be set for testing");
        let (cached_gw, _jh) = GatewayBuilder::new(db_url.as_str())
            .set_chains(&[Chain::Ethereum])
            .set_protocol_systems(&["ambient".to_string()])
            .build()
            .await
            .expect("failed to build postgres gateway");
        VmPgGateway::new("vm:ambient", Chain::Ethereum, 1000, cached_gw)
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
                .start_transaction(&models::blockchain::Block::default(), None)
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
            finalized_block_height: 0,
            revert: false,
            new_tokens: HashMap::new(),
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
            finalized_block_height: 0,
            revert: false,
            new_tokens: HashMap::new(),
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
                .get_tokens(Chain::Ethereum, None, None, None, None)
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
            assert_eq!(component_balances[0].component_id, "ambient_USDC_ETH");
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

            let gw = VmPgGateway::new(
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
            let extractor = VmContractExtractor::new(
                "vm_name",
                Chain::Ethereum,
                ChainState::default(),
                gw,
                protocol_types,
                "vm_protocol_system".to_string(),
                protocol_cache,
                preprocessor,
                None,
                5,
            )
                .await
                .expect("Failed to create extractor");

            dbg!("starting input seq");
            // Send a sequence of block scoped data.
            stream::iter(get_inp_sequence())
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
                .downcast_ref::<evm::BlockAccountChanges>()
                .expect("not good type");

            let base_ts = yesterday_midnight().timestamp();
            let block_account_expected = evm::BlockAccountChanges {
                extractor: "vm_name".to_string(),
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
                account_updates: HashMap::from([
                    (H160::from_str("0x0000000000000000000000000000000000000001").unwrap(), AccountUpdate {
                        address: H160::from_str("0x0000000000000000000000000000000000000001").unwrap(),
                        chain: Chain::Ethereum,
                        slots: HashMap::from([
                            (U256::from_dec_str("1356938545749799165119972480570561420155507632800475359837393562592731987968").unwrap(), 0.into()),
                            (1.into(), 1.into()),
                        ]),
                        balance: None,
                        code: None,
                        change: ChangeType::Update,
                    }),
                    (H160::from_str("0x0000000000000000000000000000000000000002").unwrap(), AccountUpdate {
                        address: H160::from_str("0x0000000000000000000000000000000000000002").unwrap(),
                        chain: Chain::Ethereum,
                        slots: HashMap::from([
                            (1.into(), 2.into()),
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
                            H160::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap(),
                            H160::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
                        ],
                        contract_ids: vec![
                            H160::from_str("0x0000000000000000000000000000000000000001").unwrap(),
                        ],
                        static_attributes: HashMap::new(),
                        change: ChangeType::Deletion,
                        creation_tx: H256::from_str("0x0000000000000000000000000000000000000000000000000000000000009c41").unwrap(),
                        created_at: NaiveDateTime::from_timestamp_opt(base_ts + 4000, 0).unwrap(),
                    }),
                ]),
                component_balances: HashMap::from([
                    ("pc_1".to_string(), HashMap::from([
                        (H160::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(), ComponentBalance {
                            token: H160::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
                            balance: Bytes::from("0x00000064"),
                            balance_float: 100.0,
                            modify_tx: H256::from_str("0x0000000000000000000000000000000000000000000000000000000000007532").unwrap(),
                            component_id: "pc_1".to_string(),
                        }),
                        (H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(), ComponentBalance {
                            token: H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                            balance: Bytes::from("0x00000001"),
                            balance_float: 1.0,
                            modify_tx: H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                            component_id: "pc_1".to_string(),
                        }),
                    ])),
                ]),
                component_tvl: HashMap::new(),
            };

            assert_eq!(
                res,
                &block_account_expected
            );
        })
            .await;
    }

    fn get_inp_sequence(
    ) -> impl Iterator<Item = crate::pb::sf::substreams::rpc::v2::BlockScopedData> {
        vec![
            evm::fixtures::pb_block_scoped_data(
                evm::fixtures::pb_block_contract_changes(1),
                Some(format!("cursor@{}", 1).as_str()),
                Some(1), // Syncing (buffered)
            ),
            evm::fixtures::pb_block_scoped_data(
                evm::fixtures::pb_block_contract_changes(2),
                Some(format!("cursor@{}", 2).as_str()),
                Some(1), // Buffered
            ),
            evm::fixtures::pb_block_scoped_data(
                evm::fixtures::pb_block_contract_changes(3),
                Some(format!("cursor@{}", 3).as_str()),
                Some(1), // Buffered
            ),
            evm::fixtures::pb_block_scoped_data(
                evm::fixtures::pb_block_contract_changes(4),
                Some(format!("cursor@{}", 4).as_str()),
                Some(1), // Buffered
            ),
            evm::fixtures::pb_block_scoped_data(
                evm::fixtures::pb_block_contract_changes(5),
                Some(format!("cursor@{}", 5).as_str()),
                Some(3), // Buffered + flush 1 + 2
            ),
        ]
        .into_iter()
    }
}

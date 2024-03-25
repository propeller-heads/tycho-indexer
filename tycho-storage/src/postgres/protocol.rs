use super::{
    maybe_lookup_block_ts, maybe_lookup_version_ts, orm,
    orm::{Account, ComponentTVL, NewAccount},
    schema, storage_error_from_diesel,
    versioning::apply_delta_versioning,
    PostgresError, PostgresGateway, WithTxHash,
};
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use itertools::Itertools;
use std::collections::{BTreeSet, HashMap, HashSet};
use tracing::{instrument, warn};
use tycho_core::{
    models,
    models::{
        Address, Balance, Chain, ChangeType, ComponentId, FinancialType, ImplementationType,
        PaginationParams, TxHash,
    },
    storage::{BlockOrTimestamp, StorageError, Version},
    Bytes,
};
use unicode_segmentation::UnicodeSegmentation;

// Private methods
impl PostgresGateway {
    /// # Decoding ProtocolStates from database results.
    ///
    /// This function takes as input the database result for querying protocol states and their
    /// linked component id and transaction hash.
    ///
    /// ## Assumptions:
    /// - It is assumed that the rows in the result are ordered by:
    ///     1. Component ID,
    ///     2. Transaction block, and then
    ///     3. Transaction index.
    ///
    /// The function processes these individual `ProtocolState` entities and combines all entities
    /// with matching component IDs into a single `ProtocolState`. The final output is a list
    /// where each element is a `ProtocolState` representing a unique component.
    ///
    /// ## Returns:
    /// - A Result containing a vector of `ProtocolState`, otherwise, it will return a StorageError.
    fn _decode_protocol_states(
        &self,
        result: Result<Vec<(orm::ProtocolState, ComponentId)>, diesel::result::Error>,
        context: &str,
    ) -> Result<Vec<models::protocol::ProtocolComponentState>, StorageError> {
        match result {
            Ok(data_vec) => {
                // Decode final state deltas. We can assume result is sorted by component_id and
                // transaction index. Therefore we can use slices to iterate over the data in groups
                // of component_id. The last update for each component will have the latest
                // transaction hash (modify_tx).

                let mut protocol_states = Vec::new();

                let mut index = 0;
                while index < data_vec.len() {
                    let component_start = index;
                    let current_component_id = &data_vec[index].1;

                    // Iterate until the component_id changes
                    while index < data_vec.len() && &data_vec[index].1 == current_component_id {
                        index += 1;
                    }

                    let states_slice = &data_vec[component_start..index];

                    let protocol_state = models::protocol::ProtocolComponentState::new(
                        current_component_id,
                        states_slice
                            .iter()
                            .map(|x| (x.0.attribute_name.clone(), x.0.attribute_value.clone()))
                            .collect(),
                        None,
                    );

                    protocol_states.push(protocol_state);
                }
                Ok(protocol_states)
            }

            Err(err) => Err(storage_error_from_diesel(err, "ProtocolStates", context, None).into()),
        }
    }

    async fn _get_or_create_protocol_system_id(
        &self,
        new: String,
        conn: &mut AsyncPgConnection,
    ) -> Result<i64, StorageError> {
        use super::schema::protocol_system::dsl::*;

        let existing_entry = protocol_system
            .filter(name.eq(new.to_string().clone()))
            .first::<orm::ProtocolSystem>(conn)
            .await;

        if let Ok(entry) = existing_entry {
            Ok(entry.id)
        } else {
            let new_entry = orm::NewProtocolSystem { name: new.to_string() };

            let inserted_protocol_system = diesel::insert_into(protocol_system)
                .values(&new_entry)
                .get_result::<orm::ProtocolSystem>(conn)
                .await
                .map_err(|err| {
                    storage_error_from_diesel(err, "ProtocolSystem", &new.to_string(), None)
                })?;
            Ok(inserted_protocol_system.id)
        }
    }

    pub async fn get_protocol_components(
        &self,
        chain: &Chain,
        system: Option<String>,
        ids: Option<&[&str]>,
        min_tvl: Option<f64>,
        conn: &mut AsyncPgConnection,
    ) -> Result<Vec<models::protocol::ProtocolComponent>, StorageError> {
        use super::schema::{protocol_component::dsl::*, transaction::dsl::*};
        let chain_id_value = self.get_chain_id(chain);

        let mut query = protocol_component
            .inner_join(transaction.on(creation_tx.eq(schema::transaction::id)))
            .left_join(schema::component_tvl::table)
            .select((orm::ProtocolComponent::as_select(), hash))
            .into_boxed();

        match (system, ids) {
            (Some(ps), None) => {
                let protocol_system = self.get_protocol_system_id(&ps);
                query = query.filter(
                    chain_id
                        .eq(chain_id_value)
                        .and(protocol_system_id.eq(protocol_system)),
                );
            }
            (None, Some(external_ids)) => {
                query = query.filter(
                    chain_id
                        .eq(chain_id_value)
                        .and(external_id.eq_any(external_ids)),
                );
            }
            (Some(ps), Some(external_ids)) => {
                let protocol_system = self.get_protocol_system_id(&ps);
                query = query.filter(
                    chain_id.eq(chain_id_value).and(
                        external_id
                            .eq_any(external_ids)
                            .and(protocol_system_id.eq(protocol_system)),
                    ),
                );
            }
            (_, _) => {
                query = query.filter(chain_id.eq(chain_id_value));
            }
        }

        if let Some(thr) = min_tvl {
            query = query.filter(schema::component_tvl::tvl.gt(thr));
        }

        let orm_protocol_components = query
            .load::<(orm::ProtocolComponent, TxHash)>(conn)
            .await
            .map_err(PostgresError::from)?;

        let protocol_component_ids = orm_protocol_components
            .iter()
            .map(|(pc, _)| pc.id)
            .collect::<Vec<i64>>();

        let protocol_component_tokens: Vec<(i64, Address)> =
            schema::protocol_component_holds_token::table
                .inner_join(schema::token::table)
                .inner_join(
                    schema::account::table.on(schema::token::account_id.eq(schema::account::id)),
                )
                .select((
                    schema::protocol_component_holds_token::protocol_component_id,
                    schema::account::address,
                ))
                .filter(
                    schema::protocol_component_holds_token::protocol_component_id
                        .eq_any(protocol_component_ids.clone()),
                )
                .load::<(i64, Address)>(conn)
                .await
                .map_err(PostgresError::from)?;

        let protocol_component_contracts: Vec<(i64, Address)> =
            schema::protocol_component_holds_contract::table
                .inner_join(schema::contract_code::table)
                .inner_join(
                    schema::account::table
                        .on(schema::contract_code::account_id.eq(schema::account::id)),
                )
                .select((
                    schema::protocol_component_holds_contract::protocol_component_id,
                    schema::account::address,
                ))
                .filter(
                    schema::protocol_component_holds_contract::protocol_component_id
                        .eq_any(protocol_component_ids),
                )
                .load::<(i64, Address)>(conn)
                .await
                .map_err(PostgresError::from)?;

        fn map_addresses_to_protocol_component(
            protocol_component_to_address: Vec<(i64, Address)>,
        ) -> HashMap<i64, Vec<Address>> {
            protocol_component_to_address
                .into_iter()
                .fold(HashMap::new(), |mut acc, (key, address)| {
                    acc.entry(key)
                        .or_default()
                        .push(address);
                    acc
                })
        }
        let protocol_component_tokens =
            map_addresses_to_protocol_component(protocol_component_tokens);
        let protocol_component_contracts =
            map_addresses_to_protocol_component(protocol_component_contracts);

        orm_protocol_components
            .into_iter()
            .map(|(pc, tx_hash)| {
                let ps = self.get_protocol_system(&pc.protocol_system_id);
                let tokens_by_pc: Vec<Address> = protocol_component_tokens
                    .get(&pc.id)
                    // We expect all protocol components to have tokens.
                    .expect("Could not find Tokens for Protocol Component.")
                    .clone();
                let contracts_by_pc: Vec<Address> = protocol_component_contracts
                    .get(&pc.id)
                    .cloned()
                    // We expect all protocol components to have contracts.
                    .unwrap_or_default();

                let static_attributes: HashMap<String, Bytes> = if let Some(v) = pc.attributes {
                    serde_json::from_value(v).map_err(|_| {
                        StorageError::DecodeError("Failed to decode static attributes.".to_string())
                    })?
                } else {
                    Default::default()
                };

                Ok(models::protocol::ProtocolComponent::new(
                    &pc.external_id,
                    &ps,
                    // TODO: this is obiviously wrong and needs fixing
                    &pc.protocol_type_id.to_string(),
                    *chain,
                    tokens_by_pc,
                    contracts_by_pc,
                    static_attributes,
                    ChangeType::Creation,
                    tx_hash,
                    pc.created_at,
                ))
            })
            .collect()
    }

    pub async fn add_protocol_components(
        &self,
        new: &[models::protocol::ProtocolComponent],
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        use super::schema::{
            account::dsl::*, protocol_component::dsl::*, protocol_component_holds_contract::dsl::*,
            protocol_component_holds_token::dsl::*, token::dsl::*,
        };
        let mut values: Vec<orm::NewProtocolComponent> = Vec::with_capacity(new.len());
        let tx_hashes: Vec<TxHash> = new
            .iter()
            .map(|pc| pc.creation_tx.clone())
            .collect();
        let tx_hash_id_mapping: HashMap<TxHash, i64> =
            orm::Transaction::ids_by_hash(&tx_hashes, conn)
                .await
                .map_err(PostgresError::from)?;
        let pt_id = orm::ProtocolType::id_by_name(&new[0].protocol_type_name, conn)
            .await
            .map_err(|err| {
                storage_error_from_diesel(err, "ProtocolType", &new[0].protocol_type_name, None)
            })?;
        for pc in new {
            let txh = tx_hash_id_mapping
                .get::<TxHash>(&pc.creation_tx.clone())
                .ok_or(StorageError::DecodeError("TxHash not found".to_string()))?;

            let new_pc = orm::NewProtocolComponent::new(
                &pc.id,
                self.get_chain_id(&pc.chain),
                pt_id,
                self.get_protocol_system_id(&pc.protocol_system.to_string()),
                *txh,
                pc.created_at,
                &pc.static_attributes,
            );
            values.push(new_pc);
        }

        let inserted_protocol_components: Vec<(i64, String, i64, i64)> =
            diesel::insert_into(protocol_component)
                .values(&values)
                .on_conflict((schema::protocol_component::chain_id, external_id))
                .do_nothing()
                .returning((
                    schema::protocol_component::id,
                    schema::protocol_component::external_id,
                    schema::protocol_component::protocol_system_id,
                    schema::protocol_component::chain_id,
                ))
                .get_results(conn)
                .await
                .map_err(|err| {
                    storage_error_from_diesel(err, "ProtocolComponent", "Batch insert", None)
                })?;

        let mut protocol_db_id_map = HashMap::new();
        for (pc_id, ex_id, ps_id, chain_id_db) in inserted_protocol_components {
            protocol_db_id_map.insert(
                (ex_id, self.get_protocol_system(&ps_id), self.get_chain(&chain_id_db)),
                pc_id,
            );
        }

        let filtered_new_protocol_components: Vec<&models::protocol::ProtocolComponent> = new
            .iter()
            .filter(|component| {
                let key =
                    (component.id.clone(), component.protocol_system.clone(), component.chain);

                protocol_db_id_map.contains_key(&key)
            })
            .collect();

        // establish component-token junction
        let token_addresses: HashSet<Address> = filtered_new_protocol_components
            .iter()
            .flat_map(|pc| pc.tokens.iter().cloned())
            .collect();

        let pc_tokens_map = filtered_new_protocol_components
            .iter()
            .flat_map(|pc| {
                let pc_id = protocol_db_id_map
                    .get(&(pc.id.clone(), pc.protocol_system.clone(), pc.chain))
                    .unwrap_or_else(|| {
                        //Because we just inserted the protocol systems, there should not be any missing.
                        // However, trying to handle this via Results is needlessly difficult, because you
                        // can not use flat_map on a Result.
                        panic!(
                            "Could not find Protocol Component with ID: {}, Protocol System: {}, Chain: {}",
                            pc.id, pc.protocol_system, pc.chain
                        )
                    });
                pc.tokens
                    .clone()
                    .into_iter()
                    .map(move |add| (*pc_id, add))
                    .collect::<Vec<(i64, Address)>>()
            })
            .collect::<Vec<(i64, Address)>>();

        let token_add_by_id: HashMap<Address, i64> = token
            .inner_join(account)
            .select((schema::account::address, schema::token::id))
            .filter(schema::account::address.eq_any(token_addresses))
            .into_boxed()
            .load::<(Address, i64)>(conn)
            .await
            .map_err(|err| storage_error_from_diesel(err, "Token", "Several Chains", None))?
            .into_iter()
            .collect();

        let protocol_component_token_junction: Result<
            Vec<orm::NewProtocolComponentHoldsToken>,
            StorageError,
        > = pc_tokens_map
            .iter()
            .map(|(pc_id, t_address)| {
                let t_id = token_add_by_id
                    .get(t_address)
                    .ok_or(StorageError::NotFound("Token id".to_string(), t_address.to_string()))?;
                Ok(orm::NewProtocolComponentHoldsToken {
                    protocol_component_id: *pc_id,
                    token_id: *t_id,
                })
            })
            .collect();

        diesel::insert_into(protocol_component_holds_token)
            .values(&protocol_component_token_junction?)
            .execute(conn)
            .await
            .map_err(PostgresError::from)?;

        // establish component-contract junction
        let contract_addresses: HashSet<Address> = new
            .iter()
            .flat_map(|pc| pc.contract_addresses.clone())
            .collect();

        let pc_contract_map = new
            .iter()
            .flat_map(|pc| {
                let pc_id = protocol_db_id_map
                    .get(&(pc.id.clone(), pc.protocol_system.clone(), pc.chain))
                    .unwrap_or_else(|| {
                        panic!(
                            "Could not find Protocol Component with ID: {}, Protocol System: {}, Chain: {}",
                            pc.id, pc.protocol_system, pc.chain
                        )
                    }); //Because we just inserted the protocol systems, there should not be any missing.
                // However, trying to handle this via Results is needlessly difficult, because you
                // can not use flat_map on a Result.

                pc.contract_addresses
                    .iter()
                    .cloned()
                    .map(move |add| (*pc_id, add))
                    .collect::<Vec<(i64, Address)>>()
            })
            .collect::<Vec<(i64, Address)>>();

        let contract_add_by_id: HashMap<Address, i64> = schema::contract_code::table
            .inner_join(account)
            .select((schema::account::address, schema::contract_code::id))
            .filter(schema::account::address.eq_any(contract_addresses))
            .into_boxed()
            .load::<(Address, i64)>(conn)
            .await
            .map_err(|err| storage_error_from_diesel(err, "Contract", "Several Chains", None))?
            .into_iter()
            .collect();

        let protocol_component_contract_junction: Result<
            Vec<orm::NewProtocolComponentHoldsContract>,
            StorageError,
        > = pc_contract_map
            .iter()
            .map(|(pc_id, t_address)| {
                let t_id = contract_add_by_id
                    .get(t_address)
                    .ok_or(StorageError::NotFound("Account".to_string(), t_address.to_string()))?;
                Ok(orm::NewProtocolComponentHoldsContract {
                    protocol_component_id: *pc_id,
                    contract_code_id: *t_id,
                })
            })
            .collect();

        diesel::insert_into(protocol_component_holds_contract)
            .values(&protocol_component_contract_junction?)
            .execute(conn)
            .await
            .map_err(PostgresError::from)?;

        Ok(())
    }

    pub async fn delete_protocol_components(
        &self,
        to_delete: &[models::protocol::ProtocolComponent],
        block_ts: NaiveDateTime,
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        use super::schema::protocol_component::dsl::*;

        let ids_to_delete: Vec<String> = to_delete
            .iter()
            .map(|c| c.id.to_string())
            .collect();

        diesel::update(protocol_component.filter(external_id.eq_any(ids_to_delete)))
            .set(deleted_at.eq(block_ts))
            .execute(conn)
            .await
            .map_err(PostgresError::from)?;
        Ok(())
    }
    pub async fn add_protocol_types(
        &self,
        new_protocol_types: &[models::ProtocolType],
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        use super::schema::protocol_type::dsl::*;
        let values: Vec<orm::NewProtocolType> = new_protocol_types
            .iter()
            .map(|new_protocol_type| {
                let financial_protocol_type: orm::FinancialType =
                    match new_protocol_type.financial_type {
                        FinancialType::Swap => orm::FinancialType::Swap,
                        FinancialType::Psm => orm::FinancialType::Psm,
                        FinancialType::Debt => orm::FinancialType::Debt,
                        FinancialType::Leverage => orm::FinancialType::Leverage,
                    };

                let protocol_implementation_type: orm::ImplementationType =
                    match new_protocol_type.implementation {
                        ImplementationType::Custom => orm::ImplementationType::Custom,
                        ImplementationType::Vm => orm::ImplementationType::Vm,
                    };

                orm::NewProtocolType {
                    name: new_protocol_type.name.clone(),
                    implementation: protocol_implementation_type,
                    attribute_schema: new_protocol_type
                        .attribute_schema
                        .clone(),
                    financial_type: financial_protocol_type,
                }
            })
            .collect();

        diesel::insert_into(protocol_type)
            .values(&values)
            .on_conflict(name)
            .do_nothing()
            .execute(conn)
            .await
            .map_err(|err| storage_error_from_diesel(err, "ProtocolType", "Batch insert", None))?;

        Ok(())
    }

    // Gets all protocol states from the db filtered by chain, component ids and/or protocol system.
    // The filters are applied in the following order: component ids, protocol system, chain. If
    // component ids are provided, the protocol system filter is ignored. The chain filter is
    // always applied.
    pub async fn get_protocol_states(
        &self,
        chain: &Chain,
        at: Option<Version>,
        // TODO: change to &str
        system: Option<String>,
        ids: Option<&[&str]>,
        conn: &mut AsyncPgConnection,
    ) -> Result<Vec<models::protocol::ProtocolComponentState>, StorageError> {
        let chain_db_id = self.get_chain_id(chain);
        let version_ts = match &at {
            Some(version) => Some(maybe_lookup_version_ts(version, conn).await?),
            None => None,
        };

        match (ids, system) {
            (Some(ids), Some(_)) => {
                warn!("Both protocol IDs and system were provided. System will be ignored.");
                self._decode_protocol_states(
                    orm::ProtocolState::by_id(ids, chain_db_id, version_ts, conn).await,
                    ids.join(",").as_str(),
                )
            }
            (Some(ids), _) => self._decode_protocol_states(
                orm::ProtocolState::by_id(ids, chain_db_id, version_ts, conn).await,
                ids.join(",").as_str(),
            ),
            (_, Some(system)) => self._decode_protocol_states(
                orm::ProtocolState::by_protocol_system(
                    system.clone(),
                    chain_db_id,
                    version_ts,
                    conn,
                )
                .await,
                system.to_string().as_str(),
            ),
            _ => self._decode_protocol_states(
                orm::ProtocolState::by_chain(chain_db_id, version_ts, conn).await,
                chain.to_string().as_str(),
            ),
        }
    }

    pub async fn update_protocol_states(
        &self,
        chain: &Chain,
        new: &[(TxHash, &models::protocol::ProtocolComponentStateDelta)],
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        let chain_db_id = self.get_chain_id(chain);
        let new = new
            .iter()
            .map(|(tx, delta)| WithTxHash { entity: delta, tx: Some(tx.to_owned()) })
            .collect::<Vec<_>>();

        let txns: HashMap<Bytes, (i64, i64, NaiveDateTime)> = orm::Transaction::ids_and_ts_by_hash(
            new.iter()
                .filter_map(|u| u.tx.as_ref())
                .collect::<Vec<&TxHash>>()
                .as_slice(),
            conn,
        )
        .await
        .map_err(PostgresError::from)?
        .into_iter()
        .map(|(id, hash, index, ts)| (hash, (id, index, ts)))
        .collect();

        let components: HashMap<String, i64> = orm::ProtocolComponent::ids_by_external_ids(
            new.iter()
                .map(|state| state.component_id.as_str())
                .collect::<Vec<&str>>()
                .as_slice(),
            chain_db_id,
            conn,
        )
        .await
        .map_err(PostgresError::from)?
        .into_iter()
        .map(|(id, external_id)| (external_id, id))
        .collect();

        let mut state_data: Vec<orm::NewProtocolState> = Vec::new();

        for state in new {
            let tx = state
                .tx
                .as_ref()
                .ok_or(StorageError::Unexpected(
                    "Could not reference tx in ProtocolStateDelta object".to_string(),
                ))?;
            let tx_db = txns
                .get(tx)
                .ok_or(StorageError::NotFound("Tx id".to_string(), tx.to_string()))?;

            let component_db_id = *components
                .get(&state.component_id)
                .ok_or(StorageError::NotFound(
                    "Component id".to_string(),
                    state.component_id.to_string(),
                ))?;

            state_data.extend(
                state
                    .updated_attributes
                    .iter()
                    .map(|(attribute, value)| {
                        orm::NewProtocolState::new(
                            component_db_id,
                            attribute,
                            Some(value),
                            tx_db.0,
                            tx_db.2,
                        )
                    }),
            );

            // invalidated db entities for deleted attributes
            for attr in &state.deleted_attributes {
                // PERF: slow but required due to diesel restrictions
                diesel::update(schema::protocol_state::table)
                    .filter(schema::protocol_state::protocol_component_id.eq(component_db_id))
                    .filter(schema::protocol_state::attribute_name.eq(attr))
                    .filter(schema::protocol_state::valid_to.is_null())
                    .set(schema::protocol_state::valid_to.eq(tx_db.2))
                    .execute(conn)
                    .await
                    .map_err(PostgresError::from)?;
            }
        }

        // insert the prepared protocol state deltas
        if !state_data.is_empty() {
            apply_delta_versioning::<_, orm::ProtocolState>(&mut state_data, conn).await?;
            diesel::insert_into(schema::protocol_state::table)
                .values(&state_data)
                .execute(conn)
                .await
                .map_err(PostgresError::from)?;
        }
        Ok(())
    }

    pub async fn get_tokens(
        &self,
        chain: Chain,
        addresses: Option<&[&Address]>,
        pagination_params: Option<&PaginationParams>,
        conn: &mut AsyncPgConnection,
    ) -> Result<Vec<models::token::CurrencyToken>, StorageError> {
        use super::schema::{account::dsl::*, token::dsl::*};
        let chain_db_id = self.get_chain_id(&chain);
        let mut query = token
            .inner_join(account)
            .select((token::all_columns(), schema::account::address))
            .filter(schema::account::chain_id.eq(chain_db_id))
            .into_boxed();

        if let Some(addrs) = addresses {
            query = query.filter(schema::account::address.eq_any(addrs));
        }

        if let Some(pagination) = pagination_params {
            let offset = pagination.page * pagination.page_size;
            query = query
                .limit(pagination.page_size)
                .offset(offset);
        }

        let results = query
            .order(schema::token::symbol.asc())
            .load::<(orm::Token, Address)>(conn)
            .await
            .map_err(|err| storage_error_from_diesel(err, "Token", &chain.to_string(), None))?;

        let tokens: Result<Vec<models::token::CurrencyToken>, StorageError> = results
            .into_iter()
            .map(|(orm_token, address_)| {
                let gas_usage: Vec<_> = orm_token
                    .gas
                    .iter()
                    .map(|u| u.map(|g| g as u64))
                    .collect();
                Ok(models::token::CurrencyToken::new(
                    &address_,
                    orm_token.symbol.as_str(),
                    orm_token.decimals as u32,
                    orm_token.tax as u64,
                    gas_usage.as_slice(),
                    chain,
                    orm_token.quality as u32,
                ))
            })
            .collect();
        tokens
    }

    pub async fn add_tokens(
        &self,
        tokens: &[models::token::CurrencyToken],
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        let titles: Vec<String> = tokens
            .iter()
            .map(|token| {
                format!("{:?}_{}", token.chain, token.symbol)
                    .graphemes(true)
                    .take(255)
                    .collect::<String>()
            })
            .collect();

        let addresses: Vec<_> = tokens
            .iter()
            .map(|token| token.address.clone())
            .collect();

        let new_accounts: Vec<NewAccount> = tokens
            .iter()
            .zip(titles.iter())
            .zip(addresses.iter())
            .map(|((token, title), address)| {
                let chain_id = self.get_chain_id(&token.chain);
                NewAccount {
                    title,
                    address,
                    chain_id,
                    creation_tx: None,
                    created_at: None,
                    deleted_at: None,
                }
            })
            .collect();

        diesel::insert_into(schema::account::table)
            .values(&new_accounts)
            .on_conflict((schema::account::address, schema::account::chain_id))
            .do_nothing()
            .execute(conn)
            .await
            .map_err(|err| storage_error_from_diesel(err, "Account", "batch", None))?;

        let accounts: Vec<Account> = schema::account::table
            .filter(schema::account::address.eq_any(addresses))
            .select(Account::as_select())
            .get_results::<Account>(conn)
            .await
            .map_err(|err| storage_error_from_diesel(err, "Account", "retrieve", None))?;

        let account_map: HashMap<(Vec<u8>, i64), i64> = accounts
            .iter()
            .map(|account| ((account.address.clone().to_vec(), account.chain_id), account.id))
            .collect();

        let new_tokens: Vec<orm::NewToken> = tokens
            .iter()
            .map(|token| {
                let token_chain_id = self.get_chain_id(&token.chain);
                let account_key = (token.address.to_vec(), token_chain_id);

                let account_id = *account_map
                    .get(&account_key)
                    .expect("Account ID not found");

                orm::NewToken::from_token(account_id, token)
            })
            .collect();

        diesel::insert_into(schema::token::table)
            .values(&new_tokens)
            // .on_conflict(..).do_nothing() is necessary to ignore updating duplicated entries
            .on_conflict(schema::token::account_id)
            .do_nothing()
            .execute(conn)
            .await
            .map_err(|err| storage_error_from_diesel(err, "Token", "batch", None))?;

        Ok(())
    }

    pub async fn add_component_balances(
        &self,
        component_balances: &[models::protocol::ComponentBalance],
        chain: &Chain,
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        use super::schema::{account::dsl::*, token::dsl::*};

        let chain_db_id = self.get_chain_id(chain);
        let mut new_component_balances = Vec::new();
        let token_addresses: Vec<Address> = component_balances
            .iter()
            .map(|component_balance| component_balance.token.clone())
            .collect();
        let token_ids: HashMap<Address, i64> = token
            .inner_join(account)
            .select((schema::account::address, schema::token::id))
            .filter(schema::account::address.eq_any(&token_addresses))
            .load::<(Address, i64)>(conn)
            .await
            .map_err(PostgresError::from)?
            .into_iter()
            .collect();

        let modify_txs = component_balances
            .iter()
            .map(|component_balance| component_balance.modify_tx.clone())
            .collect::<Vec<TxHash>>();
        let txn_hashes = modify_txs.iter().collect::<Vec<_>>();
        let transaction_ids_and_ts: HashMap<TxHash, (i64, NaiveDateTime)> =
            orm::Transaction::ids_and_ts_by_hash(txn_hashes.as_ref(), conn)
                .await
                .map_err(PostgresError::from)?
                .into_iter()
                .map(|(db_id, hash, _, ts)| (hash, (db_id, ts)))
                .collect();

        let external_ids: Vec<&str> = component_balances
            .iter()
            .map(|component_balance| component_balance.component_id.as_str())
            .collect();

        let protocol_component_ids: HashMap<String, i64> =
            orm::ProtocolComponent::ids_by_external_ids(&external_ids, chain_db_id, conn)
                .await
                .map_err(PostgresError::from)?
                .into_iter()
                .map(|(component_id, external_id)| (external_id, component_id))
                .collect();

        for component_balance in component_balances.iter() {
            let token_id = token_ids[&component_balance.token];
            let (transaction_id, transaction_ts) =
                transaction_ids_and_ts[&component_balance.modify_tx];
            let protocol_component_id = protocol_component_ids[&component_balance.component_id];

            let new_component_balance = orm::NewComponentBalance::new(
                token_id,
                component_balance.new_balance.clone(),
                component_balance.balance_float,
                None,
                transaction_id,
                protocol_component_id,
                transaction_ts,
            );
            new_component_balances.push(new_component_balance);
        }

        if !component_balances.is_empty() {
            apply_delta_versioning::<_, orm::ComponentBalance>(&mut new_component_balances, conn)
                .await?;
            diesel::insert_into(schema::component_balance::table)
                .values(&new_component_balances)
                .execute(conn)
                .await
                .map_err(|err| storage_error_from_diesel(err, "ComponentBalance", "batch", None))?;
        }
        Ok(())
    }

    #[instrument(skip(self, conn))]
    pub async fn get_balance_deltas(
        &self,
        chain: &Chain,
        start_version: Option<&BlockOrTimestamp>,
        target_version: &BlockOrTimestamp,
        conn: &mut AsyncPgConnection,
    ) -> Result<Vec<models::protocol::ComponentBalance>, StorageError> {
        use schema::component_balance::dsl::*;
        let chain_id = self.get_chain_id(chain);

        let start_ts = match start_version {
            Some(version) => maybe_lookup_block_ts(version, conn).await?,
            None => Utc::now().naive_utc(),
        };
        let target_ts = maybe_lookup_block_ts(target_version, conn).await?;

        let res = if start_ts <= target_ts {
            // Going forward
            //                  ]     changes to update   ]
            // -----------------|--------------------------|
            //                start                     target
            // We query for balance updates between start and target version.
            component_balance
                .inner_join(schema::protocol_component::table)
                .inner_join(schema::transaction::table)
                .inner_join(schema::token::table.inner_join(schema::account::table))
                .filter(
                    schema::protocol_component::chain_id
                        .eq(chain_id)
                        .and(valid_from.gt(start_ts))
                        .and(valid_from.le(target_ts))
                        .and(
                            valid_to
                                .gt(target_ts)
                                .or(valid_to.is_null()),
                        ),
                )
                .order_by((
                    protocol_component_id,
                    token_id,
                    valid_from.desc(),
                    schema::transaction::index.desc(),
                ))
                .distinct_on((protocol_component_id, token_id))
                .select((
                    schema::protocol_component::external_id,
                    schema::account::address,
                    new_balance,
                    balance_float,
                    schema::transaction::hash,
                ))
                .get_results::<(String, Address, Balance, f64, TxHash)>(conn)
                .await
                .map_err(PostgresError::from)?
                .into_iter()
                .map(|(component_id, address, balance, bal_f64, tx)| {
                    models::protocol::ComponentBalance::new(
                        address,
                        balance,
                        bal_f64,
                        tx,
                        component_id.as_str(),
                    )
                })
                .collect()
        } else {
            // Going backwards
            //                  ]     changes to revert    ]
            // -----------------|--------------------------|
            //                target                     start
            // We query for the previous values of all (protocol_component, token) pairs updated
            // between start and target version.
            component_balance
                .inner_join(schema::protocol_component::table)
                .inner_join(schema::transaction::table)
                .inner_join(schema::token::table.inner_join(schema::account::table))
                .filter(
                    schema::protocol_component::chain_id
                        .eq(chain_id)
                        .and(valid_from.ge(target_ts))
                        .and(valid_from.lt(start_ts))
                        .and(
                            valid_to
                                .gt(target_ts)
                                .or(valid_to.is_null()),
                        ),
                )
                .order_by((
                    protocol_component_id,
                    token_id,
                    valid_from.asc(),
                    schema::transaction::index.asc(),
                ))
                .distinct_on((protocol_component_id, token_id))
                .select((
                    schema::protocol_component::external_id,
                    schema::account::address,
                    previous_value,
                    schema::transaction::hash,
                ))
                .get_results::<(String, Address, Balance, TxHash)>(conn)
                .await
                .map_err(PostgresError::from)?
                .into_iter()
                .map(|(component_id, address, balance, tx)| {
                    models::protocol::ComponentBalance::new(
                        address,
                        balance,
                        f64::NAN,
                        tx,
                        component_id.as_str(),
                    )
                })
                .collect()
        };
        Ok(res)
    }

    pub async fn get_balances(
        &self,
        chain: &Chain,
        ids: Option<&[&str]>,
        at: Option<&Version>,
        conn: &mut AsyncPgConnection,
    ) -> Result<HashMap<String, HashMap<Bytes, f64>>, StorageError> {
        let version_ts = match &at {
            Some(version) => Some(maybe_lookup_version_ts(version, conn).await?),
            None => None,
        };
        let chain_id = self.get_chain_id(chain);

        let mut q = schema::component_balance::table
            .inner_join(schema::protocol_component::table)
            .inner_join(schema::token::table.inner_join(schema::account::table))
            .select((
                schema::protocol_component::external_id,
                schema::account::address,
                schema::component_balance::balance_float,
            ))
            .filter(schema::protocol_component::chain_id.eq(chain_id))
            .filter(
                schema::component_balance::valid_to
                    .gt(version_ts) // if version_ts is None, diesel equates this expression to "False"
                    .or(schema::component_balance::valid_to.is_null()),
            )
            .into_boxed();

        // if a version timestamp is provided, we want to filter by valid_from <= version_ts
        if let Some(ts) = version_ts {
            q = q.filter(schema::component_balance::valid_from.le(ts));
        }

        if let Some(external_ids) = ids {
            q = q.filter(schema::protocol_component::external_id.eq_any(external_ids))
        }

        let balances: HashMap<_, _> = q
            .get_results::<(String, Bytes, f64)>(conn)
            .await
            .map_err(PostgresError::from)?
            .into_iter()
            .group_by(|e| e.0.clone())
            .into_iter()
            .map(|(cid, group)| {
                (
                    cid,
                    group
                        .map(|(_, addr, bal)| (addr, bal))
                        .collect::<HashMap<_, _>>(),
                )
            })
            .collect();

        Ok(balances)
    }

    pub async fn get_protocol_states_delta(
        &self,
        chain: &Chain,
        start_version: Option<&BlockOrTimestamp>,
        end_version: &BlockOrTimestamp,
        conn: &mut AsyncPgConnection,
    ) -> Result<Vec<models::protocol::ProtocolComponentStateDelta>, StorageError> {
        let start_ts = match start_version {
            Some(version) => maybe_lookup_block_ts(version, conn).await?,
            None => Utc::now().naive_utc(),
        };
        let end_ts = maybe_lookup_block_ts(end_version, conn).await?;

        if start_ts <= end_ts {
            // Going forward
            //                  ]     changes to update   ]
            // -----------------|--------------------------|
            //                start                     target
            // We query for state updates between start and target version. We also query for
            // deleted states between start and target version. We then merge the two
            // sets of results.

            let chain_db_id = self.get_chain_id(chain);

            // fetch updated component attributes
            let state_updates =
                orm::ProtocolState::forward_deltas_by_chain(chain_db_id, start_ts, end_ts, conn)
                    .await
                    .map_err(|err| {
                        storage_error_from_diesel(
                            err,
                            "ProtocolStates",
                            chain.to_string().as_str(),
                            None,
                        )
                    })?;

            // fetch deleted component attributes
            let deleted_attrs = orm::ProtocolState::deleted_attributes_by_chain(
                chain_db_id,
                start_ts,
                end_ts,
                conn,
            )
            .await
            .map_err(|err| {
                storage_error_from_diesel(err, "ProtocolStates", chain.to_string().as_str(), None)
            })?;

            // Decode final state deltas. We can assume both the deleted_attrs and state_updates
            // are sorted by component_id and transaction index. Therefore we can use slices to
            // iterate over the data in groups of component_id. To do this we first need to collect
            // an ordered set of the component ids, then we can loop through deleted_attrs and
            // state_updates in parallel, creating a slice for each component_id.

            // Get sets of component_ids from state_updates and deleted_attrs
            let state_updates_ids: BTreeSet<_> = state_updates
                .iter()
                .map(|item| &item.1)
                .collect();
            let deleted_attrs_ids: BTreeSet<_> = deleted_attrs
                .iter()
                .map(|item| &item.0)
                .collect();
            // Union of two sets gives us a sorted set of all unique component_ids
            let mut all_component_ids = state_updates_ids.clone();
            all_component_ids.append(&mut deleted_attrs_ids.clone());

            let mut protocol_states_delta = Vec::new();

            // index trackers to iterate over the state updates and deleted attributes in parallel
            let (mut updates_index, mut deletes_index) = (0, 0);

            for current_component_id in all_component_ids {
                let component_start = updates_index;

                // Iterate over states until the component_id no longer matches the current
                // component id
                while updates_index < state_updates.len() &&
                    &state_updates[updates_index].1 == current_component_id
                {
                    updates_index += 1;
                }

                let deleted_start = deletes_index;
                // Iterate over deleted attributes until the component_id no longer matches the
                // current component id
                while deletes_index < deleted_attrs.len() &&
                    &deleted_attrs[deletes_index].0 == current_component_id
                {
                    deletes_index += 1;
                }

                let states_slice = &state_updates[component_start..updates_index];
                let deleted_slice = &deleted_attrs[deleted_start..deletes_index];

                let state_delta = models::protocol::ProtocolComponentStateDelta::new(
                    current_component_id,
                    states_slice
                        .iter()
                        .map(|x| (x.0.attribute_name.clone(), x.0.attribute_value.clone()))
                        .collect(),
                    deleted_slice
                        .iter()
                        .map(|x| x.1.clone())
                        .collect(),
                );

                protocol_states_delta.push(state_delta);
            }
            Ok(protocol_states_delta)
        } else {
            // Going backwards
            //                  ]     changes to revert    ]
            // -----------------|--------------------------|
            //                target                     start
            // We query for the previous values of all component attributes updated between
            // start and target version.

            let chain_db_id = self.get_chain_id(chain);

            // fetch reverse attribute changes
            let result =
                orm::ProtocolState::reverse_delta_by_chain(chain_db_id, start_ts, end_ts, conn)
                    .await
                    .map_err(|err| {
                        storage_error_from_diesel(
                            err,
                            "ProtocolStates",
                            chain.to_string().as_str(),
                            None,
                        )
                    })?;

            // Decode final state deltas. We can assume result is sorted by component_id and
            // transaction index. Therefore we can use slices to iterate over the data in groups of
            // component_id.

            let mut deltas = Vec::new();

            let mut index = 0;
            while index < result.len() {
                let component_start = index;
                let current_component_id = &result[index].0;

                // Iterate until the component_id changes
                while index < result.len() && &result[index].0 == current_component_id {
                    index += 1;
                }

                let states_slice = &result[component_start..index];

                // sort through state updates and deletions
                let mut updates = HashMap::new();
                let mut deleted = HashSet::new();
                for (_, attribute, prev_value) in states_slice {
                    if let Some(value) = prev_value {
                        // if prev_value is not null, then the attribute was updated and
                        // must be reverted via a reversed update
                        updates.insert(attribute.clone(), value.clone());
                    } else {
                        // if prev_value is null, then the attribute was created and must be
                        // deleted on revert
                        deleted.insert(attribute.clone());
                    }
                }
                let state_delta = models::protocol::ProtocolComponentStateDelta::new(
                    current_component_id,
                    updates,
                    deleted,
                );

                deltas.push(state_delta);
            }

            Ok(deltas)
        }
    }

    pub async fn get_token_prices(
        &self,
        chain: &Chain,
        conn: &mut AsyncPgConnection,
    ) -> Result<HashMap<Bytes, f64>, StorageError> {
        use schema::token_price::dsl::*;
        let chain_id = self.get_chain_id(chain);
        Ok(token_price
            .inner_join(schema::token::table.inner_join(schema::account::table))
            .select((schema::account::address, price))
            .filter(schema::account::chain_id.eq(chain_id))
            .get_results::<(Bytes, f64)>(conn)
            .await
            .map_err(|err| storage_error_from_diesel(err, "TokenPrice", &chain.to_string(), None))?
            .into_iter()
            .collect::<HashMap<_, _>>())
    }

    pub async fn upsert_component_tvl(
        &self,
        chain: &Chain,
        tvl_values: &HashMap<String, f64>,
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        let chain_id = self.get_chain_id(chain);
        let external_ids = tvl_values
            .keys()
            .map(|s| s.as_str())
            .collect::<Vec<_>>();
        let external_db_id_map =
            orm::ProtocolComponent::ids_by_external_ids(&external_ids, chain_id, conn)
                .await
                .map_err(PostgresError::from)?
                .into_iter()
                .map(|(a, b)| (b, a))
                .collect::<HashMap<_, _>>();

        let upsert_map: HashMap<_, _> = tvl_values
            .iter()
            .filter_map(|(component_id, v)| {
                if let Some(db_id) = external_db_id_map.get(component_id) {
                    Some((*db_id, *v))
                } else {
                    warn!(?component_id, "Tried to upsert tvl for unknown component!");
                    None
                }
            })
            .collect();
        ComponentTVL::upsert_many(&upsert_map)
            .execute(conn)
            .await
            .map_err(PostgresError::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tycho_core::storage::BlockIdentifier;

    use diesel_async::AsyncConnection;
    use ethers::types::U256;
    use rstest::rstest;
    use serde_json::json;

    use crate::postgres::db_fixtures;
    use ethers::prelude::H256;
    use std::str::FromStr;

    type EVMGateway = PostgresGateway;

    const WETH: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const USDT: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    const LUSD: &str = "0x5f98805A4E8be255a32880FDeC7F6728C6568bA0";
    const DAI: &str = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
    const ZKSYNC_PEPE: &str = "0xFD282F16a64c6D304aC05d1A58Da15bed0467c71";

    async fn setup_db() -> AsyncPgConnection {
        let db_url = std::env::var("DATABASE_URL").unwrap();
        let mut conn = AsyncPgConnection::establish(&db_url)
            .await
            .unwrap();
        conn.begin_test_transaction()
            .await
            .unwrap();

        conn
    }

    /// This sets up the data needed to test the gateway. The setup is structured such that each
    /// protocol state's historical changes are kept together this makes it easy to reason about
    /// that change an account should have at each version Please note that if you change
    /// something here, also update the state fixtures right below, which contain protocol states
    /// at each version.
    async fn setup_data(conn: &mut AsyncPgConnection) -> Vec<String> {
        let chain_id = db_fixtures::insert_chain(conn, "ethereum").await;
        let chain_id_sn = db_fixtures::insert_chain(conn, "starknet").await;
        let chain_id_zk = db_fixtures::insert_chain(conn, "zksync").await;
        let blk = db_fixtures::insert_blocks(conn, chain_id).await;
        let tx_hashes = [
            "0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945".to_string(),
            "0x794f7df7a3fe973f1583fbb92536f9a8def3a89902439289315326c04068de54".to_string(),
            "0x3108322284d0a89a7accb288d1a94384d499504fe7e04441b0706c7628dee7b7".to_string(),
            "0x50449de1973d86f21bfafa7c72011854a7e33a226709dc3e2e4edcca34188388".to_string(),
        ];

        let txn = db_fixtures::insert_txns(
            conn,
            &[
                (blk[0], 1i64, &tx_hashes[0]),
                (blk[0], 2i64, &tx_hashes[1]),
                // ----- Block 01 LAST
                (blk[1], 1i64, &tx_hashes[2]),
                (blk[1], 2i64, &tx_hashes[3]),
                // ----- Block 02 LAST
            ],
        )
        .await;

        let protocol_system_id_ambient =
            db_fixtures::insert_protocol_system(conn, "ambient".to_owned()).await;
        let protocol_system_id_zz =
            db_fixtures::insert_protocol_system(conn, "zigzag".to_owned()).await;

        let protocol_type_id = db_fixtures::insert_protocol_type(
            conn,
            "Pool",
            Some(models::FinancialType::Swap),
            None,
            Some(models::ImplementationType::Custom),
        )
        .await;

        // insert tokens
        // Ethereum
        let (account_id_weth, weth_id) =
            db_fixtures::insert_token(conn, chain_id, WETH.trim_start_matches("0x"), "WETH", 18)
                .await;
        let (_, usdc_id) =
            db_fixtures::insert_token(conn, chain_id, USDC.trim_start_matches("0x"), "USDC", 6)
                .await;
        let (_, dai_id) =
            db_fixtures::insert_token(conn, chain_id, DAI.trim_start_matches("0x"), "DAI", 18)
                .await;
        let (_, lusd_id) =
            db_fixtures::insert_token(conn, chain_id, LUSD.trim_start_matches("0x"), "LUSD", 18)
                .await;

        // ZK Sync
        db_fixtures::insert_token(
            conn,
            chain_id_zk,
            ZKSYNC_PEPE.trim_start_matches("0x"),
            "PEPE",
            6,
        )
        .await;

        // insert token prices
        db_fixtures::insert_token_prices(&[(weth_id, 1.0), (usdc_id, 0.0005)], conn).await;

        let contract_code_id = db_fixtures::insert_contract_code(
            conn,
            account_id_weth,
            txn[0],
            Bytes::from_str("C0C0C0").unwrap(),
        )
        .await;

        // components and their balances
        // tvl will be 2.0
        let protocol_component_id = db_fixtures::insert_protocol_component(
            conn,
            "state1",
            chain_id,
            protocol_system_id_ambient,
            protocol_type_id,
            txn[0],
            Some(vec![weth_id, usdc_id]),
            Some(vec![contract_code_id]),
        )
        .await;
        db_fixtures::insert_component_balance(
            conn,
            Bytes::from(U256::exp10(18)),
            Bytes::from(U256::zero()),
            1e18,
            weth_id,
            txn[0],
            protocol_component_id,
            None,
        )
        .await;
        db_fixtures::insert_component_balance(
            conn,
            Bytes::from(U256::from(2000) * U256::exp10(6)),
            Bytes::from(U256::zero()),
            2000.0 * 1e6,
            usdc_id,
            txn[0],
            protocol_component_id,
            None,
        )
        .await;
        // tvl will be 1.0 cause we miss dai price
        let protocol_component_id2 = db_fixtures::insert_protocol_component(
            conn,
            "state3",
            chain_id,
            protocol_system_id_ambient,
            protocol_type_id,
            txn[0],
            Some(vec![weth_id, dai_id]),
            Some(vec![contract_code_id]),
        )
        .await;
        db_fixtures::insert_component_balance(
            conn,
            Bytes::from(U256::exp10(18)),
            Bytes::from(U256::zero()),
            1e18,
            weth_id,
            txn[0],
            protocol_component_id2,
            None,
        )
        .await;
        db_fixtures::insert_component_balance(
            conn,
            Bytes::from(U256::from(2000) * U256::exp10(18)),
            Bytes::from(U256::zero()),
            2000.0 * 1e18,
            dai_id,
            txn[0],
            protocol_component_id2,
            None,
        )
        .await;
        // tvl will be 1.0 cause we miss lusd price
        let protocol_component_id3 = db_fixtures::insert_protocol_component(
            conn,
            "state2",
            chain_id_sn,
            protocol_system_id_zz,
            protocol_type_id,
            txn[1],
            Some(vec![lusd_id, usdc_id]),
            Some(vec![contract_code_id]),
        )
        .await;
        db_fixtures::insert_component_balance(
            conn,
            Bytes::from(U256::from(2000) * U256::exp10(18)),
            Bytes::from(U256::zero()),
            1e18,
            lusd_id,
            txn[1],
            protocol_component_id3,
            None,
        )
        .await;
        db_fixtures::insert_component_balance(
            conn,
            Bytes::from(U256::from(2000) * U256::exp10(6)),
            Bytes::from(U256::zero()),
            2000.0 * 1e6,
            usdc_id,
            txn[1],
            protocol_component_id3,
            None,
        )
        .await;
        // component without balances and thus without tvl
        db_fixtures::insert_protocol_component(
            conn,
            "no_tvl",
            chain_id,
            protocol_system_id_ambient,
            protocol_type_id,
            txn[0],
            Some(vec![weth_id, dai_id]),
            Some(vec![contract_code_id]),
        )
        .await;

        // protocol state for state1-reserve1
        db_fixtures::insert_protocol_state(
            conn,
            protocol_component_id,
            txn[0],
            "reserve1".to_owned(),
            Bytes::from(U256::from(1100)),
            None,
            Some(txn[2]),
        )
        .await;

        // protocol state for state1-reserve2
        db_fixtures::insert_protocol_state(
            conn,
            protocol_component_id,
            txn[0],
            "reserve2".to_owned(),
            Bytes::from(U256::from(500)),
            None,
            None,
        )
        .await;

        // protocol state update for state1-reserve1
        db_fixtures::insert_protocol_state(
            conn,
            protocol_component_id,
            txn[3],
            "reserve1".to_owned(),
            Bytes::from(U256::from(1000)),
            Some(Bytes::from(U256::from(1100))),
            None,
        )
        .await;

        db_fixtures::calculate_component_tvl(conn).await;
        tx_hashes.to_vec()
    }

    fn protocol_state() -> models::protocol::ProtocolComponentState {
        let attributes: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(U256::from(1000))),
            ("reserve2".to_owned(), Bytes::from(U256::from(500))),
        ]
        .into_iter()
        .collect();
        models::protocol::ProtocolComponentState::new("state1", attributes, None)
    }

    #[rstest]
    #[case::by_chain(None, None)]
    #[case::by_system(Some("ambient".to_string()), None)]
    #[case::by_ids(None, Some(vec ! ["state1"]))]
    #[tokio::test]
    async fn test_get_protocol_states(
        #[case] system: Option<String>,
        #[case] ids: Option<Vec<&str>>,
    ) {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;

        let expected = vec![protocol_state()];

        let gateway = EVMGateway::from_connection(&mut conn).await;

        let result = gateway
            .get_protocol_states(&Chain::Ethereum, None, system, ids.as_deref(), &mut conn)
            .await
            .unwrap();

        assert_eq!(result, expected)
    }

    #[tokio::test]
    async fn test_get_protocol_states_at() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;

        let gateway = EVMGateway::from_connection(&mut conn).await;

        let mut protocol_state = protocol_state();
        let attributes: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(U256::from(1100))),
            ("reserve2".to_owned(), Bytes::from(U256::from(500))),
        ]
        .into_iter()
        .collect();
        protocol_state.attributes = attributes;
        let expected = vec![protocol_state];

        let result = gateway
            .get_protocol_states(
                &Chain::Ethereum,
                Some(Version::from_block_number(Chain::Ethereum, 1)),
                None,
                None,
                &mut conn,
            )
            .await
            .unwrap();

        assert_eq!(result, expected)
    }

    fn protocol_state_delta() -> models::protocol::ProtocolComponentStateDelta {
        let attributes: HashMap<String, Bytes> =
            vec![("reserve1".to_owned(), Bytes::from(U256::from(1000)))]
                .into_iter()
                .collect();
        models::protocol::ProtocolComponentStateDelta::new("state3", attributes, HashSet::new())
    }

    #[tokio::test]
    async fn test_update_protocol_states() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;

        let gateway = EVMGateway::from_connection(&mut conn).await;
        let chain = Chain::Ethereum;

        // set up deletable attribute state
        let protocol_component_id = schema::protocol_component::table
            .filter(schema::protocol_component::external_id.eq("state2"))
            .select(schema::protocol_component::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch protocol component id");
        let txn_id = schema::transaction::table
            .filter(
                schema::transaction::hash.eq(H256::from_str(
                    "0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945",
                )
                .expect("valid txhash")
                .as_bytes()
                .to_owned()),
            )
            .select(schema::transaction::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch transaction id");
        db_fixtures::insert_protocol_state(
            &mut conn,
            protocol_component_id,
            txn_id,
            "deletable".to_owned(),
            Bytes::from(U256::from(1000)),
            None,
            None,
        )
        .await;

        // update
        let mut new_state1 = protocol_state_delta();
        let attributes1: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(U256::from(700))),
            ("reserve2".to_owned(), Bytes::from(U256::from(700))),
        ]
        .into_iter()
        .collect();
        new_state1
            .updated_attributes
            .clone_from(&attributes1);
        new_state1.deleted_attributes = vec!["deletable".to_owned()]
            .into_iter()
            .collect();
        let tx_1: H256 = "0x3108322284d0a89a7accb288d1a94384d499504fe7e04441b0706c7628dee7b7"
            .parse()
            .unwrap();

        // newer update
        let mut new_state2 = protocol_state_delta();
        let attributes2: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(U256::from(800))),
            ("reserve2".to_owned(), Bytes::from(U256::from(800))),
        ]
        .into_iter()
        .collect();
        new_state2
            .updated_attributes
            .clone_from(&attributes2);
        let tx_2: H256 = "0x50449de1973d86f21bfafa7c72011854a7e33a226709dc3e2e4edcca34188388"
            .parse()
            .unwrap();

        // update the protocol state
        gateway
            .update_protocol_states(
                &chain,
                &[(tx_1.into(), &new_state1), (tx_2.into(), &new_state2)],
                &mut conn,
            )
            .await
            .expect("Failed to update protocol states");

        // check the correct state is considered the valid one
        let db_states = gateway
            .get_protocol_states(
                &chain,
                None,
                None,
                Some(&[new_state1.component_id.as_str()]),
                &mut conn,
            )
            .await
            .expect("Failed ");
        let mut expected_state = protocol_state();
        expected_state.attributes = attributes2;
        expected_state
            .component_id
            .clone_from(&new_state1.component_id);
        assert_eq!(db_states[0], expected_state);

        // fetch the older state from the db and check it's valid_to is set correctly
        let tx_hash1: Bytes = tx_1.as_bytes().into();
        let older_state = schema::protocol_state::table
            .inner_join(schema::protocol_component::table)
            .inner_join(schema::transaction::table)
            .filter(schema::transaction::hash.eq(tx_hash1))
            .filter(schema::protocol_component::external_id.eq(new_state1.component_id.as_str()))
            .select(orm::ProtocolState::as_select())
            .first::<orm::ProtocolState>(&mut conn)
            .await
            .expect("Failed to fetch protocol state");
        assert_eq!(older_state.attribute_value, Bytes::from(U256::from(700)));
        // fetch the newer state from the db to compare the valid_from
        let tx_hash2: Bytes = tx_2.as_bytes().into();
        let newer_state = schema::protocol_state::table
            .inner_join(schema::protocol_component::table)
            .inner_join(schema::transaction::table)
            .filter(schema::transaction::hash.eq(tx_hash2))
            .filter(schema::protocol_component::external_id.eq(new_state1.component_id.as_str()))
            .select(orm::ProtocolState::as_select())
            .first::<orm::ProtocolState>(&mut conn)
            .await
            .expect("Failed to fetch protocol state");
        assert_eq!(older_state.valid_to, Some(newer_state.valid_from));
    }

    #[tokio::test]
    async fn test_get_balance_deltas() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let protocol_external_id = String::from("state1");
        // set up changed balances
        let protocol_component_id = schema::protocol_component::table
            .filter(schema::protocol_component::external_id.eq(protocol_external_id.clone()))
            .select(schema::protocol_component::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch protocol component id");
        let (token_id, account_id) = schema::token::table
            .filter(schema::token::symbol.eq("WETH"))
            .select((schema::token::id, schema::token::account_id))
            .first::<(i64, i64)>(&mut conn)
            .await
            .expect("Failed to fetch token id and acccount id");
        let token_address = schema::account::table
            .filter(schema::account::id.eq(account_id))
            .select(schema::account::address)
            .first::<Address>(&mut conn)
            .await
            .expect("Failed to fetch token address");

        let from_tx_hash =
            H256::from_str("0x794f7df7a3fe973f1583fbb92536f9a8def3a89902439289315326c04068de54")
                .expect("valid txhash");

        let from_txn_id = schema::transaction::table
            .filter(schema::transaction::hash.eq(from_tx_hash.clone().as_bytes()))
            .select(schema::transaction::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch transaction id");

        let to_tx_hash =
            Bytes::from("0x50449de1973d86f21bfafa7c72011854a7e33a226709dc3e2e4edcca34188388");

        let to_txn_id = schema::transaction::table
            .filter(schema::transaction::hash.eq(&to_tx_hash))
            .select(schema::transaction::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch transaction id");

        db_fixtures::insert_component_balance(
            &mut conn,
            Balance::from(U256::from(1000)),
            Balance::from(U256::from(0)),
            1000.0,
            token_id,
            from_txn_id,
            protocol_component_id,
            Some(to_txn_id),
        )
        .await;
        db_fixtures::insert_component_balance(
            &mut conn,
            Balance::from(U256::from(2000)),
            Balance::from(U256::from(1000)),
            2000.0,
            token_id,
            to_txn_id,
            protocol_component_id,
            None,
        )
        .await;

        let gateway = EVMGateway::from_connection(&mut conn).await;

        let expected_forward_deltas: Vec<models::protocol::ComponentBalance> =
            vec![models::protocol::ComponentBalance {
                component_id: protocol_external_id.clone(),
                token: token_address.clone(),
                new_balance: Balance::from(U256::from(2000)),
                balance_float: 2000.0,
                modify_tx: to_tx_hash,
            }];

        // test forward case
        let result = gateway
            .get_balance_deltas(
                &Chain::Ethereum,
                Some(&BlockOrTimestamp::Block(BlockIdentifier::Number((Chain::Ethereum, 1)))),
                &BlockOrTimestamp::Block(BlockIdentifier::Number((Chain::Ethereum, 2))),
                &mut conn,
            )
            .await
            .unwrap();
        assert_eq!(result, expected_forward_deltas);

        let expected_txh =
            Bytes::from("bb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945");
        let expected_backward_deltas: Vec<models::protocol::ComponentBalance> = vec![
            models::protocol::ComponentBalance {
                token: Bytes::from(DAI),
                new_balance: Bytes::from(
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                ),
                balance_float: 0.0,
                modify_tx: expected_txh.clone(),
                component_id: "state3".to_owned(),
            },
            models::protocol::ComponentBalance {
                token: Bytes::from(USDC),
                new_balance: Bytes::from(
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                ),
                balance_float: 0.0,
                modify_tx: expected_txh.clone(),
                component_id: "state1".to_owned(),
            },
            models::protocol::ComponentBalance {
                token: Bytes::from(WETH),
                new_balance: Bytes::from(
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                ),
                balance_float: 0.0,
                modify_tx: expected_txh.clone(),
                component_id: "state1".to_owned(),
            },
            models::protocol::ComponentBalance {
                token: Bytes::from(WETH),
                new_balance: Bytes::from(
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                ),
                balance_float: 0.0,
                modify_tx: expected_txh.clone(),
                component_id: "state3".to_owned(),
            },
        ];

        // test backward case
        let mut result = gateway
            .get_balance_deltas(
                &Chain::Ethereum,
                Some(&BlockOrTimestamp::Block(BlockIdentifier::Number((Chain::Ethereum, 2)))),
                &BlockOrTimestamp::Block(BlockIdentifier::Number((Chain::Ethereum, 1))),
                &mut conn,
            )
            .await
            .unwrap();
        result.sort_unstable_by_key(|e| (e.token.clone(), e.component_id.clone()));
        // fix NaN comparison
        result.iter_mut().for_each(|r| {
            assert!(r.balance_float.is_nan());
            r.balance_float = 0.0;
        });
        assert_eq!(result, expected_backward_deltas);
    }

    #[tokio::test]
    async fn test_get_protocol_states_delta_forward() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;

        // set up deleted attribute state
        let protocol_component_id = schema::protocol_component::table
            .filter(schema::protocol_component::external_id.eq("state1"))
            .select(schema::protocol_component::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch protocol component id");
        let from_txn_id = schema::transaction::table
            .filter(
                schema::transaction::hash.eq(H256::from_str(
                    "0x794f7df7a3fe973f1583fbb92536f9a8def3a89902439289315326c04068de54",
                )
                .expect("valid txhash")
                .as_bytes()
                .to_owned()),
            )
            .select(schema::transaction::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch transaction id");
        let to_txn_id = schema::transaction::table
            .filter(
                schema::transaction::hash.eq(H256::from_str(
                    "0x50449de1973d86f21bfafa7c72011854a7e33a226709dc3e2e4edcca34188388",
                )
                .expect("valid txhash")
                .as_bytes()
                .to_owned()),
            )
            .select(schema::transaction::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch transaction id");
        db_fixtures::insert_protocol_state(
            &mut conn,
            protocol_component_id,
            from_txn_id,
            "deleted".to_owned(),
            Bytes::from(U256::from(1000)),
            None,
            Some(to_txn_id),
        )
        .await;

        // set up deleted attribute different state (one that isn't also updated)
        let protocol_component_id2 = schema::protocol_component::table
            .filter(schema::protocol_component::external_id.eq("state3"))
            .select(schema::protocol_component::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch protocol component id");
        db_fixtures::insert_protocol_state(
            &mut conn,
            protocol_component_id2,
            from_txn_id,
            "deleted2".to_owned(),
            Bytes::from(U256::from(100)),
            None,
            Some(to_txn_id),
        )
        .await;

        let gateway = EVMGateway::from_connection(&mut conn).await;

        // expected result
        let mut state_delta = protocol_state_delta();
        state_delta
            .component_id
            .clone_from(&"state1".to_string());
        state_delta.deleted_attributes = vec!["deleted".to_owned()]
            .into_iter()
            .collect();
        let other_state_delta = models::protocol::ProtocolComponentStateDelta {
            component_id: "state3".to_owned(),
            updated_attributes: HashMap::new(),
            deleted_attributes: vec!["deleted2".to_owned()]
                .into_iter()
                .collect(),
        };
        let expected = vec![state_delta, other_state_delta];

        // test
        let result = gateway
            .get_protocol_states_delta(
                &Chain::Ethereum,
                Some(&BlockOrTimestamp::Block(BlockIdentifier::Number((Chain::Ethereum, 1)))),
                &BlockOrTimestamp::Block(BlockIdentifier::Number((Chain::Ethereum, 2))),
                &mut conn,
            )
            .await
            .unwrap();

        // asserts
        assert_eq!(result, expected)
    }

    #[tokio::test]
    async fn test_get_protocol_states_delta_backward() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;

        // set up newly added attribute state (to be deleted on revert)
        let protocol_component_id = schema::protocol_component::table
            .filter(schema::protocol_component::external_id.eq("state1"))
            .select(schema::protocol_component::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch protocol component id");
        let txn_id = schema::transaction::table
            .filter(
                schema::transaction::hash.eq(H256::from_str(
                    "0x3108322284d0a89a7accb288d1a94384d499504fe7e04441b0706c7628dee7b7",
                )
                .expect("valid txhash")
                .as_bytes()
                .to_owned()),
            )
            .select(schema::transaction::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch transaction id");
        db_fixtures::insert_protocol_state(
            &mut conn,
            protocol_component_id,
            txn_id,
            "to_delete".to_owned(),
            Bytes::from(U256::from(1000)),
            None,
            None,
        )
        .await;

        // set up deleted attribute state (to be created on revert)
        let from_txn_id = schema::transaction::table
            .filter(
                schema::transaction::hash.eq(H256::from_str(
                    "0x794f7df7a3fe973f1583fbb92536f9a8def3a89902439289315326c04068de54",
                )
                .expect("valid txhash")
                .as_bytes()
                .to_owned()),
            )
            .select(schema::transaction::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch transaction id");
        let to_txn_id = schema::transaction::table
            .filter(
                schema::transaction::hash.eq(H256::from_str(
                    "0x50449de1973d86f21bfafa7c72011854a7e33a226709dc3e2e4edcca34188388",
                )
                .expect("valid txhash")
                .as_bytes()
                .to_owned()),
            )
            .select(schema::transaction::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch transaction id");
        db_fixtures::insert_protocol_state(
            &mut conn,
            protocol_component_id,
            from_txn_id,
            "deleted".to_owned(),
            Bytes::from(U256::from(1000)),
            None,
            Some(to_txn_id),
        )
        .await;

        let gateway = EVMGateway::from_connection(&mut conn).await;

        // expected result
        let attributes: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(U256::from(1100))),
            ("deleted".to_owned(), Bytes::from(U256::from(1000))),
        ]
        .into_iter()
        .collect();
        let state_delta = models::protocol::ProtocolComponentStateDelta {
            component_id: "state1".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: vec!["to_delete".to_owned()]
                .into_iter()
                .collect(),
        };
        let expected = vec![state_delta];

        // test
        let result = gateway
            .get_protocol_states_delta(
                &Chain::Ethereum,
                Some(&BlockOrTimestamp::Block(BlockIdentifier::Number((Chain::Ethereum, 2)))),
                &BlockOrTimestamp::Block(BlockIdentifier::Number((Chain::Ethereum, 1))),
                &mut conn,
            )
            .await
            .unwrap();

        // asserts
        assert_eq!(result, expected)
    }

    #[tokio::test]
    async fn test_get_or_create_protocol_system_id() {
        let mut conn = setup_db().await;
        let gw = EVMGateway::from_connection(&mut conn).await;

        let first_id = gw
            ._get_or_create_protocol_system_id("ambient".to_string(), &mut conn)
            .await
            .unwrap();

        let second_id = gw
            ._get_or_create_protocol_system_id("ambient".to_string(), &mut conn)
            .await
            .unwrap();
        assert!(first_id > 0);
        assert_eq!(first_id, second_id);
    }

    #[tokio::test]
    async fn test_add_protocol_type() {
        let mut conn = setup_db().await;
        let gw = EVMGateway::from_connection(&mut conn).await;

        let protocol_type = models::ProtocolType {
            name: "Protocol".to_string(),
            financial_type: FinancialType::Debt,
            attribute_schema: Some(json!({"attribute": "schema"})),
            implementation: ImplementationType::Custom,
        };

        gw.add_protocol_types(&[protocol_type], &mut conn)
            .await
            .unwrap();

        let inserted_data = schema::protocol_type::table
            .filter(schema::protocol_type::name.eq("Protocol"))
            .select(schema::protocol_type::all_columns)
            .first::<orm::ProtocolType>(&mut conn)
            .await
            .unwrap();

        assert_eq!(inserted_data.name, "Protocol".to_string());
        assert_eq!(inserted_data.financial_type, orm::FinancialType::Debt);
        assert_eq!(inserted_data.attribute_schema, Some(json!({"attribute": "schema"})));
        assert_eq!(inserted_data.implementation, orm::ImplementationType::Custom);
    }

    #[tokio::test]
    async fn test_get_tokens() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;

        // get all eth tokens (no address filter)
        let tokens = gw
            .get_tokens(Chain::Ethereum, None, None, &mut conn)
            .await
            .unwrap();
        assert_eq!(tokens.len(), 4);

        // get weth and usdc
        let tokens = gw
            .get_tokens(Chain::Ethereum, Some(&[&WETH.into(), &USDC.into()]), None, &mut conn)
            .await
            .unwrap();
        assert_eq!(tokens.len(), 2);

        // get weth
        let tokens = gw
            .get_tokens(Chain::Ethereum, Some(&[&WETH.into()]), None, &mut conn)
            .await
            .unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].symbol, "WETH".to_string());
        assert_eq!(tokens[0].decimals, 18);
    }

    #[tokio::test]
    async fn test_get_tokens_with_pagination() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;

        // get tokens with pagination
        let tokens = gw
            .get_tokens(
                Chain::Ethereum,
                None,
                Some(&PaginationParams { page: 0, page_size: 1 }),
                &mut conn,
            )
            .await
            .unwrap();
        assert_eq!(tokens.len(), 1);
        let first_token_symbol = tokens[0].symbol.clone();

        // get tokens with 0 page_size
        let tokens = gw
            .get_tokens(
                Chain::Ethereum,
                None,
                Some(&PaginationParams { page: 0, page_size: 0 }),
                &mut conn,
            )
            .await
            .unwrap();
        assert_eq!(tokens.len(), 0);

        // get tokens skipping page
        let tokens = gw
            .get_tokens(
                Chain::Ethereum,
                None,
                Some(&PaginationParams { page: 2, page_size: 1 }),
                &mut conn,
            )
            .await
            .unwrap();
        assert_eq!(tokens.len(), 1);
        assert_ne!(tokens[0].symbol, first_token_symbol);
    }

    #[tokio::test]
    async fn test_get_tokens_zksync() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;

        let tokens = gw
            .get_tokens(Chain::ZkSync, None, None, &mut conn)
            .await
            .unwrap();

        assert_eq!(tokens.len(), 1);
        let expected_token = models::token::CurrencyToken::new(
            &ZKSYNC_PEPE.parse().unwrap(),
            "PEPE",
            6,
            10,
            &[Some(10)],
            Chain::ZkSync,
            0,
        );

        assert_eq!(tokens[0], expected_token);
    }

    #[tokio::test]
    async fn test_add_tokens() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;

        // Insert one new token (USDT) and an existing token (WETH)
        let weth_symbol = "WETH".to_string();
        let old_token = db_fixtures::get_token_by_symbol(&mut conn, weth_symbol.clone()).await;
        let old_weth_account = &orm::Account::by_address(
            &Bytes::from_str(WETH.trim_start_matches("0x")).expect("address ok"),
            &mut conn,
        )
        .await
        .unwrap()[0];

        let usdt_symbol = "USDT".to_string();
        let tokens = [
            models::token::CurrencyToken::new(
                &Bytes::from(USDT),
                usdt_symbol.as_str(),
                6,
                0,
                &[Some(64), None],
                Chain::Ethereum,
                100,
            ),
            models::token::CurrencyToken::new(
                &Bytes::from(WETH),
                weth_symbol.as_str(),
                18,
                0,
                &[Some(100), None],
                Chain::Ethereum,
                100,
            ),
        ];

        gw.add_tokens(&tokens, &mut conn)
            .await
            .unwrap();

        let inserted_token = db_fixtures::get_token_by_symbol(&mut conn, usdt_symbol.clone()).await;
        assert_eq!(inserted_token.symbol, usdt_symbol);
        assert_eq!(inserted_token.decimals, 6);
        let inserted_account = &orm::Account::by_address(
            &Bytes::from_str(USDT.trim_start_matches("0x")).expect("address ok"),
            &mut conn,
        )
        .await
        .unwrap()[0];
        assert_eq!(inserted_account.id, inserted_token.account_id);
        assert_eq!(inserted_account.title, "Ethereum_USDT".to_string());

        // make sure nothing changed on WETH (ids included)
        let new_token = db_fixtures::get_token_by_symbol(&mut conn, weth_symbol.clone()).await;
        assert_eq!(new_token, old_token);
        let updated_weth_account = &orm::Account::by_address(
            &Bytes::from_str(WETH.trim_start_matches("0x")).expect("address ok"),
            &mut conn,
        )
        .await
        .unwrap()[0];
        assert_eq!(updated_weth_account, old_weth_account);
        assert!(inserted_account.id > updated_weth_account.id);
    }

    #[tokio::test]
    async fn test_add_component_balances() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;
        let tx_hash =
            Bytes::from("0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945");
        let component_external_id = "state2".to_owned();
        let base_token = Bytes::from(WETH);
        // Test the case where a previous balance doesn't exist
        let component_balance = models::protocol::ComponentBalance {
            token: base_token.clone(),
            new_balance: Bytes::from(
                "0x000000000000000000000000000000000000000000000000000000000000000c",
            ),
            balance_float: 12.0,
            modify_tx: tx_hash.clone(),
            component_id: component_external_id.clone(),
        };

        gw.add_component_balances(&[component_balance], &Chain::Starknet, &mut conn)
            .await
            .unwrap();

        let inserted_data = schema::component_balance::table
            .select(orm::ComponentBalance::as_select())
            .filter(schema::component_balance::new_balance.eq(Bytes::from(
                "0x000000000000000000000000000000000000000000000000000000000000000c",
            )))
            .first::<orm::ComponentBalance>(&mut conn)
            .await
            .expect("retrieving inserted balance failed!");

        assert_eq!(inserted_data.new_balance, Balance::from(U256::from(12)));
        assert_eq!(inserted_data.previous_value, Balance::from("0x00"),);

        let referenced_token = schema::token::table
            .filter(schema::token::id.eq(inserted_data.token_id))
            .select(orm::Token::as_select())
            .first::<orm::Token>(&mut conn)
            .await
            .expect("failed to get associated token");
        assert_eq!(referenced_token.symbol, "WETH");

        let referenced_component = schema::protocol_component::table
            .filter(schema::protocol_component::id.eq(inserted_data.protocol_component_id))
            .select(orm::ProtocolComponent::as_select())
            .first::<orm::ProtocolComponent>(&mut conn)
            .await
            .expect("failed to get associated component");
        assert_eq!(referenced_component.external_id, "state2");

        // Test the case where there was a previous balance
        let new_tx_hash =
            Bytes::from("0x3108322284d0a89a7accb288d1a94384d499504fe7e04441b0706c7628dee7b7");
        let updated_component_balance = models::protocol::ComponentBalance {
            token: base_token.clone(),
            new_balance: Balance::from(U256::from(2000)),
            balance_float: 2000.0,
            modify_tx: new_tx_hash,
            component_id: component_external_id,
        };

        let updated_component_balances = vec![updated_component_balance.clone()];

        gw.add_component_balances(&updated_component_balances, &Chain::Starknet, &mut conn)
            .await
            .unwrap();

        // Obtain newest inserted value
        let new_inserted_data = schema::component_balance::table
            .select(orm::ComponentBalance::as_select())
            .order_by(schema::component_balance::id.desc())
            .first::<orm::ComponentBalance>(&mut conn)
            .await;

        assert!(new_inserted_data.is_ok());
        let new_inserted_data: orm::ComponentBalance = new_inserted_data.unwrap();

        assert_eq!(new_inserted_data.new_balance, Balance::from(U256::from(2000)));
        assert_eq!(new_inserted_data.previous_value, Balance::from(U256::from(12)));
    }

    #[tokio::test]
    async fn test_add_protocol_components() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;
        let protocol_type_name_1 = String::from("Test_Type_1");
        let protocol_type_id_1 =
            db_fixtures::insert_protocol_type(&mut conn, &protocol_type_name_1, None, None, None)
                .await;
        db_fixtures::insert_protocol_type(&mut conn, "Test_Type_2", None, None, None).await;
        let protocol_system = "ambient".to_string();
        let chain = Chain::Ethereum;
        let original_component = models::protocol::ProtocolComponent::new(
            "test_contract_id",
            &protocol_system,
            &protocol_type_name_1,
            chain,
            vec![Bytes::from(WETH)],
            vec![Bytes::from(WETH)],
            HashMap::new(),
            ChangeType::Creation,
            Bytes::from("0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945"),
            Default::default(),
        );

        gw.add_protocol_components(&[original_component.clone()], &mut conn)
            .await
            .expect("adding components failed");

        let inserted_data = schema::protocol_component::table
            .filter(schema::protocol_component::external_id.eq("test_contract_id".to_string()))
            .select(orm::ProtocolComponent::as_select())
            .first::<orm::ProtocolComponent>(&mut conn)
            .await
            .expect("failed to get inserted data");

        assert_eq!(inserted_data.protocol_type_id, protocol_type_id_1);
        assert_eq!(
            gw.get_protocol_system_id(
                &original_component
                    .protocol_system
                    .to_string()
            ),
            inserted_data.protocol_system_id
        );
        assert_eq!(gw.get_chain_id(&original_component.chain), inserted_data.chain_id);
        assert_eq!(original_component.id, inserted_data.external_id);

        // assert junction table
        let component_token_junction = schema::protocol_component_holds_token::table
            .select((
                schema::protocol_component_holds_token::protocol_component_id,
                schema::protocol_component_holds_token::token_id,
            ))
            .filter(
                schema::protocol_component_holds_token::protocol_component_id.eq(inserted_data.id),
            )
            .first::<(i64, i64)>(&mut conn)
            .await
            .unwrap();

        assert_eq!(component_token_junction.0, inserted_data.id);

        let token = schema::token::table
            .select(schema::token::all_columns)
            .filter(schema::token::id.eq(component_token_junction.1))
            .load::<orm::Token>(&mut conn)
            .await;

        assert!(token.is_ok());

        // assert component-contract junction table
        let component_contract_junction = schema::protocol_component_holds_contract::table
            .select((
                schema::protocol_component_holds_contract::protocol_component_id,
                schema::protocol_component_holds_contract::contract_code_id,
            ))
            .filter(
                schema::protocol_component_holds_contract::protocol_component_id
                    .eq(inserted_data.id),
            )
            .first::<(i64, i64)>(&mut conn)
            .await
            .unwrap();

        assert_eq!(component_contract_junction.0, inserted_data.id);

        let contract = schema::contract_code::table
            .select(schema::contract_code::all_columns)
            .filter(schema::contract_code::id.eq(component_contract_junction.1))
            .load::<orm::ContractCode>(&mut conn)
            .await;

        assert!(contract.is_ok())
    }

    fn create_test_protocol_component(id: &str) -> models::protocol::ProtocolComponent {
        models::protocol::ProtocolComponent::new(
            id,
            "ambient",
            "type_id_1",
            Chain::Ethereum,
            vec![],
            vec![],
            HashMap::new(),
            ChangeType::Creation,
            Bytes::from("0x0000000000000000000000000000000000000000000000000000000011121314"),
            NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
        )
    }

    #[tokio::test]
    async fn test_delete_protocol_components() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;

        let test_components = vec![
            create_test_protocol_component("state1"),
            create_test_protocol_component("state2"),
        ];

        let res = gw
            .delete_protocol_components(&test_components, Utc::now().naive_utc(), &mut conn)
            .await;

        assert!(res.is_ok());
        let pc_ids: Vec<String> = test_components
            .iter()
            .map(|test_pc| test_pc.id.to_string())
            .collect();

        let updated_timestamps = schema::protocol_component::table
            .filter(schema::protocol_component::external_id.eq_any(pc_ids))
            .select(schema::protocol_component::deleted_at)
            .load::<Option<NaiveDateTime>>(&mut conn)
            .await
            .unwrap();

        assert_eq!(updated_timestamps.len(), 2);
        updated_timestamps
            .into_iter()
            .for_each(|ts| assert!(ts.is_some(), "Found None in updated_ts"));
    }

    #[rstest]
    #[case::get_one(Some("zigzag".to_string()))]
    #[case::get_none(Some("ambient".to_string()))]
    #[tokio::test]
    async fn test_get_protocol_components_with_system_only(#[case] system: Option<String>) {
        let mut conn = setup_db().await;
        let tx_hashes = setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;

        let chain = Chain::Starknet;

        let result = gw
            .get_protocol_components(&chain, system.clone(), None, None, &mut conn)
            .await;

        assert!(result.is_ok());

        match system.unwrap().as_str() {
            "zigzag" => {
                let components = result.unwrap();
                assert_eq!(components.len(), 1);

                let pc = &components[0];
                assert_eq!(pc.id, "state2".to_string());
                assert_eq!(pc.protocol_system, "zigzag");
                assert_eq!(pc.chain, Chain::Starknet);
                assert_eq!(pc.creation_tx, Bytes::from(tx_hashes.get(1).unwrap().as_str()));
            }
            "ambient" => {
                let components = result.unwrap();
                assert_eq!(components.len(), 0)
            }
            _ => {}
        }
    }

    #[rstest]
    #[case::get_one("state1".to_string())]
    #[case::get_none("state2".to_string())]
    #[tokio::test]
    async fn test_get_protocol_components_with_external_id_only(#[case] external_id: String) {
        let mut conn = setup_db().await;
        let tx_hashes = setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;

        let temp_ids_array = [external_id.as_str()];
        let ids = Some(temp_ids_array.as_slice());
        let chain = Chain::Ethereum;

        let result = gw
            .get_protocol_components(&chain, None, ids, None, &mut conn)
            .await;

        match external_id.as_str() {
            "state1" => {
                let components = result.unwrap();
                assert_eq!(components.len(), 1);

                let pc = &components[0];
                assert_eq!(pc.id, external_id.to_string());
                assert_eq!(pc.protocol_system, "ambient");
                assert_eq!(pc.chain, Chain::Ethereum);
                assert_eq!(pc.creation_tx, Bytes::from(tx_hashes[0].as_str()));
            }
            "state2" => {
                let components = result.unwrap();
                assert_eq!(components.len(), 0)
            }
            _ => {}
        }
    }

    #[tokio::test]
    async fn test_get_protocol_components_with_system_and_ids() {
        let mut conn = setup_db().await;
        let tx_hashes = setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;

        let system = "ambient".to_string();
        let ids = Some(["state1", "state2"].as_slice());
        let chain = Chain::Ethereum;
        let result = gw
            .get_protocol_components(&chain, Some(system), ids, None, &mut conn)
            .await;

        let components = result.unwrap();
        assert_eq!(components.len(), 1);

        let pc = &components[0];
        assert_eq!(pc.id, "state1".to_string());
        assert_eq!(pc.protocol_system, "ambient");
        assert_eq!(pc.chain, Chain::Ethereum);
        assert_eq!(pc.creation_tx, Bytes::from(tx_hashes[0].as_str()));
    }

    #[rstest]
    #[case::ethereum(Chain::Ethereum, & ["state1", "state3", "no_tvl"])]
    #[case::starknet(Chain::Starknet, & ["state2"])]
    #[tokio::test]
    async fn test_get_protocol_components_with_chain_filter(
        #[case] chain: Chain,
        #[case] exp_ids: &[&str],
    ) {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;
        let exp = exp_ids
            .iter()
            .map(|&s| s.to_owned())
            .collect::<HashSet<_>>();

        let components = gw
            .get_protocol_components(&chain, None, None, None, &mut conn)
            .await
            .expect("failed retrieving components")
            .into_iter()
            .map(|c| c.id)
            .collect::<HashSet<_>>();

        assert_eq!(components, exp);
    }

    #[rstest]
    #[case::empty(Some(10.0), & [])]
    #[case::all(None, & ["state1", "state3", "no_tvl"])]
    #[case::with_tvl(Some(0.0), & ["state1", "state3"])]
    #[case::with_tvl(Some(1.0), & ["state1"])]
    #[tokio::test]
    async fn test_get_protocol_components_with_min_tvl(
        #[case] min_tvl: Option<f64>,
        #[case] exp_ids: &[&str],
    ) {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let exp = exp_ids
            .iter()
            .map(|&s| s.to_owned())
            .collect::<HashSet<_>>();
        let gw = EVMGateway::from_connection(&mut conn).await;

        let res = gw
            .get_protocol_components(&Chain::Ethereum, None, None, min_tvl, &mut conn)
            .await
            .expect("failed retrieving components")
            .into_iter()
            .map(|comp| comp.id)
            .collect::<HashSet<_>>();

        assert_eq!(res, exp);
    }

    #[tokio::test]
    async fn test_get_token_prices() {
        let mut conn = setup_db().await;
        let _ = setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;
        let exp = [(Bytes::from(WETH), 1.0), (Bytes::from(USDC), 0.0005)]
            .into_iter()
            .collect::<HashMap<_, _>>();

        let prices = gw
            .get_token_prices(&Chain::Ethereum, &mut conn)
            .await
            .expect("retrieving token prices failed!");

        assert_eq!(prices, exp);
    }

    #[tokio::test]
    async fn test_get_balances() {
        let mut conn = setup_db().await;
        let _ = setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;
        let exp: HashMap<_, _> =
            [("state1", Bytes::from(WETH), 1e18), ("state1", Bytes::from(USDC), 2000.0 * 1e6)]
                .into_iter()
                .group_by(|e| e.0)
                .into_iter()
                .map(|(cid, group)| {
                    (
                        cid.to_owned(),
                        group
                            .map(|(_, addr, bal)| (addr, bal))
                            .collect::<HashMap<_, _>>(),
                    )
                })
                .collect();

        let res = gw
            .get_balances(&Chain::Ethereum, Some(&["state1"]), None, &mut conn)
            .await
            .expect("retrieving balances failed!");

        assert_eq!(res, exp);
    }

    #[tokio::test]
    async fn test_get_balances_at() {
        let mut conn = setup_db().await;
        let _ = setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;

        // set up changed balances
        let protocol_component_id = schema::protocol_component::table
            .filter(schema::protocol_component::external_id.eq("state3"))
            .select(schema::protocol_component::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch protocol component id");
        let weth_id = schema::token::table
            .filter(schema::token::symbol.eq("WETH"))
            .select(schema::token::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch token id");
        let dai_id = schema::token::table
            .filter(schema::token::symbol.eq("DAI"))
            .select(schema::token::id)
            .first::<i64>(&mut conn)
            .await
            .expect("Failed to fetch token id");

        let tx_hash =
            H256::from_str("0x3108322284d0a89a7accb288d1a94384d499504fe7e04441b0706c7628dee7b7")
                .expect("valid txhash");

        let (txn_id, ts) = schema::transaction::table
            .inner_join(schema::block::table)
            .filter(schema::transaction::hash.eq(tx_hash.clone().as_bytes()))
            .select((schema::transaction::id, schema::block::ts))
            .first::<(i64, NaiveDateTime)>(&mut conn)
            .await
            .expect("Failed to fetch transaction id");

        diesel::update(
            schema::component_balance::table
                .filter(schema::component_balance::protocol_component_id.eq(protocol_component_id)),
        )
        .set(schema::component_balance::valid_to.eq(ts))
        .execute(&mut conn)
        .await
        .expect("updating valid_to failed");

        db_fixtures::insert_component_balance(
            &mut conn,
            Bytes::from(U256::from(2) * U256::exp10(18)),
            Bytes::from(U256::exp10(18)),
            2e18,
            weth_id,
            txn_id,
            protocol_component_id,
            None,
        )
        .await;
        db_fixtures::insert_component_balance(
            &mut conn,
            Bytes::from(U256::from(3000) * U256::exp10(6)),
            Bytes::from(U256::from(2000) * U256::exp10(18)),
            3000.0 * 1e6,
            dai_id,
            txn_id,
            protocol_component_id,
            None,
        )
        .await;

        let exp: HashMap<_, _> =
            [("state3", Bytes::from(WETH), 1e18), ("state3", Bytes::from(DAI), 2000.0 * 1e18)]
                .into_iter()
                .group_by(|e| e.0)
                .into_iter()
                .map(|(cid, group)| {
                    (
                        cid.to_owned(),
                        group
                            .map(|(_, addr, bal)| (addr, bal))
                            .collect::<HashMap<_, _>>(),
                    )
                })
                .collect();

        let res = gw
            .get_balances(
                &Chain::Ethereum,
                Some(&["state3"]),
                Some(&Version::from_block_number(Chain::Ethereum, 1)),
                &mut conn,
            )
            .await
            .expect("retrieving balances failed!");

        assert_eq!(res, exp);
    }

    #[tokio::test]
    async fn test_upsert_component_tvl() {
        let mut conn = setup_db().await;
        let _ = setup_data(&mut conn).await;
        let gw = EVMGateway::from_connection(&mut conn).await;
        let chain_id = gw.get_chain_id(&Chain::Ethereum);
        let exp = [("state1", 100.0), ("no_tvl", 1.0), ("state3", 1.0)]
            .into_iter()
            .map(|(id, tvl)| (id.to_owned(), tvl))
            .collect::<HashMap<_, _>>();

        let new_tvl = [("state1".to_owned(), 100.0), ("no_tvl".to_owned(), 1.0)]
            .into_iter()
            .collect::<HashMap<_, _>>();
        gw.upsert_component_tvl(&Chain::Ethereum, &new_tvl, &mut conn)
            .await
            .expect("upsert failed!");

        let tvl_values = schema::component_tvl::table
            .inner_join(schema::protocol_component::table)
            .select((schema::protocol_component::external_id, schema::component_tvl::tvl))
            .filter(schema::protocol_component::chain_id.eq(chain_id))
            .get_results::<(String, f64)>(&mut conn)
            .await
            .unwrap()
            .into_iter()
            .collect::<HashMap<_, _>>();

        assert_eq!(tvl_values, exp);
    }
}

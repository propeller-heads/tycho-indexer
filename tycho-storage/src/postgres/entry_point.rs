use std::collections::{HashMap, HashSet};

use diesel::{prelude::*, upsert::excluded};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use tycho_common::{
    models::{
        blockchain::{
            EntryPoint, EntryPointWithTracingParams, TracedEntryPoint, TracingParams, TracingResult,
        },
        Chain, ComponentId, EntryPointId, PaginationParams,
    },
    storage::{EntryPointFilter, StorageError, WithTotal},
    Bytes,
};

use super::{
    orm::{
        self, EntryPointTracingType, NewEntryPoint, NewEntryPointTracingParams,
        NewEntryPointTracingParamsCallsAccount, NewEntryPointTracingResult,
        NewProtocolComponentHasEntryPointTracingParams, NewProtocolComponentUsesEntryPoint,
    },
    schema::{self},
    storage_error_from_diesel, PostgresError, PostgresGateway,
};

impl PostgresGateway {
    /// Insert new entry points into the database. This function ignores conflicts on inserts.
    ///
    /// # Arguments
    ///
    /// * `new_data` - A map of protocol component external ids to a list of entry points.
    /// * `chain` - The chain to insert the entry points for.
    /// * `conn` - The database connection to use.
    pub(crate) async fn insert_entry_points(
        &self,
        new_data: &HashMap<ComponentId, HashSet<EntryPoint>>,
        chain: &Chain,
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        use schema::{entry_point::dsl::*, protocol_component_uses_entry_point::dsl::*};

        let chain_id = self.get_chain_id(chain);

        let pc_ids = orm::ProtocolComponent::ids_by_external_ids(
            &new_data
                .keys()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>(),
            chain_id,
            conn,
        )
        .await
        .map_err(PostgresError::from)?
        .into_iter()
        .map(|(id_, ext_id)| (ext_id, id_))
        .collect::<HashMap<_, _>>();

        let new_entry_points = new_data
            .iter()
            .flat_map(|(_, ep)| {
                ep.iter()
                    .map(|ep| NewEntryPoint {
                        external_id: ep.external_id.clone(),
                        target: ep.target.clone(),
                        signature: ep.signature.clone(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        diesel::insert_into(entry_point)
            .values(&new_entry_points)
            .on_conflict_do_nothing()
            .execute(conn)
            .await
            .map_err(|e| storage_error_from_diesel(e, "EntryPoint", "Batch upsert", None))?;

        // Fetch entry points by their external_ids, we can't use .returning() on the insert above
        // because it doesn't return the ids on conflicts.
        let input_external_ids: Vec<EntryPointId> = new_data
            .iter()
            .flat_map(|(_, ep)| {
                ep.iter()
                    .map(|ep| ep.external_id.clone())
            })
            .collect();

        let entry_point_ids =
            orm::EntryPoint::ids_by_external_ids(&input_external_ids, conn).await?;

        let mut pc_entry_point_links = Vec::new();

        for (pc_ext_id, eps) in new_data.iter() {
            let pc_id = match pc_ids.get(pc_ext_id) {
                Some(_id) => _id,
                None => {
                    return Err(StorageError::NotFound(
                        "ProtocolComponent".to_string(),
                        pc_ext_id.to_string(),
                    ));
                }
            };

            for ep in eps.iter() {
                let ep_id = match entry_point_ids.get(&ep.external_id) {
                    Some(_id) => _id,
                    None => {
                        return Err(StorageError::NotFound(
                            "EntryPoint".to_string(),
                            ep.external_id.clone(),
                        ));
                    }
                };

                pc_entry_point_links.push(NewProtocolComponentUsesEntryPoint {
                    protocol_component_id: *pc_id,
                    entry_point_id: *ep_id,
                });
            }
        }

        // Insert links between protocol components and entry points
        // Design choice: we don't want to delete previously inserted links here, they are
        // cumulative
        diesel::insert_into(protocol_component_uses_entry_point)
            .values(&pc_entry_point_links)
            .on_conflict_do_nothing()
            .execute(conn)
            .await
            .map_err(|e| {
                storage_error_from_diesel(
                    e,
                    "ProtocolComponentUsesEntryPoint",
                    "Batch upsert",
                    None,
                )
            })?;
        Ok(())
    }

    /// Insert entry point tracing params into the database. This function ignores conflicts on
    /// inserts.
    ///
    /// # Arguments
    ///
    /// * `new_data` - A map of entry point ids to a list of tracing params and optional component
    ///   id related to the tracing params.
    /// * `conn` - The database connection to use.
    pub(crate) async fn insert_entry_point_tracing_params(
        &self,
        new_data: &HashMap<EntryPointId, HashSet<(TracingParams, Option<ComponentId>)>>,
        chain: &Chain,
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        use schema::{
            debug_protocol_component_has_entry_point_tracing_params::dsl::*,
            entry_point_tracing_params::dsl::*,
        };

        let input_external_ids: Vec<EntryPointId> = new_data.keys().cloned().collect();
        let entry_point_ids =
            orm::EntryPoint::ids_by_external_ids(&input_external_ids, conn).await?;

        let mut new_tracing_params = Vec::new();
        for (ep_id, ep) in new_data.iter() {
            let entry_point_id_ = entry_point_ids
                .get(ep_id)
                .ok_or_else(|| {
                    StorageError::NotFound("EntryPoint".to_string(), ep_id.to_string())
                })?;
            for (params, _) in ep.iter() {
                let db_params = match params {
                    TracingParams::RPCTracer(rpc_tracer) => serde_json::to_value(rpc_tracer)
                        .map_err(|e| {
                            StorageError::Unexpected(format!(
                                "Failed to serialize RPCTracerEntryPoint: {e}"
                            ))
                        })?,
                };
                new_tracing_params.push(NewEntryPointTracingParams {
                    entry_point_id: *entry_point_id_,
                    tracing_type: EntryPointTracingType::from(params),
                    data: Some(db_params),
                });
            }
        }

        diesel::insert_into(entry_point_tracing_params)
            .values(&new_tracing_params)
            .on_conflict_do_nothing()
            .execute(conn)
            .await
            .map_err(|e| {
                storage_error_from_diesel(e, "EntryPointTracingParams", "Batch upsert", None)
            })?;

        let new_links: &Vec<(&TracingParams, &String)> = &new_data
            .values()
            .flat_map(|ep| {
                ep.iter()
                    .filter_map(|(params, pc_ext_id)| {
                        pc_ext_id
                            .as_ref()
                            .map(|pc_ext_id| (params, pc_ext_id))
                    })
            })
            .collect::<Vec<_>>();

        // Insert links between protocol components and tracing params
        if !new_links.is_empty() {
            let chain_id = self.get_chain_id(chain);

            // Fetch entry points tracing params, we can't use .returning() on the insert above
            // because it doesn't return the ids on conflicts.
            let params_ids = orm::EntryPointTracingParams::ids_by_entry_point_with_tracing_params(
                &new_data
                    .iter()
                    .flat_map(|(ep_id, ep)| {
                        ep.iter()
                            .map(|params| (ep_id.clone(), params.0.clone()))
                    })
                    .collect::<Vec<_>>(),
                conn,
            )
            .await?;

            let pc_ids = orm::ProtocolComponent::ids_by_external_ids(
                &new_links
                    .iter()
                    .map(|(_, pc_ext_id)| pc_ext_id.as_str())
                    .collect::<Vec<_>>(),
                chain_id,
                conn,
            )
            .await
            .map_err(PostgresError::from)?
            .into_iter()
            .map(|(id_, ext_id)| (ext_id, id_))
            .collect::<HashMap<_, _>>();

            let mut pc_tracing_params_links = Vec::new();
            for (ep, pc_ext_id) in new_links.iter() {
                let pc_id = match pc_ids.get(*pc_ext_id) {
                    Some(_id) => _id,
                    None => {
                        return Err(StorageError::NotFound(
                            "ProtocolComponent".to_string(),
                            pc_ext_id.to_string(),
                        ));
                    }
                };

                let params_id = match params_ids.get(ep) {
                    Some(_id) => _id,
                    None => {
                        return Err(StorageError::NotFound(
                            "EntryPointTracingParams".to_string(),
                            format!("{ep:?}"),
                        ));
                    }
                };

                pc_tracing_params_links.push(NewProtocolComponentHasEntryPointTracingParams {
                    protocol_component_id: *pc_id,
                    entry_point_tracing_params_id: *params_id,
                });
            }

            diesel::insert_into(debug_protocol_component_has_entry_point_tracing_params)
                .values(&pc_tracing_params_links)
                .on_conflict_do_nothing()
                .execute(conn)
                .await
                .map_err(|e| {
                    storage_error_from_diesel(
                        e,
                        "ProtocolComponentHasEntryPointTracingParams",
                        "Batch upsert",
                        None,
                    )
                })?;
        }

        Ok(())
    }

    /// Get entry points tracing params from the database.
    ///
    /// # Arguments
    ///
    /// * `filter` - The filter to apply to the query.
    /// * `pagination_params` - The pagination parameters to apply to the query, if None, all
    ///   results are returned.
    /// * `conn` - The database connection to use.
    ///
    /// Note: to avoid getting partial results, the pagination is applied to components, not
    /// entry points.
    pub(crate) async fn get_entry_points_tracing_params(
        &self,
        filter: EntryPointFilter,
        pagination_params: Option<&PaginationParams>,
        conn: &mut AsyncPgConnection,
    ) -> Result<WithTotal<HashMap<ComponentId, HashSet<EntryPointWithTracingParams>>>, StorageError>
    {
        use schema::{
            entry_point as ep, entry_point_tracing_params as eptp, protocol_component as pc,
            protocol_component_uses_entry_point as pcuep,
        };

        let ps_id = self.get_protocol_system_id(&filter.protocol_system);
        let mut component_query = schema::protocol_component::table
            .filter(pc::protocol_system_id.eq(ps_id))
            .select(pc::id)
            .into_boxed();

        if let Some(component_ids) = filter.component_ids {
            component_query = component_query.filter(pc::external_id.eq_any(component_ids));
        }

        // Apply pagination and fetch total count
        let count: Option<i64> = if let Some(pagination_params) = pagination_params {
            component_query = component_query
                .order_by(pc::id)
                .limit(pagination_params.page_size)
                .offset(pagination_params.offset());

            Some(
                schema::protocol_component::table
                    .filter(pc::protocol_system_id.eq(ps_id))
                    .count()
                    .get_result::<i64>(conn)
                    .await
                    .unwrap_or(0),
            )
        } else {
            None
        };

        let results = schema::entry_point::table
            .inner_join(eptp::table.on(ep::id.eq(eptp::entry_point_id)))
            .inner_join(pcuep::table.on(ep::id.eq(pcuep::entry_point_id)))
            .inner_join(pc::table.on(pcuep::protocol_component_id.eq(pc::id)))
            .filter(pc::id.eq_any(component_query))
            .select((
                pc::external_id,
                orm::EntryPoint::as_select(),
                orm::EntryPointTracingParams::as_select(),
            ))
            .load::<(String, orm::EntryPoint, orm::EntryPointTracingParams)>(conn)
            .await
            .map_err(|err| {
                storage_error_from_diesel(
                    err,
                    "EntryPointWithTracingParams",
                    "None",
                    Some(format!("protocol: {:?}", filter.protocol_system)),
                )
            })?;

        let res: HashMap<String, HashSet<EntryPointWithTracingParams>> =
            results
                .into_iter()
                .fold(HashMap::new(), |mut acc, (pc_ext_id, ep, params)| {
                    acc.entry(pc_ext_id)
                        .or_default()
                        .insert(EntryPointWithTracingParams::new(ep.into(), (&params).into()));
                    acc
                });

        Ok(WithTotal { entity: res, total: count })
    }

    /// Get entry points from the database.
    ///
    /// # Arguments
    ///
    /// * `filter` - The filter to apply to the query.
    /// * `pagination_params` - The pagination parameters to apply to the query, if None, all
    ///   results are returned.
    /// * `conn` - The database connection to use.
    ///
    /// Note: to avoid getting partial results, the pagination is applied to components, not
    /// entry points.
    pub(crate) async fn get_entry_points(
        &self,
        filter: EntryPointFilter,
        pagination_params: Option<&PaginationParams>,
        conn: &mut AsyncPgConnection,
    ) -> Result<WithTotal<HashMap<ComponentId, HashSet<EntryPoint>>>, StorageError> {
        use schema::{
            entry_point as ep, protocol_component as pc,
            protocol_component_uses_entry_point as pcuep,
        };

        let ps_id = self.get_protocol_system_id(&filter.protocol_system);
        let mut component_query = schema::protocol_component::table
            .filter(pc::protocol_system_id.eq(ps_id))
            .select(pc::id)
            .into_boxed();

        if let Some(component_ids) = filter.component_ids {
            component_query = component_query.filter(pc::external_id.eq_any(component_ids));
        }

        // Apply pagination and fetch total count
        let count: Option<i64> = if let Some(pagination_params) = pagination_params {
            component_query = component_query
                .order_by(pc::id)
                .limit(pagination_params.page_size)
                .offset(pagination_params.offset());

            Some(
                schema::protocol_component::table
                    .filter(pc::protocol_system_id.eq(ps_id))
                    .count()
                    .get_result::<i64>(conn)
                    .await
                    .unwrap_or(0),
            )
        } else {
            None
        };

        let results = schema::entry_point::table
            .inner_join(pcuep::table.on(ep::id.eq(pcuep::entry_point_id)))
            .inner_join(pc::table.on(pcuep::protocol_component_id.eq(pc::id)))
            .filter(pc::id.eq_any(component_query))
            .select((pc::external_id, orm::EntryPoint::as_select()))
            .load::<(String, orm::EntryPoint)>(conn)
            .await
            .map_err(|err| {
                storage_error_from_diesel(
                    err,
                    "EntryPoint",
                    "None",
                    Some(format!("protocol: {:?}", filter.protocol_system)),
                )
            })?;

        let res: HashMap<ComponentId, HashSet<EntryPoint>> =
            results
                .into_iter()
                .fold(HashMap::new(), |mut acc, (pc_ext_id, ep)| {
                    acc.entry(pc_ext_id)
                        .or_default()
                        .insert(ep.into());
                    acc
                });

        Ok(WithTotal { entity: res, total: count })
    }

    /// Upsert traced entry points into the database. Updates the result if it already exists for
    /// the same entry point and tracing params.
    ///
    /// # Arguments
    ///
    /// * `traced_entry_points` - The traced entry points to upsert.
    /// * `conn` - The database connection to use.
    pub(crate) async fn upsert_traced_entry_points(
        &self,
        traced_entry_points: &[TracedEntryPoint],
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        use schema::{
            entry_point_tracing_params_calls_account::dsl::*, entry_point_tracing_result::dsl::*,
        };

        let block_hashes: HashSet<_> = traced_entry_points
            .iter()
            .map(|tep| tep.detection_block_hash.clone())
            .collect();
        let blocks = schema::block::table
            .filter(schema::block::hash.eq_any(block_hashes))
            .select((schema::block::hash, schema::block::id))
            .load::<(Bytes, i64)>(conn)
            .await
            .map_err(PostgresError::from)?;
        let block_id_map: HashMap<_, _> = blocks.into_iter().collect();

        let params_ids = orm::EntryPointTracingParams::ids_by_entry_point_with_tracing_params(
            &traced_entry_points
                .iter()
                .map(|tep| {
                    (
                        tep.entry_point_with_params
                            .entry_point
                            .external_id
                            .clone(),
                        tep.entry_point_with_params
                            .params
                            .clone(),
                    )
                })
                .collect::<Vec<_>>(),
            conn,
        )
        .await?;

        let mut values = Vec::with_capacity(traced_entry_points.len());
        for tep in traced_entry_points {
            let params_id = params_ids
                .get(&tep.entry_point_with_params.params)
                .ok_or_else(|| {
                    StorageError::NotFound(
                        "EntryPointTracingParams".to_string(),
                        tep.entry_point_with_params
                            .entry_point
                            .external_id
                            .clone(),
                    )
                })?;

            let block_id = block_id_map
                .get(&tep.detection_block_hash)
                .copied()
                .ok_or_else(|| {
                    StorageError::NotFound(
                        "Block".to_string(),
                        tep.detection_block_hash.to_string(),
                    )
                })?;

            let tracing_result = serde_json::to_value(&tep.tracing_result).map_err(|e| {
                StorageError::Unexpected(format!("Failed to serialize TracingResult: {e}"))
            })?;

            values.push(NewEntryPointTracingResult {
                entry_point_tracing_params_id: *params_id,
                detection_block: block_id,
                detection_data: tracing_result,
            });
        }

        diesel::insert_into(entry_point_tracing_result)
            .values(&values)
            .on_conflict(schema::entry_point_tracing_result::entry_point_tracing_params_id)
            .do_update()
            .set((
                detection_block.eq(excluded(detection_block)),
                detection_data.eq(excluded(detection_data)),
                modified_ts.eq(excluded(modified_ts)),
            ))
            .execute(conn)
            .await
            .map_err(|err| {
                storage_error_from_diesel(err, "NewEntryPointTracingResult", "Batch upsert", None)
            })?;

        let all_called_addresses: HashSet<_> = traced_entry_points
            .iter()
            .flat_map(|tep| {
                tep.tracing_result
                    .called_addresses
                    .iter()
            })
            .cloned()
            .collect();

        let accounts = schema::account::table
            .filter(schema::account::address.eq_any(&all_called_addresses))
            .select((schema::account::address, schema::account::id))
            .load::<(Bytes, i64)>(conn)
            .await
            .map_err(PostgresError::from)?;

        let account_id_map: HashMap<_, _> = accounts.into_iter().collect();

        let mut new_entry_point_calls_account = Vec::new();
        for (tep, &params_id) in traced_entry_points
            .iter()
            .zip(params_ids.values())
        {
            for address in &tep.tracing_result.called_addresses {
                let acc_id = account_id_map
                    .get(address)
                    .ok_or_else(|| {
                        StorageError::NotFound("Account".to_string(), address.to_string())
                    })?;

                new_entry_point_calls_account.push(NewEntryPointTracingParamsCallsAccount {
                    entry_point_tracing_params_id: params_id,
                    account_id: *acc_id,
                });
            }
        }

        diesel::insert_into(entry_point_tracing_params_calls_account)
            .values(&new_entry_point_calls_account)
            .on_conflict_do_nothing() // Design choice: we don't want to delete previously inserted links here, they are
            // cumulative
            .execute(conn)
            .await
            .map_err(|err| {
                storage_error_from_diesel(err, "EntryPointPointsToAccount", "Batch upsert", None)
            })?;

        Ok(())
    }

    /// Get all tracing results for a set of entry points from the database.
    ///
    /// # Arguments
    ///
    /// * `entry_points` - The entry point ids to get tracing results for.
    /// * `conn` - The database connection to use.
    pub(crate) async fn get_tracing_results(
        &self,
        entry_points: &HashSet<EntryPointId>,
        conn: &mut AsyncPgConnection,
    ) -> Result<HashMap<EntryPointId, HashMap<TracingParams, TracingResult>>, StorageError> {
        use schema::{
            entry_point as ep, entry_point_tracing_params as eptp,
            entry_point_tracing_result as eptr,
        };
        let entry_point_ids = orm::EntryPoint::ids_by_external_ids(
            &entry_points
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            conn,
        )
        .await?;

        let results = schema::entry_point_tracing_result::table
            .inner_join(eptp::table.on(eptr::entry_point_tracing_params_id.eq(eptp::id)))
            .inner_join(ep::table.on(eptp::entry_point_id.eq(ep::id)))
            .filter(eptp::entry_point_id.eq_any(entry_point_ids.values().cloned()))
            .select((
                ep::external_id,
                orm::EntryPointTracingParams::as_select(),
                eptr::detection_data,
            ))
            .load::<(String, orm::EntryPointTracingParams, serde_json::Value)>(conn)
            .await
            .map_err(|e| storage_error_from_diesel(e, "TracingResult", "Query", None))?;

        let mut results_by_entry_point = HashMap::new();
        for (ep_ext_id, tracing_params, tracing_result) in results {
            let converted_tracing_result = serde_json::from_value(tracing_result).map_err(|e| {
                StorageError::DecodeError(format!("Failed to deserialize TracingResult: {e}"))
            })?;
            results_by_entry_point
                .entry(ep_ext_id.clone())
                .or_insert_with(HashMap::new)
                .insert((&tracing_params).into(), converted_tracing_result);
        }

        Ok(results_by_entry_point)
    }
}

#[cfg(test)]
mod test {
    use std::{slice, str::FromStr};

    use diesel_async::AsyncConnection;
    use tycho_common::{
        keccak256,
        models::{
            blockchain::{RPCTracerParams, TracedEntryPoint, TracingParams, TracingResult},
            FinancialType, ImplementationType, StoreKey,
        },
        Bytes,
    };

    use super::*;
    use crate::postgres::db_fixtures;

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

    async fn setup_data(conn: &mut AsyncPgConnection) {
        let chain_id = db_fixtures::insert_chain(conn, "ethereum").await;
        db_fixtures::insert_token(
            conn,
            chain_id,
            "0000000000000000000000000000000000000000",
            "ETH",
            18,
            Some(100),
        )
        .await;

        let blk = db_fixtures::insert_blocks(conn, chain_id).await;

        let txn = db_fixtures::insert_txns(
            conn,
            &[(blk[0], 1i64, "0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945")],
        )
        .await;

        db_fixtures::insert_account(
            conn,
            "6b175474e89094c44da98b954eedeac495271d0f",
            "test_account",
            chain_id,
            Some(txn[0]),
        )
        .await;

        let ps_id = db_fixtures::insert_protocol_system(conn, "test_protocol".to_string()).await;
        let unknown_ps_id = db_fixtures::insert_protocol_system(conn, "unknown".to_string()).await;

        let protocol_type_id = db_fixtures::insert_protocol_type(
            conn,
            "Pool",
            Some(FinancialType::Swap),
            None,
            Some(ImplementationType::Custom),
        )
        .await;
        db_fixtures::insert_protocol_component(
            conn,
            "pc_0",
            chain_id,
            ps_id,
            protocol_type_id,
            txn[0],
            None,
            None,
        )
        .await;

        db_fixtures::insert_protocol_component(
            conn,
            "pc_1",
            chain_id,
            ps_id,
            protocol_type_id,
            txn[0],
            None,
            None,
        )
        .await;
        db_fixtures::insert_protocol_component(
            conn,
            "pc_2",
            chain_id,
            ps_id,
            protocol_type_id,
            txn[0],
            None,
            None,
        )
        .await;

        db_fixtures::insert_protocol_component(
            conn,
            "unknown_pc",
            chain_id,
            unknown_ps_id,
            protocol_type_id,
            txn[0],
            None,
            None,
        )
        .await;
    }

    fn rpc_tracer_entry_point(version: u8) -> EntryPoint {
        match version {
            0 => EntryPoint::new(
                "0xEdf63cce4bA70cbE74064b7687882E71ebB0e988:getRate()".to_string(),
                Bytes::from_str("0xEdf63cce4bA70cbE74064b7687882E71ebB0e988").unwrap(),
                "getRate()".to_string(),
            ),
            1 => EntryPoint::new(
                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2:totalSupply()".to_string(),
                Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
                "totalSupply()".to_string(),
            ),
            _ => panic!("Invalid rpc_tracer_entry_point version"),
        }
    }

    fn tracing_params(version: u8) -> TracingParams {
        match version {
            0 => TracingParams::RPCTracer(RPCTracerParams::new(
                None,
                Bytes::from(&keccak256("getRate()")[0..4]),
            )),
            1 => TracingParams::RPCTracer(RPCTracerParams::new(
                None,
                Bytes::from(&keccak256("totalSupply()")[0..4]),
            )),
            _ => panic!("Invalid tracing_params version"),
        }
    }

    fn traced_entry_point() -> TracedEntryPoint {
        let entry_point_with_tracing_params =
            EntryPointWithTracingParams::new(rpc_tracer_entry_point(0), tracing_params(0));
        TracedEntryPoint::new(
            entry_point_with_tracing_params,
            Bytes::from_str("88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6")
                .unwrap(),
            TracingResult::new(
                vec![(
                    Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                    StoreKey::from_str(
                        "0x0000000000000000000000000000000000000000000000000000000000000001",
                    )
                    .unwrap(),
                )]
                .into_iter()
                .collect(),
                vec![Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap()]
                    .into_iter()
                    .collect(),
            ),
        )
    }

    #[tokio::test]
    async fn test_entry_points_round_trip() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = PostgresGateway::from_connection(&mut conn).await;

        gw.insert_entry_points(
            &HashMap::from([
                ("pc_0".to_string(), HashSet::from([rpc_tracer_entry_point(0)])),
                (
                    "pc_1".to_string(),
                    HashSet::from([rpc_tracer_entry_point(0), rpc_tracer_entry_point(1)]),
                ),
                ("pc_2".to_string(), HashSet::from([rpc_tracer_entry_point(1)])),
                ("unknown_pc".to_string(), HashSet::from([rpc_tracer_entry_point(0)])),
            ]),
            &Chain::Ethereum,
            &mut conn,
        )
        .await
        .unwrap();

        let filter = EntryPointFilter::new("test_protocol".to_string());
        let retrieved_entry_points = gw
            .get_entry_points(filter, None, &mut conn)
            .await
            .unwrap();

        assert_eq!(
            retrieved_entry_points.entity,
            HashMap::from([
                ("pc_0".to_string(), HashSet::from([rpc_tracer_entry_point(0)])),
                (
                    "pc_1".to_string(),
                    HashSet::from([rpc_tracer_entry_point(0), rpc_tracer_entry_point(1)])
                ),
                ("pc_2".to_string(), HashSet::from([rpc_tracer_entry_point(1)])),
            ])
        );

        let filter = EntryPointFilter::new("test_protocol".to_string())
            .with_component_ids(vec!["pc_1".to_string(), "unknown_pc".to_string()]);
        let retrieved_entry_points = gw
            .get_entry_points(filter, None, &mut conn)
            .await
            .unwrap();

        assert_eq!(
            retrieved_entry_points.entity,
            HashMap::from([(
                "pc_1".to_string(),
                HashSet::from([rpc_tracer_entry_point(0), rpc_tracer_entry_point(1)])
            ),])
        );
    }

    #[tokio::test]
    async fn test_entry_points_with_data_round_trip() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = PostgresGateway::from_connection(&mut conn).await;

        gw.insert_entry_points(
            &HashMap::from([
                ("pc_0".to_string(), HashSet::from([rpc_tracer_entry_point(0)])),
                (
                    "pc_1".to_string(),
                    HashSet::from([rpc_tracer_entry_point(0), rpc_tracer_entry_point(1)]),
                ),
                ("pc_2".to_string(), HashSet::from([rpc_tracer_entry_point(1)])),
                ("unknown_pc".to_string(), HashSet::from([rpc_tracer_entry_point(0)])),
            ]),
            &Chain::Ethereum,
            &mut conn,
        )
        .await
        .unwrap();

        gw.insert_entry_point_tracing_params(
            &HashMap::from([
                (
                    rpc_tracer_entry_point(0)
                        .external_id
                        .clone(),
                    HashSet::from([(tracing_params(0), Some("pc_0".to_string()))]),
                ),
                (
                    rpc_tracer_entry_point(1)
                        .external_id
                        .clone(),
                    HashSet::from([(tracing_params(1), None), (tracing_params(0), None)]),
                ),
                (
                    rpc_tracer_entry_point(1)
                        .external_id
                        .clone(),
                    HashSet::from([(tracing_params(1), Some("pc_2".to_string()))]),
                ),
                (
                    rpc_tracer_entry_point(0)
                        .external_id
                        .clone(),
                    HashSet::from([(tracing_params(0), Some("unknown_pc".to_string()))]),
                ),
            ]),
            &Chain::Ethereum,
            &mut conn,
        )
        .await
        .unwrap();

        let filter = EntryPointFilter::new("test_protocol".to_string());
        let retrieved_entry_points = gw
            .get_entry_points_tracing_params(filter, None, &mut conn)
            .await
            .unwrap();

        assert_eq!(
            retrieved_entry_points.entity,
            HashMap::from([
                (
                    "pc_1".to_string(),
                    HashSet::from([
                        EntryPointWithTracingParams::new(
                            rpc_tracer_entry_point(0),
                            tracing_params(0)
                        ),
                        EntryPointWithTracingParams::new(
                            rpc_tracer_entry_point(1),
                            tracing_params(1)
                        ),
                    ])
                ),
                (
                    "pc_0".to_string(),
                    HashSet::from([EntryPointWithTracingParams::new(
                        rpc_tracer_entry_point(0),
                        tracing_params(0)
                    )])
                ),
                (
                    "pc_2".to_string(),
                    HashSet::from([EntryPointWithTracingParams::new(
                        rpc_tracer_entry_point(1),
                        tracing_params(1)
                    )])
                ),
            ])
        );

        let filter = EntryPointFilter::new("test_protocol".to_string())
            .with_component_ids(vec!["pc_1".to_string()]);
        let retrieved_entry_points = gw
            .get_entry_points_tracing_params(filter, None, &mut conn)
            .await
            .unwrap();

        assert_eq!(
            retrieved_entry_points.entity,
            HashMap::from([(
                "pc_1".to_string(),
                HashSet::from([
                    EntryPointWithTracingParams::new(rpc_tracer_entry_point(1), tracing_params(1)),
                    EntryPointWithTracingParams::new(rpc_tracer_entry_point(0), tracing_params(0)),
                ])
            ),])
        );

        //Test pagination
        let filter = EntryPointFilter::new("test_protocol".to_string());
        let retrieved_entry_points = gw
            .get_entry_points_tracing_params(filter, Some(&PaginationParams::new(1, 1)), &mut conn)
            .await
            .unwrap();

        assert_eq!(
            retrieved_entry_points.entity,
            HashMap::from([(
                "pc_1".to_string(),
                HashSet::from([
                    EntryPointWithTracingParams::new(rpc_tracer_entry_point(1), tracing_params(1)),
                    EntryPointWithTracingParams::new(rpc_tracer_entry_point(0), tracing_params(0)),
                ])
            ),])
        );
    }

    #[tokio::test]
    async fn test_traced_entry_points_round_trip() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = PostgresGateway::from_connection(&mut conn).await;

        let entry_point = rpc_tracer_entry_point(0);
        let traced_entry_point = traced_entry_point();

        gw.insert_entry_points(
            &HashMap::from([("pc_0".to_string(), HashSet::from([entry_point.clone()]))]),
            &Chain::Ethereum,
            &mut conn,
        )
        .await
        .unwrap();

        gw.insert_entry_point_tracing_params(
            &HashMap::from([(
                entry_point.external_id.clone(),
                HashSet::from([(tracing_params(0), Some("pc_0".to_string()))]),
            )]),
            &Chain::Ethereum,
            &mut conn,
        )
        .await
        .unwrap();

        gw.upsert_traced_entry_points(slice::from_ref(&traced_entry_point), &mut conn)
            .await
            .unwrap();

        let retrieved_traced_entry_points = gw
            .get_tracing_results(&HashSet::from([entry_point.external_id.clone()]), &mut conn)
            .await
            .unwrap();

        assert_eq!(
            retrieved_traced_entry_points,
            HashMap::from([(
                entry_point.external_id.clone(),
                HashMap::from([(tracing_params(0), traced_entry_point.tracing_result)])
            )])
        );
    }
}

#![allow(unused)] //TODO: Remove this once we have usage in extractors
use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use diesel::{prelude::*, upsert::excluded};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use itertools::Itertools;
use tycho_common::{
    models::{
        blockchain::{
            EntryPoint, EntryPointTracingData, EntryPointWithData, TracedEntryPoint, TracingResult,
        },
        Chain, EntryPointId,
    },
    storage::{EntryPointFilter, StorageError},
    Bytes,
};

use super::{
    orm::{
        self, EntryPointTracingType, NewEntryPoint, NewEntryPointTracingData,
        NewEntryPointTracingDataCallsAccount, NewEntryPointTracingResult,
        NewProtocolComponentHoldsEntryPointTracingData,
    },
    schema::{self},
    storage_error_from_diesel, PostgresError, PostgresGateway,
};

impl PostgresGateway {
    /// Insert entry points into the database.
    ///
    /// # Arguments
    ///
    /// * `new_data` - A map of protocol component external ids to a list of entry points.
    /// * `chain` - The chain to insert the entry points for.
    /// * `conn` - The database connection to use.
    pub(crate) async fn insert_entry_points(
        &self,
        new_data: &HashMap<&str, &Vec<EntryPointWithData>>,
        chain: &Chain,
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        use schema::{
            entry_point::dsl::*, entry_point_tracing_data::dsl::*,
            protocol_component_holds_entry_point_tracing_data::dsl::*,
        };

        let chain_id = self.get_chain_id(chain);

        let pc_ids = orm::ProtocolComponent::ids_by_external_ids(
            &new_data
                .keys()
                .map(Clone::clone)
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
                        external_id: ep.entry_point.external_id.clone(),
                        target: ep.entry_point.target.clone(),
                        signature: ep.entry_point.signature.clone(),
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
        let input_external_ids: Vec<String> = new_data
            .iter()
            .flat_map(|(_, ep)| {
                ep.iter()
                    .map(|ep| ep.entry_point.external_id.clone())
            })
            .collect();

        let entry_point_ids =
            orm::EntryPoint::ids_by_external_ids(&input_external_ids, conn).await?;

        let new_tracing_data = new_data
            .iter()
            .flat_map(|(_, ep)| {
                ep.iter().map(|ep| {
                    let ext_id = ep.entry_point.external_id.clone();
                    let ep_id = entry_point_ids
                        .get(&ext_id)
                        .ok_or_else(|| StorageError::NotFound("EntryPoint".to_string(), ext_id))?;

                    let ep_data = match &ep.data {
                        EntryPointTracingData::RPCTracer(rpc_tracer) => {
                            Some(serde_json::to_value(rpc_tracer).map_err(|e| {
                                StorageError::Unexpected(format!(
                                    "Failed to serialize RPCTracer: {e}"
                                ))
                            })?)
                        }
                    };

                    Ok(NewEntryPointTracingData {
                        entry_point_id: *ep_id,
                        tracing_type: (&ep.data).into(),
                        data: ep_data,
                    })
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;

        // Fetch entry points by their external_ids, we can't use .returning() on the insert above
        // because it doesn't return the ids on conflicts.
        diesel::insert_into(entry_point_tracing_data)
            .values(&new_tracing_data)
            .on_conflict_do_nothing()
            .execute(conn)
            .await
            .map_err(|e| storage_error_from_diesel(e, "EntryPointData", "Batch upsert", None))?;

        let data_ids = orm::EntryPointTracingData::ids_by_entry_point_with_data(
            &new_data
                .iter()
                .flat_map(|(_, ep)| ep.iter())
                .cloned()
                .collect::<Vec<_>>(),
            conn,
        )
        .await?;

        let pc_links = new_data
            .iter()
            .flat_map(|(pc_ext_id, ep)| {
                ep.iter().map(|ep| {
                    let pc_id = pc_ids.get(*pc_ext_id).ok_or_else(|| {
                        StorageError::NotFound(
                            "ProtocolComponent".to_string(),
                            pc_ext_id.to_string(),
                        )
                    })?;
                    Ok(NewProtocolComponentHoldsEntryPointTracingData {
                        protocol_component_id: *pc_id,
                        entry_point_tracing_data_id: *data_ids.get(ep).ok_or_else(|| {
                            StorageError::NotFound(
                                "EntryPointTracingData".to_string(),
                                ep.entry_point.external_id.clone(),
                            )
                        })?,
                    })
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;

        diesel::insert_into(protocol_component_holds_entry_point_tracing_data)
            .values(&pc_links)
            .on_conflict_do_nothing() //Design choice: we don't want to delete previously inserted links here, they are
            // cumulative
            .execute(conn)
            .await
            .map_err(|e| {
                storage_error_from_diesel(
                    e,
                    "ProtocolComponentHoldsEntryPointData",
                    "Batch upsert",
                    None,
                )
            })?;

        Ok(())
    }

    /// Get entry points with data from the database.
    ///
    /// # Arguments
    ///
    /// * `filter` - The filter to apply to the query.
    /// * `conn` - The database connection to use.
    pub(crate) async fn get_entry_points_with_data(
        &self,
        filter: EntryPointFilter,
        conn: &mut AsyncPgConnection,
    ) -> Result<Vec<EntryPointWithData>, StorageError> {
        use schema::{
            entry_point::dsl::*, entry_point_tracing_data as eptd, protocol_component as pc,
            protocol_component_holds_entry_point_tracing_data as pchep,
        };

        let ps_id = self.get_protocol_system_id(&filter.protocol_system);
        let results = schema::entry_point::table
            .inner_join(eptd::table.on(id.eq(eptd::entry_point_id)))
            .inner_join(pchep::table.on(eptd::id.eq(pchep::entry_point_tracing_data_id)))
            .inner_join(pc::table.on(pchep::protocol_component_id.eq(pc::id)))
            .filter(pc::protocol_system_id.eq(ps_id))
            .select((orm::EntryPoint::as_select(), orm::EntryPointTracingData::as_select()))
            .load::<(orm::EntryPoint, orm::EntryPointTracingData)>(conn)
            .await
            .map_err(|err| {
                storage_error_from_diesel(
                    err,
                    "EntryPointWithData",
                    "None",
                    Some(format!("protocol: {:?}", filter.protocol_system)),
                )
            })?;

        Ok(results
            .into_iter()
            .map(|(ep, data)| EntryPointWithData { entry_point: ep.into(), data: (&data).into() })
            .collect())
    }

    /// Upsert traced entry points into the database.
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
            entry_point_tracing_data_calls_account::dsl::*, entry_point_tracing_result::dsl::*,
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

        let data_ids = orm::EntryPointTracingData::ids_by_entry_point_with_data(
            &traced_entry_points
                .iter()
                .map(|tep| tep.entry_point_with_data.clone())
                .collect::<Vec<_>>(),
            conn,
        )
        .await?;

        let mut values = Vec::with_capacity(traced_entry_points.len());
        for tep in traced_entry_points {
            let data_id = data_ids
                .get(&tep.entry_point_with_data)
                .ok_or_else(|| {
                    StorageError::NotFound(
                        "EntryPointTracingData".to_string(),
                        tep.entry_point_with_data
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

            let tracing_data = serde_json::to_value(&tep.tracing_result).map_err(|e| {
                StorageError::Unexpected(format!("Failed to serialize TracingResult: {e}"))
            })?;

            values.push(NewEntryPointTracingResult {
                entry_point_tracing_data_id: *data_id,
                detection_block: block_id,
                detection_data: tracing_data,
            });
        }

        diesel::insert_into(entry_point_tracing_result)
            .values(&values)
            .on_conflict(schema::entry_point_tracing_result::entry_point_tracing_data_id)
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
        for (tep, &data_id) in traced_entry_points
            .iter()
            .zip(data_ids.values())
        {
            for address in &tep.tracing_result.called_addresses {
                let acc_id = account_id_map
                    .get(address)
                    .ok_or_else(|| {
                        StorageError::NotFound("Account".to_string(), address.to_string())
                    })?;

                new_entry_point_calls_account.push(NewEntryPointTracingDataCallsAccount {
                    entry_point_tracing_data_id: data_id,
                    account_id: *acc_id,
                });
            }
        }

        diesel::insert_into(entry_point_tracing_data_calls_account)
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
    pub(crate) async fn get_traced_entry_points(
        &self,
        entry_points: &HashSet<EntryPointId>,
        conn: &mut AsyncPgConnection,
    ) -> Result<HashMap<EntryPointId, Vec<TracingResult>>, StorageError> {
        use schema::entry_point_tracing_result::dsl::*;
        let entry_point_ids = orm::EntryPoint::ids_by_external_ids(
            &entry_points
                .iter()
                .map(Clone::clone)
                .collect::<Vec<_>>(),
            conn,
        )
        .await?;

        // Reverse the map, this is safe because we know it's a 1:1 mapping.
        // This makes retrieving the external id attached to a tracing result faster.
        let reverse: HashMap<i64, String> = entry_point_ids
            .iter()
            .map(|(k, &v)| (v, k.clone()))
            .collect();

        let results = entry_point_tracing_result
            .filter(entry_point_tracing_data_id.eq_any(entry_point_ids.values().cloned()))
            .select((entry_point_tracing_data_id, detection_data))
            .load::<(i64, serde_json::Value)>(conn)
            .await
            .map_err(|e| storage_error_from_diesel(e, "TracingResult", "Query", None))?;

        let mut results_by_entry_point = HashMap::new();
        for (ep_id, tracing_result) in results {
            let ep_ext_id = reverse.get(&ep_id).ok_or_else(|| {
                StorageError::NotFound("EntryPoint".to_string(), ep_id.to_string())
            })?;
            results_by_entry_point
                .entry(ep_ext_id.clone())
                .or_insert_with(Vec::new)
                .push(tracing_result);
        }

        results_by_entry_point
            .into_iter()
            .map(|(ep_ext_id, data)| {
                let converted_data = data
                    .into_iter()
                    .map(|d| {
                        serde_json::from_value(d).map_err(|e| {
                            StorageError::Unexpected(format!(
                                "Failed to deserialize TracingResult: {e}"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, StorageError>>()?;
                Ok((ep_ext_id, converted_data))
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use diesel_async::AsyncConnection;
    use tycho_common::{
        keccak256,
        models::{
            blockchain::{
                EntryPointTracingData, RPCTracerEntryPoint, TracedEntryPoint, TracingResult,
            },
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
        db_fixtures::insert_protocol_system(conn, "unknown".to_string()).await;

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
    }

    fn rpc_tracer_entry_point() -> EntryPointWithData {
        EntryPointWithData {
            entry_point: EntryPoint {
                external_id: "0xEdf63cce4bA70cbE74064b7687882E71ebB0e988:getRate()".to_string(),
                target: Bytes::from_str("0xEdf63cce4bA70cbE74064b7687882E71ebB0e988").unwrap(),
                signature: "getRate()".to_string(),
            },
            data: EntryPointTracingData::RPCTracer(RPCTracerEntryPoint {
                caller: None,
                data: Bytes::from(&keccak256("getRate()")[0..4]),
            }),
        }
    }

    fn traced_entry_point() -> TracedEntryPoint {
        TracedEntryPoint {
            entry_point_with_data: rpc_tracer_entry_point(),
            detection_block_hash: Bytes::from_str(
                "88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6",
            )
            .unwrap(),
            tracing_result: TracingResult::new(
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
        }
    }

    #[tokio::test]
    async fn test_entry_points_round_trip() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = PostgresGateway::from_connection(&mut conn).await;

        let entry_point = rpc_tracer_entry_point();
        gw.insert_entry_points(
            &HashMap::from([("pc_0", &vec![entry_point.clone()])]),
            &Chain::Ethereum,
            &mut conn,
        )
        .await
        .unwrap();

        let filter = EntryPointFilter::new("test_protocol".to_string());
        let retrieved_entry_points = gw
            .get_entry_points_with_data(filter, &mut conn)
            .await
            .unwrap();

        assert_eq!(retrieved_entry_points[0], entry_point);
    }

    #[tokio::test]
    async fn test_get_entry_points_with_filter() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = PostgresGateway::from_connection(&mut conn).await;

        let entry_point = rpc_tracer_entry_point();
        gw.insert_entry_points(
            &HashMap::from([("pc_0", &vec![entry_point.clone()])]),
            &Chain::Ethereum,
            &mut conn,
        )
        .await
        .unwrap();

        // Filter by protocol name
        let filter = EntryPointFilter::new("test_protocol".to_string());
        let retrieved_entry_points = gw
            .get_entry_points_with_data(filter, &mut conn)
            .await
            .unwrap();
        assert_eq!(retrieved_entry_points, vec![entry_point]);

        let filter = EntryPointFilter::new("unknown".to_string());
        let retrieved_entry_points = gw
            .get_entry_points_with_data(filter, &mut conn)
            .await
            .unwrap();
        assert_eq!(retrieved_entry_points, vec![]);
    }

    #[tokio::test]
    async fn test_traced_entry_points_round_trip() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = PostgresGateway::from_connection(&mut conn).await;

        let entry_point = rpc_tracer_entry_point();
        let traced_entry_point = traced_entry_point();

        gw.insert_entry_points(
            &HashMap::from([("pc_0", &vec![entry_point.clone()])]),
            &Chain::Ethereum,
            &mut conn,
        )
        .await
        .unwrap();

        gw.upsert_traced_entry_points(&[traced_entry_point.clone()], &mut conn)
            .await
            .unwrap();

        let retrieved_traced_entry_points = gw
            .get_traced_entry_points(
                &HashSet::from([entry_point
                    .entry_point
                    .external_id
                    .clone()]),
                &mut conn,
            )
            .await
            .unwrap();

        assert_eq!(
            retrieved_traced_entry_points,
            HashMap::from([(
                entry_point
                    .entry_point
                    .external_id
                    .clone(),
                vec![traced_entry_point.tracing_result]
            )])
        );
    }
}

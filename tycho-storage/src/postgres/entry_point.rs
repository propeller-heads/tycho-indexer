#![allow(unused)] //TODO: Remove this once we have usage in extractors
use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use diesel::{prelude::*, upsert::excluded};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use tycho_common::{
    models::{
        blockchain::{
            EntryPoint, EntryPointTracingData, EntryPointWithData, TracedEntryPoint, TracingResult,
        },
        Chain, ProtocolSystem as ProtocolSystemType,
    },
    storage::{EntryPointFilter, StorageError},
    Bytes,
};

use super::{
    orm::{
        EntryPoint as ORMEntryPoint, EntryPointTracingData as ORMEntryPointTracingData,
        EntryPointTracingResult, NewEntryPoint, ProtocolComponent, ProtocolSystem,
    },
    schema::{self},
    storage_error_from_diesel, PostgresGateway,
};
use crate::postgres::{
    orm::{
        EntryPointTracingType, NewEntryPointTracingData, NewEntryPointTracingDataCallsAccount,
        NewEntryPointTracingResult, NewProtocolComponentHoldsEntryPointTracingData,
    },
    PostgresError,
};

impl PostgresGateway {
    pub(crate) async fn upsert_entry_points(
        &self,
        entry_points: &[EntryPointWithData],
        component_id: &str,
        chain: &Chain,
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        use schema::{
            entry_point::dsl::*, entry_point_tracing_data::dsl::*,
            protocol_component_holds_entry_point_tracing_data::dsl::*,
        };

        let chain_id = self.get_chain_id(chain);
        let pc_ids = ProtocolComponent::ids_by_external_ids(&[component_id], chain_id, conn)
            .await
            .map_err(PostgresError::from)?
            .into_iter()
            .map(|(pc_id, ext_id)| (ext_id, pc_id))
            .collect::<HashMap<_, _>>();

        let pc_id = pc_ids
            .get(component_id)
            .ok_or_else(|| {
                StorageError::NotFound("ProtocolComponent".to_string(), component_id.to_string())
            })?;

        let new_entry_points = entry_points
            .iter()
            .map(|ep| NewEntryPoint {
                external_id: ep.entry_point.external_id(),
                target: ep.entry_point.target.clone(),
                signature: ep.entry_point.signature.clone(),
            })
            .collect::<Vec<_>>();

        diesel::insert_into(entry_point)
            .values(&new_entry_points)
            .on_conflict_do_nothing()
            .execute(conn)
            .await
            .map_err(|e| storage_error_from_diesel(e, "EntryPoint", "Batch upsert", None))?;

        // Fetch entry points by their external_ids, we can't use .returning() on the insert above
        // because it doesn't return the ids on conflicts.
        let input_external_ids: Vec<String> = entry_points
            .iter()
            .map(|ep| ep.entry_point.external_id())
            .collect();

        let entry_point_ids = ORMEntryPoint::ids_by_external_ids(&input_external_ids, conn).await?;

        let new_tracing_data = entry_points
            .iter()
            .map(|ep| {
                let ext_id = ep.entry_point.external_id();
                let ep_id = entry_point_ids
                    .get(&ext_id)
                    .ok_or_else(|| StorageError::NotFound("EntryPoint".to_string(), ext_id))?;

                let ep_data = match &ep.data {
                    EntryPointTracingData::RPCTracer(rpc_tracer) => {
                        Some(serde_json::to_value(rpc_tracer).map_err(|e| {
                            StorageError::Unexpected(format!("Failed to serialize RPCTracer: {e}"))
                        })?)
                    }
                };

                Ok(NewEntryPointTracingData {
                    entry_point_id: *ep_id,
                    tracing_type: (&ep.data).into(),
                    data: ep_data,
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;

        let data_ids = diesel::insert_into(entry_point_tracing_data)
            .values(&new_tracing_data)
            .on_conflict_do_nothing()
            .returning(schema::entry_point_tracing_data::id)
            .get_results::<i64>(conn)
            .await
            .map_err(|e| storage_error_from_diesel(e, "EntryPointData", "Batch upsert", None))?;

        let pc_links = data_ids
            .into_iter()
            .map(|data_id| NewProtocolComponentHoldsEntryPointTracingData {
                protocol_component_id: *pc_id,
                entry_point_tracing_data_id: data_id,
            })
            .collect::<Vec<_>>();

        diesel::insert_into(protocol_component_holds_entry_point_tracing_data)
            .values(&pc_links)
            .on_conflict_do_nothing() //TODO: Do we need to delete every previously inserted links?
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

    pub(crate) async fn get_entry_points(
        &self,
        filter: EntryPointFilter,
        conn: &mut AsyncPgConnection,
    ) -> Result<Vec<EntryPoint>, StorageError> {
        use schema::{
            entry_point::dsl::*, entry_point_tracing_data as eptd, protocol_component as pc,
            protocol_component_holds_entry_point_tracing_data as pchep,
        };

        let orm_results = if let Some(ref protocol) = filter.protocol_system {
            let ps_id = ProtocolSystem::id_by_name(protocol, conn).await?;
            schema::entry_point::table
                .inner_join(eptd::table.on(schema::entry_point::id.eq(eptd::entry_point_id)))
                .inner_join(pchep::table.on(eptd::id.eq(pchep::entry_point_tracing_data_id)))
                .inner_join(pc::table.on(pchep::protocol_component_id.eq(pc::id)))
                .filter(pc::protocol_system_id.eq(ps_id))
                .select(ORMEntryPoint::as_select())
                .load::<ORMEntryPoint>(conn)
                .await
                .map_err(|err| {
                    storage_error_from_diesel(
                        err,
                        "EntryPoint",
                        "None",
                        Some(format!("protocol: {:?}", protocol)),
                    )
                })?
        } else {
            entry_point
                .load::<ORMEntryPoint>(conn)
                .await
                .map_err(|err| storage_error_from_diesel(err, "EntryPoint", "None", None))?
        };

        Ok(orm_results
            .into_iter()
            .map(Into::into)
            .collect())
    }

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

        let mut values = Vec::with_capacity(traced_entry_points.len());
        let mut data_ids = Vec::with_capacity(traced_entry_points.len());
        for tep in traced_entry_points {
            let data_id =
                ORMEntryPointTracingData::id_from_entry_point_with_data(&tep.entry_point, conn)
                    .await?;
            data_ids.push(data_id);

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
                StorageError::Unexpected(format!("Failed to serialize TracingResult: {}", e))
            })?;

            values.push(NewEntryPointTracingResult {
                entry_point_tracing_data_id: data_id,
                detection_block: block_id,
                detection_data: tracing_data,
                modified_ts: Some(chrono::Utc::now().naive_utc()),
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
            .zip(&data_ids)
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
            .on_conflict_do_nothing() // TODO: Do we need to delete every previously inserted links?
            .execute(conn)
            .await
            .map_err(|err| {
                storage_error_from_diesel(err, "EntryPointPointsToAccount", "Batch upsert", None)
            })?;

        Ok(())
    }

    pub(crate) async fn get_traced_entry_point(
        &self,
        entry_point: EntryPoint,
        conn: &mut AsyncPgConnection,
    ) -> Result<Vec<TracingResult>, StorageError> {
        use schema::entry_point_tracing_result::dsl::*;
        let entry_point_id = ORMEntryPoint::id_by_target_and_signature(
            &entry_point.target,
            &entry_point.signature,
            conn,
        )
        .await?;

        let results = entry_point_tracing_result
            .filter(entry_point_tracing_data_id.eq(entry_point_id))
            .select(detection_data)
            .load::<serde_json::Value>(conn)
            .await
            .map_err(|e| storage_error_from_diesel(e, "TracingResult", "Query", None))?;

        results
            .into_iter()
            .map(|(data)| {
                serde_json::from_value(data).map_err(|e| {
                    StorageError::Unexpected(format!("Failed to deserialize TracingResult: {}", e))
                })
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
                target: Bytes::from_str("0xEdf63cce4bA70cbE74064b7687882E71ebB0e988").unwrap(),
                signature: "getRate()".to_string(),
            },
            data: EntryPointTracingData::RPCTracer(RPCTracerEntryPoint::new(
                None,
                Bytes::from(keccak256("getRate()")),
            )),
        }
    }

    fn traced_entry_point() -> TracedEntryPoint {
        TracedEntryPoint {
            entry_point: rpc_tracer_entry_point(),
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
        gw.upsert_entry_points(&[entry_point.clone()], "pc_0", &Chain::Ethereum, &mut conn)
            .await
            .unwrap();

        let filter = EntryPointFilter::new(None);
        let retrieved_entry_points = gw
            .get_entry_points(filter, &mut conn)
            .await
            .unwrap();

        assert_eq!(retrieved_entry_points[0], entry_point.entry_point);
    }

    #[tokio::test]
    async fn test_get_entry_points_with_filter() {
        let mut conn = setup_db().await;
        setup_data(&mut conn).await;
        let gw = PostgresGateway::from_connection(&mut conn).await;

        let entry_point = rpc_tracer_entry_point();
        gw.upsert_entry_points(&[entry_point.clone()], "pc_0", &Chain::Ethereum, &mut conn)
            .await
            .unwrap();

        // Filter by protocol name
        let filter = EntryPointFilter::new(Some("test_protocol".to_string()));
        let retrieved_entry_points = gw
            .get_entry_points(filter, &mut conn)
            .await
            .unwrap();
        assert_eq!(retrieved_entry_points, vec![entry_point.entry_point]);

        let filter = EntryPointFilter::new(Some("unknown".to_string()));
        let retrieved_entry_points = gw
            .get_entry_points(filter, &mut conn)
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

        gw.upsert_entry_points(&[entry_point.clone()], "pc_0", &Chain::Ethereum, &mut conn)
            .await
            .unwrap();

        gw.upsert_traced_entry_points(&[traced_entry_point.clone()], &mut conn)
            .await
            .unwrap();

        let retrieved_traced_entry_points = gw
            .get_traced_entry_point(entry_point.entry_point, &mut conn)
            .await
            .unwrap();

        assert_eq!(retrieved_traced_entry_points, vec![traced_entry_point.tracing_result]);
    }
}

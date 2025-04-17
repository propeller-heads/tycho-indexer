#![allow(unused)] //TODO: Remove this once we have usage in extractors
use std::collections::HashMap;

use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use tycho_common::{
    models::{
        blockchain::{EntryPoint, EntryPointTracingData, EntryPointWithData, TracedEntryPoint},
        Chain,
    },
    storage::StorageError,
    Bytes,
};

use super::{
    orm::{
        EntryPoint as ORMEntryPoint, NewEntryPoint, NewTracedEntryPoint, ProtocolComponent,
        ProtocolSystem, TracedEntryPoint as ORMTracedEntryPoint,
    },
    schema::{self},
    storage_error_from_diesel, PostgresGateway,
};
use crate::postgres::{
    orm::{
        EntryPointTracingType, NewEntryPointCallsAccount, NewEntryPointTracingData,
        NewProtocolComponentHoldsEntryPoint,
    },
    PostgresError,
};

pub struct EntryPointFilter {
    protocol_name: Option<String>,
}

impl EntryPointFilter {
    pub fn new(protocol: Option<String>) -> Self {
        Self { protocol_name: protocol }
    }
}

impl PostgresGateway {
    pub async fn upsert_entry_points(
        &self,
        entry_points: &[EntryPointWithData],
        component_id: &str,
        chain: &Chain,
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        use schema::{
            entry_point::dsl::*, entry_point_tracing_data::dsl::*,
            protocol_component_holds_entry_point::dsl::*,
        };
        let chain_id = self.get_chain_id(chain);
        let pc_id = ProtocolComponent::ids_by_external_ids(&[component_id], chain_id, conn)
            .await
            .map_err(PostgresError::from)?
            .into_iter()
            .map(|(pc_id, ext_id)| (ext_id, pc_id))
            .collect::<HashMap<String, i64>>();

        let new_entry_points: Vec<NewEntryPoint> = entry_points
            .iter()
            .map(|ep| {
                Ok(NewEntryPoint {
                    target: ep.entry_point.target.clone(),
                    signature: ep.entry_point.signature.clone(),
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;

        diesel::insert_into(entry_point)
            .values(&new_entry_points)
            .on_conflict_do_nothing()
            .execute(conn)
            .await
            .map_err(|err| storage_error_from_diesel(err, "EntryPoint", "Batch upsert", None))?;

        let entry_point_pairs = entry_points
            .iter()
            .map(|ep| (ep.entry_point.target.clone(), ep.entry_point.signature.clone()))
            .collect::<Vec<_>>();
        let ids_map = ORMEntryPoint::ids_by_target_and_signature(&entry_point_pairs, conn).await?;

        let new_entry_point_holds_entry_point: Vec<NewProtocolComponentHoldsEntryPoint> =
            entry_points
                .iter()
                .map(|ep| {
                    Ok(NewProtocolComponentHoldsEntryPoint {
                        protocol_component_id: pc_id
                            .get(component_id)
                            .cloned()
                            .ok_or_else(|| {
                                StorageError::Unexpected(format!(
                                    "ProtocolComponent not found: {}",
                                    component_id
                                ))
                            })?,
                        entry_point_id: ids_map
                            .get(&(ep.entry_point.target.clone(), ep.entry_point.signature.clone()))
                            .cloned()
                            .ok_or_else(|| {
                                StorageError::Unexpected(format!(
                                    "EntryPoint not found for target: {}, signature: {}",
                                    ep.entry_point.target, ep.entry_point.signature
                                ))
                            })?,
                    })
                })
                .collect::<Result<Vec<_>, StorageError>>()?;

        diesel::insert_into(protocol_component_holds_entry_point)
            .values(&new_entry_point_holds_entry_point)
            .on_conflict_do_nothing()
            .execute(conn)
            .await
            .map_err(|err| {
                storage_error_from_diesel(
                    err,
                    "ProtocolComponentHoldsEntryPoint",
                    "Batch upsert",
                    None,
                )
            })?;

        let new_entry_point_data: Vec<NewEntryPointTracingData> = entry_points
            .iter()
            .flat_map(|ep| {
                ep.data.iter().map(|ep_data| {
                    let ep_id = ids_map
                        .get(&(ep.entry_point.target.clone(), ep.entry_point.signature.clone()))
                        .cloned()
                        .ok_or_else(|| {
                            StorageError::Unexpected(format!(
                                "EntryPoint not found for target: {}, signature: {}",
                                ep.entry_point.target, ep.entry_point.signature
                            ))
                        })?;
                    let ep_type = match ep_data {
                        EntryPointTracingData::RPCTracer(_) => EntryPointTracingType::RpcTracer,
                    };
                    let entry_point_data = match ep_data {
                        EntryPointTracingData::RPCTracer(rpc_tracer) => {
                            serde_json::to_value(rpc_tracer).map_err(|e| {
                                StorageError::Unexpected(format!(
                                    "Failed to serialize RPCTracerEntryPoint: {}",
                                    e
                                ))
                            })?
                        }
                    };

                    Ok(NewEntryPointTracingData {
                        entry_point_id: ep_id,
                        tracing_type: ep_type,
                        data: entry_point_data,
                    })
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;

        diesel::insert_into(entry_point_tracing_data)
            .values(&new_entry_point_data)
            .on_conflict_do_nothing()
            .execute(conn)
            .await
            .map_err(|err| {
                storage_error_from_diesel(err, "EntryPointData", "Batch upsert", None)
            })?;

        Ok(())
    }

    pub async fn get_entry_points(
        &self,
        filter: EntryPointFilter,
        conn: &mut AsyncPgConnection,
    ) -> Result<Vec<EntryPoint>, StorageError> {
        use schema::entry_point::dsl::*;

        let orm_results = if let Some(ref protocol) = filter.protocol_name {
            let ps_id = ProtocolSystem::id_by_name(protocol, conn).await?;
            schema::entry_point::table
                .inner_join(
                    schema::protocol_component_holds_entry_point::table.on(schema::entry_point::id
                        .eq(schema::protocol_component_holds_entry_point::entry_point_id)),
                )
                .inner_join(
                    schema::protocol_component::table
                        .on(schema::protocol_component_holds_entry_point::protocol_component_id
                            .eq(schema::protocol_component::id)),
                )
                .filter(schema::protocol_component::protocol_system_id.eq(ps_id))
                .select(entry_point::all_columns()) // Or ORMEntryPoint::as_select()
                .load::<ORMEntryPoint>(conn)
                .await
                .map_err(|err| storage_error_from_diesel(err, "EntryPoint", "None", None))?
        } else {
            entry_point
                .load::<ORMEntryPoint>(conn)
                .await
                .map_err(|err| storage_error_from_diesel(err, "EntryPoint", "None", None))?
        };

        let mut results = Vec::with_capacity(orm_results.len());

        for orm_ep in orm_results {
            results.push(EntryPoint::new(orm_ep.target, orm_ep.signature))
        }

        Ok(results)
    }

    pub async fn upsert_traced_entry_points(
        &self,
        traced_entry_points: &[TracedEntryPoint],
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        use schema::{entry_point_calls_account::dsl::*, traced_entry_point::dsl::*};

        let mut values = Vec::with_capacity(traced_entry_points.len());

        let entry_point_pairs = traced_entry_points
            .iter()
            .map(|ep| (ep.entry_point.target.clone(), ep.entry_point.signature.clone()))
            .collect::<Vec<_>>();
        let ids_map = ORMEntryPoint::ids_by_target_and_signature(&entry_point_pairs, conn).await?;

        for tep in traced_entry_points {
            let block_id = schema::block::table
                .filter(schema::block::hash.eq(tep.detection_block_hash.clone()))
                .select(schema::block::id)
                .first::<i64>(conn)
                .await
                .map_err(PostgresError::from)?;

            values.push(NewTracedEntryPoint {
                entry_point_id: ids_map
                    .get(&(tep.entry_point.target.clone(), tep.entry_point.signature.clone()))
                    .cloned()
                    .ok_or_else(|| {
                        StorageError::Unexpected(format!(
                            "EntryPoint not found for target: {}, signature: {}",
                            tep.entry_point.target, tep.entry_point.signature
                        ))
                    })?,
                detection_block: block_id,
                detection_data: serde_json::to_value(&tep.tracing_result).map_err(|e| {
                    StorageError::Unexpected(format!("Failed to serialize TracingResult: {}", e))
                })?,
            });
        }

        diesel::insert_into(traced_entry_point)
            .values(&values)
            .execute(conn)
            .await
            .map_err(|err| {
                storage_error_from_diesel(err, "TracedEntryPoint", "Batch upsert", None)
            })?;

        let mut new_entry_point_calls_account = Vec::new();
        for tep in traced_entry_points {
            let called_accounts = tep
                .tracing_result
                .called_addresses
                .clone();

            let account_ids = schema::account::table
                .filter(schema::account::address.eq_any(called_accounts))
                .select(schema::account::id)
                .load::<i64>(conn)
                .await
                .map_err(PostgresError::from)?;

            for acc_id in account_ids {
                new_entry_point_calls_account.push(NewEntryPointCallsAccount {
                    entry_point_id: ids_map
                        .get(&(tep.entry_point.target.clone(), tep.entry_point.signature.clone()))
                        .cloned()
                        .ok_or_else(|| {
                            StorageError::Unexpected(format!(
                                "EntryPoint not found for target: {}, signature: {}",
                                tep.entry_point.target, tep.entry_point.signature
                            ))
                        })?,
                    account_id: acc_id,
                });
            }
        }

        diesel::insert_into(entry_point_calls_account)
            .values(&new_entry_point_calls_account)
            .execute(conn)
            .await
            .map_err(|err| {
                storage_error_from_diesel(err, "EntryPointPointsToAccount", "Batch upsert", None)
            })?;

        Ok(())
    }

    pub async fn get_traced_entry_point(
        &self,
        entry_point: EntryPoint,
        conn: &mut AsyncPgConnection,
    ) -> Result<Vec<TracedEntryPoint>, StorageError> {
        use schema::traced_entry_point::dsl::*;
        let entry_point_pair = vec![(entry_point.target.clone(), entry_point.signature.clone())];
        let ids_map = ORMEntryPoint::ids_by_target_and_signature(&entry_point_pair, conn).await?;

        let query_results = traced_entry_point
            .filter(entry_point_id.eq_any(ids_map.values()))
            .load::<ORMTracedEntryPoint>(conn)
            .await
            .map_err(|err| storage_error_from_diesel(err, "TracedEntryPoint", "TODO", None))?;

        let mut results = Vec::with_capacity(query_results.len());

        for tep in query_results {
            let detection_block_hash = schema::block::table
                .filter(schema::block::id.eq(tep.detection_block))
                .select(schema::block::hash)
                .first::<Bytes>(conn)
                .await
                .map_err(PostgresError::from)?;

            let tracing_result = serde_json::from_value(tep.detection_data).map_err(|e| {
                StorageError::Unexpected(format!("Failed to deserialize TracingResult: {}", e))
            })?;

            results.push(TracedEntryPoint::new(
                entry_point.clone(),
                detection_block_hash,
                tracing_result,
            ));
        }

        Ok(results)
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
            data: vec![EntryPointTracingData::RPCTracer(RPCTracerEntryPoint {
                caller: None,
                data: Bytes::from(keccak256("getRate()")),
            })],
        }
    }

    fn traced_entry_point() -> TracedEntryPoint {
        TracedEntryPoint {
            entry_point: EntryPoint {
                target: Bytes::from_str("0xEdf63cce4bA70cbE74064b7687882E71ebB0e988").unwrap(),
                signature: "getRate()".to_string(),
            },
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

        assert_eq!(retrieved_traced_entry_points, vec![traced_entry_point]);
    }
}

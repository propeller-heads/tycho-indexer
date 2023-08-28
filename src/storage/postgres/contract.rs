use std::collections::HashMap;

use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use ethers::types::U256;

use crate::storage::{orm, schema, BlockIdentifier, BlockOrTimestamp, ContractId, StorageError};

use super::PostgresGateway;

impl<B, TX> PostgresGateway<B, TX> {
    async fn get_slots_delta(
        &self,
        id: ContractId<'_>,
        current_version: Option<BlockOrTimestamp>,
        target_version: Option<BlockOrTimestamp>,
        conn: &mut AsyncPgConnection,
    ) -> Result<HashMap<U256, U256>, StorageError> {
        let chain_id = self.get_chain_id(id.0);
        let start_version_ts = version_to_ts(&current_version, conn).await?;
        let target_version_ts = version_to_ts(&target_version, conn).await?;

        let contract_id = schema::contract::table
            .inner_join(schema::chain::table)
            .filter(schema::chain::id.eq(chain_id))
            .filter(schema::contract::address.eq(id.1))
            .select(schema::contract::id)
            .first::<i64>(conn)
            .await
            .unwrap();

        let changed_values = if start_version_ts <= target_version_ts {
            schema::contract_storage::table
                .filter(schema::contract_storage::contract_id.eq(contract_id))
                .filter(schema::contract_storage::valid_from.gt(start_version_ts))
                .filter(schema::contract_storage::valid_from.le(target_version_ts))
                .order_by((
                    schema::contract_storage::slot,
                    schema::contract_storage::valid_from.desc(),
                    schema::contract_storage::ordinal.desc(),
                ))
                .select((
                    schema::contract_storage::slot,
                    schema::contract_storage::value,
                ))
                .distinct_on(schema::contract_storage::slot)
                .get_results::<(Vec<u8>, Option<Vec<u8>>)>(conn)
                .await
                .unwrap()
        } else {
            // we are going backwards, so we'll include data to revert from the
            // current version. Assume the target version changes were applied
            // previously already
            schema::contract_storage::table
                .filter(schema::contract_storage::contract_id.eq(contract_id))
                .filter(schema::contract_storage::valid_from.gt(target_version_ts))
                .filter(schema::contract_storage::valid_from.le(start_version_ts))
                .order_by((
                    schema::contract_storage::slot,
                    schema::contract_storage::valid_from.asc(),
                    schema::contract_storage::ordinal.asc(),
                ))
                .select((
                    schema::contract_storage::slot,
                    schema::contract_storage::previous_value,
                ))
                .distinct_on(schema::contract_storage::slot)
                .get_results::<(Vec<u8>, Option<Vec<u8>>)>(conn)
                .await
                .unwrap()
        };

        changed_values
            .iter()
            .map(|(raw_key, raw_val)| {
                if raw_key.len() != 32 {
                    return Err(StorageError::DecodeError(format!(
                        "Invalid byte length for U256 in slot key! Found: 0x{}",
                        hex::encode(raw_key)
                    )));
                }
                if let Some(val) = raw_val {
                    if val.len() != 32 {
                        return Err(StorageError::DecodeError(format!(
                            "Invalid byte length for U256 in slot value! Found: 0x{}",
                            hex::encode(val)
                        )));
                    }
                }
                let v: U256 = raw_val
                    .as_ref()
                    .map(|rv| U256::from_big_endian(rv))
                    .unwrap_or_else(U256::zero);

                Ok((U256::from_big_endian(raw_key), v))
            })
            .collect()
    }
}

async fn version_to_ts(
    start_version: &Option<BlockOrTimestamp>,
    conn: &mut AsyncPgConnection,
) -> Result<NaiveDateTime, StorageError> {
    match &start_version {
        Some(BlockOrTimestamp::Block(BlockIdentifier::Hash(h))) => {
            Ok(orm::Block::by_hash(&h, conn)
                .await
                .map_err(|err| StorageError::from_diesel(err, "Block", &hex::encode(h), None))?
                .ts)
        }
        Some(BlockOrTimestamp::Block(BlockIdentifier::Number((chain, no)))) => {
            Ok(orm::Block::by_number(*chain, *no, conn)
                .await
                .map_err(|err| StorageError::from_diesel(err, "Block", &format!("{}", no), None))?
                .ts)
        }
        Some(BlockOrTimestamp::Timestamp(ts)) => Ok(*ts),
        None => Ok(Utc::now().naive_utc()),
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::str::FromStr;

    use chrono::NaiveDateTime;
    use diesel::prelude::*;
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
    use ethers::types::H160;
    use ethers::types::U256;

    use crate::extractor::evm;
    use crate::models::Chain;
    use crate::storage::orm;
    use crate::storage::postgres::fixtures;
    use crate::storage::postgres::PostgresGateway;
    use crate::storage::schema;
    use crate::storage::BlockOrTimestamp;
    use crate::storage::ContractId;

    async fn setup_db() -> AsyncPgConnection {
        let db_url = std::env::var("DATABASE_URL").unwrap();
        let mut conn = AsyncPgConnection::establish(&db_url).await.unwrap();
        conn.begin_test_transaction().await.unwrap();
        conn
    }

    async fn setup_slots_delta(conn: &mut AsyncPgConnection) {
        let chain_id = fixtures::insert_chain(conn, "ethereum").await;
        let blk = fixtures::insert_blocks(conn, chain_id).await;
        let txn = fixtures::insert_txns(
            conn,
            &[
                (
                    blk[0],
                    1i64,
                    "0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945",
                ),
                (
                    blk[1],
                    1i64,
                    "0x3108322284d0a89a7accb288d1a94384d499504fe7e04441b0706c7628dee7b7",
                ),
            ],
        )
        .await;
        let c0 = fixtures::insert_contract(
            conn,
            "0x6B175474E89094C44Da98b954EedeAC495271d0F",
            "c0",
            chain_id,
        )
        .await;
        fixtures::insert_slots(
            conn,
            c0,
            txn[0],
            "2020-01-01T00:00:00",
            &[(0, 1), (1, 5), (2, 1)],
        )
        .await;
        fixtures::insert_slots(
            conn,
            c0,
            txn[1],
            "2020-01-01T01:00:00",
            &[(0, 2), (1, 3), (5, 25), (6, 30)],
        )
        .await;
    }

    async fn print_slots(conn: &mut AsyncPgConnection) {
        let all_slots: Vec<orm::ContractStorage> = schema::contract_storage::table
            .select(orm::ContractStorage::as_select())
            .get_results(conn)
            .await
            .unwrap();

        dbg!(all_slots
            .iter()
            .map(|s| (
                s.contract_id,
                U256::from_big_endian(&s.slot),
                s.previous_value
                    .clone()
                    .map(|v| U256::from_big_endian(&v))
                    .unwrap_or_else(U256::zero),
                s.value
                    .clone()
                    .map(|v| U256::from_big_endian(&v))
                    .unwrap_or_else(U256::zero),
                s.valid_from,
                s.valid_to
            ))
            .collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn get_slots_delta_forward() {
        let mut conn = setup_db().await;
        setup_slots_delta(&mut conn).await;
        let gw = PostgresGateway::<evm::Block, evm::Transaction>::from_connection(&mut conn).await;
        let exp: HashMap<U256, U256> = vec![(0, 2), (1, 3), (5, 25), (6, 30)]
            .iter()
            .map(|(k, v)| (U256::from(*k), U256::from(*v)))
            .collect();

        let res = gw
            .get_slots_delta(
                ContractId(
                    Chain::Ethereum,
                    H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                        .unwrap()
                        .as_bytes(),
                ),
                Some(BlockOrTimestamp::Timestamp(
                    "2020-01-01T00:00:00".parse::<NaiveDateTime>().unwrap(),
                )),
                Some(BlockOrTimestamp::Timestamp(
                    "2020-01-01T02:00:00".parse::<NaiveDateTime>().unwrap(),
                )),
                &mut conn,
            )
            .await
            .unwrap();

        assert_eq!(res, exp);
    }

    #[tokio::test]
    async fn get_slots_delta_backward() {
        let mut conn = setup_db().await;
        setup_slots_delta(&mut conn).await;
        let gw = PostgresGateway::<evm::Block, evm::Transaction>::from_connection(&mut conn).await;
        print_slots(&mut conn).await;
        let exp: HashMap<U256, U256> = vec![(0, 1), (1, 5), (5, 0), (6, 0)]
            .iter()
            .map(|(k, v)| (U256::from(*k), U256::from(*v)))
            .collect();

        let res = gw
            .get_slots_delta(
                ContractId(
                    Chain::Ethereum,
                    H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                        .unwrap()
                        .as_bytes(),
                ),
                Some(BlockOrTimestamp::Timestamp(
                    "2020-01-01T02:00:00".parse::<NaiveDateTime>().unwrap(),
                )),
                Some(BlockOrTimestamp::Timestamp(
                    "2020-01-01T00:00:00".parse::<NaiveDateTime>().unwrap(),
                )),
                &mut conn,
            )
            .await
            .unwrap();

        assert_eq!(res, exp);
    }
}

use std::collections::hash_map::Entry;

use async_trait::async_trait;
use chrono::{NaiveDateTime, Utc};
use ethers::types::{H160, U256};

use crate::{
    extractor::evm::{Account, AccountUpdate},
    storage::{
        BlockIdentifier, BlockOrTimestamp, ContractId, ContractStateGateway, StorableBlock,
        StorableTransaction, Version,
    },
};

use super::*;

#[async_trait]
impl<B, TX> ContractStateGateway for PostgresGateway<B, TX>
where
    B: StorableBlock<orm::Block, orm::NewBlock> + Send + Sync + 'static,
    TX: StorableTransaction<orm::Transaction, orm::NewTransaction, Vec<u8>, i64>
        + Send
        + Sync
        + 'static,
{
    type DB = AsyncPgConnection;
    type ContractState = Account;
    type Address = H160;
    type Slot = U256;
    type Value = U256;

    async fn get_contract(
        &mut self,
        id: ContractId,
        at: Option<Version>,
    ) -> Result<Self::ContractState, StorageError> {
        Err(StorageError::NotFound(
            "ContractState".to_owned(),
            "id".to_owned(),
        ))
    }

    async fn add_contract(&mut self, new: Self::ContractState) -> Result<(), StorageError> {
        Ok(())
    }

    async fn delete_contract(
        &self,
        id: ContractId,
        at_tx: Option<&[u8]>,
    ) -> Result<(), StorageError> {
        Ok(())
    }

    async fn get_contract_slots(
        &self,
        id: ContractId,
        at: Option<Version>,
    ) -> Result<HashMap<Self::Slot, Self::Value>, StorageError> {
        Err(StorageError::NotFound(
            "ContractState".to_owned(),
            "id".to_owned(),
        ))
    }

    async fn upsert_slots(
        &self,
        id: ContractId,
        modify_tx: &[u8],
        slots: HashMap<Self::Slot, Self::Value>,
    ) -> Result<(), StorageError> {
        Ok(())
    }

    async fn get_slots_delta(
        &self,
        chain: Chain,
        start_version: Option<BlockOrTimestamp>,
        target_version: Option<BlockOrTimestamp>,
        conn: &mut AsyncPgConnection,
    ) -> Result<HashMap<H160, HashMap<U256, U256>>, StorageError> {
        let chain_id = self.get_chain_id(chain);
        // To support blocks as versions, we need to ingest all blocks, else the
        // below method can error for any blocks that are not present.
        let start_version_ts = version_to_ts(&start_version, conn).await?;
        let target_version_ts = version_to_ts(&target_version, conn).await?;

        let changed_values = if start_version_ts <= target_version_ts {
            // Going forward
            //                  ]     relevant changes     ]
            // -----------------|--------------------------|
            //                start                     target
            // We query for changes between start and target version. Then sort
            // these by account and slot by change time in a desending matter
            // (latest change first). Next we deduplicate by account and slot.
            // Finally we select the value column to give us the latest value
            // within the version range.
            schema::contract_storage::table
                .inner_join(schema::account::table.inner_join(schema::chain::table))
                .filter(schema::chain::id.eq(chain_id))
                .filter(schema::contract_storage::valid_from.gt(start_version_ts))
                .filter(schema::contract_storage::valid_from.le(target_version_ts))
                .order_by((
                    schema::account::id,
                    schema::contract_storage::slot,
                    schema::contract_storage::valid_from.desc(),
                    schema::contract_storage::ordinal.desc(),
                ))
                .select((
                    schema::account::id,
                    schema::contract_storage::slot,
                    schema::contract_storage::value,
                ))
                .distinct_on((schema::account::id, schema::contract_storage::slot))
                .get_results::<(i64, Vec<u8>, Option<Vec<u8>>)>(conn)
                .await
                .unwrap()
        } else {
            // Going backwards
            //                  ]     relevant changes     ]
            // -----------------|--------------------------|
            //                target                     start
            // We query for changes between target and start version. Then sort
            // these for each account and slot by change time in an ascending
            // manner. Next, we deduplicate by taking the first row for each
            // account and slot. Finally we select the previous_value column to
            // give us the value before this first change within the version
            // range.
            schema::contract_storage::table
                .inner_join(schema::account::table.inner_join(schema::chain::table))
                .filter(schema::chain::id.eq(chain_id))
                .filter(schema::contract_storage::valid_from.gt(target_version_ts))
                .filter(schema::contract_storage::valid_from.le(start_version_ts))
                .order_by((
                    schema::account::id.asc(),
                    schema::contract_storage::slot.asc(),
                    schema::contract_storage::valid_from.asc(),
                    schema::contract_storage::ordinal.asc(),
                ))
                .select((
                    schema::account::id,
                    schema::contract_storage::slot,
                    schema::contract_storage::previous_value,
                ))
                .distinct_on((schema::account::id, schema::contract_storage::slot))
                .get_results::<(i64, Vec<u8>, Option<Vec<u8>>)>(conn)
                .await
                .unwrap()
        };

        // We retrieve account addresses separately because this is more
        // efficient for the most common cases. In the most common case, only a
        // handful of accounts that we are interested in will have had changes
        // that need to be reverted. The previous query only returns duplicated
        // account ids, which are lighweight (8 byte vs 20 for addresses), once
        // deduplicated we only fetch the associated addresses. These addresses
        // are considered immutable, so if necessary we could event cache these
        // locally.
        // In the worst case each changed slot is changed on a different
        // account. On mainnet that would be at max 300 contracts/slots, which
        // although not ideal is still bearable.
        let account_addresses = schema::account::table
            .filter(schema::account::id.eq_any(changed_values.iter().map(|(cid, _, _)| cid)))
            .select((schema::account::id, schema::account::address))
            .get_results::<(i64, Vec<u8>)>(conn)
            .await
            .map_err(StorageError::from)?
            .iter()
            .map(|(k, v)| {
                if v.len() != 20 {
                    return Err(StorageError::DecodeError(format!(
                        "Invalid contract address found for contract with id: {}, address: {}",
                        k,
                        hex::encode(v)
                    )));
                }
                Ok((*k, H160::from_slice(v)))
            })
            .collect::<Result<HashMap<i64, H160>, StorageError>>()?;

        let mut result: HashMap<H160, HashMap<U256, U256>> =
            HashMap::with_capacity(account_addresses.len());
        for (cid, raw_key, raw_val) in changed_values.into_iter() {
            // note this can theoretically happen (only if there is some really
            // bad database inconsistency) because the call above simply filters
            // for account ids, but won't error or give any inidication of a
            // missing contract id.
            let account_address = account_addresses.get(&cid).ok_or_else(|| {
                StorageError::DecodeError(format!("Failed to find contract address for id {}", cid))
            })?;

            if raw_key.len() != 32 {
                return Err(StorageError::DecodeError(format!(
                    "Invalid byte length for U256 in slot key! Found: 0x{}",
                    hex::encode(raw_key)
                )));
            }
            let v = if let Some(val) = raw_val {
                if val.len() != 32 {
                    return Err(StorageError::DecodeError(format!(
                        "Invalid byte length for U256 in slot value! Found: 0x{}",
                        hex::encode(val)
                    )));
                }
                U256::from_big_endian(&val)
            } else {
                U256::zero()
            };

            let k = U256::from_big_endian(&raw_key);

            match result.entry(*account_address) {
                Entry::Occupied(mut e) => {
                    e.get_mut().insert(k, v);
                }
                Entry::Vacant(e) => {
                    let mut contract_storage = HashMap::new();
                    contract_storage.insert(k, v);
                    e.insert(contract_storage);
                }
            }
        }
        Ok(result)
    }

    async fn revert_contract_state(
        &self,
        to: BlockIdentifier,
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        // To revert all changes of a chain, we need to delete & modify entries
        // from a big number of tables. Reverting state, signifies deleting
        // history. We will not keep any branches in the db only the main branch
        // will be kept.
        let block = orm::Block::by_id(to, conn).await?;

        // All entities and version updates are connected to the block via a
        // cascade delete, this ensures that the state is reverted by simply
        // deleting the correct blocks, which then triggers cascading deletes on
        // child entries.
        diesel::delete(
            schema::block::table
                .filter(schema::block::number.gt(block.number))
                .filter(schema::block::chain_id.eq(block.chain_id)),
        )
        .execute(conn)
        .await?;

        // Any versioned table's rows, which have `valid_to` set to "> block.ts"
        // need, to be updated to be valid again (thus, valid_to = NULL).
        diesel::update(
            schema::contract_storage::table.filter(schema::contract_storage::valid_to.gt(block.ts)),
        )
        .set(schema::contract_storage::valid_to.eq(Option::<NaiveDateTime>::None))
        .execute(conn)
        .await?;

        diesel::update(
            schema::account_balance::table.filter(schema::account_balance::valid_to.gt(block.ts)),
        )
        .set(schema::account_balance::valid_to.eq(Option::<NaiveDateTime>::None))
        .execute(conn)
        .await?;

        diesel::update(
            schema::contract_code::table.filter(schema::contract_code::valid_to.gt(block.ts)),
        )
        .set(schema::contract_code::valid_to.eq(Option::<NaiveDateTime>::None))
        .execute(conn)
        .await?;

        diesel::update(
            schema::protocol_state::table.filter(schema::protocol_state::valid_to.gt(block.ts)),
        )
        .set(schema::protocol_state::valid_to.eq(Option::<NaiveDateTime>::None))
        .execute(conn)
        .await?;

        diesel::update(
            schema::protocol_calls_contract::table
                .filter(schema::protocol_calls_contract::valid_to.gt(block.ts)),
        )
        .set(schema::protocol_calls_contract::valid_to.eq(Option::<NaiveDateTime>::None))
        .execute(conn)
        .await?;

        Ok(())
    }
}

/// Given a version find the corresponding timestamp.
///
/// If the version is a block, it will query the database for that block and
/// return its timestamp.
///
/// ## Note:
/// This can fail if there is no block present in the db. With the current table
/// schema this means, that there were no changes detected at that block, but
/// there might have been on previous or in later blocks.
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
    use std::str::FromStr;

    use diesel_async::{AsyncConnection, RunQueryDsl};
    use ethers::types::H256;

    use super::*;
    use crate::extractor::evm;
    use crate::storage::postgres::fixtures;

    async fn setup_db() -> AsyncPgConnection {
        let db_url = std::env::var("DATABASE_URL").unwrap();
        let mut conn = AsyncPgConnection::establish(&db_url).await.unwrap();
        conn.begin_test_transaction().await.unwrap();
        conn
    }

    #[tokio::test]
    async fn test_get_contract() {
        let expected = AccountUpdate::new(
            "setup_extractor".to_owned(),
            Chain::Ethereum,
            H160::zero(),
            HashMap::new(),
            Some(U256::zero()),
            None,
            None,
        );

        let mut conn = setup_db().await;
        let mut gateway =
            PostgresGateway::<evm::Block, evm::Transaction>::from_connection(&mut conn).await;
        let id = ContractId(Chain::Ethereum, vec![]);
        let actual = gateway.get_contract(id, None).await.unwrap();

        assert_eq!(expected, actual);
    }

    #[tokio::test]
    async fn test_add_contract() {
        let mut conn = setup_db().await;
        let mut gateway =
            PostgresGateway::<evm::Block, evm::Transaction>::from_connection(&mut conn).await;
        let new = AccountUpdate::new(
            "setup_extractor".to_owned(),
            Chain::Ethereum,
            H160::random(),
            HashMap::new(),
            Some(U256::zero()),
            None,
            None,
        );

        let res = gateway
            .add_contract(new)
            .await
            .expect("Succesful insertion");
    }

    #[tokio::test]
    async fn test_delete_contract() {}

    #[tokio::test]
    async fn test_upsert_contract() {}

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
        let c0 = fixtures::insert_account(
            conn,
            "6B175474E89094C44Da98b954EedeAC495271d0F",
            "c0",
            chain_id,
            Some(txn[0]),
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

    #[tokio::test]
    async fn get_slots_delta_forward() {
        let mut conn = setup_db().await;
        setup_slots_delta(&mut conn).await;
        let gw = PostgresGateway::<evm::Block, evm::Transaction>::from_connection(&mut conn).await;
        let storage: HashMap<U256, U256> = vec![(0, 2), (1, 3), (5, 25), (6, 30)]
            .iter()
            .map(|(k, v)| (U256::from(*k), U256::from(*v)))
            .collect();
        let mut exp = HashMap::new();
        let addr = H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap();
        exp.insert(addr, storage);

        let res = gw
            .get_slots_delta(
                Chain::Ethereum,
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
        let storage: HashMap<U256, U256> = vec![(0, 1), (1, 5), (5, 0), (6, 0)]
            .iter()
            .map(|(k, v)| (U256::from(*k), U256::from(*v)))
            .collect();
        let mut exp = HashMap::new();
        let addr = H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap();
        exp.insert(addr, storage);

        let res = gw
            .get_slots_delta(
                Chain::Ethereum,
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

    async fn setup_revert(conn: &mut AsyncPgConnection) {
        let chain_id = fixtures::insert_chain(conn, "ethereum").await;
        let blk = fixtures::insert_blocks(conn, chain_id).await;
        let txn = fixtures::insert_txns(
            conn,
            &[
                (
                    // deploy c0
                    blk[0],
                    1i64,
                    "0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945",
                ),
                (
                    // change c0 state
                    blk[0],
                    2i64,
                    "0x794f7df7a3fe973f1583fbb92536f9a8def3a89902439289315326c04068de54",
                ),
                (
                    // deploy c1
                    blk[1],
                    1i64,
                    "0x3108322284d0a89a7accb288d1a94384d499504fe7e04441b0706c7628dee7b7",
                ),
                (
                    // change c0 and c1 state
                    blk[1],
                    2i64,
                    "0x50449de1973d86f21bfafa7c72011854a7e33a226709dc3e2e4edcca34188388",
                ),
            ],
        )
        .await;
        let c0 = fixtures::insert_account(
            conn,
            "6B175474E89094C44Da98b954EedeAC495271d0F",
            "c0",
            chain_id,
            Some(txn[0]),
        )
        .await;
        let c1 = fixtures::insert_account(
            conn,
            "73BcE791c239c8010Cd3C857d96580037CCdd0EE",
            "c1",
            chain_id,
            Some(txn[2]),
        )
        .await;
        fixtures::insert_slots(
            conn,
            c0,
            txn[1],
            "2020-01-01T00:00:00",
            &[(0, 1), (1, 5), (2, 1)],
        )
        .await;
        fixtures::insert_slots(
            conn,
            c0,
            txn[3],
            "2020-01-01T01:00:00",
            &[(0, 2), (1, 3), (5, 25), (6, 30)],
        )
        .await;
        fixtures::insert_slots(
            conn,
            c1,
            txn[3],
            "2020-01-01T01:00:00",
            &[(0, 128), (1, 256)],
        )
        .await;
    }

    #[tokio::test]
    async fn test_revert() {
        let mut conn = setup_db().await;
        setup_revert(&mut conn).await;
        let block1_hash =
            H256::from_str("0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6")
                .unwrap()
                .as_bytes()
                .into();
        let exp_slots: HashMap<U256, U256> = vec![
            (U256::from(0), U256::from(1)),
            (U256::from(1), U256::from(5)),
            (U256::from(2), U256::from(1)),
        ]
        .into_iter()
        .collect();
        let gw = PostgresGateway::<evm::Block, evm::Transaction>::from_connection(&mut conn).await;

        gw.revert_contract_state(BlockIdentifier::Hash(block1_hash), &mut conn)
            .await
            .unwrap();

        let slots: HashMap<U256, U256> = schema::contract_storage::table
            .select((
                schema::contract_storage::slot,
                schema::contract_storage::value,
            ))
            .get_results::<(Vec<u8>, Option<Vec<u8>>)>(&mut conn)
            .await
            .unwrap()
            .iter()
            .map(|(k, v)| {
                (
                    U256::from_big_endian(k),
                    v.as_ref()
                        .map(|rv| U256::from_big_endian(rv))
                        .unwrap_or_else(U256::zero),
                )
            })
            .collect();
        assert_eq!(slots, exp_slots);

        let c1 = schema::account::table
            .filter(schema::account::title.eq("c1"))
            .select(schema::account::id)
            .get_results::<i64>(&mut conn)
            .await
            .unwrap();
        assert_eq!(c1.len(), 0);
    }
}

#![allow(unused_variables)]

use async_trait::async_trait;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::{
    extractor::evm::ProtocolState,
    models::{Chain, ProtocolSystem},
    storage::{
        postgres::{
            orm,
            orm::{NewProtocolType, ProtocolType},
            PostgresGateway,
        },
        Address, BlockIdentifier, BlockOrTimestamp, ContractDelta, ProtocolGateway, StorableBlock,
        StorableContract, StorableToken, StorableTransaction, StorageError, TxHash, Version,
    },
};

#[async_trait]
impl<B, TX, A, D, T> ProtocolGateway for PostgresGateway<B, TX, A, D, T>
where
    B: StorableBlock<orm::Block, orm::NewBlock, i64>,
    TX: StorableTransaction<orm::Transaction, orm::NewTransaction, i64>,
    D: ContractDelta + From<A>,
    A: StorableContract<orm::Contract, orm::NewContract, i64>,
    T: StorableToken<orm::Token, orm::NewToken, i64>,
{
    type DB = AsyncPgConnection;
    type Token = T;
    type ProtocolState = ProtocolState;

    // TODO: uncomment to implement in ENG 2049
    // async fn get_components(
    //     &self,
    //     chain: &Chain,
    //     system: Option<ProtocolSystem>,
    //     ids: Option<&[&str]>,
    // ) -> Result<Vec<ProtocolComponent>, StorageError> {
    //     todo!()
    // }

    // TODO: uncomment to implement in ENG 2049
    // async fn upsert_components(&self, new: &[&ProtocolComponent]) -> Result<(), StorageError> {
    //     todo!()
    // }

    async fn upsert_protocol_types(
        &self,
        new: &[&ProtocolType],
        conn: &mut Self::DB,
    ) -> Result<(), StorageError> {
        use super::schema::protocol_type::dsl::*;

        for new_protocol_type in new {
            let values = NewProtocolType {
                name: new_protocol_type.name.to_string(),
                financial_type: new_protocol_type.financial_type.clone(),
                attribute_schema: new_protocol_type
                    .attribute_schema
                    .clone(),
                implementation: new_protocol_type.implementation.clone(),
            };

            diesel::insert_into(protocol_type)
                .values(&values)
                .on_conflict(id)
                .do_update()
                .set(&values)
                .execute(conn)
                .await
                .map_err(|err| {
                    StorageError::from_diesel(err, "ProtocolType", &new_protocol_type.name, None)
                })?;
        }

        Ok(())
    }

    async fn get_states(
        &self,
        chain: &Chain,
        at: Option<Version>,
        system: Option<ProtocolSystem>,
        id: Option<&[&str]>,
    ) -> Result<Vec<ProtocolState>, StorageError> {
        let block_chain_id = self.get_chain_id(chain);
        todo!()
    }

    async fn update_state(&self, chain: Chain, new: &[(TxHash, ProtocolState)], db: &mut Self::DB) {
        todo!()
    }

    async fn get_tokens(
        &self,
        chain: Chain,
        address: Option<&[&Address]>,
    ) -> Result<Vec<Self::Token>, StorageError> {
        todo!()
    }

    async fn add_tokens(&self, chain: Chain, token: &[&Self::Token]) -> Result<(), StorageError> {
        todo!()
    }

    async fn get_state_delta(
        &self,
        chain: &Chain,
        system: Option<ProtocolSystem>,
        id: Option<&[&str]>,
        start_version: Option<&BlockOrTimestamp>,
        end_version: &BlockOrTimestamp,
        conn: &mut Self::DB,
    ) -> Result<ProtocolState, StorageError> {
        todo!()
    }

    async fn revert_protocol_state(
        &self,
        to: &BlockIdentifier,
        conn: &mut Self::DB,
    ) -> Result<(), StorageError> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime};

    use diesel_async::AsyncConnection;

    use crate::{
        extractor::evm,
        storage::{
            postgres::{
                orm::{FinancialProtocolType, ProtocolImplementationType, ProtocolType},
                schema, PostgresGateway,
            },
            BlockHash,
        },
    };

    use super::*;

    type EVMGateway = PostgresGateway<
        evm::Block,
        evm::Transaction,
        evm::Account,
        evm::AccountUpdate,
        evm::ERC20Token,
    >;

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

    #[tokio::test]
    async fn test_add_protocol_type() {
        let mut conn = setup_db().await;
        let gw = EVMGateway::from_connection(&mut conn).await;

        let d = NaiveDate::from_ymd_opt(2015, 6, 3).unwrap();
        let t = NaiveTime::from_hms_milli_opt(12, 34, 56, 789).unwrap();
        let dt = NaiveDateTime::new(d, t);

        let protocol_types: Vec<ProtocolType> = vec![ProtocolType {
            id: 1,
            name: "Protocol".to_string(),
            financial_type: FinancialProtocolType::Debt,
            attribute_schema: None,
            implementation: ProtocolImplementationType::Custom,
            inserted_ts: dt,
            modified_ts: dt,
        }];

        let protocol_types_slice: Vec<&ProtocolType> = protocol_types.iter().collect();
        gw.upsert_protocol_types(protocol_types_slice.as_slice(), &mut conn)
            .await
            .unwrap();
    }
}

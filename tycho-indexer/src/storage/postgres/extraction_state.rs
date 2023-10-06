use crate::storage::{
    ContractDelta, ExtractionState, ExtractionStateGateway, StorableBlock, StorableContract,
    StorableTransaction,
};

use super::{orm, schema, Chain, PostgresGateway, StorageError};
use async_trait::async_trait;
use diesel::ExpressionMethods;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

#[async_trait]
impl<B, TX, A, D> ExtractionStateGateway for PostgresGateway<B, TX, A, D>
where
    B: StorableBlock<orm::Block, orm::NewBlock, i64>,
    TX: StorableTransaction<orm::Transaction, orm::NewTransaction, i64>,
    D: ContractDelta,
    A: StorableContract<orm::Contract, orm::NewContract, i64>,
{
    type DB = AsyncPgConnection;

    async fn get_state(
        &self,
        name: &str,
        chain: &Chain,
        conn: &mut Self::DB,
    ) -> Result<ExtractionState, StorageError> {
        let block_chain_id = self.get_chain_id(chain);

        match orm::ExtractionState::by_name(name, block_chain_id, conn).await {
            Ok(Some(orm_state)) => {
                let state = ExtractionState::new(
                    orm_state.name,
                    *chain,
                    orm_state.attributes,
                    &orm_state.cursor.unwrap_or_default(),
                );
                Ok(state)
            }
            Ok(None) => Err(StorageError::NotFound("ExtractionState".to_owned(), name.to_owned())),
            Err(err) => Err(StorageError::from_diesel(err, "ExtractionState", name, None)),
        }
    }

    async fn save_state(
        &self,
        state: &ExtractionState,
        conn: &mut Self::DB,
    ) -> Result<(), StorageError> {
        let block_chain_id = self.get_chain_id(&state.chain);
        match orm::ExtractionState::by_name(&state.name, block_chain_id, conn).await {
            Ok(Some(_)) => {
                let update_form = orm::ExtractionStateForm {
                    attributes: Some(&state.attributes),
                    cursor: Some(&state.cursor),
                    modified_ts: Some(chrono::Utc::now().naive_utc()),
                };
                let update_query = diesel::update(schema::extraction_state::dsl::extraction_state)
                    .filter(schema::extraction_state::name.eq(&state.name))
                    .filter(schema::extraction_state::chain_id.eq(block_chain_id))
                    .set(&update_form);
                update_query
                    .execute(conn)
                    .await
                    .map_err(|err| {
                        StorageError::from_diesel(err, "ExtractionState", &state.name, None)
                    })?;
            }
            Ok(None) => {
                // No matching entry in the DB
                let orm_state = orm::NewExtractionState {
                    name: &state.name,
                    version: "0.1.0",
                    chain_id: block_chain_id,
                    attributes: Some(&state.attributes),
                    cursor: Some(&state.cursor),
                    modified_ts: chrono::Utc::now().naive_utc(),
                };
                let query = diesel::insert_into(schema::extraction_state::dsl::extraction_state)
                    .values(&orm_state);
                query
                    .execute(conn)
                    .await
                    .map_err(|err| {
                        StorageError::from_diesel(err, "ExtractionState", &state.name, None)
                    })?;
            }
            Err(err) => {
                return Err(StorageError::from_diesel(err, "ExtractionState", &state.name, None))
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use diesel::prelude::*;
    use diesel_async::{AsyncConnection, RunQueryDsl};

    use super::*;
    use crate::extractor::evm;

    async fn setup_db() -> AsyncPgConnection {
        // Creates a DB connecton
        // Creates a chain entry in the DB
        // Creates a ExtractionState entry in the DB named "setup_extractor"
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let mut conn = AsyncPgConnection::establish(&db_url)
            .await
            .unwrap();
        conn.begin_test_transaction()
            .await
            .unwrap();
        let chain_id: i64 = diesel::insert_into(schema::chain::table)
            .values(schema::chain::name.eq("ethereum"))
            .returning(schema::chain::id)
            .get_result(&mut conn)
            .await
            .unwrap();
        let extractor_name = "setup_extractor";

        let cursor = Some("10".as_bytes());
        let attributes = serde_json::json!({"test": "test"});
        let orm_state = orm::NewExtractionState {
            name: extractor_name,
            chain_id,
            attributes: Some(&attributes),
            cursor,
            version: "0.1.0",
            modified_ts: chrono::Utc::now().naive_utc(),
        };

        diesel::insert_into(schema::extraction_state::table)
            .values(&orm_state)
            .execute(&mut conn)
            .await
            .unwrap();

        conn
    }

    async fn get_dgw(
        conn: &mut AsyncPgConnection,
    ) -> PostgresGateway<evm::Block, evm::Transaction, evm::Account, evm::AccountUpdate> {
        PostgresGateway::<evm::Block, evm::Transaction, evm::Account, evm::AccountUpdate>::from_connection(conn).await
    }

    #[tokio::test]
    async fn test_save_new_state() {
        // Adds a ExtractionState to the DB named "test_extractor" and asserts for it
        let mut conn = setup_db().await;
        let extractor_name = "test_extractor".to_string();

        let gateway = get_dgw(&mut conn).await;
        let state = ExtractionState::new(
            extractor_name.clone(),
            Chain::Ethereum,
            Some(serde_json::json!({"test": "test"})),
            "10".to_owned().as_bytes(),
        );

        // Save the state using the gateway
        gateway
            .save_state(&state, &mut conn)
            .await
            .unwrap();

        let query_res: orm::ExtractionState = schema::extraction_state::table
            .filter(schema::extraction_state::name.eq(extractor_name.clone()))
            .select(orm::ExtractionState::as_select())
            .first(&mut conn)
            .await
            .unwrap();

        assert_eq!(query_res.name, extractor_name);
        assert_eq!(query_res.version, "0.1.0".to_string());
        assert_eq!(&query_res.cursor.unwrap(), "10".as_bytes());
    }

    #[tokio::test]
    async fn test_get_state() {
        // Tests the get_state method of the gateway by loading the state named "setup_extractor"
        let mut conn = setup_db().await;
        let gateway = get_dgw(&mut conn).await;
        let extractor_name = "setup_extractor";

        let state = gateway
            .get_state(extractor_name, &Chain::Ethereum, &mut conn)
            .await
            .unwrap();

        assert_eq!(state.name, extractor_name);
        assert_eq!(state.chain, Chain::Ethereum);
    }

    #[tokio::test]
    async fn test_get_non_existing_state() {
        // Tests the get_state method of the gateway by loading a state that does not exist
        let mut conn = setup_db().await;
        let gateway = get_dgw(&mut conn).await;
        let extractor_name = "missing_extractor";

        let _ = gateway
            .get_state(extractor_name, &Chain::Ethereum, &mut conn)
            .await
            .expect_err("Expected an error when loading a non-existing state");
    }

    #[tokio::test]
    async fn test_update_state() {
        let mut conn = setup_db().await;
        let gateway = get_dgw(&mut conn).await;
        let extractor_name = "setup_extractor".to_string();

        let state = ExtractionState::new(
            extractor_name.clone(),
            Chain::Ethereum,
            Some(serde_json::json!({"test": "test"})),
            "20".as_bytes(),
        );

        gateway
            .save_state(&state, &mut conn)
            .await
            .expect("Failed to save state!");
        assert_eq!(
            gateway
                .get_state(&extractor_name, &Chain::Ethereum, &mut conn)
                .await
                .unwrap()
                .cursor,
            "20".to_owned().into_bytes()
        );
    }
}

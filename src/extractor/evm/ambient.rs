use diesel_async::{
    pooled_connection::bb8::Pool, scoped_futures::ScopedFutureExt, AsyncConnection,
    AsyncPgConnection,
};
use ethers::types::{H160, H256};
use mockall::automock;
use prost::Message;
use serde_json::json;
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tracing::{debug, info};

use async_trait::async_trait;
use tokio::sync::Mutex;

use super::EVMStateGateway;
use crate::{
    extractor::{evm, ExtractionError, Extractor},
    models::{Chain, ExtractionState, ExtractorIdentity},
    pb::{
        sf::substreams::rpc::v2::{BlockScopedData, BlockUndoSignal, ModulesProgress},
        tycho::evm::v1::BlockContractChanges,
    },
    storage::{BlockIdentifier, BlockOrTimestamp, StorageError},
};

const AMBIENT_CONTRACT: [u8; 20] = hex_literal::hex!("aaaaaaaaa24eeeb8d57d431224f73832bc34f688");
const DEPLOY_TX: [u8; 32] =
    hex_literal::hex!("11f2acc5882e7a6903bcbb39d1af7cd6cad99afd7e421197f48a537ae73a7f3a");

struct Inner {
    cursor: Vec<u8>,
}

pub struct AmbientContractExtractor<G> {
    gateway: G,
    name: String,
    chain: Chain,
    // TODO: There is not reason this needs to be shared
    // try removing the Mutex
    inner: Arc<Mutex<Inner>>,
}

impl<DB> AmbientContractExtractor<DB> {
    async fn update_cursor(&self, cursor: String) {
        let cursor_bytes: Vec<u8> = cursor.into();
        let mut state = self.inner.lock().await;
        state.cursor = cursor_bytes;
    }
}

pub struct AmbientPgGateway {
    name: String,
    chain: Chain,
    pool: Pool<AsyncPgConnection>,
    state_gateway: EVMStateGateway<AsyncPgConnection>,
}

#[automock]
#[async_trait]
pub trait AmbientGateway: Send + Sync {
    async fn get_cursor(&self, name: &str, chain: Chain) -> Result<Vec<u8>, StorageError>;
    async fn upsert_contract(
        &self,
        changes: &evm::BlockStateChanges,
        new_cursor: &str,
    ) -> Result<(), StorageError>;

    async fn revert(
        &self,
        to: BlockIdentifier,
        new_cursor: &str,
    ) -> Result<evm::BlockAccountChanges, StorageError>;
}

impl AmbientPgGateway {
    pub fn new(
        name: &str,
        chain: Chain,
        pool: Pool<AsyncPgConnection>,
        gw: EVMStateGateway<AsyncPgConnection>,
    ) -> Self {
        AmbientPgGateway { name: name.to_owned(), chain, pool, state_gateway: gw }
    }

    async fn save_cursor(
        &self,
        new_cursor: &str,
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        let state = ExtractionState {
            name: self.name.clone(),
            chain: self.chain,
            attributes: json!(null),
            cursor: new_cursor.as_bytes().to_vec(),
        };
        self.state_gateway
            .save_state(&state, conn)
            .await?;
        Ok(())
    }

    async fn forward(
        &self,
        changes: &evm::BlockStateChanges,
        new_cursor: &str,
        conn: &mut AsyncPgConnection,
    ) -> Result<(), StorageError> {
        debug!("Upserting block: {:?}", &changes.block);
        self.state_gateway
            .upsert_block(&changes.block, conn)
            .await?;
        for update in changes.tx_updates.iter() {
            debug!("Processing tx: 0x{:x}", &update.tx.hash);
            self.state_gateway
                .upsert_tx(&update.tx, conn)
                .await?;
            if update.tx.hash == H256(DEPLOY_TX) {
                let new: evm::Account = update.into();
                info!("New contract found at {}: 0x{:x}", &changes.block.number, &new.address);
                self.state_gateway
                    .insert_contract(&new, conn)
                    .await?;
            }
        }
        debug!("Applying contract state changes");
        self.state_gateway
            .update_contracts(
                self.chain,
                changes
                    .tx_updates
                    .iter()
                    .filter(|&u| (u.tx.hash != H256(DEPLOY_TX)))
                    .map(|u| (u.tx.hash.as_bytes(), &u.update))
                    .collect::<Vec<_>>()
                    .as_slice(),
                conn,
            )
            .await?;
        self.save_cursor(new_cursor, conn)
            .await?;
        Result::<(), StorageError>::Ok(())
    }
}

#[async_trait]
impl AmbientGateway for AmbientPgGateway {
    async fn get_cursor(&self, name: &str, chain: Chain) -> Result<Vec<u8>, StorageError> {
        let mut conn = self.pool.get().await.unwrap();
        let state = self
            .state_gateway
            .get_state(name, chain, &mut conn)
            .await?;
        Ok(state.cursor)
    }
    async fn upsert_contract(
        &self,
        changes: &evm::BlockStateChanges,
        new_cursor: &str,
    ) -> Result<(), StorageError> {
        let mut conn = self.pool.get().await.unwrap();
        conn.transaction(|conn| {
            async move {
                self.forward(changes, new_cursor, conn)
                    .await
            }
            .scope_boxed()
        })
        .await?;
        Ok(())
    }

    async fn revert(
        &self,
        to: BlockIdentifier,
        new_cursor: &str,
    ) -> Result<evm::BlockAccountChanges, StorageError> {
        let mut conn = self.pool.get().await.unwrap();
        let res = conn
            .transaction(|conn| {
                async move {
                    let block = self
                        .state_gateway
                        .get_block(&to, conn)
                        .await?;
                    let target = BlockOrTimestamp::Block(to);
                    let address = H160::from(AMBIENT_CONTRACT);
                    let account_updates =
                        self.state_gateway
                            .get_account_delta(self.chain, None, &target, conn)
                            .await?
                            .into_iter()
                            .filter_map(|u| {
                                if u.address == address {
                                    Some((u.address, u))
                                } else {
                                    None
                                }
                            })
                            .collect();

                    self.save_cursor(new_cursor, conn)
                        .await?;

                    let changes = evm::BlockAccountChanges {
                        chain: self.chain,
                        extractor: self.name.clone(),
                        block,
                        account_updates,
                        new_pools: HashMap::new(),
                    };
                    Result::<evm::BlockAccountChanges, StorageError>::Ok(changes)
                }
                .scope_boxed()
            })
            .await?;
        Ok(res)
    }
}

impl<G> AmbientContractExtractor<G>
where
    G: AmbientGateway,
{
    pub async fn new(name: &str, chain: Chain, gateway: G) -> Result<Self, ExtractionError> {
        // check if this extractor has state
        let res = match gateway.get_cursor(name, chain).await {
            Err(StorageError::NotFound(_, _)) => AmbientContractExtractor {
                gateway,
                name: name.to_owned(),
                chain,
                inner: Arc::new(Mutex::new(Inner { cursor: Vec::new() })),
            },
            Ok(cursor) => AmbientContractExtractor {
                gateway,
                name: name.to_owned(),
                chain,
                inner: Arc::new(Mutex::new(Inner { cursor })),
            },
            Err(err) => return Err(ExtractionError::Setup(err.to_string())),
        };
        Ok(res)
    }
}

#[async_trait]
impl<G> Extractor<G, evm::BlockAccountChanges> for AmbientContractExtractor<G>
where
    G: AmbientGateway,
{
    fn get_id(&self) -> ExtractorIdentity {
        ExtractorIdentity { chain: self.chain, name: self.name.to_owned() }
    }

    async fn get_cursor(&self) -> String {
        String::from_utf8(self.inner.lock().await.cursor.clone()).expect("Cursor is utf8")
    }

    async fn handle_tick_scoped_data(
        &self,
        inp: BlockScopedData,
    ) -> Result<Option<evm::BlockAccountChanges>, ExtractionError> {
        let _data = inp
            .output
            .as_ref()
            .unwrap()
            .map_output
            .as_ref()
            .unwrap();

        let raw_msg = BlockContractChanges::decode(_data.value.as_slice())?;
        debug!("Received message: {raw_msg:?}");

        let msg = match evm::BlockStateChanges::try_from_message(raw_msg, &self.name, self.chain) {
            Ok(changes) => changes,
            Err(ExtractionError::Empty) => {
                self.update_cursor(inp.cursor).await;
                return Ok(None)
            }
            Err(e) => return Err(e),
        };
        self.gateway
            .upsert_contract(&msg, inp.cursor.as_ref())
            .await?;

        self.update_cursor(inp.cursor).await;
        Ok(Some(msg.aggregate_updates()?))
    }

    async fn handle_revert(
        &self,
        inp: BlockUndoSignal,
    ) -> Result<Option<evm::BlockAccountChanges>, ExtractionError> {
        let block_ref = inp
            .last_valid_block
            .ok_or_else(|| ExtractionError::DecodeError("Revert without block ref".into()))?;
        let block_hash = H256::from_str(&block_ref.id).map_err(|err| {
            ExtractionError::DecodeError(format!(
                "Failed to parse {} as block hash: {}",
                block_ref.id, err
            ))
        })?;
        let changes = self
            .gateway
            .revert(
                BlockIdentifier::Hash(block_hash.as_bytes().to_vec()),
                inp.last_valid_cursor.as_ref(),
            )
            .await?;
        self.update_cursor(inp.last_valid_cursor)
            .await;

        Ok((!changes.account_updates.is_empty()).then_some(changes))
    }

    async fn handle_progress(&self, _inp: ModulesProgress) -> Result<(), ExtractionError> {
        todo!()
    }
}

#[cfg(test)]
mod test {

    use crate::{
        extractor::evm::{fixtures, BlockAccountChanges},
        pb::sf::substreams::v1::BlockRef,
    };

    use super::*;

    #[tokio::test]
    async fn test_get_cursor() {
        let mut gw = MockAmbientGateway::new();
        gw.expect_get_cursor()
            .withf(|name, chain| name == "vm:ambient" && chain == &Chain::Ethereum)
            .times(1)
            .returning(|_, _| Ok("cursor".into()));
        let extractor = AmbientContractExtractor::new("vm:ambient", Chain::Ethereum, gw)
            .await
            .expect("extractor init ok");

        let res = extractor.get_cursor().await;

        assert_eq!(res, "cursor");
    }

    fn block_contract_changes_ok() -> BlockContractChanges {
        let mut data = fixtures::pb_block_contract_changes();
        // TODO: make fixtures configurable through parameters so they can be
        // properly reused. Will need fixture to easily assemble contract
        // change objects.
        data.changes[0]
            .contract_changes
            .remove(1);
        data
    }

    #[tokio::test]
    async fn test_handle_tick_scoped_data() {
        let mut gw = MockAmbientGateway::new();
        gw.expect_get_cursor()
            .withf(|name, chain| name == "vm:ambient" && chain == &Chain::Ethereum)
            .times(1)
            .returning(|_, _| Ok("cursor".into()));
        gw.expect_upsert_contract()
            .times(1)
            .returning(|_, _| Ok(()));
        let extractor = AmbientContractExtractor::new("vm:ambient", Chain::Ethereum, gw)
            .await
            .expect("extractor init ok");
        let inp = fixtures::pb_block_scoped_data(block_contract_changes_ok());
        let exp = Ok(Some(()));

        let res = extractor
            .handle_tick_scoped_data(inp)
            .await
            .map(|o| o.map(|_| ()));

        assert_eq!(res, exp);
        assert_eq!(extractor.get_cursor().await, "cursor@420");
    }

    #[tokio::test]
    async fn test_handle_tick_scoped_data_skip() {
        let mut gw = MockAmbientGateway::new();
        gw.expect_get_cursor()
            .withf(|name, chain| name == "vm:ambient" && chain == &Chain::Ethereum)
            .times(1)
            .returning(|_, _| Ok("cursor".into()));
        gw.expect_upsert_contract()
            .times(0)
            .returning(|_, _| Ok(()));
        let extractor = AmbientContractExtractor::new("vm:ambient", Chain::Ethereum, gw)
            .await
            .expect("extractor init ok");
        let inp = fixtures::pb_block_scoped_data(());

        let res = extractor
            .handle_tick_scoped_data(inp)
            .await;

        assert_eq!(res, Ok(None));
        assert_eq!(extractor.get_cursor().await, "cursor@420");
    }

    fn undo_signal() -> BlockUndoSignal {
        BlockUndoSignal {
            last_valid_block: Some(BlockRef { id: fixtures::HASH_256_0.into(), number: 400 }),
            last_valid_cursor: "cursor@400".into(),
        }
    }

    #[tokio::test]
    async fn test_handle_revert() {
        let mut gw = MockAmbientGateway::new();
        gw.expect_get_cursor()
            .withf(|name, chain| name == "vm:ambient" && chain == &Chain::Ethereum)
            .times(1)
            .returning(|_, _| Ok("cursor".into()));
        gw.expect_revert()
            .withf(|v, cursor| {
                v == &BlockIdentifier::Hash(hex::decode(&fixtures::HASH_256_0[2..]).unwrap()) &&
                    cursor == "cursor@400"
            })
            .times(1)
            .returning(|_, _| Ok(BlockAccountChanges::default()));
        let extractor = AmbientContractExtractor::new("vm:ambient", Chain::Ethereum, gw)
            .await
            .expect("extractor init ok");
        let inp = undo_signal();

        let res = extractor.handle_revert(inp).await;

        assert!(matches!(res, Ok(None)));
        assert_eq!(extractor.get_cursor().await, "cursor@400");
    }
}

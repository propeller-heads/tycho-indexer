use crate::{
    postgres,
    postgres::{cache::CachedGateway, PostgresGateway},
};
use chrono::NaiveDateTime;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::debug;
use tycho_core::{models::Chain, storage::StorageError};

/// Different mode this gateway can be use with. Depending on the mode it will have different
/// behaviour.
#[derive(Clone, Default, PartialEq)]
pub enum GatewayMode {
    /// Gateway read-only mode. If set to this mode the gateway will never commit to the db.
    ReadOnly,
    #[default]
    ReadWrite,
}

#[derive(Default)]
pub struct GatewayBuilder {
    database_url: String,
    protocol_systems: Vec<String>,
    retention_horizon: NaiveDateTime,
    chains: Vec<Chain>,
    mode: GatewayMode,
}

impl GatewayBuilder {
    pub fn new(database_url: &str) -> Self {
        Self { database_url: database_url.to_string(), ..Default::default() }
    }

    pub fn set_chains(mut self, chains: &[Chain]) -> Self {
        self.chains = chains.to_vec();
        self
    }

    pub fn set_protocol_systems(mut self, protocol_systems: &[String]) -> Self {
        self.protocol_systems = protocol_systems.to_vec();
        self
    }

    pub fn set_retention_horizon(mut self, horizon: NaiveDateTime) -> Self {
        self.retention_horizon = horizon;
        self
    }

    pub fn set_mode(mut self, mode: GatewayMode) -> Self {
        self.mode = mode;
        self
    }

    pub async fn build(self) -> Result<(CachedGateway, JoinHandle<()>), StorageError> {
        let pool = postgres::connect(&self.database_url).await?;
        // postgres::ensure_chains(&self.chains, pool.clone()).await;
        // postgres::ensure_protocol_systems(&self.protocol_systems, pool.clone()).await;

        debug!("here");
        let inner_gw = PostgresGateway::new(pool.clone(), self.retention_horizon).await?;
        debug!("here");
        let (tx, rx) = mpsc::channel(10);
        let chain = self
            .chains
            .first()
            .expect("No chains provided"); //TODO: handle multichain?
        debug!("here");
        let write_executor = postgres::cache::DBCacheWriteExecutor::new(
            chain.to_string(),
            *chain,
            pool.clone(),
            inner_gw.clone(),
            rx,
        )
        .await;
        debug!("here");
        let handle = write_executor.run();
        debug!("here");

        let cached_gw = CachedGateway::new(tx, pool.clone(), inner_gw.clone(), self.mode);
        Ok((cached_gw, handle))
    }

    pub async fn build_gw(self) -> Result<CachedGateway, StorageError> {
        let pool = postgres::connect(&self.database_url).await?;

        let inner_gw = PostgresGateway::new(pool.clone(), self.retention_horizon).await?;
        let (tx, _) = mpsc::channel(10);

        let cached_gw =
            CachedGateway::new(tx, pool.clone(), inner_gw.clone(), GatewayMode::ReadWrite);
        Ok(cached_gw)
    }
}

use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use diesel::{sql_query, sql_types::{Text, Timestamptz}};
use diesel_async::{pooled_connection::deadpool::Pool, AsyncPgConnection, RunQueryDsl};
use tracing::info;
use tokio::{sync::mpsc, task::JoinHandle};
use tycho_common::{models::Chain, storage::StorageError};

use crate::{
    postgres,
    postgres::{cache::CachedGateway, direct::DirectGateway, PostgresGateway},
};

#[derive(Default)]
pub struct GatewayBuilder {
    database_url: String,
    protocol_systems: Vec<String>,
    retention_horizon: NaiveDateTime,
    chains: Vec<Chain>,
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

    pub async fn build(self) -> Result<(CachedGateway, JoinHandle<()>), StorageError> {
        let pool = postgres::connect(&self.database_url).await?;
        postgres::ensure_chains(&self.chains, pool.clone()).await;
        postgres::ensure_protocol_systems(&self.protocol_systems, pool.clone()).await;
        ensure_partitions_exist(pool.clone(), self.retention_horizon).await;
        let inner_gw = PostgresGateway::new(pool.clone(), self.retention_horizon).await?;
        let (tx, rx) = mpsc::channel(10);
        let chain = self
            .chains
            .get(0)
            .expect("No chains provided"); //TODO: handle multichain?
        let write_executor = postgres::cache::DBCacheWriteExecutor::new(
            chain.to_string(),
            *chain,
            pool.clone(),
            inner_gw.clone(),
            rx,
        )
        .await;
        let handle = write_executor.run();

        let cached_gw = CachedGateway::new(tx, pool.clone(), inner_gw.clone());
        Ok((cached_gw, handle))
    }

    pub async fn build_gw(self) -> Result<CachedGateway, StorageError> {
        let pool = postgres::connect(&self.database_url).await?;
        ensure_partitions_exist(pool.clone(), self.retention_horizon).await;
        let inner_gw = PostgresGateway::new(pool.clone(), self.retention_horizon).await?;
        let (tx, _) = mpsc::channel(10);

        let cached_gw = CachedGateway::new(tx, pool.clone(), inner_gw.clone());
        Ok(cached_gw)
    }

    pub async fn build_direct_gw(self) -> Result<DirectGateway, StorageError> {
        let pool = postgres::connect(&self.database_url).await?;
        postgres::ensure_chains(&self.chains, pool.clone()).await;
        postgres::ensure_protocol_systems(&self.protocol_systems, pool.clone()).await;
        ensure_partitions_exist(pool.clone(), self.retention_horizon).await;
        let inner_gw = PostgresGateway::new(pool.clone(), self.retention_horizon).await?;

        let chain = self
            .chains
            .get(0)
            .expect("No chains provided"); //TODO: handle multichain?

        let direct_gw = DirectGateway::new(pool.clone(), inner_gw.clone(), *chain);
        Ok(direct_gw)
    }
}

#[derive(diesel::QueryableByName)]
struct PartitionBoundRow {
    #[diesel(sql_type = Timestamptz)]
    lower_bound: NaiveDateTime,
}

#[derive(diesel::QueryableByName)]
struct ParentTableRow {
    #[diesel(sql_type = Text)]
    parent_table: String,
}

async fn ensure_partitions_exist(pool: Pool<AsyncPgConnection>, retention_horizon: NaiveDateTime) {
    // We require daily partitions from the retention horizon day up to today for all partitioned tables.
    let mut conn = pool.get().await.expect("connection ok");
    // Auto-discover parent partitioned tables in public schema that are partitioned and include a valid_to column
    let parent_rows: Vec<ParentTableRow> = sql_query(
        r#"
        SELECT format('%I.%I', n.nspname, c.relname) AS parent_table
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'p'
          AND n.nspname = 'public'
          AND EXISTS (
            SELECT 1
            FROM information_schema.columns col
            WHERE col.table_schema = n.nspname
              AND col.table_name = c.relname
              AND col.column_name = 'valid_to'
          )
        "#
    )
    .load(&mut conn)
    .await
    .expect("Failed to list parent partitioned tables");
    let parents: Vec<String> = parent_rows.into_iter().map(|r| r.parent_table).collect();
    info!("Verifying existence of daily partitions for: {} ...", parents.join(", "));

    // Compute day range [start_day, end_day]
    let start_day: NaiveDate = retention_horizon.date();
    let now = chrono::Local::now().naive_utc();
    let end_day: NaiveDate = now.date();

    for parent in parents.iter() {
        let sql = format!(
            "SELECT substring(pg_get_expr(c.relpartbound, c.oid) from 'FROM \\(''(.*?)''\\)')::timestamptz AS lower_bound \
             FROM pg_inherits i \
             JOIN pg_class c ON c.oid = i.inhrelid \
             WHERE i.inhparent = '{}'::regclass \
               AND pg_get_expr(c.relpartbound, c.oid) <> 'DEFAULT'",
            parent
        );

        let rows: Vec<PartitionBoundRow> = sql_query(sql)
            .load(&mut conn)
            .await
            .expect("Failed to list partitions");

        let mut existing_days = std::collections::HashSet::new();
        for r in rows.iter() {
            existing_days.insert(r.lower_bound.date());
        }

        let mut missing: Vec<NaiveDate> = Vec::new();
        let mut d = start_day;
        while d <= end_day {
            if !existing_days.contains(&d) {
                missing.push(d);
            }
            d = d.succ_opt().expect("date increment");
        }

        if !missing.is_empty() {
            let first = missing.get(0).unwrap();
            let last = missing.last().unwrap();
            let start_ts = NaiveDateTime::new(*first, NaiveTime::from_hms_opt(0, 0, 0).unwrap());
            let end_ts = NaiveDateTime::new(*last, NaiveTime::from_hms_opt(23, 59, 59).unwrap());
            panic!(
                "Missing daily partitions for {} in range [{} .. {}] ({} days). Ensure pg_partman created them.",
                parent,
                start_ts,
                end_ts,
                missing.len()
            );
        }
    }
}

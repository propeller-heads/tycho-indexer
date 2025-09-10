use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use diesel::{
    sql_query,
    sql_types::{Text, Timestamptz},
};
use diesel_async::RunQueryDsl;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::info;
use tycho_common::{models::Chain, storage::StorageError};

use crate::postgres::{self, cache::CachedGateway, direct::DirectGateway, PostgresGateway};

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

#[derive(Default, Debug)]
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
        let inner_gw = PostgresGateway::new(pool.clone(), self.retention_horizon).await?;
        let (tx, rx) = mpsc::channel(10);
        let chain = self
            .chains
            .as_slice()
            .first()
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
        let inner_gw = PostgresGateway::new(pool.clone(), self.retention_horizon).await?;
        let (tx, _) = mpsc::channel(10);

        let cached_gw = CachedGateway::new(tx, pool.clone(), inner_gw.clone());
        Ok(cached_gw)
    }

    pub async fn build_direct_gw(self) -> Result<DirectGateway, StorageError> {
        let pool = postgres::connect(&self.database_url).await?;
        postgres::ensure_chains(&self.chains, pool.clone()).await;
        postgres::ensure_protocol_systems(&self.protocol_systems, pool.clone()).await;
        let inner_gw = PostgresGateway::new(pool.clone(), self.retention_horizon).await?;

        let chain = self
            .chains
            .as_slice()
            .first()
            .expect("No chains provided"); //TODO: handle multichain?

        let direct_gw = DirectGateway::new(pool.clone(), inner_gw.clone(), *chain);
        Ok(direct_gw)
    }

    pub async fn ensure_partitions_exist(self) -> Result<Self, StorageError> {
        let pool = postgres::connect(&self.database_url).await?;

        // We require daily partitions from the retention horizon day up to today for all
        // partitioned tables.
        let mut conn = pool.get().await.expect("connection ok");
        // Auto-discover parent partitioned tables in public schema that are partitioned and include
        // a valid_to column
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
            "#,
        )
        .load(&mut conn)
        .await
        .expect("Failed to list parent partitioned tables");
        let parents: Vec<String> = parent_rows
            .into_iter()
            .map(|r| r.parent_table)
            .collect();
        info!("Verifying existence of daily partitions for: {} ...", parents.join(", "));

        // Compute day range [start_day, end_day]
        let start_day: NaiveDate = self.retention_horizon.date();
        let now = chrono::Local::now().naive_utc();
        let end_day: NaiveDate = now.date();

        for parent in parents.iter() {
            let sql = format!(
                "SELECT substring(pg_get_expr(c.relpartbound, c.oid) from 'FROM \\(''(.*?)''\\)')::timestamptz AS lower_bound \
                FROM pg_inherits i \
                JOIN pg_class c ON c.oid = i.inhrelid \
                WHERE i.inhparent = '{parent}'::regclass \
                AND pg_get_expr(c.relpartbound, c.oid) <> 'DEFAULT'"
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
                let first = missing.as_slice().first().unwrap();
                let last = missing.as_slice().last().unwrap();
                let start_ts =
                    NaiveDateTime::new(*first, NaiveTime::from_hms_opt(0, 0, 0).unwrap());
                let end_ts =
                    NaiveDateTime::new(*last, NaiveTime::from_hms_opt(23, 59, 59).unwrap());
                panic!(
                    "Missing daily partitions for {} in range [{} .. {}] ({} days). Ensure pg_partman created them.",
                    parent,
                    start_ts,
                    end_ts,
                    missing.len()
                );
            }
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDate;
    use diesel::sql_query;
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

    use super::*;

    async fn setup_db() -> AsyncPgConnection {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let mut conn = AsyncPgConnection::establish(&db_url)
            .await
            .expect("Connection ok");
        conn.begin_test_transaction()
            .await
            .expect("test tx ok");
        conn
    }

    #[tokio::test]
    async fn test_parent_discovery_and_lower_bounds() {
        let mut conn = setup_db().await;

        // Create a temporary partitioned table in public schema with valid_to
        sql_query("DROP TABLE IF EXISTS public.test_part_parent CASCADE;")
            .execute(&mut conn)
            .await
            .expect("drop ok");

        // Create parent and child partitions (split into separate statements)
        sql_query(
            r#"
            CREATE TABLE public.test_part_parent (
                id bigserial,
                valid_to timestamptz NOT NULL
            ) PARTITION BY RANGE (valid_to);
            "#,
        )
        .execute(&mut conn)
        .await
        .expect("create parent ok");

        sql_query(
            r#"
            CREATE TABLE public.test_part_parent_20250901 PARTITION OF public.test_part_parent
            FOR VALUES FROM ('2025-09-01') TO ('2025-09-02');
            "#,
        )
        .execute(&mut conn)
        .await
        .expect("create child 20250901 ok");

        sql_query(
            r#"
            CREATE TABLE public.test_part_parent_20250902 PARTITION OF public.test_part_parent
            FOR VALUES FROM ('2025-09-02') TO ('2025-09-03');
            "#,
        )
        .execute(&mut conn)
        .await
        .expect("create child 20250902 ok");

        // Discover parents in public schema with valid_to column
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
            "#,
        )
        .load(&mut conn)
        .await
        .expect("discover parents ok");

        let parents: Vec<String> = parent_rows
            .into_iter()
            .map(|r| r.parent_table)
            .collect();
        assert!(parents.contains(&"public.test_part_parent".to_string()));

        // Parse child lower bounds for our temp parent
        let lb_rows: Vec<PartitionBoundRow> = sql_query(
            r#"
            SELECT
                substring(pg_get_expr(c.relpartbound, c.oid) from 'FROM \(''(.*?)''\)')::timestamptz AS lower_bound
            FROM pg_inherits i
            JOIN pg_class c ON c.oid = i.inhrelid
            WHERE i.inhparent = 'public.test_part_parent'::regclass
              AND pg_get_expr(c.relpartbound, c.oid) <> 'DEFAULT'
            "#,
        )
        .load(&mut conn)
        .await
        .expect("list child lower bounds ok");

        let mut days: Vec<NaiveDate> = lb_rows
            .into_iter()
            .map(|r| r.lower_bound.date())
            .collect();
        days.sort();

        assert_eq!(
            days,
            vec![
                NaiveDate::from_ymd_opt(2025, 9, 1).unwrap(),
                NaiveDate::from_ymd_opt(2025, 9, 2).unwrap(),
            ]
        );

        // Cleanup
        sql_query("DROP TABLE IF EXISTS public.test_part_parent CASCADE;")
            .execute(&mut conn)
            .await
            .expect("cleanup ok");
    }

    #[tokio::test]
    async fn test_missing_partition_detected() {
        // Note: This test creates/drops real tables; no test transaction.
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let mut conn = AsyncPgConnection::establish(&db_url)
            .await
            .expect("Connection ok");

        // Clean slate
        sql_query("DROP TABLE IF EXISTS public.test_part_parent_missing CASCADE;")
            .execute(&mut conn)
            .await
            .expect("drop ok");

        // Create parent with only one day partition (2025-09-02), leaving 2025-09-01 missing
        sql_query(
            r#"
            CREATE TABLE public.test_part_parent_missing (
                id bigserial,
                valid_to timestamptz NOT NULL
            ) PARTITION BY RANGE (valid_to);
            "#,
        )
        .execute(&mut conn)
        .await
        .expect("create parent missing ok");

        sql_query(
            r#"
            CREATE TABLE public.test_part_parent_missing_20250902 PARTITION OF public.test_part_parent_missing
            FOR VALUES FROM ('2025-09-02') TO ('2025-09-03');
            "#,
        )
        .execute(&mut conn)
        .await
        .expect("create existing child ok");

        // Run the partition check; it should panic due to the missing day
        let horizon = NaiveDate::from_ymd_opt(1999, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let builder = GatewayBuilder::new(&db_url).set_retention_horizon(horizon);
        let handle = tokio::spawn(builder.ensure_partitions_exist());
        let res = handle.await;
        assert!(
            res.is_err() && res.unwrap_err().is_panic(),
            "expected panic on missing partitions"
        );

        // Cleanup
        sql_query("DROP TABLE IF EXISTS public.test_part_parent_missing CASCADE;")
            .execute(&mut conn)
            .await
            .expect("cleanup ok");
    }
}

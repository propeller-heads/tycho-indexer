use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::Deref,
    str::FromStr,
    sync::Arc,
};

use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel_async::{pooled_connection::deadpool::Pool, AsyncPgConnection, RunQueryDsl};
use tokio::sync::RwLock;
use tycho_common::{
    models::{protocol::QualityRange, token::CurrencyToken, Address, Chain, PaginationParams},
    storage::{StorageError, WithTotal},
};

use crate::postgres::{orm, schema, PostgresError};

#[derive(Debug, Clone)]
pub struct TokenCache {
    tokens: Arc<RwLock<HashMap<Address, CurrencyToken>>>,
    quality_index: Arc<RwLock<BTreeMap<i32, HashSet<Address>>>>,
    traded_ts_index: Arc<RwLock<BTreeMap<NaiveDateTime, HashSet<Address>>>>,
}

impl TokenCache {
    pub async fn from_pool(pool: Pool<AsyncPgConnection>) -> Result<Self, StorageError> {
        let mut conn = pool
            .get()
            .await
            .map_err(|err| StorageError::Unexpected(err.to_string()))?;

        Self::from_connection(&mut conn).await
    }

    pub async fn from_connection(mut conn: &mut AsyncPgConnection) -> Result<Self, StorageError> {
        use super::schema::token as dsl_token;

        //TODO: Would be safer to get the chain from the CLI args, but it requires some interface
        // changes
        let chain_str = schema::chain::table
            .select(schema::chain::name)
            .first::<String>(&mut conn)
            .await
            .map_err(PostgresError::from)?;

        let chain = Chain::from_str(&chain_str)
            .map_err(|_| StorageError::Unexpected("Invalid chain".to_string()))?;

        let tokens = Arc::new(RwLock::new(HashMap::new()));
        let quality_index = Arc::new(RwLock::new(BTreeMap::<i32, HashSet<Address>>::new()));
        let traded_ts_index =
            Arc::new(RwLock::new(BTreeMap::<NaiveDateTime, HashSet<Address>>::new()));

        let raw_results: Vec<_> = dsl_token::table
            .inner_join(schema::account::table)
            .select((dsl_token::all_columns, schema::account::address))
            .load::<(orm::Token, Address)>(&mut conn)
            .await
            .map_err(PostgresError::from)?;

        let ids_to_tokens = raw_results
            .iter()
            .map(|(token, address)| (token.id, address.clone()))
            .collect::<HashMap<_, _>>();

        let results: Vec<CurrencyToken> = raw_results
            .into_iter()
            .map(|(token, address)| {
                let gas_usage: Vec<_> = token
                    .gas
                    .iter()
                    .map(|u| u.map(|g| g as u64))
                    .collect();
                CurrencyToken::new(
                    &address,
                    token.symbol.as_str(),
                    token.decimals as u32,
                    token.tax as u64,
                    gas_usage.as_slice(),
                    chain,
                    token.quality as u32,
                )
            })
            .collect();

        // Scope for holding the locks
        {
            let mut tokens_lock = tokens.write().await;
            let mut quality_index_lock = quality_index.write().await;

            results.into_iter().for_each(|token| {
                tokens_lock.insert(token.address.clone(), token.clone());
                quality_index_lock
                    .entry(token.quality as i32)
                    .or_default()
                    .insert(token.address.clone());
            });
        }

        let last_traded_ts = schema::component_balance_default::table
            .select((
                schema::component_balance_default::token_id,
                schema::component_balance_default::valid_from,
            ))
            .order_by((
                schema::component_balance_default::token_id.asc(),
                schema::component_balance_default::valid_from.desc(),
            ))
            .distinct_on(schema::component_balance_default::token_id)
            .load::<(i64, chrono::NaiveDateTime)>(&mut conn)
            .await
            .map_err(PostgresError::from)?;

        // Scope for holding the locks
        {
            let mut traded_ts_index_lock = traded_ts_index.write().await;
            for (token_id, valid_from) in last_traded_ts {
                let token = ids_to_tokens.get(&token_id).unwrap();
                traded_ts_index_lock
                    .entry(valid_from)
                    .or_default()
                    .insert((*token).clone());
            }
        }

        Ok(Self { tokens, quality_index, traded_ts_index })
    }

    pub async fn upsert_tokens(&self, tokens: Vec<CurrencyToken>) {
        let mut quality_index_lock = self.quality_index.write().await;
        let mut tokens_lock = self.tokens.write().await;
        for token in tokens {
            let old_token = tokens_lock.insert(token.address.clone(), token.clone());
            if let Some(old_token) = old_token {
                quality_index_lock
                    .entry(old_token.quality as i32)
                    .or_default()
                    .remove(&old_token.address);
            }
            quality_index_lock
                .entry(token.quality as i32)
                .or_default()
                .insert(token.address);
        }
    }

    pub async fn update_last_traded_ts(&self, entries: HashMap<NaiveDateTime, Vec<Address>>) {
        // TODO: This function doesn't remove old entries. Is this a problem?
        // For filtering it is not because we only filter by >= target ts, so worst case we will
        // encounter the same token twice. But what about memory usage? It will keep growing
        // forever.
        let mut traded_ts_index_lock = self.traded_ts_index.write().await;
        for (last_traded_ts, addresses) in entries {
            traded_ts_index_lock
                .entry(last_traded_ts)
                .or_default()
                .extend(addresses.iter().map(|a| (*a).clone()));
        }
    }

    pub(crate) async fn query_tokens(
        &self,
        addresses: Option<&[&Address]>,
        quality_range: QualityRange,
        last_traded_ts_threshold: Option<NaiveDateTime>,
        pagination: Option<&PaginationParams>,
    ) -> Result<WithTotal<Vec<CurrencyToken>>, StorageError> {
        let tokens_lock = self.tokens.read().await;
        let mut candidate_addrs: HashSet<&Address> = match addresses {
            Some(addrs) => addrs.iter().copied().collect(),
            None => tokens_lock.keys().collect(),
        };

        match (quality_range.min, quality_range.max) {
            (Some(min_q), Some(max_q)) => {
                let quality_index_lock = self.quality_index.read().await;

                let quality_ids: HashSet<_> = quality_index_lock
                    .range(min_q..=max_q)
                    .flat_map(|(_, addrs)| addrs)
                    .collect();

                candidate_addrs.retain(|addr| quality_ids.contains(addr));
            }
            (Some(min_q), None) => {
                let quality_index_lock = self.quality_index.read().await;
                let quality_ids: HashSet<_> = quality_index_lock
                    .range(min_q..)
                    .flat_map(|(_, addrs)| addrs)
                    .collect();
                candidate_addrs.retain(|addr| quality_ids.contains(addr));
            }
            (None, Some(max_q)) => {
                let quality_index_lock = self.quality_index.read().await;
                let quality_ids: HashSet<_> = quality_index_lock
                    .range(..=max_q)
                    .flat_map(|(_, addrs)| addrs)
                    .collect();
                candidate_addrs.retain(|addr| quality_ids.contains(addr));
            }
            (None, None) => {
                // No filter; no-op
            }
        }

        if let Some(ts) = last_traded_ts_threshold {
            let traded_ts_index_lock = self.traded_ts_index.read().await;
            let ts_ids: HashSet<_> = traded_ts_index_lock
                .range(ts..)
                .flat_map(|(_, addrs)| addrs)
                .collect();

            candidate_addrs.retain(|addr| ts_ids.contains(addr));
        }

        let mut results: Vec<_> = candidate_addrs
            .iter()
            .map(|addr| {
                tokens_lock
                    .get(*addr)
                    .cloned()
                    .ok_or(StorageError::NotFound("Token".to_string(), format!("{}", addr)))
            })
            .collect::<Result<Vec<_>, StorageError>>()?;

        let total = results.len() as i64;

        if let Some(pagination) = pagination {
            let offset = pagination.offset() as usize;
            let limit = pagination.page_size as usize;
            results = results
                .into_iter()
                .skip(offset)
                .take(limit)
                .collect();
        }

        Ok(WithTotal { total: Some(total), entity: results })
    }
}

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ops::Bound,
    str::FromStr,
    sync::Arc,
    time::Instant,
};

use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel_async::{pooled_connection::deadpool::Pool, AsyncPgConnection, RunQueryDsl};
use iter_set::{intersection, union};
use itertools::Itertools;
use tokio::sync::RwLock;
use tracing::{debug, info};
use tycho_common::{
    models::{protocol::QualityRange, token::CurrencyToken, Address, Chain, PaginationParams},
    storage::{StorageError, WithTotal},
};

#[derive(Debug, Clone)]
pub(crate) struct TokenQuery {
    pub(crate) chain: Chain,
    pub(crate) addresses: Option<Vec<Address>>,
    pub(crate) quality_range: QualityRange,
    pub(crate) last_traded_ts_threshold: Option<NaiveDateTime>,
    pub(crate) pagination: Option<PaginationParams>,
}

use crate::postgres::{orm, schema, PostgresError};

/// Index of tokens by address.
type TokenIndex = Arc<RwLock<HashMap<Address, Arc<CurrencyToken>>>>;
/// Index of tokens by quality.
type QualityIndex = Arc<RwLock<BTreeMap<i32, BTreeSet<Address>>>>;
/// Index of tokens by last traded timestamp.
type TradedTsIndex = Arc<RwLock<BTreeMap<NaiveDateTime, BTreeSet<Address>>>>;

#[derive(Debug, Clone)]
pub struct TokenCache {
    tokens: HashMap<Chain, TokenIndex>,
    quality_index: HashMap<Chain, QualityIndex>,
    traded_ts_index: HashMap<Chain, TradedTsIndex>,
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
            .load::<String>(&mut conn)
            .await
            .map_err(PostgresError::from)?;

        let mut tokens = HashMap::new();
        let mut quality_index = HashMap::new();
        let mut traded_ts_index = HashMap::new();

        for chain_str in chain_str {
            let chain = Chain::from_str(&chain_str)
                .map_err(|_| StorageError::Unexpected("Invalid chain".to_string()))?;

            let chain_id = schema::chain::table
                .select(schema::chain::id)
                .filter(schema::chain::name.eq(&chain_str))
                .first::<i64>(&mut conn)
                .await
                .map_err(PostgresError::from)?;

            let chain_tokens = Arc::new(RwLock::new(HashMap::new()));
            let chain_quality_index =
                Arc::new(RwLock::new(BTreeMap::<i32, BTreeSet<Address>>::new()));
            let chain_traded_ts_index =
                Arc::new(RwLock::new(BTreeMap::<NaiveDateTime, BTreeSet<Address>>::new()));

            let raw_results: Vec<_> = dsl_token::table
                .inner_join(schema::account::table)
                .filter(schema::account::chain_id.eq(chain_id))
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
            let res_len = results.len();

            // Scope for holding the locks
            {
                let mut tokens_lock = chain_tokens.write().await;
                let mut quality_index_lock = chain_quality_index.write().await;

                results.into_iter().for_each(|token| {
                    let arc_token = Arc::new(token.clone());
                    tokens_lock.insert(token.address.clone(), arc_token);
                    quality_index_lock
                        .entry(token.quality as i32)
                        .or_default()
                        .insert(token.address.clone());
                });
            }

            let last_traded_ts = schema::component_balance_default::table
                .inner_join(schema::protocol_component::table)
                .filter(schema::protocol_component::chain_id.eq(chain_id))
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
                .map_err(PostgresError::from)?
                .into_iter()
                .map(|(token_id, valid_from)| (token_id, valid_from))
                .collect::<HashMap<_, _>>();

            // Scope for holding the locks
            {
                let mut traded_ts_index_lock = chain_traded_ts_index.write().await;
                for (token_id, valid_from) in last_traded_ts {
                    let token = ids_to_tokens.get(&token_id).unwrap();
                    traded_ts_index_lock
                        .entry(valid_from)
                        .or_default()
                        .insert((*token).clone());
                }
            }

            info!("TokenCache created with {} chains, {} tokens", chain_str.len(), res_len);
            info!("Quality index: {:?}", chain_quality_index.read().await.len());
            info!("Traded ts index: {:?}", chain_traded_ts_index.read().await.len());

            tokens.insert(chain, chain_tokens);
            quality_index.insert(chain, chain_quality_index);
            traded_ts_index.insert(chain, chain_traded_ts_index);
        }

        Ok(Self { tokens, quality_index, traded_ts_index })
    }

    pub async fn upsert_tokens(&self, tokens: Vec<CurrencyToken>) {
        let mut quality_index_lock = self
            .quality_index
            .get(&tokens[0].chain)
            .unwrap()
            .write()
            .await;
        let mut tokens_lock = self
            .tokens
            .get(&tokens[0].chain)
            .unwrap()
            .write()
            .await;
        for token in tokens {
            let arc_token = Arc::new(token.clone());
            let old_token = tokens_lock.insert(token.address.clone(), arc_token);
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

    pub async fn update_last_traded_ts(
        &self,
        chain: &Chain,
        entries: HashMap<NaiveDateTime, Vec<Address>>,
    ) {
        // TODO: This function doesn't remove old entries. Is this a problem?
        // For filtering it is not because we only filter by >= target ts, so worst case we will
        // encounter the same token twice. But what about memory usage? It will keep growing
        // forever.
        let mut traded_ts_index_lock = self
            .traded_ts_index
            .get(chain)
            .unwrap()
            .write()
            .await;
        for (last_traded_ts, addresses) in entries {
            traded_ts_index_lock
                .entry(last_traded_ts)
                .or_default()
                .extend(addresses.iter().map(|a| (*a).clone()));
        }
    }

    pub(crate) async fn query_tokens(
        &self,
        query: TokenQuery,
    ) -> Result<WithTotal<Vec<CurrencyToken>>, StorageError> {
        info!("Querying tokens: {:?}", query);
        let query_start = Instant::now();
        info!("Querying tokens for chain: {:?}", query.chain);

        let lock_start = Instant::now();
        let tokens_lock = self
            .tokens
            .get(&query.chain)
            .unwrap()
            .read()
            .await;
        debug!("Tokens lock acquisition took: {:?}", lock_start.elapsed());

        // Smart filter ordering - start with the most restrictive filter to minimize work
        let intersection_start = Instant::now();

        // Determine filter priorities and get the most restrictive one first
        let has_addresses = query.addresses.is_some();
        let has_quality = query.quality_range.min.is_some() || query.quality_range.max.is_some();
        let has_timestamp = query.last_traded_ts_threshold.is_some();

        let addresses_iter = match query.addresses {
            Some(addresses) => Some(addresses.iter().sorted()),
            None => None,
        };

        let quality_lookup_start = Instant::now();
        let quality_index_lock = self
            .quality_index
            .get(&query.chain)
            .unwrap()
            .read()
            .await;
        let quality_iter = match (query.quality_range.min, query.quality_range.max) {
            (Some(min_q), Some(max_q)) => {
                info!("qualities range: {:?}", min_q..=max_q);
                Some(
                    quality_index_lock
                        .range(min_q..=max_q)
                        .map(|(_, addrs)| addrs.iter())
                        .kmerge()
                        .dedup(),
                )
            }
            (Some(min_q), None) => {
                info!("qualities range: {:?}", (Bound::Included(min_q), Bound::<i32>::Unbounded));
                Some(
                    quality_index_lock
                        .range((Bound::Included(min_q), Bound::Unbounded))
                        .map(|(_, addrs)| addrs.iter())
                        .kmerge()
                        .dedup(),
                )
            }
            (None, Some(max_q)) => {
                info!("qualities range: {:?}", (Bound::<i32>::Unbounded, Bound::Excluded(max_q)));
                Some(
                    quality_index_lock
                        .range(..=max_q)
                        .map(|(_, addrs)| addrs.iter())
                        .kmerge()
                        .dedup(),
                )
            }
            (None, None) => None,
        };
        drop(quality_index_lock);
        debug!("Quality lookup took: {:?}", quality_lookup_start.elapsed());

        let ts_lookup_start = Instant::now();
        let ts_iter = match (query.last_traded_ts_threshold) {
            Some(ts) => {
                let traded_ts_index_lock = self
                    .traded_ts_index
                    .get(&query.chain)
                    .unwrap()
                    .read()
                    .await;
                Some(
                    traded_ts_index_lock
                        .range((Bound::Excluded(ts), Bound::Unbounded))
                        .map(|(_, addrs)| addrs.iter())
                        .kmerge()
                        .dedup(),
                )
            }
            None => None,
        };
        debug!("Traded timestamp lookup took: {:?}", ts_lookup_start.elapsed());

        let candidate_iter = [quality_iter, ts_iter, addresses_iter]
            .into_iter()
            .flatten() // Remove None values, keep Some iterators
            .reduce(|acc, iter| intersection(&acc, &iter));

        let total_candidates = candidate_addrs.len() as i64;
        info!("Total candidates: {:?}", total_candidates);

        // Apply pagination and lookup tokens using iterators
        let pagination_start = Instant::now();
        let results: Result<Vec<_>, StorageError> = if let Some(pagination) = query.pagination {
            let offset = pagination.offset() as usize;
            let limit = pagination.page_size as usize;
            candidate_addrs
                .iter()
                .skip(offset)
                .take(limit)
                .map(|addr| {
                    tokens_lock
                        .get(addr)
                        .map(|arc_token| (**arc_token).clone())
                        .ok_or(StorageError::NotFound("Token".to_string(), format!("{addr}")))
                })
                .collect()
        } else {
            candidate_addrs
                .iter()
                .map(|addr| {
                    tokens_lock
                        .get(addr)
                        .map(|arc_token| (**arc_token).clone())
                        .ok_or(StorageError::NotFound("Token".to_string(), format!("{addr}")))
                })
                .collect()
        };
        debug!("Pagination and token lookup took: {:?}", pagination_start.elapsed());

        let results = results?;
        info!("Final results: {:?}", results.len());

        info!("Total query_tokens took: {:?}", query_start.elapsed());
        Ok(WithTotal { total: Some(total_candidates), entity: results })
    }
}

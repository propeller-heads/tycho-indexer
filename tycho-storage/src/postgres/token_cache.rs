use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::Bound,
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

/// Index of tokens by address.
type TokenIndex = Arc<RwLock<HashMap<Address, CurrencyToken>>>;
/// Index of tokens by quality.
type QualityIndex = Arc<RwLock<BTreeMap<i32, HashSet<Address>>>>;
/// Index of tokens by last traded timestamp.
type TradedTsIndex = Arc<RwLock<BTreeMap<NaiveDateTime, HashSet<Address>>>>;

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
                .filter(schema::chain::name.eq(chain_str))
                .first::<i64>(&mut conn)
                .await
                .map_err(PostgresError::from)?;

            let chain_tokens = Arc::new(RwLock::new(HashMap::new()));
            let chain_quality_index =
                Arc::new(RwLock::new(BTreeMap::<i32, HashSet<Address>>::new()));
            let chain_traded_ts_index =
                Arc::new(RwLock::new(BTreeMap::<NaiveDateTime, HashSet<Address>>::new()));

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

            // Scope for holding the locks
            {
                let mut tokens_lock = chain_tokens.write().await;
                let mut quality_index_lock = chain_quality_index.write().await;

                results.into_iter().for_each(|token| {
                    tokens_lock.insert(token.address.clone(), token.clone());
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
        chain: &Chain,
        addresses: Option<&[&Address]>,
        quality_range: QualityRange,
        last_traded_ts_threshold: Option<NaiveDateTime>,
        pagination: Option<&PaginationParams>,
    ) -> Result<WithTotal<Vec<CurrencyToken>>, StorageError> {
        let tokens_lock = self
            .tokens
            .get(chain)
            .unwrap()
            .read()
            .await;
        let mut candidate_addrs: HashSet<&Address> = match addresses {
            Some(addrs) => addrs.iter().copied().collect(),
            None => tokens_lock.keys().collect(),
        };

        match (quality_range.min, quality_range.max) {
            (Some(min_q), Some(max_q)) => {
                let quality_index_lock = self
                    .quality_index
                    .get(chain)
                    .unwrap()
                    .read()
                    .await;

                let quality_ids: HashSet<_> = quality_index_lock
                    .range(min_q..=max_q)
                    .flat_map(|(_, addrs)| addrs)
                    .collect();

                candidate_addrs.retain(|addr| quality_ids.contains(addr));
            }
            (Some(min_q), None) => {
                let quality_index_lock = self
                    .quality_index
                    .get(chain)
                    .unwrap()
                    .read()
                    .await;
                let quality_ids: HashSet<_> = quality_index_lock
                    .range((Bound::Excluded(min_q), Bound::Unbounded))
                    .flat_map(|(_, addrs)| addrs)
                    .collect();
                candidate_addrs.retain(|addr| quality_ids.contains(addr));
            }
            (None, Some(max_q)) => {
                let quality_index_lock = self
                    .quality_index
                    .get(chain)
                    .unwrap()
                    .read()
                    .await;
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
            let traded_ts_index_lock = self
                .traded_ts_index
                .get(chain)
                .unwrap()
                .read()
                .await;
            let ts_ids: HashSet<_> = traded_ts_index_lock
                .range((Bound::Excluded(ts), Bound::Unbounded))
                .flat_map(|(_, addrs)| addrs)
                .collect();

            candidate_addrs.retain(|addr| ts_ids.contains(addr));
        }

        let mut candidate_addrs = candidate_addrs
            .into_iter()
            .collect::<Vec<_>>();
        candidate_addrs.sort_unstable_by_key(|addr| addr.to_string());

        let total_candidates = candidate_addrs.len() as i64;

        let paginated_addrs: Vec<_> = if let Some(pagination) = pagination {
            let offset = pagination.offset() as usize;
            let limit = pagination.page_size as usize;
            candidate_addrs
                .iter()
                .skip(offset)
                .take(limit)
                .copied()
                .collect()
        } else {
            candidate_addrs.to_vec()
        };

        let results: Vec<_> = paginated_addrs
            .into_iter()
            .map(|addr| {
                tokens_lock
                    .get(addr)
                    .cloned()
                    .ok_or(StorageError::NotFound("Token".to_string(), format!("{addr}")))
            })
            .collect::<Result<Vec<_>, StorageError>>()?;

        Ok(WithTotal { total: Some(total_candidates), entity: results })
    }
}

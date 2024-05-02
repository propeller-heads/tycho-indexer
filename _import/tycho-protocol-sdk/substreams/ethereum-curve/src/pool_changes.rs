use substreams::{
    scalar::BigInt,
    store::{StoreGet, StoreGetInt64, StoreGetString},
};
use substreams_ethereum::{block_view::LogView, Event};
use tycho_substreams::prelude::*;

use crate::abi;

struct GenericAddLiquidity {
    token_amounts: Vec<BigInt>,
    provider: String,
    fees: BigInt,
    invariant: BigInt,
    token_supply: BigInt,
}

fn tx_from_log(log: &LogView) -> Transaction {
    Transaction {
        hash: log.receipt.transaction.hash.clone(),
        from: log.receipt.transaction.from.clone(),
        to: log.receipt.transaction.to.clone(),
        index: Into::<u64>::into(log.receipt.transaction.index),
    }
}

/// This function emits balance deltas for mints, burns, and exchanges in Curve pools. Since some
///  pools contain differing ABIs, we load in several examples of abis in order to best match the
///  topic ID to the correct event. The repetition in this function is dervived from the fact that
///  most of these events have similar structures, but the specific topic id differs.
pub fn emit_deltas(
    log: LogView,
    pools_store: &StoreGetInt64,
    tokens_store: &StoreGetString,
) -> Option<Vec<BalanceDelta>> {
    let pool_key = format!("pool:{}", hex::encode(&log.address()));
    if pools_store.get_last(pool_key).is_none() {
        return None;
    }

    let tokens = tokens_store
        .get_last(format!("pool:{}", hex::encode(log.address())))?
        .split(":")
        .map(|token| token.to_owned())
        .collect::<Vec<_>>();

    if let Some(event) = abi::pool::events::TokenExchange::match_and_decode(log) {
        return token_change_deltas(event, log);
    } else if let Some(event) = abi::pool_3pool::events::TokenExchange::match_and_decode(log) {
        return token_change_deltas(
            abi::pool::events::TokenExchange {
                sold_id: event.sold_id,
                bought_id: event.bought_id,
                tokens_sold: event.tokens_sold,
                tokens_bought: event.tokens_bought,
                buyer: event.buyer,
            },
            log,
        );
    } else if let Some(event) = abi::pool_steth::events::TokenExchange::match_and_decode(log) {
        return token_change_deltas(
            abi::pool::events::TokenExchange {
                sold_id: event.sold_id,
                bought_id: event.bought_id,
                tokens_sold: event.tokens_sold,
                tokens_bought: event.tokens_bought,
                buyer: event.buyer,
            },
            log,
        );
    } else if let Some(event) = abi::pool_tricrypto::events::TokenExchange::match_and_decode(log) {
        return token_change_deltas(
            abi::pool::events::TokenExchange {
                sold_id: event.sold_id,
                bought_id: event.bought_id,
                tokens_sold: event.tokens_sold,
                tokens_bought: event.tokens_bought,
                buyer: event.buyer,
            },
            log,
        );
    } else if let Some(event) = abi::pool::events::AddLiquidity::match_and_decode(log) {
        return add_liquidity_deltas(event.token_amounts.into(), &tokens, log);
    } else if let Some(event) = abi::pool_3pool::events::AddLiquidity::match_and_decode(log) {
        return add_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool_steth::events::AddLiquidity::match_and_decode(log) {
        return add_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool_tricrypto::events::AddLiquidity::match_and_decode(log) {
        return add_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool::events::RemoveLiquidity::match_and_decode(log) {
        return add_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool_3pool::events::RemoveLiquidity::match_and_decode(log) {
        return add_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool_steth::events::RemoveLiquidity::match_and_decode(log) {
        return add_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool_tricrypto::events::RemoveLiquidity::match_and_decode(log)
    {
        return add_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else {
        None
    }
}

fn token_change_deltas(
    event: abi::pool::events::TokenExchange,
    log: LogView<'_>,
) -> Option<Vec<BalanceDelta>> {
    let tokens_bought_delta: BigInt = event.tokens_bought * -1;
    Some(vec![
        BalanceDelta {
            ord: log.log.ordinal,
            tx: Some(tx_from_log(&log)),
            token: event.sold_id.to_signed_bytes_be(),
            delta: event.tokens_sold.to_signed_bytes_be(),
            component_id: log.address().into(),
        },
        BalanceDelta {
            ord: log.log.ordinal,
            tx: Some(tx_from_log(&log)),
            token: event.bought_id.to_signed_bytes_be(),
            delta: tokens_bought_delta.to_signed_bytes_be(),
            component_id: log.address().into(),
        },
    ])
}

fn add_liquidity_deltas(
    amounts: Vec<BigInt>,
    tokens: &Vec<String>,
    log: LogView<'_>,
) -> Option<Vec<BalanceDelta>> {
    Some(
        amounts
            .iter()
            .zip(tokens)
            .map(move |(token_amount, token_id)| BalanceDelta {
                ord: log.log.ordinal,
                tx: Some(tx_from_log(&log)),
                token: token_id.as_str().into(),
                delta: token_amount.to_signed_bytes_be(),
                component_id: log.address().into(),
            })
            .collect::<Vec<_>>(),
    )
}

fn remove_liquidity_deltas(
    amounts: Vec<BigInt>,
    tokens: &Vec<String>,
    log: LogView<'_>,
) -> Option<Vec<BalanceDelta>> {
    Some(
        amounts
            .iter()
            .zip(tokens)
            .map(move |(token_amount, token_id)| BalanceDelta {
                ord: log.log.ordinal,
                tx: Some(tx_from_log(&log)),
                token: token_id.as_str().into(),
                delta: token_amount.to_signed_bytes_be(),
                component_id: log.address().into(),
            })
            .collect::<Vec<_>>(),
    )
}

use substreams::{
    scalar::BigInt,
    store::{StoreGet, StoreGetInt64, StoreGetString},
};
use substreams_ethereum::{block_view::LogView, Event};
use tycho_substreams::prelude::*;

use crate::abi;

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
pub fn emit_deltas(log: LogView, tokens_store: &StoreGetString) -> Option<Vec<BalanceDelta>> {
    let pool_key = format!("pool:{}", hex::encode(&log.address()));
    let tokens = tokens_store
        .get_last(pool_key)?
        .split(":")
        .map(|token| token.to_owned())
        .collect::<Vec<_>>();

    if let Some(event) = abi::pool::events::TokenExchange::match_and_decode(log) {
        token_change_deltas(tokens, event, log)
    } else if let Some(event) = abi::pool_3pool::events::TokenExchange::match_and_decode(log) {
        token_change_deltas(
            tokens,
            abi::pool::events::TokenExchange {
                sold_id: event.sold_id,
                bought_id: event.bought_id,
                tokens_sold: event.tokens_sold,
                tokens_bought: event.tokens_bought,
                buyer: event.buyer,
            },
            log,
        )
    } else if let Some(event) = abi::pool_steth::events::TokenExchange::match_and_decode(log) {
        token_change_deltas(
            tokens,
            abi::pool::events::TokenExchange {
                sold_id: event.sold_id,
                bought_id: event.bought_id,
                tokens_sold: event.tokens_sold,
                tokens_bought: event.tokens_bought,
                buyer: event.buyer,
            },
            log,
        )
    } else if let Some(event) = abi::pool_tricrypto::events::TokenExchange::match_and_decode(log) {
        token_change_deltas(
            tokens,
            abi::pool::events::TokenExchange {
                sold_id: event.sold_id,
                bought_id: event.bought_id,
                tokens_sold: event.tokens_sold,
                tokens_bought: event.tokens_bought,
                buyer: event.buyer,
            },
            log,
        )
    } else if let Some(event) = abi::pool_tricrypto2::events::TokenExchange::match_and_decode(log) {
        token_change_deltas(
            tokens,
            abi::pool::events::TokenExchange {
                sold_id: event.sold_id,
                bought_id: event.bought_id,
                tokens_sold: event.tokens_sold,
                tokens_bought: event.tokens_bought,
                buyer: event.buyer,
            },
            log,
        )
    } else if let Some(event) =
        abi::pool_crypto_swap_ng::events::TokenExchange::match_and_decode(log)
    {
        token_change_deltas(
            tokens,
            abi::pool::events::TokenExchange {
                sold_id: event.sold_id,
                bought_id: event.bought_id,
                tokens_sold: event.tokens_sold,
                tokens_bought: event.tokens_bought,
                buyer: event.buyer,
            },
            log,
        )
    } else if let Some(event) =
        abi::pool_crypto_swap_ng::events::TokenExchangeUnderlying::match_and_decode(log)
    {
        token_change_deltas(
            tokens,
            abi::pool::events::TokenExchange {
                sold_id: event.sold_id,
                bought_id: event.bought_id,
                tokens_sold: event.tokens_sold,
                tokens_bought: event.tokens_bought,
                buyer: event.buyer,
            },
            log,
        )
    } else if let Some(event) = abi::pool::events::AddLiquidity::match_and_decode(log) {
        add_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool_3pool::events::AddLiquidity::match_and_decode(log) {
        add_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool_steth::events::AddLiquidity::match_and_decode(log) {
        add_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool_tricrypto::events::AddLiquidity::match_and_decode(log) {
        add_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool_tricrypto2::events::AddLiquidity::match_and_decode(log) {
        add_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) =
        abi::pool_crypto_swap_ng::events::AddLiquidity::match_and_decode(log)
    {
        add_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool::events::RemoveLiquidity::match_and_decode(log) {
        remove_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool_3pool::events::RemoveLiquidity::match_and_decode(log) {
        remove_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool_steth::events::RemoveLiquidity::match_and_decode(log) {
        remove_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool_tricrypto::events::RemoveLiquidity::match_and_decode(log)
    {
        remove_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) = abi::pool_tricrypto2::events::RemoveLiquidity::match_and_decode(log)
    {
        remove_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    } else if let Some(event) =
        abi::pool_crypto_swap_ng::events::RemoveLiquidity::match_and_decode(log)
    {
        remove_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    // } else if let Some(event) =
    //     abi::pool_crypto_swap_ng::events::RemoveLiquidityImbalance::match_and_decode(log)
    // {
    //     remove_liquidity_deltas(event.token_amounts.into(), &tokens, log)
    // } else if let Some(event) =
    //     abi::pool_crypto_swap_ng::events::RemoveLiquidityOne::match_and_decode(log)
    // {
    //     Some(vec![
    //         BalanceDelta {
    //             ord: log.log.ordinal,
    //             tx: Some(tx_from_log(&log)),
    //             token: hex::decode(sold_token_id.clone()).unwrap(),
    //             delta: event.tokens_sold.to_signed_bytes_be(),
    //             component_id: hex::encode(log.address()).into(),
    //         },
    //         BalanceDelta {
    //             ord: log.log.ordinal,
    //             tx: Some(tx_from_log(&log)),
    //             token: hex::decode(sold_token_id.clone()).unwrap(),
    //             delta: event.tokens_sold.to_signed_bytes_be(),
    //             component_id: hex::encode(log.address()).into(),
    //         },
    //     ])
    } else {
        None
    }
}

fn token_change_deltas(
    tokens: Vec<String>,
    event: abi::pool::events::TokenExchange,
    log: LogView<'_>,
) -> Option<Vec<BalanceDelta>> {
    let tokens_bought_delta: BigInt = event.tokens_bought * -1;
    let sold_token_id = &tokens[event.sold_id.to_u64() as usize];
    let bought_token_id = &tokens[event.bought_id.to_u64() as usize];
    Some(vec![
        BalanceDelta {
            ord: log.log.ordinal,
            tx: Some(tx_from_log(&log)),
            token: hex::decode(sold_token_id.clone()).unwrap(),
            delta: event.tokens_sold.to_signed_bytes_be(),
            component_id: hex::encode(log.address()).into(),
        },
        BalanceDelta {
            ord: log.log.ordinal,
            tx: Some(tx_from_log(&log)),
            token: hex::decode(bought_token_id.clone()).unwrap(),
            delta: tokens_bought_delta.to_signed_bytes_be(),
            component_id: hex::encode(log.address()).into(),
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
                token: hex::decode(token_id).unwrap(),
                delta: token_amount.to_signed_bytes_be(),
                component_id: hex::encode(log.address()).into(),
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
            .map(move |(token_amount, token_id)| {
                let token_amount_neg: BigInt = token_amount.clone() * -1;
                BalanceDelta {
                    ord: log.log.ordinal,
                    tx: Some(tx_from_log(&log)),
                    token: hex::decode(token_id).unwrap(),
                    delta: token_amount_neg.to_signed_bytes_be(),
                    component_id: hex::encode(log.address()).into(),
                }
            })
            .collect::<Vec<_>>(),
    )
}

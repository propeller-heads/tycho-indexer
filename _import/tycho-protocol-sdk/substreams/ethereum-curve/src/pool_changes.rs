use substreams::{
    scalar::BigInt,
    store::{StoreGet, StoreGetInt64, StoreGetString},
};
use substreams_ethereum::{block_view::LogView, pb::eth, Event};
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

pub fn emit_deltas(
    log: LogView,
    pools_store: StoreGetInt64,
    tokens_store: StoreGetString,
) -> Option<impl Iterator<Item = BalanceDelta>> {
    if let Some(event) = abi::pool::events::TokenExchange::match_and_decode(log) {
        if pools_store
            .get_last(format!("pool:{0}", hex::encode(&log.address())))
            .is_none()
        {
            return None;
        }
        let tokens_bought_delta: BigInt = event.tokens_bought * -1;
        return Some(
            vec![
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
            ]
            .into_iter(),
        )
    } else if let Some(event) = abi::pool::events::AddLiquidity::match_and_decode(log) {
        let tokens = tokens_store
            .get_last(format!("pool:{0}", hex::encode(log.address())))?
            .split(":")
            .map(|token| token.to_owned()) // Clone the tokens
            .collect::<Vec<_>>();

        let deltas: Vec<_> = event
            .token_amounts
            .iter()
            .zip(tokens)
            .map(move |(token_amount, token_id)| BalanceDelta {
                ord: log.log.ordinal,
                tx: Some(tx_from_log(&log)),
                token: token_id.into(),
                delta: token_amount.to_signed_bytes_be(),
                component_id: log.address().into(),
            })
            .collect();

        return Some(deltas.into_iter());
    } else if let Some(event) = abi::pool::events::RemoveLiquidity::match_and_decode(log) {
        let tokens = tokens_store
            .get_last(format!("pool:{0}", hex::encode(log.address())))?
            .split(":")
            .map(|token| token.to_owned()) // Clone the tokens
            .collect::<Vec<_>>();

        let deltas: Vec<_> = event
            .token_amounts
            .iter()
            .zip(tokens)
            .map(move |(token_amount, token_id)| BalanceDelta {
                ord: log.log.ordinal,
                tx: Some(tx_from_log(&log)),
                token: token_id.into(),
                delta: token_amount.to_signed_bytes_be(),
                component_id: log.address().into(),
            })
            .collect();

        return Some(deltas.into_iter());
    }

    deltas.extend(
        block
            .logs()
            .filter_map(|log| {
                let event = abi::pool::events::AddLiquidity::match_and_decode(log)?;
                Some((log, event))
            })
            .filter_map(|(log, event)| {
                let tokens = tokens_store
                    .get_last(format!("pool:{0}", hex::encode(log.address())))?
                    .split(":")
                    .map(|token| token.to_owned()) // Clone the tokens
                    .collect::<Vec<_>>();

                Some((tokens, log, event))
            })
            .flat_map(|(tokens, log, event)| {
                event
                    .token_amounts
                    .iter()
                    .zip(tokens)
                    .map(move |(token_amount, token_id)| BalanceDelta {
                        ord: log.log.ordinal,
                        tx: Some(tx_from_log(&log)),
                        token: token_id.into(),
                        delta: token_amount.to_signed_bytes_be(),
                        component_id: log.address().into(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    );

    deltas.extend(
        block
            .logs()
            .filter_map(|log| {
                let event = abi::pool::events::RemoveLiquidity::match_and_decode(log)?;
                Some((log, event))
            })
            .filter(|(log, _)| {
                pools_store
                    .get_last(format!("pool:{0}", hex::encode(&log.address())))
                    .is_none()
            })
            .flat_map(|(log, event)| {
                let tokens = tokens_store
                    .get_last(format!("pool:{}", hex::encode(log.address())))
                    .unwrap()
                    .split(":")
                    .map(|token| token.to_owned()) // Clone the tokens
                    .collect::<Vec<_>>();

                event
                    .token_amounts
                    .iter()
                    .zip(tokens)
                    .map(move |(token_amount, token_id)| {
                        let negative_token_amount: BigInt = token_amount * BigInt::from(-1);
                        BalanceDelta {
                            ord: log.log.ordinal,
                            tx: Some(tx_from_log(&log)),
                            token: token_id.into(),
                            delta: negative_token_amount.to_signed_bytes_be(),
                            component_id: log.address().into(),
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    );
    deltas
}

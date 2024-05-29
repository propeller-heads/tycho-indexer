use substreams::store::{StoreGet, StoreGetString};
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

fn get_pool_tokens(pool_address: &Vec<u8>, tokens_store: &StoreGetString) -> Option<Vec<String>> {
    let pool_key = format!("pool:{}", hex::encode(&pool_address));
    Some(
        tokens_store
            .get_last(pool_key)?
            .split(":")
            .map(|token| token.to_owned())
            .collect::<Vec<_>>(),
    )
}

/// TODO rewrite
pub fn emit_deltas(log: LogView, tokens_store: &StoreGetString) -> Option<BalanceDelta> {
    let transfer = abi::erc20::events::Transfer::match_and_decode(log)?;

    let (component_id, pool_tokens, is_incoming) =
        if let Some(pool_tokens) = get_pool_tokens(&transfer.to, tokens_store) {
            (hex::encode(&transfer.to), pool_tokens, true)
        } else if let Some(pool_tokens) = get_pool_tokens(&transfer.from, tokens_store) {
            (hex::encode(&transfer.from), pool_tokens, false)
        } else {
            return None;
        };

    let token_id = hex::encode(log.address());
    if pool_tokens.contains(&token_id) {
        let delta = if is_incoming { transfer.value } else { transfer.value * -1 };
        Some(BalanceDelta {
            ord: log.log.ordinal,
            tx: Some(tx_from_log(&log)),
            token: hex::decode(token_id).unwrap(),
            delta: delta.to_signed_bytes_be(),
            component_id: component_id.into(),
        })
    } else {
        substreams::log::info!("Token {:?} not in pool: {:?}", token_id, &component_id);
        None
    }
}

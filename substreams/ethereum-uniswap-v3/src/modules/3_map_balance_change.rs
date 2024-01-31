use substreams_ethereum::pb::eth::v2::{self as eth};

#[substreams::handlers::map]
pub fn map_balance_change(block: eth::v2::Block) -> Result<tycho::BalanceDeltas, anyhow::Error> {
    // Ok(tycho::BalanceDeltas {
    //     balance_deltas: block
    //         .events::<abi::vault::events::PoolBalanceChanged>(&[&VAULT_ADDRESS])
    //         .flat_map(|(event, log)| {
    //             event
    //                 .tokens
    //                 .iter()
    //                 .zip(event.deltas.iter())
    //                 .map(|(token, delta)| tycho::BalanceDelta {
    //                     ord: log.log.ordinal,
    //                     tx: Some(tycho::Transaction {
    //                         hash: log.receipt.transaction.hash.clone(),
    //                         from: log.receipt.transaction.from.clone(),
    //                         to: log.receipt.transaction.to.clone(),
    //                         index: Into::<u64>::into(log.receipt.transaction.index),
    //                     }),
    //                     token: token.clone(),
    //                     delta: delta.to_signed_bytes_be(),
    //                     component_id: event.pool_id.into(),
    //                 })
    //                 .collect::<Vec<_>>()
    //         })
    //         .collect::<Vec<_>>(),
    // })
}

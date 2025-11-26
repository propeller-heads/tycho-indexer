use crate::{
    abi::rocket_deposit_pool,
    constants::{ETH_ADDRESS, ROCKET_POOL_COMPONENT_ID},
};
use anyhow::Result;
use substreams_ethereum::{pb::eth, Event};
use tycho_substreams::models::{BalanceDelta, BlockBalanceDeltas};

/// Extracts ETH balance changes for rocket pool component
///
/// This function uses RocketDepositPool events to extract ETH balance changes. If a
/// deposit to the component is detected, it's balanced is increased and if a balance
/// from the component is withdrawn its balance is decreased.
#[substreams::handlers::map]
fn map_relative_component_balance(block: eth::v2::Block) -> Result<BlockBalanceDeltas> {
    let res = block
        .logs()
        .filter_map(|log| {
            let amount = if let Some(deposit) =
                rocket_deposit_pool::events::DepositReceived::match_and_decode(log)
            {
                deposit.amount
            } else if let Some(deposit) =
                rocket_deposit_pool::events::DepositAssigned::match_and_decode(log)
            {
                deposit.amount.neg()
            } else if let Some(deposit) =
                rocket_deposit_pool::events::DepositRecycled::match_and_decode(log)
            {
                deposit.amount
            } else if let Some(deposit) =
                rocket_deposit_pool::events::ExcessWithdrawn::match_and_decode(log)
            {
                deposit.amount.neg()
            } else {
                return None;
            };

            Some(BalanceDelta {
                ord: log.ordinal(),
                tx: Some(log.receipt.transaction.into()),
                token: ETH_ADDRESS.to_vec(),
                delta: amount.to_signed_bytes_be(),
                component_id: ROCKET_POOL_COMPONENT_ID.into(),
            })
        })
        .collect::<Vec<_>>();

    Ok(BlockBalanceDeltas { balance_deltas: res })
}

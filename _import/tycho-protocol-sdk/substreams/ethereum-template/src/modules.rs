use std::collections::HashMap;
use substreams_ethereum::pb::eth;
use tycho_substreams::prelude::*;

#[substreams::handlers::map]
fn map_protocol_changes(
    block: eth::v2::Block,
) -> Result<BlockContractChanges, substreams::errors::Error> {
    let mut transaction_contract_changes = Vec::<TransactionContractChanges>::new();
    // TODO: protocol specific logic goes here
    Ok(BlockContractChanges { block: Some((&block).into()), changes: transaction_contract_changes })
}

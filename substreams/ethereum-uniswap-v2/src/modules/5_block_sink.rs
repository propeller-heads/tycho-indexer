use substreams_ethereum::pb::eth::v2::{self as eth};

use crate::pb::tycho::evm::v1::{
    Block, BlockEntityChanges, SameTypeTransactionContractChanges, TransactionEntityChanges,
};

#[substreams::handlers::map]
pub fn block_sink(
    block: eth::Block,
    balance_changes: SameTypeTransactionContractChanges,
    new_protocol_components: SameTypeTransactionContractChanges,
) -> Result<BlockEntityChanges, substreams::errors::Error> {
    let tycho_block: Block = block.into();

    let tx_entity_changes = balance_changes
        .changes
        .into_iter()
        .chain(
            new_protocol_components
                .changes
                .into_iter(),
        )
        .collect::<Vec<TransactionEntityChanges>>();

    let block_entity_changes =
        BlockEntityChanges { block: Option::from(tycho_block), changes: tx_entity_changes };

    Ok(block_entity_changes)
}

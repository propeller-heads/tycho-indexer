use crate::pool_factories::{self};
use anyhow::Result;
use substreams_ethereum::pb::eth;
use tycho_substreams::prelude::*;

/// Create all relevant protocol components
///
/// This method instantiates hardcoded ProtocolComponents for the first block,
///  with a unique ids as well as all necessary metadata for routing and encoding.
#[substreams::handlers::map]
fn map_protocol_components(block: eth::v2::Block) -> Result<BlockTransactionProtocolComponents> {
    // TODO: add flag to emit only once
    Ok(BlockTransactionProtocolComponents {
        tx_components: block
            .transactions()
            .filter_map(|tx| {
                let components = tx
                    .logs_with_calls()
                    .filter_map(|(log, call)| {
                        pool_factories::maybe_create_component(call.call, log, tx)
                    })
                    .collect::<Vec<_>>();

                if !components.is_empty() {
                    Some(TransactionProtocolComponents { tx: Some(tx.into()), components })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>(),
    })
}


use substreams_ethereum::pb::eth;

use pb::tycho::evm::v1::{self as tycho};

mod pb;

#[substreams::handlers::map]
fn map_changes(
    block: eth::v2::Block,
) -> Result<tycho::BlockContractChanges, substreams::errors::Error> {
    todo!("Not implemented")
}
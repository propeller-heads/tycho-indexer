use substreams_ethereum::pb::eth;
mod modules;

#[substreams::handlers::map]
fn map_changes(
    block: eth::v2::Block,
) -> Result<tycho::BlockContractChanges, substreams::errors::Error> {
    todo!("Not implemented")
}

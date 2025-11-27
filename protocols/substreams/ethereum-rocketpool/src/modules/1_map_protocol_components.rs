use crate::constants::{
    ETH_ADDRESS, RETH_ADDRESS, ROCKET_DEPOSIT_POOL_ADDRESS_V1_0, ROCKET_POOL_COMPONENT_ID,
};
use anyhow::Result;
use substreams_ethereum::pb::eth;
use tycho_substreams::models::{
    BlockTransactionProtocolComponents, ImplementationType, ProtocolComponent,
    TransactionProtocolComponents,
};

/// Find and create all relevant protocol components
///
/// This method maps over blocks and instantiates ProtocolComponents with a unique ids
/// as well as all necessary metadata for routing and encoding.
#[substreams::handlers::map]
fn map_protocol_components(
    params: String,
    block: eth::v2::Block,
) -> Result<BlockTransactionProtocolComponents> {
    if block.number != params.parse::<u64>()? {
        return Ok(BlockTransactionProtocolComponents { tx_components: vec![] });
    }

    let tx = block
        .transactions()
        .find(|tx| {
            tx.calls
                .iter()
                .flat_map(|call| &call.account_creations)
                .any(|account| account.account == ROCKET_DEPOSIT_POOL_ADDRESS_V1_0)
        })
        .ok_or(anyhow::anyhow!("No transaction found for Rocket Deposit Pool"))?;

    let component = ProtocolComponent::new(ROCKET_POOL_COMPONENT_ID)
        .with_tokens(&[RETH_ADDRESS.to_vec(), ETH_ADDRESS.to_vec()])
        .as_swap_type("rocketpool_pool", ImplementationType::Custom);

    Ok(BlockTransactionProtocolComponents {
        tx_components: vec![TransactionProtocolComponents {
            tx: Some(tx.into()),
            components: vec![component],
        }],
    })
}

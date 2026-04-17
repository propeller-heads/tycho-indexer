use anyhow::{anyhow, Result};
use substreams_ethereum::pb::eth;
use tycho_substreams::{
    models::{ImplementationType, ProtocolComponent},
    prelude::{BlockTransactionProtocolComponents, TransactionProtocolComponents},
};

use crate::{
    constants::{
        ETH_ADDRESS, STETH_ADDRESS, STETH_COMPONENT_ID, WSTETH_ADDRESS, WSTETH_COMPONENT_ID,
    },
    state::InitialState,
};

#[substreams::handlers::map]
pub fn map_protocol_components(
    params: String,
    block: eth::v2::Block,
) -> Result<BlockTransactionProtocolComponents> {
    let initial_state = InitialState::parse(&params)?;

    if block.number != initial_state.start_block {
        return Ok(BlockTransactionProtocolComponents { tx_components: vec![] });
    }

    let tx = block
        .transactions()
        .next()
        .ok_or_else(|| anyhow!("Activation block has no transactions"))?;

    Ok(BlockTransactionProtocolComponents {
        tx_components: vec![TransactionProtocolComponents {
            tx: Some(tx.into()),
            components: create_components(),
        }],
    })
}

fn create_components() -> Vec<ProtocolComponent> {
    vec![
        ProtocolComponent::new(STETH_COMPONENT_ID)
            .with_tokens(&[STETH_ADDRESS, ETH_ADDRESS])
            .as_swap_type("stETH", ImplementationType::Custom),
        ProtocolComponent::new(WSTETH_COMPONENT_ID)
            .with_tokens(&[STETH_ADDRESS, WSTETH_ADDRESS])
            .as_swap_type("wstETH", ImplementationType::Custom),
    ]
}

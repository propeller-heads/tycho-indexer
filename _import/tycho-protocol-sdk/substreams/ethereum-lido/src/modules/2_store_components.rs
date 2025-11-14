use substreams::prelude::*;
use tycho_substreams::prelude::*;

/// Stores all protocol components in a store.
///
/// Stores information about components in a key value store.
#[substreams::handlers::store]
fn store_protocol_components(
    map_protocol_components: BlockTransactionProtocolComponents,
    store: StoreSetRaw,
) {
    map_protocol_components
        .tx_components
        .into_iter()
        .for_each(|tx_pc| {
            tx_pc
                .components
                .into_iter()
                .for_each(|pc| {
                    let key = pc.id.clone();
                    // TODO: proper error handling
                    let val = serde_sibor::to_bytes(&pc.tokens).unwrap();
                    store.set(0, key, &val);
                })
        });
}

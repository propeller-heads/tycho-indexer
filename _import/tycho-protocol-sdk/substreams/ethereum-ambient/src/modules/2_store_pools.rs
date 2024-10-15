use substreams::store::{StoreNew, StoreSet, StoreSetProto};
use tycho_substreams::models::{BlockPoolChanges, ProtocolComponent};

#[substreams::handlers::store]
pub fn store_pools(changes: BlockPoolChanges, component_store: StoreSetProto<ProtocolComponent>) {
    for component in changes.protocol_components {
        component_store.set(0, component.id.clone(), &component);
    }
}

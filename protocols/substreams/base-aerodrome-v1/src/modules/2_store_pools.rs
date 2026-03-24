use substreams::store::{StoreNew, StoreSetIfNotExists, StoreSetIfNotExistsProto};

use crate::store_key::StoreKey;
use tycho_substreams::prelude::*;

#[substreams::handlers::store]
pub fn store_pools(
    pools_created: BlockChanges,
    store: StoreSetIfNotExistsProto<ProtocolComponent>,
) {
    for change in pools_created.changes {
        for new_protocol_component in change.component_changes {
            store.set_if_not_exists(
                0,
                StoreKey::Pool.get_unique_pool_key(&new_protocol_component.id),
                &new_protocol_component,
            );
        }
    }
}

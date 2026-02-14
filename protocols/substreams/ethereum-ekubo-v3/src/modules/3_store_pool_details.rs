use alloy_primitives::aliases::B32;
use ekubo_sdk::chain::evm::EvmPoolTypeConfig;
use substreams::store::{
    StoreGet as _, StoreGetProto, StoreNew, StoreSetIfNotExists, StoreSetIfNotExistsProto,
};
use tycho_substreams::models::BlockChanges;

use crate::pb::ekubo::PoolDetails;

pub fn get_pool_details(store: &StoreGetProto<PoolDetails>, component_id: &str) -> PoolDetails {
    store
        .get_at(0, component_id)
        .expect("pool id should exist in store")
}

// Since only the PoolInitialized event contains the complete pool key we need to store some info
// required when processing other events
#[substreams::handlers::store]
fn store_pool_details(changes: BlockChanges, store: StoreSetIfNotExistsProto<PoolDetails>) {
    changes
        .changes
        .into_iter()
        .flat_map(|c| c.component_changes)
        .for_each(|component| {
            let attrs = component.static_att;
            let pool_type_config = EvmPoolTypeConfig::try_from(
                B32::try_from(attrs[3].value.as_slice())
                    .expect("pool type config to be 4 bytes long"),
            )
            .expect("pool type config to be valid");

            store.set_if_not_exists(
                0,
                component.id,
                &PoolDetails {
                    token0: attrs[0].value.clone(),
                    token1: attrs[1].value.clone(),
                    is_stableswap: matches!(
                        pool_type_config,
                        EvmPoolTypeConfig::FullRange(_) | EvmPoolTypeConfig::Stableswap(_)
                    ),
                },
            );
        });
}

use substreams::store::{Appender, StoreAppend};
use tycho_substreams::prelude::BlockChanges;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};

#[substreams::handlers::store]
pub fn store_token_to_pools(pools_created: BlockChanges, store: StoreAppend<String>) {
    for change in pools_created.changes {
        for component_change in &change.component_changes {
            if component_change.tokens.len() < 2 {
                continue;
            }

            let pool_address = component_change
                .id
                .trim_start_matches("0x");
            let token0 = hex::encode(&component_change.tokens[0]);
            let token1 = hex::encode(&component_change.tokens[1]);

            if let Ok(pool_address_bytes) = hex::decode(pool_address) {
                let pool_address_b64 = STANDARD_NO_PAD.encode(&pool_address_bytes);
                store.append(0, token0, pool_address_b64.clone());
                store.append(0, token1, pool_address_b64);
            }
        }
    }
}

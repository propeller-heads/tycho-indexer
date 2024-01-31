use substreams_ethereum::pb::eth::v2::StorageChange;
use substreams_helper::hex::Hexable;

use crate::{
    abi::pool::events::Burn,
    pb::tycho::evm::{uniswap::v3::Pool, v1::Attribute},
    storage::uniswap_v3_pool::UniswapPoolStorage,
};

use super::{BalanceDelta, EventHandlers};

impl EventHandlers for Burn {
    fn get_changed_attributes(
        &self,
        storage_changes: &[StorageChange],
        pool: &Pool,
    ) -> Vec<Attribute> {
        let storage_vec = storage_changes.to_vec();

        let pool_storage = UniswapPoolStorage::new(&storage_vec, &pool.address);

        let mut changed_attributes = pool_storage.get_changed_attributes();

        let changed_ticks = pool_storage.get_ticks_changes(&self.tick_upper, &self.tick_lower);

        changed_attributes.extend(changed_ticks);

        changed_attributes
    }

    fn get_balance_delta(&self, pool: &Pool, ordinal: usize) -> Vec<BalanceDelta> {
        let changed_balance = vec![
            BalanceDelta {
                token: pool.token0.clone(),
                delta: self.amount0.clone(),
                component_id: pool.address.clone().to_hex(),
                ordinal,
            },
            BalanceDelta {
                token: pool.token1.clone(),
                delta: self.amount1.clone(),
                component_id: pool.address.clone().to_hex(),
                ordinal,
            },
        ];
        changed_balance
    }
}

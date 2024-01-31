use substreams_ethereum::pb::eth::v2::StorageChange;
use substreams_helper::hex::Hexable;

use crate::{
    abi::pool::events::CollectProtocol,
    pb::tycho::evm::{uniswap::v3::Pool, v1::Attribute},
    storage::uniswap_v3_pool::UniswapPoolStorage,
};

use super::{BalanceDelta, EventHandlers};

impl EventHandlers for CollectProtocol {
    fn get_changed_attributes(
        &self,
        storage_changes: &[StorageChange],
        pool: &Pool,
    ) -> Vec<Attribute> {
        let storage_vec = storage_changes.to_vec();

        let pool_storage = UniswapPoolStorage::new(&storage_vec, &pool.address);

        pool_storage.get_changed_attributes()
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

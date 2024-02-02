use substreams_ethereum::pb::eth::v2::StorageChange;

use crate::{
    abi::pool::events::Flash,
    pb::tycho::evm::{uniswap::v3::Pool, v1::Attribute},
    storage::uniswap_v3_pool::UniswapPoolStorage,
};

use super::{BalanceDelta, EventHandlers};

impl EventHandlers for Flash {
    fn get_changed_attributes(
        &self,
        storage_changes: &[StorageChange],
        pool: &Pool,
    ) -> Vec<Attribute> {
        let storage_vec = storage_changes.to_vec();

        let pool_storage = UniswapPoolStorage::new(&storage_vec, &pool.address);

        pool_storage.get_changed_attributes()
    }

    fn get_balance_delta(&self, pool: &Pool, ordinal: u64) -> Vec<BalanceDelta> {
        let changed_balance = vec![
            BalanceDelta {
                token_address: pool.token0.clone(),
                amount: self.paid0.clone().to_bytes_le().1,
                sign: true,
                pool_address: pool.address.clone(),
                ordinal,
            },
            BalanceDelta {
                token_address: pool.token1.clone(),
                amount: self.paid1.clone().to_bytes_le().1,
                sign: true,
                pool_address: pool.address.clone(),
                ordinal,
            },
        ];
        changed_balance
    }
}

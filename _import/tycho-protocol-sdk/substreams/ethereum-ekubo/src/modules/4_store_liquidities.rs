use substreams::{
    scalar::BigInt,
    store::{StoreSetSum, StoreSetSumBigInt},
};
use substreams_helper::hex::Hexable;

use crate::pb::ekubo::{LiquidityChangeType, LiquidityChanges};

#[substreams::handlers::store]
pub fn store_liquidities(liquidity_changes: LiquidityChanges, store: StoreSetSumBigInt) {
    liquidity_changes
        .changes
        .into_iter()
        .for_each(|changes| match changes.change_type() {
            LiquidityChangeType::Delta => {
                store.sum(
                    changes.ordinal,
                    format!("pool:{0}", changes.pool_id.to_hex()),
                    BigInt::from_signed_bytes_be(&changes.value),
                );
            }
            LiquidityChangeType::Absolute => {
                store.set(
                    changes.ordinal,
                    format!("pool:{0}", changes.pool_id.to_hex()),
                    BigInt::from_signed_bytes_be(&changes.value),
                );
            }
        });
}

use substreams::{prelude::StoreAddBigInt, store::StoreNew};
use tycho_substreams::models::BlockBalanceDeltas;

/// Aggregates relative eth balance values into absolute values
#[substreams::handlers::store]
pub fn store_balance(deltas: BlockBalanceDeltas, store: StoreAddBigInt) {
    tycho_substreams::balances::store_balance_changes(deltas, store);
}

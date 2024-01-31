#[substreams::handlers::store]
pub fn store_pools_balances(deltas: tycho::BalanceDeltas, store: StoreAddBigInt) {
    deltas
        .balance_deltas
        .iter()
        .for_each(|delta| {
            store.add(
                delta.ord,
                format!(
                    "pool:{0}:token:{1}",
                    hex::encode(&delta.component_id),
                    hex::encode(&delta.token)
                ),
                BigInt::from_signed_bytes_be(&delta.delta),
            );
        });
}

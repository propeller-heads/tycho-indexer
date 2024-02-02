use crate::pb::tycho::evm::uniswap::v3::BalanceDeltas;
use num_bigint::Sign;
use substreams::{
    scalar::BigInt,
    store::{StoreAdd, StoreAddBigInt, StoreNew},
};

#[substreams::handlers::store]
pub fn store_pools_balances(balances_deltas: BalanceDeltas, store: StoreAddBigInt) {
    balances_deltas
        .deltas
        .iter()
        .for_each(|delta| {
            store.add(
                delta.ordinal,
                format!(
                    "pool:{0}:token:{1}",
                    hex::encode(&delta.pool_address),
                    hex::encode(&delta.token_address)
                ),
                BigInt::from_bytes_le(
                    if delta.sign { Sign::Plus } else { Sign::Minus },
                    delta.amount.as_slice(),
                ),
            );
        });
}

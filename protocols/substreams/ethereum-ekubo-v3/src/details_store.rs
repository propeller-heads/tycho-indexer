use substreams::store::{StoreGet as _, StoreGetProto, StoreSetSum};

use crate::pb::ekubo::{ChangeType, PoolDetails};

pub fn store_method_from_change_type<T, S: StoreSetSum<T>>(
    change_type: ChangeType,
) -> fn(&S, u64, String, T) {
    match change_type {
        ChangeType::Delta => StoreSetSum::sum,
        ChangeType::Absolute => StoreSetSum::set,
    }
}

pub fn get_pool_details(store: &StoreGetProto<PoolDetails>, component_id: &str) -> PoolDetails {
    let Some(pool_details) = store.get_last(component_id) else {
        panic!("expect pool details for {component_id} to exist")
    };

    pool_details
}

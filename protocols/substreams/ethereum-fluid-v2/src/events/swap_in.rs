use crate::{
    abi::d3_swap_module::events::LogSwapIn,
    events::EventTrait,
    pb::tycho::evm::fluid_v2::Pool,
    storage::{dex_v2, storage_view::StorageChangesView},
};
use substreams::store::{StoreGet, StoreGetProto};
use substreams_ethereum::pb::eth::v2::StorageChange;
use substreams_helper::hex::Hexable;
use tycho_substreams::prelude::*;

impl EventTrait for LogSwapIn {
    fn get_changed_attributes(
        &self,
        storage_changes: &[StorageChange],
        dex_v2_address: &[u8],
    ) -> (String, Vec<Attribute>) {
        let storage_view = StorageChangesView::new_filtered(dex_v2_address, storage_changes);
        let dex_type = self.dex_type.to_u64();
        let mut attrs = Vec::new();
        attrs.extend(dex_v2::dex_variables_attributes(&storage_view, &self.dex_id, dex_type));
        attrs.extend(dex_v2::token_reserves_attributes(&storage_view, &self.dex_id, dex_type));
        (self.dex_id.to_hex(), attrs)
    }

    fn get_balance_delta(
        &self,
        tx: &Transaction,
        ordinal: u64,
        pools_store: &StoreGetProto<Pool>,
    ) -> Vec<BalanceDelta> {
        let pool_key = format!("Pool:{}", hex::encode(self.dex_id).to_hex());
        let pool = match pools_store.get_last(pool_key) {
            Some(pool) => pool,
            None => return vec![],
        };
        let (token_in, token_out) =
            if self.is0to1 { (pool.token0, pool.token1) } else { (pool.token1, pool.token0) };
        vec![
            BalanceDelta {
                ord: ordinal,
                tx: Some(tx.clone()),
                token: token_in.clone(),
                delta: self
                    .amount_in
                    .clone()
                    .to_signed_bytes_be(),
                component_id: self
                    .dex_id
                    .clone()
                    .to_hex()
                    .as_bytes()
                    .to_vec(),
            },
            BalanceDelta {
                ord: ordinal,
                tx: Some(tx.clone()),
                token: token_out.clone(),
                delta: self
                    .amount_out
                    .neg()
                    .clone()
                    .to_signed_bytes_be(),
                component_id: self
                    .dex_id
                    .clone()
                    .to_hex()
                    .as_bytes()
                    .to_vec(),
            },
        ]
    }
}

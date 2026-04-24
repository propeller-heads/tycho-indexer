use crate::{
    abi::d3_user_module::events::LogWithdraw,
    events::EventTrait,
    pb::tycho::evm::fluid_v2::Pool,
    storage::{dex_v2, storage_view::StorageChangesView},
};
use substreams::store::{StoreGet, StoreGetProto};
use substreams_ethereum::pb::eth::v2::StorageChange;
use substreams_helper::hex::Hexable;
use tycho_substreams::prelude::*;

impl EventTrait for LogWithdraw {
    fn get_changed_attributes(
        &self,
        storage_changes: &[StorageChange],
        dex_v2_address: &[u8],
    ) -> (String, Vec<Attribute>) {
        let storage_view = StorageChangesView::new_filtered(dex_v2_address, storage_changes);
        let dex_type = self.dex_type.to_u64();
        let mut attrs = Vec::new();
        attrs.extend(dex_v2::tick_data_attributes(
            &storage_view,
            &self.dex_id,
            dex_type,
            vec![&self.tick_lower, &self.tick_upper],
        ));
        attrs.extend(dex_v2::dex_variables2_attributes(&storage_view, &self.dex_id, dex_type));
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

        vec![
            BalanceDelta {
                ord: ordinal,
                tx: Some(tx.clone()),
                token: pool.token0.clone(),
                delta: self
                    .amount0
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
            BalanceDelta {
                ord: ordinal,
                tx: Some(tx.clone()),
                token: pool.token1.clone(),
                delta: self
                    .amount1
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

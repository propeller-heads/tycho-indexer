use anyhow::Result;
use substreams::{
    prelude::StoreSetBigInt,
    scalar::BigInt,
    store::{StoreNew, StoreSet},
};
use substreams_ethereum::pb::eth;

use crate::{
    constants::{
        BUFFERED_ETHER_AND_DEPOSITED_VALIDATORS_POSITION, BUFFERED_ETHER_ATTR,
        CL_BALANCE_AND_CL_VALIDATORS_POSITION, CL_BALANCE_ATTR, CL_VALIDATORS_ATTR,
        DEPOSITED_VALIDATORS_ATTR, EXTERNAL_SHARES_ATTR, STAKING_STATE_ATTR,
        STAKING_STATE_POSITION, STETH_ADDRESS, STETH_COMPONENT_ID,
        TOTAL_AND_EXTERNAL_SHARES_POSITION, TOTAL_SHARES_ATTR,
    },
    state::{InitialState, LidoProtocolState},
    utils::decode_packed_uint128_pair,
};

#[substreams::handlers::store]
pub fn store_protocol_state(params: String, block: eth::v2::Block, store: StoreSetBigInt) {
    store_protocol_state_inner(&params, &block, &store).expect("Failed to store Lido V3 state");
}

fn store_protocol_state_inner(
    params: &str,
    block: &eth::v2::Block,
    store: &StoreSetBigInt,
) -> Result<()> {
    let initial_state = InitialState::parse(params)?;

    if block.number == initial_state.start_block {
        let initial_state = LidoProtocolState::from_initial(&initial_state)?;
        set_attr(0, TOTAL_SHARES_ATTR, &initial_state.total_shares, store);
        set_attr(0, EXTERNAL_SHARES_ATTR, &initial_state.external_shares, store);
        set_attr(0, BUFFERED_ETHER_ATTR, &initial_state.buffered_ether, store);
        set_attr(0, DEPOSITED_VALIDATORS_ATTR, &initial_state.deposited_validators, store);
        set_attr(0, CL_BALANCE_ATTR, &initial_state.cl_balance, store);
        set_attr(0, CL_VALIDATORS_ATTR, &initial_state.cl_validators, store);
        set_attr(0, STAKING_STATE_ATTR, &initial_state.staking_state, store);
    }

    for tx in block.transactions() {
        for call in tx
            .calls
            .iter()
            .filter(|call| !call.state_reverted)
        {
            for storage_change in call
                .storage_changes
                .iter()
                .filter(|change| change.address == STETH_ADDRESS)
            {
                if storage_change.key == TOTAL_AND_EXTERNAL_SHARES_POSITION {
                    let (total_shares, external_shares) =
                        decode_packed_uint128_pair(&storage_change.new_value);
                    set_attr(call.begin_ordinal, TOTAL_SHARES_ATTR, &total_shares, store);
                    set_attr(call.begin_ordinal, EXTERNAL_SHARES_ATTR, &external_shares, store);
                } else if storage_change.key == BUFFERED_ETHER_AND_DEPOSITED_VALIDATORS_POSITION {
                    let (buffered_ether, deposited_validators) =
                        decode_packed_uint128_pair(&storage_change.new_value);
                    set_attr(call.begin_ordinal, BUFFERED_ETHER_ATTR, &buffered_ether, store);
                    set_attr(
                        call.begin_ordinal,
                        DEPOSITED_VALIDATORS_ATTR,
                        &deposited_validators,
                        store,
                    );
                } else if storage_change.key == CL_BALANCE_AND_CL_VALIDATORS_POSITION {
                    let (cl_balance, cl_validators) =
                        decode_packed_uint128_pair(&storage_change.new_value);
                    set_attr(call.begin_ordinal, CL_BALANCE_ATTR, &cl_balance, store);
                    set_attr(call.begin_ordinal, CL_VALIDATORS_ATTR, &cl_validators, store);
                } else if storage_change.key == STAKING_STATE_POSITION {
                    set_attr(
                        call.begin_ordinal,
                        STAKING_STATE_ATTR,
                        &BigInt::from_unsigned_bytes_be(&storage_change.new_value),
                        store,
                    );
                }
            }
        }
    }

    Ok(())
}

fn set_attr(ordinal: u64, attr: &str, value: &BigInt, store: &StoreSetBigInt) {
    store.set(ordinal, format!("{STETH_COMPONENT_ID}:{attr}"), value);
}

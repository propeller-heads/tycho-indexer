use substreams_ethereum::pb::eth::{self};

use crate::{
    contracts::{
        hotproxy::{
            decode_direct_swap_hotproxy_call, AMBIENT_HOTPROXY_CONTRACT, USER_CMD_HOTPROXY_FN_SIG,
        },
        knockout::{decode_knockout_call, AMBIENT_KNOCKOUT_CONTRACT, USER_CMD_KNOCKOUT_FN_SIG},
        main::{
            decode_direct_swap_call, decode_pool_init, AMBIENT_CONTRACT, SWAP_FN_SIG,
            USER_CMD_FN_SIG,
        },
        micropaths::{
            decode_burn_ambient_call, decode_burn_range_call, decode_mint_ambient_call,
            decode_mint_range_call, decode_sweep_swap_call, AMBIENT_MICROPATHS_CONTRACT,
            BURN_AMBIENT_FN_SIG, BURN_RANGE_FN_SIG, MINT_AMBIENT_FN_SIG, MINT_RANGE_FN_SIG,
            SWEEP_SWAP_FN_SIG,
        },
        warmpath::{
            decode_warm_path_user_cmd_call, AMBIENT_WARMPATH_CONTRACT, USER_CMD_WARMPATH_FN_SIG,
        },
    },
    utils::from_u256_to_vec,
};
use tycho_substreams::{
    models::{AmbientBalanceDelta, BlockPoolChanges},
    prelude::Transaction,
};

#[substreams::handlers::map]
fn map_pool_changes(block: eth::v2::Block) -> Result<BlockPoolChanges, substreams::errors::Error> {
    let mut protocol_components = Vec::new();
    let mut balance_deltas = Vec::new();
    for block_tx in block.transactions() {
        let tx = Transaction {
            hash: block_tx.hash.clone(),
            from: block_tx.from.clone(),
            to: block_tx.to.clone(),
            index: block_tx.index as u64,
        };
        // extract storage changes
        let mut storage_changes = block_tx
            .calls
            .iter()
            .filter(|call| !call.state_reverted)
            .flat_map(|call| {
                call.storage_changes
                    .iter()
                    .filter(|c| c.address == AMBIENT_CONTRACT)
            })
            .collect::<Vec<_>>();
        storage_changes.sort_unstable_by_key(|change| change.ordinal);

        let block_calls = block_tx
            .calls
            .iter()
            .filter(|call| !call.state_reverted)
            .collect::<Vec<_>>();

        for call in block_calls {
            if call.input.len() < 4 {
                continue;
            }
            let selector: [u8; 4] = call.input[0..4].try_into().unwrap();
            let address: [u8; 20] = call.address.clone().try_into().unwrap();

            if call.address == AMBIENT_CONTRACT && selector == USER_CMD_FN_SIG {
                // Extract pool creations
                if let Some(protocol_component) = decode_pool_init(call, tx.clone())? {
                    protocol_components.push(protocol_component);
                }
            }

            // Extract TVL changes
            let result = match (address, selector) {
                (AMBIENT_CONTRACT, SWAP_FN_SIG) => Some(decode_direct_swap_call(call)?),
                (AMBIENT_HOTPROXY_CONTRACT, USER_CMD_HOTPROXY_FN_SIG) => {
                    Some(decode_direct_swap_hotproxy_call(call)?)
                }
                (AMBIENT_MICROPATHS_CONTRACT, SWEEP_SWAP_FN_SIG) => {
                    Some(decode_sweep_swap_call(call)?)
                }
                (AMBIENT_WARMPATH_CONTRACT, USER_CMD_WARMPATH_FN_SIG) => {
                    decode_warm_path_user_cmd_call(call)?
                }
                (AMBIENT_MICROPATHS_CONTRACT, MINT_RANGE_FN_SIG) => {
                    Some(decode_mint_range_call(call)?)
                }
                (AMBIENT_MICROPATHS_CONTRACT, MINT_AMBIENT_FN_SIG) => {
                    Some(decode_mint_ambient_call(call)?)
                }
                (AMBIENT_MICROPATHS_CONTRACT, BURN_RANGE_FN_SIG) => {
                    Some(decode_burn_range_call(call)?)
                }
                (AMBIENT_MICROPATHS_CONTRACT, BURN_AMBIENT_FN_SIG) => {
                    Some(decode_burn_ambient_call(call)?)
                }
                (AMBIENT_KNOCKOUT_CONTRACT, USER_CMD_KNOCKOUT_FN_SIG) => {
                    Some(decode_knockout_call(call)?)
                }
                _ => None,
            };
            let (pool_hash, base_flow, quote_flow) = match result {
                Some((pool_hash, base_flow, quote_flow)) => (pool_hash, base_flow, quote_flow),
                None => continue,
            };
            let base_balance_delta = AmbientBalanceDelta {
                pool_hash: Vec::from(pool_hash),
                token_type: "base".to_string(),
                token_delta: from_u256_to_vec(base_flow),
                ordinal: call.index as u64,
                tx: Some(tx.clone()),
            };
            let quote_balance_delta = AmbientBalanceDelta {
                pool_hash: Vec::from(pool_hash),
                token_type: "quote".to_string(),
                token_delta: from_u256_to_vec(quote_flow),
                ordinal: call.index as u64,
                tx: Some(tx.clone()),
            };
            balance_deltas.extend([base_balance_delta.clone(), quote_balance_delta.clone()]);
        }
    }
    balance_deltas.sort_by_key(|delta| (delta.ordinal, delta.token_type.clone()));
    let pool_changes = BlockPoolChanges { protocol_components, balance_deltas };
    Ok(pool_changes)
}

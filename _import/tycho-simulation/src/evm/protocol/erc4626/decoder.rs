use std::{collections::HashMap, str::FromStr};

use alloy::primitives::{Address, U256};
use tycho_client::feed::{synchronizer::ComponentWithState, BlockHeader};
use tycho_common::{models::token::Token, Bytes};

use super::state::ERC4626State;
use crate::{
    evm::{
        engine_db::{create_engine, SHARED_TYCHO_DB},
        protocol::erc4626::vm,
    },
    protocol::{
        errors::InvalidSnapshotError,
        models::{DecoderContext, TryFromWithBlock},
    },
};

impl TryFromWithBlock<ComponentWithState, BlockHeader> for ERC4626State {
    type Error = InvalidSnapshotError;

    async fn try_from_with_header(
        snapshot: ComponentWithState,
        _block: BlockHeader,
        _account_balances: &HashMap<Bytes, HashMap<Bytes, Bytes>>,
        all_tokens: &HashMap<Bytes, Token>,
        decoder_context: &DecoderContext,
    ) -> Result<Self, Self::Error> {
        let pool_address = Bytes::from_str(snapshot.component.id.as_str()).map_err(|e| {
            InvalidSnapshotError::ValueError(format!(
                "Expected component id to be pool contract address: {e}"
            ))
        })?;
        let asset_address = snapshot
            .component
            .tokens
            .first()
            .ok_or_else(|| {
                InvalidSnapshotError::ValueError("Missing asset_address in component".to_string())
            })?;
        let asset_token = all_tokens
            .get(asset_address)
            .ok_or_else(|| {
                InvalidSnapshotError::ValueError(format!(
                    "Missing token0 in state: {asset_address}"
                ))
            })?;
        let share_address = snapshot
            .component
            .tokens
            .get(1)
            .ok_or_else(|| {
                InvalidSnapshotError::ValueError("Missing share_address in component".to_string())
            })?;
        let share_token = all_tokens
            .get(share_address)
            .ok_or_else(|| {
                InvalidSnapshotError::ValueError(format!(
                    "Missing share_address in state: {share_address}"
                ))
            })?;
        let component_balances = snapshot
            .state
            .balances
            .iter()
            .map(|(k, v)| (Address::from_slice(k), U256::from_be_slice(v)))
            .collect::<HashMap<_, _>>();
        let pool_asset_balance = component_balances
            .get(&Address::from_slice(asset_address.0.as_ref()))
            .ok_or_else(|| {
                InvalidSnapshotError::ValueError(format!(
                    "Missing asset_address in state: {asset_address}"
                ))
            })?;
        let engine = create_engine(
            SHARED_TYCHO_DB.clone(),
            decoder_context
                .vm_traces
                .unwrap_or_default(),
        )
        .expect("Failed to create engine");
        let erc4626_state = vm::decode_from_vm(
            &pool_address,
            asset_token,
            share_token,
            *pool_asset_balance,
            engine,
        )?;
        Ok(erc4626_state)
    }
}

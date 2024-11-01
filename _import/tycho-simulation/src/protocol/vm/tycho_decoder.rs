use std::time::{SystemTime, UNIX_EPOCH};

use ethers::types::{H160, H256, U256};

use tycho_client::feed::{synchronizer::ComponentWithState, Header};

use crate::{
    evm::{simulation_db::BlockHeader, tycho_db::PreCachedDB},
    protocol::{errors::InvalidSnapshotError, vm::state::VMPoolState, BytesConvertible},
};

#[allow(dead_code)]
trait TryFromWithBlock<T> {
    type Error;
    async fn try_from_with_block(value: T, block: Header) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

impl From<Header> for BlockHeader {
    fn from(header: Header) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        BlockHeader { number: header.number, hash: H256::from_bytes(&header.hash), timestamp: now }
    }
}

impl TryFromWithBlock<ComponentWithState> for VMPoolState<PreCachedDB> {
    type Error = InvalidSnapshotError;

    /// Decodes a `ComponentWithState` into a `VMPoolState`. Errors with a `InvalidSnapshotError`
    /// if ???
    async fn try_from_with_block(
        snapshot: ComponentWithState,
        block: Header,
    ) -> Result<Self, Self::Error> {
        let id = snapshot.component.id.clone();
        let tokens = snapshot
            .component
            .tokens
            .clone()
            .into_iter()
            .map(|t| H160::from_bytes(&t))
            .collect();
        let block = BlockHeader::from(block);
        let balances = snapshot
            .state
            .balances
            .iter()
            .map(|(k, v)| (H160::from_bytes(k), U256::from_bytes(v)))
            .collect();
        let balance_owner = snapshot
            .state
            .attributes
            .get("balance_owner")
            .map(H160::from_bytes);

        let manual_updates = snapshot
            .state
            .attributes
            .contains_key("manual_updates");

        use std::collections::HashMap;

        // Decode involved contracts
        let mut stateless_contracts = HashMap::new();
        let mut index = 0;

        loop {
            let address_key = format!("stateless_contract_addr_{}", index);
            if let Some(encoded_address_bytes) = snapshot
                .state
                .attributes
                .get(&address_key)
            {
                let encoded_address = hex::encode(encoded_address_bytes);
                // Stateless contracts address are UTF-8 encoded
                let address_hex = encoded_address
                    .strip_prefix("0x")
                    .unwrap_or(&encoded_address);

                let decoded = match hex::decode(address_hex) {
                    Ok(decoded_bytes) => match String::from_utf8(decoded_bytes) {
                        Ok(decoded_string) => decoded_string,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                };

                let code_key = format!("stateless_contract_code_{}", index);
                let code = snapshot
                    .state
                    .attributes
                    .get(&code_key)
                    .map(|value| value.to_vec());

                stateless_contracts.insert(decoded, code);
                index += 1;
            } else {
                break;
            }
        }

        let involved_contracts = snapshot
            .component
            .contract_ids
            .iter()
            .map(H160::from_bytes)
            .collect();

        let pool_state = VMPoolState::new(
            id,
            tokens,
            block,
            balances,
            balance_owner,
            "todo".to_string(), // TODO: map for adapter paths needed
            involved_contracts,
            stateless_contracts,
            manual_updates,
            false,
        )
        .await
        .map_err(InvalidSnapshotError::VMError)?;

        Ok(pool_state)
    }
}

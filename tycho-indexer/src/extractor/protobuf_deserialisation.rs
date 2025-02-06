#![allow(deprecated)]
use chrono::NaiveDateTime;
use std::collections::{hash_map::Entry, HashMap, HashSet};
use tracing::warn;

use tycho_core::{
    models::{
        blockchain::{Block, Transaction, TxWithChanges},
        contract::{AccountBalance, AccountChangesWithTx, AccountDelta},
        protocol::{
            ComponentBalance, ProtocolChangesWithTx, ProtocolComponent, ProtocolComponentStateDelta,
        },
        Address, Chain, ChangeType, ComponentId, ProtocolType, TxHash,
    },
    Bytes,
};

use crate::{
    extractor::{
        models::{BlockChanges, BlockContractChanges, BlockEntityChanges},
        u256_num::bytes_to_f64,
        ExtractionError,
    },
    pb::tycho::evm::v1 as substreams,
};

pub trait TryFromMessage {
    type Args<'a>;

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError>
    where
        Self: Sized;
}

impl TryFromMessage for AccountDelta {
    type Args<'a> = (substreams::ContractChange, Chain);

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, chain) = args;
        let change = msg.change().into();
        let update = AccountDelta::new(
            chain,
            msg.address.into(),
            msg.slots
                .into_iter()
                .map(|cs| (cs.slot.into(), Some(cs.value.into())))
                .collect(),
            if !msg.balance.is_empty() { Some(msg.balance.into()) } else { None },
            if !msg.code.is_empty() { Some(msg.code.into()) } else { None },
            change,
        );
        Ok(update)
    }
}

impl TryFromMessage for AccountBalance {
    type Args<'a> = (substreams::AccountBalanceChange, &'a Address, &'a Transaction);

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, addr, tx) = args;
        Ok(Self {
            token: msg.token.into(),
            balance: Bytes::from(msg.balance),
            modify_tx: tx.hash.clone(),
            account: addr.clone(),
        })
    }
}

impl TryFromMessage for Block {
    type Args<'a> = (substreams::Block, Chain);

    /// Parses block from tychos protobuf block message
    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, chain) = args;
        let ts_nano = match chain {
            // For blockchains with subsecond block times, like Arbitrum, timestamps aren't precise
            // enough to distinguish between two blocks accurately. To maintain accurate ordering,
            // we adjust timestamps by appending part of the current block number as microseconds.
            Chain::Arbitrum => (msg.number as u32 % 1000) * 1000,
            _ => 0,
        };

        Ok(Self {
            chain,
            number: msg.number,
            hash: msg.hash.into(),
            parent_hash: msg.parent_hash.into(),
            ts: NaiveDateTime::from_timestamp_opt(msg.ts as i64, ts_nano).ok_or_else(|| {
                ExtractionError::DecodeError(format!(
                    "Failed to convert timestamp {} to datetime!",
                    msg.ts
                ))
            })?,
        })
    }
}

impl TryFromMessage for Transaction {
    type Args<'a> = (substreams::Transaction, &'a TxHash);

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, block_hash) = args;

        let to = if !msg.to.is_empty() { Some(msg.to.into()) } else { None };

        Ok(Self {
            hash: msg.hash.into(),
            block_hash: block_hash.clone(),
            from: msg.from.into(),
            to,
            index: msg.index,
        })
    }
}

impl TryFromMessage for ComponentBalance {
    type Args<'a> = (substreams::BalanceChange, &'a Transaction);

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, tx) = args;
        let balance_float = bytes_to_f64(&msg.balance).unwrap_or(f64::NAN);
        Ok(Self {
            token: msg.token.into(),
            balance: Bytes::from(msg.balance),
            balance_float,
            modify_tx: tx.hash.clone(),
            component_id: String::from_utf8(msg.component_id)
                .map_err(|error| ExtractionError::DecodeError(error.to_string()))?,
        })
    }
}

impl TryFromMessage for ProtocolComponent {
    type Args<'a> = (
        substreams::ProtocolComponent,
        Chain,
        &'a str,
        &'a HashMap<String, ProtocolType>,
        TxHash,
        NaiveDateTime,
    );

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, chain, protocol_system, protocol_types, tx_hash, creation_ts) = args;
        let tokens: Vec<Bytes> = msg
            .tokens
            .clone()
            .into_iter()
            .map(Into::into)
            .collect();

        let contract_ids = msg
            .contracts
            .clone()
            .into_iter()
            .map(Into::into)
            .collect();

        let static_attributes = msg
            .static_att
            .clone()
            .into_iter()
            .map(|attribute| (attribute.name, Bytes::from(attribute.value)))
            .collect();

        let protocol_type = msg
            .protocol_type
            .clone()
            .ok_or(ExtractionError::DecodeError("Missing protocol type".to_owned()))?;

        if !protocol_types.contains_key(&protocol_type.name) {
            return Err(ExtractionError::DecodeError(format!(
                "Unknown protocol type name: {}",
                protocol_type.name
            )));
        }

        Ok(Self {
            id: msg.id.clone(),
            protocol_type_name: protocol_type.name,
            protocol_system: protocol_system.to_owned(),
            tokens,
            contract_addresses: contract_ids,
            static_attributes,
            chain,
            change: msg.change().into(),
            creation_tx: tx_hash,
            created_at: creation_ts,
        })
    }
}

impl From<substreams::ChangeType> for ChangeType {
    fn from(value: substreams::ChangeType) -> Self {
        match value {
            substreams::ChangeType::Unspecified => {
                panic!("Unkown enum member encountered: {:?}", value)
            }
            substreams::ChangeType::Update => ChangeType::Update,
            substreams::ChangeType::Creation => ChangeType::Creation,
            substreams::ChangeType::Deletion => ChangeType::Deletion,
        }
    }
}

impl TryFromMessage for ProtocolComponentStateDelta {
    type Args<'a> = substreams::EntityChanges;

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let msg = args;

        let (mut updates, mut deletions) = (HashMap::new(), HashSet::new());

        for attribute in msg.attributes.into_iter() {
            match attribute.change().into() {
                ChangeType::Update | ChangeType::Creation => {
                    updates.insert(attribute.name, Bytes::from(attribute.value));
                }
                ChangeType::Deletion => {
                    deletions.insert(attribute.name);
                }
            }
        }

        Ok(Self {
            component_id: msg.component_id,
            updated_attributes: updates,
            deleted_attributes: deletions,
        })
    }
}

impl TryFromMessage for ProtocolChangesWithTx {
    type Args<'a> = (
        substreams::TransactionEntityChanges,
        &'a Block,
        &'a str,
        &'a HashMap<String, ProtocolType>,
    );

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, block, protocol_system, protocol_types) = args;
        let tx = Transaction::try_from_message((
            msg.tx
                .expect("TransactionEntityChanges should have a transaction"),
            &block.hash.clone(),
        ))?;

        let mut new_protocol_components: HashMap<String, ProtocolComponent> = HashMap::new();
        let mut state_updates: HashMap<String, ProtocolComponentStateDelta> = HashMap::new();
        let mut component_balances: HashMap<String, HashMap<Bytes, ComponentBalance>> =
            HashMap::new();

        // First, parse the new protocol components
        for change in msg.component_changes.into_iter() {
            let component = ProtocolComponent::try_from_message((
                change.clone(),
                block.chain,
                protocol_system,
                protocol_types,
                tx.hash.clone(),
                block.ts,
            ))?;
            new_protocol_components.insert(change.id, component);
        }

        // Then, parse the state updates
        for state_msg in msg.entity_changes.into_iter() {
            let state = ProtocolComponentStateDelta::try_from_message(state_msg)?;
            // Check if a state update for the same component already exists
            // If it exists, overwrite the existing state update with the new one and log a warning
            match state_updates.entry(state.component_id.clone()) {
                Entry::Vacant(e) => {
                    e.insert(state);
                }
                Entry::Occupied(mut e) => {
                    warn!("Received two state updates for the same component. Overwriting state for component {}", e.key());
                    e.insert(state);
                }
            }
        }

        // Finally, parse the balance changes
        for balance_change in msg.balance_changes.into_iter() {
            let component_balance = ComponentBalance::try_from_message((balance_change, &tx))?;

            // Check if a balance change for the same token and component already exists
            // If it exists, overwrite the existing balance change with the new one and log a
            // warning
            let token_balances = component_balances
                .entry(component_balance.component_id.clone())
                .or_default();

            if let Some(existing_balance) =
                token_balances.insert(component_balance.token.clone(), component_balance)
            {
                warn!(
                    "Received two balance updates for the same component id: {} and token {}. Overwriting balance change",
                    existing_balance.component_id, existing_balance.token
                );
            }
        }

        Ok(Self {
            new_protocol_components,
            protocol_states: state_updates,
            balance_changes: component_balances,
            tx,
        })
    }
}

impl TryFromMessage for TxWithChanges {
    type Args<'a> =
        (substreams::TransactionChanges, &'a Block, &'a str, &'a HashMap<String, ProtocolType>);

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, block, protocol_system, protocol_types) = args;
        let tx = Transaction::try_from_message((
            msg.tx
                .expect("TransactionChanges should have a transaction"),
            &block.hash.clone(),
        ))?;

        let mut new_protocol_components: HashMap<ComponentId, ProtocolComponent> = HashMap::new();
        let mut account_updates: HashMap<Address, AccountDelta> = HashMap::new();
        let mut state_updates: HashMap<ComponentId, ProtocolComponentStateDelta> = HashMap::new();
        let mut balance_changes: HashMap<ComponentId, HashMap<Address, ComponentBalance>> =
            HashMap::new();
        let mut account_balance_changes: HashMap<Address, HashMap<Address, AccountBalance>> =
            HashMap::new();

        // First, parse the new protocol components
        for change in msg.component_changes.into_iter() {
            let component = ProtocolComponent::try_from_message((
                change,
                block.chain,
                protocol_system,
                protocol_types,
                tx.hash.clone(),
                block.ts,
            ))?;
            new_protocol_components.insert(component.id.clone(), component);
        }

        // Then, parse the account updates
        for contract_change in msg.contract_changes.clone().into_iter() {
            let update = AccountDelta::try_from_message((contract_change, block.chain))?;
            account_updates.insert(update.address.clone(), update);
        }

        // Then, parse the state updates
        for state_msg in msg.entity_changes.into_iter() {
            let state = ProtocolComponentStateDelta::try_from_message(state_msg)?;
            // Check if a state update for the same component already exists
            // If it exists, overwrite the existing state update with the new one and log a warning
            match state_updates.entry(state.component_id.clone()) {
                Entry::Vacant(e) => {
                    e.insert(state);
                }
                Entry::Occupied(mut e) => {
                    warn!("Received two state updates for the same component. Overwriting state for component {}", e.key());
                    e.insert(state);
                }
            }
        }

        // Finally, parse the component balance changes
        for balance_change in msg.balance_changes.into_iter() {
            let component_id = String::from_utf8(balance_change.component_id.clone())
                .map_err(|error| ExtractionError::DecodeError(error.to_string()))?;
            let token_address = Bytes::from(balance_change.token.clone());
            let balance = ComponentBalance::try_from_message((balance_change, &tx))?;

            balance_changes
                .entry(component_id)
                .or_default()
                .insert(token_address, balance);
        }

        // parse the account balance changes
        for contract_change in msg.contract_changes.into_iter() {
            for balance_change in contract_change
                .token_balances
                .into_iter()
            {
                let account_addr = contract_change.address.clone().into();
                let token_address = Bytes::from(balance_change.token.clone());
                let balance =
                    AccountBalance::try_from_message((balance_change, &account_addr, &tx))?;

                account_balance_changes
                    .entry(account_addr)
                    .or_default()
                    .insert(token_address, balance);
            }
        }

        Ok(Self {
            protocol_components: new_protocol_components,
            account_deltas: account_updates,
            state_updates,
            balance_changes,
            account_balance_changes,
            tx,
        })
    }
}

impl TryFromMessage for BlockContractChanges {
    type Args<'a> = (
        substreams::BlockContractChanges,
        &'a str,
        Chain,
        String,
        &'a HashMap<String, ProtocolType>,
        u64,
    );

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, extractor, chain, protocol_system, protocol_types, finalized_block_height) = args;

        if let Some(block) = msg.block {
            let block = Block::try_from_message((block, chain))?;
            let mut tx_updates = Vec::new();

            for change in msg.changes.into_iter() {
                let mut account_updates = HashMap::new();
                let mut protocol_components = HashMap::new();
                let mut balances_changes: HashMap<ComponentId, HashMap<Address, ComponentBalance>> =
                    HashMap::new();
                let mut account_balance_changes: HashMap<
                    Address,
                    HashMap<Address, AccountBalance>,
                > = HashMap::new();

                if let Some(tx) = change.tx {
                    let tx = Transaction::try_from_message((tx, &block.hash.clone()))?;
                    for contract_change in change
                        .contract_changes
                        .clone()
                        .into_iter()
                    {
                        let update = AccountDelta::try_from_message((contract_change, chain))?;
                        account_updates.insert(update.address.clone(), update);
                    }
                    for component_msg in change.component_changes.into_iter() {
                        let component = ProtocolComponent::try_from_message((
                            component_msg,
                            chain,
                            &protocol_system,
                            protocol_types,
                            tx.hash.clone(),
                            block.ts,
                        ))?;
                        protocol_components.insert(component.id.clone(), component);
                    }

                    // parse the balance changes
                    for balance_change in change.balance_changes.into_iter() {
                        let component_id =
                            String::from_utf8(balance_change.component_id.clone())
                                .map_err(|error| ExtractionError::DecodeError(error.to_string()))?;
                        let token_address = balance_change.token.clone().into();
                        let balance = ComponentBalance::try_from_message((balance_change, &tx))?;

                        balances_changes
                            .entry(component_id)
                            .or_default()
                            .insert(token_address, balance);
                    }

                    // parse the account balance changes
                    for contract_change in change.contract_changes.into_iter() {
                        for balance_change in contract_change
                            .token_balances
                            .into_iter()
                        {
                            let account_addr = contract_change.address.clone().into();
                            let token_address = Bytes::from(balance_change.token.clone());
                            let balance = AccountBalance::try_from_message((
                                balance_change,
                                &account_addr,
                                &tx,
                            ))?;

                            account_balance_changes
                                .entry(account_addr)
                                .or_default()
                                .insert(token_address, balance);
                        }
                    }

                    tx_updates.push(AccountChangesWithTx::new(
                        account_updates,
                        protocol_components,
                        balances_changes,
                        account_balance_changes,
                        tx,
                    ));
                }
            }
            tx_updates.sort_unstable_by_key(|update| update.tx.index);
            return Ok(Self::new(
                extractor.to_owned(),
                chain,
                block,
                finalized_block_height,
                false,
                tx_updates,
            ));
        }
        Err(ExtractionError::Empty)
    }
}

impl TryFromMessage for BlockEntityChanges {
    type Args<'a> = (
        substreams::BlockEntityChanges,
        &'a str,
        Chain,
        &'a str,
        &'a HashMap<String, ProtocolType>,
        u64,
    );

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, extractor, chain, protocol_system, protocol_types, finalized_block_height) = args;

        if let Some(block) = msg.block {
            let block = Block::try_from_message((block, chain))?;

            let mut txs_with_update = msg
                .changes
                .into_iter()
                .map(|change| {
                    change.tx.as_ref().ok_or_else(|| {
                        ExtractionError::DecodeError(
                            "TransactionEntityChanges misses a transaction".to_owned(),
                        )
                    })?;

                    ProtocolChangesWithTx::try_from_message((
                        change,
                        &block,
                        protocol_system,
                        protocol_types,
                    ))
                })
                .collect::<Result<Vec<ProtocolChangesWithTx>, ExtractionError>>()?;

            // Sort updates by transaction index
            txs_with_update.sort_unstable_by_key(|update| update.tx.index);

            Ok(Self::new(
                extractor.to_string(),
                chain,
                block,
                finalized_block_height,
                false,
                txs_with_update,
            ))
        } else {
            Err(ExtractionError::Empty)
        }
    }
}

impl TryFromMessage for BlockChanges {
    type Args<'a> =
        (substreams::BlockChanges, &'a str, Chain, &'a str, &'a HashMap<String, ProtocolType>, u64);

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, extractor, chain, protocol_system, protocol_types, finalized_block_height) = args;

        if let Some(block) = msg.block {
            let block = Block::try_from_message((block, chain))?;

            let txs_with_update = msg
                .changes
                .into_iter()
                .map(|change| {
                    change.tx.as_ref().ok_or_else(|| {
                        ExtractionError::DecodeError(
                            "TransactionEntityChanges misses a transaction".to_owned(),
                        )
                    })?;

                    TxWithChanges::try_from_message((
                        change,
                        &block,
                        protocol_system,
                        protocol_types,
                    ))
                })
                .collect::<Result<Vec<TxWithChanges>, ExtractionError>>()?;

            // Sort updates by transaction index
            let mut txs_with_update = txs_with_update;
            txs_with_update.sort_unstable_by_key(|update| update.tx.index);

            Ok(Self::new(
                extractor.to_string(),
                chain,
                block,
                finalized_block_height,
                false,
                txs_with_update,
            ))
        } else {
            Err(ExtractionError::Empty)
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use rstest::rstest;

    use super::*;

    use crate::{
        extractor::models::fixtures::{
            block_entity_changes, block_state_changes, create_transaction,
        },
        pb::testing::fixtures,
    };

    #[test]
    fn test_parse_protocol_state_update() {
        let msg = fixtures::pb_state_changes();

        let res = ProtocolComponentStateDelta::try_from_message(msg).unwrap();

        assert_eq!(res, fixtures::protocol_state_delta());
    }

    #[rstest]
    fn test_parse_protocol_component() {
        let msg = fixtures::pb_protocol_component();

        let expected_chain = Chain::Ethereum;
        let expected_protocol_system = "ambient".to_string();
        let expected_attribute_map: HashMap<String, Bytes> = vec![
            ("balance".to_string(), Bytes::from(100u64).lpad(32, 0)),
            ("factory_address".to_string(), Bytes::from(b"0x0fwe0g240g20".to_vec())),
        ]
        .into_iter()
        .collect();

        let protocol_type_id = "WeightedPool".to_string();
        let protocol_types: HashMap<String, ProtocolType> =
            HashMap::from([(protocol_type_id.clone(), ProtocolType::default())]);

        // Call the try_from_message method
        let result = ProtocolComponent::try_from_message((
            msg,
            expected_chain,
            &expected_protocol_system,
            &protocol_types,
            Bytes::from_str("0x0e22048af8040c102d96d14b0988c6195ffda24021de4d856801553aa468bcac")
                .unwrap(),
            Default::default(),
        ));

        // Assert the result
        assert!(result.is_ok());

        // Unwrap the result for further assertions
        let protocol_component = result.unwrap();

        // Assert specific properties of the protocol component
        assert_eq!(
            protocol_component.id,
            "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_string()
        );
        assert_eq!(protocol_component.protocol_system, expected_protocol_system);
        assert_eq!(protocol_component.protocol_type_name, protocol_type_id);
        assert_eq!(protocol_component.chain, expected_chain);
        assert_eq!(
            protocol_component.tokens,
            vec![
                Bytes::from_str("6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                Bytes::from_str("6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            ]
        );
        assert_eq!(
            protocol_component.contract_addresses,
            vec![
                Bytes::from_str("31fF2589Ee5275a2038beB855F44b9Be993aA804").unwrap(),
                Bytes::from_str("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
            ]
        );
        assert_eq!(protocol_component.static_attributes, expected_attribute_map);
    }

    pub fn transaction() -> Transaction {
        create_transaction(
            "0000000000000000000000000000000000000000000000000000000011121314",
            "0000000000000000000000000000000000000000000000000000000031323334",
            2,
        )
    }

    #[rstest]
    fn test_parse_component_balance() {
        let tx = transaction();
        let expected_balance: f64 = 3000.0;
        let msg_balance = expected_balance.to_le_bytes().to_vec();

        let expected_token = Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let msg_token = expected_token.0.to_vec();
        let expected_component_id =
            "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902";
        let msg_component_id = expected_component_id
            .as_bytes()
            .to_vec();
        let msg = substreams::BalanceChange {
            balance: msg_balance.to_vec(),
            token: msg_token,
            component_id: msg_component_id,
        };
        let from_message = ComponentBalance::try_from_message((msg, &tx)).unwrap();

        assert_eq!(from_message.balance, msg_balance);
        assert_eq!(from_message.modify_tx, tx.hash);
        assert_eq!(from_message.token, expected_token);
        assert_eq!(from_message.component_id, expected_component_id);
    }

    #[test]
    fn test_parse_block_contract_changes() {
        let msg = fixtures::pb_block_contract_changes(0);

        let res = BlockContractChanges::try_from_message((
            msg,
            "test",
            Chain::Ethereum,
            "ambient".to_string(),
            &HashMap::from([("WeightedPool".to_string(), ProtocolType::default())]),
            0,
        ))
        .unwrap();
        assert_eq!(res, block_state_changes());
    }

    #[test]
    fn test_block_entity_changes_parse_msg() {
        let msg = fixtures::pb_block_entity_changes(0);

        let res = BlockEntityChanges::try_from_message((
            msg,
            "test",
            Chain::Ethereum,
            "ambient",
            &HashMap::from([
                ("Pool".to_string(), ProtocolType::default()),
                ("WeightedPool".to_string(), ProtocolType::default()),
            ]),
            420,
        ))
        .unwrap();
        assert_eq!(res, block_entity_changes());
    }
}

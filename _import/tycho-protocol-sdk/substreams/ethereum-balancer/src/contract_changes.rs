/// This file contains helpers to capture contract changes from the expanded block model. These
///  leverage the `code_changes`, `balance_changes`, and `storage_changes` fields available on the
///  `Call` type provided by block model in a substream (i.e. `logs_and_calls`, etc).
///
/// ⚠️ These helpers *only* work if the **expanded block model** is available, more info blow.
/// https://streamingfastio.medium.com/new-block-model-to-accelerate-chain-integration-9f65126e5425
use std::collections::HashMap;

use substreams_ethereum::pb::eth;

use pb::tycho::evm::v1::{self as tycho};

use substreams::store::{StoreGet, StoreGetInt64};

use crate::pb;

struct SlotValue {
    new_value: Vec<u8>,
    start_value: Vec<u8>,
}

impl SlotValue {
    fn has_changed(&self) -> bool {
        self.start_value != self.new_value
    }
}

// Uses a map for slots, protobuf does not allow bytes in hashmap keys
pub struct InterimContractChange {
    address: Vec<u8>,
    balance: Vec<u8>,
    code: Vec<u8>,
    slots: HashMap<Vec<u8>, SlotValue>,
    change: tycho::ChangeType,
}

impl From<InterimContractChange> for tycho::ContractChange {
    fn from(value: InterimContractChange) -> Self {
        tycho::ContractChange {
            address: value.address,
            balance: value.balance,
            code: value.code,
            slots: value
                .slots
                .into_iter()
                .filter(|(_, value)| value.has_changed())
                .map(|(slot, value)| tycho::ContractSlot {
                    slot,
                    value: value.new_value,
                })
                .collect(),
            change: value.change.into(),
        }
    }
}

pub fn extract_contract_changes(
    block: &eth::v2::Block,
    contracts: StoreGetInt64,
    transaction_contract_changes: &mut HashMap<u64, tycho::TransactionContractChanges>,
) {
    let mut changed_contracts: HashMap<Vec<u8>, InterimContractChange> = HashMap::new();

    // Collect all accounts created in this block
    let created_accounts: HashMap<_, _> = block
        .transactions()
        .flat_map(|tx| {
            tx.calls.iter().flat_map(|call| {
                call.account_creations
                    .iter()
                    .map(|ac| (&ac.account, ac.ordinal))
            })
        })
        .collect();

    block.transactions().for_each(|block_tx| {
        let mut storage_changes = Vec::new();
        let mut balance_changes = Vec::new();
        let mut code_changes = Vec::new();

        block_tx
            .calls
            .iter()
            .filter(|call| {
                !call.state_reverted
                    && contracts
                        .get_last(format!("pool:{0}", hex::encode(&call.address)))
                        .is_some()
            })
            .for_each(|call| {
                storage_changes.extend(call.storage_changes.iter());
                balance_changes.extend(call.balance_changes.iter());
                code_changes.extend(call.code_changes.iter());
            });

        storage_changes.sort_unstable_by_key(|change| change.ordinal);
        balance_changes.sort_unstable_by_key(|change| change.ordinal);
        code_changes.sort_unstable_by_key(|change| change.ordinal);

        storage_changes.iter().for_each(|storage_change| {
            let contract_change = changed_contracts
                .entry(storage_change.address.clone())
                .or_insert_with(|| InterimContractChange {
                    address: storage_change.address.clone(),
                    balance: Vec::new(),
                    code: Vec::new(),
                    slots: HashMap::new(),
                    change: if created_accounts.contains_key(&storage_change.address) {
                        tycho::ChangeType::Creation
                    } else {
                        tycho::ChangeType::Update
                    },
                });

            let slot_value = contract_change
                .slots
                .entry(storage_change.key.clone())
                .or_insert_with(|| SlotValue {
                    new_value: storage_change.new_value.clone(),
                    start_value: storage_change.old_value.clone(),
                });

            slot_value
                .new_value
                .copy_from_slice(&storage_change.new_value);
        });

        balance_changes.iter().for_each(|balance_change| {
            let contract_change = changed_contracts
                .entry(balance_change.address.clone())
                .or_insert_with(|| InterimContractChange {
                    address: balance_change.address.clone(),
                    balance: Vec::new(),
                    code: Vec::new(),
                    slots: HashMap::new(),
                    change: if created_accounts.contains_key(&balance_change.address) {
                        tycho::ChangeType::Creation
                    } else {
                        tycho::ChangeType::Update
                    },
                });

            if let Some(new_balance) = &balance_change.new_value {
                contract_change.balance.clear();
                contract_change
                    .balance
                    .extend_from_slice(&new_balance.bytes);
            }
        });

        code_changes.iter().for_each(|code_change| {
            let contract_change = changed_contracts
                .entry(code_change.address.clone())
                .or_insert_with(|| InterimContractChange {
                    address: code_change.address.clone(),
                    balance: Vec::new(),
                    code: Vec::new(),
                    slots: HashMap::new(),
                    change: if created_accounts.contains_key(&code_change.address) {
                        tycho::ChangeType::Creation
                    } else {
                        tycho::ChangeType::Update
                    },
                });

            contract_change.code.clear();
            contract_change
                .code
                .extend_from_slice(&code_change.new_code);
        });

        if !storage_changes.is_empty() || !balance_changes.is_empty() || !code_changes.is_empty() {
            transaction_contract_changes
                .entry(block_tx.index.into())
                .or_insert_with(|| tycho::TransactionContractChanges {
                    tx: Some(tycho::Transaction {
                        hash: block_tx.hash.clone(),
                        from: block_tx.from.clone(),
                        to: block_tx.to.clone(),
                        index: block_tx.index as u64,
                    }),
                    contract_changes: vec![],
                    component_changes: vec![],
                    balance_changes: vec![],
                })
                .contract_changes
                .extend(changed_contracts.drain().map(|(_, change)| change.into()));
        }
    });
}

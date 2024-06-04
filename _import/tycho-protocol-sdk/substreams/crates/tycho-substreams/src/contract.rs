/// Helpers to extract relevant contract storage.
///
/// This file contains helpers to capture contract changes from the expanded block
/// model. These leverage the `code_changes`, `balance_changes`, and `storage_changes`
/// fields available on the `Call` type provided by block model in a substream
/// (i.e. `logs_and_calls`, etc).
///
/// ## Warning
/// ⚠️ These helpers *only* work if the **extended block model** is available,
/// more [here](https://streamingfastio.medium.com/new-block-model-to-accelerate-chain-integration-9f65126e5425)
use std::collections::HashMap;

use substreams_ethereum::pb::{
    eth,
    eth::v2::{block::DetailLevel, StorageChange},
};

use crate::pb::tycho::evm::v1::{self as tycho};

struct SlotValue {
    new_value: Vec<u8>,
    start_value: Vec<u8>,
}

impl From<&StorageChange> for SlotValue {
    fn from(change: &StorageChange) -> Self {
        Self { new_value: change.new_value.clone(), start_value: change.old_value.clone() }
    }
}

impl SlotValue {
    fn has_changed(&self) -> bool {
        self.start_value != self.new_value
    }
}

// Uses a map for slots, protobuf does not allow bytes in hashmap keys
struct InterimContractChange {
    address: Vec<u8>,
    balance: Vec<u8>,
    code: Vec<u8>,
    slots: HashMap<Vec<u8>, SlotValue>,
    change: tycho::ChangeType,
}

impl InterimContractChange {
    fn new(address: &[u8], creation: bool) -> Self {
        Self {
            address: address.to_vec(),
            balance: vec![],
            code: vec![],
            slots: Default::default(),
            change: if creation { tycho::ChangeType::Creation } else { tycho::ChangeType::Update },
        }
    }
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
                .map(|(slot, value)| tycho::ContractSlot { slot, value: value.new_value })
                .collect(),
            change: value.change.into(),
        }
    }
}

/// Extracts and aggregates contract changes from a block.
///
/// This function identifies and collects changes to contract storage, code, and native balance for
/// contracts of interest within a given block. It filters contracts based on a user-defined
/// predicate and aggregates changes into a provided mutable map.
///
/// ## Arguments
/// * `block` - The block from which to extract contract changes, expected to be an extended block
///   model.
/// * `inclusion_predicate` - A closure that determines if a contract's address is of interest for
///   the collection of changes. Only contracts satisfying this predicate are included.
/// * `transaction_changes` - A mutable reference to a map where extracted contract changes are
///   stored. Keyed by transaction index, it aggregates changes into `tycho::TransactionChanges`.
///
/// ## Panics
/// Panics if the provided block is not an extended block model, as indicated by its detail level.
///
/// ## Operation
/// The function iterates over transactions and their calls within the block, collecting contract
/// changes (storage, balance, code) that pass the inclusion predicate. Changes are then sorted by
/// their ordinals to maintain the correct sequence of events. Aggregated changes for each contract
/// are stored in `transaction_changes`, categorized by transaction index.
///
/// Contracts created within the block are tracked to differentiate between new and existing
/// contracts. The aggregation process respects transaction boundaries, ensuring that changes are
/// mapped accurately to their originating transactions.
pub fn extract_contract_changes<F: Fn(&[u8]) -> bool>(
    block: &eth::v2::Block,
    inclusion_predicate: F,
    transaction_changes: &mut HashMap<u64, tycho::TransactionChanges>,
) {
    if block.detail_level != Into::<i32>::into(DetailLevel::DetaillevelExtended) {
        panic!("Only extended blocks are supported");
    }
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

    block
        .transactions()
        .for_each(|block_tx| {
            let mut storage_changes = Vec::new();
            let mut balance_changes = Vec::new();
            let mut code_changes = Vec::new();

            block_tx
                .calls
                .iter()
                .filter(|call| !call.state_reverted && inclusion_predicate(&call.address))
                .for_each(|call| {
                    storage_changes.extend(call.storage_changes.iter());
                    balance_changes.extend(call.balance_changes.iter());
                    code_changes.extend(call.code_changes.iter());
                });

            storage_changes.sort_unstable_by_key(|change| change.ordinal);
            balance_changes.sort_unstable_by_key(|change| change.ordinal);
            code_changes.sort_unstable_by_key(|change| change.ordinal);

            storage_changes
                .iter()
                .filter(|changes| inclusion_predicate(&changes.address))
                .for_each(|&storage_change| {
                    let contract_change = changed_contracts
                        .entry(storage_change.address.clone())
                        .or_insert_with(|| {
                            InterimContractChange::new(
                                &storage_change.address,
                                created_accounts.contains_key(&storage_change.address),
                            )
                        });

                    let slot_value = contract_change
                        .slots
                        .entry(storage_change.key.clone())
                        .or_insert_with(|| storage_change.into());

                    slot_value
                        .new_value
                        .copy_from_slice(&storage_change.new_value);
                });

            balance_changes
                .iter()
                .filter(|changes| inclusion_predicate(&changes.address))
                .for_each(|balance_change| {
                    let contract_change = changed_contracts
                        .entry(balance_change.address.clone())
                        .or_insert_with(|| {
                            InterimContractChange::new(
                                &balance_change.address,
                                created_accounts.contains_key(&balance_change.address),
                            )
                        });

                    if let Some(new_balance) = &balance_change.new_value {
                        contract_change.balance.clear();
                        contract_change
                            .balance
                            .extend_from_slice(&new_balance.bytes);
                    }
                });

            code_changes
                .iter()
                .filter(|changes| inclusion_predicate(&changes.address))
                .for_each(|code_change| {
                    let contract_change = changed_contracts
                        .entry(code_change.address.clone())
                        .or_insert_with(|| {
                            InterimContractChange::new(
                                &code_change.address,
                                created_accounts.contains_key(&code_change.address),
                            )
                        });

                    contract_change.code.clear();
                    contract_change
                        .code
                        .extend_from_slice(&code_change.new_code);
                });

            if !storage_changes.is_empty() ||
                !balance_changes.is_empty() ||
                !code_changes.is_empty()
            {
                transaction_changes
                    .entry(block_tx.index.into())
                    .or_insert_with(|| tycho::TransactionChanges::new(&(block_tx.into())))
                    .contract_changes
                    .extend(
                        changed_contracts
                            .drain()
                            .map(|(_, change)| change.into()),
                    );
            }
        });
}

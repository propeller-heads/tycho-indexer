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
    eth::v2::block::DetailLevel, eth::v2::CallType
};
use substreams_ethereum::pb::eth::v2::TransactionTrace;
use crate::models::{InterimContractChange, TransactionChanges};
use crate::prelude::TransactionChangesBuilder;

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
    transaction_changes: &mut HashMap<u64, TransactionChanges>,
) {
    extract_contract_changes_generic(
        block,
        inclusion_predicate,
        |tx, changed_contracts| {
            transaction_changes
                .entry(tx.index.into())
                .or_insert_with(|| TransactionChanges::new(&(tx.into())))
                .contract_changes
                .extend(
                    changed_contracts
                        .clone()
                        .into_values()
                        .map(|change| change.into()),
                );
        },
    )
}


pub fn extract_contract_changes_builder<F: Fn(&[u8]) -> bool>(
    block: &eth::v2::Block,
    inclusion_predicate: F,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    extract_contract_changes_generic(
        block,
        inclusion_predicate,
        |tx, changed_contracts| {
            let builder = transaction_changes
                .entry(tx.index.into())
                .or_insert_with(|| TransactionChangesBuilder::new(&(tx.into())));
            changed_contracts
                .clone()
                .into_iter()
                .for_each(|(_, change)| builder.add_contract_changes(&change));
        },
    )
}

fn extract_contract_changes_generic<F: Fn(&[u8]) -> bool, G: FnMut(&TransactionTrace, &HashMap<Vec<u8>, InterimContractChange>)>(
    block: &eth::v2::Block,
    inclusion_predicate: F,
    mut store_changes: G,
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

            let filtered_calls = block_tx.calls.iter().filter(|call| {
                let address_included = inclusion_predicate(&call.address);
                let caller_included = inclusion_predicate(&call.caller);
                let is_delegate_or_callcode = call.call_type() == CallType::Delegate ||
                    call.call_type() == CallType::Callcode;

                !call.state_reverted &&
                    (address_included || (caller_included && is_delegate_or_callcode))
            });

            filtered_calls.for_each(|call| {
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

                    contract_change.upsert_slot(storage_change);
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
                        contract_change.set_balance(&new_balance.bytes);
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

                    contract_change.set_code(&code_change.new_code);
                });

            if !storage_changes.is_empty() ||
                !balance_changes.is_empty() ||
                !code_changes.is_empty()
            {
                store_changes(block_tx, &changed_contracts)
            }
            changed_contracts.clear()
        });
}

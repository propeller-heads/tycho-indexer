use std::collections::HashMap;

use substreams_ethereum::pb::{
    eth,
    eth::v2::{block::DetailLevel, StorageChange},
};

use crate::{
    models::{ContractSlot, StorageChanges, Transaction},
    pb::tycho::evm::v1::TransactionStorageChanges,
};

#[allow(dead_code)]
/// Helper function to extract all storage changes on a block.
/// The raw block information collected is intended to be used by the DCI (Dynamic Contract Indexer)
/// to extract and index relevant changes. This is specifically for dynamically identified contracts
/// that the DCI has chosen to index. Note that core protocol data should still be properly
/// integrated and indexed by the substreams package as per usual.
///
/// ## Panics
/// Panics if the provided block is not an extended block model, as indicated by its detail level.
///
/// ## Warning
/// ⚠️ This function *only* works if the **extended block model** is available,
/// more [here](https://streamingfastio.medium.com/new-block-model-to-accelerate-chain-integration-9f65126e5425)
fn get_block_storage_changes(block: &eth::v2::Block) -> Vec<TransactionStorageChanges> {
    if block.detail_level != Into::<i32>::into(DetailLevel::DetaillevelExtended) {
        panic!("Only extended blocks are supported");
    }
    let mut block_storage_changes = Vec::with_capacity(block.transaction_traces.len());

    for block_tx in block.transactions() {
        let transaction: Transaction = block_tx.into();

        let mut changes_by_address: HashMap<Vec<u8>, Vec<StorageChange>> = HashMap::new();
        for storage_change in block_tx
            .calls
            .iter()
            .filter(|call| !call.state_reverted)
            .flat_map(|call| call.storage_changes.iter())
        {
            changes_by_address
                .entry(storage_change.address.clone())
                .or_default()
                .push(storage_change.clone());
        }

        // For each address, sort by ordinal and collect latest changes per slot
        let tx_storage_changes: Vec<StorageChanges> = changes_by_address
            .into_iter()
            .map(|(address, mut changes)| {
                changes.sort_unstable_by_key(|change| change.ordinal);

                // Collect latest change per slot
                let mut latest_changes: HashMap<Vec<u8>, ContractSlot> = HashMap::new();
                for change in changes {
                    latest_changes.insert(
                        change.key.clone(),
                        ContractSlot { slot: change.key, value: change.new_value },
                    );
                }

                StorageChanges { address, slots: latest_changes.into_values().collect() }
            })
            .collect();

        block_storage_changes.push(TransactionStorageChanges {
            tx: Some(transaction),
            storage_changes: tx_storage_changes,
        });
    }

    block_storage_changes
}

# Tracking Contract Balances

Sometimes the balances a component uses is stored on a contract that is not a dedicated single pool contract. During Tycho VM simulations, token contracts are mocked and any balances checked or used during a swap need to be overwritten for a simulation to succeed. Default behavior is for the component balances reported to be used to overwrite the pool contract balances. This assumes 2 things: there is a one-to-one relationship between contracts and components, and the hex-encoded contract address serves as the component ID.

If a protocol deviates from this assumption, the balances for each appropriate contract needs to be tracked for that contract. All contracts that have their balances checked/accessed during a simulation need to be tracked in this way.

### Implementation Steps:

1. Implement logic/a helper function to extract the absolute balances of the contract. This is protocol specific and might be obtained from an event, or extracted from a storage slot if an appropriate one is identified.
2. Create an `InterimContractChange` for the contract and add the contract balances using `upsert_token_balance`.&#x20;
3. Add these contract changes to the appropriate `TransactionChangesBuilder` using `add_contract_changes`.

An example for a protocol that uses a single vault contract is as follows:

```rust
use tycho_substreams::models::{InterimContractChange, TransactionChangesBuilder};

// all changes on this block, aggregated by transaction
let mut transaction_changes: HashMap<_, TransactionChanges> = HashMap::new();

// Extract token balances for vault contract
block
    .transaction_traces
    .iter()
    .for_each(|tx| {
        // use helper function to get absolute balances at this transaction
        let vault_balance_change = get_vault_reserves(tx, &components_store, &tokens_store);

        if !vault_balance_change.is_empty() {
            let tycho_tx = Transaction::from(tx);
            let builder = transaction_changes
                .entry(tx.index.into())
                .or_insert_with(|| TransactionChangesBuilder::new(&tycho_tx));

            let mut vault_contract_changes = InterimContractChange::new(VAULT_ADDRESS, false);
            for (token_addr, reserve_value) in vault_balance_change {
                vault_contract_changes.upsert_token_balance(
                    token_addr.as_slice(),
                    reserve_value.value.as_slice(),
                );
            }
            builder.add_contract_changes(&vault_contract_changes);
        }
    });
```


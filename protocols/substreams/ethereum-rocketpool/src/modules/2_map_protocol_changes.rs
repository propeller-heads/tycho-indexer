use crate::{
    abi::{
        rocket_dao_protocol_proposal, rocket_deposit_pool, rocket_minipool_queue,
        rocket_network_balances, rocket_token_reth,
    },
    constants::{
        ALL_STORAGE_SLOTS, DEPOSITS_ENABLED_SLOT, DEPOSIT_ASSIGN_ENABLED_SLOT,
        DEPOSIT_ASSIGN_MAXIMUM_SLOT, DEPOSIT_ASSIGN_SOCIALISED_MAXIMUM_SLOT, DEPOSIT_FEE_SLOT,
        ETH_ADDRESS, MAX_DEPOSIT_AMOUNT_SLOT, MIN_DEPOSIT_AMOUNT_SLOT, QUEUE_KEY_FULL,
        QUEUE_KEY_HALF, QUEUE_KEY_VARIABLE, QUEUE_VARIABLE_END_SLOT, QUEUE_VARIABLE_START_SLOT,
        RETH_ADDRESS, ROCKET_DAO_MINIPOOL_QUEUE_ADDRESS, ROCKET_DAO_PROTOCOL_PROPOSAL_ADDRESS,
        ROCKET_DEPOSIT_POOL_ADDRESS_V1_2, ROCKET_DEPOSIT_POOL_ETH_BALANCE_SLOT,
        ROCKET_NETWORK_BALANCES_ADDRESS, ROCKET_POOL_COMPONENT_ID, ROCKET_STORAGE_ADDRESS,
        ROCKET_VAULT_ADDRESS,
    },
    utils::{get_changed_attributes, hex_to_bytes},
};
use anyhow::Result;
use itertools::Itertools;
use std::collections::HashMap;
use substreams_ethereum::{
    pb::eth::{self, v2::TransactionTrace},
    Event,
};
use tycho_substreams::{
    models::{
        Attribute, BlockChanges, BlockTransactionProtocolComponents, ChangeType, EntityChanges,
        TransactionChangesBuilder,
    },
    prelude::BalanceChange,
};

/// Aggregates protocol component, balance and attribute changes by transaction.
///
/// This is the main method that will aggregate all changes as well as extract all
/// relevant contract storage deltas.
#[substreams::handlers::map]
fn map_protocol_changes(
    params: String,
    block: eth::v2::Block,
    protocol_components: BlockTransactionProtocolComponents,
) -> Result<BlockChanges> {
    let mut transaction_changes: HashMap<_, TransactionChangesBuilder> = HashMap::new();

    // As we start indexing mid-protocol (at Deposit Pool V1.2 deployment), we provide
    // initial attribute values that represent the state at the END of the deployment block.
    // Therefore, if a protocol component was created in this block, we need to initialize it
    // with the provided initial state values, and we can skip further updates for this block.
    let component_created = !protocol_components
        .tx_components
        .is_empty();

    if component_created {
        initialize_protocol_component(&params, protocol_components, &mut transaction_changes)?;
    } else {
        update_deposit_liquidity(&block, &mut transaction_changes);
        update_reth_liquidity(&block, &mut transaction_changes);

        update_network_balance(&block, &mut transaction_changes);

        update_protocol_settings(&block, &mut transaction_changes);

        update_minipool_queue_sizes(&block, &mut transaction_changes)?;
    }

    Ok(BlockChanges {
        block: Some((&block).into()),
        changes: transaction_changes
            .drain()
            .sorted_unstable_by_key(|(index, _)| *index)
            .filter_map(|(_, builder)| builder.build())
            .collect(),
        storage_changes: vec![],
    })
}

/// Initializes the protocol component with initial state values.
///
/// This function is called only once when the component is created. It adds the protocol
/// component, initial attributes (with ChangeType::Creation), and initial ETH balance.
fn initialize_protocol_component(
    params: &str,
    protocol_components: BlockTransactionProtocolComponents,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) -> Result<()> {
    // Parse initial state JSON once
    let initial_state: HashMap<String, String> = serde_json::from_str(params)
        .map_err(|e| anyhow::anyhow!("Failed to parse initial state: {}", e))?;

    // We expect exactly one tx_component with one component for RocketPool
    let tx_component = protocol_components
        .tx_components
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No transaction component found"))?;

    let tx = tx_component
        .tx
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Transaction missing in protocol components"))?;

    let component = tx_component
        .components
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No component found in transaction"))?;

    let builder = transaction_changes
        .entry(tx.index)
        .or_insert_with(|| TransactionChangesBuilder::new(tx));

    builder.add_protocol_component(&component);

    builder.add_entity_change(&EntityChanges {
        component_id: ROCKET_POOL_COMPONENT_ID.to_owned(),
        attributes: build_initial_attributes(&initial_state)?,
    });

    builder.add_balance_change(&BalanceChange {
        token: ETH_ADDRESS.to_vec(),
        balance: get_initial_eth_balance(&initial_state)?,
        component_id: ROCKET_POOL_COMPONENT_ID
            .as_bytes()
            .to_vec(),
    });

    Ok(())
}

/// Updates deposit contract liquidity based on deposit pool events.
/// This is part of the overall Rocket Pool ETH liquidity tracking.
///
/// Listens for DepositReceived, DepositAssigned, DepositRecycled, and ExcessWithdrawn events
/// from the RocketDepositPool contracts and fetches the updated ETH balance from RocketVault's
/// etherBalances storage slot.
/// The reason we do not use the event parameters directly is that they only contain the delta
/// change, whereas we want to track the absolute balance. We have decided against using the
/// balance stores to accumulate the changes due to added complexity and need to start from the
/// first deployed Deposit Pool contract, while with the storage slot approach we can start
/// indexing at any point in time (in our case, at Deposit Pool V1.2 deployment).
fn update_deposit_liquidity(
    block: &eth::v2::Block,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    for log in block.logs() {
        // Only process events from RocketDepositPool contracts
        if log.log.address != ROCKET_DEPOSIT_POOL_ADDRESS_V1_2 {
            continue;
        }

        let is_deposit_event = rocket_deposit_pool::events::DepositReceived::match_log(log.log) ||
            rocket_deposit_pool::events::DepositAssigned::match_log(log.log) ||
            rocket_deposit_pool::events::DepositRecycled::match_log(log.log) ||
            rocket_deposit_pool::events::ExcessWithdrawn::match_log(log.log);

        if !is_deposit_event {
            continue;
        }

        let tx = log.receipt.transaction;

        let attributes = tx
            .calls
            .iter()
            .filter(|call| call.address == ROCKET_VAULT_ADDRESS)
            .flat_map(|call| {
                get_changed_attributes(
                    &call.storage_changes,
                    &[ROCKET_DEPOSIT_POOL_ETH_BALANCE_SLOT],
                )
            })
            .collect::<Vec<_>>();

        add_entity_change_if_needed(attributes, tx, transaction_changes);
    }
}

/// Updates rETH contract liquidity based on rETH events.
/// This is part of the overall Rocket Pool ETH liquidity tracking.
///
/// Listens for EtherDeposited and TokensBurned events from the RocketTokenRETH contract and
/// fetches the updated native ETH balance from the transaction's balance changes.
///
/// The reason we do not use the event parameters directly is that they only contain the delta
/// change, and would force us to start indexing from the very beginning of the protocol.
fn update_reth_liquidity(
    block: &eth::v2::Block,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    for log in block.logs() {
        // Only process events from the RocketTokenRETH contract
        if log.log.address != RETH_ADDRESS {
            continue;
        }

        // Check if any of the relevant rETH token events fired
        let is_eth_event = rocket_token_reth::events::EtherDeposited::match_log(log.log) ||
            rocket_token_reth::events::TokensBurned::match_log(log.log);

        if !is_eth_event {
            continue;
        }

        let tx = log.receipt.transaction;

        // Extract the updated ETH balance from the transaction's balance changes
        let reth_balance = tx
            .calls
            .iter()
            .flat_map(|call| call.balance_changes.iter())
            .filter(|bc| bc.address == RETH_ADDRESS)
            .filter_map(|bc| bc.new_value.as_ref())
            .last();

        if let Some(reth_balance) = reth_balance {
            let attributes = vec![Attribute {
                name: "reth_contract_liquidity".to_string(),
                value: reth_balance.bytes.to_vec(),
                change: ChangeType::Update.into(),
            }];

            add_entity_change_if_needed(attributes, tx, transaction_changes);
        }
    }
}

/// Extracts Rocket Pool network balance updates from the block logs.
fn update_network_balance(
    block: &eth::v2::Block,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    for log in block.logs() {
        // If the log is not from the Rocket Network Balances contract, skip it.
        if log.log.address != ROCKET_NETWORK_BALANCES_ADDRESS {
            continue;
        }

        if let Some(balance_update) =
            rocket_network_balances::events::BalancesUpdated::match_and_decode(log)
        {
            let tx = log.receipt.transaction;

            let builder = transaction_changes
                .entry(tx.index as u64)
                .or_insert_with(|| TransactionChangesBuilder::new(&(tx.into())));

            let eth_bc = BalanceChange {
                token: ETH_ADDRESS.to_vec(),
                balance: balance_update
                    .total_eth
                    .to_signed_bytes_be(),
                component_id: ROCKET_POOL_COMPONENT_ID
                    .as_bytes()
                    .to_vec(),
            };

            let attributes = vec![
                Attribute {
                    name: "reth_supply".to_string(),
                    value: balance_update
                        .reth_supply
                        .to_signed_bytes_be(),
                    change: ChangeType::Update.into(),
                },
                Attribute {
                    name: "total_eth".to_string(),
                    value: balance_update
                        .total_eth
                        .to_signed_bytes_be(),
                    change: ChangeType::Update.into(),
                },
            ];

            builder.add_balance_change(&eth_bc);
            builder.add_entity_change(&EntityChanges {
                component_id: ROCKET_POOL_COMPONENT_ID.to_owned(),
                attributes,
            });
        }
    }
}

/// Extracts protocol settings updates from the block logs.
///
/// Note: that the protocol settings updates can only be triggered by executing DAO proposals, hence
/// it is sufficient to first check for the `ProposalExecuted` event and only then check the
/// associated storage changes.
fn update_protocol_settings(
    block: &eth::v2::Block,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    for log in block.logs() {
        // If the log is not a ProposalExecuted event from the DAO Proposal contract, skip it as no
        // protocol settings could have changed.
        if !(log.log.address != ROCKET_DAO_PROTOCOL_PROPOSAL_ADDRESS &&
            rocket_dao_protocol_proposal::events::ProposalExecuted::match_log(log.log))
        {
            continue;
        }

        let tx = log.receipt.transaction;

        let attributes = tx
            .calls
            .iter()
            .filter(|call| call.address == ROCKET_STORAGE_ADDRESS)
            .flat_map(|call| {
                get_changed_attributes(
                    &call.storage_changes,
                    &[
                        DEPOSITS_ENABLED_SLOT,
                        DEPOSIT_ASSIGN_ENABLED_SLOT,
                        DEPOSIT_ASSIGN_MAXIMUM_SLOT,
                        DEPOSIT_ASSIGN_SOCIALISED_MAXIMUM_SLOT,
                        MIN_DEPOSIT_AMOUNT_SLOT,
                        MAX_DEPOSIT_AMOUNT_SLOT,
                        DEPOSIT_FEE_SLOT,
                    ],
                )
            })
            .collect::<Vec<_>>();

        add_entity_change_if_needed(attributes, tx, transaction_changes);
    }
}

/// Updates minipool queue sizes based on queue events.
///
/// Listens for MinipoolEnqueued, MinipoolDequeued, and MinipoolRemoved events from the
/// RocketMinipoolQueue contract and fetches the updated queue storage values from RocketStorage.
/// - MinipoolEnqueued: updates the end slot for the variable queue
/// - MinipoolDequeued: updates the start slot for the variable queue
/// - MinipoolRemoved: updates the end slot for the variable queue
///
/// Note that since the V1.2 Deposit Pool deployment, only the variable queue can receive new
/// minipools (Enqueued), and as there were no minipools in the full or half queues at that time,
/// we do not expect any enqueue events for those queues.
fn update_minipool_queue_sizes(
    block: &eth::v2::Block,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) -> Result<()> {
    for log in block.logs() {
        // Only process events from the RocketMinipoolQueue contract
        if log.log.address != ROCKET_DAO_MINIPOOL_QUEUE_ADDRESS {
            continue;
        }

        let tx = log.receipt.transaction;

        // Determine which storage slot to check based on the event type and queue_id
        let storage_slot = if let Some(event) =
            rocket_minipool_queue::events::MinipoolEnqueued::match_and_decode(log)
        {
            assert_variable_queue_id(event.queue_id)?;

            QUEUE_VARIABLE_END_SLOT
        } else if let Some(event) =
            rocket_minipool_queue::events::MinipoolDequeued::match_and_decode(log)
        {
            assert_variable_queue_id(event.queue_id)?;

            QUEUE_VARIABLE_START_SLOT
        } else if let Some(event) =
            rocket_minipool_queue::events::MinipoolRemoved::match_and_decode(log)
        {
            assert_variable_queue_id(event.queue_id)?;

            QUEUE_VARIABLE_END_SLOT
        } else {
            continue;
        };

        // Extract changed attributes from RocketStorage contract storage changes
        let slots = &[storage_slot];
        let attributes = tx
            .calls
            .iter()
            .filter(|call| call.address == ROCKET_STORAGE_ADDRESS)
            .flat_map(|call| get_changed_attributes(&call.storage_changes, slots))
            .collect::<Vec<_>>();

        add_entity_change_if_needed(attributes, tx, transaction_changes);
    }

    Ok(())
}

/// Asserts that the provided queue_id corresponds to the variable queue.
fn assert_variable_queue_id(queue_id: [u8; 32]) -> Result<()> {
    match queue_id {
        QUEUE_KEY_VARIABLE => Ok(()),
        QUEUE_KEY_FULL => {
            Err(anyhow::anyhow!("Full queue is not supported since Deposit Pool V1.2"))
        }
        QUEUE_KEY_HALF => {
            Err(anyhow::anyhow!("Half queue is not supported since Deposit Pool V1.2"))
        }
        _ => Err(anyhow::anyhow!("Unknown queue_id for enqueue: 0x{}", hex::encode(queue_id))),
    }
}

/// Helper to add entity changes for a transaction if attributes are non-empty.
fn add_entity_change_if_needed(
    attributes: Vec<Attribute>,
    tx: &TransactionTrace,
    transaction_changes: &mut HashMap<u64, TransactionChangesBuilder>,
) {
    if !attributes.is_empty() {
        let builder = transaction_changes
            .entry(tx.index as u64)
            .or_insert_with(|| TransactionChangesBuilder::new(&(tx.into())));

        builder.add_entity_change(&EntityChanges {
            component_id: ROCKET_POOL_COMPONENT_ID.to_owned(),
            attributes,
        });
    }
}

/// Build initial attributes from parsed state, validating all required attributes exist.
fn build_initial_attributes(state: &HashMap<String, String>) -> Result<Vec<Attribute>> {
    ALL_STORAGE_SLOTS
        .iter()
        .map(|loc| loc.name)
        .chain(["total_eth", "reth_supply", "reth_contract_liquidity"])
        .map(|name| {
            let value = state
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("Missing initial attribute: {}", name))?;
            Ok(Attribute {
                name: name.to_string(),
                value: hex_to_bytes(value)?,
                change: ChangeType::Creation.into(),
            })
        })
        .collect()
}

/// Get the initial ETH balance from parsed state.
fn get_initial_eth_balance(state: &HashMap<String, String>) -> Result<Vec<u8>> {
    hex_to_bytes(
        state
            .get("total_eth")
            .ok_or_else(|| anyhow::anyhow!("Missing initial attribute: total_eth"))?,
    )
}

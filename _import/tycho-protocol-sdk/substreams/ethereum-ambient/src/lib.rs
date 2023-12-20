use std::collections::{hash_map::Entry, HashMap};

use anyhow::{anyhow, bail};
use ethabi::{decode, ParamType};
use hex_literal::hex;
use substreams_ethereum::pb::eth::{self};

use pb::tycho::evm::v1::{self as tycho, ChangeType};

mod pb;

const AMBIENT_CONTRACT: [u8; 20] = hex!("aaaaaaaaa24eeeb8d57d431224f73832bc34f688");
const INIT_POOL_CODE: u8 = 71;
const USER_CMD_FN_SIG: [u8; 4] = [0xA1, 0x51, 0x12, 0xF9];

struct SlotValue {
    new_value: Vec<u8>,
    start_value: Vec<u8>,
}

impl SlotValue {
    fn has_changed(&self) -> bool {
        self.start_value != self.new_value
    }
}

// uses a map for slots, protobuf does not
// allow bytes in hashmap keys
struct InterimContractChange {
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
                .map(|(slot, value)| tycho::ContractSlot { slot, value: value.new_value })
                .collect(),
            change: value.change.into(),
        }
    }
}

/// Extracts all contract changes relevant to vm simulations
///
/// This implementation has currently two major limitations:
/// 1. It is hardwired to only care about changes to the ambient main contract, this is ok for this
///    particular use case but for a more general purpose implementation this is not ideal
/// 2. Changes are processed separately, this means that if there are any side effects between each
///    other (e.g. if account is deleted and then created again in ethereum all the storage is set
///    to 0. So there is a side effect between account creation and contract storage.) these might
///    not be properly accounted for. Most of the time this should not be a major issue but may lead
///    to wrong results so consume this implementation with care. See example below for a concrete
///    case where this is problematic.
///
/// ## A very contrived example:
/// 1. Some existing contract receives a transaction that changes it state, the state is updated
/// 2. Next, this contract has self destruct called on itself
/// 3. The contract is created again using CREATE2 at the same address
/// 4. The contract receives a transaction that changes it state
/// 5. We would emit this as as contract creation with slots set from 1 and from 4, although we
///    should only emit the slots changed from 4.
#[substreams::handlers::map]
fn map_changes(
    block: eth::v2::Block,
) -> Result<tycho::BlockContractChanges, substreams::errors::Error> {
    let mut block_changes = tycho::BlockContractChanges { block: None, changes: Vec::new() };

    let mut tx_change = tycho::TransactionContractChanges::default();

    let mut changed_contracts: HashMap<Vec<u8>, InterimContractChange> = HashMap::new();

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

    for block_tx in block.transactions() {
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

        let ambient_calls = block_tx
            .calls
            .iter()
            .filter(|call| !call.state_reverted)
            .filter(|call| call.address == AMBIENT_CONTRACT)
            .collect::<Vec<_>>();

        for call in ambient_calls {
            if call.input.len() < 4 {
                continue;
            }
            if call.input[0..4] == USER_CMD_FN_SIG {
                let user_cmd_external_abi_types = &[
                    // index of the proxy sidecar the command is being called on
                    ParamType::Uint(16),
                    // call data for internal UserCmd method
                    ParamType::Bytes,
                ];
                let user_cmd_internal_abi_types = &[
                    ParamType::Uint(8),   // command
                    ParamType::Address,   // base
                    ParamType::Address,   // quote
                    ParamType::Uint(256), // pool index
                    ParamType::Uint(128), // price
                ];

                // Decode external call to UserCmd
                if let Ok(external_params) = decode(user_cmd_external_abi_types, &call.input[4..]) {
                    let cmd_bytes = external_params[1]
                        .to_owned()
                        .into_bytes()
                        .ok_or_else(|| {
                            anyhow!("Failed to convert to bytes: {:?}", &external_params[1])
                        })?;

                    // Call data is structured differently depending on the cmd code, so only
                    // decode if this is an init pool code.
                    if cmd_bytes[31] == INIT_POOL_CODE {
                        // Decode internal call to UserCmd
                        if let Ok(internal_params) = decode(user_cmd_internal_abi_types, &cmd_bytes)
                        {
                            let base = internal_params[1]
                                .to_owned()
                                .into_address()
                                .ok_or_else(|| {
                                    anyhow!(
                                        "Failed to convert to address: {:?}",
                                        &internal_params[1]
                                    )
                                })?
                                .to_fixed_bytes()
                                .to_vec();

                            let quote = internal_params[2]
                                .to_owned()
                                .into_address()
                                .ok_or_else(|| {
                                    anyhow!(
                                        "Failed to convert to address: {:?}",
                                        &internal_params[2]
                                    )
                                })?
                                .to_fixed_bytes()
                                .to_vec();

                            let pool_index = internal_params[3]
                                .to_owned()
                                .into_uint()
                                .ok_or_else(|| anyhow!("Failed to convert to u32".to_string()))?
                                .as_u32();

                            let static_attribute = tycho::Attribute {
                                name: String::from("pool_index"),
                                value: pool_index.to_be_bytes().to_vec(),
                                change: ChangeType::Creation.into(),
                            };

                            let mut tokens: Vec<Vec<u8>> = vec![base.clone(), quote.clone()];
                            tokens.sort();

                            let new_component = tycho::ProtocolComponent {
                                id: format!(
                                    "{}{}{}",
                                    hex::encode(base.clone()),
                                    hex::encode(quote.clone()),
                                    pool_index
                                ),
                                tokens,
                                contracts: vec![hex::encode(AMBIENT_CONTRACT)],
                                static_att: vec![static_attribute],
                                change: ChangeType::Creation.into(),
                            };
                            tx_change
                                .component_changes
                                .push(new_component);
                        } else {
                            bail!("Failed to decode ABI internal call.".to_string());
                        }
                    }
                } else {
                    bail!("Failed to decode ABI external call.".to_string());
                }
            }
        }

        // Note: some contracts change slot values and change them back to their
        //  original value before the transactions ends we remember the initial
        //  value before the first change and in the end filter found deltas
        //  that ended up not actually changing anything.
        for storage_change in storage_changes.iter() {
            match changed_contracts.entry(storage_change.address.clone()) {
                // We have already an entry recording a change about this contract
                //  only append the change about this storage slot
                Entry::Occupied(mut e) => {
                    let contract_change = e.get_mut();
                    match contract_change
                        .slots
                        .entry(storage_change.key.clone())
                    {
                        // The storage slot was already changed before, simply
                        //  update new_value
                        Entry::Occupied(mut v) => {
                            let slot_value = v.get_mut();
                            slot_value
                                .new_value
                                .copy_from_slice(&storage_change.new_value);
                        }
                        // The storage slots is being initialised for the first time
                        Entry::Vacant(v) => {
                            v.insert(SlotValue {
                                new_value: storage_change.new_value.clone(),
                                start_value: storage_change.old_value.clone(),
                            });
                        }
                    }
                }
                // Intialise a new contract change after obsering a storage change
                Entry::Vacant(e) => {
                    let mut slots = HashMap::new();
                    slots.insert(
                        storage_change.key.clone(),
                        SlotValue {
                            new_value: storage_change.new_value.clone(),
                            start_value: storage_change.old_value.clone(),
                        },
                    );
                    e.insert(InterimContractChange {
                        address: storage_change.address.clone(),
                        balance: Vec::new(),
                        code: Vec::new(),
                        slots,
                        change: if created_accounts.contains_key(&storage_change.address) {
                            ChangeType::Creation
                        } else {
                            ChangeType::Update
                        },
                    });
                }
            }
        }

        // extract balance changes
        let mut balance_changes = block_tx
            .calls
            .iter()
            .filter(|call| !call.state_reverted)
            .flat_map(|call| {
                call.balance_changes
                    .iter()
                    .filter(|c| c.address == AMBIENT_CONTRACT)
            })
            .collect::<Vec<_>>();
        balance_changes.sort_unstable_by_key(|change| change.ordinal);

        for balance_change in balance_changes.iter() {
            match changed_contracts.entry(balance_change.address.clone()) {
                Entry::Occupied(mut e) => {
                    let contract_change = e.get_mut();
                    if let Some(new_balance) = &balance_change.new_value {
                        contract_change.balance.clear();
                        contract_change
                            .balance
                            .extend_from_slice(&new_balance.bytes);
                    }
                }
                Entry::Vacant(e) => {
                    if let Some(new_balance) = &balance_change.new_value {
                        e.insert(InterimContractChange {
                            address: balance_change.address.clone(),
                            balance: new_balance.bytes.clone(),
                            code: Vec::new(),
                            slots: HashMap::new(),
                            change: if created_accounts.contains_key(&balance_change.address) {
                                ChangeType::Creation
                            } else {
                                ChangeType::Update
                            },
                        });
                    }
                }
            }
        }

        // extract code changes
        let mut code_changes = block_tx
            .calls
            .iter()
            .filter(|call| !call.state_reverted)
            .flat_map(|call| {
                call.code_changes
                    .iter()
                    .filter(|c| c.address == AMBIENT_CONTRACT)
            })
            .collect::<Vec<_>>();
        code_changes.sort_unstable_by_key(|change| change.ordinal);

        for code_change in code_changes.iter() {
            match changed_contracts.entry(code_change.address.clone()) {
                Entry::Occupied(mut e) => {
                    let contract_change = e.get_mut();
                    contract_change.code.clear();
                    contract_change
                        .code
                        .extend_from_slice(&code_change.new_code);
                }
                Entry::Vacant(e) => {
                    e.insert(InterimContractChange {
                        address: code_change.address.clone(),
                        balance: Vec::new(),
                        code: code_change.new_code.clone(),
                        slots: HashMap::new(),
                        change: if created_accounts.contains_key(&code_change.address) {
                            ChangeType::Creation
                        } else {
                            ChangeType::Update
                        },
                    });
                }
            }
        }

        // if there were any changes, add transaction and push the changes
        if !storage_changes.is_empty() || !balance_changes.is_empty() || !code_changes.is_empty() {
            tx_change.tx = Some(tycho::Transaction {
                hash: block_tx.hash.clone(),
                from: block_tx.from.clone(),
                to: block_tx.to.clone(),
                index: block_tx.index as u64,
            });

            // reuse changed_contracts hash map by draining it, next iteration
            // will start empty. This avoids a costly reallocation
            for (_, change) in changed_contracts.drain() {
                tx_change
                    .contract_changes
                    .push(change.into())
            }

            block_changes
                .changes
                .push(tx_change.clone());

            // clear out the interim contract changes after we pushed those.
            tx_change.tx = None;
            tx_change.contract_changes.clear();
        }
    }

    block_changes.block = Some(tycho::Block {
        number: block.number,
        hash: block.hash.clone(),
        parent_hash: block
            .header
            .as_ref()
            .expect("Block header not present")
            .parent_hash
            .clone(),
        ts: block.timestamp_seconds(),
    });

    Ok(block_changes)
}

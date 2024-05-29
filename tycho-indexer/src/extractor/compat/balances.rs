use crate::extractor::{evm::BlockChanges, u256_num::bytes_to_f64};
use ethers::types::U256;
use tycho_core::Bytes;

fn transcode_ascii_balance_to_be(ascii_encoded: &Bytes) -> anyhow::Result<Bytes> {
    let ascii_string = String::from_utf8(ascii_encoded.clone().to_vec())
        .map_err(|e| anyhow::format_err!("Invalid UTF-8 sequence: {ascii_encoded}: {e}"))?;
    // Balances can go negative, so if the ascii string starts with a -, we default to
    // U256::zero(), see WBTC/USDC pool at block 19297943
    if ascii_string.starts_with('-') {
        Ok(Bytes::from(U256::zero()))
    } else {
        let as_integer = U256::from_dec_str(&ascii_string)
            .map_err(|e| anyhow::format_err!("Invalid integer: {e}"))?;
        Ok(Bytes::from(as_integer))
    }
}

fn transcode_le_balance_to_be(le_encoded: &Bytes) -> anyhow::Result<Bytes> {
    let mut be_encoded = le_encoded.clone().to_vec();
    be_encoded.reverse(); // Reverse the vector to convert from little-endian to big-endian
    Ok(Bytes::from(be_encoded))
}

pub fn transcode_ambient_balances(mut changes: BlockChanges) -> BlockChanges {
    changes
        .txs_with_update
        .iter_mut()
        .for_each(|tx_changes| {
            tx_changes
                .balance_changes
                .iter_mut()
                .for_each(|(_, balance)| {
                    balance
                        .iter_mut()
                        .for_each(|(_, value)| {
                            value.balance = transcode_ascii_balance_to_be(&value.balance)
                                .expect("Balance transcoding failed");
                            value.balance_float = bytes_to_f64(value.balance.as_ref())
                                .expect("failed converting balance to float");
                        });
                });
        });
    changes
}

/// This post processor allow us to ignore any balance change if the component id and the token are
/// the same. We had to add this for Balancer because when a EulerLinearPool is created it returns
/// the minted pool tokens in the balance changes.
/// TODO: look into this and see if we can fix it on the substreams side.
pub fn ignore_self_balances(mut changes: BlockChanges) -> BlockChanges {
    changes
        .txs_with_update
        .iter_mut()
        .for_each(|tx_changes| {
            tx_changes
                .balance_changes
                .iter_mut()
                .for_each(|(_, balance)| {
                    balance
                        .retain(|_, value| format!("{:#020x}", value.token) != value.component_id);
                });
        });
    changes
}

pub fn transcode_usv2_balances(mut changes: BlockChanges) -> BlockChanges {
    changes
        .txs_with_update
        .iter_mut()
        .for_each(|tx_changes| {
            tx_changes
                .balance_changes
                .iter_mut()
                .for_each(|(_, balance)| {
                    balance
                        .iter_mut()
                        .for_each(|(_, value)| {
                            value.balance = transcode_le_balance_to_be(&value.balance).unwrap();
                            value.balance_float = bytes_to_f64(value.balance.as_ref())
                                .expect("failed converting balance to float");
                        });
                });
        });
    changes
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use ethers::types::{H160, H256};
    use tycho_core::models::Chain;

    use crate::{
        extractor::evm::{ComponentBalance, Transaction, TxWithChanges},
        testing::evm_block,
    };

    use super::*;

    #[test]
    fn test_trancode_ascii_balance_to_be() {
        let ascii_balance = Bytes::from("0x373131383430313238");

        let be_balance = transcode_ascii_balance_to_be(&ascii_balance).unwrap();

        assert_eq!(be_balance, Bytes::from(U256::from(711840128)));
    }

    #[test]
    fn test_transcode_le_balance_to_be() {
        let le_balance = Bytes::from("0xb55cb8eef8db0b5c");

        let be_balance = transcode_le_balance_to_be(&le_balance).unwrap();

        assert_eq!(be_balance, Bytes::from("0x5c0bdbf8eeb85cb5"));
    }

    #[test]
    fn test_ignore_self_balances() {
        let txs_with_update =
            vec![TxWithChanges {
            account_updates: HashMap::new(),
            protocol_components: HashMap::new(),
            balance_changes: HashMap::from([(
                "0xabc".to_string(),
                HashMap::from([(
                    H160::from_str("0xeb91861f8a4e1c12333f42dce8fb0ecdc28da716").unwrap(),
                    ComponentBalance {
                        token: H160::from_str("0xeb91861f8a4e1c12333f42dce8fb0ecdc28da716")
                            .unwrap(),
                        balance: Bytes::from(0_i32.to_le_bytes()),
                        balance_float: 36522027799.0,
                        modify_tx: H256::from_low_u64_be(
                            0x0000000000000000000000000000000000000000000000000000000011121314,
                        ),
                        component_id: "0xd4e7c1f3da1144c9e2cfd1b015eda7652b4a4399".to_string(),
                    },
                ),(
                    H160::from_str("0xd4e7c1f3da1144c9e2cfd1b015eda7652b4a4399").unwrap(),
                    ComponentBalance {
                        token: H160::from_str("0xd4e7c1f3da1144c9e2cfd1b015eda7652b4a4399")
                            .unwrap(),
                        balance: Bytes::from(0_i32.to_le_bytes()),
                        balance_float: 36522027799.0,
                        modify_tx: H256::from_low_u64_be(
                            0x0000000000000000000000000000000000000000000000000000000011121314,
                        ),
                        component_id: "0xd4e7c1f3da1144c9e2cfd1b015eda7652b4a4399".to_string(),
                    },
                )]),
            )]),
            tx: Transaction::new(H256::zero(), H256::zero(), H160::zero(), Some(H160::zero()), 10),
                state_updates: Default::default(),
            }];

        let changes = BlockChanges::new(
            "test".to_string(),
            Chain::Ethereum,
            evm_block(1),
            0,
            false,
            txs_with_update.clone(),
        );

        let expected = BlockChanges::new(
            "test".to_string(),
            Chain::Ethereum,
            evm_block(1),
            0,
            false,
            vec![TxWithChanges {
                account_updates: HashMap::new(),
                protocol_components: HashMap::new(),
                balance_changes: HashMap::from([(
                    "0xabc".to_string(),
                    HashMap::from([(
                        H160::from_str("0xeb91861f8a4e1c12333f42dce8fb0ecdc28da716").unwrap(),
                        ComponentBalance {
                            token: H160::from_str("0xeb91861f8a4e1c12333f42dce8fb0ecdc28da716")
                                .unwrap(),
                            balance: Bytes::from(0_i32.to_le_bytes()),
                            balance_float: 36522027799.0,
                            modify_tx: H256::from_low_u64_be(
                                0x0000000000000000000000000000000000000000000000000000000011121314,
                            ),
                            component_id: "0xd4e7c1f3da1144c9e2cfd1b015eda7652b4a4399".to_string(),
                        },
                    )]),
                )]),
                tx: Transaction::new(
                    H256::zero(),
                    H256::zero(),
                    H160::zero(),
                    Some(H160::zero()),
                    10,
                ),
                state_updates: Default::default(),
            }],
        );

        let processed = ignore_self_balances(changes);

        assert_eq!(processed, expected)
    }
}

use std::collections::HashMap;

use crate::{
    extractor::{
        evm,
        evm::utils::{parse_u256_slot_entry, TryDecode},
    },
    models::Chain,
    storage::{
        AddressRef, BalanceRef, CodeRef, ContractDelta, ContractId, ContractStore, StorableBlock,
        StorableContract, StorableTransaction, StorageError, TxHashRef,
    },
};

use chrono::NaiveDateTime;
use ethers::prelude::*;

pub mod pg {
    use ethers::abi::AbiEncode;

    use crate::storage::{postgres::orm, ChangeType};

    use super::*;

    impl From<evm::Account> for evm::AccountUpdate {
        fn from(value: evm::Account) -> Self {
            evm::AccountUpdate::new(
                value.address,
                value.chain,
                value.slots,
                Some(value.balance),
                Some(value.code),
                ChangeType::Creation,
            )
        }
    }

    impl StorableBlock<orm::Block, orm::NewBlock, i64> for evm::Block {
        fn from_storage(val: orm::Block, chain: Chain) -> Result<Self, StorageError> {
            Ok(evm::Block {
                number: val.number as u64,
                hash: H256::try_decode(val.hash.as_slice(), "block hash")
                    .map_err(StorageError::DecodeError)?,
                parent_hash: H256::try_decode(val.parent_hash.as_slice(), "parent hash")
                    .map_err(|err| StorageError::DecodeError(err.to_string()))?,
                chain,
                ts: val.ts,
            })
        }

        fn to_storage(&self, chain_id: i64) -> orm::NewBlock {
            orm::NewBlock {
                hash: Vec::from(self.hash.as_bytes()),
                parent_hash: Vec::from(self.parent_hash.as_bytes()),
                chain_id,
                main: false,
                number: self.number as i64,
                ts: self.ts,
            }
        }

        fn chain(&self) -> Chain {
            self.chain
        }
    }

    impl StorableTransaction<orm::Transaction, orm::NewTransaction, i64> for evm::Transaction {
        fn from_storage(val: orm::Transaction, block_hash: &[u8]) -> Result<Self, StorageError> {
            let to = if !val.to.is_empty() {
                Some(H160::try_decode(&val.to, "tx receiver").map_err(StorageError::DecodeError)?)
            } else {
                None
            };
            Ok(Self {
                hash: H256::try_decode(&val.hash, "tx hash").map_err(StorageError::DecodeError)?,
                block_hash: H256::try_decode(block_hash, "tx block hash")
                    .map_err(StorageError::DecodeError)?,
                from: H160::try_decode(&val.from, "tx sender")
                    .map_err(StorageError::DecodeError)?,
                to,
                index: val.index as u64,
            })
        }

        fn to_storage(&self, block_id: i64) -> orm::NewTransaction {
            let to: Vec<u8> =
                if let Some(h) = self.to { Vec::from(h.as_bytes()) } else { Vec::new() };
            orm::NewTransaction {
                hash: Vec::from(self.hash.as_bytes()),
                block_id,
                from: Vec::from(self.from.as_bytes()),
                to,
                index: self.index as i64,
            }
        }

        fn block_hash(&self) -> &[u8] {
            self.block_hash.as_bytes()
        }

        fn hash(&self) -> &[u8] {
            self.hash.as_bytes()
        }
    }

    impl StorableContract<orm::Contract, orm::NewContract, i64> for evm::Account {
        fn from_storage(
            val: orm::Contract,
            chain: Chain,
            balance_modify_tx: TxHashRef,
            code_modify_tx: TxHashRef,
            creation_tx: Option<TxHashRef>,
        ) -> Result<Self, StorageError> {
            Ok(evm::Account::new(
                chain,
                H160::try_decode(&val.account.address, "address")
                    .map_err(StorageError::DecodeError)?,
                val.account.title.clone(),
                HashMap::new(),
                U256::try_decode(&val.balance.balance, "balance")
                    .map_err(StorageError::DecodeError)?,
                val.code.code,
                H256::try_decode(&val.code.hash, "code hash").map_err(StorageError::DecodeError)?,
                H256::try_decode(balance_modify_tx, "tx hash")
                    .map_err(StorageError::DecodeError)?,
                H256::try_decode(code_modify_tx, "tx hash").map_err(StorageError::DecodeError)?,
                match creation_tx {
                    Some(v) => H256::try_decode(v, "tx hash")
                        .map(Some)
                        .map_err(StorageError::DecodeError)?,
                    _ => None,
                },
            ))
        }

        fn to_storage(
            &self,
            chain_id: i64,
            creation_ts: NaiveDateTime,
            tx_id: Option<i64>,
        ) -> orm::NewContract {
            orm::NewContract {
                title: self.title.clone(),
                address: self.address.as_bytes().to_vec(),
                chain_id,
                creation_tx: tx_id,
                created_at: Some(creation_ts),
                deleted_at: None,
                balance: self.balance.encode(),
                code: self.code.clone(),
                code_hash: self.code_hash.as_bytes().to_vec(),
            }
        }

        fn chain(&self) -> Chain {
            self.chain
        }

        fn creation_tx(&self) -> Option<TxHashRef> {
            self.creation_tx
                .as_ref()
                .map(|h| h.as_bytes())
        }

        fn address(&self) -> AddressRef {
            self.address.as_bytes()
        }

        fn store(&self) -> ContractStore {
            self.slots
                .iter()
                .map(|(s, v)| (s.encode(), Some(v.encode())))
                .collect()
        }

        fn set_store(&mut self, store: &ContractStore) -> Result<(), StorageError> {
            self.slots = store
                .iter()
                .map(|(rk, rv)| {
                    parse_u256_slot_entry(rk, rv.as_deref()).map_err(StorageError::DecodeError)
                })
                .collect::<Result<HashMap<_, _>, _>>()?;
            Ok(())
        }
    }

    impl ContractDelta for evm::AccountUpdate {
        fn contract_id(&self) -> ContractId {
            ContractId::new(self.chain, self.address.as_bytes().to_vec())
        }

        fn dirty_balance(&self) -> Option<Vec<u8>> {
            self.balance.map(|b| b.encode())
        }

        fn dirty_code(&self) -> Option<&[u8]> {
            self.code.as_deref()
        }

        fn dirty_slots(&self) -> ContractStore {
            self.slots
                .iter()
                .map(|(s, v)| (s.encode(), Some(v.encode())))
                .collect()
        }

        fn from_storage(
            chain: Chain,
            address: AddressRef,
            slots: Option<&ContractStore>,
            balance: Option<BalanceRef>,
            code: Option<CodeRef>,
            change: ChangeType,
        ) -> Result<Self, StorageError> {
            let slots = slots
                .map(|s| {
                    s.iter()
                        .map(|(s, v)| {
                            parse_u256_slot_entry(s, v.as_deref())
                                .map_err(StorageError::DecodeError)
                        })
                        .collect::<Result<HashMap<U256, U256>, StorageError>>()
                })
                .unwrap_or_else(|| Ok(HashMap::new()))?;

            let update = evm::AccountUpdate::new(
                H160::try_decode(address, "address").map_err(StorageError::DecodeError)?,
                chain,
                slots,
                match balance {
                    // match expr is required so the error can be raised
                    Some(v) => U256::try_decode(v, "balance")
                        .map(Some)
                        .map_err(|err| StorageError::DecodeError(err.to_string()))?,
                    _ => None,
                },
                code.map(|v| v.to_vec()),
                change,
            );
            Ok(update)
        }
    }
}

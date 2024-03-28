use std::collections::HashMap;

use crate::extractor::{
    evm,
    evm::{ERC20Token, ProtocolStateDelta},
};
use ethers::prelude::{H160, H256, U256};
use tycho_core::{
    models::{
        blockchain::{Block, Transaction},
        contract::{Contract, ContractDelta},
        protocol::{ComponentBalance, ProtocolComponent, ProtocolComponentStateDelta},
        token::CurrencyToken,
    },
    Bytes,
};

impl From<&evm::Block> for Block {
    fn from(value: &evm::Block) -> Self {
        Self {
            hash: Bytes::from(value.hash),
            parent_hash: Bytes::from(value.parent_hash),
            number: value.number,
            chain: value.chain,
            ts: value.ts,
        }
    }
}

// TODO: Remove once remove DB side reverts.
impl From<Block> for evm::Block {
    fn from(value: Block) -> Self {
        Self {
            number: value.number,
            hash: H256::from_slice(&value.hash),
            parent_hash: H256::from_slice(&value.parent_hash),
            chain: value.chain,
            ts: value.ts,
        }
    }
}

impl From<Transaction> for evm::Transaction {
    fn from(value: Transaction) -> Self {
        Self {
            hash: H256::from_slice(&value.hash),
            block_hash: H256::from_slice(&value.block_hash),
            from: H160::from_slice(&value.from),
            to: value
                .to
                .as_ref()
                .map(|e| H160::from_slice(e)),
            index: value.index,
        }
    }
}

impl From<&evm::Transaction> for Transaction {
    fn from(value: &evm::Transaction) -> Self {
        Self {
            hash: Bytes::from(value.hash),
            block_hash: Bytes::from(value.block_hash),
            from: Bytes::from(value.from),
            to: value.to.map(Bytes::from),
            index: value.index,
        }
    }
}

impl From<&evm::Account> for Contract {
    fn from(value: &evm::Account) -> Self {
        Self {
            chain: value.chain,
            address: Bytes::from(value.address.as_bytes()),
            title: value.title.clone(),
            slots: value
                .slots
                .clone()
                .into_iter()
                .map(|(u, v)| (Bytes::from(u), Bytes::from(v)))
                .collect(),
            native_balance: Bytes::from(value.balance),
            balances: HashMap::new(), // empty balances when converted from Account
            code: value.code.clone(),
            code_hash: Bytes::from(value.code_hash.as_bytes()),
            balance_modify_tx: Bytes::from(value.balance_modify_tx.as_bytes()),
            code_modify_tx: Bytes::from(value.code_modify_tx.as_bytes()),
            creation_tx: value
                .creation_tx
                .map(|s| Bytes::from(s.as_bytes())),
        }
    }
}

impl From<&evm::AccountUpdate> for ContractDelta {
    fn from(value: &evm::AccountUpdate) -> Self {
        Self {
            chain: value.chain,
            address: Bytes::from(value.address.as_bytes()),
            slots: value
                .slots
                .clone()
                .into_iter()
                .map(|(u, v)| (Bytes::from(u), Some(Bytes::from(v))))
                .collect(),
            balance: value.balance.map(Bytes::from),
            code: value.code.clone(),
            change: value.change,
        }
    }
}

// Temporary until evm models are phased out
impl From<ContractDelta> for evm::AccountUpdate {
    fn from(value: ContractDelta) -> Self {
        Self {
            address: H160::from_slice(&value.address),
            chain: value.chain,
            slots: value
                .slots
                .into_iter()
                .map(|(k, v)| (k.into(), v.map(Into::into).unwrap_or_default()))
                .collect(),
            balance: value.balance.map(U256::from),
            code: value.code,
            change: value.change,
        }
    }
}

impl From<&evm::ProtocolComponent> for ProtocolComponent {
    fn from(value: &evm::ProtocolComponent) -> Self {
        Self {
            id: value.id.clone(),
            protocol_system: value.protocol_system.clone(),
            protocol_type_name: value.protocol_type_name.clone(),
            chain: value.chain,
            tokens: value
                .tokens
                .iter()
                .map(|t| t.as_bytes().into())
                .collect(),
            contract_addresses: value
                .contract_ids
                .iter()
                .map(|a| a.as_bytes().into())
                .collect(),
            static_attributes: value.static_attributes.clone(),
            change: value.change,
            creation_tx: value.creation_tx.into(),
            created_at: value.created_at,
        }
    }
}

impl From<&evm::ProtocolStateDelta> for ProtocolComponentStateDelta {
    fn from(value: &ProtocolStateDelta) -> Self {
        Self {
            component_id: value.component_id.clone(),
            updated_attributes: value.updated_attributes.clone(),
            deleted_attributes: value.deleted_attributes.clone(),
        }
    }
}

impl From<&evm::ComponentBalance> for ComponentBalance {
    fn from(value: &evm::ComponentBalance) -> Self {
        Self {
            token: value.token.as_bytes().into(),
            new_balance: value.balance.clone(),
            balance_float: value.balance_float,
            modify_tx: value.modify_tx.as_bytes().into(),
            component_id: value.component_id.clone(),
        }
    }
}

impl From<&evm::ERC20Token> for CurrencyToken {
    fn from(value: &ERC20Token) -> Self {
        Self {
            address: Bytes::from(value.address.as_bytes()),
            symbol: value.symbol.clone(),
            decimals: value.decimals,
            tax: value.tax,
            gas: value.gas.clone(),
            chain: value.chain,
            quality: value.quality,
        }
    }
}

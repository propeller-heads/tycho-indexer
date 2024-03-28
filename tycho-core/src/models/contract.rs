use crate::models::{Chain, ChangeType, ContractId};
use std::collections::HashMap;

use super::{Address, Balance, Code, CodeHash, StoreKey, StoreVal, TxHash};

#[derive(Clone, Debug, PartialEq)]
pub struct Contract {
    pub chain: Chain,
    pub address: Address,
    pub title: String,
    pub slots: HashMap<StoreKey, StoreVal>,
    pub native_balance: Balance,
    pub balances: HashMap<Address, Balance>,
    pub code: Code,
    pub code_hash: CodeHash,
    pub balance_modify_tx: TxHash,
    pub code_modify_tx: TxHash,
    pub creation_tx: Option<TxHash>,
}

impl Contract {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: Chain,
        address: Address,
        title: String,
        slots: HashMap<StoreKey, StoreVal>,
        native_balance: Balance,
        balances: HashMap<Address, Balance>,
        code: Code,
        code_hash: CodeHash,
        balance_modify_tx: TxHash,
        code_modify_tx: TxHash,
        creation_tx: Option<TxHash>,
    ) -> Self {
        Self {
            chain,
            address,
            title,
            slots,
            native_balance,
            balances,
            code,
            code_hash,
            balance_modify_tx,
            code_modify_tx,
            creation_tx,
        }
    }

    pub fn set_balance(&mut self, new_balance: &Balance, modified_at: &Balance) {
        self.native_balance = new_balance.clone();
        self.balance_modify_tx = modified_at.clone();
    }
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct ContractDelta {
    pub chain: Chain,
    pub address: Address,
    pub slots: HashMap<StoreKey, Option<StoreVal>>,
    pub balance: Option<Balance>,
    pub code: Option<Code>,
    pub change: ChangeType,
}

impl ContractDelta {
    pub fn deleted(chain: &Chain, address: &Address) -> Self {
        Self {
            chain: *chain,
            address: address.clone(),
            change: ChangeType::Deletion,
            ..Default::default()
        }
    }

    pub fn new(
        chain: &Chain,
        address: &Address,
        slots: Option<&HashMap<StoreKey, Option<StoreVal>>>,
        balance: Option<&Balance>,
        code: Option<&Code>,
        change: ChangeType,
    ) -> Self {
        Self {
            chain: *chain,
            address: address.clone(),
            change,
            slots: slots.cloned().unwrap_or_default(),
            balance: balance.cloned(),
            code: code.cloned(),
        }
    }

    pub fn contract_id(&self) -> ContractId {
        ContractId::new(self.chain, self.address.clone())
    }
}

impl From<Contract> for ContractDelta {
    fn from(value: Contract) -> Self {
        Self {
            chain: value.chain,
            address: value.address,
            slots: value
                .slots
                .into_iter()
                .map(|(k, v)| (k, Some(v)))
                .collect(),
            balance: Some(value.native_balance),
            code: Some(value.code),
            change: ChangeType::Creation,
        }
    }
}

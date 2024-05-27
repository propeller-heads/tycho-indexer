use self::utils::TryDecode;
use super::{revert_buffer::StateUpdateBufferEntry, u256_num::bytes_to_f64, ExtractionError};
use crate::{
    extractor::revert_buffer::{
        AccountStateIdType, AccountStateKeyType, AccountStateValueType, ProtocolStateIdType,
        ProtocolStateKeyType, ProtocolStateValueType,
    },
    pb::tycho::evm::v1 as substreams,
};
use chrono::NaiveDateTime;
use ethers::{
    types::{H160, H256, U256},
    utils::keccak256,
};
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::Arc,
};
use tracing::log::warn;
use tycho_core::{
    dto,
    models::{
        blockchain::BlockScoped, protocol as tycho_core_protocol, token::CurrencyToken, Address,
        AttrStoreKey, Chain, ChangeType, ComponentId, ExtractorIdentity, NormalisedMessage,
        ProtocolType, StoreVal,
    },
    Bytes,
};
use utils::{pad_and_parse_32bytes, pad_and_parse_h160};

pub mod chain_state;
mod convert;
mod hybrid;
pub mod native;
pub mod protocol_cache;
pub mod token_analysis_cron;
pub mod token_pre_processor;
mod utils;
pub mod vm;

#[derive(Debug, PartialEq, Clone)]
pub struct ERC20Token {
    pub address: H160,
    pub symbol: String,
    pub decimals: u32,
    pub tax: u64,
    pub gas: Vec<Option<u64>>,
    pub chain: Chain,
    /// Quality is between 0-100, where:
    ///  - 100: Normal token
    ///  - 75: Rebase token
    ///  - 50: Fee token
    ///  - 0: Scam token that we shouldn't use
    pub quality: u32,
}

impl ERC20Token {
    pub fn new(
        address: H160,
        symbol: String,
        decimals: u32,
        tax: u64,
        gas: Vec<Option<u64>>,
        chain: Chain,
        quality: u32,
    ) -> Self {
        ERC20Token { address, symbol, decimals, tax, gas, chain, quality }
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Deserialize, Serialize, Default)]
pub struct Block {
    pub number: u64,
    pub hash: H256,
    pub parent_hash: H256,
    pub chain: Chain,
    pub ts: NaiveDateTime,
}

#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct Transaction {
    pub hash: H256,
    pub block_hash: H256,
    pub from: H160,
    pub to: Option<H160>,
    pub index: u64,
}

impl Transaction {
    pub fn new(hash: H256, block_hash: H256, from: H160, to: Option<H160>, index: u64) -> Self {
        Transaction { hash, block_hash, from, to, index }
    }

    // This serves to expose the 'try_decode' method from utils externally
    pub fn hash_from_bytes(hash: Bytes) -> H256 {
        H256::try_decode(&hash, "tx hash").expect("Failed to decode tx hash")
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct Account {
    pub chain: Chain,
    pub address: H160,
    pub title: String,
    pub slots: HashMap<U256, U256>,
    pub balance: U256,
    pub code: Bytes,
    pub code_hash: H256,
    pub balance_modify_tx: H256,
    pub code_modify_tx: H256,
    pub creation_tx: Option<H256>,
}

impl Account {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: Chain,
        address: H160,
        title: String,
        slots: HashMap<U256, U256>,
        balance: U256,
        code: Bytes,
        code_hash: H256,
        balance_modify_tx: H256,
        code_modify_tx: H256,
        creation_tx: Option<H256>,
    ) -> Self {
        Self {
            chain,
            address,
            title,
            slots,
            balance,
            code,
            code_hash,
            balance_modify_tx,
            code_modify_tx,
            creation_tx,
        }
    }

    #[cfg(test)]
    pub fn set_balance(&mut self, new_balance: U256, modified_at: H256) {
        self.balance = new_balance;
        self.balance_modify_tx = modified_at;
    }
}

impl From<&TransactionVMUpdates> for Vec<Account> {
    /// Creates a full account from a change.
    ///
    /// This can be used to get an insertable an account if we know the update
    /// is actually a creation.
    ///
    /// Assumes that all relevant changes are set on `self` if something is
    /// missing, it will use the corresponding types default.
    /// Will use the associated transaction as creation, balance and code modify
    /// transaction.
    fn from(value: &TransactionVMUpdates) -> Self {
        value
            .account_updates
            .clone()
            .into_values()
            .map(|update| {
                let acc = Account::new(
                    update.chain,
                    update.address,
                    format!("{:#020x}", update.address),
                    update.slots,
                    update.balance.unwrap_or_default(),
                    update.code.clone().unwrap_or_default(),
                    update
                        .code
                        .as_ref()
                        .map(|v| H256::from(keccak256(v)))
                        .unwrap_or_default(),
                    value.tx.hash,
                    value.tx.hash,
                    Some(value.tx.hash),
                );
                acc
            })
            .collect()
    }
}

#[derive(PartialEq, Serialize, Deserialize, Clone, Debug)]
pub struct AccountUpdate {
    pub address: H160,
    pub chain: Chain,
    pub slots: HashMap<U256, U256>,
    pub balance: Option<U256>,
    pub code: Option<Bytes>,
    pub change: ChangeType,
}

impl AccountUpdate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: H160,
        chain: Chain,
        slots: HashMap<U256, U256>,
        balance: Option<U256>,
        code: Option<Bytes>,
        change: ChangeType,
    ) -> Self {
        Self { address, chain, slots, balance, code, change }
    }

    // Converting AccountUpdate into Account with references saves us from cloning the whole
    // struct of BlockContractChanges in the forward function in ambient.rs.
    pub fn ref_into_account(&self, tx: &Transaction) -> Account {
        let empty_hash = H256::from(keccak256(Vec::new()));
        if self.change != ChangeType::Creation {
            warn!("Creating an account from a partial change!")
        }

        Account::new(
            self.chain,
            self.address,
            format!("{:#020x}", self.address),
            self.slots.clone(),
            self.balance.unwrap_or_default(),
            self.code.clone().unwrap_or_default(),
            self.code
                .as_ref()
                .map(|v| H256::from(keccak256(v)))
                .unwrap_or(empty_hash),
            tx.hash,
            tx.hash,
            Some(tx.hash),
        )
    }

    pub fn try_from_message(
        msg: substreams::ContractChange,
        chain: Chain,
    ) -> Result<Self, ExtractionError> {
        let change = msg.change().into();
        let update = AccountUpdate::new(
            pad_and_parse_h160(&msg.address.into()).map_err(ExtractionError::DecodeError)?,
            chain,
            msg.slots
                .into_iter()
                .map(|cs| {
                    Ok((
                        pad_and_parse_32bytes::<U256>(&cs.slot)
                            .map_err(ExtractionError::DecodeError)?,
                        pad_and_parse_32bytes::<U256>(&cs.value)
                            .map_err(ExtractionError::DecodeError)?,
                    ))
                })
                .collect::<Result<HashMap<_, _>, ExtractionError>>()?,
            if !msg.balance.is_empty() {
                Some(pad_and_parse_32bytes(&msg.balance).map_err(ExtractionError::DecodeError)?)
            } else {
                None
            },
            if !msg.code.is_empty() { Some(msg.code.into()) } else { None },
            change,
        );
        Ok(update)
    }

    /// Merge this update (`self`) with another one (`other`)
    ///
    /// This function is utilized for aggregating multiple updates into a single
    /// update. The attribute values of `other` are set on `self`.
    /// Meanwhile, contract storage maps are merged, in which keys from `other`
    /// take precedence.
    ///
    /// Be noted that, this function will mutate the state of the calling
    /// struct. An error will occur if merging updates from different accounts.
    ///
    /// There are no further validation checks within this method, hence it
    /// could be used as needed. However, you should give preference to
    /// utilizing [TransactionVMUpdates] for merging, when possible.
    ///
    /// # Errors
    ///
    /// It returns an `ExtractionError::MergeError` error if `self.address` and
    /// `other.address` are not identical.
    ///
    /// # Arguments
    ///
    /// * `other`: An instance of `AccountUpdate`. The attribute values and keys
    /// of `other` will overwrite those of `self`.
    fn merge(&mut self, other: AccountUpdate) -> Result<(), ExtractionError> {
        if self.address != other.address {
            return Err(ExtractionError::MergeError(format!(
                "Can't merge AccountUpdates from differing identities; Expected {:#020x}, got {:#020x}",
                self.address, other.address
            )));
        }

        self.slots.extend(other.slots);

        self.balance = other.balance.or(self.balance);
        self.code = other.code.or(self.code.take());

        Ok(())
    }

    fn is_update(&self) -> bool {
        self.change == ChangeType::Update
    }

    fn is_creation(&self) -> bool {
        self.change == ChangeType::Creation
    }
}

/// A container for account updates grouped by account.
///
/// Hold a single update per account. This is a condensed form of
/// [BlockContractChanges].
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Default)]
pub struct BlockAccountChanges {
    extractor: String,
    chain: Chain,
    pub block: Block,
    pub finalized_block_height: u64,
    pub revert: bool,
    pub account_updates: HashMap<H160, AccountUpdate>,
    pub new_tokens: HashMap<Address, CurrencyToken>,
    pub new_protocol_components: HashMap<ComponentId, ProtocolComponent>,
    pub deleted_protocol_components: HashMap<ComponentId, ProtocolComponent>,
    pub component_balances: HashMap<ComponentId, HashMap<H160, ComponentBalance>>,
    pub component_tvl: HashMap<ComponentId, f64>,
}

impl BlockAccountChanges {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        extractor: &str,
        chain: Chain,
        block: Block,
        finalized_block_height: u64,
        revert: bool,
        account_updates: HashMap<H160, AccountUpdate>,
        new_tokens: HashMap<Address, CurrencyToken>,
        new_protocol_components: HashMap<ComponentId, ProtocolComponent>,
        deleted_protocol_components: HashMap<ComponentId, ProtocolComponent>,
        component_balances: HashMap<ComponentId, HashMap<H160, ComponentBalance>>,
    ) -> Self {
        BlockAccountChanges {
            extractor: extractor.to_owned(),
            chain,
            block,
            finalized_block_height,
            revert,
            account_updates,
            new_tokens,
            new_protocol_components,
            deleted_protocol_components,
            component_balances,
            component_tvl: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.account_updates.is_empty() &&
            self.new_protocol_components.is_empty() &&
            self.deleted_protocol_components
                .is_empty() &&
            self.component_balances.is_empty() &&
            self.component_tvl.is_empty()
    }
}

impl std::fmt::Display for BlockAccountChanges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "block_number: {}, extractor: {}", self.block.number, self.extractor)
    }
}

#[typetag::serde]
impl NormalisedMessage for BlockAccountChanges {
    fn source(&self) -> ExtractorIdentity {
        ExtractorIdentity::new(self.chain, &self.extractor)
    }

    fn drop_state(&self) -> Arc<dyn NormalisedMessage> {
        Arc::new(Self {
            extractor: self.extractor.clone(),
            chain: self.chain,
            block: self.block,
            finalized_block_height: self.finalized_block_height,
            revert: self.revert,
            account_updates: HashMap::new(),
            new_tokens: self.new_tokens.clone(),
            new_protocol_components: self.new_protocol_components.clone(),
            deleted_protocol_components: self.deleted_protocol_components.clone(),
            component_balances: self.component_balances.clone(),
            component_tvl: self.component_tvl.clone(),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl std::fmt::Display for BlockEntityChangesResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "block_number: {}, extractor: {}", self.block.number, self.extractor)
    }
}

#[typetag::serde]
impl NormalisedMessage for BlockEntityChangesResult {
    fn source(&self) -> ExtractorIdentity {
        ExtractorIdentity::new(self.chain, &self.extractor)
    }

    fn drop_state(&self) -> Arc<dyn NormalisedMessage> {
        Arc::new(Self::new(
            &self.extractor,
            self.chain,
            self.block,
            self.finalized_block_height,
            self.revert,
            HashMap::new(),
            self.new_tokens.clone(),
            self.new_protocol_components.clone(),
            self.deleted_protocol_components.clone(),
            self.component_balances.clone(),
            self.component_tvl.clone(),
        ))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Updates grouped by their respective transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionVMUpdates {
    pub account_updates: HashMap<H160, AccountUpdate>,
    pub protocol_components: HashMap<ComponentId, ProtocolComponent>,
    pub component_balances: HashMap<ComponentId, HashMap<H160, ComponentBalance>>,
    pub tx: Transaction,
}

impl TransactionVMUpdates {
    pub fn new(
        account_updates: HashMap<H160, AccountUpdate>,
        protocol_components: HashMap<ComponentId, ProtocolComponent>,
        component_balances: HashMap<ComponentId, HashMap<H160, ComponentBalance>>,
        tx: Transaction,
    ) -> Self {
        Self { account_updates, protocol_components, component_balances, tx }
    }

    /// Merges this update with another one.
    ///
    /// The method combines two `AccountUpdateWithTx` instances under certain
    /// conditions:
    /// - The block from which both updates came should be the same. If the updates are from
    ///   different blocks, the method will return an error.
    /// - The transactions for each of the updates should be distinct. If they come from the same
    ///   transaction, the method will return an error.
    /// - The order of the transaction matters. The transaction from `other` must have occurred
    ///   later than the self transaction. If the self transaction has a higher index than `other`,
    ///   the method will return an error.
    ///
    /// The merged update keeps the transaction of `other`.
    ///
    /// # Errors
    /// This method will return `ExtractionError::MergeError` if any of the above
    /// conditions is violated.
    pub fn merge(&mut self, other: &TransactionVMUpdates) -> Result<(), ExtractionError> {
        if self.tx.block_hash != other.tx.block_hash {
            return Err(ExtractionError::MergeError(format!(
                "Can't merge TransactionVMUpdates from different blocks: 0x{:x} != 0x{:x}",
                self.tx.block_hash, other.tx.block_hash,
            )));
        }
        if self.tx.hash == other.tx.hash {
            return Err(ExtractionError::MergeError(format!(
                "Can't merge TransactionVMUpdates from the same transaction: 0x{:x}",
                self.tx.hash
            )));
        }
        if self.tx.index > other.tx.index {
            return Err(ExtractionError::MergeError(format!(
                "Can't merge TransactionVMUpdates with lower transaction index: {} > {}",
                self.tx.index, other.tx.index
            )));
        }
        self.tx = other.tx;

        for (address, update) in other
            .account_updates
            .clone()
            .into_iter()
        {
            match self.account_updates.entry(address) {
                Entry::Occupied(mut e) => {
                    e.get_mut().merge(update)?;
                }
                Entry::Vacant(e) => {
                    e.insert(update);
                }
            }
        }

        // Add new protocol components
        self.protocol_components
            .extend(other.protocol_components.clone());

        // Add new component balances and overwrite existing ones
        for (component_id, balance_by_token_map) in other
            .component_balances
            .clone()
            .into_iter()
        {
            // Check if the key exists in the first map
            if let Some(existing_inner_map) = self
                .component_balances
                .get_mut(&component_id)
            {
                // Iterate through the inner map and update values
                for (inner_key, value) in balance_by_token_map {
                    existing_inner_map.insert(inner_key, value);
                }
            } else {
                self.component_balances
                    .insert(component_id, balance_by_token_map);
            }
        }

        Ok(())
    }
}

/// A container for account updates grouped by transaction.
///
/// Hold the detailed state changes for a block alongside with protocol
/// component changes.
#[derive(Debug, PartialEq, Clone)]
pub struct BlockContractChanges {
    extractor: String,
    chain: Chain,
    pub block: Block,
    pub finalized_block_height: u64,
    pub revert: bool,
    /// Required here, so it is part of the revert buffer and thus inserted into storage once
    /// finalized.
    pub new_tokens: HashMap<Address, CurrencyToken>,
    /// Vec of updates at this block, aggregated by tx and sorted by tx index in ascending order
    pub tx_updates: Vec<TransactionVMUpdates>,
}

impl StateUpdateBufferEntry for BlockContractChanges {
    fn get_filtered_protocol_state_update(
        &self,
        _: Vec<(&ProtocolStateIdType, &ProtocolStateKeyType)>,
    ) -> HashMap<(ProtocolStateIdType, ProtocolStateKeyType), ProtocolStateValueType> {
        todo!()
    }

    fn get_filtered_account_state_update(
        &self,
        keys: Vec<(&AccountStateIdType, &AccountStateKeyType)>,
    ) -> HashMap<(AccountStateIdType, AccountStateKeyType), AccountStateValueType> {
        let keys_set: HashSet<_> = keys.into_iter().collect();
        let mut res = HashMap::new();

        for update in self.tx_updates.iter().rev() {
            for (address, account_update) in update.account_updates.iter() {
                for (attr, val) in account_update
                    .slots
                    .iter()
                    .filter(|(attr, _)| keys_set.contains(&(address, attr)))
                {
                    res.entry((*address, *attr))
                        .or_insert(*val);
                }
            }
        }

        res
    }

    #[allow(clippy::mutable_key_type)] // Clippy thinks that tuple with Bytes are a mutable type.
    fn get_filtered_balance_update(
        &self,
        keys: Vec<(&ComponentId, &Address)>,
    ) -> HashMap<(String, Bytes), tycho_core_protocol::ComponentBalance> {
        // Convert keys to a HashSet for faster lookups
        let keys_set: HashSet<(&String, &Bytes)> = keys.into_iter().collect();

        let mut res = HashMap::new();

        for update in self.tx_updates.iter().rev() {
            for (component_id, balance_update) in update.component_balances.iter() {
                for (token, value) in balance_update
                    .iter()
                    .filter(|(token, _)| {
                        keys_set.contains(&(component_id, &token.as_bytes().into()))
                    })
                {
                    res.entry((component_id.clone(), token.as_bytes().into()))
                        .or_insert(value.into());
                }
            }
        }

        res
    }
}

impl BlockScoped for BlockContractChanges {
    fn block(&self) -> tycho_core::models::blockchain::Block {
        (&self.block).into()
    }
}

impl Block {
    /// Parses block from tychos protobuf block message
    pub fn try_from_message(msg: substreams::Block, chain: Chain) -> Result<Self, ExtractionError> {
        Ok(Self {
            chain,
            number: msg.number,
            hash: pad_and_parse_32bytes(&msg.hash).map_err(ExtractionError::DecodeError)?,
            parent_hash: pad_and_parse_32bytes(&msg.parent_hash)
                .map_err(ExtractionError::DecodeError)?,
            ts: NaiveDateTime::from_timestamp_opt(msg.ts as i64, 0).ok_or_else(|| {
                ExtractionError::DecodeError(format!(
                    "Failed to convert timestamp {} to datetime!",
                    msg.ts
                ))
            })?,
        })
    }
}

impl Transaction {
    /// Parses transaction from tychos protobuf transaction message
    pub fn try_from_message(
        msg: substreams::Transaction,
        block_hash: &H256,
    ) -> Result<Self, ExtractionError> {
        let to = if !msg.to.is_empty() {
            Some(pad_and_parse_h160(&msg.to.into()).map_err(ExtractionError::DecodeError)?)
        } else {
            None
        };
        Ok(Self {
            hash: pad_and_parse_32bytes(&msg.hash).map_err(ExtractionError::DecodeError)?,
            block_hash: *block_hash,
            from: pad_and_parse_h160(&msg.from.into()).map_err(ExtractionError::DecodeError)?,
            to,
            index: msg.index,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ComponentBalance {
    pub token: H160,
    pub balance: Bytes,
    /// the balance as a float value, its main usage is to allow for fast queries and tvl
    /// calculation. Not available for backward revert deltas. In this case the balance will be
    /// NaN.
    pub balance_float: f64,
    // tx where the this balance was observed
    pub modify_tx: H256,
    pub component_id: ComponentId,
}

impl From<ComponentBalance> for dto::ComponentBalance {
    fn from(value: ComponentBalance) -> Self {
        Self {
            token: value.token.into(),
            balance: value.balance,
            balance_float: value.balance_float,
            modify_tx: value.modify_tx.into(),
            component_id: value.component_id,
        }
    }
}

impl ComponentBalance {
    pub fn try_from_message(
        msg: substreams::BalanceChange,
        tx: &Transaction,
    ) -> Result<Self, ExtractionError> {
        let balance_float = bytes_to_f64(&msg.balance).unwrap_or(f64::NAN);
        Ok(Self {
            token: pad_and_parse_h160(&msg.token.into()).map_err(ExtractionError::DecodeError)?,
            balance: Bytes::from(msg.balance),
            balance_float,
            modify_tx: tx.hash,
            component_id: String::from_utf8(msg.component_id)
                .map_err(|error| ExtractionError::DecodeError(error.to_string()))?,
        })
    }
}

/// Represents the static parts of a protocol component.
///
/// `ProtocolComponent` provides detailed descriptions of the functionalities a protocol,
/// for example, swap pools that enables the exchange of two tokens.
///
/// A `ProtocolComponent` can be associated with an `Account`, and it has an identifier (`id`) that
/// can be either the on-chain address or a custom one. It belongs to a specific `ProtocolSystem`
/// and has a `ProtocolTypeID` that associates it with a `ProtocolType` that describes its behaviour
/// e.g., swap, lend, bridge. The component is associated with a specific `Chain` and holds
/// information about tradable tokens, related contract IDs, and static attributes.
///
/// A `ProtocolComponent` can have a one-to-one or one-to-many relationship with contracts.
/// For example, `UniswapV2` and `UniswapV3` have a one-to-one relationship one component (pool) one
/// contract, while `Ambient` has a one-to-many relationship with a single component and multiple
/// contracts.
///
/// The `ProtocolComponent` struct is designed to store static attributes related to the associated
/// smart contract.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
pub struct ProtocolComponent {
    /// Is the unique identifier of a contract. It can represent an on-chain
    /// address or in the case of a one-to-many relationship it could be something like
    /// 'USDC-ETH'. This is for example the case with ambient, where one contract is
    /// responsible for multiple components.
    pub id: ComponentId,
    // what system this component belongs to
    pub protocol_system: String,
    // more metadata information about the components general type (swap, lend, bridge, etc.)
    pub protocol_type_name: String,
    // blockchain the component belongs to
    pub chain: Chain,
    // ids of the tokens tradable
    pub tokens: Vec<H160>,
    // addresses of the related contracts
    pub contract_ids: Vec<H160>,
    // stores the static attributes
    pub static_attributes: HashMap<AttrStoreKey, StoreVal>,
    // the type of change (creation, deletion etc)
    pub change: ChangeType,
    // Hash of the transaction in which the component got created
    pub creation_tx: H256,
    // Time at which the component got created
    pub created_at: NaiveDateTime,
}

impl ProtocolComponent {
    pub fn try_from_message(
        msg: substreams::ProtocolComponent,
        chain: Chain,
        protocol_system: &str,
        protocol_types: &HashMap<String, ProtocolType>,
        tx_hash: H256,
        creation_ts: NaiveDateTime,
    ) -> Result<Self, ExtractionError> {
        let tokens = msg
            .tokens
            .clone()
            .into_iter()
            .map(|t| pad_and_parse_h160(&t.into()).map_err(ExtractionError::DecodeError))
            .collect::<Result<Vec<_>, ExtractionError>>()?;

        let contract_ids = msg
            .contracts
            .clone()
            .into_iter()
            .map(|c| pad_and_parse_h160(&c.into()).map_err(ExtractionError::DecodeError))
            .collect::<Result<Vec<_>, ExtractionError>>()?;

        let static_attributes = msg
            .static_att
            .clone()
            .into_iter()
            .map(|attribute| Ok((attribute.name, Bytes::from(attribute.value))))
            .collect::<Result<HashMap<_, _>, ExtractionError>>()?;

        let protocol_type = msg
            .protocol_type
            .clone()
            .ok_or(ExtractionError::DecodeError("Missing protocol type".to_owned()))?;

        if !protocol_types.contains_key(&protocol_type.name) {
            return Err(ExtractionError::DecodeError(format!(
                "Unknown protocol type name: {}",
                protocol_type.name
            )));
        }

        Ok(Self {
            id: msg.id.clone(),
            protocol_type_name: protocol_type.name,
            protocol_system: protocol_system.to_owned(),
            tokens,
            contract_ids,
            static_attributes,
            chain,
            change: msg.change().into(),
            creation_tx: tx_hash,
            created_at: creation_ts,
        })
    }

    pub fn get_byte_contract_addresses(&self) -> Vec<Address> {
        self.contract_ids
            .iter()
            .map(|t| Address::from(t.0))
            .collect()
    }

    pub fn get_byte_token_addresses(&self) -> Vec<Address> {
        self.tokens
            .iter()
            .map(|t| Address::from(t.0))
            .collect()
    }
}

impl From<substreams::ChangeType> for ChangeType {
    fn from(value: substreams::ChangeType) -> Self {
        match value {
            substreams::ChangeType::Unspecified => {
                panic!("Unkown enum member encountered: {:?}", value)
            }
            substreams::ChangeType::Update => ChangeType::Update,
            substreams::ChangeType::Creation => ChangeType::Creation,
            substreams::ChangeType::Deletion => ChangeType::Deletion,
        }
    }
}

impl BlockContractChanges {
    pub fn new(
        extractor: String,
        chain: Chain,
        block: Block,
        finalized_block_height: u64,
        revert: bool,
        tx_updates: Vec<TransactionVMUpdates>,
    ) -> Self {
        BlockContractChanges {
            extractor,
            chain,
            block,
            finalized_block_height,
            revert,
            new_tokens: HashMap::new(),
            tx_updates,
        }
    }
    /// Parse from tychos protobuf message
    pub fn try_from_message(
        msg: substreams::BlockContractChanges,
        extractor: &str,
        chain: Chain,
        protocol_system: String,
        protocol_types: &HashMap<String, ProtocolType>,
        finalized_block_height: u64,
    ) -> Result<Self, ExtractionError> {
        if let Some(block) = msg.block {
            let block = Block::try_from_message(block, chain)?;
            let mut tx_updates = Vec::new();

            for change in msg.changes.into_iter() {
                let mut account_updates = HashMap::new();
                let mut protocol_components = HashMap::new();
                let mut balances_changes: HashMap<ComponentId, HashMap<H160, ComponentBalance>> =
                    HashMap::new();

                if let Some(tx) = change.tx {
                    let tx = Transaction::try_from_message(tx, &block.hash)?;
                    for el in change.contract_changes.into_iter() {
                        let update = AccountUpdate::try_from_message(el, chain)?;
                        account_updates.insert(update.address, update);
                    }
                    for component_msg in change.component_changes.into_iter() {
                        let component = ProtocolComponent::try_from_message(
                            component_msg,
                            chain,
                            &protocol_system,
                            protocol_types,
                            tx.hash,
                            block.ts,
                        )?;
                        protocol_components.insert(component.id.clone(), component);
                    }

                    for balance_change in change.balance_changes.into_iter() {
                        let component_id =
                            String::from_utf8(balance_change.component_id.clone())
                                .map_err(|error| ExtractionError::DecodeError(error.to_string()))?;
                        let token_address = H160::from_slice(balance_change.token.as_slice());
                        let balance = ComponentBalance::try_from_message(balance_change, &tx)?;

                        balances_changes
                            .entry(component_id)
                            .or_default()
                            .insert(token_address, balance);
                    }

                    tx_updates.push(TransactionVMUpdates::new(
                        account_updates,
                        protocol_components,
                        balances_changes,
                        tx,
                    ));
                }
            }
            tx_updates.sort_unstable_by_key(|update| update.tx.index);
            return Ok(Self {
                extractor: extractor.to_owned(),
                chain,
                block,
                finalized_block_height,
                revert: false,
                new_tokens: HashMap::new(),
                tx_updates,
            });
        }
        Err(ExtractionError::Empty)
    }

    /// Aggregates transaction updates.
    ///
    /// This function aggregates the transaction updates (`tx_updates`) from
    /// different accounts into a single object of  
    /// `BlockAccountChanges`. It maintains a HashMap to hold
    /// `AccountUpdate` corresponding to each unique address.
    ///
    /// If the address from an update is already present in the HashMap, it
    /// merges the update with the existing one. Otherwise, it inserts the new
    /// update into the HashMap.
    ///
    /// After merging all updates, a `BlockAccountChanges` object is returned
    /// which contains, amongst other data, the compacted account updates.
    ///
    /// # Errors
    ///
    /// This returns an error if there was a problem during merge. The error
    /// type is `ExtractionError`.
    pub fn aggregate_updates(self) -> Result<BlockAccountChanges, ExtractionError> {
        let (account_updates, protocol_components, component_balances) = if !self
            .tx_updates
            .is_empty()
        {
            let mut sorted_tx_updates = self.tx_updates.clone();
            sorted_tx_updates.sort_unstable_by_key(|update| update.tx.index);
            let mut tx_update = sorted_tx_updates
                .first()
                .cloned()
                .ok_or(ExtractionError::Empty)?;

            for update in sorted_tx_updates.into_iter().skip(1) {
                tx_update.merge(&update.clone())?;
            }
            (tx_update.account_updates, tx_update.protocol_components, tx_update.component_balances)
        } else {
            (HashMap::new(), HashMap::new(), HashMap::new())
        };

        Ok(BlockAccountChanges::new(
            &self.extractor,
            self.chain,
            self.block,
            self.finalized_block_height,
            self.revert,
            account_updates,
            self.new_tokens,
            protocol_components,
            HashMap::new(),
            component_balances,
        ))
    }

    pub fn protocol_components(&self) -> Vec<ProtocolComponent> {
        self.tx_updates
            .iter()
            .flat_map(|tx_u| {
                tx_u.protocol_components
                    .values()
                    .cloned()
            })
            .collect()
    }
}

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
/// Represents a change in protocol state.
pub struct ProtocolStateDelta {
    // associates back to a component, which has metadata like type, tokens, etc.
    pub component_id: ComponentId,
    // the update protocol specific attributes, validated by the components schema
    pub updated_attributes: HashMap<AttrStoreKey, StoreVal>,
    // the deleted protocol specific attributes
    pub deleted_attributes: HashSet<AttrStoreKey>,
}

impl ProtocolStateDelta {
    pub fn new(component_id: ComponentId, attributes: HashMap<AttrStoreKey, StoreVal>) -> Self {
        Self { component_id, updated_attributes: attributes, deleted_attributes: HashSet::new() }
    }

    /// Parses protocol state from tychos protobuf EntityChanges message
    pub fn try_from_message(msg: substreams::EntityChanges) -> Result<Self, ExtractionError> {
        let (mut updates, mut deletions) = (HashMap::new(), HashSet::new());

        for attribute in msg.attributes.into_iter() {
            match attribute.change().into() {
                ChangeType::Update | ChangeType::Creation => {
                    updates.insert(attribute.name, Bytes::from(attribute.value));
                }
                ChangeType::Deletion => {
                    deletions.insert(attribute.name);
                }
            }
        }

        Ok(Self {
            component_id: msg.component_id,
            updated_attributes: updates,
            deleted_attributes: deletions,
        })
    }

    /// Merges this update with another one.
    ///
    /// The method combines two `ProtocolStateDelta` instances if they are for the same
    /// protocol component.
    ///
    /// NB: It is assumed that `other` is a more recent update than `self` is and the two are
    /// combined accordingly.
    ///
    /// # Errors
    /// This method will return `ExtractionError::MergeError` if any of the above
    /// conditions is violated.
    pub fn merge(&mut self, other: ProtocolStateDelta) -> Result<(), ExtractionError> {
        if self.component_id != other.component_id {
            return Err(ExtractionError::MergeError(format!(
                "Can't merge ProtocolStates from differing identities; Expected {}, got {}",
                self.component_id, other.component_id
            )));
        }
        for attr in &other.deleted_attributes {
            self.updated_attributes.remove(attr);
        }
        for attr in other.updated_attributes.keys() {
            self.deleted_attributes.remove(attr);
        }
        self.updated_attributes
            .extend(other.updated_attributes);
        self.deleted_attributes
            .extend(other.deleted_attributes);
        Ok(())
    }
}

/// Updates grouped by their respective transaction.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProtocolChangesWithTx {
    pub new_protocol_components: HashMap<ComponentId, ProtocolComponent>,
    pub protocol_states: HashMap<ComponentId, ProtocolStateDelta>,
    pub balance_changes: HashMap<ComponentId, HashMap<H160, ComponentBalance>>,
    pub tx: Transaction,
}

impl ProtocolChangesWithTx {
    /// Parses protocol state from tychos protobuf EntityChanges message
    pub fn try_from_message(
        msg: substreams::TransactionEntityChanges,
        block: &Block,
        protocol_system: &str,
        protocol_types: &HashMap<String, ProtocolType>,
    ) -> Result<Self, ExtractionError> {
        let tx = Transaction::try_from_message(
            msg.tx
                .expect("TransactionEntityChanges should have a transaction"),
            &block.hash,
        )?;

        let mut new_protocol_components: HashMap<String, ProtocolComponent> = HashMap::new();
        let mut state_updates: HashMap<String, ProtocolStateDelta> = HashMap::new();
        let mut component_balances: HashMap<String, HashMap<H160, ComponentBalance>> =
            HashMap::new();

        // First, parse the new protocol components
        for change in msg.component_changes.into_iter() {
            let component = ProtocolComponent::try_from_message(
                change.clone(),
                block.chain,
                protocol_system,
                protocol_types,
                tx.hash,
                block.ts,
            )?;
            new_protocol_components.insert(change.id, component);
        }

        // Then, parse the state updates
        for state_msg in msg.entity_changes.into_iter() {
            let state = ProtocolStateDelta::try_from_message(state_msg)?;
            // Check if a state update for the same component already exists
            // If it exists, overwrite the existing state update with the new one and log a warning
            match state_updates.entry(state.component_id.clone()) {
                Entry::Vacant(e) => {
                    e.insert(state);
                }
                Entry::Occupied(mut e) => {
                    warn!("Received two state updates for the same component. Overwriting state for component {}", e.key());
                    e.insert(state);
                }
            }
        }

        // Finally, parse the balance changes
        for balance_change in msg.balance_changes.into_iter() {
            let component_balance = ComponentBalance::try_from_message(balance_change, &tx)?;

            // Check if a balance change for the same token and component already exists
            // If it exists, overwrite the existing balance change with the new one and log a
            // warning
            let token_balances = component_balances
                .entry(component_balance.component_id.clone())
                .or_default();

            if let Some(existing_balance) =
                token_balances.insert(component_balance.token, component_balance)
            {
                warn!(
                    "Received two balance updates for the same component id: {} and token {}. Overwriting balance change",
                    existing_balance.component_id, existing_balance.token
                );
            }
        }

        Ok(Self {
            new_protocol_components,
            protocol_states: state_updates,
            balance_changes: component_balances,
            tx,
        })
    }

    /// Merges this update with another one.
    ///
    /// The method combines two `ProtocolStatesWithTx` instances under certain
    /// conditions:
    /// - The block from which both updates came should be the same. If the updates are from
    ///   different blocks, the method will return an error.
    /// - The transactions for each of the updates should be distinct. If they come from the same
    ///   transaction, the method will return an error.
    /// - The order of the transaction matters. The transaction from `other` must have occurred
    ///   later than the self transaction. If the self transaction has a higher index than `other`,
    ///   the method will return an error.
    ///
    /// The merged update keeps the transaction of `other`.
    ///
    /// # Errors
    /// This method will return `ExtractionError::MergeError` if any of the above
    /// conditions is violated.
    pub fn merge(&mut self, other: ProtocolChangesWithTx) -> Result<(), ExtractionError> {
        dbg!("Called merge");
        if self.tx.block_hash != other.tx.block_hash {
            return Err(ExtractionError::MergeError(format!(
                "Can't merge ProtocolStates from different blocks: 0x{:x} != 0x{:x}",
                self.tx.block_hash, other.tx.block_hash,
            )));
        }
        if self.tx.hash == other.tx.hash {
            return Err(ExtractionError::MergeError(format!(
                "Can't merge ProtocolStates from the same transaction: 0x{:x}",
                self.tx.hash
            )));
        }
        if self.tx.index > other.tx.index {
            return Err(ExtractionError::MergeError(format!(
                "Can't merge ProtocolStates with lower transaction index: {} > {}",
                self.tx.index, other.tx.index
            )));
        }
        self.tx = other.tx;
        // Merge protocol states
        for (key, value) in other.protocol_states {
            match self.protocol_states.entry(key) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().merge(value)?;
                }
                Entry::Vacant(entry) => {
                    entry.insert(value);
                }
            }
        }

        // Merge token balances
        for (component_id, balance_changes) in other.balance_changes {
            let token_balances = self
                .balance_changes
                .entry(component_id)
                .or_default();
            for (token, balance) in balance_changes {
                token_balances.insert(token, balance);
            }
        }

        // Merge new protocol components
        // Log a warning if a new protocol component for the same id already exists, because this
        // should never happen.
        for (key, value) in other.new_protocol_components {
            match self.new_protocol_components.entry(key) {
                Entry::Occupied(mut entry) => {
                    warn!(
                        "Overwriting new protocol component for id {} with a new one. This should never happen! Please check logic",
                        entry.get().id
                    );
                    entry.insert(value);
                }
                Entry::Vacant(entry) => {
                    entry.insert(value);
                }
            }
        }

        Ok(())
    }
}

/// A container for state updates grouped by protocol component.
///
/// Hold a single update per component. This is a condensed form of
/// [BlockEntityChanges].
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Default)]
pub struct BlockEntityChangesResult {
    extractor: String,
    chain: Chain,
    pub block: Block,
    pub finalized_block_height: u64,
    pub revert: bool,
    pub state_updates: HashMap<String, ProtocolStateDelta>,
    pub new_tokens: HashMap<Address, CurrencyToken>,
    pub new_protocol_components: HashMap<String, ProtocolComponent>,
    pub deleted_protocol_components: HashMap<String, ProtocolComponent>,
    pub component_balances: HashMap<String, HashMap<H160, ComponentBalance>>,
    pub component_tvl: HashMap<String, f64>,
}

impl BlockEntityChangesResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        extractor: &str,
        chain: Chain,
        block: Block,
        finalized_block_height: u64,
        revert: bool,
        state_updates: HashMap<String, ProtocolStateDelta>,
        new_tokens: HashMap<Address, CurrencyToken>,
        new_protocol_components: HashMap<String, ProtocolComponent>,
        deleted_protocol_components: HashMap<String, ProtocolComponent>,
        component_balances: HashMap<String, HashMap<H160, ComponentBalance>>,
        component_tvl: HashMap<String, f64>,
    ) -> Self {
        Self {
            extractor: extractor.to_string(),
            chain,
            block,
            finalized_block_height,
            revert,
            state_updates,
            new_tokens,
            new_protocol_components,
            deleted_protocol_components,
            component_balances,
            component_tvl,
        }
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.state_updates.is_empty() &&
            self.new_protocol_components.is_empty() &&
            self.deleted_protocol_components
                .is_empty() &&
            self.component_balances.is_empty() &&
            self.component_tvl.is_empty()
    }
}

/// A container for state updates grouped by transaction
///
/// Hold the detailed state changes for a block alongside with protocol
/// component changes.
#[derive(Debug, PartialEq, Default, Clone)]
pub struct BlockEntityChanges {
    extractor: String,
    chain: Chain,
    pub block: Block,
    pub finalized_block_height: u64,
    pub revert: bool,
    /// Required here, so it is part of the revert buffer and thus inserted into storage once
    /// finalized.
    pub new_tokens: HashMap<Address, CurrencyToken>,
    /// Vec of updates at this block, aggregated by tx and sorted by tx index in ascending order
    pub txs_with_update: Vec<ProtocolChangesWithTx>,
}

impl StateUpdateBufferEntry for BlockEntityChanges {
    fn get_filtered_protocol_state_update(
        &self,
        keys: Vec<(&ProtocolStateIdType, &ProtocolStateKeyType)>,
    ) -> HashMap<(ProtocolStateIdType, ProtocolStateKeyType), ProtocolStateValueType> {
        // Convert keys to a HashSet for faster lookups
        let keys_set: HashSet<(&ComponentId, &AttrStoreKey)> = keys.into_iter().collect();
        let mut res = HashMap::new();

        for update in self.txs_with_update.iter().rev() {
            for (component_id, protocol_update) in update.protocol_states.iter() {
                for (attr, val) in protocol_update
                    .updated_attributes
                    .iter()
                    .filter(|(attr, _)| keys_set.contains(&(component_id, attr)))
                {
                    res.entry((component_id.clone(), attr.clone()))
                        .or_insert(val.clone());
                }
            }
        }

        res
    }

    fn get_filtered_account_state_update(
        &self,
        _: Vec<(&AccountStateIdType, &AccountStateKeyType)>,
    ) -> HashMap<(AccountStateIdType, AccountStateKeyType), AccountStateValueType> {
        todo!()
    }

    #[allow(clippy::mutable_key_type)] // Clippy thinks that tuple with Bytes are a mutable type.
    fn get_filtered_balance_update(
        &self,
        keys: Vec<(&ComponentId, &Address)>,
    ) -> HashMap<(String, Bytes), tycho_core_protocol::ComponentBalance> {
        // Convert keys to a HashSet for faster lookups
        let keys_set: HashSet<(&String, &Bytes)> = keys.into_iter().collect();

        let mut res = HashMap::new();

        for update in self.txs_with_update.iter().rev() {
            for (component_id, protocol_update) in update.balance_changes.iter() {
                for (token, value) in protocol_update
                    .iter()
                    .filter(|(token, _)| {
                        keys_set.contains(&(component_id, &token.as_bytes().into()))
                    })
                {
                    res.entry((component_id.clone(), token.as_bytes().into()))
                        .or_insert(value.into());
                }
            }
        }

        res
    }
}

impl BlockScoped for BlockEntityChanges {
    fn block(&self) -> tycho_core::models::blockchain::Block {
        (&self.block).into()
    }
}

impl BlockEntityChanges {
    pub fn new(
        extractor: String,
        chain: Chain,
        block: Block,
        finalized_block_height: u64,
        revert: bool,
        txs_with_update: Vec<ProtocolChangesWithTx>,
    ) -> Self {
        BlockEntityChanges {
            extractor,
            chain,
            block,
            finalized_block_height,
            revert,
            new_tokens: HashMap::new(),
            txs_with_update,
        }
    }
    /// Parse from tychos protobuf message
    pub fn try_from_message(
        msg: substreams::BlockEntityChanges,
        extractor: &str,
        chain: Chain,
        protocol_system: &str,
        protocol_types: &HashMap<String, ProtocolType>,
        finalized_block_height: u64,
    ) -> Result<Self, ExtractionError> {
        if let Some(block) = msg.block {
            let block = Block::try_from_message(block, chain)?;

            let mut txs_with_update = msg
                .changes
                .into_iter()
                .map(|change| {
                    change.tx.as_ref().ok_or_else(|| {
                        ExtractionError::DecodeError(
                            "TransactionEntityChanges misses a transaction".to_owned(),
                        )
                    })?;

                    ProtocolChangesWithTx::try_from_message(
                        change,
                        &block,
                        protocol_system,
                        protocol_types,
                    )
                })
                .collect::<Result<Vec<ProtocolChangesWithTx>, ExtractionError>>()?;

            // Sort updates by transaction index
            txs_with_update.sort_unstable_by_key(|update| update.tx.index);

            Ok(Self {
                extractor: extractor.to_string(),
                chain,
                block,
                finalized_block_height,
                revert: false,
                new_tokens: HashMap::new(),
                txs_with_update,
            })
        } else {
            Err(ExtractionError::Empty)
        }
    }

    /// Aggregates state updates.
    ///
    /// This function aggregates the protocol updates (`ProtocolStateDelta` and `ComponentBalance`)
    /// for different protocol components into a `BlockEntityChangesResult` object.
    /// This new object should have only one final ProtocolStateDelta per component_id.
    ///
    /// After merging all updates, a `BlockEntityChangesResult` object is returned
    /// which contains, amongst other data, the compacted state updates.
    ///
    /// # Errors
    ///
    /// This returns an error if there was a problem during merge. The error
    /// type is `ExtractionError`.
    pub fn aggregate_updates(self) -> Result<BlockEntityChangesResult, ExtractionError> {
        let mut iter = self.txs_with_update.into_iter();

        // Use unwrap_or_else to provide a default state if iter.next() is None
        let first_state = iter.next().unwrap_or_default();

        let aggregated_changes = iter
            .try_fold(first_state, |mut acc_state, new_state| {
                acc_state.merge(new_state.clone())?;
                Ok::<_, ExtractionError>(acc_state.clone())
            })
            .unwrap();

        Ok(BlockEntityChangesResult {
            extractor: self.extractor,
            chain: self.chain,
            block: self.block,
            finalized_block_height: self.finalized_block_height,
            revert: self.revert,
            state_updates: aggregated_changes.protocol_states,
            new_tokens: self.new_tokens,
            new_protocol_components: aggregated_changes.new_protocol_components,
            deleted_protocol_components: HashMap::new(),
            component_balances: aggregated_changes.balance_changes,
            component_tvl: HashMap::new(),
        })
    }

    pub fn protocol_components(&self) -> Vec<ProtocolComponent> {
        self.txs_with_update
            .iter()
            .flat_map(|tx_u| {
                tx_u.new_protocol_components
                    .values()
                    .cloned()
            })
            .collect()
    }
}

/// Changes grouped by their respective transaction.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TxWithChanges {
    pub protocol_components: HashMap<ComponentId, ProtocolComponent>,
    pub account_updates: HashMap<H160, AccountUpdate>,
    pub protocol_states: HashMap<ComponentId, ProtocolStateDelta>,
    pub balance_changes: HashMap<ComponentId, HashMap<H160, ComponentBalance>>,
    pub tx: Transaction,
}

impl TxWithChanges {
    pub fn new(
        protocol_components: HashMap<ComponentId, ProtocolComponent>,
        account_updates: HashMap<H160, AccountUpdate>,
        protocol_states: HashMap<ComponentId, ProtocolStateDelta>,
        balance_changes: HashMap<ComponentId, HashMap<H160, ComponentBalance>>,
        tx: Transaction,
    ) -> Self {
        Self { account_updates, protocol_components, protocol_states, balance_changes, tx }
    }

    fn try_from_message(
        msg: substreams::TransactionChanges,
        block: &Block,
        protocol_system: &str,
        protocol_types: &HashMap<String, ProtocolType>,
    ) -> Result<Self, ExtractionError> {
        let tx = Transaction::try_from_message(
            msg.tx
                .expect("TransactionChanges should have a transaction"),
            &block.hash,
        )?;

        let mut new_protocol_components: HashMap<String, ProtocolComponent> = HashMap::new();
        let mut account_updates: HashMap<H160, AccountUpdate> = HashMap::new();
        let mut state_updates: HashMap<String, ProtocolStateDelta> = HashMap::new();
        let mut balance_changes: HashMap<String, HashMap<H160, ComponentBalance>> = HashMap::new();

        // First, parse the new protocol components
        for change in msg.component_changes.into_iter() {
            let component = ProtocolComponent::try_from_message(
                change,
                block.chain,
                protocol_system,
                protocol_types,
                tx.hash,
                block.ts,
            )?;
            new_protocol_components.insert(component.id.clone(), component);
        }

        // Then, parse the account updates
        for el in msg.contract_changes.into_iter() {
            let update = AccountUpdate::try_from_message(el, block.chain)?;
            account_updates.insert(update.address, update);
        }

        // Then, parse the state updates
        for state_msg in msg.entity_changes.into_iter() {
            let state = ProtocolStateDelta::try_from_message(state_msg)?;
            // Check if a state update for the same component already exists
            // If it exists, overwrite the existing state update with the new one and log a warning
            match state_updates.entry(state.component_id.clone()) {
                Entry::Vacant(e) => {
                    e.insert(state);
                }
                Entry::Occupied(mut e) => {
                    warn!("Received two state updates for the same component. Overwriting state for component {}", e.key());
                    e.insert(state);
                }
            }
        }

        // Finally, parse the balance changes
        for balance_change in msg.balance_changes.into_iter() {
            let component_id = String::from_utf8(balance_change.component_id.clone())
                .map_err(|error| ExtractionError::DecodeError(error.to_string()))?;
            let token_address = H160::from_slice(balance_change.token.as_slice());
            let balance = ComponentBalance::try_from_message(balance_change, &tx)?;

            balance_changes
                .entry(component_id)
                .or_default()
                .insert(token_address, balance);
        }

        Ok(Self {
            protocol_components: new_protocol_components,
            account_updates,
            protocol_states: state_updates,
            balance_changes,
            tx,
        })
    }

    /// Merges this update with another one.
    ///
    /// The method combines two `ChangesWithTx` instances if they are for the same
    /// transaction.
    ///
    /// NB: It is assumed that `other` is a more recent update than `self` is and the two are
    /// combined accordingly.
    ///
    /// # Errors
    /// This method will return `ExtractionError::MergeError` if any of the above
    /// conditions is violated.
    pub fn merge(&mut self, other: TxWithChanges) -> Result<(), ExtractionError> {
        dbg!("Called merge");

        if self.tx.block_hash != other.tx.block_hash {
            return Err(ExtractionError::MergeError(format!(
                "Can't merge ProtocolStates from different blocks: 0x{:x} != 0x{:x}",
                self.tx.block_hash, other.tx.block_hash,
            )));
        }
        if self.tx.hash != other.tx.hash {
            return Err(ExtractionError::MergeError(format!(
                "Can't merge ChangesWithTx from different transactions: 0x{:x} != 0x{:x}",
                self.tx.hash, other.tx.hash,
            )));
        }
        if self.tx.index > other.tx.index {
            return Err(ExtractionError::MergeError(format!(
                "Can't merge ProtocolStates with lower transaction index: {} > {}",
                self.tx.index, other.tx.index
            )));
        }

        self.tx = other.tx;

        // Merge new protocol components
        // Log a warning if a new protocol component for the same id already exists, because this
        // should never happen.
        for (key, value) in other.protocol_components {
            match self.protocol_components.entry(key) {
                Entry::Occupied(mut entry) => {
                    warn!(
                        "Overwriting new protocol component for id {} with a new one. This should never happen! Please check logic",
                        entry.get().id
                    );
                    entry.insert(value);
                }
                Entry::Vacant(entry) => {
                    entry.insert(value);
                }
            }
        }

        // Merge Account Updates
        for (address, update) in other
            .account_updates
            .clone()
            .into_iter()
        {
            match self.account_updates.entry(address) {
                Entry::Occupied(mut e) => {
                    e.get_mut().merge(update)?;
                }
                Entry::Vacant(e) => {
                    e.insert(update);
                }
            }
        }

        // Merge Protocol States
        for (key, value) in other.protocol_states {
            match self.protocol_states.entry(key) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().merge(value)?;
                }
                Entry::Vacant(entry) => {
                    entry.insert(value);
                }
            }
        }

        // Merge Balance Changes
        for (component_id, balance_changes) in other.balance_changes {
            let token_balances = self
                .balance_changes
                .entry(component_id)
                .or_default();
            for (token, balance) in balance_changes {
                token_balances.insert(token, balance);
            }
        }
        Ok(())
    }
}

/// A container for updates grouped by protocol component.
///
/// Hold a single update per component. This is a condensed form of
/// [BlockChanges].
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Default)]
pub struct BlockChangesResult {
    extractor: String,
    chain: Chain,
    pub block: Block,
    pub finalized_block_height: u64,
    pub revert: bool,
    pub new_protocol_components: HashMap<ComponentId, ProtocolComponent>,
    pub new_tokens: HashMap<Address, CurrencyToken>,
    pub deleted_protocol_components: HashMap<ComponentId, ProtocolComponent>,
    pub protocol_states: HashMap<ComponentId, ProtocolStateDelta>,
    pub account_updates: HashMap<H160, AccountUpdate>,
    pub component_balances: HashMap<ComponentId, HashMap<H160, ComponentBalance>>,
    pub component_tvl: HashMap<ComponentId, f64>,
}

impl BlockChangesResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        extractor: &str,
        chain: Chain,
        block: Block,
        finalized_block_height: u64,
        revert: bool,
        new_protocol_components: HashMap<ComponentId, ProtocolComponent>,
        new_tokens: HashMap<Address, CurrencyToken>,
        deleted_protocol_components: HashMap<ComponentId, ProtocolComponent>,
        protocol_states: HashMap<ComponentId, ProtocolStateDelta>,
        account_updates: HashMap<H160, AccountUpdate>,
        component_balances: HashMap<ComponentId, HashMap<H160, ComponentBalance>>,
    ) -> Self {
        Self {
            extractor: extractor.to_string(),
            chain,
            block,
            finalized_block_height,
            revert,
            new_protocol_components,
            new_tokens,
            deleted_protocol_components,
            protocol_states,
            account_updates,
            component_balances,
            component_tvl: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.new_protocol_components.is_empty() &&
            self.deleted_protocol_components
                .is_empty() &&
            self.protocol_states.is_empty() &&
            self.account_updates.is_empty() &&
            self.component_balances.is_empty() &&
            self.component_tvl.is_empty()
    }
}

impl std::fmt::Display for BlockChangesResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "block_number: {}, extractor: {}", self.block.number, self.extractor)
    }
}

#[typetag::serde]
impl NormalisedMessage for BlockChangesResult {
    fn source(&self) -> ExtractorIdentity {
        ExtractorIdentity::new(self.chain, &self.extractor)
    }

    fn drop_state(&self) -> Arc<dyn NormalisedMessage> {
        Arc::new(Self {
            extractor: self.extractor.clone(),
            chain: self.chain,
            block: self.block,
            finalized_block_height: self.finalized_block_height,
            revert: self.revert,
            account_updates: HashMap::new(),
            protocol_states: HashMap::new(),
            new_tokens: self.new_tokens.clone(),
            new_protocol_components: self.new_protocol_components.clone(),
            deleted_protocol_components: self.deleted_protocol_components.clone(),
            component_balances: self.component_balances.clone(),
            component_tvl: self.component_tvl.clone(),
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug, PartialEq, Default, Clone)]
pub struct BlockChanges {
    extractor: String,
    chain: Chain,
    pub block: Block,
    pub finalized_block_height: u64,
    pub revert: bool,
    /// Required here, so it is part of the revert buffer and thus inserted into storage once
    /// finalized.
    pub new_tokens: HashMap<Address, CurrencyToken>,
    /// Vec of updates at this block, aggregated by tx and sorted by tx index in ascending order
    pub txs_with_update: Vec<TxWithChanges>,
}

impl StateUpdateBufferEntry for BlockChanges {
    fn get_filtered_protocol_state_update(
        &self,
        keys: Vec<(&ProtocolStateIdType, &ProtocolStateKeyType)>,
    ) -> HashMap<(ProtocolStateIdType, ProtocolStateKeyType), ProtocolStateValueType> {
        // Convert keys to a HashSet for faster lookups
        let keys_set: HashSet<(&ComponentId, &AttrStoreKey)> = keys.into_iter().collect();
        let mut res = HashMap::new();

        for update in self.txs_with_update.iter().rev() {
            for (component_id, protocol_update) in update.protocol_states.iter() {
                for (attr, val) in protocol_update
                    .updated_attributes
                    .iter()
                    .filter(|(attr, _)| keys_set.contains(&(component_id, attr)))
                {
                    res.entry((component_id.clone(), attr.clone()))
                        .or_insert(val.clone());
                }
            }
        }

        res
    }

    fn get_filtered_account_state_update(
        &self,
        keys: Vec<(&AccountStateIdType, &AccountStateKeyType)>,
    ) -> HashMap<(AccountStateIdType, AccountStateKeyType), AccountStateValueType> {
        let keys_set: HashSet<_> = keys.into_iter().collect();
        let mut res = HashMap::new();

        for update in self.txs_with_update.iter().rev() {
            for (address, account_update) in update.account_updates.iter() {
                for (attr, val) in account_update
                    .slots
                    .iter()
                    .filter(|(attr, _)| keys_set.contains(&(address, attr)))
                {
                    res.entry((*address, *attr))
                        .or_insert(*val);
                }
            }
        }

        res
    }

    #[allow(clippy::mutable_key_type)] // Clippy thinks that tuple with Bytes are a mutable type.
    fn get_filtered_balance_update(
        &self,
        keys: Vec<(&ComponentId, &Address)>,
    ) -> HashMap<(String, Bytes), tycho_core_protocol::ComponentBalance> {
        // Convert keys to a HashSet for faster lookups
        let keys_set: HashSet<(&String, &Bytes)> = keys.into_iter().collect();

        let mut res = HashMap::new();

        for update in self.txs_with_update.iter().rev() {
            for (component_id, balance_update) in update.balance_changes.iter() {
                for (token, value) in balance_update
                    .iter()
                    .filter(|(token, _)| {
                        keys_set.contains(&(component_id, &token.as_bytes().into()))
                    })
                {
                    res.entry((component_id.clone(), token.as_bytes().into()))
                        .or_insert(value.into());
                }
            }
        }

        res
    }
}

impl BlockScoped for BlockChanges {
    fn block(&self) -> tycho_core::models::blockchain::Block {
        (&self.block).into()
    }
}

impl BlockChanges {
    pub fn new(
        extractor: String,
        chain: Chain,
        block: Block,
        finalized_block_height: u64,
        revert: bool,
        txs_with_update: Vec<TxWithChanges>,
    ) -> Self {
        BlockChanges {
            extractor,
            chain,
            block,
            finalized_block_height,
            revert,
            new_tokens: HashMap::new(),
            txs_with_update,
        }
    }

    /// Parse from Tycho's protobuf message
    pub fn try_from_message(
        msg: substreams::BlockChanges,
        extractor: &str,
        chain: Chain,
        protocol_system: &str,
        protocol_types: &HashMap<String, ProtocolType>,
        finalized_block_height: u64,
    ) -> Result<Self, ExtractionError> {
        if let Some(block) = msg.block {
            let block = Block::try_from_message(block, chain)?;

            let txs_with_update = msg
                .changes
                .into_iter()
                .map(|change| {
                    change.tx.as_ref().ok_or_else(|| {
                        ExtractionError::DecodeError(
                            "TransactionEntityChanges misses a transaction".to_owned(),
                        )
                    })?;

                    TxWithChanges::try_from_message(change, &block, protocol_system, protocol_types)
                })
                .collect::<Result<Vec<TxWithChanges>, ExtractionError>>()?;

            // Sort updates by transaction index
            let mut txs_with_update = txs_with_update;
            txs_with_update.sort_unstable_by_key(|update| update.tx.index);

            Ok(Self {
                extractor: extractor.to_string(),
                chain,
                block,
                finalized_block_height,
                revert: false,
                new_tokens: HashMap::new(),
                txs_with_update,
            })
        } else {
            Err(ExtractionError::Empty)
        }
    }

    /// Aggregates state updates.
    ///
    /// This function aggregates the protocol updates
    /// for different protocol components into a `BlockChangesResult` object.
    /// This new object should have only one final ProtocolStateDelta and a HashMap to hold
    /// `AccountUpdate` per component_id.
    ///
    /// After merging all updates, a `BlockChangesResult` object is returned
    /// which contains, amongst other data, the compacted state updates.
    ///
    /// # Errors
    ///
    /// This returns an error if there was a problem during merge. The error
    /// type is `ExtractionError`.
    pub fn aggregate_updates(self) -> Result<BlockChangesResult, ExtractionError> {
        let mut iter = self.txs_with_update.into_iter();

        // Use unwrap_or_else to provide a default state if iter.next() is None
        let first_state = iter.next().unwrap_or_default();

        let aggregated_changes = iter
            .try_fold(first_state, |mut acc_state, new_state| {
                acc_state.merge(new_state.clone())?;
                Ok::<_, ExtractionError>(acc_state.clone())
            })
            .unwrap();

        Ok(BlockChangesResult {
            extractor: self.extractor,
            chain: self.chain,
            block: self.block,
            finalized_block_height: self.finalized_block_height,
            revert: self.revert,
            new_protocol_components: aggregated_changes.protocol_components,
            new_tokens: self.new_tokens,
            deleted_protocol_components: HashMap::new(),
            protocol_states: aggregated_changes.protocol_states,
            account_updates: aggregated_changes.account_updates,
            component_balances: aggregated_changes.balance_changes,
            component_tvl: HashMap::new(),
        })
    }

    pub fn protocol_components(&self) -> Vec<ProtocolComponent> {
        self.txs_with_update
            .iter()
            .flat_map(|tx_u| {
                tx_u.protocol_components
                    .values()
                    .cloned()
            })
            .collect()
    }
}

#[cfg(test)]
pub mod fixtures {
    use prost::Message;
    use std::str::FromStr;
    use tycho_storage::postgres::db_fixtures::yesterday_midnight;

    use super::*;

    pub const HASH_256_0: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000000";

    pub fn transaction01() -> Transaction {
        Transaction::new(H256::zero(), H256::zero(), H160::zero(), Some(H160::zero()), 10)
    }

    pub fn transaction02(hash: &str, block: &str, index: u64) -> Transaction {
        Transaction::new(
            hash.parse().unwrap(),
            block.parse().unwrap(),
            H160::zero(),
            Some(H160::zero()),
            index,
        )
    }

    pub fn evm_slots(data: impl IntoIterator<Item = (u64, u64)>) -> HashMap<U256, U256> {
        data.into_iter()
            .map(|(s, v)| (U256::from(s), U256::from(v)))
            .collect()
    }

    pub fn pb_block_scoped_data(
        msg: impl prost::Message,
        cursor: Option<&str>,
        final_block_height: Option<u64>,
    ) -> crate::pb::sf::substreams::rpc::v2::BlockScopedData {
        use crate::pb::sf::substreams::{rpc::v2::*, v1::Clock};
        let val = msg.encode_to_vec();
        BlockScopedData {
            output: Some(MapModuleOutput {
                name: "map_changes".to_owned(),
                map_output: Some(prost_types::Any {
                    type_url: "tycho.evm.v1.BlockContractChanges".to_owned(),
                    value: val,
                }),
                debug_info: None,
            }),
            clock: Some(Clock {
                id: HASH_256_0.to_owned(),
                number: 420,
                timestamp: Some(prost_types::Timestamp { seconds: 1000, nanos: 0 }),
            }),
            cursor: cursor
                .unwrap_or("cursor@420")
                .to_owned(),
            final_block_height: final_block_height.unwrap_or(420),
            debug_map_outputs: vec![],
            debug_store_outputs: vec![],
        }
    }

    pub fn pb_block_contract_changes(
        version: u8,
    ) -> crate::pb::tycho::evm::v1::BlockContractChanges {
        use crate::pb::tycho::evm::v1::*;

        match version {
            0 => BlockContractChanges {
                block: Some(Block {
                    hash: vec![0x31, 0x32, 0x33, 0x34],
                    parent_hash: vec![0x21, 0x22, 0x23, 0x24],
                    number: 1,
                    ts: 1000,
                }),

                changes: vec![
                    TransactionContractChanges {
                        tx: Some(Transaction {
                            hash: vec![0x11, 0x12, 0x13, 0x14],
                            from: vec![0x41, 0x42, 0x43, 0x44],
                            to: vec![0x51, 0x52, 0x53, 0x54],
                            index: 2,
                        }),
                        contract_changes: vec![ContractChange {
                            address: vec![0x61, 0x62, 0x63, 0x64],
                            balance: vec![0x71, 0x72, 0x73, 0x74],
                            code: vec![0x81, 0x82, 0x83, 0x84],
                            slots: vec![
                                ContractSlot {
                                    slot: vec![0xa1, 0xa2, 0xa3, 0xa4],
                                    value: vec![0xb1, 0xb2, 0xb3, 0xb4],
                                },
                                ContractSlot {
                                    slot: vec![0xc1, 0xc2, 0xc3, 0xc4],
                                    value: vec![0xd1, 0xd2, 0xd3, 0xd4],
                                },
                            ],
                            change: ChangeType::Update.into(),
                        }],
                        component_changes: vec![ProtocolComponent {
                            id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                .to_owned(),
                            tokens: vec![
                                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                            ],
                            contracts: vec![
                                H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                                H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                            ],
                            static_att: vec![
                                Attribute {
                                    name: "key1".to_owned(),
                                    value: b"value1".to_vec(),
                                    change: ChangeType::Creation.into(),
                                },
                                Attribute {
                                    name: "key2".to_owned(),
                                    value: b"value2".to_vec(),
                                    change: ChangeType::Creation.into(),
                                },
                            ],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "WeightedPool".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![BalanceChange {
                            token: hex::decode(
                                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
                                    .trim_start_matches("0x"),
                            )
                            .unwrap(),
                            balance: 50000000.encode_to_vec(),
                            component_id:
                                "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                    .as_bytes()
                                    .to_vec(),
                        }],
                    },
                    TransactionContractChanges {
                        tx: Some(Transaction {
                            hash: vec![
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                            ],
                            from: vec![0x41, 0x42, 0x43, 0x44],
                            to: vec![0x51, 0x52, 0x53, 0x54],
                            index: 5,
                        }),
                        contract_changes: vec![ContractChange {
                            address: vec![0x61, 0x62, 0x63, 0x64],
                            balance: vec![0xf1, 0xf2, 0xf3, 0xf4],
                            code: vec![0x01, 0x02, 0x03, 0x04],
                            slots: vec![
                                ContractSlot {
                                    slot: vec![0x91, 0x92, 0x93, 0x94],
                                    value: vec![0xa1, 0xa2, 0xa3, 0xa4],
                                },
                                ContractSlot {
                                    slot: vec![0xa1, 0xa2, 0xa3, 0xa4],
                                    value: vec![0xc1, 0xc2, 0xc3, 0xc4],
                                },
                            ],
                            change: ChangeType::Update.into(),
                        }],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: hex::decode(
                                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
                                    .trim_start_matches("0x"),
                            )
                            .unwrap(),
                            balance: 10.encode_to_vec(),
                            component_id:
                                "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                    .to_string()
                                    .as_bytes()
                                    .to_vec(),
                        }],
                    },
                ],
            },
            1 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionContractChanges {
                    tx: Some(pb_transactions(1, 1)),
                    contract_changes: vec![ContractChange {
                        address: address_from_str("0000000000000000000000000000000000000001"),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        code: 123_i32.to_be_bytes().to_vec(),
                        slots: vec![ContractSlot {
                            slot: Bytes::from("0x01").into(),
                            value: Bytes::from("0x01").into(),
                        }],
                        change: ChangeType::Creation.into(),
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_1".to_owned(),
                        tokens: vec![
                            address_from_str(WETH_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            2 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionContractChanges {
                    tx: Some(pb_transactions(2, 1)),
                    contract_changes: vec![
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000002"),
                            balance: 2_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_be_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x02").into(),
                            }],
                            change: ChangeType::Creation.into(),
                        },
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 10_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_be_bytes().to_vec(),
                            slots: vec![
                                ContractSlot {
                                    slot: Bytes::from(U256::from(1)).into(),
                                    value: Bytes::from(U256::from(10)).into(),
                                },
                                ContractSlot {
                                    slot: Bytes::from("0x02").into(),
                                    value: Bytes::from("0x0a").into(),
                                },
                            ],
                            change: ChangeType::Update.into(),
                        },
                    ],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![address_from_str(
                            "0000000000000000000000000000000000000002",
                        )],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 20_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDT_ADDRESS),
                            balance: 20_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 10_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            3 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionContractChanges {
                        tx: Some(pb_transactions(3, 1)),
                        contract_changes: vec![
                            ContractChange {
                                address: address_from_str(
                                    "0000000000000000000000000000000000000001",
                                ),
                                balance: 1_i32.to_be_bytes().to_vec(),
                                code: 123_i32.to_le_bytes().to_vec(),
                                slots: vec![ContractSlot {
                                    slot: Bytes::from("0x01").into(),
                                    value: Bytes::from("0x01").into(),
                                }],
                                change: ChangeType::Update.into(),
                            },
                            ContractChange {
                                address: address_from_str(
                                    "0000000000000000000000000000000000000002",
                                ),
                                balance: 20_i32.to_be_bytes().to_vec(),
                                code: 123_i32.to_le_bytes().to_vec(),
                                slots: vec![ContractSlot {
                                    slot: Bytes::from("0x02").into(),
                                    value: Bytes::from(U256::from(200)).into(),
                                }],
                                change: ChangeType::Update.into(),
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        }],
                    },
                    TransactionContractChanges {
                        tx: Some(pb_transactions(3, 2)),
                        contract_changes: vec![ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x01").into(),
                            }],
                            change: ChangeType::Update.into(),
                        }],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 100_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 2_i32.to_be_bytes().to_vec(),
                                component_id: "pc_2".into(),
                            },
                        ],
                    },
                ],
            },
            4 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionContractChanges {
                    tx: Some(pb_transactions(4, 1)),
                    contract_changes: vec![ContractChange {
                        address: address_from_str("0000000000000000000000000000000000000001"),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        code: 123_i32.to_le_bytes().to_vec(),
                        slots: vec![ContractSlot {
                            slot: Bytes::from(U256::from(3)).into(),
                            value: Bytes::from(U256::from(10)).into(),
                        }],
                        change: ChangeType::Update.into(),
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_3".to_owned(),
                        tokens: vec![address_from_str(DAI_ADDRESS), address_from_str(USDC_ADDRESS)],
                        contracts: vec![address_from_str(
                            "0000000000000000000000000000000000000001",
                        )],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![],
                }],
            },
            5 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionContractChanges {
                    tx: Some(pb_transactions(5, 1)),
                    contract_changes: vec![
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from(U256::from(1)).into(),
                                value: Bytes::from(U256::from(10)).into(),
                            }],
                            change: ChangeType::Update.into(),
                        },
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000002"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from(U256::from(1)).into(),
                                value: Bytes::from(U256::from(10)).into(),
                            }],
                            change: ChangeType::Update.into(),
                        },
                    ],
                    component_changes: vec![],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_3".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            _ => panic!("Requested BlockContractChanges version doesn't exist"),
        }
    }

    pub fn pb_vm_block_changes(version: u8) -> crate::pb::tycho::evm::v1::BlockChanges {
        use crate::pb::tycho::evm::v1::*;

        match version {
            0 => BlockChanges {
                block: Some(Block {
                    hash: vec![0x31, 0x32, 0x33, 0x34],
                    parent_hash: vec![0x21, 0x22, 0x23, 0x24],
                    number: 1,
                    ts: 1000,
                }),

                changes: vec![
                    TransactionChanges {
                        tx: Some(Transaction {
                            hash: vec![0x11, 0x12, 0x13, 0x14],
                            from: vec![0x41, 0x42, 0x43, 0x44],
                            to: vec![0x51, 0x52, 0x53, 0x54],
                            index: 2,
                        }),
                        contract_changes: vec![ContractChange {
                            address: vec![0x61, 0x62, 0x63, 0x64],
                            balance: vec![0x71, 0x72, 0x73, 0x74],
                            code: vec![0x81, 0x82, 0x83, 0x84],
                            slots: vec![
                                ContractSlot {
                                    slot: vec![0xa1, 0xa2, 0xa3, 0xa4],
                                    value: vec![0xb1, 0xb2, 0xb3, 0xb4],
                                },
                                ContractSlot {
                                    slot: vec![0xc1, 0xc2, 0xc3, 0xc4],
                                    value: vec![0xd1, 0xd2, 0xd3, 0xd4],
                                },
                            ],
                            change: ChangeType::Update.into(),
                        }],
                        entity_changes: vec![],
                        component_changes: vec![ProtocolComponent {
                            id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                .to_owned(),
                            tokens: vec![
                                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                            ],
                            contracts: vec![
                                H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                                H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                            ],
                            static_att: vec![
                                Attribute {
                                    name: "key1".to_owned(),
                                    value: b"value1".to_vec(),
                                    change: ChangeType::Creation.into(),
                                },
                                Attribute {
                                    name: "key2".to_owned(),
                                    value: b"value2".to_vec(),
                                    change: ChangeType::Creation.into(),
                                },
                            ],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "WeightedPool".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![BalanceChange {
                            token: hex::decode(
                                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
                                    .trim_start_matches("0x"),
                            )
                            .unwrap(),
                            balance: 50000000.encode_to_vec(),
                            component_id:
                                "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                    .as_bytes()
                                    .to_vec(),
                        }],
                    },
                    TransactionChanges {
                        tx: Some(Transaction {
                            hash: vec![
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                            ],
                            from: vec![0x41, 0x42, 0x43, 0x44],
                            to: vec![0x51, 0x52, 0x53, 0x54],
                            index: 5,
                        }),
                        contract_changes: vec![ContractChange {
                            address: vec![0x61, 0x62, 0x63, 0x64],
                            balance: vec![0xf1, 0xf2, 0xf3, 0xf4],
                            code: vec![0x01, 0x02, 0x03, 0x04],
                            slots: vec![
                                ContractSlot {
                                    slot: vec![0x91, 0x92, 0x93, 0x94],
                                    value: vec![0xa1, 0xa2, 0xa3, 0xa4],
                                },
                                ContractSlot {
                                    slot: vec![0xa1, 0xa2, 0xa3, 0xa4],
                                    value: vec![0xc1, 0xc2, 0xc3, 0xc4],
                                },
                            ],
                            change: ChangeType::Update.into(),
                        }],
                        entity_changes: vec![],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: hex::decode(
                                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
                                    .trim_start_matches("0x"),
                            )
                            .unwrap(),
                            balance: 10.encode_to_vec(),
                            component_id:
                                "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                    .to_string()
                                    .as_bytes()
                                    .to_vec(),
                        }],
                    },
                ],
            },
            1 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(1, 1)),
                    contract_changes: vec![ContractChange {
                        address: address_from_str("0000000000000000000000000000000000000001"),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        code: 123_i32.to_be_bytes().to_vec(),
                        slots: vec![ContractSlot {
                            slot: Bytes::from("0x01").into(),
                            value: Bytes::from("0x01").into(),
                        }],
                        change: ChangeType::Creation.into(),
                    }],
                    entity_changes: vec![],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_1".to_owned(),
                        tokens: vec![
                            address_from_str(WETH_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            2 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(2, 1)),
                    contract_changes: vec![
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000002"),
                            balance: 2_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_be_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x02").into(),
                            }],
                            change: ChangeType::Creation.into(),
                        },
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 10_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_be_bytes().to_vec(),
                            slots: vec![
                                ContractSlot {
                                    slot: Bytes::from(U256::from(1)).into(),
                                    value: Bytes::from(U256::from(10)).into(),
                                },
                                ContractSlot {
                                    slot: Bytes::from("0x02").into(),
                                    value: Bytes::from("0x0a").into(),
                                },
                            ],
                            change: ChangeType::Update.into(),
                        },
                    ],
                    entity_changes: vec![],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![address_from_str(
                            "0000000000000000000000000000000000000002",
                        )],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 20_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDT_ADDRESS),
                            balance: 20_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 10_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            3 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionChanges {
                        tx: Some(pb_transactions(3, 1)),
                        contract_changes: vec![
                            ContractChange {
                                address: address_from_str(
                                    "0000000000000000000000000000000000000001",
                                ),
                                balance: 1_i32.to_be_bytes().to_vec(),
                                code: 123_i32.to_le_bytes().to_vec(),
                                slots: vec![ContractSlot {
                                    slot: Bytes::from("0x01").into(),
                                    value: Bytes::from("0x01").into(),
                                }],
                                change: ChangeType::Update.into(),
                            },
                            ContractChange {
                                address: address_from_str(
                                    "0000000000000000000000000000000000000002",
                                ),
                                balance: 20_i32.to_be_bytes().to_vec(),
                                code: 123_i32.to_le_bytes().to_vec(),
                                slots: vec![ContractSlot {
                                    slot: Bytes::from("0x02").into(),
                                    value: Bytes::from(U256::from(200)).into(),
                                }],
                                change: ChangeType::Update.into(),
                            },
                        ],
                        entity_changes: vec![],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        }],
                    },
                    TransactionChanges {
                        tx: Some(pb_transactions(3, 2)),
                        contract_changes: vec![ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x01").into(),
                            }],
                            change: ChangeType::Update.into(),
                        }],
                        entity_changes: vec![],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 100_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 2_i32.to_be_bytes().to_vec(),
                                component_id: "pc_2".into(),
                            },
                        ],
                    },
                ],
            },
            4 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(4, 1)),
                    contract_changes: vec![ContractChange {
                        address: address_from_str("0000000000000000000000000000000000000001"),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        code: 123_i32.to_le_bytes().to_vec(),
                        slots: vec![ContractSlot {
                            slot: Bytes::from(U256::from(3)).into(),
                            value: Bytes::from(U256::from(10)).into(),
                        }],
                        change: ChangeType::Update.into(),
                    }],
                    entity_changes: vec![],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_3".to_owned(),
                        tokens: vec![address_from_str(DAI_ADDRESS), address_from_str(USDC_ADDRESS)],
                        contracts: vec![address_from_str(
                            "0000000000000000000000000000000000000001",
                        )],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![],
                }],
            },
            5 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(5, 1)),
                    contract_changes: vec![
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from(U256::from(1)).into(),
                                value: Bytes::from(U256::from(10)).into(),
                            }],
                            change: ChangeType::Update.into(),
                        },
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000002"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from(U256::from(1)).into(),
                                value: Bytes::from(U256::from(10)).into(),
                            }],
                            change: ChangeType::Update.into(),
                        },
                    ],
                    entity_changes: vec![],
                    component_changes: vec![],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_3".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            _ => panic!("Requested BlockChanges version doesn't exist"),
        }
    }

    pub fn pb_state_changes() -> crate::pb::tycho::evm::v1::EntityChanges {
        use crate::pb::tycho::evm::v1::*;
        let res1_value = 1000_u64.to_be_bytes().to_vec();
        let res2_value = 500_u64.to_be_bytes().to_vec();
        EntityChanges {
            component_id: "State1".to_owned(),
            attributes: vec![
                Attribute {
                    name: "reserve1".to_owned(),
                    value: res1_value,
                    change: ChangeType::Update.into(),
                },
                Attribute {
                    name: "reserve2".to_owned(),
                    value: res2_value,
                    change: ChangeType::Update.into(),
                },
            ],
        }
    }

    pub fn pb_blocks(version: u64) -> crate::pb::tycho::evm::v1::Block {
        if version == 0 {
            panic!("Block version 0 doesn't exist. It starts at 1");
        }
        let base_ts = yesterday_midnight().timestamp() as u64;

        crate::pb::tycho::evm::v1::Block {
            number: version,
            hash: H256::from_low_u64_be(version)
                .as_bytes()
                .to_vec(),
            parent_hash: H256::from_low_u64_be(version - 1)
                .as_bytes()
                .to_vec(),
            ts: base_ts + version * 1000,
        }
    }

    pub fn pb_transactions(version: u64, index: u64) -> crate::pb::tycho::evm::v1::Transaction {
        crate::pb::tycho::evm::v1::Transaction {
            hash: H256::from_low_u64_be(version * 10_000 + index)
                .as_bytes()
                .to_vec(),
            from: H160::from_low_u64_be(version * 100_000 + index)
                .as_bytes()
                .to_vec(),
            to: H160::from_low_u64_be(version * 1_000_000 + index)
                .as_bytes()
                .to_vec(),
            index,
        }
    }

    const WETH_ADDRESS: &str = "C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    const USDC_ADDRESS: &str = "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const DAI_ADDRESS: &str = "6B175474E89094C44Da98b954EedeAC495271d0F";
    const USDT_ADDRESS: &str = "dAC17F958D2ee523a2206206994597C13D831ec7";

    pub fn address_from_str(token: &str) -> Vec<u8> {
        H160::from_str(token)
            .unwrap()
            .0
            .to_vec()
    }

    pub fn pb_block_entity_changes(version: u8) -> crate::pb::tycho::evm::v1::BlockEntityChanges {
        use crate::pb::tycho::evm::v1::*;

        match version {
            0 => BlockEntityChanges {
                block: Some(Block {
                    hash: vec![0x0, 0x0, 0x0, 0x0],
                    parent_hash: vec![0x21, 0x22, 0x23, 0x24],
                    number: 1,
                    ts: yesterday_midnight().timestamp() as u64,
                }),
                changes: vec![
                    TransactionEntityChanges {
                        tx: Some(Transaction {
                            hash: vec![0x0, 0x0, 0x0, 0x0],
                            from: vec![0x0, 0x0, 0x0, 0x0],
                            to: vec![0x0, 0x0, 0x0, 0x0],
                            index: 10,
                        }),
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "State1".to_owned(),
                                attributes: vec![
                                    Attribute {
                                        name: "reserve".to_owned(),
                                        value: 1000_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "static_attribute".to_owned(),
                                        value: 1_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                ],
                            },
                            EntityChanges {
                                component_id: "State2".to_owned(),
                                attributes: vec![
                                    Attribute {
                                        name: "reserve".to_owned(),
                                        value: 1000_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "static_attribute".to_owned(),
                                        value: 1_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                ],
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![],
                    },
                    TransactionEntityChanges {
                        tx: Some(Transaction {
                            hash: vec![0x11, 0x12, 0x13, 0x14],
                            from: vec![0x41, 0x42, 0x43, 0x44],
                            to: vec![0x51, 0x52, 0x53, 0x54],
                            index: 11,
                        }),
                        entity_changes: vec![EntityChanges {
                            component_id: "State1".to_owned(),
                            attributes: vec![
                                Attribute {
                                    name: "reserve".to_owned(),
                                    value: 600_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                },
                                Attribute {
                                    name: "new".to_owned(),
                                    value: 0_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                },
                            ],
                        }],
                        component_changes: vec![ProtocolComponent {
                            id: "Pool".to_owned(),
                            tokens: vec![
                                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                            ],
                            contracts: vec![H160::from_str(
                                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                            )
                            .unwrap()
                            .0
                            .to_vec()],
                            static_att: vec![Attribute {
                                name: "key".to_owned(),
                                value: 600_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Creation.into(),
                            }],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "WeightedPool".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![BalanceChange {
                            token: H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                .unwrap()
                                .0
                                .to_vec(),
                            balance: 1_i32.to_le_bytes().to_vec(),
                            component_id: "Balance1".into(),
                        }],
                    },
                ],
            },
            1 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionEntityChanges {
                    tx: Some(pb_transactions(1, 1)),
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![
                            Attribute {
                                name: "attr_1".to_owned(),
                                value: 1_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            },
                            Attribute {
                                name: "attr_2".to_owned(),
                                value: 2_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            },
                        ],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_1".to_owned(),
                        tokens: vec![
                            address_from_str(WETH_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![Attribute {
                            name: "st_attr_1".to_owned(),
                            value: 1_u64.to_be_bytes().to_vec(),
                            change: ChangeType::Creation.into(),
                        }],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![BalanceChange {
                        token: address_from_str(USDC_ADDRESS),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        component_id: "pc_1".into(),
                    }],
                }],
            },
            2 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionEntityChanges {
                    tx: Some(pb_transactions(2, 1)),
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![Attribute {
                            name: "attr_1".to_owned(),
                            value: 10_u64.to_be_bytes().to_vec(),
                            change: ChangeType::Update.into(),
                        }],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDT_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            3 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionEntityChanges {
                        tx: Some(pb_transactions(3, 2)),
                        entity_changes: vec![EntityChanges {
                            component_id: "pc_1".to_owned(),
                            attributes: vec![Attribute {
                                name: "attr_1".to_owned(),
                                value: 1000_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 3_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        }],
                    },
                    TransactionEntityChanges {
                        tx: Some(pb_transactions(3, 1)),
                        entity_changes: vec![EntityChanges {
                            component_id: "pc_1".to_owned(),
                            attributes: vec![Attribute {
                                name: "attr_1".to_owned(),
                                value: 99999_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 99999_i32.to_be_bytes().to_vec(),
                                component_id: "pc_2".into(),
                            },
                            BalanceChange {
                                token: address_from_str(WETH_ADDRESS),
                                balance: 1000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                        ],
                    },
                ],
            },
            4 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionEntityChanges {
                        tx: Some(pb_transactions(4, 1)),
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "pc_1".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 10000_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                            EntityChanges {
                                component_id: "pc_3".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 3_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                        ],
                        component_changes: vec![ProtocolComponent {
                            id: "pc_3".to_owned(),
                            tokens: vec![
                                address_from_str(DAI_ADDRESS),
                                address_from_str(WETH_ADDRESS),
                            ],
                            contracts: vec![],
                            static_att: vec![],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "pt_2".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![],
                    },
                    TransactionEntityChanges {
                        tx: Some(pb_transactions(4, 2)),
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "pc_3".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 30_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                            EntityChanges {
                                component_id: "pc_1".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 100000_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 3000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_3".into(),
                            },
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 1000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                        ],
                    },
                ],
            },
            5 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionEntityChanges {
                    tx: Some(pb_transactions(5, 1)),
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![Attribute {
                            name: "attr_2".to_owned(),
                            value: 1000000_u64.to_be_bytes().to_vec(),
                            change: ChangeType::Update.into(),
                        }],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Deletion.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![BalanceChange {
                        token: address_from_str(WETH_ADDRESS),
                        balance: 1000_i32.to_be_bytes().to_vec(),
                        component_id: "pc_1".into(),
                    }],
                }],
            },
            _ => panic!("Requested unknown version of block entity changes"),
        }
    }

    pub fn pb_native_block_changes(version: u8) -> crate::pb::tycho::evm::v1::BlockChanges {
        use crate::pb::tycho::evm::v1::*;

        match version {
            0 => BlockChanges {
                block: Some(Block {
                    hash: vec![0x0, 0x0, 0x0, 0x0],
                    parent_hash: vec![0x21, 0x22, 0x23, 0x24],
                    number: 1,
                    ts: yesterday_midnight().timestamp() as u64,
                }),
                changes: vec![
                    TransactionChanges {
                        tx: Some(Transaction {
                            hash: vec![0x0, 0x0, 0x0, 0x0],
                            from: vec![0x0, 0x0, 0x0, 0x0],
                            to: vec![0x0, 0x0, 0x0, 0x0],
                            index: 10,
                        }),
                        contract_changes: vec![],
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "State1".to_owned(),
                                attributes: vec![
                                    Attribute {
                                        name: "reserve".to_owned(),
                                        value: 1000_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "static_attribute".to_owned(),
                                        value: 1_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                ],
                            },
                            EntityChanges {
                                component_id: "State2".to_owned(),
                                attributes: vec![
                                    Attribute {
                                        name: "reserve".to_owned(),
                                        value: 1000_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "static_attribute".to_owned(),
                                        value: 1_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                ],
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![],
                    },
                    TransactionChanges {
                        tx: Some(Transaction {
                            hash: vec![0x11, 0x12, 0x13, 0x14],
                            from: vec![0x41, 0x42, 0x43, 0x44],
                            to: vec![0x51, 0x52, 0x53, 0x54],
                            index: 11,
                        }),
                        contract_changes: vec![],
                        entity_changes: vec![EntityChanges {
                            component_id: "State1".to_owned(),
                            attributes: vec![
                                Attribute {
                                    name: "reserve".to_owned(),
                                    value: 600_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                },
                                Attribute {
                                    name: "new".to_owned(),
                                    value: 0_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                },
                            ],
                        }],
                        component_changes: vec![ProtocolComponent {
                            id: "Pool".to_owned(),
                            tokens: vec![
                                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                            ],
                            contracts: vec![H160::from_str(
                                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                            )
                            .unwrap()
                            .0
                            .to_vec()],
                            static_att: vec![Attribute {
                                name: "key".to_owned(),
                                value: 600_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Creation.into(),
                            }],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "WeightedPool".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![BalanceChange {
                            token: H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                .unwrap()
                                .0
                                .to_vec(),
                            balance: 1_i32.to_le_bytes().to_vec(),
                            component_id: "Balance1".into(),
                        }],
                    },
                ],
            },
            1 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(1, 1)),
                    contract_changes: vec![],
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![
                            Attribute {
                                name: "attr_1".to_owned(),
                                value: 1_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            },
                            Attribute {
                                name: "attr_2".to_owned(),
                                value: 2_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            },
                        ],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_1".to_owned(),
                        tokens: vec![
                            address_from_str(WETH_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![Attribute {
                            name: "st_attr_1".to_owned(),
                            value: 1_u64.to_be_bytes().to_vec(),
                            change: ChangeType::Creation.into(),
                        }],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![BalanceChange {
                        token: address_from_str(USDC_ADDRESS),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        component_id: "pc_1".into(),
                    }],
                }],
            },
            2 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(2, 1)),
                    contract_changes: vec![],
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![Attribute {
                            name: "attr_1".to_owned(),
                            value: 10_u64.to_be_bytes().to_vec(),
                            change: ChangeType::Update.into(),
                        }],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDT_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            3 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionChanges {
                        tx: Some(pb_transactions(3, 2)),
                        contract_changes: vec![],
                        entity_changes: vec![EntityChanges {
                            component_id: "pc_1".to_owned(),
                            attributes: vec![Attribute {
                                name: "attr_1".to_owned(),
                                value: 1000_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 3_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        }],
                    },
                    TransactionChanges {
                        tx: Some(pb_transactions(3, 1)),
                        contract_changes: vec![],
                        entity_changes: vec![EntityChanges {
                            component_id: "pc_1".to_owned(),
                            attributes: vec![Attribute {
                                name: "attr_1".to_owned(),
                                value: 99999_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 99999_i32.to_be_bytes().to_vec(),
                                component_id: "pc_2".into(),
                            },
                            BalanceChange {
                                token: address_from_str(WETH_ADDRESS),
                                balance: 1000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                        ],
                    },
                ],
            },
            4 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionChanges {
                        tx: Some(pb_transactions(4, 1)),
                        contract_changes: vec![],
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "pc_1".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 10000_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                            EntityChanges {
                                component_id: "pc_3".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 3_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                        ],
                        component_changes: vec![ProtocolComponent {
                            id: "pc_3".to_owned(),
                            tokens: vec![
                                address_from_str(DAI_ADDRESS),
                                address_from_str(WETH_ADDRESS),
                            ],
                            contracts: vec![],
                            static_att: vec![],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "pt_2".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![],
                    },
                    TransactionChanges {
                        tx: Some(pb_transactions(4, 2)),
                        contract_changes: vec![],
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "pc_3".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 30_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                            EntityChanges {
                                component_id: "pc_1".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 100000_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 3000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_3".into(),
                            },
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 1000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                        ],
                    },
                ],
            },
            5 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(5, 1)),
                    contract_changes: vec![],
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![Attribute {
                            name: "attr_2".to_owned(),
                            value: 1000000_u64.to_be_bytes().to_vec(),
                            change: ChangeType::Update.into(),
                        }],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Deletion.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![BalanceChange {
                        token: address_from_str(WETH_ADDRESS),
                        balance: 1000_i32.to_be_bytes().to_vec(),
                        component_id: "pc_1".into(),
                    }],
                }],
            },
            _ => panic!("Requested unknown version of block entity changes"),
        }
    }

    pub fn pb_protocol_component() -> crate::pb::tycho::evm::v1::ProtocolComponent {
        use crate::pb::tycho::evm::v1::*;
        ProtocolComponent {
            id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_owned(),
            tokens: vec![
                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                    .unwrap()
                    .0
                    .to_vec(),
                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                    .unwrap()
                    .0
                    .to_vec(),
            ],
            contracts: vec![
                H160::from_str("0x31fF2589Ee5275a2038beB855F44b9Be993aA804")
                    .unwrap()
                    .0
                    .to_vec(),
                H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                    .unwrap()
                    .0
                    .to_vec(),
            ],
            static_att: vec![
                Attribute {
                    name: "balance".to_owned(),
                    value: 100_u64.to_be_bytes().to_vec(),
                    change: ChangeType::Creation.into(),
                },
                Attribute {
                    name: "factory_address".to_owned(),
                    value: b"0x0fwe0g240g20".to_vec(),
                    change: ChangeType::Creation.into(),
                },
            ],
            change: ChangeType::Creation.into(),
            protocol_type: Some(ProtocolType {
                name: "WeightedPool".to_string(),
                financial_type: 0,
                attribute_schema: vec![],
                implementation_type: 0,
            }),
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use prost::Message;

    use rstest::rstest;
    use tycho_storage::postgres::db_fixtures::yesterday_midnight;

    use crate::extractor::evm::fixtures::transaction01;

    use super::*;

    const HASH_256_0: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
    const HASH_256_1: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

    fn account01() -> Account {
        let code = vec![0, 0, 0, 0];
        let code_hash = H256(keccak256(&code));
        Account::new(
            Chain::Ethereum,
            "0xe688b84b23f322a994A53dbF8E15FA82CDB71127"
                .parse()
                .unwrap(),
            "0xe688b84b23f322a994a53dbf8e15fa82cdb71127".into(),
            fixtures::evm_slots([]),
            U256::from(10000),
            code.into(),
            code_hash,
            H256::zero(),
            H256::zero(),
            Some(H256::zero()),
        )
    }

    fn tx_update() -> TransactionVMUpdates {
        let code = vec![0, 0, 0, 0];
        let mut account_updates = HashMap::new();
        account_updates.insert(
            "0xe688b84b23f322a994A53dbF8E15FA82CDB71127"
                .parse()
                .unwrap(),
            AccountUpdate::new(
                "0xe688b84b23f322a994A53dbF8E15FA82CDB71127"
                    .parse()
                    .unwrap(),
                Chain::Ethereum,
                fixtures::evm_slots([]),
                Some(U256::from(10000)),
                Some(code.into()),
                ChangeType::Update,
            ),
        );

        TransactionVMUpdates::new(
            account_updates,
            HashMap::new(),
            HashMap::new(),
            fixtures::transaction01(),
        )
    }

    fn update_balance() -> AccountUpdate {
        AccountUpdate::new(
            "0xe688b84b23f322a994A53dbF8E15FA82CDB71127"
                .parse()
                .unwrap(),
            Chain::Ethereum,
            fixtures::evm_slots([]),
            Some(U256::from(420)),
            None,
            ChangeType::Update,
        )
    }

    fn update_slots() -> AccountUpdate {
        AccountUpdate::new(
            "0xe688b84b23f322a994A53dbF8E15FA82CDB71127"
                .parse()
                .unwrap(),
            Chain::Ethereum,
            fixtures::evm_slots([(0, 1), (1, 2)]),
            None,
            None,
            ChangeType::Update,
        )
    }

    #[test]
    fn test_account_from_update_w_tx() {
        let update = tx_update();
        let exp = account01();

        assert_eq!(
            update
                .account_updates
                .values()
                .next()
                .unwrap()
                .ref_into_account(&update.tx),
            exp
        );
    }

    #[test]
    fn test_merge_account_update() {
        let mut update_left = update_balance();
        let update_right = update_slots();
        let mut exp = update_slots();
        exp.balance = Some(U256::from(420));

        update_left.merge(update_right).unwrap();

        assert_eq!(update_left, exp);
    }

    #[test]
    fn test_merge_account_update_wrong_address() {
        let mut update_left = update_balance();
        let mut update_right = update_slots();
        update_right.address = H160::zero();
        let exp = Err(ExtractionError::MergeError(
            "Can't merge AccountUpdates from differing identities; \
            Expected 0xe688b84b23f322a994a53dbf8e15fa82cdb71127, \
            got 0x0000000000000000000000000000000000000000"
                .into(),
        ));

        let res = update_left.merge(update_right);

        assert_eq!(res, exp);
    }

    #[rstest]
    #[case::diff_block(
    fixtures::transaction02(HASH_256_1, HASH_256_1, 11),
    Err(ExtractionError::MergeError(format ! ("Can't merge TransactionVMUpdates from different blocks: 0x{:x} != {}", H256::zero(), HASH_256_1)))
    )]
    #[case::same_tx(
    fixtures::transaction02(HASH_256_0, HASH_256_0, 11),
    Err(ExtractionError::MergeError(format ! ("Can't merge TransactionVMUpdates from the same transaction: 0x{:x}", H256::zero())))
    )]
    #[case::lower_idx(
    fixtures::transaction02(HASH_256_1, HASH_256_0, 1),
    Err(ExtractionError::MergeError("Can't merge TransactionVMUpdates with lower transaction index: 10 > 1".to_owned()))
    )]
    fn test_merge_account_update_w_tx(
        #[case] tx: Transaction,
        #[case] exp: Result<(), ExtractionError>,
    ) {
        let mut left = tx_update();
        let mut right = left.clone();
        right.tx = tx;

        let res = left.merge(&right);

        assert_eq!(res, exp);
    }

    fn create_protocol_component(tx_hash: H256) -> ProtocolComponent {
        ProtocolComponent {
            id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_owned(),
            protocol_system: "ambient".to_string(),
            protocol_type_name: String::from("WeightedPool"),
            chain: Chain::Ethereum,
            tokens: vec![
                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            ],
            contract_ids: vec![
                H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
                H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
            ],
            static_attributes: HashMap::from([
                ("key1".to_string(), Bytes::from(b"value1".to_vec())),
                ("key2".to_string(), Bytes::from(b"value2".to_vec())),
            ]),
            change: ChangeType::Creation,
            creation_tx: tx_hash,
            created_at: NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
        }
    }

    fn block_state_changes() -> BlockContractChanges {
        let tx = Transaction {
            hash: H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000011121314,
            ),
            block_hash: H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000031323334,
            ),
            from: H160::from_low_u64_be(0x0000000000000000000000000000000041424344),
            to: Some(H160::from_low_u64_be(0x0000000000000000000000000000000051525354)),
            index: 2,
        };
        let tx_5 = Transaction {
            hash: H256::from_str(HASH_256_1).unwrap(),
            block_hash: H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000031323334,
            ),
            from: H160::from_low_u64_be(0x0000000000000000000000000000000041424344),
            to: Some(H160::from_low_u64_be(0x0000000000000000000000000000000051525354)),
            index: 5,
        };
        let protocol_component = create_protocol_component(tx.hash);
        BlockContractChanges {
            extractor: "test".to_string(),
            chain: Chain::Ethereum,
            block: Block {
                number: 1,
                hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000031323334,
                ),
                parent_hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000021222324,
                ),
                chain: Chain::Ethereum,
                ts: NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
            },
            finalized_block_height: 0,
            revert: false,
            new_tokens: HashMap::new(),
            tx_updates: vec![
                TransactionVMUpdates {
                    account_updates: [(
                        H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                        AccountUpdate::new(
                            H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                            Chain::Ethereum,
                            fixtures::evm_slots([
                                (2711790500, 2981278644),
                                (3250766788, 3520254932),
                            ]),
                            Some(U256::from(1903326068)),
                            Some(vec![129, 130, 131, 132].into()),
                            ChangeType::Update,
                        ),
                    )]
                        .into_iter()
                        .collect(),
                    protocol_components: [(protocol_component.id.clone(), protocol_component)]
                        .into_iter()
                        .collect(),
                    component_balances: [(
                        "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_string(),
                        [(
                            H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                            ComponentBalance {
                                token: H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                                balance: Bytes::from(50000000.encode_to_vec()),
                                balance_float: 36522027799.0,
                                modify_tx: H256::from_low_u64_be(0x0000000000000000000000000000000000000000000000000000000011121314),
                                component_id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_string(),
                            },
                        )]
                            .into_iter()
                            .collect(),
                    )]
                        .into_iter()
                        .collect(),

                    tx,
                },
                TransactionVMUpdates {
                    account_updates: [(
                        H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                        AccountUpdate::new(
                            H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                            Chain::Ethereum,
                            fixtures::evm_slots([
                                (2711790500, 3250766788),
                                (2442302356, 2711790500),
                            ]),
                            Some(U256::from(4059231220u64)),
                            Some(vec![1, 2, 3, 4].into()),
                            ChangeType::Update,
                        ),
                    )]
                        .into_iter()
                        .collect(),
                    protocol_components: HashMap::new(),
                    component_balances: [(
                        "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_string(),
                        [(
                            H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                            ComponentBalance {
                                token: H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                                balance: Bytes::from(10.encode_to_vec()),
                                balance_float: 2058.0,
                                modify_tx: H256::from_low_u64_be(0x0000000000000000000000000000000000000000000000000000000000000001),
                                component_id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_string(),
                            },
                        )]
                            .into_iter()
                            .collect(),
                    )]
                        .into_iter()
                        .collect(),
                    tx: tx_5,
                },
            ],
        }
    }

    #[test]
    fn test_block_state_changes_parse_msg() {
        let msg = fixtures::pb_block_contract_changes(0);

        let res = BlockContractChanges::try_from_message(
            msg,
            "test",
            Chain::Ethereum,
            "ambient".to_string(),
            &HashMap::from([("WeightedPool".to_string(), ProtocolType::default())]),
            0,
        )
        .unwrap();
        assert_eq!(res, block_state_changes());
    }

    fn block_account_changes() -> BlockAccountChanges {
        let address = H160::from_low_u64_be(0x0000000000000000000000000000000061626364);
        let protocol_component = ProtocolComponent {
            id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_owned(),
            protocol_system: "ambient".to_string(),
            protocol_type_name: String::from("WeightedPool"),
            chain: Chain::Ethereum,
            tokens: vec![
                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            ],
            contract_ids: vec![
                H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
                H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
            ],
            static_attributes: [
                ("key1".to_string(), Bytes::from(b"value1".to_vec())),
                ("key2".to_string(), Bytes::from(b"value2".to_vec())),
            ]
            .iter()
            .cloned()
            .collect(),
            change: ChangeType::Creation,
            creation_tx: H256::from_str(
                "0x0000000000000000000000000000000000000000000000000000000011121314",
            )
            .unwrap(),
            created_at: NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
        };
        let component_balances: HashMap<ComponentId, HashMap<H160, ComponentBalance>> = [(
            String::from("d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"),
            [(
                H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                ComponentBalance {
                    token: H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                    balance: Bytes::from(10.encode_to_vec()),
                    balance_float: 2058.0,
                    modify_tx: H256::from_low_u64_be(
                        0x0000000000000000000000000000000000000000000000000000000000000001,
                    ),
                    component_id:
                        "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                            .to_string(),
                },
            )]
            .into_iter()
            .collect(),
        )]
        .into_iter()
        .collect();

        BlockAccountChanges::new(
            "test",
            Chain::Ethereum,
            Block {
                number: 1,
                hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000031323334,
                ),
                parent_hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000021222324,
                ),
                chain: Chain::Ethereum,
                ts: NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
            },
            0,
            false,
            vec![(
                address,
                AccountUpdate {
                    address: H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                    chain: Chain::Ethereum,
                    slots: fixtures::evm_slots([
                        (2711790500, 2981278644),
                        (3250766788, 3520254932),
                        (2711790500, 3250766788),
                        (2442302356, 2711790500),
                    ]),
                    balance: Some(U256::from(4059231220u64)),
                    code: Some(vec![1, 2, 3, 4].into()),
                    change: ChangeType::Update,
                },
            )]
            .into_iter()
            .collect(),
            HashMap::new(),
            [(protocol_component.id.clone(), protocol_component)]
                .into_iter()
                .collect(),
            HashMap::new(),
            component_balances,
        )
    }

    #[test]
    fn test_block_state_changes_aggregate() {
        let mut msg = block_state_changes();
        let block_hash = "0x0000000000000000000000000000000000000000000000000000000031323334";
        // use a different tx so merge works
        msg.tx_updates[1].tx = fixtures::transaction02(HASH_256_1, block_hash, 5);

        // should error cause same tx
        let res = msg.aggregate_updates().unwrap();

        assert_eq!(res, block_account_changes());
    }

    #[test]
    fn test_merge_protocol_state_updates() {
        let up_attributes1: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(U256::from(1000))),
            ("reserve2".to_owned(), Bytes::from(U256::from(500))),
            ("static_attribute".to_owned(), Bytes::from(U256::from(1))),
            ("to_be_removed".to_owned(), Bytes::from(U256::from(1))),
        ]
        .into_iter()
        .collect();
        let del_attributes1: HashSet<String> = vec!["to_add_back".to_owned()]
            .into_iter()
            .collect();
        let mut state1 = ProtocolStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: up_attributes1,
            deleted_attributes: del_attributes1,
        };

        let up_attributes2: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(U256::from(900))),
            ("reserve2".to_owned(), Bytes::from(U256::from(550))),
            ("new_attribute".to_owned(), Bytes::from(U256::from(1))),
            ("to_add_back".to_owned(), Bytes::from(U256::from(200))),
        ]
        .into_iter()
        .collect();
        let del_attributes2: HashSet<String> = vec!["to_be_removed".to_owned()]
            .into_iter()
            .collect();
        let state2 = ProtocolStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: up_attributes2.clone(),
            deleted_attributes: del_attributes2,
        };

        let res = state1.merge(state2);

        assert!(res.is_ok());
        let expected_up_attributes: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(U256::from(900))),
            ("reserve2".to_owned(), Bytes::from(U256::from(550))),
            ("static_attribute".to_owned(), Bytes::from(U256::from(1))),
            ("new_attribute".to_owned(), Bytes::from(U256::from(1))),
            ("to_add_back".to_owned(), Bytes::from(U256::from(200))),
        ]
        .into_iter()
        .collect();
        assert_eq!(state1.updated_attributes, expected_up_attributes);
        let expected_del_attributes: HashSet<String> = vec!["to_be_removed".to_owned()]
            .into_iter()
            .collect();
        assert_eq!(state1.deleted_attributes, expected_del_attributes);
    }

    fn protocol_state_with_tx() -> ProtocolChangesWithTx {
        let attributes: HashMap<String, Bytes> = vec![
            ("reserve".to_owned(), Bytes::from(1000_u64.to_be_bytes().to_vec())),
            ("static_attribute".to_owned(), Bytes::from(1_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let states: HashMap<String, ProtocolStateDelta> = vec![
            (
                "State1".to_owned(),
                ProtocolStateDelta {
                    component_id: "State1".to_owned(),
                    updated_attributes: attributes.clone(),
                    deleted_attributes: HashSet::new(),
                },
            ),
            (
                "State2".to_owned(),
                ProtocolStateDelta {
                    component_id: "State2".to_owned(),
                    updated_attributes: attributes,
                    deleted_attributes: HashSet::new(),
                },
            ),
        ]
        .into_iter()
        .collect();
        ProtocolChangesWithTx { protocol_states: states, tx: transaction01(), ..Default::default() }
    }

    #[test]
    fn test_block_contract_changes_state_filter() {
        let block = block_state_changes();

        let account1 = H160::from_low_u64_be(0x0000000000000000000000000000000061626364);
        let slot1 = U256::from(2711790500_u64);
        let slot2 = U256::from(3250766788_u64);
        let account_missing = H160::from_low_u64_be(0x000000000000000000000000000000000badbabe);
        let slot_missing = U256::from(12345678_u64);

        let keys = vec![
            (&account1, &slot1),
            (&account1, &slot2),
            (&account_missing, &slot1),
            (&account1, &slot_missing),
        ];

        let filtered = block.get_filtered_account_state_update(keys);

        assert_eq!(
            filtered,
            HashMap::from([
                ((account1, slot1), U256::from(3250766788_u64)),
                ((account1, slot2), U256::from(3520254932_u64))
            ])
        );
    }

    #[test]
    fn test_block_contract_changes_balance_filter() {
        let block = block_state_changes();

        let c_id_key =
            "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_string();
        let token_key =
            Bytes::from(H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap());
        let missing_token =
            Bytes::from(H160::from_str("0x0000000000000000000000000000000000000000").unwrap());
        let missing_component = "missing".to_string();

        let keys = vec![
            (&c_id_key, &token_key),
            (&c_id_key, &missing_token),
            (&missing_component, &token_key),
        ];

        #[allow(clippy::mutable_key_type)]
        // Clippy thinks that tuple with Bytes are a mutable type.
        let filtered = block.get_filtered_balance_update(keys);

        assert_eq!(
            filtered,
            HashMap::from([(
                (c_id_key.clone(), token_key.clone()),
                tycho_core::models::protocol::ComponentBalance {
                    token: H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
                        .unwrap()
                        .into(),
                    new_balance: Bytes::from(10.encode_to_vec()),
                    balance_float: 2058.0,
                    modify_tx: Bytes::from(
                        "0x0000000000000000000000000000000000000000000000000000000000000001"
                    ),
                    component_id: c_id_key.clone()
                }
            )])
        )
    }

    #[test]
    fn test_merge_protocol_state_update_with_tx() {
        let mut base_state = protocol_state_with_tx();

        let new_attributes: HashMap<String, Bytes> = vec![
            ("reserve".to_owned(), Bytes::from(900_u64.to_be_bytes().to_vec())),
            ("new_attribute".to_owned(), Bytes::from(1_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let new_tx = fixtures::transaction02(HASH_256_1, HASH_256_0, 11);
        let new_states: HashMap<String, ProtocolStateDelta> = vec![(
            "State1".to_owned(),
            ProtocolStateDelta {
                component_id: "State1".to_owned(),
                updated_attributes: new_attributes,
                deleted_attributes: HashSet::new(),
            },
        )]
        .into_iter()
        .collect();

        let tx_update =
            ProtocolChangesWithTx { protocol_states: new_states, tx: new_tx, ..Default::default() };

        let res = base_state.merge(tx_update);

        assert!(res.is_ok());
        assert_eq!(base_state.protocol_states.len(), 2);
        let expected_attributes: HashMap<String, Bytes> = vec![
            ("reserve".to_owned(), Bytes::from(900_u64.to_be_bytes().to_vec())),
            ("static_attribute".to_owned(), Bytes::from(1_u64.to_be_bytes().to_vec())),
            ("new_attribute".to_owned(), Bytes::from(1_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            base_state
                .protocol_states
                .get("State1")
                .unwrap()
                .updated_attributes,
            expected_attributes
        );
    }

    #[rstest]
    #[case::diff_block(
    fixtures::transaction02(HASH_256_1, HASH_256_1, 11),
    Err(ExtractionError::MergeError(format ! ("Can't merge ProtocolStates from different blocks: 0x{:x} != {}", H256::zero(), HASH_256_1)))
    )]
    #[case::same_tx(
    fixtures::transaction02(HASH_256_0, HASH_256_0, 11),
    Err(ExtractionError::MergeError(format ! ("Can't merge ProtocolStates from the same transaction: 0x{:x}", H256::zero())))
    )]
    #[case::lower_idx(
    fixtures::transaction02(HASH_256_1, HASH_256_0, 1),
    Err(ExtractionError::MergeError("Can't merge ProtocolStates with lower transaction index: 10 > 1".to_owned()))
    )]
    fn test_merge_pool_state_update_with_tx_errors(
        #[case] tx: Transaction,
        #[case] exp: Result<(), ExtractionError>,
    ) {
        let mut base_state = protocol_state_with_tx();

        let mut new_state = protocol_state_with_tx();
        new_state.tx = tx;

        let res = base_state.merge(new_state);

        assert_eq!(res, exp);
    }

    fn protocol_state() -> ProtocolStateDelta {
        let res1_value = 1000_u64.to_be_bytes().to_vec();
        let res2_value = 500_u64.to_be_bytes().to_vec();
        ProtocolStateDelta {
            component_id: "State1".to_string(),
            updated_attributes: vec![
                ("reserve1".to_owned(), Bytes::from(res1_value)),
                ("reserve2".to_owned(), Bytes::from(res2_value)),
            ]
            .into_iter()
            .collect(),
            deleted_attributes: HashSet::new(),
        }
    }

    #[test]
    fn test_merge_protocol_state_update_wrong_id() {
        let mut state1 = protocol_state();

        let attributes2: HashMap<String, Bytes> =
            vec![("reserve".to_owned(), Bytes::from(U256::from(900)))]
                .into_iter()
                .collect();
        let state2 = ProtocolStateDelta {
            component_id: "State2".to_owned(),
            updated_attributes: attributes2.clone(),
            deleted_attributes: HashSet::new(),
        };

        let res = state1.merge(state2);

        assert_eq!(
            res,
            Err(ExtractionError::MergeError(
                "Can't merge ProtocolStates from differing identities; Expected State1, got State2"
                    .to_owned()
            ))
        );
    }

    #[test]
    fn test_protocol_state_update_parse_msg() {
        let msg = fixtures::pb_state_changes();

        let res = ProtocolStateDelta::try_from_message(msg).unwrap();

        assert_eq!(res, protocol_state());
    }

    fn block_entity_changes() -> BlockEntityChanges {
        let tx = Transaction {
            hash: H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000011121314,
            ),
            block_hash: H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000000000000,
            ),
            from: H160::from_low_u64_be(0x0000000000000000000000000000000041424344),
            to: Some(H160::from_low_u64_be(0x0000000000000000000000000000000051525354)),
            index: 11,
        };
        let attr: HashMap<String, Bytes> = vec![
            ("reserve".to_owned(), Bytes::from(600_u64.to_be_bytes().to_vec())),
            ("new".to_owned(), Bytes::from(0_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let state_updates: HashMap<String, ProtocolStateDelta> = vec![(
            "State1".to_owned(),
            ProtocolStateDelta {
                component_id: "State1".to_owned(),
                updated_attributes: attr,
                deleted_attributes: HashSet::new(),
            },
        )]
        .into_iter()
        .collect();
        let static_attr: HashMap<String, Bytes> =
            vec![("key".to_owned(), Bytes::from(600_u64.to_be_bytes().to_vec()))]
                .into_iter()
                .collect();
        let new_protocol_components: HashMap<String, ProtocolComponent> = vec![(
            "Pool".to_owned(),
            ProtocolComponent {
                id: "Pool".to_owned(),
                protocol_system: "ambient".to_string(),
                protocol_type_name: "WeightedPool".to_owned(),
                chain: Chain::Ethereum,
                tokens: vec![
                    H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                    H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                ],
                static_attributes: static_attr,
                contract_ids: vec![
                    H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap()
                ],
                change: ChangeType::Creation,
                creation_tx: tx.hash,
                created_at: yesterday_midnight(),
            },
        )]
        .into_iter()
        .collect();
        let new_balances = HashMap::from([(
            "Balance1".to_string(),
            [(
                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                ComponentBalance {
                    token: H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                    balance: Bytes::from(1_i32.to_le_bytes()),
                    modify_tx: tx.hash,
                    component_id: "Balance1".to_string(),
                    balance_float: 16777216.0,
                },
            )]
            .into_iter()
            .collect(),
        )]);
        BlockEntityChanges {
            extractor: "test".to_string(),
            chain: Chain::Ethereum,
            block: Block {
                number: 1,
                hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000000000000,
                ),
                parent_hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000021222324,
                ),
                chain: Chain::Ethereum,
                ts: yesterday_midnight(),
            },
            finalized_block_height: 420,
            revert: false,
            new_tokens: HashMap::new(),
            txs_with_update: vec![
                protocol_state_with_tx(),
                ProtocolChangesWithTx {
                    protocol_states: state_updates,
                    tx,
                    new_protocol_components: new_protocol_components.clone(),
                    balance_changes: new_balances,
                },
            ],
        }
    }

    #[test]
    fn test_block_entity_changes_state_filter() {
        let block = block_entity_changes();

        let state1_key = "State1".to_string();
        let reserve_value = "reserve".to_string();
        let missing = "missing".to_string();

        let keys = vec![
            (&state1_key, &reserve_value),
            (&missing, &reserve_value),
            (&state1_key, &missing),
        ];

        let filtered = block.get_filtered_protocol_state_update(keys);
        assert_eq!(
            filtered,
            HashMap::from([(
                (state1_key.clone(), reserve_value.clone()),
                Bytes::from(600_u64.to_be_bytes().to_vec())
            )])
        );
    }

    #[test]
    fn test_block_entity_changes_balance_filter() {
        let block = block_entity_changes();

        let c_id_key = "Balance1".to_string();
        let token_key =
            Bytes::from(H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap());
        let missing_token =
            Bytes::from(H160::from_str("0x0000000000000000000000000000000000000000").unwrap());
        let missing_component = "missing".to_string();

        let keys = vec![
            (&c_id_key, &token_key),
            (&c_id_key, &missing_token),
            (&missing_component, &token_key),
        ];

        #[allow(clippy::mutable_key_type)]
        // Clippy thinks that tuple with Bytes are a mutable type.
        let filtered = block.get_filtered_balance_update(keys);

        assert_eq!(
            filtered,
            HashMap::from([(
                (c_id_key.clone(), token_key.clone()),
                tycho_core::models::protocol::ComponentBalance {
                    token: H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                        .unwrap()
                        .into(),
                    new_balance: Bytes::from(1_i32.to_le_bytes()),
                    balance_float: 16777216.0,
                    modify_tx: Bytes::from(
                        "0x0000000000000000000000000000000000000000000000000000000011121314"
                    ),
                    component_id: c_id_key.clone()
                }
            )])
        )
    }

    #[test]
    fn test_block_entity_changes_parse_msg() {
        let msg = fixtures::pb_block_entity_changes(0);

        let res = BlockEntityChanges::try_from_message(
            msg,
            "test",
            Chain::Ethereum,
            "ambient",
            &HashMap::from([
                ("Pool".to_string(), ProtocolType::default()),
                ("WeightedPool".to_string(), ProtocolType::default()),
            ]),
            420,
        )
        .unwrap();
        assert_eq!(res, block_entity_changes());
    }

    fn block_entity_changes_result() -> BlockEntityChangesResult {
        let tx = Transaction {
            hash: H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000011121314,
            ),
            block_hash: H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000000000000,
            ),
            from: H160::from_low_u64_be(0x0000000000000000000000000000000041424344),
            to: Some(H160::from_low_u64_be(0x0000000000000000000000000000000051525354)),
            index: 2,
        };
        let attr1: HashMap<String, Bytes> = vec![
            ("reserve".to_owned(), Bytes::from(600_u64.to_be_bytes().to_vec())),
            ("static_attribute".to_owned(), Bytes::from(1_u64.to_be_bytes().to_vec())),
            ("new".to_owned(), Bytes::from(0_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let attr2: HashMap<String, Bytes> = vec![
            ("reserve".to_owned(), Bytes::from(1000_u64.to_be_bytes().to_vec())),
            ("static_attribute".to_owned(), Bytes::from(1_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let state_updates: HashMap<String, ProtocolStateDelta> = vec![
            (
                "State1".to_owned(),
                ProtocolStateDelta {
                    component_id: "State1".to_owned(),
                    updated_attributes: attr1,
                    deleted_attributes: HashSet::new(),
                },
            ),
            (
                "State2".to_owned(),
                ProtocolStateDelta {
                    component_id: "State2".to_owned(),
                    updated_attributes: attr2,
                    deleted_attributes: HashSet::new(),
                },
            ),
        ]
        .into_iter()
        .collect();
        let static_attr: HashMap<String, Bytes> =
            vec![("key".to_owned(), Bytes::from(600_u64.to_be_bytes().to_vec()))]
                .into_iter()
                .collect();
        let new_protocol_components: HashMap<String, ProtocolComponent> = vec![(
            "Pool".to_owned(),
            ProtocolComponent {
                id: "Pool".to_owned(),
                protocol_system: "ambient".to_string(),
                protocol_type_name: "WeightedPool".to_owned(),
                chain: Chain::Ethereum,
                tokens: vec![
                    H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                    H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                ],
                static_attributes: static_attr,
                contract_ids: vec![
                    H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap()
                ],
                change: ChangeType::Creation,
                creation_tx: tx.hash,
                created_at: yesterday_midnight(),
            },
        )]
        .into_iter()
        .collect();

        let new_balances = [(
            "Balance1".to_string(),
            [(
                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                ComponentBalance {
                    token: H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                    balance: Bytes::from(1_i32.to_le_bytes()),
                    modify_tx: tx.hash,
                    component_id: "Balance1".to_string(),
                    balance_float: 16777216.0,
                },
            )]
            .into_iter()
            .collect(),
        )]
        .into_iter()
        .collect();

        BlockEntityChangesResult {
            extractor: "test".to_string(),
            chain: Chain::Ethereum,
            block: Block {
                number: 1,
                hash: tx.block_hash,
                parent_hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000021222324,
                ),
                chain: Chain::Ethereum,
                ts: yesterday_midnight(),
            },
            finalized_block_height: 420,
            revert: false,
            state_updates,
            new_tokens: HashMap::new(),
            new_protocol_components,
            deleted_protocol_components: HashMap::new(),
            component_balances: new_balances,
            component_tvl: HashMap::new(),
        }
    }

    #[test]
    fn test_block_entity_changes_aggregate() {
        let mut block_changes = block_entity_changes();
        let block_hash = "0x0000000000000000000000000000000000000000000000000000000000000000";
        // use a different tx so merge works
        let new_tx = fixtures::transaction02(HASH_256_1, block_hash, 5);
        block_changes.txs_with_update[0].tx = new_tx;

        let res = block_changes
            .aggregate_updates()
            .unwrap();

        assert_eq!(res, block_entity_changes_result());
        assert_eq!(res.state_updates.len(), 2);
    }

    fn create_transaction() -> Transaction {
        Transaction {
            hash: H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000011121314,
            ),
            block_hash: H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000031323334,
            ),
            from: H160::from_low_u64_be(0x0000000000000000000000000000000041424344),
            to: Some(H160::from_low_u64_be(0x0000000000000000000000000000000051525354)),
            index: 2,
        }
    }

    #[rstest]
    fn test_try_from_message_protocol_component() {
        let msg = fixtures::pb_protocol_component();

        let expected_chain = Chain::Ethereum;
        let expected_protocol_system = "ambient".to_string();
        let expected_attribute_map: HashMap<String, Bytes> = vec![
            ("balance".to_string(), Bytes::from(100_u64.to_be_bytes().to_vec())),
            ("factory_address".to_string(), Bytes::from(b"0x0fwe0g240g20".to_vec())),
        ]
        .into_iter()
        .collect();

        let protocol_type_id = "WeightedPool".to_string();
        let protocol_types: HashMap<String, ProtocolType> =
            HashMap::from([(protocol_type_id.clone(), ProtocolType::default())]);

        // Call the try_from_message method
        let result = ProtocolComponent::try_from_message(
            msg,
            expected_chain,
            &expected_protocol_system,
            &protocol_types,
            H256::from_str("0x0e22048af8040c102d96d14b0988c6195ffda24021de4d856801553aa468bcac")
                .unwrap(),
            Default::default(),
        );

        // Assert the result
        assert!(result.is_ok());

        // Unwrap the result for further assertions
        let protocol_component = result.unwrap();

        // Assert specific properties of the protocol component
        assert_eq!(
            protocol_component.id,
            "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_string()
        );
        assert_eq!(protocol_component.protocol_system, expected_protocol_system);
        assert_eq!(protocol_component.protocol_type_name, protocol_type_id);
        assert_eq!(protocol_component.chain, expected_chain);
        assert_eq!(
            protocol_component.tokens,
            vec![
                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            ]
        );
        assert_eq!(
            protocol_component.contract_ids,
            vec![
                H160::from_str("0x31fF2589Ee5275a2038beB855F44b9Be993aA804").unwrap(),
                H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
            ]
        );
        assert_eq!(protocol_component.static_attributes, expected_attribute_map);
    }

    #[rstest]
    fn test_try_from_message_component_balance() {
        let tx = create_transaction();
        let expected_balance: f64 = 3000.0;
        let msg_balance = expected_balance.to_le_bytes().to_vec();

        let expected_token = H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let msg_token = expected_token.0.to_vec();
        let expected_component_id =
            "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902";
        let msg_component_id = expected_component_id
            .as_bytes()
            .to_vec();
        let msg = substreams::BalanceChange {
            balance: msg_balance.to_vec(),
            token: msg_token,
            component_id: msg_component_id,
        };
        let from_message = ComponentBalance::try_from_message(msg, &tx).unwrap();

        assert_eq!(from_message.balance, msg_balance);
        assert_eq!(from_message.modify_tx, tx.hash);
        assert_eq!(from_message.token, expected_token);
        assert_eq!(from_message.component_id, expected_component_id);
    }

    #[rstest]
    fn test_merge() {
        let tx_first_update = fixtures::transaction01();
        let tx_second_update = fixtures::transaction02(HASH_256_1, HASH_256_0, 15);
        let protocol_component_first_tx = create_protocol_component(tx_first_update.hash);
        let protocol_component_second_tx = create_protocol_component(tx_second_update.hash);

        let first_update = TransactionVMUpdates {
            account_updates: [(
                H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                AccountUpdate::new(
                    H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                    Chain::Ethereum,
                    fixtures::evm_slots([(2711790500, 2981278644), (3250766788, 3520254932)]),
                    Some(U256::from(1903326068)),
                    Some(vec![129, 130, 131, 132].into()),
                    ChangeType::Update,
                ),
            )]
            .into_iter()
            .collect(),
            protocol_components: [(
                protocol_component_first_tx.id.clone(),
                protocol_component_first_tx.clone(),
            )]
            .into_iter()
            .collect(),
            component_balances: [(
                protocol_component_first_tx.id.clone(),
                [(
                    H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                    ComponentBalance {
                        token: H160::from_low_u64_be(0x0000000000000000000000000000000066666666),
                        balance: Bytes::from(0_i32.to_le_bytes()),
                        modify_tx: Default::default(),
                        component_id: protocol_component_first_tx.id.clone(),
                        balance_float: 0.0,
                    },
                )]
                .into_iter()
                .collect(),
            )]
            .into_iter()
            .collect(),
            tx: tx_first_update,
        };
        let second_update = TransactionVMUpdates {
            account_updates: [(
                H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                AccountUpdate::new(
                    H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                    Chain::Ethereum,
                    fixtures::evm_slots([(2981278644, 3250766788), (2442302356, 2711790500)]),
                    Some(U256::from(4059231220u64)),
                    Some(vec![1, 2, 3, 4].into()),
                    ChangeType::Update,
                ),
            )]
            .into_iter()
            .collect(),
            protocol_components: [(
                protocol_component_second_tx.id.clone(),
                protocol_component_second_tx.clone(),
            )]
            .into_iter()
            .collect(),
            component_balances: [(
                protocol_component_second_tx.id.clone(),
                [(
                    H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                    ComponentBalance {
                        token: H160::from_low_u64_be(0x0000000000000000000000000000000066666666),
                        balance: Bytes::from(500000_i32.to_le_bytes()),
                        modify_tx: Default::default(),
                        component_id: protocol_component_first_tx.id.clone(),
                        balance_float: 500000.0,
                    },
                )]
                .into_iter()
                .collect(),
            )]
            .into_iter()
            .collect(),
            tx: tx_second_update,
        };

        let mut to_merge_on = first_update.clone();
        to_merge_on
            .merge(&second_update)
            .unwrap();

        let expected_protocol_components: HashMap<ComponentId, ProtocolComponent> = [
            (protocol_component_first_tx.id.clone(), protocol_component_first_tx.clone()),
            (protocol_component_second_tx.id.clone(), protocol_component_second_tx.clone()),
        ]
        .into_iter()
        .collect();
        assert_eq!(to_merge_on.component_balances, second_update.component_balances);
        assert_eq!(to_merge_on.protocol_components, expected_protocol_components);

        let mut acc_update = second_update
            .account_updates
            .clone()
            .into_values()
            .next()
            .unwrap();

        acc_update.slots = fixtures::evm_slots([
            (2442302356, 2711790500),
            (2711790500, 2981278644),
            (3250766788, 3520254932),
            (2981278644, 3250766788),
        ]);

        let acc_update = [(acc_update.address, acc_update)]
            .iter()
            .cloned()
            .collect();

        assert_eq!(to_merge_on.account_updates, acc_update);
    }
}

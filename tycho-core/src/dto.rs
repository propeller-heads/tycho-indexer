//! Data Transfer Objects (or structs)
//!
//! These structs serve to serialise and deserialize messages between server and client, they should
//! be very simple and ideally not contain any business logic.
//!
//! Structs in here implement utoipa traits so they can be used to derive an OpenAPI schema.
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use strum_macros::{Display, EnumString};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::{
    models,
    models::{
        contract::{Contract, ContractDelta},
        token::CurrencyToken,
    },
    serde_primitives::{
        hex_bytes, hex_bytes_option, hex_bytes_vec, hex_hashmap_key, hex_hashmap_key_value,
        hex_hashmap_value,
    },
    Bytes,
};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumString, Display, Default,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum Chain {
    #[default]
    Ethereum,
    Starknet,
    ZkSync,
}

impl From<models::contract::Contract> for ResponseAccount {
    fn from(value: Contract) -> Self {
        ResponseAccount::new(
            value.chain.into(),
            value.address,
            value.title,
            value.slots,
            value.native_balance,
            value.balances,
            value.code,
            value.code_hash,
            value.balance_modify_tx,
            value.code_modify_tx,
            value.creation_tx,
        )
    }
}

impl From<models::Chain> for Chain {
    fn from(value: models::Chain) -> Self {
        match value {
            models::Chain::Ethereum => Chain::Ethereum,
            models::Chain::Starknet => Chain::Starknet,
            models::Chain::ZkSync => Chain::ZkSync,
        }
    }
}

#[derive(Debug, PartialEq, Default, Copy, Clone, Deserialize, Serialize, ToSchema)]
pub enum ChangeType {
    #[default]
    Update,
    Deletion,
    Creation,
    Unspecified,
}

impl From<models::ChangeType> for ChangeType {
    fn from(value: models::ChangeType) -> Self {
        match value {
            models::ChangeType::Update => ChangeType::Update,
            models::ChangeType::Creation => ChangeType::Creation,
            models::ChangeType::Deletion => ChangeType::Deletion,
        }
    }
}

impl ChangeType {
    pub fn merge(&self, other: &Self) -> Self {
        if matches!(self, Self::Creation) {
            Self::Creation
        } else {
            *other
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ExtractorIdentity {
    pub chain: Chain,
    pub name: String,
}

impl ExtractorIdentity {
    pub fn new(chain: Chain, name: &str) -> Self {
        Self { chain, name: name.to_owned() }
    }
}

impl std::fmt::Display for ExtractorIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.chain, self.name)
    }
}

/// A command sent from the client to the server
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum Command {
    Subscribe { extractor_id: ExtractorIdentity, include_state: bool },
    Unsubscribe { subscription_id: Uuid },
}

/// A response sent from the server to the client
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum Response {
    NewSubscription { extractor_id: ExtractorIdentity, subscription_id: Uuid },
    SubscriptionEnded { subscription_id: Uuid },
}

/// A message sent from the server to the client
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum WebSocketMessage {
    BlockChanges { subscription_id: Uuid, deltas: BlockChanges },
    Response(Response),
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Default, ToSchema)]
pub struct Block {
    pub number: u64,
    #[serde(with = "hex_bytes")]
    pub hash: Bytes,
    #[serde(with = "hex_bytes")]
    pub parent_hash: Bytes,
    pub chain: Chain,
    pub ts: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, ToSchema)]
pub struct BlockParam {
    #[schema(value_type=Option<String>)]
    #[serde(with = "hex_bytes_option", default)]
    pub hash: Option<Bytes>,
    #[serde(default)]
    pub chain: Option<Chain>,
    #[serde(default)]
    pub number: Option<i64>,
}

impl From<&Block> for BlockParam {
    fn from(value: &Block) -> Self {
        // The hash should uniquely identify a block across chains
        BlockParam { hash: Some(value.hash.clone()), chain: None, number: None }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Default)]
pub struct TokenBalances(#[serde(with = "hex_hashmap_key")] pub HashMap<Bytes, ComponentBalance>);

impl From<HashMap<Bytes, ComponentBalance>> for TokenBalances {
    fn from(value: HashMap<Bytes, ComponentBalance>) -> Self {
        TokenBalances(value)
    }
}

#[derive(Debug, PartialEq, Clone, Default, Deserialize, Serialize)]
pub struct Transaction {
    #[serde(with = "hex_bytes")]
    pub hash: Bytes,
    #[serde(with = "hex_bytes")]
    pub block_hash: Bytes,
    #[serde(with = "hex_bytes")]
    pub from: Bytes,
    #[serde(with = "hex_bytes_option")]
    pub to: Option<Bytes>,
    pub index: u64,
}

impl Transaction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(hash: Bytes, block_hash: Bytes, from: Bytes, to: Option<Bytes>, index: u64) -> Self {
        Self { hash, block_hash, from, to, index }
    }
}

/// A container for updates grouped by account/component.
///
/// Hold a single update per account/component. This is a condensed form of
/// [BlockChanges].
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Default)]
pub struct BlockChanges {
    pub extractor: String,
    pub chain: Chain,
    pub block: Block,
    pub revert: bool,
    #[serde(with = "hex_hashmap_key", default)]
    pub new_tokens: HashMap<Bytes, ResponseToken>,
    #[serde(with = "hex_hashmap_key")]
    pub account_updates: HashMap<Bytes, AccountUpdate>,
    pub state_updates: HashMap<String, ProtocolStateDelta>,
    pub new_protocol_components: HashMap<String, ProtocolComponent>,
    pub deleted_protocol_components: HashMap<String, ProtocolComponent>,
    pub component_balances: HashMap<String, TokenBalances>,
    pub component_tvl: HashMap<String, f64>,
}

impl BlockChanges {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        extractor: &str,
        chain: Chain,
        block: Block,
        revert: bool,
        account_updates: HashMap<Bytes, AccountUpdate>,
        state_updates: HashMap<String, ProtocolStateDelta>,
        new_protocol_components: HashMap<String, ProtocolComponent>,
        deleted_protocol_components: HashMap<String, ProtocolComponent>,
        component_balances: HashMap<String, HashMap<Bytes, ComponentBalance>>,
    ) -> Self {
        BlockChanges {
            extractor: extractor.to_owned(),
            chain,
            block,
            revert,
            new_tokens: HashMap::new(),
            account_updates,
            state_updates,
            new_protocol_components,
            deleted_protocol_components,
            component_balances: component_balances
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            component_tvl: HashMap::new(),
        }
    }

    pub fn merge(mut self, other: Self) -> Self {
        other
            .account_updates
            .into_iter()
            .for_each(|(k, v)| {
                self.account_updates
                    .entry(k)
                    .and_modify(|e| {
                        e.merge(&v);
                    })
                    .or_insert(v);
            });

        other
            .state_updates
            .into_iter()
            .for_each(|(k, v)| {
                self.state_updates
                    .entry(k)
                    .and_modify(|e| {
                        e.merge(&v);
                    })
                    .or_insert(v);
            });

        other
            .component_balances
            .into_iter()
            .for_each(|(k, v)| {
                self.component_balances
                    .entry(k)
                    .and_modify(|e| e.0.extend(v.0.clone()))
                    .or_insert_with(|| v);
            });

        self.component_tvl
            .extend(other.component_tvl);
        self.new_protocol_components
            .extend(other.new_protocol_components);
        self.deleted_protocol_components
            .extend(other.deleted_protocol_components);
        self.revert = other.revert;
        self.block = other.block;

        self
    }

    pub fn get_block(&self) -> &Block {
        &self.block
    }

    pub fn is_revert(&self) -> bool {
        self.revert
    }

    pub fn filter_by_component<F: Fn(&str) -> bool>(&mut self, keep: F) {
        self.state_updates
            .retain(|k, _| keep(k));
        self.component_balances
            .retain(|k, _| keep(k));
        self.component_tvl
            .retain(|k, _| keep(k));
    }

    pub fn filter_by_contract<F: Fn(&Bytes) -> bool>(&mut self, keep: F) {
        self.account_updates
            .retain(|k, _| keep(k));
    }

    pub fn n_changes(&self) -> usize {
        self.account_updates.len() + self.state_updates.len()
    }
}

#[derive(PartialEq, Serialize, Deserialize, Clone, Debug, ToSchema)]
pub struct AccountUpdate {
    #[serde(with = "hex_bytes")]
    #[schema(value_type=Vec<String>)]
    pub address: Bytes,
    pub chain: Chain,
    #[serde(with = "hex_hashmap_key_value")]
    #[schema(value_type=HashMap<String, String>)]
    pub slots: HashMap<Bytes, Bytes>,
    #[serde(with = "hex_bytes_option")]
    #[schema(value_type=Option<String>)]
    pub balance: Option<Bytes>,
    #[serde(with = "hex_bytes_option")]
    #[schema(value_type=Option<String>)]
    pub code: Option<Bytes>,
    pub change: ChangeType,
}

impl AccountUpdate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: Bytes,
        chain: Chain,
        slots: HashMap<Bytes, Bytes>,
        balance: Option<Bytes>,
        code: Option<Bytes>,
        change: ChangeType,
    ) -> Self {
        Self { address, chain, slots, balance, code, change }
    }

    pub fn merge(&mut self, other: &Self) {
        self.slots.extend(
            other
                .slots
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        self.balance.clone_from(&other.balance);
        self.code.clone_from(&other.code);
        self.change = self.change.merge(&other.change);
    }
}

impl From<models::contract::ContractDelta> for AccountUpdate {
    fn from(value: ContractDelta) -> Self {
        AccountUpdate::new(
            value.address,
            value.chain.into(),
            value
                .slots
                .into_iter()
                .map(|(k, v)| (k, v.unwrap_or_default()))
                .collect(),
            value.balance,
            value.code,
            value.change.into(),
        )
    }
}

/// Represents the static parts of a protocol component.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize, ToSchema)]
pub struct ProtocolComponent {
    pub id: String,
    pub protocol_system: String,
    pub protocol_type_name: String,
    pub chain: Chain,
    #[serde(with = "hex_bytes_vec")]
    #[schema(value_type=Vec<String>)]
    pub tokens: Vec<Bytes>,
    #[serde(with = "hex_bytes_vec")]
    #[schema(value_type=Vec<String>)]
    pub contract_ids: Vec<Bytes>,
    #[serde(with = "hex_hashmap_value")]
    #[schema(value_type=HashMap<String, String>)]
    pub static_attributes: HashMap<String, Bytes>,
    pub change: ChangeType,
    #[serde(with = "hex_bytes")]
    #[schema(value_type=String)]
    pub creation_tx: Bytes,
    pub created_at: NaiveDateTime,
}

impl From<models::protocol::ProtocolComponent> for ProtocolComponent {
    fn from(value: models::protocol::ProtocolComponent) -> Self {
        Self {
            id: value.id,
            protocol_system: value.protocol_system,
            protocol_type_name: value.protocol_type_name,
            chain: value.chain.into(),
            tokens: value.tokens,
            contract_ids: value.contract_addresses,
            static_attributes: value.static_attributes,
            change: value.change.into(),
            creation_tx: value.creation_tx,
            created_at: value.created_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Default)]
pub struct ComponentBalance {
    #[serde(with = "hex_bytes")]
    pub token: Bytes,
    pub balance: Bytes,
    pub balance_float: f64,
    #[serde(with = "hex_bytes")]
    pub modify_tx: Bytes,
    pub component_id: String,
}

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize, ToSchema)]
/// Represents a change in protocol state.
pub struct ProtocolStateDelta {
    pub component_id: String,
    #[schema(value_type=HashMap<String, String>)]
    pub updated_attributes: HashMap<String, Bytes>,
    pub deleted_attributes: HashSet<String>,
}

impl From<models::protocol::ProtocolComponentStateDelta> for ProtocolStateDelta {
    fn from(value: models::protocol::ProtocolComponentStateDelta) -> Self {
        Self {
            component_id: value.component_id,
            updated_attributes: value.updated_attributes,
            deleted_attributes: value.deleted_attributes,
        }
    }
}

impl ProtocolStateDelta {
    /// Merges 'other' into 'self'.
    ///
    ///
    /// During merge of these deltas a special situation can arise when an attribute is present in
    /// `self.deleted_attributes` and `other.update_attributes``. If we would just merge the sets
    /// of deleted attributes or vice versa, it would be ambiguous and potential lead to a
    /// deletion of an attribute that should actually be present, or retention of an actually
    /// deleted attribute.
    ///
    /// This situation is handled the following way:
    ///
    ///     - If an attribute is deleted and in the next message recreated, it is removed from the
    ///       set of deleted attributes and kept in updated_attributes. This way it's temporary
    ///       deletion is never communicated to the final receiver.
    ///     - If an attribute was updated and is deleted in the next message, it is removed from
    ///       updated attributes and kept in deleted. This way the attributes temporary update (or
    ///       potentially short-lived existence) before its deletion is never communicated to the
    ///       final receiver.
    pub fn merge(&mut self, other: &Self) {
        // either updated and then deleted -> keep in deleted, remove from updated
        self.updated_attributes
            .retain(|k, _| !other.deleted_attributes.contains(k));

        // or deleted and then updated/recreated -> remove from deleted and keep in updated
        self.deleted_attributes.retain(|attr| {
            !other
                .updated_attributes
                .contains_key(attr)
        });

        // simply merge updates
        self.updated_attributes.extend(
            other
                .updated_attributes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );

        // simply merge deletions
        self.deleted_attributes
            .extend(other.deleted_attributes.iter().cloned());
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, ToSchema)]
pub struct StateRequestBody {
    #[serde(rename = "contractIds")]
    pub contract_ids: Option<Vec<ContractId>>,
    #[serde(default = "VersionParam::default")]
    pub version: VersionParam,
}

impl StateRequestBody {
    pub fn new(contract_ids: Option<Vec<Bytes>>, version: VersionParam) -> Self {
        Self {
            contract_ids: contract_ids.map(|ids| {
                ids.into_iter()
                    .map(|id| ContractId::new(Chain::Ethereum, id))
                    .collect()
            }),
            version,
        }
    }

    pub fn from_block(block: BlockParam) -> Self {
        Self { contract_ids: None, version: VersionParam { timestamp: None, block: Some(block) } }
    }

    pub fn from_timestamp(timestamp: NaiveDateTime) -> Self {
        Self {
            contract_ids: None,
            version: VersionParam { timestamp: Some(timestamp), block: None },
        }
    }
}

/// Response from Tycho server for a contract state request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct StateRequestResponse {
    pub accounts: Vec<ResponseAccount>,
}

impl StateRequestResponse {
    pub fn new(accounts: Vec<ResponseAccount>) -> Self {
        Self { accounts }
    }
}

#[derive(PartialEq, Clone, Serialize, Deserialize, Default, ToSchema)]
#[serde(rename = "Account")]
/// Account struct for the response from Tycho server for a contract state request.
///
/// Code is serialized as a hex string instead of a list of bytes.
pub struct ResponseAccount {
    pub chain: Chain,
    #[schema(value_type=String, example="0xc9f2e6ea1637E499406986ac50ddC92401ce1f58")]
    #[serde(with = "hex_bytes")]
    pub address: Bytes,
    #[schema(value_type=String, example="Protocol Vault")]
    pub title: String,
    #[schema(value_type=HashMap<String, String>, example=json!({"0x....": "0x...."}))]
    #[serde(with = "hex_hashmap_key_value")]
    pub slots: HashMap<Bytes, Bytes>,
    #[schema(value_type=HashMap<String, String>, example="0x00")]
    #[serde(with = "hex_bytes")]
    pub native_balance: Bytes,
    #[schema(value_type=HashMap<String, String>)]
    #[serde(with = "hex_hashmap_key_value")]
    pub balances: HashMap<Bytes, Bytes>,
    #[schema(value_type=HashMap<String, String>, example="0xBADBABE")]
    #[serde(with = "hex_bytes")]
    pub code: Bytes,
    #[schema(value_type=HashMap<String, String>, example="0x123456789")]
    #[serde(with = "hex_bytes")]
    pub code_hash: Bytes,
    #[schema(value_type=HashMap<String, String>, example="0x8f1133bfb054a23aedfe5d25b1d81b96195396d8b88bd5d4bcf865fc1ae2c3f4")]
    #[serde(with = "hex_bytes")]
    pub balance_modify_tx: Bytes,
    #[schema(value_type=HashMap<String, String>, example="0x8f1133bfb054a23aedfe5d25b1d81b96195396d8b88bd5d4bcf865fc1ae2c3f4")]
    #[serde(with = "hex_bytes")]
    pub code_modify_tx: Bytes,
    #[schema(value_type=HashMap<String, String>, example="0x8f1133bfb054a23aedfe5d25b1d81b96195396d8b88bd5d4bcf865fc1ae2c3f4")]
    #[serde(with = "hex_bytes_option")]
    pub creation_tx: Option<Bytes>,
}

impl ResponseAccount {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: Chain,
        address: Bytes,
        title: String,
        slots: HashMap<Bytes, Bytes>,
        native_balance: Bytes,
        balances: HashMap<Bytes, Bytes>,
        code: Bytes,
        code_hash: Bytes,
        balance_modify_tx: Bytes,
        code_modify_tx: Bytes,
        creation_tx: Option<Bytes>,
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
}

/// Implement Debug for ResponseAccount manually to avoid printing the code field.
impl std::fmt::Debug for ResponseAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseAccount")
            .field("chain", &self.chain)
            .field("address", &self.address)
            .field("title", &self.title)
            .field("slots", &self.slots)
            .field("native_balance", &self.native_balance)
            .field("balances", &self.balances)
            .field("code", &format!("[{} bytes]", self.code.len()))
            .field("code_hash", &self.code_hash)
            .field("balance_modify_tx", &self.balance_modify_tx)
            .field("code_modify_tx", &self.code_modify_tx)
            .field("creation_tx", &self.creation_tx)
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ContractId {
    #[serde(with = "hex_bytes")]
    pub address: Bytes,
    pub chain: Chain,
}

/// Uniquely identifies a contract on a specific chain.
impl ContractId {
    pub fn new(chain: Chain, address: Bytes) -> Self {
        Self { address, chain }
    }

    pub fn address(&self) -> &Bytes {
        &self.address
    }
}

impl Display for ContractId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: 0x{}", self.chain, hex::encode(&self.address))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, ToSchema)]
pub struct VersionParam {
    pub timestamp: Option<NaiveDateTime>,
    pub block: Option<BlockParam>,
}

impl VersionParam {
    pub fn new(timestamp: Option<NaiveDateTime>, block: Option<BlockParam>) -> Self {
        Self { timestamp, block }
    }
}

impl Default for VersionParam {
    fn default() -> Self {
        VersionParam { timestamp: Some(Utc::now().naive_utc()), block: None }
    }
}

fn default_include_balances_flag() -> bool {
    true
}

#[derive(Serialize, Deserialize, Default, Debug, IntoParams)]
pub struct StateRequestParameters {
    #[param(default = 0)]
    pub tvl_gt: Option<u64>,
    #[param(default = 0)]
    pub inertia_min_gt: Option<u64>,
    #[serde(default = "default_include_balances_flag")]
    pub include_balances: bool,
}

impl StateRequestParameters {
    pub fn new(include_balances: bool) -> Self {
        Self { tvl_gt: None, inertia_min_gt: None, include_balances }
    }

    pub fn to_query_string(&self) -> String {
        let mut parts = vec![format!("include_balances={}", self.include_balances)];

        if let Some(tvl_gt) = self.tvl_gt {
            parts.push(format!("tvl_gt={}", tvl_gt));
        }

        if let Some(inertia) = self.inertia_min_gt {
            parts.push(format!("inertia_min_gt={}", inertia));
        }

        let mut res = parts.join("&");
        if !res.is_empty() {
            res = format!("?{res}");
        }
        res
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, ToSchema)]
pub struct TokensRequestBody {
    #[serde(rename = "tokenAddresses")]
    #[schema(value_type=Option<Vec<String>>)]
    pub token_addresses: Option<Vec<Bytes>>,
    #[serde(default)]
    pub min_quality: Option<i32>,
    #[serde(default)]
    pub traded_n_days_ago: Option<u64>,
    #[serde(default)]
    pub pagination: PaginationParams,
}

/// Response from Tycho server for a tokens request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct TokensRequestResponse {
    pub tokens: Vec<ResponseToken>,
    pub pagination: PaginationParams,
}

impl TokensRequestResponse {
    pub fn new(tokens: Vec<ResponseToken>, pagination_request: &PaginationParams) -> Self {
        Self { tokens, pagination: pagination_request.clone() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct PaginationParams {
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: i64,
}

impl PaginationParams {
    pub fn new(page: i64, page_size: i64) -> Self {
        Self { page, page_size }
    }
}

impl Default for PaginationParams {
    fn default() -> Self {
        PaginationParams {
            page: 0,       // Default page number
            page_size: 20, // Default page size
        }
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
#[serde(rename = "Token")]
/// Token struct for the response from Tycho server for a tokens request.
pub struct ResponseToken {
    pub chain: Chain,
    #[schema(value_type=String, example="0xc9f2e6ea1637E499406986ac50ddC92401ce1f58")]
    #[serde(with = "hex_bytes")]
    pub address: Bytes,
    #[schema(value_type=String, example="WETH")]
    pub symbol: String,
    pub decimals: u32,
    pub tax: u64,
    pub gas: Vec<Option<u64>>,
    pub quality: u32,
}

impl From<models::token::CurrencyToken> for ResponseToken {
    fn from(value: CurrencyToken) -> Self {
        Self {
            chain: value.chain.into(),
            address: value.address,
            symbol: value.symbol,
            decimals: value.decimals,
            tax: value.tax,
            gas: value.gas,
            quality: value.quality,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, ToSchema)]
pub struct ProtocolComponentsRequestBody {
    pub protocol_system: Option<String>,
    #[serde(rename = "componentAddresses")]
    pub component_ids: Option<Vec<String>>,
}

impl ProtocolComponentsRequestBody {
    pub fn system_filtered(system: &str) -> Self {
        Self { protocol_system: Some(system.to_string()), component_ids: None }
    }

    pub fn id_filtered(ids: Vec<String>) -> Self {
        Self { protocol_system: None, component_ids: Some(ids) }
    }
}

impl ProtocolComponentsRequestBody {
    pub fn new(protocol_system: Option<String>, component_ids: Option<Vec<String>>) -> Self {
        Self { protocol_system, component_ids }
    }
}

#[derive(Serialize, Deserialize, Default, Debug, IntoParams)]
pub struct ProtocolComponentRequestParameters {
    #[param(default = 0)]
    pub tvl_gt: Option<f64>,
}

impl ProtocolComponentRequestParameters {
    pub fn tvl_filtered(min_tvl: f64) -> Self {
        Self { tvl_gt: Some(min_tvl) }
    }
}

impl ProtocolComponentRequestParameters {
    pub fn to_query_string(&self) -> String {
        if let Some(tvl_gt) = self.tvl_gt {
            return format!("?tvl_gt={}", tvl_gt);
        }
        String::new()
    }
}

/// Response from Tycho server for a protocol components request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct ProtocolComponentRequestResponse {
    pub protocol_components: Vec<ProtocolComponent>,
}

impl ProtocolComponentRequestResponse {
    pub fn new(protocol_components: Vec<ProtocolComponent>) -> Self {
        Self { protocol_components }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct ContractDeltaRequestBody {
    #[serde(rename = "contractIds")]
    pub contract_ids: Option<Vec<ContractId>>,
    #[serde(default = "VersionParam::default")]
    pub start: VersionParam,
    #[serde(default = "VersionParam::default")]
    pub end: VersionParam,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct ContractDeltaRequestResponse {
    pub accounts: Vec<AccountUpdate>,
}

impl ContractDeltaRequestResponse {
    pub fn new(accounts: Vec<AccountUpdate>) -> Self {
        Self { accounts }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, ToSchema)]
pub struct ProtocolId {
    pub id: String,
    pub chain: Chain,
}
/// Protocol State struct for the response from Tycho server for a protocol state request.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize, ToSchema)]
pub struct ResponseProtocolState {
    pub component_id: String,
    /// Attributes of the component. If an attribute's value is a `bigint`,
    /// it will be encoded as a little endian signed hex string.
    #[schema(value_type=HashMap<String, String>)]
    #[serde(with = "hex_hashmap_value")]
    pub attributes: HashMap<String, Bytes>,
    #[schema(value_type=HashMap<String, String>)]
    #[serde(with = "hex_hashmap_key_value")]
    pub balances: HashMap<Bytes, Bytes>,
}

impl From<models::protocol::ProtocolComponentState> for ResponseProtocolState {
    fn from(value: models::protocol::ProtocolComponentState) -> Self {
        Self {
            component_id: value.component_id,
            attributes: value.attributes,
            balances: value.balances,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, ToSchema, Default)]
pub struct ProtocolStateRequestBody {
    #[serde(rename = "protocolIds")]
    pub protocol_ids: Option<Vec<ProtocolId>>,
    #[serde(rename = "protocolSystem")]
    pub protocol_system: Option<String>,
    #[serde(default = "VersionParam::default")]
    pub version: VersionParam,
}

impl ProtocolStateRequestBody {
    pub fn id_filtered(ids: Vec<ProtocolId>) -> Self {
        Self { protocol_ids: Some(ids), ..Default::default() }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct ProtocolStateRequestResponse {
    pub states: Vec<ResponseProtocolState>,
}

impl ProtocolStateRequestResponse {
    pub fn new(states: Vec<ResponseProtocolState>) -> Self {
        Self { states }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct ProtocolDeltaRequestBody {
    #[serde(rename = "contractIds")]
    pub component_ids: Option<Vec<String>>,
    #[serde(default = "VersionParam::default")]
    pub start: VersionParam,
    #[serde(default = "VersionParam::default")]
    pub end: VersionParam,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct ProtocolDeltaRequestResponse {
    pub protocols: Vec<ProtocolStateDelta>,
}

impl ProtocolDeltaRequestResponse {
    pub fn new(protocols: Vec<ProtocolStateDelta>) -> Self {
        Self { protocols }
    }
}

#[derive(Clone, PartialEq, Hash, Eq)]
pub struct ProtocolComponentId {
    pub chain: Chain,
    pub system: String,
    pub id: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "status", content = "message")]
#[schema(example=json!({"status": "NotReady", "message": "No db connection"}))]
pub enum Health {
    Ready,
    Starting(String),
    NotReady(String),
}

#[cfg(test)]
mod test {
    use maplit::hashmap;

    use super::*;

    #[test]
    fn test_parse_state_request() {
        let json_str = r#"
        {
            "contractIds": [
                {
                    "address": "0xb4eccE46b8D4e4abFd03C9B806276A6735C9c092",
                    "chain": "ethereum"
                }
            ],
            "version": {
                "timestamp": "2069-01-01T04:20:00",
                "block": {
                    "hash": "0x24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4",
                    "parentHash": "0x8d75152454e60413efe758cc424bfd339897062d7e658f302765eb7b50971815",
                    "number": 213,
                    "chain": "ethereum"
                }
            }
        }
        "#;

        let result: StateRequestBody = serde_json::from_str(json_str).unwrap();

        let contract0 = "b4eccE46b8D4e4abFd03C9B806276A6735C9c092"
            .parse()
            .unwrap();
        let block_hash = "24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4"
            .parse()
            .unwrap();
        let block_number = 213;

        let expected_timestamp =
            NaiveDateTime::parse_from_str("2069-01-01T04:20:00", "%Y-%m-%dT%H:%M:%S").unwrap();

        let expected = StateRequestBody {
            contract_ids: Some(vec![ContractId::new(Chain::Ethereum, contract0)]),
            version: VersionParam {
                timestamp: Some(expected_timestamp),
                block: Some(BlockParam {
                    hash: Some(block_hash),
                    chain: Some(Chain::Ethereum),
                    number: Some(block_number),
                }),
            },
        };

        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_state_request_no_contract_specified() {
        let json_str = r#"
    {
        "version": {
            "timestamp": "2069-01-01T04:20:00",
            "block": {
                "hash": "0x24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4",
                "parentHash": "0x8d75152454e60413efe758cc424bfd339897062d7e658f302765eb7b50971815",
                "number": 213,
                "chain": "ethereum"
            }
        }
    }
    "#;

        let result: StateRequestBody = serde_json::from_str(json_str).unwrap();

        let block_hash = "24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4".into();
        let block_number = 213;
        let expected_timestamp =
            NaiveDateTime::parse_from_str("2069-01-01T04:20:00", "%Y-%m-%dT%H:%M:%S").unwrap();

        let expected = StateRequestBody {
            contract_ids: None,
            version: VersionParam {
                timestamp: Some(expected_timestamp),
                block: Some(BlockParam {
                    hash: Some(block_hash),
                    chain: Some(Chain::Ethereum),
                    number: Some(block_number),
                }),
            },
        };

        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_block_account_changes() {
        let json_data = r#"
        {
            "extractor": "vm:ambient",
            "chain": "ethereum",
            "block": {
                "number": 123,
                "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "parent_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "chain": "ethereum",
                "ts": "2023-09-14T00:00:00"
            },
            "revert": false,
            "new_tokens": {},
            "account_updates": {
                "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": {
                    "address": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
                    "chain": "ethereum",
                    "slots": {},
                    "balance": "0x01f4",
                    "code": "",
                    "change": "Update"
                }
            },
            "new_protocol_components":
                { "protocol_1": {
                        "id": "protocol_1",
                        "protocol_system": "system_1",
                        "protocol_type_name": "type_1",
                        "chain": "ethereum",
                        "tokens": ["0x01", "0x02"],
                        "contract_ids": ["0x01", "0x02"],
                        "static_attributes": {"attr1": "0x01f4"},
                        "change": "Update",
                        "creation_tx": "0x01",
                        "created_at": "2023-09-14T00:00:00"
                    }
                },
            "deleted_protocol_components": {},
            "component_balances": {
                "protocol_1":
                    {
                        "0x01": {
                            "token": "0x01",
                            "balance": "0xb77831d23691653a01",
                            "balance_float": 3.3844151001790677e21,
                            "modify_tx": "0x01",
                            "component_id": "protocol_1"
                        }
                    }
            },
            "component_tvl": {
                "protocol_1": 1000.0
            }
        }
        "#;

        serde_json::from_str::<BlockAccountChanges>(json_data).expect("parsing failed");
    }

    #[test]
    fn test_parse_block_entity_changes() {
        let json_data = r#"
        {
            "extractor": "vm:ambient",
            "chain": "ethereum",
            "block": {
                "number": 123,
                "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "parent_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "chain": "ethereum",
                "ts": "2023-09-14T00:00:00"
            },
            "revert": false,
            "new_tokens": {},
            "state_updates": {
                "component_1": {
                    "component_id": "component_1",
                    "updated_attributes": {"attr1": "0x01"},
                    "deleted_attributes": ["attr2"]
                }
            },
            "new_protocol_components": {
                "protocol_1": {
                    "id": "protocol_1",
                    "protocol_system": "system_1",
                    "protocol_type_name": "type_1",
                    "chain": "ethereum",
                    "tokens": ["0x01", "0x02"],
                    "contract_ids": ["0x01", "0x02"],
                    "static_attributes": {"attr1": "0x01f4"},
                    "change": "Update",
                    "creation_tx": "0x01",
                    "created_at": "2023-09-14T00:00:00"
                }
            },
            "deleted_protocol_components": {},
            "component_balances": {
                "protocol_1": {
                    "0x01": {
                        "token": "0x01",
                        "balance": "0x01f4",
                        "balance_float": 0.0,
                        "modify_tx": "0x01",
                        "component_id": "protocol_1"
                    }
                }
            },
            "component_tvl": {
                "protocol_1": 1000.0
            }
        }
        "#;

        serde_json::from_str::<BlockEntityChangesResult>(json_data).expect("parsing failed");
    }

    #[test]
    fn test_parse_native_websocket_message() {
        let json_data = r#"
        {
            "subscription_id": "5d23bfbe-89ad-4ea3-8672-dc9e973ac9dc",
            "deltas": {
                "type": "BlockEntityChangesResult",
                "extractor": "uniswap_v2",
                "chain": "ethereum",
                "block": {
                "number": 19291517,
                "hash": "0xbc3ea4896c0be8da6229387a8571b72818aa258daf4fab46471003ad74c4ee83",
                "parent_hash": "0x89ca5b8d593574cf6c886f41ef8208bf6bdc1a90ef36046cb8c84bc880b9af8f",
                "chain": "ethereum",
                "ts": "2024-02-23T16:35:35"
                },
                "revert": false,
                "new_tokens": {},
                "state_updates": {
                    "0xde6faedbcae38eec6d33ad61473a04a6dd7f6e28": {
                        "component_id": "0xde6faedbcae38eec6d33ad61473a04a6dd7f6e28",
                        "updated_attributes": {
                        "reserve0": "0x87f7b5973a7f28a8b32404",
                        "reserve1": "0x09e9564b11"
                        },
                        "deleted_attributes": [ ]
                    },
                    "0x99c59000f5a76c54c4fd7d82720c045bdcf1450d": {
                        "component_id": "0x99c59000f5a76c54c4fd7d82720c045bdcf1450d",
                        "updated_attributes": {
                        "reserve1": "0x44d9a8fd662c2f4d03",
                        "reserve0": "0x500b1261f811d5bf423e"
                        },
                        "deleted_attributes": [ ]
                    }
                },
                "new_protocol_components": { },
                "deleted_protocol_components": { },
                "component_balances": {
                    "0x99c59000f5a76c54c4fd7d82720c045bdcf1450d": {
                        "0x9012744b7a564623b6c3e40b144fc196bdedf1a9": {
                        "token": "0x9012744b7a564623b6c3e40b144fc196bdedf1a9",
                        "balance": "0x500b1261f811d5bf423e",
                        "balance_float": 3.779935574269033E23,
                        "modify_tx": "0xe46c4db085fb6c6f3408a65524555797adb264e1d5cf3b66ad154598f85ac4bf",
                        "component_id": "0x99c59000f5a76c54c4fd7d82720c045bdcf1450d"
                        },
                        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": {
                        "token": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                        "balance": "0x44d9a8fd662c2f4d03",
                        "balance_float": 1.270062661329837E21,
                        "modify_tx": "0xe46c4db085fb6c6f3408a65524555797adb264e1d5cf3b66ad154598f85ac4bf",
                        "component_id": "0x99c59000f5a76c54c4fd7d82720c045bdcf1450d"
                        }
                    }
                },
                "component_tvl": { }
            }
            }
        "#;
        serde_json::from_str::<WebSocketMessage>(json_data).expect("parsing failed");
    }

    #[test]
    fn test_protocol_state_delta_merge_update_delete() {
        // Initialize ProtocolStateDelta instances
        let mut delta1 = ProtocolStateDelta {
            component_id: "Component1".to_string(),
            updated_attributes: [("Attribute1".to_string(), Bytes::from("0xbadbabe420"))]
                .iter()
                .cloned()
                .collect(),
            deleted_attributes: HashSet::new(),
        };
        let delta2 = ProtocolStateDelta {
            component_id: "Component1".to_string(),
            updated_attributes: [("Attribute2".to_string(), Bytes::from("0x0badbabe"))]
                .iter()
                .cloned()
                .collect(),
            deleted_attributes: ["Attribute1".to_string()]
                .iter()
                .cloned()
                .collect(),
        };
        let exp = ProtocolStateDelta {
            component_id: "Component1".to_string(),
            updated_attributes: [("Attribute2".to_string(), Bytes::from("0x0badbabe"))]
                .iter()
                .cloned()
                .collect(),
            deleted_attributes: ["Attribute1".to_string()]
                .iter()
                .cloned()
                .collect(),
        };

        delta1.merge(&delta2);

        assert_eq!(delta1, exp);
    }

    #[test]
    fn test_protocol_state_delta_merge_delete_update() {
        // Initialize ProtocolStateDelta instances
        let mut delta1 = ProtocolStateDelta {
            component_id: "Component1".to_string(),
            updated_attributes: HashMap::new(),
            deleted_attributes: ["Attribute1".to_string()]
                .iter()
                .cloned()
                .collect(),
        };
        let delta2 = ProtocolStateDelta {
            component_id: "Component1".to_string(),
            updated_attributes: [("Attribute1".to_string(), Bytes::from("0x0badbabe"))]
                .iter()
                .cloned()
                .collect(),
            deleted_attributes: HashSet::new(),
        };
        let exp = ProtocolStateDelta {
            component_id: "Component1".to_string(),
            updated_attributes: [("Attribute1".to_string(), Bytes::from("0x0badbabe"))]
                .iter()
                .cloned()
                .collect(),
            deleted_attributes: HashSet::new(),
        };

        delta1.merge(&delta2);

        assert_eq!(delta1, exp);
    }

    #[test]
    fn test_account_update_merge() {
        // Initialize AccountUpdate instances with same address and valid hex strings for Bytes
        let mut account1 = AccountUpdate::new(
            Bytes::from(b"0x1234"),
            Chain::Ethereum,
            [(Bytes::from("0xaabb"), Bytes::from("0xccdd"))]
                .iter()
                .cloned()
                .collect(),
            Some(Bytes::from("0x1000")),
            Some(Bytes::from("0xdeadbeaf")),
            ChangeType::Creation,
        );

        let account2 = AccountUpdate::new(
            Bytes::from(b"0x1234"), // Same id as account1
            Chain::Ethereum,
            [(Bytes::from("0xeeff"), Bytes::from("0x11223344"))]
                .iter()
                .cloned()
                .collect(),
            Some(Bytes::from("0x2000")),
            Some(Bytes::from("0xcafebabe")),
            ChangeType::Update,
        );

        // Merge account2 into account1
        account1.merge(&account2);

        // Define the expected state after merge
        let expected = AccountUpdate::new(
            Bytes::from(b"0x1234"), // Same id as before the merge
            Chain::Ethereum,
            [
                (Bytes::from("0xaabb"), Bytes::from("0xccdd")), // Original slot from account1
                (Bytes::from("0xeeff"), Bytes::from("0x11223344")), // New slot from account2
            ]
            .iter()
            .cloned()
            .collect(),
            Some(Bytes::from("0x2000")),     // Updated balance
            Some(Bytes::from("0xcafebabe")), // Updated code
            ChangeType::Creation,            // Updated change type
        );

        // Assert the new account1 equals to the expected state
        assert_eq!(account1, expected);
    }

    #[test]
    fn test_block_account_changes_merge() {
        // Prepare account updates
        let old_account_updates: HashMap<Bytes, AccountUpdate> = [(
            Bytes::from("0x0011"),
            AccountUpdate {
                address: Bytes::from("0x00"),
                chain: Chain::Ethereum,
                slots: [(Bytes::from("0x0022"), Bytes::from("0x0033"))]
                    .into_iter()
                    .collect(),
                balance: Some(Bytes::from("0x01")),
                code: Some(Bytes::from("0x02")),
                change: ChangeType::Creation,
            },
        )]
        .into_iter()
        .collect();
        let new_account_updates: HashMap<Bytes, AccountUpdate> = [(
            Bytes::from("0x0011"),
            AccountUpdate {
                address: Bytes::from("0x00"),
                chain: Chain::Ethereum,
                slots: [(Bytes::from("0x0044"), Bytes::from("0x0055"))]
                    .into_iter()
                    .collect(),
                balance: Some(Bytes::from("0x03")),
                code: Some(Bytes::from("0x04")),
                change: ChangeType::Update,
            },
        )]
        .into_iter()
        .collect();
        // Create initial and new BlockAccountChanges instances
        let block_account_changes_initial = BlockAccountChanges::new(
            "extractor1",
            Chain::Ethereum,
            Block::default(),
            false,
            old_account_updates,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        let block_account_changes_new = BlockAccountChanges::new(
            "extractor2",
            Chain::Ethereum,
            Block::default(),
            true,
            new_account_updates,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        // Merge the new BlockAccountChanges into the initial one
        let res = block_account_changes_initial.merge(block_account_changes_new);

        // Create the expected result of the merge operation
        let expected_account_updates: HashMap<Bytes, AccountUpdate> = [(
            Bytes::from("0x0011"),
            AccountUpdate {
                address: Bytes::from("0x00"),
                chain: Chain::Ethereum,
                slots: [
                    (Bytes::from("0x0044"), Bytes::from("0x0055")),
                    (Bytes::from("0x0022"), Bytes::from("0x0033")),
                ]
                .into_iter()
                .collect(),
                balance: Some(Bytes::from("0x03")),
                code: Some(Bytes::from("0x04")),
                change: ChangeType::Creation,
            },
        )]
        .into_iter()
        .collect();
        let block_account_changes_expected = BlockAccountChanges::new(
            "extractor1",
            Chain::Ethereum,
            Block::default(),
            true,
            expected_account_updates,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );
        assert_eq!(res, block_account_changes_expected);
    }

    #[test]
    fn test_block_entity_changes_merge() {
        // Initialize two BlockEntityChangesResult instances with different details
        let block_entity_changes_result1 = BlockEntityChangesResult {
            extractor: String::from("extractor1"),
            chain: Chain::Ethereum,
            block: Block::default(),
            revert: false,
            new_tokens: HashMap::new(),
            state_updates: hashmap! { "state1".to_string() => ProtocolStateDelta::default() },
            new_protocol_components: hashmap! { "component1".to_string() => ProtocolComponent::default() },
            deleted_protocol_components: HashMap::new(),
            component_balances: hashmap! {
                "component1".to_string() => TokenBalances(hashmap! {
                    Bytes::from("0x01") => ComponentBalance {
                            token: Bytes::from("0x01"),
                            balance: Bytes::from("0x01"),
                            balance_float: 1.0,
                            modify_tx: Bytes::from("0x00"),
                            component_id: "component1".to_string()
                        },
                    Bytes::from("0x02") => ComponentBalance {
                        token: Bytes::from("0x02"),
                        balance: Bytes::from("0x02"),
                        balance_float: 2.0,
                        modify_tx: Bytes::from("0x00"),
                        component_id: "component1".to_string()
                    },
                })

            },
            component_tvl: hashmap! { "tvl1".to_string() => 1000.0 },
        };
        let block_entity_changes_result2 = BlockEntityChangesResult {
            extractor: String::from("extractor2"),
            chain: Chain::Ethereum,
            block: Block::default(),
            revert: true,
            new_tokens: HashMap::new(),
            state_updates: hashmap! { "state2".to_string() => ProtocolStateDelta::default() },
            new_protocol_components: hashmap! { "component2".to_string() => ProtocolComponent::default() },
            deleted_protocol_components: hashmap! { "component3".to_string() => ProtocolComponent::default() },
            component_balances: hashmap! {
                "component1".to_string() => TokenBalances::default(),
                "component2".to_string() => TokenBalances::default()
            },
            component_tvl: hashmap! { "tvl2".to_string() => 2000.0 },
        };

        let res = block_entity_changes_result1.merge(block_entity_changes_result2);

        let expected_block_entity_changes_result = BlockEntityChangesResult {
            extractor: String::from("extractor1"),
            chain: Chain::Ethereum,
            block: Block::default(),
            revert: true,
            new_tokens: HashMap::new(),
            state_updates: hashmap! {
                "state1".to_string() => ProtocolStateDelta::default(),
                "state2".to_string() => ProtocolStateDelta::default(),
            },
            new_protocol_components: hashmap! {
                "component1".to_string() => ProtocolComponent::default(),
                "component2".to_string() => ProtocolComponent::default(),
            },
            deleted_protocol_components: hashmap! {
                "component3".to_string() => ProtocolComponent::default(),
            },
            component_balances: hashmap! {
                "component1".to_string() => TokenBalances(hashmap! {
                    Bytes::from("0x01") => ComponentBalance {
                            token: Bytes::from("0x01"),
                            balance: Bytes::from("0x01"),
                            balance_float: 1.0,
                            modify_tx: Bytes::from("0x00"),
                            component_id: "component1".to_string()
                        },
                    Bytes::from("0x02") => ComponentBalance {
                        token: Bytes::from("0x02"),
                        balance: Bytes::from("0x02"),
                        balance_float: 2.0,
                        modify_tx: Bytes::from("0x00"),
                        component_id: "component1".to_string()
                        },
                    }),
                "component2".to_string() => TokenBalances::default(),
            },
            component_tvl: hashmap! {
                "tvl1".to_string() => 1000.0,
                "tvl2".to_string() => 2000.0
            },
        };

        assert_eq!(res, expected_block_entity_changes_result);
    }
}

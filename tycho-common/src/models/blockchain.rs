use std::collections::{hash_map::Entry, BTreeMap, HashMap, HashSet};

use chrono::NaiveDateTime;
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use tracing::warn;

use crate::{
    dto,
    models::{
        contract::{AccountBalance, AccountChangesWithTx, AccountDelta},
        protocol::{
            ComponentBalance, ProtocolChangesWithTx, ProtocolComponent, ProtocolComponentStateDelta,
        },
        token::Token,
        Address, Balance, BlockHash, Chain, Code, ComponentId, EntryPointId, MergeError, StoreKey,
        StoreVal,
    },
    Bytes,
};

#[derive(Clone, Default, PartialEq, Serialize, Deserialize, Debug)]
pub struct Block {
    pub number: u64,
    pub chain: Chain,
    pub hash: Bytes,
    pub parent_hash: Bytes,
    pub ts: NaiveDateTime,
}

impl Block {
    pub fn new(
        number: u64,
        chain: Chain,
        hash: Bytes,
        parent_hash: Bytes,
        ts: NaiveDateTime,
    ) -> Self {
        Block { hash, parent_hash, number, chain, ts }
    }
}

#[derive(Clone, Default, PartialEq, Debug, Eq, Hash)]
pub struct Transaction {
    pub hash: Bytes,
    pub block_hash: Bytes,
    pub from: Bytes,
    pub to: Option<Bytes>,
    pub index: u64,
}

impl Transaction {
    pub fn new(hash: Bytes, block_hash: Bytes, from: Bytes, to: Option<Bytes>, index: u64) -> Self {
        Transaction { hash, block_hash, from, to, index }
    }
}

pub struct BlockTransactionDeltas<T> {
    pub extractor: String,
    pub chain: Chain,
    pub block: Block,
    pub revert: bool,
    pub deltas: Vec<TransactionDeltaGroup<T>>,
}

#[allow(dead_code)]
pub struct TransactionDeltaGroup<T> {
    changes: T,
    protocol_component: HashMap<String, ProtocolComponent>,
    component_balances: HashMap<String, ComponentBalance>,
    component_tvl: HashMap<String, f64>,
    tx: Transaction,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockAggregatedChanges {
    pub extractor: String,
    pub chain: Chain,
    pub block: Block,
    pub finalized_block_height: u64,
    pub revert: bool,
    pub state_deltas: HashMap<String, ProtocolComponentStateDelta>,
    pub account_deltas: HashMap<Bytes, AccountDelta>,
    pub new_tokens: HashMap<Address, Token>,
    pub new_protocol_components: HashMap<String, ProtocolComponent>,
    pub deleted_protocol_components: HashMap<String, ProtocolComponent>,
    pub component_balances: HashMap<ComponentId, HashMap<Bytes, ComponentBalance>>,
    pub account_balances: HashMap<Address, HashMap<Address, AccountBalance>>,
    pub component_tvl: HashMap<String, f64>,
    pub dci_update: DCIUpdate,
}

impl BlockAggregatedChanges {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        extractor: &str,
        chain: Chain,
        block: Block,
        finalized_block_height: u64,
        revert: bool,
        state_deltas: HashMap<String, ProtocolComponentStateDelta>,
        account_deltas: HashMap<Bytes, AccountDelta>,
        new_tokens: HashMap<Address, Token>,
        new_components: HashMap<String, ProtocolComponent>,
        deleted_components: HashMap<String, ProtocolComponent>,
        component_balances: HashMap<ComponentId, HashMap<Bytes, ComponentBalance>>,
        account_balances: HashMap<Address, HashMap<Address, AccountBalance>>,
        component_tvl: HashMap<String, f64>,
        dci_update: DCIUpdate,
    ) -> Self {
        Self {
            extractor: extractor.to_string(),
            chain,
            block,
            finalized_block_height,
            revert,
            state_deltas,
            account_deltas,
            new_tokens,
            new_protocol_components: new_components,
            deleted_protocol_components: deleted_components,
            component_balances,
            account_balances,
            component_tvl,
            dci_update,
        }
    }
}

impl std::fmt::Display for BlockAggregatedChanges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "block_number: {}, extractor: {}", self.block.number, self.extractor)
    }
}

impl BlockAggregatedChanges {
    pub fn drop_state(&self) -> Self {
        Self {
            extractor: self.extractor.clone(),
            chain: self.chain,
            block: self.block.clone(),
            finalized_block_height: self.finalized_block_height,
            revert: self.revert,
            account_deltas: HashMap::new(),
            state_deltas: HashMap::new(),
            new_tokens: self.new_tokens.clone(),
            new_protocol_components: self.new_protocol_components.clone(),
            deleted_protocol_components: self.deleted_protocol_components.clone(),
            component_balances: self.component_balances.clone(),
            account_balances: self.account_balances.clone(),
            component_tvl: self.component_tvl.clone(),
            dci_update: self.dci_update.clone(),
        }
    }
}

pub trait BlockScoped {
    fn block(&self) -> Block;
}

impl BlockScoped for BlockAggregatedChanges {
    fn block(&self) -> Block {
        self.block.clone()
    }
}

impl From<dto::Block> for Block {
    fn from(value: dto::Block) -> Self {
        Self {
            number: value.number,
            chain: value.chain.into(),
            hash: value.hash,
            parent_hash: value.parent_hash,
            ts: value.ts,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct DCIUpdate {
    pub new_entrypoints: HashMap<ComponentId, HashSet<EntryPoint>>,
    pub new_entrypoint_params: HashMap<EntryPointId, HashSet<(TracingParams, Option<ComponentId>)>>,
    pub trace_results: HashMap<EntryPointId, TracingResult>,
}

/// Changes grouped by their respective transaction.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TxWithChanges {
    pub tx: Transaction,
    pub protocol_components: HashMap<ComponentId, ProtocolComponent>,
    pub account_deltas: HashMap<Address, AccountDelta>,
    pub state_updates: HashMap<ComponentId, ProtocolComponentStateDelta>,
    pub balance_changes: HashMap<ComponentId, HashMap<Address, ComponentBalance>>,
    pub account_balance_changes: HashMap<Address, HashMap<Address, AccountBalance>>,
    pub entrypoints: HashMap<ComponentId, HashSet<EntryPoint>>,
    pub entrypoint_params: HashMap<EntryPointId, HashSet<(TracingParams, Option<ComponentId>)>>,
}

impl TxWithChanges {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx: Transaction,
        protocol_components: HashMap<ComponentId, ProtocolComponent>,
        account_deltas: HashMap<Address, AccountDelta>,
        protocol_states: HashMap<ComponentId, ProtocolComponentStateDelta>,
        balance_changes: HashMap<ComponentId, HashMap<Address, ComponentBalance>>,
        account_balance_changes: HashMap<Address, HashMap<Address, AccountBalance>>,
        entrypoints: HashMap<ComponentId, HashSet<EntryPoint>>,
        entrypoint_params: HashMap<EntryPointId, HashSet<(TracingParams, Option<ComponentId>)>>,
    ) -> Self {
        Self {
            tx,
            account_deltas,
            protocol_components,
            state_updates: protocol_states,
            balance_changes,
            account_balance_changes,
            entrypoints,
            entrypoint_params,
        }
    }

    /// Merges this update with another one.
    ///
    /// The method combines two [`TxWithChanges`] instances if they are on the same block.
    ///
    /// NB: It is expected that `other` is a more recent update than `self` is and the two are
    /// combined accordingly.
    ///
    /// # Errors
    /// Returns a `MergeError` if any of the above conditions are violated.
    pub fn merge(&mut self, other: TxWithChanges) -> Result<(), MergeError> {
        if self.tx.block_hash != other.tx.block_hash {
            return Err(MergeError::BlockMismatch(
                "TxWithChanges".to_string(),
                self.tx.block_hash.clone(),
                other.tx.block_hash,
            ));
        }
        if self.tx.index > other.tx.index {
            return Err(MergeError::TransactionOrderError(
                "TxWithChanges".to_string(),
                self.tx.index,
                other.tx.index,
            ));
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

        // Merge account deltas
        for (address, update) in other.account_deltas.clone().into_iter() {
            match self.account_deltas.entry(address) {
                Entry::Occupied(mut e) => {
                    e.get_mut().merge(update)?;
                }
                Entry::Vacant(e) => {
                    e.insert(update);
                }
            }
        }

        // Merge protocol state updates
        for (key, value) in other.state_updates {
            match self.state_updates.entry(key) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().merge(value)?;
                }
                Entry::Vacant(entry) => {
                    entry.insert(value);
                }
            }
        }

        // Merge component balance changes
        for (component_id, balance_changes) in other.balance_changes {
            let token_balances = self
                .balance_changes
                .entry(component_id)
                .or_default();
            for (token, balance) in balance_changes {
                token_balances.insert(token, balance);
            }
        }

        // Merge account balance changes
        for (account_addr, balance_changes) in other.account_balance_changes {
            let token_balances = self
                .account_balance_changes
                .entry(account_addr)
                .or_default();
            for (token, balance) in balance_changes {
                token_balances.insert(token, balance);
            }
        }

        // Merge new entrypoints
        for (component_id, entrypoints) in other.entrypoints {
            self.entrypoints
                .entry(component_id)
                .or_default()
                .extend(entrypoints);
        }

        // Merge new entrypoint params
        for (entrypoint_id, params) in other.entrypoint_params {
            self.entrypoint_params
                .entry(entrypoint_id)
                .or_default()
                .extend(params);
        }

        Ok(())
    }
}

impl From<AccountChangesWithTx> for TxWithChanges {
    fn from(value: AccountChangesWithTx) -> Self {
        Self {
            tx: value.tx,
            protocol_components: value.protocol_components,
            account_deltas: value.account_deltas,
            balance_changes: value.component_balances,
            account_balance_changes: value.account_balances,
            ..Default::default()
        }
    }
}

impl From<ProtocolChangesWithTx> for TxWithChanges {
    fn from(value: ProtocolChangesWithTx) -> Self {
        Self {
            tx: value.tx,
            protocol_components: value.new_protocol_components,
            state_updates: value.protocol_states,
            balance_changes: value.balance_changes,
            ..Default::default()
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum BlockTag {
    /// Finalized block
    Finalized,
    /// Safe block
    Safe,
    /// Latest block
    Latest,
    /// Earliest block (genesis)
    Earliest,
    /// Pending block (not yet part of the blockchain)
    Pending,
    /// Block by number
    Number(u64),
}
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntryPoint {
    /// Entry point id
    pub external_id: String,
    /// The address of the contract to trace.
    pub target: Address,
    /// The signature of the function to trace.
    pub signature: String,
}

impl EntryPoint {
    pub fn new(external_id: String, target: Address, signature: String) -> Self {
        Self { external_id, target, signature }
    }
}

impl From<dto::EntryPoint> for EntryPoint {
    fn from(value: dto::EntryPoint) -> Self {
        Self { external_id: value.external_id, target: value.target, signature: value.signature }
    }
}

/// A struct that combines an entry point with its associated tracing params.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntryPointWithTracingParams {
    /// The entry point to trace, containing the target contract address and function signature
    pub entry_point: EntryPoint,
    /// The tracing parameters for this entry point
    pub params: TracingParams,
}

impl From<dto::EntryPointWithTracingParams> for EntryPointWithTracingParams {
    fn from(value: dto::EntryPointWithTracingParams) -> Self {
        match value.params {
            dto::TracingParams::RPCTracer(ref tracer_params) => Self {
                entry_point: EntryPoint {
                    external_id: value.entry_point.external_id,
                    target: value.entry_point.target,
                    signature: value.entry_point.signature,
                },
                params: TracingParams::RPCTracer(RPCTracerParams {
                    caller: tracer_params.caller.clone(),
                    calldata: tracer_params.calldata.clone(),
                    state_overrides: tracer_params
                        .state_overrides
                        .clone()
                        .map(|s| {
                            s.into_iter()
                                .map(|(k, v)| (k, v.into()))
                                .collect()
                        }),
                    prune_addresses: tracer_params.prune_addresses.clone(),
                }),
            },
        }
    }
}

impl EntryPointWithTracingParams {
    pub fn new(entry_point: EntryPoint, params: TracingParams) -> Self {
        Self { entry_point, params }
    }
}

impl std::fmt::Display for EntryPointWithTracingParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tracer_type = match &self.params {
            TracingParams::RPCTracer(_) => "RPC",
        };
        write!(f, "{} [{}]", self.entry_point.external_id, tracer_type)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
/// An entry point to trace. Different types of entry points tracing will be supported in the
/// future. Like RPC debug tracing, symbolic execution, etc.
pub enum TracingParams {
    /// Uses RPC calls to retrieve the called addresses and retriggers
    RPCTracer(RPCTracerParams),
}

impl std::fmt::Display for TracingParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TracingParams::RPCTracer(params) => write!(f, "RPC: {}", params),
        }
    }
}

impl From<dto::TracingParams> for TracingParams {
    fn from(value: dto::TracingParams) -> Self {
        match value {
            dto::TracingParams::RPCTracer(tracer_params) => {
                TracingParams::RPCTracer(tracer_params.into())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
pub enum StorageOverride {
    Diff(BTreeMap<StoreKey, StoreVal>),
    Replace(BTreeMap<StoreKey, StoreVal>),
}

impl From<dto::StorageOverride> for StorageOverride {
    fn from(value: dto::StorageOverride) -> Self {
        match value {
            dto::StorageOverride::Diff(diff) => StorageOverride::Diff(diff),
            dto::StorageOverride::Replace(replace) => StorageOverride::Replace(replace),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
pub struct AccountOverrides {
    pub slots: Option<StorageOverride>,
    pub native_balance: Option<Balance>,
    pub code: Option<Code>,
}

impl From<dto::AccountOverrides> for AccountOverrides {
    fn from(value: dto::AccountOverrides) -> Self {
        Self {
            slots: value.slots.map(|s| s.into()),
            native_balance: value.native_balance,
            code: value.code,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Eq, Hash)]
pub struct RPCTracerParams {
    /// The caller address of the transaction, if not provided tracing will use the default value
    /// for an address defined by the VM.
    pub caller: Option<Address>,
    /// The call data used for the tracing call, this needs to include the function selector
    pub calldata: Bytes,
    /// Optionally allow for state overrides so that the call works as expected
    pub state_overrides: Option<BTreeMap<Address, AccountOverrides>>,
    /// Addresses to prune from trace results. Useful for hooks that use mock
    /// accounts/routers that shouldn't be tracked in the final DCI results.
    pub prune_addresses: Option<Vec<Address>>,
}

impl From<dto::RPCTracerParams> for RPCTracerParams {
    fn from(value: dto::RPCTracerParams) -> Self {
        Self {
            caller: value.caller,
            calldata: value.calldata,
            state_overrides: value.state_overrides.map(|overrides| {
                overrides
                    .into_iter()
                    .map(|(address, account_overrides)| (address, account_overrides.into()))
                    .collect()
            }),
            prune_addresses: value.prune_addresses,
        }
    }
}

impl RPCTracerParams {
    pub fn new(caller: Option<Address>, calldata: Bytes) -> Self {
        Self { caller, calldata, state_overrides: None, prune_addresses: None }
    }

    pub fn with_state_overrides(mut self, state: BTreeMap<Address, AccountOverrides>) -> Self {
        self.state_overrides = Some(state);
        self
    }

    pub fn with_prune_addresses(mut self, addresses: Vec<Address>) -> Self {
        self.prune_addresses = Some(addresses);
        self
    }
}

impl std::fmt::Display for RPCTracerParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let caller_str = match &self.caller {
            Some(addr) => format!("caller={addr}"),
            None => String::new(),
        };

        let calldata_str = if self.calldata.len() >= 8 {
            format!(
                "calldata=0x{}..({} bytes)",
                hex::encode(&self.calldata[..8]),
                self.calldata.len()
            )
        } else {
            format!("calldata={}", self.calldata)
        };

        let overrides_str = match &self.state_overrides {
            Some(overrides) if !overrides.is_empty() => {
                format!(", {} state override(s)", overrides.len())
            }
            _ => String::new(),
        };

        write!(f, "{caller_str}, {calldata_str}{overrides_str}")
    }
}

// Ensure serialization order, required by the storage layer
impl Serialize for RPCTracerParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Count fields: always serialize caller and calldata, plus optional fields
        let mut field_count = 2;
        if self.state_overrides.is_some() {
            field_count += 1;
        }
        if self.prune_addresses.is_some() {
            field_count += 1;
        }

        let mut state = serializer.serialize_struct("RPCTracerEntryPoint", field_count)?;
        state.serialize_field("caller", &self.caller)?;
        state.serialize_field("calldata", &self.calldata)?;

        // Only serialize optional fields if they are present
        if let Some(ref overrides) = self.state_overrides {
            state.serialize_field("state_overrides", overrides)?;
        }
        if let Some(ref prune_addrs) = self.prune_addresses {
            state.serialize_field("prune_addresses", prune_addrs)?;
        }

        state.end()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AddressStorageLocation {
    pub key: StoreKey,
    pub offset: u8,
}

impl AddressStorageLocation {
    pub fn new(key: StoreKey, offset: u8) -> Self {
        Self { key, offset }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TracingResult {
    /// A set of (address, storage slot) pairs representing state that contain a called address.
    /// If any of these storage slots change, the execution path might change.
    pub retriggers: HashSet<(Address, AddressStorageLocation)>,
    /// A map of all addresses that were called during the trace with a list of storage slots that
    /// were accessed.
    pub accessed_slots: HashMap<Address, HashSet<StoreKey>>,
}

impl TracingResult {
    pub fn new(
        retriggers: HashSet<(Address, AddressStorageLocation)>,
        accessed_slots: HashMap<Address, HashSet<StoreKey>>,
    ) -> Self {
        Self { retriggers, accessed_slots }
    }

    /// Merges this tracing result with another one.
    ///
    /// The method combines two [`TracingResult`] instances.
    pub fn merge(&mut self, other: TracingResult) {
        self.retriggers.extend(other.retriggers);
        for (address, slots) in other.accessed_slots {
            self.accessed_slots
                .entry(address)
                .or_default()
                .extend(slots);
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
/// Represents a traced entry point and the results of the tracing operation.
pub struct TracedEntryPoint {
    /// The combined entry point and tracing params that was traced
    pub entry_point_with_params: EntryPointWithTracingParams,
    /// The block hash of the block that the entry point was traced on.
    pub detection_block_hash: BlockHash,
    /// The results of the tracing operation
    pub tracing_result: TracingResult,
}

impl TracedEntryPoint {
    pub fn new(
        entry_point_with_params: EntryPointWithTracingParams,
        detection_block_hash: BlockHash,
        result: TracingResult,
    ) -> Self {
        Self { entry_point_with_params, detection_block_hash, tracing_result: result }
    }

    pub fn entry_point_id(&self) -> String {
        self.entry_point_with_params
            .entry_point
            .external_id
            .clone()
    }
}

impl std::fmt::Display for TracedEntryPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}: {} retriggers, {} accessed addresses]",
            self.entry_point_id(),
            self.tracing_result.retriggers.len(),
            self.tracing_result.accessed_slots.len()
        )
    }
}

#[cfg(test)]
pub mod fixtures {
    use std::str::FromStr;

    use rstest::rstest;

    use super::*;
    use crate::models::ChangeType;

    pub fn transaction01() -> Transaction {
        Transaction::new(
            Bytes::zero(32),
            Bytes::zero(32),
            Bytes::zero(20),
            Some(Bytes::zero(20)),
            10,
        )
    }

    pub fn create_transaction(hash: &str, block: &str, index: u64) -> Transaction {
        Transaction::new(
            hash.parse().unwrap(),
            block.parse().unwrap(),
            Bytes::zero(20),
            Some(Bytes::zero(20)),
            index,
        )
    }

    #[test]
    fn test_merge_tx_with_changes() {
        let base_token = Bytes::from_str("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let quote_token = Bytes::from_str("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
        let contract_addr = Bytes::from_str("aaaaaaaaa24eeeb8d57d431224f73832bc34f688").unwrap();
        let tx_hash0 = "0x2f6350a292c0fc918afe67cb893744a080dacb507b0cea4cc07437b8aff23cdb";
        let tx_hash1 = "0x0d9e0da36cf9f305a189965b248fc79c923619801e8ab5ef158d4fd528a291ad";
        let block = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let component = ProtocolComponent::new(
            "ambient_USDC_ETH",
            "test",
            "vm:pool",
            Chain::Ethereum,
            vec![base_token.clone(), quote_token.clone()],
            vec![contract_addr.clone()],
            Default::default(),
            Default::default(),
            Bytes::from_str(tx_hash0).unwrap(),
            Default::default(),
        );
        let account_delta = AccountDelta::new(
            Chain::Ethereum,
            contract_addr.clone(),
            HashMap::new(),
            None,
            Some(vec![0, 0, 0, 0].into()),
            ChangeType::Creation,
        );

        let mut changes1 = TxWithChanges::new(
            create_transaction(tx_hash0, block, 1),
            HashMap::from([(component.id.clone(), component.clone())]),
            HashMap::from([(contract_addr.clone(), account_delta.clone())]),
            HashMap::new(),
            HashMap::from([(
                component.id.clone(),
                HashMap::from([(
                    base_token.clone(),
                    ComponentBalance {
                        token: base_token.clone(),
                        balance: Bytes::from(800_u64).lpad(32, 0),
                        balance_float: 800.0,
                        component_id: component.id.clone(),
                        modify_tx: Bytes::from_str(tx_hash0).unwrap(),
                    },
                )]),
            )]),
            HashMap::from([(
                contract_addr.clone(),
                HashMap::from([(
                    base_token.clone(),
                    AccountBalance {
                        token: base_token.clone(),
                        balance: Bytes::from(800_u64).lpad(32, 0),
                        modify_tx: Bytes::from_str(tx_hash0).unwrap(),
                        account: contract_addr.clone(),
                    },
                )]),
            )]),
            HashMap::from([(
                component.id.clone(),
                HashSet::from([EntryPoint::new(
                    "test".to_string(),
                    contract_addr.clone(),
                    "function()".to_string(),
                )]),
            )]),
            HashMap::from([(
                "test".to_string(),
                HashSet::from([(
                    TracingParams::RPCTracer(RPCTracerParams::new(
                        None,
                        Bytes::from_str("0x000001ef").unwrap(),
                    )),
                    Some(component.id.clone()),
                )]),
            )]),
        );
        let changes2 = TxWithChanges::new(
            create_transaction(tx_hash1, block, 2),
            HashMap::from([(
                component.id.clone(),
                ProtocolComponent {
                    creation_tx: Bytes::from_str(tx_hash1).unwrap(),
                    ..component.clone()
                },
            )]),
            HashMap::from([(
                contract_addr.clone(),
                AccountDelta::new(
                    Chain::Ethereum,
                    contract_addr.clone(),
                    HashMap::from([(vec![0, 0, 0, 0].into(), Some(vec![0, 0, 0, 0].into()))]),
                    None,
                    None,
                    ChangeType::Update,
                ),
            )]),
            HashMap::new(),
            HashMap::from([(
                component.id.clone(),
                HashMap::from([(
                    base_token.clone(),
                    ComponentBalance {
                        token: base_token.clone(),
                        balance: Bytes::from(1000_u64).lpad(32, 0),
                        balance_float: 1000.0,
                        component_id: component.id.clone(),
                        modify_tx: Bytes::from_str(tx_hash1).unwrap(),
                    },
                )]),
            )]),
            HashMap::from([(
                contract_addr.clone(),
                HashMap::from([(
                    base_token.clone(),
                    AccountBalance {
                        token: base_token.clone(),
                        balance: Bytes::from(1000_u64).lpad(32, 0),
                        modify_tx: Bytes::from_str(tx_hash1).unwrap(),
                        account: contract_addr.clone(),
                    },
                )]),
            )]),
            HashMap::from([(
                component.id.clone(),
                HashSet::from([
                    EntryPoint::new(
                        "test".to_string(),
                        contract_addr.clone(),
                        "function()".to_string(),
                    ),
                    EntryPoint::new(
                        "test2".to_string(),
                        contract_addr.clone(),
                        "function_2()".to_string(),
                    ),
                ]),
            )]),
            HashMap::from([(
                "test2".to_string(),
                HashSet::from([(
                    TracingParams::RPCTracer(RPCTracerParams::new(
                        None,
                        Bytes::from_str("0x000001").unwrap(),
                    )),
                    None,
                )]),
            )]),
        );

        assert!(changes1.merge(changes2).is_ok());
        assert_eq!(
            changes1
                .account_balance_changes
                .get(&contract_addr)
                .unwrap()
                .get(&base_token)
                .unwrap()
                .balance,
            Bytes::from(1000_u64).lpad(32, 0),
        );
        assert_eq!(
            changes1
                .balance_changes
                .get(&component.id)
                .unwrap()
                .get(&base_token)
                .unwrap()
                .balance,
            Bytes::from(1000_u64).lpad(32, 0),
        );
        assert_eq!(changes1.tx.hash, Bytes::from_str(tx_hash1).unwrap(),);
        assert_eq!(changes1.entrypoints.len(), 1);
        assert_eq!(
            changes1
                .entrypoints
                .get(&component.id)
                .unwrap()
                .len(),
            2
        );
        let mut expected_entry_points = changes1
            .entrypoints
            .values()
            .flat_map(|ep| ep.iter())
            .map(|ep| ep.signature.clone())
            .collect::<Vec<_>>();
        expected_entry_points.sort();
        assert_eq!(
            expected_entry_points,
            vec!["function()".to_string(), "function_2()".to_string()],
        );
    }

    #[rstest]
    #[case::mismatched_blocks(
        fixtures::create_transaction("0x01", "0x0abc", 1),
        fixtures::create_transaction("0x02", "0x0def", 2)
    )]
    #[case::older_transaction(
        fixtures::create_transaction("0x02", "0x0abc", 2),
        fixtures::create_transaction("0x01", "0x0abc", 1)
    )]
    fn test_merge_errors(#[case] tx1: Transaction, #[case] tx2: Transaction) {
        let mut changes1 = TxWithChanges { tx: tx1, ..Default::default() };

        let changes2 = TxWithChanges { tx: tx2, ..Default::default() };

        assert!(changes1.merge(changes2).is_err());
    }

    #[test]
    fn test_rpc_tracer_entry_point_serialization_order() {
        use std::str::FromStr;

        use serde_json;

        let entry_point = RPCTracerParams::new(
            Some(Address::from_str("0x1234567890123456789012345678901234567890").unwrap()),
            Bytes::from_str("0xabcdef").unwrap(),
        );

        let serialized = serde_json::to_string(&entry_point).unwrap();

        // Verify that "caller" comes before "calldata" in the serialized output
        assert!(serialized.find("\"caller\"").unwrap() < serialized.find("\"calldata\"").unwrap());

        // Verify we can deserialize it back
        let deserialized: RPCTracerParams = serde_json::from_str(&serialized).unwrap();
        assert_eq!(entry_point, deserialized);
    }

    #[test]
    fn test_tracing_result_merge() {
        let address1 = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let address2 = Address::from_str("0x2345678901234567890123456789012345678901").unwrap();
        let address3 = Address::from_str("0x3456789012345678901234567890123456789012").unwrap();

        let store_key1 = StoreKey::from(vec![1, 2, 3, 4]);
        let store_key2 = StoreKey::from(vec![5, 6, 7, 8]);

        let mut result1 = TracingResult::new(
            HashSet::from([(
                address1.clone(),
                AddressStorageLocation::new(store_key1.clone(), 12),
            )]),
            HashMap::from([
                (address2.clone(), HashSet::from([store_key1.clone()])),
                (address3.clone(), HashSet::from([store_key2.clone()])),
            ]),
        );

        let result2 = TracingResult::new(
            HashSet::from([(
                address3.clone(),
                AddressStorageLocation::new(store_key2.clone(), 12),
            )]),
            HashMap::from([
                (address1.clone(), HashSet::from([store_key1.clone()])),
                (address2.clone(), HashSet::from([store_key2.clone()])),
            ]),
        );

        result1.merge(result2);

        // Verify retriggers were merged
        assert_eq!(result1.retriggers.len(), 2);
        assert!(result1
            .retriggers
            .contains(&(address1.clone(), AddressStorageLocation::new(store_key1.clone(), 12))));
        assert!(result1
            .retriggers
            .contains(&(address3.clone(), AddressStorageLocation::new(store_key2.clone(), 12))));

        // Verify accessed slots were merged
        assert_eq!(result1.accessed_slots.len(), 3);
        assert!(result1
            .accessed_slots
            .contains_key(&address1));
        assert!(result1
            .accessed_slots
            .contains_key(&address2));
        assert!(result1
            .accessed_slots
            .contains_key(&address3));

        assert_eq!(
            result1
                .accessed_slots
                .get(&address2)
                .unwrap(),
            &HashSet::from([store_key1.clone(), store_key2.clone()])
        );
    }

    #[test]
    fn test_entry_point_with_tracing_params_display() {
        use std::str::FromStr;

        let entry_point = EntryPoint::new(
            "uniswap_v3_pool_swap".to_string(),
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
            "swapExactETHForTokens(uint256,address[],address,uint256)".to_string(),
        );

        let tracing_params = TracingParams::RPCTracer(RPCTracerParams::new(
            Some(Address::from_str("0x9876543210987654321098765432109876543210").unwrap()),
            Bytes::from_str("0xabcdef").unwrap(),
        ));

        let entry_point_with_params = EntryPointWithTracingParams::new(entry_point, tracing_params);

        let display_output = entry_point_with_params.to_string();
        assert_eq!(display_output, "uniswap_v3_pool_swap [RPC]");
    }

    #[test]
    fn test_traced_entry_point_display() {
        use std::str::FromStr;

        let entry_point = EntryPoint::new(
            "uniswap_v3_pool_swap".to_string(),
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
            "swapExactETHForTokens(uint256,address[],address,uint256)".to_string(),
        );

        let tracing_params = TracingParams::RPCTracer(RPCTracerParams::new(
            Some(Address::from_str("0x9876543210987654321098765432109876543210").unwrap()),
            Bytes::from_str("0xabcdef").unwrap(),
        ));

        let entry_point_with_params = EntryPointWithTracingParams::new(entry_point, tracing_params);

        // Create tracing result with 2 retriggers and 3 accessed addresses
        let address1 = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let address2 = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
        let address3 = Address::from_str("0x3333333333333333333333333333333333333333").unwrap();

        let store_key1 = StoreKey::from(vec![1, 2, 3, 4]);
        let store_key2 = StoreKey::from(vec![5, 6, 7, 8]);

        let tracing_result = TracingResult::new(
            HashSet::from([
                (address1.clone(), AddressStorageLocation::new(store_key1.clone(), 0)),
                (address2.clone(), AddressStorageLocation::new(store_key2.clone(), 12)),
            ]),
            HashMap::from([
                (address1.clone(), HashSet::from([store_key1.clone()])),
                (address2.clone(), HashSet::from([store_key2.clone()])),
                (address3.clone(), HashSet::from([store_key1.clone()])),
            ]),
        );

        let traced_entry_point = TracedEntryPoint::new(
            entry_point_with_params,
            Bytes::from_str("0xabcdef1234567890").unwrap(),
            tracing_result,
        );

        let display_output = traced_entry_point.to_string();
        assert_eq!(display_output, "[uniswap_v3_pool_swap: 2 retriggers, 3 accessed addresses]");
    }
}
